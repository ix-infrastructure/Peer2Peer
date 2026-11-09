// Copyright 2026 Ix Infrastructure Inc.
//
// Message history (`p2p history`, docs/concepts.md "Message history"): what this device sent and
// received, kept so the person (and each session, for its own messages) can look back. Local only:
// nothing new goes to a relay or a peer, and nothing on the wire changes.
//
//  - What is kept: messages in (p2p.message events, once each: the copy logged for a session that
//    ended is not kept twice) and out (`p2p send`, the TUI, the front ends' sends), and extension
//    kinds as their one-line fallback (never the body). Statuses, rosters and control events aren't.
//  - Where: `<home>/cli/history.json` (the index) and `<home>/cli/history-<n>.json` (segments of at
//    most SEGMENT_BYTES), each sealed with ChaCha20-Poly1305 under a key derived from
//    `<home>/cli/history.key` (32 random bytes, 0600, made exclusively like the person token), with
//    the document's name as associated data, so no plaintext is on disk and no segment can be
//    swapped for another. There is no OS keychain backend yet (docs/roadmap.md): the key sits next
//    to the device keys, with the same 0600 posture. It keeps the text out of backups, indexers and
//    a grep of the home; it does not stop malware running as you (docs/security/threat-model.md).
//  - Bounded: older than `history.retentionDays` (config.json, default 30) or past
//    `history.maxBytes` (default 8 MiB of records), the oldest go, pruned on every write.
//    `history.enabled: false` (or P2P_HISTORY=0) records nothing more; `p2p history --clear`
//    deletes everything, the key included, and the messages in the event log (events.json).
//    A record's `at` is when it arrived here (`sentAt`: the sender's clock), so a sender can't
//    backdate one. A document that can't be opened is set aside (history.bad-*), never swept
//    silently or overwritten. Writes are copy-on-write (see "Writing"), so a crash loses at most
//    what was being written, and an older segment put back is never taken back in.
//  - Who reads it (assertHistoryReader):
//      the person's own view (no --session, or session `tui`: messages to the person, to no
//      session, or from `p2p tui` / a terminal send): only the person, by the same gate as the
//      other person-only commands (their front end's token, or outside any agent's session their
//      "yes" on the controlling terminal; refused inside an agent's session);
//      one session's (`--session <sid>`): its front end (the token), for a session a front end
//      registered, and only records made since its binding began (projects.ts `since`), while the
//      session was in projects it is still bound to (a record kept with no binding is UNBOUND: the
//      person's only), so a session id bound anew never sees the earlier one's history.
//      Without the token, only the person at their own terminal, as above.
//  - Peer text stays untrusted: kept as received, sanitized for a terminal on the way out, and
//    framed as the peer's data by the front ends that show it to a model.

import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { b64uDecode, b64uEncode, loadCircle, sanitizePeerText } from "@peer2peer/core/v3";
import type { App } from "./app.js";
import { readFileConfig } from "./config.js";
import { CliError } from "./errors.js";
import { agentContext, assertPersonForWidening, PERSON_SESSION, sessionBinding } from "./projects.js";
import type { EventRec } from "./state.js";

/** Kept this long by default (config.json `history.retentionDays`). */
export const HISTORY_RETENTION_DAYS = 30;
export const HISTORY_RETENTION_MIN_DAYS = 1;
export const HISTORY_RETENTION_MAX_DAYS = 365;
/** At most this many bytes of records by default (config.json `history.maxBytes`). */
export const HISTORY_MAX_BYTES = 8 * 1024 * 1024;
export const HISTORY_MIN_BYTES = 64 * 1024;
export const HISTORY_MAX_BYTES_CAP = 64 * 1024 * 1024;
/** A segment is closed past this many bytes of records (each write rewrites only the newest). */
export const SEGMENT_BYTES = 256 * 1024;
/** One record's text is at most this long (a message is at most 24 KiB anyway). */
export const MAX_RECORD_TEXT = 24 * 1024;
/** `p2p history` lists at most this many by default, the newest. */
export const HISTORY_LIST_DEFAULT = 50;
export const HISTORY_LIST_MAX = 1000;

const INDEX = "history";
const KEY_INFO = "p2p/v3/history/v1";
const AAD_PREFIX = "p2p/v3/history/v1|";

export interface HistoryRec {
  /** The event id for one received (what `p2p watch` printed), or `out:<random>`. */
  id: string;
  /** When it was recorded here (ms, this device's clock): retention, `--since` and the boundary check use it. */
  at: number;
  /** Received: when the sender says it sent it (the envelope's ts, the sender's clock). */
  sentAt?: number;
  dir: "in" | "out";
  type: "message" | "ext";
  /**
   * The local session it belongs to: the one it went into or was sent from. Absent: sent to this
   * user with no session (the person's inbox, as session `tui` is).
   */
  session?: string;
  /** The other side (for a message between two of your own sessions, you). */
  peer: { userId: string; address: string; self?: true };
  /** Their session (or ours, for a message into a session of ours), when known. */
  peerSession?: { own: string; sid: string; ref: string };
  /** The circle the peer session's roster names, when it has one. */
  circle?: string;
  /** Message text as sent or received (peer data), or an extension kind's fallback line. */
  text: string;
  /** Extension kinds: the kind (`x:<ns>.<type>`). */
  ext?: string;
  /** Sends: what became of it when it was sent. */
  state?: "sent" | "offline" | "outbox";
  /**
   * The session's projects when it was recorded (projects.ts), for the boundary check on reads.
   * UNBOUND when the session had none, or they couldn't be read: such a record is never shown to a
   * session's reader, only to the person.
   */
  projects?: string[];
}

interface Sealed {
  v: 1;
  alg: "c20p1305";
  n: string;
  c: string;
}

interface IndexDoc {
  v: 1;
  /** Oldest first. */
  /** `h`: a hash of the sealed document as written, so an older copy put back is set aside. */
  segs: { name: string; first: number; last: number; bytes: number; count: number; h?: string }[];
  next: number;
}

export interface HistorySettings {
  enabled: boolean;
  retentionDays: number;
  maxBytes: number;
}

/** What config.json and P2P_HISTORY say (out-of-range values are clamped; a broken config.json: the defaults). */
export function historySettings(app: Pick<App, "env" | "home">): HistorySettings {
  let cfg: { enabled?: unknown; retentionDays?: unknown; maxBytes?: unknown } = {};
  try {
    const h = (readFileConfig(app.home) as { history?: unknown }).history;
    if (h && typeof h === "object" && !Array.isArray(h)) cfg = h as typeof cfg;
  } catch {
    // the defaults
  }
  const env = app.env.P2P_HISTORY?.trim().toLowerCase();
  const enabled = env === "0" || env === "false" ? false : env === "1" || env === "true" ? true : cfg.enabled !== false;
  const num = (v: unknown, d: number, lo: number, hi: number) => (typeof v === "number" && Number.isFinite(v) ? Math.min(hi, Math.max(lo, Math.floor(v))) : d);
  return {
    enabled,
    retentionDays: num(cfg.retentionDays, HISTORY_RETENTION_DAYS, HISTORY_RETENTION_MIN_DAYS, HISTORY_RETENTION_MAX_DAYS),
    maxBytes: num(cfg.maxBytes, HISTORY_MAX_BYTES, HISTORY_MIN_BYTES, HISTORY_MAX_BYTES_CAP),
  };
}

// ---------------------------------------------------------------------------
// Sealing

export function historyKeyFile(home: string): string {
  return join(home, "cli", "history.key");
}

const KEY_RE = /^[A-Za-z0-9_-]{43}$/;

function readKey(home: string): Buffer | undefined {
  try {
    const t = readFileSync(historyKeyFile(home), "utf8").trim();
    return KEY_RE.test(t) ? Buffer.from(hkdfSync("sha256", b64uDecode(t, 32), new Uint8Array(0), new TextEncoder().encode(KEY_INFO), 32)) : undefined;
  } catch {
    return undefined;
  }
}

/** The history key, made once (exclusively, 0600, in the CLI's own folder). */
function historyKey(home: string, create: boolean): Buffer | undefined {
  const have = readKey(home);
  if (have || !create) return have;
  mkdirSync(join(home, "cli"), { recursive: true, mode: 0o700 });
  try {
    writeFileSync(historyKeyFile(home), b64uEncode(new Uint8Array(randomBytes(32))), { mode: 0o600, flag: "wx" });
  } catch {
    // made meanwhile by another process (or something is in the way: then nothing is recorded)
  }
  return readKey(home);
}

function seal(key: Buffer, name: string, value: unknown): Sealed {
  const nonce = randomBytes(12);
  const pt = Buffer.from(JSON.stringify(value), "utf8");
  const c = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  c.setAAD(Buffer.from(AAD_PREFIX + name, "utf8"), { plaintextLength: pt.length });
  const ct = Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
  return { v: 1, alg: "c20p1305", n: b64uEncode(new Uint8Array(nonce)), c: b64uEncode(new Uint8Array(ct)) };
}

/** The value sealed in `doc`, or undefined (missing, altered, swapped, or sealed under another key). */
function open<T>(key: Buffer, name: string, doc: unknown): T | undefined {
  const s = doc as Partial<Sealed> | undefined;
  if (!s || s.v !== 1 || s.alg !== "c20p1305" || typeof s.n !== "string" || typeof s.c !== "string") return undefined;
  try {
    const nonce = Buffer.from(b64uDecode(s.n, 12));
    const raw = Buffer.from(b64uDecode(s.c));
    if (raw.length < 16) return undefined;
    const d = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    d.setAAD(Buffer.from(AAD_PREFIX + name, "utf8"), { plaintextLength: raw.length - 16 });
    d.setAuthTag(raw.subarray(raw.length - 16));
    const pt = Buffer.concat([d.update(raw.subarray(0, raw.length - 16)), d.final()]);
    return JSON.parse(pt.toString("utf8")) as T;
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Writing
//
// Copy-on-write, so a crash at any point leaves a history that opens with nothing lost but what was
// being written: a segment's new version goes under a fresh name (`history-<next>`, numbers never
// reused), then the index, then its copy (MARK), then the old version is removed.
//
//  - The index names each live segment with a hash of the sealed document, and `next`, the lowest
//    number never used. A segment the index doesn't name is adopted only when its number is at or
//    above `next` (written after the index: a crash before the index was) and it opens; if it says
//    it `replaces` a listed segment, that one is dropped. Below `next` it is an old version (pruned,
//    or superseded) put back or left behind: removed, never adopted. So a restored segment brings no
//    older copy back.
//  - The index can't be opened: its copy (MARK, sealed under its own name) stands in. Neither can:
//    nothing older is trusted, and every segment is set aside. History starts again.

const recBytes = (r: HistoryRec) => Buffer.byteLength(JSON.stringify(r), "utf8");
const docHash = (doc: unknown) => createHash("sha256").update(JSON.stringify(doc), "utf8").digest("base64url").slice(0, 22);
const segNum = (name: string) => Number(name.slice("history-".length));

/** The index's copy: what stands in when the index itself can't be opened. */
const MARK = "history-mark";

/** At most this many set-aside files are kept (each also goes once it is past retention). */
export const MAX_QUARANTINED = 16;
const QUARANTINE_RE = /^history\.bad-(\d{13})-[\w.-]{1,40}\.json$/;

/** A segment's sealed content: its records, and the segment it is the new version of. */
interface SegDoc {
  v: 2;
  recs: HistoryRec[];
  replaces?: string;
}

/** Segment documents on disk (`<home>/cli/history-<n>.json`), whatever the index says, oldest first. */
function segmentNames(app: App): string[] {
  try {
    return readdirSync(join(app.state.dir, "cli"))
      .map((f) => /^(history-\d{1,9})\.json$/.exec(f)?.[1])
      .filter((x): x is string => x !== undefined)
      .sort((a, b) => segNum(a) - segNum(b));
  } catch {
    return [];
  }
}

/**
 * A history document that can't be read or opened (altered, sealed under another key, not JSON):
 * moved aside to `history.bad-<ms>-<name>.json`, never silently deleted or overwritten, and said
 * once on stderr. Set-aside files go once past retention, or past MAX_QUARANTINED.
 */
/** Documents set aside by this process (readAll reports the ones its read set aside). */
let setAside = 0;

function quarantine(app: App, name: string, why: string): void {
  setAside++;
  const dir = join(app.state.dir, "cli");
  const to = `history.bad-${Date.now()}-${name}.json`;
  try {
    renameSync(join(dir, `${name}.json`), join(dir, to));
    app.io.err(`p2p: message history: ${name} couldn't be opened (${why}); set aside as ${to}`);
  } catch {
    // gone meanwhile
  }
}

function pruneQuarantine(app: App, cutoff: number): void {
  const dir = join(app.state.dir, "cli");
  let files: { f: string; at: number }[];
  try {
    files = readdirSync(dir)
      .map((f) => ({ f, m: QUARANTINE_RE.exec(f) }))
      .filter((x) => x.m)
      .map((x) => ({ f: x.f, at: Number(x.m![1]) }))
      .sort((a, b) => a.at - b.at);
  } catch {
    return;
  }
  for (const [i, x] of files.entries()) if (x.at < cutoff || i < files.length - MAX_QUARANTINED) rmSync(join(dir, x.f), { force: true });
}

type Opened<T> = { ok: true; value: T; doc: unknown } | { ok: false; missing: boolean; why: string };

/** One document read and opened; never throws (each document's failure is its own). */
async function readSealed<T>(app: App, key: Buffer, name: string, hash?: string): Promise<Opened<T>> {
  let doc: unknown;
  try {
    doc = await app.state.backend.read(name);
  } catch {
    return { ok: false, missing: false, why: "not readable" };
  }
  if (doc === undefined || doc === null) return { ok: false, missing: true, why: "missing" };
  if (hash !== undefined && docHash(doc) !== hash) return { ok: false, missing: false, why: "not the copy the index names" };
  const v = open<T>(key, name, doc);
  return v === undefined ? { ok: false, missing: false, why: "altered, or sealed under another key" } : { ok: true, value: v, doc };
}

/** A segment's records (and what it replaces), or why not. */
async function readSeg(app: App, key: Buffer, name: string, hash?: string): Promise<{ ok: true; seg: SegDoc; doc: unknown } | { ok: false; missing: boolean; why: string }> {
  const got = await readSealed<SegDoc>(app, key, name, hash);
  if (!got.ok) return got;
  const v = got.value;
  if (!v || v.v !== 2 || !Array.isArray(v.recs)) return { ok: false, missing: false, why: "not a history segment" };
  return { ok: true, seg: v, doc: got.doc };
}

/** A segment's place in the index, from its records. */
function segEntry(name: string, items: readonly HistoryRec[], sealed: unknown): IndexDoc["segs"][number] {
  return {
    name,
    first: items.length ? Math.min(...items.map((r) => r.at)) : 0,
    last: items.length ? Math.max(...items.map((r) => r.at)) : 0,
    bytes: items.reduce((n, r) => n + recBytes(r), 0),
    count: items.length,
    h: docHash(sealed),
  };
}

const okIndex = (v: unknown): v is IndexDoc => {
  const i = v as IndexDoc | undefined;
  return !!i && i.v === 1 && Array.isArray(i.segs) && Number.isSafeInteger(i.next);
};

/**
 * The index as the last write left it (see "Writing" above), with segments a crash left unlisted
 * adopted or removed. Under the lock. `changed`: it differs from what is on disk.
 */
async function loadIndex(app: App, key: Buffer): Promise<{ idx: IndexDoc; changed: boolean }> {
  const b = app.state.backend;
  const main = await readSealed<IndexDoc>(app, key, INDEX);
  let idx: IndexDoc | undefined = main.ok && okIndex(main.value) ? main.value : undefined;
  let changed = false;
  if (!idx) {
    if (!main.ok && !main.missing) quarantine(app, INDEX, main.why);
    const copy = await readSealed<IndexDoc>(app, key, MARK);
    if (copy.ok && okIndex(copy.value)) idx = copy.value;
    else {
      if (!copy.ok && !copy.missing) quarantine(app, MARK, copy.why);
      // Nothing says which segments are current: none is trusted (an older copy could be any of them).
      const names = segmentNames(app);
      for (const name of names) quarantine(app, name, "no index names it");
      idx = { v: 1, segs: [], next: Math.max(0, ...names.map(segNum)) + 1 };
    }
    changed = true;
  }
  idx = { ...idx, segs: [...idx.segs] };
  const listed = new Set(idx.segs.map((s) => s.name));
  for (const name of segmentNames(app)) {
    if (listed.has(name)) continue;
    if (segNum(name) < idx.next) {
      // An old version: pruned, superseded (a crash before its removal), or put back. Never adopted.
      if (b.remove) await b.remove(name);
      else await b.write(name, null);
      continue;
    }
    // Written after the index (a crash before the index write): kept if it opens.
    const seg = await readSeg(app, key, name);
    if (!seg.ok) {
      if (!seg.missing) quarantine(app, name, seg.why);
      continue;
    }
    if (seg.seg.replaces) idx.segs = idx.segs.filter((s) => s.name !== seg.seg.replaces);
    idx.segs.push(segEntry(name, seg.seg.recs, seg.doc));
    idx.next = Math.max(idx.next, segNum(name) + 1);
    changed = true;
  }
  // Oldest first, by their records (a trimmed oldest segment keeps its place under its new number).
  idx.segs.sort((a, b) => a.first - b.first || segNum(a.name) - segNum(b.name));
  return { idx, changed };
}

/**
 * Appends records, then prunes by age and size, under the state lock. Never throws: history is a
 * convenience, and a full disk or a missing key must not fail a send or a delivery.
 */
export async function recordHistory(app: App, recs: readonly HistoryRec[], now = Date.now()): Promise<void> {
  if (recs.length === 0 || app.readOnly || typeof app.home !== "string") return;
  const settings = historySettings(app);
  if (!settings.enabled) return;
  try {
    const key = historyKey(app.home, true);
    if (!key) return;
    await app.state.withLock(async () => {
      const { idx } = await loadIndex(app, key);
      const old: string[] = [];
      const last = idx.segs.at(-1);
      let items: HistoryRec[] = [];
      let replaces: string | undefined;
      if (last && last.bytes < SEGMENT_BYTES) {
        const seg = await readSeg(app, key, last.name, last.h);
        if (seg.ok) {
          items = seg.seg.recs;
          replaces = last.name;
        } else if (!seg.missing) quarantine(app, last.name, seg.why);
        // Either way, a new version of it (or a new segment) takes its place; it goes once the index no longer names it.
        if (seg.ok) old.push(last.name);
        idx.segs.pop();
      }
      const have = new Set(items.map((r) => r.id));
      for (const r0 of recs) {
        const r: HistoryRec = { ...r0, text: r0.text.length > MAX_RECORD_TEXT ? r0.text.slice(0, MAX_RECORD_TEXT) : r0.text };
        if (have.has(r.id)) continue;
        if (recBytesOf(items) >= SEGMENT_BYTES) {
          await writeSeg(app, key, idx, items, replaces);
          items = [];
          replaces = undefined;
        }
        items.push(r);
        have.add(r.id);
      }
      if (items.length > 0) await writeSeg(app, key, idx, items, replaces);
      old.push(...(await prune(app, key, idx, settings, now)));
      await commitIndex(app, key, idx, old);
    });
  } catch (e) {
    app.io.err(`p2p: message history not written: ${sanitizePeerText((e as Error).message, 200)}`);
  }
}

const recBytesOf = (items: readonly HistoryRec[]) => items.reduce((n, r) => n + recBytes(r), 0);

/** Writes `items` as a new segment (a fresh name) and lists it in `idx` (not yet written). */
async function writeSeg(app: App, key: Buffer, idx: IndexDoc, items: readonly HistoryRec[], replaces?: string): Promise<void> {
  const name = `history-${idx.next++}`;
  const sealed = seal(key, name, { v: 2, recs: [...items], ...(replaces ? { replaces } : {}) } satisfies SegDoc);
  await app.state.backend.write(name, sealed);
  idx.segs.push(segEntry(name, items, sealed));
}

/** The index, then its copy, then the segments they no longer name are removed. */
async function commitIndex(app: App, key: Buffer, idx: IndexDoc, old: readonly string[]): Promise<void> {
  const b = app.state.backend;
  await b.write(INDEX, seal(key, INDEX, idx));
  await b.write(MARK, seal(key, MARK, idx));
  const listed = new Set(idx.segs.map((s) => s.name));
  for (const name of old) {
    if (listed.has(name)) continue;
    if (b.remove) await b.remove(name);
    else await b.write(name, null);
  }
}

/**
 * Drops what is past retention or the size cap, oldest first (the lock is held). Returns the
 * segments to remove once the index no longer names them.
 */
async function prune(app: App, key: Buffer, idx: IndexDoc, s: HistorySettings, now: number): Promise<string[]> {
  const cutoff = now - s.retentionDays * 86_400_000;
  const gone: string[] = [];
  pruneQuarantine(app, cutoff);
  // Whole segments past retention.
  while (idx.segs.length > 0 && idx.segs[0].last < cutoff) gone.push(idx.segs.shift()!.name);
  // Past the size cap: whole segments, oldest first, but never the newest one.
  let total = idx.segs.reduce((n, x) => n + x.bytes, 0);
  while (idx.segs.length > 1 && total > s.maxBytes) {
    const g = idx.segs.shift()!;
    total -= g.bytes;
    gone.push(g.name);
  }
  // The oldest segment still holding records past retention, or the only one over the cap: trimmed
  // (copy-on-write, like every segment write).
  const first = idx.segs[0];
  if (first && (first.first < cutoff || total > s.maxBytes)) {
    const seg = await readSeg(app, key, first.name, first.h);
    idx.segs.shift();
    if (!seg.ok) {
      if (!seg.missing) quarantine(app, first.name, seg.why);
      return gone;
    }
    gone.push(first.name);
    const items = seg.seg.recs.filter((r) => r.at >= cutoff);
    let bytes = recBytesOf(items);
    const others = total - first.bytes;
    while (items.length > 0 && others + bytes > s.maxBytes) bytes -= recBytes(items.shift()!);
    if (items.length > 0) {
      await writeSeg(app, key, idx, items, first.name);
      idx.segs.sort((a, b) => a.first - b.first || segNum(a.name) - segNum(b.name));
    }
  }
  return gone;
}

/**
 * `p2p history --clear`: every segment, the index and its copy, set-aside files and the key, and the
 * messages and extension notices in the event log `p2p watch` reads (events.json), so no copy of
 * their text is left in P2P_HOME. A message a session's watch hasn't printed yet is gone with it.
 */
export async function clearHistory(app: App): Promise<{ cleared: number; events: number }> {
  const key = historyKey(app.home, false);
  const b = app.state.backend;
  const cleared = await app.state.withLock(async () => {
    let n = 0;
    const idx = key ? await readSealed<IndexDoc>(app, key, INDEX) : undefined;
    const segs = idx?.ok && okIndex(idx.value) ? idx.value.segs : [];
    for (const s of segs) n += s.count;
    for (const name of new Set([...segs.map((s) => s.name), ...segmentNames(app), INDEX, MARK])) {
      if (b.remove) await b.remove(name);
      else await b.write(name, null);
    }
    pruneQuarantine(app, Number.MAX_SAFE_INTEGER);
    rmSync(historyKeyFile(app.home), { force: true });
    return n;
  });
  const events = await app.state.update("events", (cur) => {
    if (!cur) return { result: 0 };
    const keep = cur.items.filter((e) => e.kind !== "p2p.message" && e.kind !== "p2p.ext");
    return keep.length === cur.items.length ? { result: 0 } : { next: { ...cur, items: keep }, result: cur.items.length - keep.length };
  });
  return { cleared, events };
}

// ---------------------------------------------------------------------------
// What gets recorded

/** The marker a record carries when its session's projects were unknown (fail closed: the person's only). */
export const UNBOUND = "!unbound";

/** The projects a session is bound to now (projects.ts), for the record's boundary; [UNBOUND] when none or unreadable. */
async function projectsOf(app: App, sid: string | undefined): Promise<string[] | undefined> {
  if (sid === undefined || sid === PERSON_SESSION) return undefined;
  try {
    const ids = Object.keys((await sessionBinding(app, sid))?.projects ?? {}).sort();
    return ids.length > 0 ? ids : [UNBOUND];
  } catch {
    return [UNBOUND];
  }
}

async function circleOf(app: App, own: string, sid: string): Promise<string | undefined> {
  try {
    const r = own === app.userId ? (await app.state.get("sessions"))?.[sid] : await app.store.getRoster(own, sid);
    return r && "circle" in r && typeof r.circle === "string" ? r.circle : undefined;
  } catch {
    return undefined;
  }
}

/** Received messages and extension notices among events just added to the log (inbound.ts). */
export async function recordEvents(app: App, events: readonly EventRec[]): Promise<void> {
  if (!events.some((e) => e.kind === "p2p.message" || e.kind === "p2p.ext") || app.readOnly || !historySettings(app).enabled) return;
  await historyRecords(app, events).then(
    (recs) => recordHistory(app, recs),
    () => undefined,
  );
}

async function historyRecords(app: App, events: readonly EventRec[]): Promise<HistoryRec[]> {
  const recs: HistoryRec[] = [];
  for (const e of events) {
    if (e.kind !== "p2p.message" && e.kind !== "p2p.ext") continue;
    const d = e.data as { from?: { userId?: unknown; address?: unknown; self?: unknown }; own?: unknown; sid?: unknown; ref?: unknown; text?: unknown; fallback?: unknown; ext?: unknown; unclaimedFor?: unknown };
    // The copy for a session that ended: the message itself is kept, once.
    if (d.unclaimedFor !== undefined) continue;
    if (typeof d.from?.userId !== "string") continue;
    const text = e.kind === "p2p.message" ? d.text : d.fallback;
    if (typeof text !== "string") continue;
    const session = e.toSession;
    // Their session, when it went into one of theirs; into one of ours, the envelope names only ours.
    const peerSession = typeof d.own === "string" && d.own !== app.userId && typeof d.sid === "string" ? { own: d.own, sid: d.sid, ref: typeof d.ref === "string" ? d.ref : "" } : undefined;
    const circle = peerSession ? await circleOf(app, peerSession.own, peerSession.sid) : undefined;
    const projects = await projectsOf(app, session);
    recs.push({
      id: e.id,
      at: Date.now(),
      sentAt: e.at,
      dir: "in",
      type: e.kind === "p2p.message" ? "message" : "ext",
      ...(session !== undefined ? { session } : {}),
      peer: { userId: d.from.userId, address: typeof d.from.address === "string" ? d.from.address : d.from.userId, ...(d.from.self === true ? { self: true as const } : {}) },
      ...(peerSession ? { peerSession } : {}),
      ...(circle ? { circle } : {}),
      text,
      ...(e.kind === "p2p.ext" && typeof d.ext === "string" ? { ext: d.ext } : {}),
      ...(projects ? { projects } : {}),
    });
  }
  return recs;
}

/** A send this device made (sessions.ts sendMessage, sendExtension). */
export async function recordSent(
  app: App,
  o: { fromSession: string; to: { userId: string; address: string; own: string; sid: string; ref: string }; text: string; ext?: string; state?: HistoryRec["state"] },
): Promise<void> {
  if (app.readOnly || !historySettings(app).enabled) return;
  const projects = await projectsOf(app, o.fromSession);
  const circle = await circleOf(app, o.to.own, o.to.sid);
  await recordHistory(app, [
    {
      id: `out:${randomBytes(9).toString("base64url")}`,
      at: Date.now(),
      dir: "out",
      type: o.ext ? "ext" : "message",
      session: o.fromSession,
      peer: { userId: o.to.userId, address: o.to.address, ...(o.to.userId === app.userId ? { self: true as const } : {}) },
      peerSession: { own: o.to.own, sid: o.to.sid, ref: o.to.ref },
      ...(circle ? { circle } : {}),
      text: o.text,
      ...(o.ext ? { ext: o.ext } : {}),
      ...(o.state ? { state: o.state } : {}),
      ...(projects ? { projects } : {}),
    },
  ]);
}

// ---------------------------------------------------------------------------
// Reading

/** Whether a record is the person's own inbox: to no session, or the `tui` session's. */
export function isPersonRecord(r: HistoryRec): boolean {
  return r.session === undefined || r.session === PERSON_SESSION;
}

/**
 * Every record held (decrypted), oldest first, without the ones past retention, and how many
 * documents couldn't be opened (set aside, never shown). Under the state lock, so a write in
 * another process (copy-on-write: a segment's old version is removed once the index moved on)
 * never shows as a document that couldn't be opened; a crash's newest segment is adopted here too.
 */
async function readAll(app: App, now: number): Promise<{ recs: HistoryRec[]; unreadable: number }> {
  const key = historyKey(app.home, false);
  if (!key) return { recs: [], unreadable: 0 };
  const cutoff = now - historySettings(app).retentionDays * 86_400_000;
  return app.state.withLock(async () => {
    const before = setAside;
    let unreadable = 0;
    {
      const { idx } = await loadIndex(app, key);
      const out: HistoryRec[] = [];
      for (const s of idx.segs) {
        if (s.last < cutoff) continue;
        const seg = await readSeg(app, key, s.name, s.h);
        if (!seg.ok) {
          unreadable++;
          continue;
        }
        for (const r of seg.seg.recs) if (r && typeof r.at === "number" && r.at >= cutoff && typeof r.text === "string") out.push(r);
      }
      return { recs: out.sort((a, b) => a.at - b.at), unreadable: unreadable + setAside - before };
    }
  });
}

export type HistoryReader = { person: true } | { person: false; sid: string; projects: Set<string>; since: number };

/**
 * Who may read: the person (every record), or one session (its own records, within its projects).
 * `sid` absent or `tui`: the person's own view. The gates are the existing ones (projects.ts):
 * assertPersonForWidening for the person, the registration a front end made for a session.
 */
export async function assertHistoryReader(app: App, sid: string | undefined): Promise<HistoryReader> {
  if (sid === undefined || sid === PERSON_SESSION) {
    await assertPersonForWidening(app, "history", app.confirmTty, "shows your own messages");
    return { person: true };
  }
  if (!app.front) {
    // Without the token: inside an agent's session nobody reads a session's history (its front end
    // reads it for it); outside one, only the person, on their own terminal.
    if (agentContext(app.env)) {
      throw new CliError("refused", `session ${sid}: inside an agent's session only its front end reads a session's history (the Codex bridge's p2p_history), never the shell`);
    }
    await assertPersonForWidening(app, `history --session ${sid}`, app.confirmTty, "shows your own messages");
    return { person: true };
  }
  // The front end (it holds the person token) speaks for its own session: one it registered.
  const b = await sessionBinding(app, sid);
  if (!b?.registered) throw new CliError("refused", `session ${sid} isn't a session a front end of yours registered: no history is read for it`);
  // A binding from before it had a start (`since`) shows nothing until the session's next status gives it one.
  return { person: false, sid, projects: new Set(Object.keys(b.projects ?? {})), since: typeof b.since === "number" ? b.since : Number.MAX_SAFE_INTEGER };
}

/**
 * Whether `reader` may see `r`. A session sees only its own: recorded since its binding began (a
 * binding made anew, after the old one expired, inherits nothing), with projects known (never
 * UNBOUND or none), all of which it is still bound to.
 */
export function mayRead(reader: HistoryReader, r: HistoryRec): boolean {
  if (reader.person) return true;
  if (isPersonRecord(r) || r.session !== reader.sid) return false;
  if (typeof r.at !== "number" || r.at < reader.since) return false;
  if (!Array.isArray(r.projects) || r.projects.length === 0 || r.projects.includes(UNBOUND)) return false;
  return r.projects.every((p) => reader.projects.has(p));
}

export interface HistoryQuery {
  session?: string;
  peer?: string;
  circle?: string;
  since?: number;
  limit?: number;
  /** The person's view only: just their inbox (session tui, or none). */
  inbox?: boolean;
}

export interface HistoryResult {
  messages: (HistoryRec & { inbox?: true })[];
  /** More matched than `limit`: the oldest of them were left out. */
  truncated: boolean;
  /** History documents that couldn't be opened (set aside at the next write). */
  unreadable?: number;
  retention: { days: number; maxBytes: number; enabled: boolean };
}

/** Parses `--since`: `30m`, `12h`, `7d`, `2w`, or a date (ISO 8601). */
export function parseSince(s: string, now = Date.now()): number {
  const m = /^(\d{1,6})\s*(m|min|h|d|w)$/i.exec(s.trim());
  if (m) {
    const n = Number(m[1]);
    const unit = m[2].toLowerCase();
    const ms = unit === "w" ? 7 * 86_400_000 : unit === "d" ? 86_400_000 : unit === "h" ? 3_600_000 : 60_000;
    return now - n * ms;
  }
  const t = Date.parse(s);
  if (!Number.isFinite(t)) throw new CliError("usage", "--since takes a duration (30m, 12h, 7d, 2w) or a date (2026-11-01, 2026-11-01T09:00)");
  return t;
}

/** `p2p history`: the records `reader` may see that match `q`, oldest first, at most `limit` (the newest). */
export async function readHistory(app: App, reader: HistoryReader, q: HistoryQuery = {}, now = Date.now()): Promise<HistoryResult> {
  const s = historySettings(app);
  const all = await readAll(app, now);
  let recs = all.recs.filter((r) => mayRead(reader, r));
  if (!reader.person) recs = recs.filter((r) => r.session === reader.sid);
  else if (q.inbox) recs = recs.filter(isPersonRecord);
  else if (q.session !== undefined) recs = recs.filter((r) => (q.session === PERSON_SESSION ? isPersonRecord(r) : r.session === q.session));
  if (q.since !== undefined) recs = recs.filter((r) => r.at >= q.since!);
  if (q.peer !== undefined) {
    const u = await app.resolveUser(q.peer);
    recs = recs.filter((r) => r.peer.userId === u);
  }
  if (q.circle !== undefined) {
    const { resolveCircle } = await import("./circle-ops.js");
    const c = await resolveCircle(app, q.circle);
    const lc = await loadCircle(app.store, c.record.cid).catch(() => undefined);
    const members = new Set(lc?.chain.head.members ?? []);
    recs = recs.filter((r) => r.circle === c.record.cid || (members.has(r.peer.userId) && r.peer.userId !== app.userId));
  }
  const limit = Math.min(HISTORY_LIST_MAX, Math.max(1, q.limit ?? HISTORY_LIST_DEFAULT));
  const truncated = recs.length > limit;
  if (truncated) recs = recs.slice(recs.length - limit);
  // What a session's reader gets never names other projects (the boundary is already applied).
  const messages = recs.map((r) => {
    const { projects: _p, ...rest } = r;
    void _p;
    return { ...rest, ...(reader.person && isPersonRecord(r) ? { inbox: true as const } : {}) };
  });
  return { messages, truncated, ...(all.unreadable > 0 ? { unreadable: all.unreadable } : {}), retention: { days: s.retentionDays, maxBytes: s.maxBytes, enabled: s.enabled } };
}

/** One record as a terminal line: peer text sanitized (no control, bidi or format characters, one line). */
export function historyLine(r: HistoryRec): string {
  const when = new Date(r.at).toISOString().replace("T", " ").slice(0, 16);
  const who = `${sanitizePeerText(r.peer.address, 120)}${r.peerSession?.ref ? ` [${sanitizePeerText(r.peerSession.ref, 12)}]` : ""}`;
  const where = isPersonRecord(r) ? "you" : `session ${sanitizePeerText(r.session, 128)}`;
  const arrow = r.dir === "in" ? `${who} → ${where}` : `${where} → ${who}`;
  const kind = r.type === "ext" ? ` (${sanitizePeerText(r.ext ?? "extension", 64)})` : "";
  const state = r.state && r.state !== "sent" ? ` [${r.state}]` : "";
  return `${when}  ${arrow}${kind}${state}: ${capText(sanitizePeerText(r.text, HISTORY_SHOW_MAX + 1))}`;
}

/** What one record shows at most, in a terminal or to a model (the rest: `--json`). */
export const HISTORY_SHOW_MAX = 4000;

/** `s` cut at HISTORY_SHOW_MAX characters, saying so. */
export function capText(s: string, max = HISTORY_SHOW_MAX): string {
  const cps = [...s];
  return cps.length > max ? `${cps.slice(0, max).join("")}… (truncated)` : s;
}
