// Copyright 2026 Ix Infrastructure Inc.
//
// Extension state kinds (docs/protocol.md §4.3 "Extension state kinds", cap
// xstate.v1; footprint P2). An extension declares some of its kinds as state
// (P2PExtension.state): a session's latest value of such a kind, such as an
// Ix footprint, rather than an event.
//
//  - Sending (`publishExtensionState`, ExtContext.publish): to the session's
//    status audience (§4.2, as `p2p status`), never to one target. Gated per
//    recipient: a user gets it only when every live session of theirs we know
//    of advertises xstate.v1, and then only on the devices those sessions run
//    on. A device with no live session, or an older client, never gets one.
//    The plaintext carries `state: {ttl}`. A sender updates one kind of one
//    session at most every EXT_STATE_MIN_INTERVAL_MS (`rate_limited`).
//  - Receiving (`onStateEnvelope`): only from the session's owner. Latest wins
//    per (sender, session, kind), replacing what was stored, after the
//    extension (when installed) validated it. Never an event: not logged, not
//    printed by `watch`, never toasted or shown to a model. Size-capped, rate
//    limited (by the envelopes' own spacing and per (sender, session)),
//    bounded per session, per sender (count and charged size) and in total,
//    where the biggest holder is evicted first. A kind the owning extension
//    doesn't declare as state keeps only its fallback.
//  - Reading (`liveStates`): only for live sessions (§4.3, 150 s) and within
//    the value's ttl. `ls --json` gets a bounded summary (no bodies);
//    ExtContext gets an extension's own kinds' kept bodies.

import {
  EXT_STATE_MAX_BYTES,
  EXT_STATE_MIN_INTERVAL_MS,
  EXT_STATE_TTL_DEFAULT,
  extensionKindCap,
  FALLBACK_MAX,
  isExtensionKind,
  isExtStateTtl,
  isLive,
  sanitizePeerText,
  STATUS_CAP_XSTATE,
  STATUS_LIVE_MS,
  type AcceptedMessageV3,
  type ExtensionKind,
  type ExtStateMarker,
} from "@peer2peer/core/v3";
import { createHash } from "node:crypto";
import type { App } from "./app.js";
import { CliError } from "./errors.js";
import { MAX_RENDERED_BYTES, renderExtension, type ExtensionRegistry } from "./extensions.js";
import { checkSid, getSession, rosterAudience, sessionRef } from "./sessions.js";
import { supportsIn } from "./features.js";
import { sessKey, type PeerStatusRec, type XStateIndex, type XStateRec, type XStateSenderDoc } from "./state.js";

/** At most this many state kinds stored per session; a new kind beyond it is dropped. */
export const XSTATE_KINDS_PER_SESSION = 8;
/** At most this many values kept per sender (all their sessions); their oldest go first. */
export const XSTATE_VALUES_PER_USER = 64;
/** At most this much kept per sender, counted with xstateCost(); their oldest values go first. */
export const XSTATE_BYTES_PER_USER = 64 * 1024;
/** What every value is charged at least (a tiny value still costs a record), plus its strings and XSTATE_OVERHEAD. */
export const XSTATE_MIN_COST = 1024;
export const XSTATE_OVERHEAD = 128;
/**
 * At most this many values kept in all. Over it, the sender holding the most
 * loses their oldest value first (never another sender's by age), so one
 * sender can't evict everyone else's state.
 */
export const XSTATE_MAX_RECORDS = 512;
/** Updates accepted per minute for one (sender, session), all its kinds; the rest are dropped (flood guard). */
export const XSTATE_UPDATES_PER_MIN = 120;
/** ...and for one sender across all their sessions (session ids are free to make up). */
export const XSTATE_SENDER_UPDATES_PER_MIN = 240;
/** At most this many per-session rate windows kept per sender; the oldest go first. */
export const XSTATE_RATE_WINDOWS_MAX = 128;
/** A receiver drops an update this much sooner than EXT_STATE_MIN_INTERVAL_MS after the last (clock jitter). */
export const XSTATE_SPACING_SLACK_MS = 1_000;
/** `ls --json`: at most this many state summaries per row. */
export const XSTATE_LS_MAX = 8;

/** What a stored value is charged against its sender's XSTATE_BYTES_PER_USER. */
export function xstateCost(r: Pick<XStateRec, "bytes" | "fallback" | "kind" | "sid">): number {
  return Math.max(r.bytes, XSTATE_MIN_COST) + Buffer.byteLength(r.fallback, "utf8") + r.kind.length + r.sid.length + XSTATE_OVERHEAD;
}

/** Within a sender's document: one value per (sid, kind). */
const valueKey = (sid: string, kind: string) => `${sid}|${kind}`;
/** Each sender's values live in a document of their own (`xstate-<16 hex of sha256(userId)>`); `xstate` is the small index. */
export const senderDoc = (own: string) => `xstate-${createHash("sha256").update(own).digest("hex").slice(0, 16)}`;

/** The kinds the loaded extensions declare as state, with their declared ttl. */
export function declaredState(reg: ExtensionRegistry | undefined, kind: string): { ttl: number } | undefined {
  const ext = reg?.forKind(kind);
  const d = ext?.state?.[kind];
  if (!d) return undefined;
  return { ttl: isExtStateTtl(d.ttl) ? d.ttl : EXT_STATE_TTL_DEFAULT };
}

/** The caps this client advertises for state kinds: `<kind>.v1` for each one a loaded extension declares. */
export function stateKindCaps(reg: ExtensionRegistry | undefined): string[] {
  const out: string[] = [];
  for (const { ext } of reg?.list() ?? []) {
    for (const kind of Object.keys(ext.state ?? {})) {
      const cap = extensionKindCap(kind);
      if (cap && !out.includes(cap)) out.push(cap);
    }
  }
  return out;
}

/**
 * The devices of `u` that get a state kind: none unless every live session of
 * theirs we know of (other than this device's own) advertises xstate.v1 (the
 * agents.v1 rule), and then only the devices those sessions run on.
 */
export function stateDevices(peers: Record<string, PeerStatusRec>, u: string, self: { userId: string; did: string }, now = Date.now()): string[] {
  if (!supportsIn({ peers, self, now }, u, { all: true }, STATUS_CAP_XSTATE)) return [];
  const live = Object.values(peers).filter((p) => p.own === u && isLive(p.ts, now) && !(p.own === self.userId && p.did === self.did));
  return [...new Set(live.map((p) => p.did))];
}

// ---------------------------------------------------------------------------
// Sending

export interface PublishStateOpts {
  fromSession: string;
  kind: string;
  v: number;
  body: unknown;
  /** ≤200 characters of plain text: what a state-aware client without the extension shows in `ls`. */
  fallback: string;
  /** Seconds (EXT_STATE_TTL_MIN-MAX); default EXT_STATE_TTL_DEFAULT. */
  ttl?: number;
}

export interface PublishStateResult {
  kind: string;
  bytes: number;
  ttl: number;
  delivered: { userId: string; address: string; relays: number; devices: number }[];
  /** In the audience, but not sent: no live session that advertises xstate.v1 (an older client, or none live). */
  skipped: { userId: string; address: string; reason: string }[];
  failed: { userId: string; address: string; error: string }[];
}

export async function publishExtensionState(app: App, o: PublishStateOpts): Promise<PublishStateResult> {
  const sid = checkSid(o.fromSession, "--from-session");
  if (!isExtensionKind(o.kind)) throw new CliError("usage", `${o.kind} is not an extension kind (x:<ns>.<type>)`);
  if (!Number.isSafeInteger(o.v) || o.v < 0) throw new CliError("usage", "ext.v must be a non-negative integer");
  if (typeof o.fallback !== "string" || o.fallback.trim() === "" || [...o.fallback].length > FALLBACK_MAX) {
    throw new CliError("usage", `a state kind needs a plain-text fallback of 1-${FALLBACK_MAX} characters (§8.1)`);
  }
  const ttl = o.ttl ?? EXT_STATE_TTL_DEFAULT;
  if (!isExtStateTtl(ttl)) throw new CliError("usage", "a state kind's ttl is an integer of 10-3600 seconds");
  const ext = { v: o.v, body: o.body };
  const json = JSON.stringify(ext);
  if (json === undefined) throw new CliError("usage", "the state body must be JSON");
  const bytes = Buffer.byteLength(json, "utf8");
  if (bytes > EXT_STATE_MAX_BYTES) throw new CliError("too_large", `the state body is ${bytes} bytes; at most ${EXT_STATE_MAX_BYTES}`);
  // The sender's own rate limit: one update of a kind per session every EXT_STATE_MIN_INTERVAL_MS.
  const now = Date.now();
  const slot = `${sid}|${o.kind}`;
  const wait = await app.state.update("xstateSent", (cur = {}) => {
    const last = cur[slot] ?? 0;
    if (now - last < EXT_STATE_MIN_INTERVAL_MS && last <= now) return { result: EXT_STATE_MIN_INTERVAL_MS - (now - last) };
    const next: Record<string, number> = {};
    // Forget slots older than a day.
    for (const [k, t] of Object.entries(cur)) if (now - t < 86_400_000) next[k] = t;
    next[slot] = now;
    return { next, result: 0 };
  });
  if (wait > 0) throw new CliError("rate_limited", `${o.kind} for session ${sid} was published less than ${EXT_STATE_MIN_INTERVAL_MS / 1000} s ago; try again in ${Math.ceil(wait / 1000)} s`, { retryAfterMs: wait });

  await app.connectAndDrain();
  const sess = await getSession(app, sid);
  const audience = await rosterAudience(app, sess);
  const peers = (await app.state.get("peers")) ?? {};
  const plaintext = { ext, fallback: o.fallback, roster: sess.jws, state: { ttl } satisfies ExtStateMarker };
  const result: PublishStateResult = { kind: o.kind, bytes, ttl, delivered: [], skipped: [], failed: [] };
  for (const u of [...audience, app.userId]) {
    if (u === app.userId) {
      const v = await app.view(app.userId);
      if (!v || !v.devices.some((d) => d !== app.did)) continue;
    }
    const address = await app.addressOf(u);
    const devices = stateDevices(peers, u, { userId: app.userId, did: app.did });
    if (devices.length === 0) {
      result.skipped.push({ userId: u, address, reason: `no live session that advertises ${STATUS_CAP_XSTATE}` });
      continue;
    }
    try {
      const d = await app.deliver(u, o.kind as ExtensionKind, { own: app.userId, sid }, plaintext, { onlyDevices: devices });
      if (d.relays.length > 0) result.delivered.push({ userId: u, address, relays: d.relays.length, devices: d.devices });
      else result.failed.push({ userId: u, address, error: "delivered via 0 relays" });
    } catch (e) {
      result.failed.push({ userId: u, address, error: (e as Error).message });
    }
  }
  // This device keeps its own latest value too (its own `ls`, ExtContext.peerState).
  const own = keepFor(app.extensions, o.kind as ExtensionKind, o.v, o.body, o.fallback, { userId: app.userId, address: await app.addressOf(app.userId), self: true }, { own: app.userId, sid, ref: sessionRef(app.userId, sid) }, ttl);
  await store(app, { own: app.userId, sid, did: app.did, kind: o.kind, ts: now, at: now, ttl, v: o.v, fallback: sanitizePeerText(o.fallback, FALLBACK_MAX), bytes, ...own, self: true });
  return result;
}

// ---------------------------------------------------------------------------
// Receiving

type ExtPlaintext = { kind: ExtensionKind; ext: { v: number; body: unknown }; fallback: string; state?: ExtStateMarker };

/** Whether an inbound extension kind is a state kind: it says so, or a loaded extension declares it. */
export function isStateEnvelope(reg: ExtensionRegistry | undefined, pt: ExtPlaintext): boolean {
  return pt.state !== undefined || declaredState(reg, pt.kind) !== undefined;
}

/** Validates and keeps the body through the extension; nothing kept when there is none, or it refuses. */
function keepFor(
  reg: ExtensionRegistry | undefined,
  kind: ExtensionKind,
  v: number,
  body: unknown,
  fallback: string,
  from: { userId: string; address: string; self: boolean },
  session: { own: string; sid: string; ref: string },
  ttl: number,
): { body?: unknown; extError?: string } {
  const r = renderExtension(reg, { kind, v, body, fallback, from, session, state: { ttl } });
  if (r.extError) return { extError: r.extError };
  if (r.kept === undefined) return {};
  const s = JSON.stringify(r.kept.body);
  // The kept value is held to the state cap too (an extension can't grow what it keeps).
  if (s === undefined || Buffer.byteLength(s, "utf8") > EXT_STATE_MAX_BYTES) return { extError: "the kept state was too large" };
  return { body: r.kept.body };
}

/** What happened to an inbound state value (for tests and P2P_DEBUG). */
export type StateVerdict = "stored" | "not-owner" | "too-large" | "older" | "rate-limited" | "too-many-kinds" | "flood";

/**
 * An inbound state kind: stored (latest wins) or dropped, never an event.
 * Only the session's owner publishes its state.
 */
/** `now` is the receiver's clock (its rate windows and arrival time); tests pass a fixed one. */
export async function onStateEnvelope(app: App, r: AcceptedMessageV3, pt: ExtPlaintext, from: { userId: string; address: string; self: boolean }, now: number = Date.now()): Promise<StateVerdict> {
  const e = r.envelope;
  const debug = (why: string) => {
    if (app.env.P2P_DEBUG === "1") app.io.err(`p2p: dropped ${sanitizePeerText(pt.kind, 60)} from ${sanitizePeerText(from.address, 80)}: ${why}`);
  };
  if (e.from !== e.own) {
    debug("only a session's owner publishes its state");
    return "not-owner";
  }
  const bytes = Buffer.byteLength(JSON.stringify(pt.ext) ?? "", "utf8");
  if (bytes > EXT_STATE_MAX_BYTES) {
    debug(`${bytes} bytes; at most ${EXT_STATE_MAX_BYTES}`);
    return "too-large";
  }
  const ttl = pt.state?.ttl ?? declaredState(app.extensions, pt.kind)?.ttl ?? EXT_STATE_TTL_DEFAULT;
  const ref = sessionRef(e.own, e.sid);
  // L1: an extension that owns the namespace but doesn't declare this kind as state never sees it as
  // one: only the fallback is kept.
  const owner = app.extensions?.forKind(pt.kind);
  const kept = owner && !declaredState(app.extensions, pt.kind) ? { extError: `${pt.kind} isn't a state kind of ${owner.name}` } : keepFor(app.extensions, pt.kind, pt.ext.v, pt.ext.body, pt.fallback, from, { own: e.own, sid: e.sid, ref }, ttl);
  const verdict = await store(app, { own: e.own, sid: e.sid, did: e.fdid, kind: pt.kind, ts: e.ts, at: now, ttl, v: pt.ext.v, fallback: sanitizePeerText(pt.fallback, FALLBACK_MAX), bytes, ...kept, ...(from.self ? { self: true } : {}) });
  if (verdict !== "stored") debug(verdict);
  return verdict;
}

const emptyIndex = (): XStateIndex => ({ v: 2, users: {} });
export function asIndex(v: unknown): XStateIndex {
  const x = v as XStateIndex | undefined;
  return x && x.v === 2 && typeof x.users === "object" && x.users !== null ? x : emptyIndex();
}
function asSenderDoc(v: unknown, own: string): XStateSenderDoc {
  const x = v as XStateSenderDoc | undefined;
  return x && x.own === own && typeof x.recs === "object" && x.recs !== null
    ? { own, recs: { ...x.recs }, rate: { ...(x.rate ?? {}) }, ...(x.all ? { all: x.all } : {}) }
    : { own, recs: {}, rate: {} };
}

/** Rate windows still open at `now`: stale ones dropped, at most XSTATE_RATE_WINDOWS_MAX (the oldest go first). */
function liveWindows(rate: XStateSenderDoc["rate"], now: number): XStateSenderDoc["rate"] {
  const open = Object.entries(rate)
    .filter(([, w]) => now - w.start < 60_000)
    .sort((a, b) => b[1].start - a[1].start)
    .slice(0, XSTATE_RATE_WINDOWS_MAX);
  return Object.fromEntries(open);
}

/**
 * Writes a sender's document with its rate windows pruned. Once it holds no
 * values and no open rate window it is deleted (N2): a window still open is
 * kept for its minute, or deleting it would reset a flooding sender's limit.
 * False when the document is gone.
 */
async function writeSender(backend: App["state"]["backend"], name: string, doc: XStateSenderDoc, now: number): Promise<boolean> {
  const rate = liveWindows(doc.rate, now);
  const all = doc.all && now - doc.all.start < 60_000 ? doc.all : undefined;
  if (Object.keys(doc.recs).length === 0 && Object.keys(rate).length === 0 && !all && backend.remove) {
    await backend.remove(name);
    return false;
  }
  await backend.write(name, { own: doc.own, recs: doc.recs, rate, ...(all ? { all } : {}) });
  return true;
}

/** Backends whose index was reconciled with the sender documents in this process (N3). */
const reconciled = new WeakSet<object>();

/**
 * The index with each sender's totals recomputed from their document (N3);
 * senders whose document is gone are dropped, and an empty document whose
 * rate windows have closed is deleted.
 */
async function reconcile(backend: App["state"]["backend"], index: XStateIndex, now: number): Promise<XStateIndex> {
  const users: XStateIndex["users"] = {};
  for (const [own, u] of Object.entries(index.users)) {
    const raw = await backend.read(u.doc);
    if (raw === undefined) continue;
    const doc = asSenderDoc(raw, own);
    if (await writeSender(backend, u.doc, doc, now)) users[own] = { doc: u.doc, ...summarize(doc.recs) };
  }
  if (JSON.stringify(users) !== JSON.stringify(index.users)) await backend.write("xstate", { v: 2, users });
  return { v: 2, users };
}

/** Drops a sender's oldest values (never `keep`) until they hold at most `max` values and `budget` cost. */
function trimSender(recs: Record<string, XStateRec>, max: number, budget: number, keep?: string): void {
  const order = Object.entries(recs)
    .filter(([k]) => k !== keep)
    .sort((a, b) => a[1].at - b[1].at);
  let n = Object.keys(recs).length;
  let cost = Object.values(recs).reduce((t, r) => t + xstateCost(r), 0);
  for (const [k, r] of order) {
    if (n <= max && cost <= budget) break;
    delete recs[k];
    n--;
    cost -= xstateCost(r);
  }
}

const summarize = (recs: Record<string, XStateRec>) => ({ n: Object.keys(recs).length, cost: Object.values(recs).reduce((t, r) => t + xstateCost(r), 0) });

/**
 * Writes one value under the state lock: latest wins, within every bound;
 * prunes what is dead. Only the sender's own document is rewritten, plus the
 * small index when their totals change (and, over the global cap, the
 * documents of the senders holding the most).
 */
async function store(app: App, rec: XStateRec): Promise<StateVerdict> {
  const peers = (await app.state.get("peers")) ?? {};
  const backend = app.state.backend;
  return backend.withLock(async () => {
    const now = rec.at;
    let index = asIndex(await backend.read("xstate"));
    if (!reconciled.has(backend)) {
      index = await reconcile(backend, index, now);
      reconciled.add(backend);
    }
    const name = senderDoc(rec.own);
    const doc = asSenderDoc(await backend.read(name), rec.own);
    const key = valueKey(rec.sid, rec.kind);
    const recs = prune(doc.recs, peers, now);
    const old = recs[key];
    if (old && old.ts >= rec.ts) return "older";
    if (old && !rec.self && rec.ts - old.ts < EXT_STATE_MIN_INTERVAL_MS - XSTATE_SPACING_SLACK_MS) return "rate-limited";
    if (!old && Object.values(recs).filter((x) => x.sid === rec.sid).length >= XSTATE_KINDS_PER_SESSION) return "too-many-kinds";
    // Per (sender, session) at most XSTATE_UPDATES_PER_MIN, and per sender at most
    // XSTATE_SENDER_UPDATES_PER_MIN, accepted a minute (this device's own aren't counted).
    doc.rate = liveWindows(doc.rate, now);
    if (!rec.self) {
      const all = doc.all && now - doc.all.start < 60_000 ? doc.all : { start: now, n: 0 };
      const w = doc.rate[rec.sid] ?? { start: now, n: 0 };
      if (w.n >= XSTATE_UPDATES_PER_MIN || all.n >= XSTATE_SENDER_UPDATES_PER_MIN) {
        await writeSender(backend, name, { ...doc, recs }, now);
        return "flood";
      }
      doc.rate[rec.sid] = { start: w.start, n: w.n + 1 };
      doc.all = { start: all.start, n: all.n + 1 };
    }
    recs[key] = rec;
    // Per sender: at most XSTATE_VALUES_PER_USER values and XSTATE_BYTES_PER_USER of cost, their oldest first.
    trimSender(recs, XSTATE_VALUES_PER_USER, XSTATE_BYTES_PER_USER, key);
    const users = { ...index.users, [rec.own]: { doc: name, ...summarize(recs) } };
    // A new sender is in the index before their document exists (N3: no document the index doesn't know).
    if (!index.users[rec.own]) await backend.write("xstate", { v: 2, users });
    await writeSender(backend, name, { ...doc, recs }, now);
    const gone = new Set<string>();
    // In all: over XSTATE_MAX_RECORDS, the sender holding the most gives up their oldest value first.
    let total = Object.values(users).reduce((t, u) => t + u.n, 0);
    while (total > XSTATE_MAX_RECORDS) {
      // The sender holding the most (then the most cost) that has a value to give up; the new value never goes.
      let evicted = false;
      for (const [own, u] of Object.entries(users).sort((x, y) => y[1].n - x[1].n || y[1].cost - x[1].cost)) {
        const theirs = own === rec.own ? doc : asSenderDoc(await backend.read(u.doc), own);
        const live = own === rec.own ? recs : prune(theirs.recs, peers, now);
        const victim = Object.entries(live)
          .filter(([k]) => !(own === rec.own && k === key))
          .sort((x, y) => x[1].at - y[1].at)[0];
        if (!victim && Object.keys(live).length === u.n) continue;
        if (victim) delete live[victim[0]];
        if (!(await writeSender(backend, u.doc, { ...theirs, recs: live }, now))) gone.add(own);
        users[own] = { doc: u.doc, ...summarize(live) };
        evicted = true;
        break;
      }
      if (!evicted) break;
      total = Object.values(users).reduce((t, u) => t + u.n, 0);
    }
    // A sender stays indexed while their document exists (an empty one keeps an open rate window).
    for (const own of gone) delete users[own];
    if (JSON.stringify(users) !== JSON.stringify(index.users)) await backend.write("xstate", { v: 2, users });
    return "stored";
  });
}

/** Expiry: the ttl from the earlier of the envelope's ts and arrival (a ts set ahead can't stretch it). */
export function expiresAt(rec: XStateRec): number {
  return Math.min(rec.ts, rec.at) + rec.ttl * 1000;
}

/** Without the values that expired, or whose session isn't live (and wasn't heard from in the last 150 s). */
function prune(recs: Record<string, XStateRec>, peers: Record<string, PeerStatusRec>, now: number): Record<string, XStateRec> {
  const out: Record<string, XStateRec> = {};
  for (const [k, r] of Object.entries(recs)) {
    if (now >= expiresAt(r)) continue;
    // A value may arrive before its session's status: kept for a status's lifetime meanwhile.
    if (!isLive(peers[sessKey(r.own, r.sid)]?.ts, now) && now - r.at > STATUS_LIVE_MS) continue;
    out[k] = r;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Reading

/** The stored values of live sessions, within their ttl; optionally of one kind, or one namespace. */
export async function liveStates(app: App, filter: { kind?: string; ns?: string } = {}, now = Date.now()): Promise<XStateRec[]> {
  const index = asIndex(await app.state.backend.read("xstate"));
  const peers = (await app.state.get("peers")) ?? {};
  const out: XStateRec[] = [];
  for (const [own, u] of Object.entries(index.users)) {
    const doc = asSenderDoc(await app.state.backend.read(u.doc), own);
    for (const r of Object.values(doc.recs)) {
      if (
        r.own === own &&
        now < expiresAt(r) &&
        isLive(peers[sessKey(r.own, r.sid)]?.ts, now) &&
        (filter.kind === undefined || r.kind === filter.kind) &&
        (filter.ns === undefined || r.kind.startsWith(`x:${filter.ns}.`))
      ) {
        out.push(r);
      }
    }
  }
  return out;
}

/** One `ls --json` summary entry: no body, only what any client may show (the sanitized fallback). */
export interface StateSummary {
  kind: string;
  at: number;
  expiresAt: number;
  fallback: string;
  bytes: number;
}

/** The bounded `ls` summary of one session's state: at most XSTATE_LS_MAX, newest first. */
export function stateSummaries(recs: readonly XStateRec[]): StateSummary[] {
  return [...recs]
    .sort((a, b) => b.ts - a.ts)
    .slice(0, XSTATE_LS_MAX)
    .map((r) => ({ kind: r.kind, at: r.ts, expiresAt: expiresAt(r), fallback: sanitizePeerText(r.fallback, FALLBACK_MAX), bytes: r.bytes }));
}

/** A kept body as a copy, bounded by the rendered cap again (it was checked when stored). */
export function keptCopy(body: unknown): unknown {
  if (body === undefined) return undefined;
  const s = JSON.stringify(body);
  return s === undefined || Buffer.byteLength(s, "utf8") > Math.max(MAX_RENDERED_BYTES, EXT_STATE_MAX_BYTES) ? undefined : JSON.parse(s);
}
