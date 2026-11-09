// Copyright 2026 Ix Infrastructure Inc.
//
// Graph memory (epic #41 piece 2): while a session runs, its context goes into the person's
// LOCAL Ix graph: its record (start, end, repo, branch), its status one-liners and the files it
// edits. Notes peers share go there only when the person imports them (`p2p ix import`, ext-ix).
// Message bodies never do.
//
// Off the hook path, best effort:
//   - Nothing on the hook path changes. `p2p status` already keeps this device's own statuses
//     (`peers`, self); `p2p watch`, the one long-running command, reads them every
//     GRAPH_MEMORY_TICK_MS, turns what changed since it last looked into items, and queues them
//     (`graphMemory`, under the state lock, so two watches never queue the same thing twice).
//   - The queue is bounded (GRAPH_MEMORY_QUEUE_MAX): past it, new items are dropped and counted
//     (`p2p doctor` says how many, and why). So are items a write refused or failed.
//   - The same watch drains it, a batch at a time, one at a time per process, through the
//     extension's memory writer (ExtMemory: ext-ix's runs OSS `ix note` / `ix session`).
//   - Without the Ix extension, without Ix, or with an Ix that has no local `ix note` (or whose
//     `ix note` is Ix Pro's, the cloud), nothing is gathered at all: nothing changes. The doctor
//     says why.
//
// Local only: each batch is for one session, and its graph target (projects.ts graphTarget, the
// chokepoint) must be local, or the batch is dropped (`not_local`) and nothing is asked of the
// extension. The extension checks the target again. No shared target exists today; the refusal
// is explicit so a later shared graph can't receive memory by accident.

import { sanitizePeerText } from "@peer2peer/core/v3";
import type { App } from "./app.js";
import { graphMemoryEnabled } from "./config.js";
import { extContext } from "./ext-host.js";
import { memoryOf, type ExtMemory, type ExtMemoryItem, type ExtMemoryUnavailable, type P2PExtension } from "./extensions.js";
import { graphTarget, sessionCeiling, sessionDirs, type GraphTarget } from "./projects.js";
import { sessionEnded } from "./running.js";
import type { PeerStatusRec } from "./state.js";

/** How often `p2p watch` gathers and drains (P2P_IX_MEMORY_TICK_MS, 1-60 s, for tests). */
export const GRAPH_MEMORY_TICK_MS = 5_000;
/** At most this many items wait; past it, new ones are dropped (counted as `queue_full`). */
export const GRAPH_MEMORY_QUEUE_MAX = 64;
/** At most this many items are handed over in one drain. */
export const GRAPH_MEMORY_BATCH = 16;
/** At most this many sessions are tracked (the oldest ended ones go first). */
export const GRAPH_MEMORY_SESSIONS_MAX = 64;
/** At most this many files are remembered as recorded per session. */
export const GRAPH_MEMORY_FILES_MAX = 200;
/** A session first seen with no status newer than this isn't recorded (one from before an upgrade). */
export const GRAPH_MEMORY_FRESH_MS = 6 * 3600_000;
/** While memory is unavailable, it is asked again this often (Ix installed or upgraded meanwhile). */
export const GRAPH_MEMORY_RECHECK_MS = 5 * 60_000;
/** One drain gives up waiting on the extension after this long (its `ix` calls are bounded too). */
export const GRAPH_MEMORY_DRAIN_MS = 120_000;

export type GraphMemoryItem = ExtMemoryItem & { sid: string };

export interface GraphMemorySession {
  /** When the session's start was queued (ms). */
  start: number;
  /** The last status one-liner queued. */
  summary?: string;
  /** Files already queued (capped). */
  files: string[];
  /** When its end was queued. */
  ended?: number;
}

export interface GraphMemoryDoc {
  v: 1;
  sessions: Record<string, GraphMemorySession>;
  queue: GraphMemoryItem[];
  /** Items written to the local graph. */
  written: number;
  /** Items dropped, by reason (queue_full, not_local, ix_failed, ix_timeout, graph_target, ix_unconfirmed, …). */
  dropped: Record<string, number>;
  lastWriteAt?: number;
  lastDropAt?: number;
  /** Why memory is off now (no Ix, an Ix without local notes, Ix Pro), as the extension said it. */
  unavailable?: { reason: string; message: string; at: number };
  /**
   * Sessions a drain is writing now, until when (ms): one writer per session at a time, across
   * every process (take() skips them), so a session's record is never created twice.
   */
  leases?: Record<string, number>;
}

const emptyDoc = (): GraphMemoryDoc => ({ v: 1, sessions: {}, queue: [], written: 0, dropped: {} });

function docOf(cur: GraphMemoryDoc | undefined): GraphMemoryDoc {
  if (!cur || cur.v !== 1 || typeof cur !== "object") return emptyDoc();
  return {
    v: 1,
    sessions: cur.sessions && typeof cur.sessions === "object" ? { ...cur.sessions } : {},
    queue: Array.isArray(cur.queue) ? [...cur.queue] : [],
    written: typeof cur.written === "number" ? cur.written : 0,
    dropped: cur.dropped && typeof cur.dropped === "object" ? { ...cur.dropped } : {},
    ...(cur.lastWriteAt ? { lastWriteAt: cur.lastWriteAt } : {}),
    ...(cur.lastDropAt ? { lastDropAt: cur.lastDropAt } : {}),
    ...(cur.unavailable ? { unavailable: cur.unavailable } : {}),
    ...(cur.leases && typeof cur.leases === "object" ? { leases: { ...cur.leases } } : {}),
  };
}

const short = (s: unknown, max: number) => (typeof s === "string" ? sanitizePeerText(s, max).trim() : "");

/** Every file a status names: its own and its agents'. */
function statusFiles(rec: PeerStatusRec): string[] {
  const out = new Set<string>();
  for (const f of rec.status.files ?? []) if (typeof f === "string") out.add(f);
  for (const a of rec.status.agents ?? []) for (const f of a.files ?? []) if (typeof f === "string") out.add(f);
  return [...out];
}

/**
 * What changed in this device's own sessions since the last look, as items, queued (pure, for
 * tests: `ended` says whether a session's watch is gone). Returns the next doc and how many were
 * queued and dropped. Only sessions `recordable` says yes to are gathered: a session whose project
 * ceiling isn't shared (a private or unmapped project, `.p2p-private`, not bound yet) is never
 * recorded, and one that becomes so stops being recorded (fail closed: its context never reaches a
 * graph that a shared session's agent could read and pass on).
 */
export function gather(doc: GraphMemoryDoc, recs: readonly PeerStatusRec[], ended: (sid: string) => boolean, now = Date.now(), recordable: (sid: string) => boolean = () => true): { doc: GraphMemoryDoc; queued: number; dropped: number } {
  const next = docOf(doc);
  let queued = 0;
  let dropped = 0;
  const push = (item: GraphMemoryItem) => {
    if (next.queue.length >= GRAPH_MEMORY_QUEUE_MAX) {
      next.dropped.queue_full = (next.dropped.queue_full ?? 0) + 1;
      next.lastDropAt = now;
      dropped++;
      return;
    }
    next.queue.push(item);
    queued++;
  };
  for (const rec of recs) {
    const sid = rec.sid;
    if (!recordable(sid)) continue;
    let s = next.sessions[sid];
    const isEnded = ended(sid);
    if (!s) {
      // A session from before this ran (or one already over): not recorded after the fact.
      if (isEnded || now - rec.ts > GRAPH_MEMORY_FRESH_MS) continue;
      s = { start: now, files: [] };
      push({ sid, kind: "start", at: rec.ts, label: short(rec.status.label, 64) || "session", ...(rec.status.repo ? { repo: short(rec.status.repo, 200) } : {}), ...(rec.status.branch ? { branch: short(rec.status.branch, 128) } : {}) });
    }
    if (s.ended) continue;
    const summary = short(rec.status.summary, 280);
    if (summary && summary !== s.summary) {
      push({ sid, kind: "status", at: rec.status.summaryAt ?? rec.ts, summary });
      s = { ...s, summary };
    }
    const known = new Set(s.files);
    const fresh = statusFiles(rec).filter((f) => !known.has(f));
    if (fresh.length > 0) {
      push({ sid, kind: "files", at: rec.ts, files: fresh });
      s = { ...s, files: [...s.files, ...fresh].slice(-GRAPH_MEMORY_FILES_MAX) };
    }
    if (isEnded) {
      push({ sid, kind: "end", at: rec.ts });
      s = { ...s, ended: now };
    }
    next.sessions[sid] = s;
  }
  // Bounded: ended sessions a day old go, then the oldest.
  const entries = Object.entries(next.sessions).filter(([, s]) => !(s.ended && now - s.ended > 24 * 3600_000));
  entries.sort((a, b) => a[1].start - b[1].start);
  next.sessions = Object.fromEntries(entries.slice(-GRAPH_MEMORY_SESSIONS_MAX));
  return { doc: next, queued, dropped };
}

/** This device's own sessions' last statuses. */
async function ownRecs(app: App): Promise<PeerStatusRec[]> {
  const peers = (await app.state.get("peers")) ?? {};
  return Object.values(peers).filter((r) => r && r.self === true && r.own === app.userId && r.did === app.did && typeof r.sid === "string" && r.status && typeof r.status === "object");
}

/** Gathers and queues what changed (under the state lock). */
export async function gatherGraphMemory(app: App, now = Date.now()): Promise<{ queued: number; dropped: number }> {
  const recs = await ownRecs(app);
  if (recs.length === 0) return { queued: 0, dropped: 0 };
  // Only sessions whose project ceiling is shared (projects.ts sessionCeiling): private ones never.
  const shared = new Set<string>();
  for (const r of recs) if ((await sessionCeiling(app, r.sid).catch(() => ({ kind: "private" as const }))).kind === "shared") shared.add(r.sid);
  return app.state.update("graphMemory", (cur) => {
    const before = docOf(cur);
    const r = gather(before, recs, (sid) => sessionEnded(app, sid), now, (sid) => shared.has(sid));
    // Unchanged: nothing written (this runs every few seconds).
    const changed = JSON.stringify(r.doc) !== JSON.stringify(before);
    return { ...(changed ? { next: r.doc } : {}), result: { queued: r.queued, dropped: r.dropped } };
  });
}

/** Counts `n` dropped items under `reason`. */
async function countDropped(app: App, reason: string, n: number): Promise<void> {
  if (n <= 0) return;
  const key = /^[a-z_]{1,32}$/.test(reason) ? reason : "other";
  await app.state.update("graphMemory", (cur) => {
    const d = docOf(cur);
    d.dropped[key] = (d.dropped[key] ?? 0) + n;
    d.lastDropAt = Date.now();
    return { next: d, result: undefined };
  });
}

/** Records why memory is off (or that it is on again). */
async function noteAvailability(app: App, u: ExtMemoryUnavailable | undefined): Promise<void> {
  await app.state.update("graphMemory", (cur) => {
    const d = docOf(cur);
    const was = d.unavailable;
    if (!u && !was) return { result: undefined };
    if (u && was && was.reason === u.reason) return { result: undefined };
    if (u) d.unavailable = { reason: short(u.reason, 32) || "unavailable", message: short(u.message, 300), at: Date.now() };
    else delete d.unavailable;
    return { next: d, result: undefined };
  });
}

export interface DrainDeps {
  /** The graph target of a session's batch (default: the chokepoint, projects.ts graphTarget). */
  target?: (sid: string) => Promise<GraphTarget>;
  log?: (msg: string) => void;
  /** One session's time to write (tests); default GRAPH_MEMORY_DRAIN_MS. */
  deadlineMs?: number;
}

/** How long a session's lease lasts: past every drain's own bound, then free again (a crashed writer). */
export const GRAPH_MEMORY_LEASE_MS = 2 * GRAPH_MEMORY_DRAIN_MS + 60_000;

/**
 * One batch: up to GRAPH_MEMORY_BATCH items taken off the queue (they are the taker's now), of
 * sessions no other drain holds a lease on; their leases are taken with them, under the state lock.
 */
async function take(app: App, now = Date.now()): Promise<GraphMemoryItem[]> {
  return app.state.update("graphMemory", (cur) => {
    const d = docOf(cur);
    if (d.queue.length === 0) return { result: [] };
    const leases = Object.fromEntries(Object.entries(d.leases ?? {}).filter(([, until]) => typeof until === "number" && until > now));
    const batch: GraphMemoryItem[] = [];
    const rest: GraphMemoryItem[] = [];
    for (const it of d.queue) (batch.length < GRAPH_MEMORY_BATCH && !leases[it.sid] ? batch : rest).push(it);
    if (batch.length === 0) return { result: [] };
    for (const it of batch) leases[it.sid] = now + GRAPH_MEMORY_LEASE_MS;
    d.queue = rest;
    d.leases = leases;
    return { next: d, result: batch };
  });
}

/** Gives the leases of `sids` back. */
async function release(app: App, sids: readonly string[]): Promise<void> {
  await app.state.update("graphMemory", (cur) => {
    const d = docOf(cur);
    if (!d.leases) return { result: undefined };
    for (const sid of sids) delete d.leases[sid];
    if (Object.keys(d.leases).length === 0) delete d.leases;
    return { next: d, result: undefined };
  });
}

/** `p`, or "timeout" after `ms` (the work goes on: the caller aborts it and waits for it to settle). */
const within = <T>(p: Promise<T>, ms: number): Promise<T | "timeout"> =>
  Promise.race([p, new Promise<"timeout">((r) => setTimeout(() => r("timeout"), ms).unref())]);

/**
 * Hands the next batch to the extension, a session at a time. A session whose graph target isn't
 * local is never handed over: its items are dropped as `not_local`. Returns what happened.
 */
export async function drainGraphMemory(app: App, ext: P2PExtension, mem: ExtMemory, deps: DrainDeps = {}): Promise<{ written: number; dropped: number; unavailable?: ExtMemoryUnavailable }> {
  const batch = await take(app);
  if (batch.length === 0) return { written: 0, dropped: 0 };
  try {
    return await drainBatch(app, ext, mem, batch, deps);
  } finally {
    await release(app, [...new Set(batch.map((i) => i.sid))]).catch(() => undefined);
  }
}

async function drainBatch(app: App, ext: P2PExtension, mem: ExtMemory, batch: GraphMemoryItem[], deps: DrainDeps): Promise<{ written: number; dropped: number; unavailable?: ExtMemoryUnavailable }> {
  const ctx = extContext(app, ext, { out: () => {}, err: (s) => deps.log?.(s) }, true, async () => false);
  const target =
    deps.target ??
    ((sid: string) => {
      const { dirs, over } = sessionDirs(app.env);
      return graphTarget(app, { sid, dirs, over });
    });
  let written = 0;
  let dropped = 0;
  const bySid = new Map<string, ExtMemoryItem[]>();
  for (const { sid, ...item } of batch) bySid.set(sid, [...(bySid.get(sid) ?? []), item]);
  const groups = [...bySid];
  for (let g = 0; g < groups.length; g++) {
    const [sid, items] = groups[g];
    let t: GraphTarget;
    try {
      t = await target(sid);
    } catch {
      t = { kind: "shared", circle: "?", endpoint: "" };
    }
    if (t.kind !== "local") {
      // Explicit: graph memory goes to the local graph only.
      await countDropped(app, "not_local", items.length);
      dropped += items.length;
      continue;
    }
    // A real deadline: past it the writer is told to stop (it checks the signal before every write),
    // and this waits for it to settle, so no write overlaps the next batch or follows the timeout.
    const stop = new AbortController();
    const writing = Promise.resolve()
      .then(() => mem.write(ctx, { sid, items, signal: stop.signal }))
      .catch(() => undefined);
    let r = await within(writing, deps.deadlineMs ?? GRAPH_MEMORY_DRAIN_MS);
    if (r === "timeout") {
      stop.abort();
      const late = await writing;
      // What it wrote before it stopped still counts; the rest timed out.
      const lateOk = late && typeof late === "object" ? Math.max(0, Math.min(items.length, Number(late.written) || 0)) : 0;
      r = { written: lateOk, failed: [{ reason: "timeout", n: items.length - lateOk }] };
    }
    if (r === undefined || typeof r !== "object") {
      await countDropped(app, "ext_failed", items.length);
      dropped += items.length;
      continue;
    }
    const ok = Math.max(0, Math.min(items.length, Number(r.written) || 0));
    written += ok;
    if (ok > 0) {
      await app.state.update("graphMemory", (cur) => {
        const d = docOf(cur);
        d.written += ok;
        d.lastWriteAt = Date.now();
        return { next: d, result: undefined };
      });
    }
    for (const f of Array.isArray(r.failed) ? r.failed : []) {
      const n = Math.max(0, Math.min(items.length, Number(f?.n) || 0));
      await countDropped(app, String(f?.reason ?? "other"), n);
      dropped += n;
    }
    if (r.unavailable) {
      // Whatever is still queued would meet the same answer: off until it is asked again. This
      // batch's other sessions are dropped (counted), never handed over.
      await noteAvailability(app, r.unavailable);
      const left = groups.slice(g + 1).reduce((a, [, its]) => a + its.length, 0);
      await countDropped(app, short(r.unavailable.reason, 32) || "unavailable", left);
      return { written, dropped: dropped + left, unavailable: r.unavailable };
    }
  }
  return { written, dropped };
}

/** The tick interval (P2P_IX_MEMORY_TICK_MS, 1-60 s). */
export function graphMemoryTickMs(env: Record<string, string | undefined>): number {
  const n = Number(env.P2P_IX_MEMORY_TICK_MS);
  return Number.isInteger(n) && n >= 1000 && n <= 60_000 ? n : GRAPH_MEMORY_TICK_MS;
}

/**
 * The loop `p2p watch` runs: `tick()` gathers and drains when memory is on and available (asked of
 * the extension at most every GRAPH_MEMORY_RECHECK_MS while it isn't). Never throws; one tick at a
 * time.
 */
export function graphMemoryLoop(app: App, deps: DrainDeps = {}): { tick(): Promise<void> } {
  let busy = false;
  let okUntil = 0;
  let offUntil = 0;
  return {
    tick: async () => {
      if (busy) return;
      busy = true;
      try {
        if (!graphMemoryEnabled(app.env, app.home)) return;
        const ext = app.extensions?.get("ix");
        const mem = memoryOf(ext);
        if (!ext || !mem) return;
        const now = Date.now();
        if (now < offUntil) return;
        if (now >= okUntil) {
          const ctx = extContext(app, ext, { out: () => {}, err: (s) => deps.log?.(s) }, true, async () => false);
          const a = await within(
            mem.available(ctx).catch((e) => ({ ok: false as const, reason: "ext_failed", message: String((e as Error)?.message ?? e) })),
            GRAPH_MEMORY_DRAIN_MS,
          );
          const u: ExtMemoryUnavailable | undefined = a === "timeout" ? { ok: false, reason: "timeout", message: "Ix didn't answer in time" } : a.ok ? undefined : a;
          await noteAvailability(app, u);
          if (u) {
            offUntil = now + GRAPH_MEMORY_RECHECK_MS;
            return;
          }
          okUntil = now + GRAPH_MEMORY_RECHECK_MS;
        }
        await gatherGraphMemory(app);
        const r = await drainGraphMemory(app, ext, mem, deps);
        if (r.unavailable) {
          okUntil = 0;
          offUntil = Date.now() + GRAPH_MEMORY_RECHECK_MS;
        }
      } catch (e) {
        deps.log?.(`p2p watch: graph memory: ${sanitizePeerText(String((e as Error)?.message ?? e), 200)}`);
      } finally {
        busy = false;
      }
    },
  };
}

/** What `p2p doctor` says about graph memory (undefined: nothing recorded yet). */
export async function graphMemoryReport(app: App): Promise<GraphMemoryDoc | undefined> {
  const d = await app.state.get("graphMemory");
  return d ? docOf(d) : undefined;
}
