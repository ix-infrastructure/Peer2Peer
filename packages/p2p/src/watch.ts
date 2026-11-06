// Copyright 2026 Ix Infrastructure Inc.
//
// `p2p watch --session <sid> --jsonl`: the one long-running command.
//
// It stays connected to every relay of the user (reconnecting with backoff,
// silently), handles each delivery (inbound.ts), and prints one compact JSON
// line per accepted event from the shared event log, so events picked up by
// any other `p2p` process are printed too. The cursor lives in
// `<home>/cursors/<sid>.cursor` and advances only after a line was handed to
// stdout, so a restart resumes where it stopped.
//
// Filtering for `--session <sid>`: session events of our own session `sid`,
// events addressed to it (`toSession`: replies in sessions it spoke to,
// notify-when-idle), session events of others' sessions that no local
// session has claimed, and every control event (contacts, circles, held).
//
// Exit codes: 0 when stopped
// (SIGINT/SIGTERM) or when the reader goes away (EPIPE), 1 on a fatal error
// (usage, no identity, every relay refusing this device).

import { watch as watchDir, type FSWatcher } from "node:fs";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { certExpiresWithin, mayRepublish, nowSec } from "@peer2peer/core/v3";
import type { App } from "./app.js";
import { CLOSE_GRACE_MS, REPUBLISH_DOC_WITHIN_SEC } from "./app.js";
import { receiving } from "./inbound.js";
import { answerDeferredWants, renewOpenJoinCaps } from "./circle-ops.js";
import { checkSid, expireSubs } from "./sessions.js";
import type { EventRec } from "./state.js";
import { CliError } from "./errors.js";
import { safeJson } from "./format.js";
import { alertForeignRotations, noteDocRotations, retryRotationJoins } from "./rotation.js";
import { flushOutbox, OUTBOX_RETRY_MS } from "./outbox.js";
import { markRunning, unmarkRunning } from "./running.js";

export interface WatchOptions {
  session: string;
  /** Hands one line to the reader; resolves false when it is gone. */
  write: (line: string) => Promise<boolean>;
  signal: AbortSignal;
  log: (msg: string) => void;
  /**
   * Event log poll interval. A backstop only: the watch wakes at once when this process appends
   * events, and when the log file changes (another `p2p` process handled a delivery).
   */
  pollMs?: number;
}

interface Cursor {
  /** Last printed log position. */
  n: number;
  /** Log position when the cursor was created: older events print only if addressed to this session. */
  start: number;
}

function cursorPath(app: App, sid: string): string {
  return join(app.home, "cursors", `${sid}.cursor`);
}

async function readCursor(app: App, sid: string): Promise<Cursor | undefined> {
  try {
    const v = JSON.parse(await readFile(cursorPath(app, sid), "utf8")) as Cursor;
    if (typeof v.n === "number" && typeof v.start === "number") return v;
  } catch {
    // none yet
  }
  return undefined;
}

async function writeCursor(app: App, sid: string, c: Cursor): Promise<void> {
  const p = cursorPath(app, sid);
  await mkdir(join(app.home, "cursors"), { recursive: true, mode: 0o700 });
  const tmp = `${p}.${process.pid}.tmp`;
  await writeFile(tmp, JSON.stringify(c), { mode: 0o600 });
  await rename(tmp, p);
}

/** Does session `sid` of `self` see this event? */
export function eventFor(e: EventRec, sid: string, self: string, cursor: Cursor): boolean {
  if (e.n <= cursor.n) return false;
  if (e.toSession !== undefined) return e.toSession === sid;
  // The copy of a message for a session that wasn't running (onSessionEnvelope): every other
  // session shows it, never the one it was for (that one has the message itself, if it resumes).
  if (e.data.unclaimedFor === sid) return false;
  // A message for no session: only the sessions whose projects reach its sender (sessions.ts routableSessions).
  if (Array.isArray(e.data.routable) && !e.data.routable.includes(sid)) return false;
  if (e.n <= cursor.start) return false;
  if (e.own !== undefined) return e.own !== self;
  return true;
}

/**
 * The JSON line for an event: `{kind, id, at, ...data, toSession?}`. Fields
 * starting with `_` are local-only (an extension's kept body) and never printed.
 */
export function eventLine(e: EventRec): string {
  const data = Object.fromEntries(Object.entries(e.data).filter(([k]) => !k.startsWith("_")));
  return safeJson({ kind: e.kind, id: e.id, at: e.at, ...data, ...(e.toSession ? { toSession: e.toSession } : {}) });
}

/** How long a stopped watch waits for its own clean-up (the running marker, the app's close) before returning. */
export const WATCH_EXIT_MS = 2 * CLOSE_GRACE_MS;

/** Settles with `p`, or with undefined as soon as `signal` aborts (the work itself goes on, unawaited). */
function untilAborted<T>(p: Promise<T>, signal: AbortSignal): Promise<T | undefined> {
  if (signal.aborted) {
    p.catch(() => undefined);
    return Promise.resolve(undefined);
  }
  return new Promise<T | undefined>((resolve, reject) => {
    const off = () => signal.removeEventListener("abort", onAbort);
    const onAbort = () => {
      off();
      resolve(undefined);
    };
    signal.addEventListener("abort", onAbort);
    p.then(
      (v) => {
        off();
        resolve(v);
      },
      (e) => {
        off();
        if (signal.aborted) resolve(undefined);
        else reject(e);
      },
    );
  });
}

/** `p`, or give up after `ms` (the work goes on, unawaited). */
function within(p: Promise<unknown>, ms: number): Promise<unknown> {
  return Promise.race([p.catch(() => undefined), new Promise((r) => setTimeout(r, ms).unref())]);
}

export async function watch(app: App, opts: WatchOptions): Promise<number> {
  const sid = checkSid(opts.session);
  receiving(app);
  // This session is running while this process lives (running.ts): messages for it are its own.
  app.watching = sid;
  await markRunning(app, sid);
  let exitCode = 0;
  let fatal: string | undefined;
  const stop = new AbortController();
  const onAbort = () => stop.abort();
  opts.signal.addEventListener("abort", onAbort);
  const log = await app.state.get("events");
  let cursor = await readCursor(app, sid);
  if (!cursor) {
    const max = log?.items.at(-1)?.n ?? 0;
    const mine = (log?.items ?? []).filter((e) => e.toSession === sid).map((e) => e.n);
    cursor = { n: mine.length > 0 ? Math.min(...mine) - 1 : max, start: max };
    await writeCursor(app, sid, cursor);
  }
  await app.connect({
    reconnect: true,
    onFatal: (why) => {
      fatal = why;
      stop.abort();
    },
  });
  const timers: NodeJS.Timeout[] = [];
  const every = (ms: number, fn: () => Promise<void>) => {
    const t = setInterval(() => void fn().catch((e) => opts.log(`p2p watch: ${(e as Error).message}`)), ms);
    t.unref();
    timers.push(t);
  };
  every(60_000, () => expireSubs(app));
  // Messages this device couldn't send when they were written (outbox.ts): due ones, with backoff.
  // Back from a stretch with no relay: everything waiting goes out at once, not at its backoff.
  let wasOffline = false;
  every(OUTBOX_RETRY_MS, async () => {
    const up = (app.pool?.connected.length ?? 0) > 0;
    if (!up) wasOffline = true;
    else {
      await flushOutbox(app, { force: wasOffline });
      wasOffline = false;
    }
  });
  // A watch starting is a new connection: everything waiting goes out now, backoff or not.
  void flushOutbox(app, { force: true }).catch(() => {});
  // Re-review N6: wants the first device in line didn't answer in time.
  every(30_000, async () => void (await answerDeferredWants(app)));
  every(10 * 60_000, async () => {
    await refreshContacts(app);
    await renewOpenJoinCaps(app);
  });
  every(3600_000, () => maintain(app));
  void maintain(app).catch(() => {});

  const pollMs = opts.pollMs ?? 300;
  const startedAs = app.userId;
  let polls = 0;
  // Push, not poll: a delivery this process handled, or a change to the event log by another
  // process, wakes the loop at once. The poll stays as a backstop (a file system without change
  // notifications), and the scan itself is unchanged.
  let woke: boolean;
  let wakeUp: (() => void) | undefined;
  const wake = () => {
    woke = true;
    wakeUp?.();
  };
  const offEvents = app.state.onEventsAdded(wake);
  let logWatcher: FSWatcher | undefined;
  try {
    logWatcher = watchDir(join(app.state.dir, "cli"), { persistent: false }, (_ev, name) => {
      if (name === null || String(name) === "events.json") wake();
    });
    logWatcher.on("error", () => {
      logWatcher?.close();
      logWatcher = undefined;
    });
  } catch {
    // no change notifications here: the poll covers it
  }
  try {
    while (!stop.signal.aborted) {
      woke = false;
      // §2.8: this home's identity changed (the user followed a rotation with `p2p identity follow`,
      // or rotated it, in another process). This watch holds the old keys: stop, so the next one
      // starts as the new. (Never follows by itself: pre-release review H2.)
      if (polls++ % 10 === 0) {
        const keys = await untilAborted(app.state.get("keys"), stop.signal);
        if (stop.signal.aborted) break;
        if (app.userId !== startedAs || keys?.userId !== startedAs) {
          opts.log(`p2p watch: this device moved to your new identity; restart watch`);
          stop.abort();
          break;
        }
      }
      // Every wait in here gives way to a stop at once: a state lock held elsewhere (a background
      // refresh, another process) must never keep a stopped watch from returning.
      const doc = await untilAborted(app.state.get("events"), stop.signal);
      if (stop.signal.aborted) break;
      for (const e of doc?.items ?? []) {
        if (stop.signal.aborted) break;
        if (!eventFor(e, sid, app.userId, cursor)) continue;
        const ok = await opts.write(eventLine(e));
        if (!ok) {
          stop.abort();
          break;
        }
        cursor = { ...cursor, n: e.n };
        await untilAborted(writeCursor(app, sid, cursor), stop.signal);
      }
      if (stop.signal.aborted) break;
      // Skip past events not for us, so the scan stays short.
      const last: number = doc?.items.at(-1)?.n ?? cursor.n;
      if (last > cursor.n && !(doc?.items ?? []).some((e) => e.n > cursor!.n && eventFor(e, sid, app.userId, cursor!))) {
        cursor = { ...cursor, n: last };
        await untilAborted(writeCursor(app, sid, cursor), stop.signal);
      }
      if (woke) continue;
      await new Promise<void>((r) => {
        const done = () => {
          clearTimeout(t);
          wakeUp = undefined;
          stop.signal.removeEventListener("abort", done);
          r();
        };
        const t = setTimeout(done, pollMs);
        wakeUp = done;
        stop.signal.addEventListener("abort", done);
      });
    }
  } finally {
    offEvents();
    logWatcher?.close();
    for (const t of timers) clearInterval(t);
    opts.signal.removeEventListener("abort", onAbort);
    // Bounded: a stopped watch returns within WATCH_EXIT_MS whatever its clean-up waits on.
    const deadline = Date.now() + WATCH_EXIT_MS;
    await within(unmarkRunning(app, sid), CLOSE_GRACE_MS);
    await within(app.close(), Math.max(0, deadline - Date.now()));
  }
  if (fatal) {
    opts.log(`p2p watch: ${fatal}`);
    exitCode = 1;
  }
  return exitCode;
}

/** §2.5: refresh friends' and co-members' documents (revocations spread this way). */
export async function refreshContacts(app: App): Promise<void> {
  const users = new Set<string>();
  for (const f of await app.store.listFriendships()) users.add(f.inviter === app.userId ? f.invitee : f.inviter);
  for (const c of await app.store.listCircles()) if (c.joinedByMe) for (const s of Object.keys(c.statements)) users.add(s);
  users.delete(app.userId);
  for (const u of users) {
    const v = await app.view(u);
    if (v) await app.refreshIdentity(u, v.relays, { force: true }).catch(() => undefined);
    // §2.8: a final version carrying a rotation is found here with no push (conflicts are flagged).
    await noteDocRotations(app, u).catch(() => undefined);
  }
  await app.refreshIdentity(app.userId, app.relays, { force: true }).catch(() => undefined);
  await alertForeignRotations(app).catch(() => undefined);
  await retryRotationJoins(app).catch(() => []);
  await app.adoptCertFromDoc();
}

/** Key holders keep the document and certificates fresh (§2.3 renewal, §2.5 re-publish, single writer). */
export async function maintain(app: App): Promise<void> {
  if (!app.isKeyholder) {
    await app.adoptCertFromDoc();
    return;
  }
  // Fail closed (review H2): only on a head confirmed on the relays, and never from a device that's no longer listed.
  try {
    await app.refreshIdentity(app.userId, app.relays, { force: true, strict: true });
  } catch (e) {
    if (e instanceof CliError) return;
    throw e;
  }
  const v = await app.ownView();
  if (!v.devices.includes(app.did) || !v.keyholders.includes(app.did)) return;
  const now = nowSec();
  const certSoon = (v.head.certs ?? []).some((c) => {
    try {
      const exp = JSON.parse(Buffer.from(c.split(".")[1], "base64url").toString()).exp as number;
      return certExpiresWithin({ exp }, 30 * 86_400, now);
    } catch {
      return false;
    }
  });
  const docSoon = v.head.exp - now <= REPUBLISH_DOC_WITHIN_SEC;
  if ((docSoon || certSoon) && mayRepublish(app.did, v.head, now)) {
    await app.publishNext(() => {}).catch((e) => {
      if (!(e instanceof CliError)) throw e;
    });
  }
}
