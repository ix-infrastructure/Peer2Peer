// Copyright 2026 Ix Infrastructure Inc.
//
// Messages to a peer whose session isn't live right now, and messages written while this device
// can't reach a relay: held and delivered later, never refused or lost (P0, a live report: a
// message sent as the peer's connection dropped failed and nothing retried).
//  A. a session not live but seen within OFFLINE_TARGET_MS is sent to anyway (relays hold it);
//     older ones are refused as before; several recent ones are ambiguous;
//  B. the recipient: a session that reconnects gets it; one that ended (not running) leaves a copy
//     addressed to no session, which the user's other sessions show (never the ended one);
//  C. no relay reachable: the sealed envelope waits in the outbox, `watch` sends it later, a second
//     send of the same envelope is dropped by the recipient, and the outbox expires and is capped.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { App } from "../app.js";
import { CliError } from "../errors.js";
import { enqueue, flushOutbox, OUTBOX_MAX, OUTBOX_MAX_BYTES, OUTBOX_PER_RECIPIENT, OUTBOX_RECIPIENT_BYTES, OUTBOX_STUCK_MS, OUTBOX_TTL_MS, OUTBOX_WINDOW, recipientShare } from "../outbox.js";
import { markRunning, sessionEnded } from "../running.js";
import { sendMessage, sessionRef, OFFLINE_TARGET_MS } from "../sessions.js";
import { sessKey } from "../state.js";
import { watch } from "../watch.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-offline.test/v3";
let relay: TestRelay;
let ann: User;
let ben: User;
const ids: Record<string, string> = {};

/** Ben's record of Ann's session `sid` says it was last seen `agoMs` ago. */
const lastSeen = async (sid: string, agoMs: number) => {
  const app = await ben.app();
  await app.state.update("peers", (cur = {}) => {
    const k = sessKey(ids.ann, sid);
    return { next: { ...cur, [k]: { ...cur[k], ts: Date.now() - agoMs } }, result: undefined };
  });
};
const annEvents = async () => ((await (await ann.app()).state.get("events"))?.items ?? []);
const textsOf = async (text: string) => (await annEvents()).filter((e) => e.kind === "p2p.message" && e.data.text === text);

describe("offline peers and an offline sender", () => {
  beforeAll(async () => {
    relay = await startRelay(R);
    const t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    ann = new User("ann", t);
    ben = new User("ben", t);
    for (const u of [ann, ben]) ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
    const code = (await ann.ok(["invite"])).code as string;
    await ben.ok(["join", "--confirmed", code]);
    await ann.ok(["friends"]);
    // Two sessions of Ann's that Ben sees.
    for (const sid of ["a1", "a2"]) {
      await ann.ok(["session", "roster", sid, "--add", ids.ben]);
      await ann.ok(["status", "--session", sid, "--state", "idle", "--label", sid]);
    }
    await ben.ok(["session", "roster", "b1", "--add", ids.ann]);
    await ben.ok(["ls"]);
  }, 90_000);

  afterAll(async () => {
    await relay?.close();
    ann?.cleanup();
    ben?.cleanup();
  });

  it("A: a session seen recently but not live gets the message (held by the relays), with when it was last seen", async () => {
    await lastSeen("a1", 10 * 60_000);
    const r = await ben.ok(["send", "--from-session", "b1", "--to", `${ids.ann}/a1`, "--stdin", "--json"], { stdin: "while you were away" });
    expect(r).toMatchObject({ delivered: true, queued: true, state: "offline", to: { sid: "a1" } });
    expect(Date.now() - r.lastSeen).toBeGreaterThan(9 * 60_000);
    expect(r.expiresAt - Date.now()).toBeGreaterThan(OUTBOX_TTL_MS - 60_000);
    await ann.ok(["ls"]);
    const got = await textsOf("while you were away");
    expect(got.filter((e) => e.toSession === "a1")).toHaveLength(1);
  }, 60_000);

  it("A: older than OFFLINE_TARGET_MS is refused as before; two recent ones are ambiguous (with when each was seen)", async () => {
    await lastSeen("a1", OFFLINE_TARGET_MS + 60_000);
    await lastSeen("a2", OFFLINE_TARGET_MS + 60_000);
    const old = await ben.run(["send", "--from-session", "b1", "--to", `${ids.ann}/a1`, "--stdin", "--json"], { stdin: "too late" });
    expect(old.code).toBe(1);
    expect(old.json.error).toBe("not_found");
    await lastSeen("a1", 5 * 60_000);
    await lastSeen("a2", 7 * 60_000);
    const two = await ben.run(["send", "--from-session", "b1", "--to", ids.ann, "--stdin", "--json"], { stdin: "which one" });
    expect(two.json.error).toBe("ambiguous");
    expect(two.json.candidates.map((c: { sid: string; state: string }) => `${c.sid}:${c.state}`).sort()).toEqual(["a1:offline", "a2:offline"]);
    // With exactly one recent session, a send without a ref goes to it.
    await lastSeen("a2", OFFLINE_TARGET_MS + 60_000);
    const one = await ben.ok(["send", "--from-session", "b1", "--to", ids.ann, "--stdin", "--json"], { stdin: "the only one" });
    expect(one).toMatchObject({ queued: true, state: "offline", to: { sid: "a1" } });
  }, 60_000);

  it("B: a session that reconnects (same sid, its cursor kept) prints the message that came while it was away", async () => {
    // a1's watch ran before (its cursor exists) and stopped: a message arrives meanwhile.
    const app0 = await ann.app();
    await app0.load();
    const ctl0 = new AbortController();
    const first = watch(app0, { session: "a1", signal: ctl0.signal, log: () => {}, write: async () => true, pollMs: 50 });
    await new Promise((r) => setTimeout(r, 800));
    ctl0.abort();
    await first;
    await lastSeen("a1", 3 * 60_000);
    await ben.ok(["send", "--from-session", "b1", "--to", `${ids.ann}/a1`, "--stdin"], { stdin: "back again" });
    const app = await ann.app();
    await app.load();
    const lines: string[] = [];
    const ctl = new AbortController();
    const running = watch(app, { session: "a1", signal: ctl.signal, log: () => {}, write: async (l) => (lines.push(l), true), pollMs: 50 });
    const end = Date.now() + 8000;
    while (Date.now() < end && !lines.some((l) => l.includes("back again"))) await new Promise((r) => setTimeout(r, 50));
    ctl.abort();
    await running;
    const mine = lines.filter((l) => l.includes("back again"));
    expect(mine).toHaveLength(1);
    expect(JSON.parse(mine[0])).toMatchObject({ kind: "p2p.message", toSession: "a1" });
  }, 60_000);

  it("B: for a session that ended (not running), a copy for no session is logged; other sessions show it, the ended one doesn't", async () => {
    // a2 ended: its watch's marker names a process that is gone.
    mkdirSync(join(ann.home, "cursors"), { recursive: true });
    writeFileSync(join(ann.home, "cursors", "a2.watch"), JSON.stringify({ pid: 2 ** 22 + 4242, started: 1 }));
    await lastSeen("a1", OFFLINE_TARGET_MS + 60_000);
    await lastSeen("a2", 2 * 60_000);
    await ben.ok(["send", "--from-session", "b1", "--to", `${ids.ann}/a2`, "--stdin"], { stdin: "for an ended session" });
    await ann.ok(["ls"]);
    const got = await textsOf("for an ended session");
    expect(got.filter((e) => e.toSession === "a2")).toHaveLength(1);
    const copy = got.filter((e) => e.toSession === undefined);
    expect(copy).toHaveLength(1);
    expect(copy[0].data.unclaimedFor).toBe("a2");
    expect(copy[0].own).toBeUndefined(); // shown by every watch, not one session's own
    // The user's current session (a3, a fresh watch) prints it as a message for no session.
    const app = await ann.app();
    await app.load();
    const lines: string[] = [];
    const ctl = new AbortController();
    const cur = app.state.get("events");
    const before = (await cur)?.items.at(-1)?.n ?? 0;
    // A watch only shows control events after its cursor starts: start a3 before the next one.
    const running = watch(app, { session: "a3", signal: ctl.signal, log: () => {}, write: async (l) => (lines.push(l), true), pollMs: 50 });
    await new Promise((r) => setTimeout(r, 600));
    writeFileSync(join(ann.home, "cursors", "a2.watch"), JSON.stringify({ pid: 2 ** 22 + 4242, started: 1 }));
    await ben.ok(["send", "--from-session", "b1", "--to", `${ids.ann}/a2`, "--stdin"], { stdin: "second for the ended one" });
    const end = Date.now() + 8000;
    while (Date.now() < end && !lines.some((l) => l.includes("second for the ended one"))) await new Promise((r) => setTimeout(r, 50));
    ctl.abort();
    await running;
    const shown = lines.filter((l) => l.includes("second for the ended one")).map((l) => JSON.parse(l));
    expect(shown).toHaveLength(1);
    expect(shown[0]).toMatchObject({ kind: "p2p.message", unclaimedFor: "a2", from: { userId: ids.ben } });
    expect(shown[0].toSession).toBeUndefined();
    expect(before).toBeGreaterThan(0);
  }, 60_000);

  it("B: for a session that is running, no copy", async () => {
    await lastSeen("a2", 2 * 60_000);
    // a2 is running: its marker names this (live) process.
    writeFileSync(join(ann.home, "cursors", "a2.watch"), JSON.stringify({ pid: process.pid, started: Math.round(Date.now() - process.uptime() * 1000) }));
    await ben.ok(["send", "--from-session", "b1", "--to", `${ids.ann}/a2`, "--stdin"], { stdin: "it is running" });
    await ann.ok(["ls"]);
    const got = await textsOf("it is running");
    expect(got).toHaveLength(1);
    expect(got[0].toSession).toBe("a2");
  }, 60_000);

  it("C: no relay reachable: queued in the outbox; watch sends it once a relay is back; a second send of it is dropped", async () => {
    await lastSeen("a2", 2 * 60_000);
    // Ben's device can't reach any relay (nothing listens on that port).
    const offline = new App({ env: { ...ben.env, P2P_RELAY_TRANSPORT: JSON.stringify({ [R]: "ws://127.0.0.1:9/v3" }), P2P_CONNECT_TIMEOUT_MS: "500" }, io: ben.io({ out: [], err: [] }) });
    await offline.load();
    let r;
    try {
      r = await sendMessage(offline, { fromSession: "b1", to: `${ids.ann} [${sessionRef(ids.ann, "a2")}]`, text: "written offline" });
    } finally {
      await offline.close();
    }
    expect(r).toMatchObject({ delivered: false, queued: true, state: "outbox", relays: 0 });
    const app = await ben.app();
    const items = (await app.state.get("outbox"))?.items ?? [];
    expect(items.length).toBeGreaterThan(0);
    const env = items[0].env;
    expect(await textsOf("written offline")).toHaveLength(0);
    // Back online: watch sends it.
    const online = await ben.app();
    await online.load();
    const ctl = new AbortController();
    const running = watch(online, { session: "b1", signal: ctl.signal, log: () => {}, write: async () => true, pollMs: 50 });
    const end = Date.now() + 10_000;
    while (Date.now() < end && ((await (await ben.app()).state.get("outbox"))?.items.length ?? 0) > 0) await new Promise((r) => setTimeout(r, 100));
    expect((await (await ben.app()).state.get("outbox"))?.items ?? []).toHaveLength(0);
    // The same sealed envelope again (a lost answer, a second process): the recipient drops it.
    await online.pool!.sendEnvelope(env, ids.ann, items[0].tdid, "msg", items[0].targets);
    ctl.abort();
    await running;
    await ann.ok(["ls"]);
    await ann.ok(["ls"]);
    expect((await textsOf("written offline")).filter((e) => e.toSession === "a2")).toHaveLength(1);
    // The session that wrote it hears it went out (data only).
    const notes = ((await (await ben.app()).state.get("events"))?.items ?? []).filter((e) => e.kind === "p2p.outbox");
    expect(notes.at(-1)).toMatchObject({ toSession: "b1", data: { state: "delivered", to: { sid: "a2" } } });
  }, 60_000);

  it("C: the outbox is capped per recipient, and expires after OUTBOX_TTL_MS with a notice", async () => {
    const app = await ben.app();
    await app.load();
    const dest = { userId: ids.ann, address: "ann", own: ids.ann, sid: "a2", ref: "000000" };
    const copy = (i: number) => ({ did: "d_x", env: `env-${i}-${"x".repeat(10)}`, targets: [{ relay: R }] });
    for (let i = 0; i < OUTBOX_PER_RECIPIENT; i++) await enqueue(app, [copy(i)], { kind: "msg", dest, fromSession: "b1" });
    await expect(enqueue(app, [copy(999)], { kind: "msg", dest, fromSession: "b1" })).rejects.toThrow(CliError);
    await expect(enqueue(app, [copy(999)], { kind: "msg", dest, fromSession: "b1" })).rejects.toThrow(/outbox is full/);
    // A week on: expired, gone, and the writing session is told.
    await app.connect();
    try {
      const r = await flushOutbox(app, { now: Date.now() + OUTBOX_TTL_MS + 1000 });
      expect(r.expired).toBe(OUTBOX_PER_RECIPIENT);
    } finally {
      await app.close();
    }
    expect((await (await ben.app()).state.get("outbox"))?.items ?? []).toHaveLength(0);
    const notes = ((await (await ben.app()).state.get("events"))?.items ?? []).filter((e) => e.kind === "p2p.outbox" && e.data.state === "expired");
    expect(notes.length).toBeGreaterThan(0);
  }, 60_000);

  // ---------------------------------------------------------------------------------------------
  // pre-release review: every queued item is re-checked before each retry (O1), stays inside the replay
  // window (O2), and no single recipient holds the outbox (O5); marker paths are session ids (O4).

  /** Queues one message for Ann's session a2 while Ben's device can't reach a relay. */
  const queueOffline = async (text: string) => {
    await lastSeen("a2", 2 * 60_000);
    const offline = new App({ env: { ...ben.env, P2P_RELAY_TRANSPORT: JSON.stringify({ [R]: "ws://127.0.0.1:9/v3" }), P2P_CONNECT_TIMEOUT_MS: "500" }, io: ben.io({ out: [], err: [] }) });
    await offline.load();
    try {
      const r = await sendMessage(offline, { fromSession: "b1", to: `${ids.ann} [${sessionRef(ids.ann, "a2")}]`, text });
      expect(r).toMatchObject({ queued: true, state: "outbox" });
    } finally {
      await offline.close();
    }
  };
  /** One flush from an online App, `patch` applied to it first; what became of the outbox. */
  const flushWith = async (patch: (app: App) => void = () => {}, connected: (app: App) => void = () => {}) => {
    const app = await ben.app();
    await app.load();
    patch(app);
    await app.connect();
    connected(app);
    try {
      return await flushOutbox(app, { force: true });
    } finally {
      await app.close();
    }
  };
  const outboxItems = async () => (await (await ben.app()).state.get("outbox"))?.items ?? [];
  const lastNote = async () => ((await (await ben.app()).state.get("events"))?.items ?? []).filter((e) => e.kind === "p2p.outbox").at(-1);

  it("O1: a device no longer on the recipient's document: refused, never sent", async () => {
    await queueOffline("device revoked meanwhile");
    // Ann's current document no longer lists the device it was sealed to (as after a revoke); the
    // relay itself would still take it for that mailbox.
    const r = await flushWith((app) => {
      const real = app.refreshIdentity.bind(app);
      app.refreshIdentity = async (u, relays, opts) => {
        const v = await real(u, relays, opts);
        return v && u === ids.ann ? ({ ...v, devices: [] } as typeof v) : v;
      };
    });
    expect(r).toMatchObject({ sent: 0, failed: 1 });
    expect(await outboxItems()).toHaveLength(0);
    expect(await lastNote()).toMatchObject({ data: { state: "refused" } });
    await ann.ok(["ls"]);
    expect(await textsOf("device revoked meanwhile")).toHaveLength(0);
  }, 60_000);

  it("O1: a recipient whose identity rotated meanwhile: refused, never sent", async () => {
    await queueOffline("rotated meanwhile");
    const r = await flushWith((app) => {
      const real = app.refreshIdentity.bind(app);
      // Ann's newest document now carries a rotation statement (§2.8).
      app.refreshIdentity = async (u, relays, opts) => {
        const v = await real(u, relays, opts);
        return v && u === ids.ann ? ({ ...v, rotations: [{ jws: "x" }] } as unknown as typeof v) : v;
      };
    });
    expect(r).toMatchObject({ sent: 0, failed: 1 });
    await ann.ok(["ls"]);
    expect(await textsOf("rotated meanwhile")).toHaveLength(0);
  }, 60_000);

  it("O1: blocked after it was queued: refused, never sent", async () => {
    await queueOffline("blocked meanwhile");
    await ben.ok(["block", ids.ann]);
    try {
      const r = await flushWith();
      expect(r).toMatchObject({ sent: 0, failed: 1 });
      expect(await outboxItems()).toHaveLength(0);
    } finally {
      await ben.ok(["unblock", ids.ann]);
    }
    await ann.ok(["ls"]);
    expect(await textsOf("blocked meanwhile")).toHaveLength(0);
  }, 60_000);

  it("O2: queued, then the session's seq moved past the recipient's window: expired, not 'delivered'; queuing one already past it is refused", async () => {
    await queueOffline("outrun by later sends");
    const [item] = await outboxItems();
    const app = await ben.app();
    const bump = async (n: number) =>
      app.state.update("seq", (cur = {}) => ({ next: { ...cur, [sessKey(ids.ann, "a2")]: (cur[sessKey(ids.ann, "a2")] ?? 0) + n }, result: undefined }));
    await bump(OUTBOX_WINDOW + 10);
    const r = await flushWith();
    expect(r.expired).toBe(1);
    expect(r.sent).toBe(0);
    expect(await lastNote()).toMatchObject({ data: { state: "expired" } });
    await expect(enqueue(app, [{ did: item.tdid, env: item.env, targets: item.targets }], { kind: "msg", dest: item.dest, fromSession: "b1" })).rejects.toThrow(/would drop it as too old/);
  }, 60_000);

  it("O5: no recipient holds more than its share of bytes; one failing for an hour while our relays work expires early", async () => {
    const app = await ben.app();
    await app.load();
    const dest = { userId: ids.ann, address: "ann", own: ids.ann, sid: "a9", ref: "000000" };
    const big = (i: number) => ({ did: "d_x", env: `${i}-${"x".repeat(90 * 1024)}`, targets: [{ relay: R }] });
    await enqueue(app, [big(1)], { kind: "msg", dest, fromSession: "b1" });
    await enqueue(app, [big(2)], { kind: "msg", dest, fromSession: "b1" });
    await expect(enqueue(app, [big(3)], { kind: "msg", dest, fromSession: "b1" })).rejects.toThrow(/outbox is full/);
    expect(OUTBOX_RECIPIENT_BYTES).toBeLessThan(210 * 1024);
    // Stuck: failing for more than OUTBOX_STUCK_MS while this device was online.
    await app.state.update("outbox", (cur = { items: [] }) => ({ next: { items: cur.items.map((i) => ({ ...i, failingSince: Date.now() - OUTBOX_STUCK_MS - 1000 })) }, result: undefined }));
    const r = await flushWith();
    expect(r.expired).toBe(2);
    expect(await outboxItems()).toHaveLength(0);
  }, 60_000);

  it("O4: a marker is only ever named by a session id", async () => {
    const app = await ann.app();
    expect(sessionEnded(app, "../../etc/passwd")).toBe(false);
    expect(sessionEnded(app, "..")).toBe(false);
    await expect(markRunning(app, "../x")).rejects.toThrow(/not a session id/);
  });

  // pre-release re-review lows (P1-P5).

  it("P2: the recipient moved relays since it was sealed: sent over the relays of their current document", async () => {
    await queueOffline("after a relay move");
    const app = await ben.app();
    // Sealed when their document named a relay they've since left.
    await app.state.update("outbox", (cur = { items: [] }) => ({ next: { items: cur.items.map((i) => ({ ...i, targets: [{ relay: "wss://relay-left.test/v3" }] })) }, result: undefined }));
    const r = await flushWith();
    expect(r).toMatchObject({ sent: 1, failed: 0 });
    await ann.ok(["ls"]);
    expect((await textsOf("after a relay move")).filter((e) => e.toSession === "a2")).toHaveLength(1);
  }, 60_000);

  it("P1: the document can't be refreshed and the one held is stale: kept for a later round, not refused", async () => {
    await queueOffline("held while unsure");
    const app = await ben.app();
    await app.state.update("fetched", (cur = {}) => ({ next: { ...cur, [ids.ann]: Date.now() - 3600_000 }, result: undefined }));
    const r = await flushWith((a) => {
      a.refreshIdentity = async () => {
        throw new Error("fetch failed");
      };
    });
    expect(r).toMatchObject({ sent: 0, failed: 0, expired: 0 });
    expect(await outboxItems()).toHaveLength(1);
    // Refreshable again: it goes out.
    expect(await flushWith()).toMatchObject({ sent: 1 });
    expect(await outboxItems()).toHaveLength(0);
  }, 60_000);

  it("P5: one refresh per recipient per round, however many of their items", async () => {
    await queueOffline("one of two");
    await queueOffline("two of two");
    let refreshes = 0;
    const r = await flushWith((a) => {
      const real = a.refreshIdentity.bind(a);
      a.refreshIdentity = async (u, relays, opts) => {
        if (u === ids.ann) refreshes++;
        return real(u, relays, opts);
      };
    });
    expect(r.sent).toBe(2);
    expect(refreshes).toBe(1);
  }, 60_000);

  it("P3: only answered refusals run toward the early expiry; a timeout (an outage) breaks the run and keeps the 7 days", async () => {
    await queueOffline("through an outage");
    const failWith = (code: string) => (a: App) => {
      a.pool!.sendEnvelope = async () => ({ sent: [], errors: [{ relay: R, code }] });
    };
    // Answered and refused: the run starts.
    await flushWith(undefined, failWith("relay-error"));
    const [started] = await outboxItems();
    expect(started.failingSince).toBeDefined();
    // A timeout: an outage, not a refusal. The run is broken.
    await flushWith(undefined, failWith("timeout"));
    const [broken] = await outboxItems();
    expect(broken.failingSince).toBeUndefined();
    // Timeouts for over an hour: never expired early.
    const app = await ben.app();
    await app.state.update("outbox", (cur = { items: [] }) => ({ next: { items: cur.items.map((i) => ({ ...i, queuedAt: Date.now() - 2 * OUTBOX_STUCK_MS })) }, result: undefined }));
    const r = await flushWith(undefined, failWith("timeout"));
    expect(r.expired).toBe(0);
    expect(await outboxItems()).toHaveLength(1);
    await flushWith();
    expect(await outboxItems()).toHaveLength(0);
  }, 60_000);

  it("P4: a recipient gets 1/20 of the outbox, half that while it is more than half full", async () => {
    expect(recipientShare(0, 0)).toEqual({ items: OUTBOX_MAX / 20, bytes: OUTBOX_RECIPIENT_BYTES });
    expect(recipientShare(OUTBOX_MAX / 2 + 1, 0)).toEqual({ items: OUTBOX_MAX / 40, bytes: OUTBOX_RECIPIENT_BYTES / 2 });
    expect(recipientShare(0, OUTBOX_MAX_BYTES / 2 + 1).items).toBe(OUTBOX_MAX / 40);
    const app = await ben.app();
    await app.load();
    const copy = (u: number, i: number) => ({ did: "d_x", env: `p4-${u}-${i}`, targets: [{ relay: R }] });
    const other = (u: number) => ({ userId: `p2p:${String(u).padStart(52, "q")}`, address: `u${u}`, own: `p2p:${String(u).padStart(52, "q")}`, sid: "s", ref: "000000" });
    try {
      // Ten others with their full share each (half the outbox), and one more item: past half.
      for (let u = 0; u < 10; u++) for (let i = 0; i < OUTBOX_PER_RECIPIENT; i++) await enqueue(app, [copy(u, i)], { kind: "msg", dest: other(u), fromSession: "b1" });
      await enqueue(app, [copy(10, 0)], { kind: "msg", dest: other(10), fromSession: "b1" });
      const dest = { userId: ids.ann, address: "ann", own: ids.ann, sid: "a8", ref: "000000" };
      for (let i = 0; i < OUTBOX_PER_RECIPIENT / 2; i++) await enqueue(app, [copy(99, i)], { kind: "msg", dest, fromSession: "b1" });
      await expect(enqueue(app, [copy(99, 99)], { kind: "msg", dest, fromSession: "b1" })).rejects.toThrow(/at most 5 messages per person while it is this full/);
    } finally {
      await app.state.update("outbox", () => ({ next: { items: [] }, result: undefined }));
    }
  }, 60_000);

  // Last: it ends the friendship this file's other tests use.
  it("O1: unfriended after it was queued: refused, never sent", async () => {
    await queueOffline("unfriended meanwhile");
    await ben.ok(["unfriend", ids.ann]);
    const r = await flushWith();
    expect(r).toMatchObject({ sent: 0, failed: 1 });
    expect(await outboxItems()).toHaveLength(0);
    await ann.ok(["ls"]);
    expect(await textsOf("unfriended meanwhile")).toHaveLength(0);
  }, 60_000);
});
