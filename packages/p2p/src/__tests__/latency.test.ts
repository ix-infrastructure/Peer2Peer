// Copyright 2026 Ix Infrastructure Inc.
//
// Regression guards for the latency work (bench/latency.mjs measures it; these
// only pin the mechanisms, with generous bounds so a slow machine still passes):
//  - a short command stops draining when its relay says `caught-up` (§5.4)
//    instead of waiting out P2P_DRAIN_QUIET_MS, and still handles what was queued;
//  - `watch` prints an event as soon as it is appended, by this process or
//    another one, instead of at its next poll;
//  - (pre-release soak, tail latency) the backlog drain ends with the backlog, not with
//    what keeps arriving live.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isTransient, receiving } from "../inbound.js";
import { processStartMs } from "../procstart.js";
import { CliError } from "../errors.js";
import { CliState, STATE_BURST } from "../state.js";
import { watch } from "../watch.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-latency.test/v3";
// Far longer than any bound below: a command that waits it out fails the test.
const SLOW_DRAIN = { P2P_DRAIN_QUIET_MS: "6000", P2P_DRAIN_MAX_MS: "9000" };
let relay: TestRelay;
let ann: User;
let ben: User;
const ids: Record<string, string> = {};

describe("latency mechanisms", () => {
  beforeAll(async () => {
    relay = await startRelay(R);
    const t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    ann = new User("ann", t, SLOW_DRAIN);
    ben = new User("ben", t, SLOW_DRAIN);
    for (const u of [ann, ben]) ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
    const code = (await ann.ok(["invite"])).code as string;
    await ben.ok(["join", "--confirmed", code]);
    await ann.ok(["friends"]);
  }, 60_000);

  afterAll(async () => {
    await relay?.close();
    ann?.cleanup();
    ben?.cleanup();
  });

  it("a short command stops draining at the relay's caught-up, after handling what was queued", async () => {
    await ben.ok(["session", "roster", "bs1", "--add", ids.ann]);
    await ben.ok(["status", "--session", "bs1", "--state", "idle", "--label", "api"]);
    // Ann's ls drains Ben's status (queued for her), well before the 6 s quiet period.
    let t0 = Date.now();
    const ls = await ann.ok(["ls"]);
    // Well before the 6 s quiet period it no longer waits for (room for a slow runner).
    expect(Date.now() - t0).toBeLessThan(5000);
    expect(ls.peers.map((p: { own: string; sid: string }) => `${p.own}/${p.sid}`)).toContain(`${ids.ben}/bs1`);
    // A message queued for Ben is handled by his next short command, which also doesn't wait.
    await ann.ok(["send", "--from-session", "as1", "--to", ids.ben, "--stdin"], { stdin: "queued for ben" });
    t0 = Date.now();
    await ben.ok(["friends"]);
    expect(Date.now() - t0).toBeLessThan(5000);
    const app = await ben.app();
    const events = (await app.state.get("events"))?.items ?? [];
    expect(events.some((e) => e.kind === "p2p.message" && e.data.text === "queued for ben")).toBe(true);
  }, 60_000);

  it("watch prints an appended event at once (this process or another), not at its next poll", async () => {
    const app = await ann.app();
    await app.load();
    const lines: { t: number; line: string }[] = [];
    const ctl = new AbortController();
    const running = watch(app, {
      session: "as1",
      signal: ctl.signal,
      log: () => {},
      write: async (line) => {
        lines.push({ t: Date.now(), line });
        return true;
      },
      // A poll this slow would fail both checks below.
      pollMs: 60_000,
    });
    const waitFor = async (id: string) => {
      const end = Date.now() + 5000;
      while (Date.now() < end) {
        const hit = lines.find((l) => l.line.includes(id));
        if (hit) return hit.t;
        await new Promise((r) => setTimeout(r, 10));
      }
      throw new Error(`watch never printed ${id}`);
    };
    // Let it connect and write its cursor.
    await new Promise((r) => setTimeout(r, 500));
    const ev = (id: string) => ({ id, at: Date.now(), kind: "p2p.test", toSession: "as1", data: { id } });
    // Appended by this process (a delivery the watch itself handled).
    let t0 = Date.now();
    await app.state.addEvents([ev("in-process-1")]);
    expect((await waitFor("in-process-1")) - t0).toBeLessThan(1500);
    // Appended by another process on the same home (here: another App, its own state handle).
    const other = await ann.app();
    t0 = Date.now();
    await other.state.addEvents([ev("other-process-1")]);
    expect((await waitFor("other-process-1")) - t0).toBeLessThan(2500);
    ctl.abort();
    expect(await running).toBe(0);
  }, 30_000);

  // pre-release review M1: a handler still running while close() waits for it used to find no pool and
  // open a new one that nobody closed (it then took the next command's deliveries).
  it("a handler running while the command closes uses the closing pool, and opens none of its own", async () => {
    const app = await ann.app();
    await app.load();
    const pool = await app.connect();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let started!: () => void;
    const running = new Promise<void>((r) => (started = r));
    const seen: unknown[] = [];
    app.onEnvelope = async () => {
      started();
      await gate;
      seen.push(await app.connect({ allowNone: true }).catch((e: Error) => e));
      return "keep";
    };
    await ben.ok(["send", "--from-session", "bs1", "--to", ids.ann, "--stdin"], { stdin: "for the closing handler" });
    await running;
    const closing = app.close();
    release();
    await closing;
    expect(seen).toEqual([pool]);
    expect(app.pool).toBeUndefined();
  }, 30_000);

  // pre-release review M2 / M-A: the replay window records an envelope only once it was applied, and a
  // clearly transient local failure (here a full disk while writing its events) is retried.
  const message = async (text: string) => ben.ok(["send", "--from-session", "bs1", "--to", ids.ann, "--stdin"], { stdin: text });
  // Applications only: a session of Ann's that a watch ran earlier in this file has ended, so a
  // message for it is also logged once more for no session (onSessionEnvelope), not applied again.
  const applied = async (text: string) => ((await (await ann.app()).state.get("events"))?.items ?? []).filter((e) => e.data.text === text && e.data.unclaimedFor === undefined).length;
  const gaveUp = async () => (await (await ann.app()).state.get("inbound"))?.gaveUp ?? 0;
  /** One short command on Ann's home whose handling is sabotaged by `patch`. */
  const attempt = async (patch: (app: Awaited<ReturnType<User["app"]>>) => void) => {
    const app = await ann.app();
    await app.load();
    receiving(app);
    patch(app);
    await app.connectAndDrain();
    await app.close();
  };
  const enospc = () => Object.assign(new Error("ENOSPC: no space left on device, write"), { code: "ENOSPC" });

  it("an envelope whose handling failed before it was applied (a full disk) is applied on redelivery", async () => {
    await message("survives a full disk");
    await attempt((app) => {
      app.state.addEvents = async () => {
        throw enospc();
      };
    });
    expect(await applied("survives a full disk")).toBe(0);
    // The next command gets it again from the relay (never acked) and applies it, once.
    await ann.ok(["ls"]);
    await ann.ok(["ls"]);
    expect(await applied("survives a full disk")).toBe(1);
  }, 30_000);

  it("a transient lock error is retried and then applied", async () => {
    await message("survives a lock timeout");
    await attempt((app) => {
      app.addressOf = async () => {
        throw new Error(`trust store ${app.home} is locked`);
      };
    });
    expect(await applied("survives a lock timeout")).toBe(0);
    await ann.ok(["ls"]);
    expect(await applied("survives a lock timeout")).toBe(1);
  }, 30_000);

  it("a TypeError (a bug) is final at once: acked, not retried, and counted for doctor", async () => {
    const before = await gaveUp();
    await message("hits a bug");
    await attempt((app) => {
      app.addressOf = async () => {
        throw new TypeError("cannot read properties of undefined");
      };
    });
    await ann.ok(["ls"]);
    expect(await applied("hits a bug")).toBe(0);
    expect(await gaveUp()).toBe(before + 1);
  }, 30_000);

  it("a poison envelope is given up and acked after 3 attempts, and counted for doctor", async () => {
    const before = await gaveUp();
    await message("poison");
    const lock = (app: Awaited<ReturnType<User["app"]>>) => {
      app.addressOf = async () => {
        throw new Error(`trust store ${app.home} is locked`);
      };
    };
    for (let i = 0; i < 3; i++) await attempt(lock);
    expect(await gaveUp()).toBe(before);
    // The fourth claim records it as given up (acked, never applied), even with nothing failing now.
    await ann.ok(["ls"]);
    expect(await gaveUp()).toBe(before + 1);
    expect(await applied("poison")).toBe(0);
    // Acked: it doesn't come back.
    await ann.ok(["ls"]);
    expect(await gaveUp()).toBe(before + 1);
    const doctor = await ann.run(["doctor"]);
    expect(JSON.stringify(doctor.json)).toMatch(/couldn't be applied and were dropped|couldn't be applied and was dropped/);
    expect(JSON.stringify(doctor.json)).not.toContain("poison");
  }, 60_000);

  // pre-release review L3: the in-process queue in front of the state lock must not starve other processes.
  it("a burst of state updates from one process leaves another process's update a turn", async () => {
    const dir = mkdtempSync(join(tmpdir(), "p2p-fair-"));
    try {
      const mine = new CliState(dir);
      const theirs = new CliState(dir); // another process: its own handle, the same lock file
      const order: string[] = [];
      const burst = Array.from({ length: STATE_BURST * 5 }, (_, i) => mine.update("spoke", (cur = {}) => (order.push(`m${i}`), { next: { ...cur, [`m${i}`]: "x" }, result: undefined })));
      await new Promise((r) => setTimeout(r, 5));
      const other = theirs.update("spoke", (cur = {}) => (order.push("them"), { next: { ...cur, them: "x" }, result: undefined }));
      await Promise.all([...burst, other]);
      expect(order.indexOf("them")).toBeLessThan(order.length - 1);
      expect(Object.keys((await mine.get("spoke")) ?? {})).toHaveLength(STATE_BURST * 5 + 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);

  it("only clearly local, transient failures are retried; a reused pid isn't the claim's holder", () => {
    expect(isTransient(new CliError("closing", "x"))).toBe(true);
    expect(isTransient(new Error("trust store /x is locked"))).toBe(true);
    expect(isTransient(Object.assign(new Error("busy"), { code: "EBUSY" }))).toBe(true);
    expect(isTransient(new CliError("network", "relay closed the connection"))).toBe(true);
    expect(isTransient(new CliError("unreachable", "can't reach"))).toBe(true);
    expect(isTransient(Object.assign(new Error("x"), { code: "ECONNRESET" }))).toBe(true);
    expect(isTransient(new TypeError("x"))).toBe(false);
    expect(isTransient(new CliError("usage", "x"))).toBe(false);
    expect(isTransient(new Error("malformed roster"))).toBe(false);
    // review L-C: a process's start time, where the platform tells it cheaply.
    if (process.platform === "linux" || process.platform === "darwin") {
      const own = Date.now() - process.uptime() * 1000;
      expect(Math.abs((processStartMs(process.pid) ?? 0) - own)).toBeLessThan(2500);
      expect(processStartMs(2 ** 22 + 12345)).toBeUndefined();
    }
  });

  // A real friend accept must survive a short network drop while it is handled: the inviter's
  // client grants its cap back over the network, and that delivery fails once.
  it("a network failure on the accept path is retried, then the friendship completes", async () => {
    const t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    const cara = new User("cara", t, SLOW_DRAIN);
    try {
      const caraId = (await cara.ok(["init", "--name", "cara", "--relay", R, "--yes"])).userId as string;
      const code = (await ann.ok(["invite", "--no-circle"])).code as string;
      await cara.ok(["join", "--confirmed", code]);
      // Ann's client handles the accept with the network down for its outbound delivery.
      await attempt((app) => {
        app.deliver = async () => {
          throw new CliError("network", "relay closed the connection (1006)");
        };
      });
      const half = (await ann.ok(["friends"])).friends as { userId: string }[];
      // Retried by that `friends` (the first attempt released its claim) and applied in full.
      expect(half.map((f) => f.userId)).toContain(caraId);
      await cara.ok(["friends"]);
      const theirs = (await cara.ok(["friends"])).friends as { userId: string; canMessage: boolean }[];
      expect(theirs.find((f) => f.userId === ids.ann)?.canMessage).toBe(true);
    } finally {
      cara.cleanup();
    }
  }, 60_000);

  // pre-release soak (tail latency): a short command waits for the backlog, not for what keeps arriving
  // live while it handles it.
  it("the backlog drain ends with the backlog: envelopes arriving live after caught-up don't hold it", async () => {
    await ann.ok(["ls"]); // nothing else queued for Ann
    await message("backlog one");
    const app = await ann.app();
    await app.load();
    const gate = (() => {
      let open!: () => void;
      const p = new Promise<void>((r) => (open = r));
      return { p, open };
    })();
    const live = (() => {
      let open!: () => void;
      const p = new Promise<void>((r) => (open = r));
      return { p, open };
    })();
    let handled = 0;
    let firstStarted!: () => void;
    const started = new Promise<void>((r) => (firstStarted = r));
    app.onEnvelope = async () => {
      handled++;
      if (handled === 1) {
        firstStarted();
        await gate.p; // the backlog's envelope, held until a live one is queued behind it
      } else await live.p; // a live one: still running when the drain must have ended
      return "keep";
    };
    const drained = app.connectAndDrain();
    await started;
    await message("arrives live");
    await new Promise((r) => setTimeout(r, 500)); // delivered and queued behind the first
    const t0 = Date.now();
    gate.open();
    await drained;
    // Old: the drain waited for the live envelope too (here: never, until P2P_DRAIN_MAX_MS, 4 s).
    expect(Date.now() - t0).toBeLessThan(3500);
    live.open();
    await app.close();
    // Kept: the next command applies both, once.
    await ann.ok(["ls"]);
    expect(await applied("backlog one")).toBe(1);
    expect(await applied("arrives live")).toBe(1);
  }, 60_000);

  // pre-release review M-A: a short command that exits with a handler still running gives the claim back
  // without counting an attempt; before, three such exits gave a legitimate envelope up.
  it("a command cut off with a handler running gives its claim back uncounted: three cut-offs, then applied once", async () => {
    await ann.ok(["ls"]);
    await message("cut off three times");
    const before = await gaveUp();
    for (let i = 0; i < 3; i++) {
      const app = await ann.app();
      await app.load();
      receiving(app);
      let started!: () => void;
      const running = new Promise<void>((r) => (started = r));
      app.state.addEvents = async (): Promise<never> => {
        started();
        return new Promise<never>(() => {}); // never finishes: the command exits under it
      };
      await app.connect();
      await running;
      await app.close(); // past CLOSE_GRACE_MS: abandoned
      expect(await applied("cut off three times")).toBe(0);
    }
    await ann.ok(["ls"]);
    expect(await applied("cut off three times")).toBe(1);
    expect(await gaveUp()).toBe(before);
  }, 60_000);

  // pre-release re-review F1: an abandoned handler sends nothing more (its claim went back, so another
  // attempt applies the envelope again and would send the same answer).
  it("a handler abandoned past the close grace can't send anything afterwards", async () => {
    await ann.ok(["ls"]);
    await message("abandoned sender");
    const app = await ann.app();
    await app.load();
    receiving(app);
    let started!: () => void;
    const running = new Promise<void>((r) => (started = r));
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let sent: unknown;
    app.state.addEvents = async (): Promise<never> => {
      started();
      await gate;
      // Still running after its command gave up on it: try to send (as a want's answer would).
      sent = await app.deliver(ids.ben, "msg", { own: app.userId, sid: "as1" }, { text: "should not go out" }).catch((e: Error) => e);
      return new Promise<never>(() => {});
    };
    // The handler goes on right after it was abandoned, while the closing pool still exists (the
    // window where it could have sent on it).
    const abandon = app.onAbandon!;
    app.onAbandon = async () => {
      await abandon();
      release();
      for (let i = 0; i < 100 && sent === undefined; i++) await new Promise((r) => setTimeout(r, 50));
    };
    await app.connect();
    await running;
    await app.close(); // waits CLOSE_GRACE_MS, then abandons the handler
    expect(sent).toBeInstanceOf(Error);
    expect((sent as Error).message).toMatch(/not sending/);
    await ben.ok(["ls"]);
    const benApp = await ben.app();
    const got = ((await benApp.state.get("events"))?.items ?? []).filter((e) => e.data.text === "should not go out").length;
    expect(got).toBe(0);
  }, 60_000);

  // pre-release review M-A: a relay sends each envelope once per connection, so a watch that kept one
  // because another process held its claim handles it again later itself.
  it("a watch handles an envelope it kept (another process held the claim) again once that claim is gone", async () => {
    await ann.ok(["ls"]);
    const holder = await ann.app();
    await holder.load();
    receiving(holder);
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let started!: () => void;
    const holding = new Promise<void>((r) => (started = r));
    holder.state.addEvents = async (): Promise<never> => {
      started();
      await gate;
      throw enospc(); // gives the claim back (transient), unapplied
    };
    await message("kept by the watch");
    await holder.connect();
    await holding;
    const app = await ann.app();
    (app as unknown as { env: Record<string, string | undefined> }).env = { ...app.env, P2P_KEEP_RETRY_MS: "200" };
    await app.load();
    const ctl = new AbortController();
    const watching = watch(app, { session: "as1", signal: ctl.signal, log: () => {}, write: async () => true, pollMs: 60_000 });
    // The watch got its copy while the holder had the claim: kept, not applied.
    await new Promise((r) => setTimeout(r, 1500));
    expect(await applied("kept by the watch")).toBe(0);
    release();
    await holder.close();
    const end = Date.now() + 8000;
    while (Date.now() < end && (await applied("kept by the watch")) === 0) await new Promise((r) => setTimeout(r, 100));
    expect(await applied("kept by the watch")).toBe(1);
    ctl.abort();
    expect(await watching).toBe(0);
  }, 60_000);
});
