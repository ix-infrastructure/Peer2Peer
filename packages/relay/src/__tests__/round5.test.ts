// Copyright 2026 Ix Infrastructure Inc.
// Unit regression tests for resilience findings F-2 (cap cache, frame
// yielding), F-4 (bounded sweep steps), F-5 (IPv4 vs IPv6 defaults) and F-6
// (current-process groups evicted first). The resilience suite checks the
// same at process level.

import { mkdirSync, mkdtempSync, renameSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DEFAULT_LIMITS } from "../config.js";
import { createRelayCrypto } from "../crypto.js";
import { SqliteStore } from "../sqlite-store.js";
import { MemoryStore, pickSource, type Store } from "../store.js";
import { passNow, stall, untilReport, virtualClock } from "./checkpoint-clock.js";
import { authed, DAY, makeCap, makeDevice, makeEnvelope, makeIdentity, RELAY_URL, startRelay, TestClient, type TestRelay } from "./helpers.js";

let r: TestRelay | undefined;
let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "p2p-relay-r5-"));
});
afterEach(async () => {
  await r?.close();
  r = undefined;
  rmSync(dir, { recursive: true, force: true });
});
const R = () => r as TestRelay;

describe("F-2: verified-cap cache", () => {
  it("returns the same verdict from cache, and still checks the clock and the per-send context", () => {
    const c = createRelayCrypto();
    const now = 2_000_000_000;
    const bob = makeDevice(makeIdentity(), now);
    const alice = makeIdentity().userId;
    const cap = makeCap(bob, now, { sub: alice, kinds: ["*"] }).jws;
    const ctx = { relayUrl: RELAY_URL, to: bob.identity.userId, envFrom: alice, kind: "msg", now };
    const a = c.verifyCapForSend(cap, ctx);
    const b = c.verifyCapForSend(cap, ctx); // cached
    expect(b).toEqual(a);
    // Context still checked on a cache hit.
    expect(() => c.verifyCapForSend(cap, { ...ctx, envFrom: makeIdentity().userId })).toThrow(expect.objectContaining({ code: "not-allowed" }));
    expect(() => c.verifyCapForSend(cap, { ...ctx, relayUrl: "wss://other.test/v3" })).toThrow(expect.objectContaining({ code: "not-allowed" }));
    expect(() => c.verifyCapForSend(cap, { ...ctx, to: alice })).toThrow(expect.objectContaining({ code: "not-allowed" }));
    // Expiry still checked on a cache hit.
    expect(() => c.verifyCapForSend(cap, { ...ctx, now: now + 40 * DAY })).toThrow(expect.objectContaining({ code: "expired" }));
    // A mutated copy is a different key and fails.
    const forged = cap.slice(0, -4) + (cap.endsWith("AAAA") ? "BBBB" : "AAAA");
    expect(() => c.verifyCapForSend(forged, ctx)).toThrow();
  });

  it("revocation and uses still apply on every send with a cached cap", async () => {
    r = await startRelay();
    const alice = makeDevice(makeIdentity(), R().nowSec());
    const ac = await authed(R(), alice);
    const bob = makeDevice(makeIdentity(), R().nowSec());
    const bc = await authed(R(), bob);
    const send = (cap: string) =>
      ac.request({ t: "send", to: bob.identity.userId, tdid: bob.did, env: makeEnvelope(alice, { userId: bob.identity.userId, did: bob.did }), cap });
    const limited = makeCap(bob, R().nowSec(), { uses: 2 }).jws;
    expect(await send(limited)).toMatchObject({ t: "sent" });
    expect(await send(limited)).toMatchObject({ t: "sent" });
    expect(await send(limited)).toMatchObject({ code: "undeliverable" });
    const rev = makeCap(bob, R().nowSec());
    expect(await send(rev.jws)).toMatchObject({ t: "sent" });
    await bc.request({ t: "revoke", capid: rev.capid });
    expect(await send(rev.jws)).toMatchObject({ code: "undeliverable" });
  });
});

describe("F-2: one socket's pipeline yields between frames", () => {
  it("interleaves another connection's frames into a long pipeline", async () => {
    r = await startRelay({ limits: { framesPerConnPerMinute: 10_000 } });
    const a = await TestClient.connect(R().url);
    const b = await TestClient.connect(R().url);
    const order: string[] = [];
    a.ws.on("message", (d) => {
      if (JSON.parse(String(d)).id?.startsWith("a")) order.push("a");
    });
    b.ws.on("message", (d) => {
      if (JSON.parse(String(d)).id === "b") order.push("b");
    });
    const lid = "a".repeat(26);
    // 200 frames written in one go on `a`, then one on `b`.
    for (let i = 0; i < 200; i++) a.send({ t: "link-get", lid, slot: "req", id: `a${i}` });
    b.send({ t: "nope", id: "b" });
    await new Promise((res) => setTimeout(res, 500));
    const pos = order.indexOf("b");
    expect(pos).toBeGreaterThanOrEqual(0);
    // `b` was answered long before `a`'s pipeline finished.
    expect(pos).toBeLessThan(order.length - 50);
    await a.close();
    await b.close();
  });
});

describe("F-4: bounded sweep steps", () => {
  for (const [name, mk] of [
    ["memory", () => new MemoryStore()],
    ["sqlite", () => new SqliteStore(join(dir, "s.db"))],
  ] as [string, () => Store][]) {
    it(`store.sweep deletes at most \`limit\` rows per table per call (${name})`, () => {
      const s = mk();
      for (let i = 0; i < 25; i++) {
        s.revokeCap(`k${i}`, 1);
        s.touchDevice(`d_${i}`, "p2p:x", 1);
      }
      const cut = { capsBefore: 10, identityVersionsBefore: 0, devicesBefore: 10 };
      expect(s.sweep(cut, 10)).toMatchObject({ caps: 10, devices: 10 });
      expect(s.sweep(cut, 10)).toMatchObject({ caps: 10, devices: 10 });
      expect(s.sweep(cut, 10)).toMatchObject({ caps: 5, devices: 5 });
      expect(s.sweep(cut, 10)).toMatchObject({ caps: 0, devices: 0 });
      s.close();
    });
  }
});

describe("F-4: WAL checkpoints run off the main thread", () => {
  // Driven by the worker's own reports, never by wall-clock sleeps: under load (pre-release re-review F5)
  // a 600 ms or 700 ms wait could end before the worker had run at all.
  it("disables in-commit autocheckpoint, keeps the WAL bounded, and falls back if the worker dies", async () => {
    const path = join(dir, "ck.db");
    const s = new SqliteStore(path);
    const db = (s as unknown as { db: { prepare(q: string): { get(): Record<string, number> } } }).db;
    const autocheckpoint = () => Object.values(db.prepare("PRAGMA wal_autocheckpoint").get())[0];
    const w = s.checkpointState().worker!;
    // In-commit autocheckpoint goes off once the worker reports a checkpoint.
    await untilReport(w, () => autocheckpoint() === 0);
    const caps = { maxEnvelopes: 1e9, maxBytes: 1e12 };
    const walSize = () => {
      try {
        return statSync(`${path}-wal`).size;
      } catch {
        return 0;
      }
    };
    /** Runs passes until one has copied everything written so far (log fully checkpointed). */
    const caughtUp = async () => {
      for (let i = 0; i < 100; i++) {
        const r = await passNow(w);
        if (r.ok && r.checkpointed === r.log) return;
      }
      throw new Error("the worker never caught up");
    };
    const sizes: number[] = [];
    for (let round = 0; round < 4; round++) {
      s.transaction(() => {
        for (let i = 0; i < 1500; i++) s.putEnvelope({ to: "p2p:a", tdid: "d_a", env: "x".repeat(1000), size: 1000, receivedAt: 1, src: "s" }, caps);
      });
      s.expireBatch(2, 1500);
      await caughtUp();
      sizes.push(walSize());
    }
    // The WAL is reused after each checkpoint instead of growing round after round.
    expect(sizes[3]).toBeLessThanOrEqual(sizes[0] * 1.5 + 64 * 1024);
    // If the worker dies, SQLite's own autocheckpoint comes back (the store's exit handler runs
    // before this one: it was registered first).
    const exited = new Promise((res) => w.once("exit", res));
    await (s as unknown as { checkpointer: { terminate(): Promise<number> } }).checkpointer.terminate();
    await exited;
    expect(autocheckpoint()).toBe(1000);
    s.close();
  }, 30_000);
});

describe("pre-release re-review F5: a checkpoint worker whose database is gone ends quietly", () => {
  it("closed before its worker could open the database (directory moved away): no uncaught error", async () => {
    const sub = join(dir, "gone");
    mkdirSync(sub);
    const s = new SqliteStore(join(sub, "g.db"));
    const w = s.checkpointState().worker!;
    // The worker thread starts after this synchronous code: its database path is gone by then.
    renameSync(sub, join(dir, "moved"));
    s.close();
    let error: unknown;
    w.on("error", (e) => (error = e)); // close() removed the store's own listeners
    await new Promise((res) => w.once("exit", res));
    expect(error).toBeUndefined();
  });
});

describe("pre-release review: the checkpoint worker has a watchdog", () => {
  const autocheckpoint = (s: SqliteStore) =>
    Object.values((s as unknown as { db: { prepare(q: string): { get(): Record<string, number> } } }).db.prepare("PRAGMA wal_autocheckpoint").get())[0];

  // The watchdog runs on a virtual clock here, and the tests wait for worker
  // reports instead of sleeping: under the full suite the worker thread can be
  // scheduled late enough to miss a wall-clock window (a Node 22 flake).
  it("a stalled worker re-enables autocheckpoint, warns, and is restarted; the new worker switches it off again", async () => {
    const warnings: string[] = [];
    const clock = virtualClock();
    const s = new SqliteStore(join(dir, "wd.db"), { checkpointIntervalMs: 50, checkpointWatchdogMs: 400, now: clock.now, warn: (m) => warnings.push(m) });
    const first = s.checkpointState().worker!;
    // Its first completed pass hands checkpoints to the worker.
    await untilReport(first, () => autocheckpoint(s) === 0);
    await stall(first);
    // Past the watchdog window with no report: the fallback fires.
    clock.advance(500);
    s.checkWatchdog();
    expect(warnings.some((w) => /stalled/.test(w))).toBe(true);
    expect(autocheckpoint(s)).toBe(1000);
    const state = s.checkpointState();
    expect(state.worker).toBeDefined();
    expect(state.worker).not.toBe(first);
    // The restarted worker reports in and turns in-commit checkpoints off again.
    await untilReport(state.worker!, () => autocheckpoint(s) === 0);
    s.close();
  });

  it("L-3: a reader pinning an old snapshot (checkpoints run but can't finish) triggers the stall fallback", async () => {
    const path = join(dir, "rp.db");
    const warnings: string[] = [];
    const clock = virtualClock();
    const s = new SqliteStore(path, { checkpointIntervalMs: 50, checkpointWatchdogMs: 400, now: clock.now, warn: (m) => warnings.push(m) });
    const put = () => s.putEnvelope({ to: "p2p:a", tdid: "d_a", env: "x".repeat(2000), size: 2000, receivedAt: 1, src: "s" }, { maxEnvelopes: 1e9, maxBytes: 1e12 });
    put();
    await untilReport(s.checkpointState().worker!, () => autocheckpoint(s) === 0);
    // Another connection opens a read transaction and holds its snapshot.
    const reader = new DatabaseSync(path);
    reader.exec("BEGIN");
    reader.prepare("SELECT count(*) AS n FROM meta").get();
    for (let i = 0; i < 20; i++) put();
    // Passes keep running but stop at the reader's frame: 100 ms per report until the watchdog trips.
    const w = s.checkpointState().worker!;
    await untilReport(w, () => {
      clock.advance(100);
      s.checkWatchdog();
      return warnings.some((m) => /stalled/.test(m));
    });
    expect(autocheckpoint(s)).toBe(1000);
    // The reader lets go: the restarted worker catches up and takes checkpoints back.
    reader.exec("COMMIT");
    reader.close();
    await untilReport(s.checkpointState().worker!, () => autocheckpoint(s) === 0);
    s.close();
  });

  it("a WAL past its limit triggers the same fallback", async () => {
    const warnings: string[] = [];
    const clock = virtualClock();
    const s = new SqliteStore(join(dir, "wl.db"), { checkpointIntervalMs: 50, checkpointWatchdogMs: 60_000, walLimitBytes: 1, now: clock.now, warn: (m) => warnings.push(m) });
    s.putEnvelope({ to: "p2p:a", tdid: "d_a", env: "x".repeat(5000), size: 5000, receivedAt: 1, src: "s" }, { maxEnvelopes: 1e9, maxBytes: 1e12 });
    // Checks a few watchdog periods apart, all inside the 60 s warning interval.
    for (let i = 0; i < 4; i++) {
      s.checkWatchdog();
      clock.advance(1000);
    }
    expect(warnings.some((w) => /WAL over its limit/.test(w))).toBe(true);
    expect(autocheckpoint(s)).toBe(1000);
    expect(warnings.length).toBe(1); // rate-limited, not once per check
    s.close();
  });

  it("the worker never leaves a read transaction open (which would pin the WAL and let it grow)", async () => {
    const path = join(dir, "pin.db");
    const s = new SqliteStore(path, { checkpointIntervalMs: 50 });
    for (let i = 0; i < 200; i++) s.putEnvelope({ to: "p2p:a", tdid: "d_a", env: "x".repeat(2000), size: 2000, receivedAt: 1, src: "s" }, { maxEnvelopes: 1e9, maxBytes: 1e12 });
    await new Promise((res) => setTimeout(res, 300)); // several worker checkpoints
    const db = (s as unknown as { db: { prepare(q: string): { get(): Record<string, number> } } }).db;
    // A TRUNCATE checkpoint can only finish (busy 0) if no other connection holds a read lock.
    const r = db.prepare("PRAGMA wal_checkpoint(TRUNCATE)").get();
    expect(Number(r.busy)).toBe(0);
    expect(statSync(`${path}-wal`).size).toBe(0);
    s.close();
  });

  it("sets journal_size_limit", () => {
    const s = new SqliteStore(join(dir, "js.db"));
    const db = (s as unknown as { db: { prepare(q: string): { get(): Record<string, number> } } }).db;
    expect(Object.values(db.prepare("PRAGMA journal_size_limit").get())[0]).toBe(64 * 1024 * 1024);
    s.close();
  });
});

describe("F-5: IPv4 and IPv6 /64 have separate per-address defaults", () => {
  it("defaults: shared IPv4 gets room, an IPv6 /64 keeps the tighter limits", () => {
    expect(DEFAULT_LIMITS.maxConnectionsPerIpv4).toBe(512);
    expect(DEFAULT_LIMITS.newDevicesPerIpv4PerDay).toBe(1000);
    expect(DEFAULT_LIMITS.authsPerIpv4PerMinute).toBe(600);
    expect(DEFAULT_LIMITS.maxConnectionsPerIp).toBe(64);
    expect(DEFAULT_LIMITS.newDevicesPerIpPerDay).toBe(50);
    expect(DEFAULT_LIMITS.authsPerIpPerMinute).toBe(60);
    // Still bounded globally.
    expect(DEFAULT_LIMITS.maxConnectionsPerIpv4).toBeLessThan(DEFAULT_LIMITS.maxConnections);
  });

  it("applies the IPv4 caps to IPv4 addresses and the /64 caps to IPv6", async () => {
    r = await startRelay({ config: { trustProxy: 1 }, limits: { maxConnectionsPerIp: 2, maxConnectionsPerIpv4: 4, authsPerIpPerMinute: 100, authsPerIpv4PerMinute: 100 } });
    const from = (ip: string) => TestClient.connect(R().url, { "x-forwarded-for": ip });
    const v4: string[] = [];
    for (let i = 0; i < 5; i++) v4.push(await from("198.51.100.5").then(() => "open", (e: Error) => e.message));
    const v6: string[] = [];
    for (let i = 0; i < 3; i++) v6.push(await from(`2001:db8:5:5::${i + 1}`).then(() => "open", (e: Error) => e.message));
    expect(v4.filter((x) => x === "open")).toHaveLength(4);
    expect(v6.filter((x) => x === "open")).toHaveLength(2);
  });
});

describe("F-6 (revised): the sender pays first, then the largest group, whatever its generation", () => {
  it("pickSource: sender above the floor, else the largest above the floor, else the largest overall", () => {
    const cands = [
      { src: "old-attacker", bytes: 900 },
      { src: "old-canary", bytes: 400 },
      { src: "new-attacker", bytes: 300 },
      { src: "new-honest", bytes: 50 },
    ];
    // The sender's own group pays when it is above the floor.
    expect(pickSource(cands, { floor: 100, sender: "new-attacker" })).toBe("new-attacker");
    // ... and above its fair share of the quota: an honest sender to a full
    // mailbox (here 300 of a 1,650 quota over 4 groups, share 412) doesn't
    // evict its own older mail; the largest group goes.
    expect(pickSource(cands, { floor: 100, sender: "new-attacker", quota: 1650 })).toBe("old-attacker");
    // A sender under the floor doesn't: the largest group goes, old or new.
    expect(pickSource(cands, { floor: 100, sender: "new-honest" })).toBe("old-attacker");
    // The pre-release review's case: many sources each under the floor, and honest
    // old mail under it too. No generation is preferred: the largest goes.
    const spread = [{ src: "old-honest", bytes: 60 }, ...Array.from({ length: 12 }, (_, i) => ({ src: `new-sybil-${i}`, bytes: 90 }))];
    expect(pickSource(spread, { floor: 100, sender: "new-sybil-3" })).toMatch(/^new-sybil-/);
  });

  for (const [name, mk] of [
    ["memory", () => new MemoryStore()],
    ["sqlite", () => new SqliteStore(join(dir, "f6.db"))],
  ] as [string, () => Store][]) {
    it(`evictGlobal follows the policy (${name})`, async () => {
      const s = mk();
      await s.init();
      const caps = { maxEnvelopes: 1e9, maxBytes: 1e12 };
      const put = (src: string, to: string, n: number) => {
        for (let i = 0; i < n; i++) s.putEnvelope({ to, tdid: "d_x", env: "e".repeat(100), size: 100, receivedAt: 1, src }, caps);
      };
      put("old-attacker", "p2p:sink", 9);
      put("old-canary", "p2p:parked", 4);
      put("new-attacker", "p2p:sink2", 5);
      // The renewed flood (the sender) pays for itself down to the floor first.
      s.evictGlobal(300, { floor: 100, sender: "new-attacker" });
      expect(s.sourceBytes("new-attacker")).toBe(200);
      expect(s.sourceBytes("old-canary")).toBe(400);
      expect(s.sourceBytes("old-attacker")).toBe(900);
      // Many sources under the floor: the largest groups go, never the small honest one.
      for (let i = 0; i < 6; i++) put(`sybil-${i}`, `p2p:t${i}`, 1);
      s.evictGlobal(500, { floor: 1000, sender: "sybil-0" });
      expect(s.sourceBytes("old-attacker")).toBe(400);
      expect(s.sourceBytes("old-canary")).toBe(400);
      s.close();
    });
  }
});
