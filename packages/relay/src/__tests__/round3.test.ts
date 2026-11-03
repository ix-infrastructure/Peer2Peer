// Copyright 2026 Ix Infrastructure Inc.
// Regression tests for the third hardening round: N-M1..N-M3, N-L2, and the
// malformed-target crash, cap-cert cache and unauthenticated-slot findings.

import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DEFAULT_LIMITS } from "../config.js";
import { createRelayCrypto } from "../crypto.js";
import { CLOSE } from "../server.js";
import { SqliteStore } from "../sqlite-store.js";
import { DatabaseSync } from "node:sqlite";
import {
  authed,
  DAY,
  makeCap,
  makeDevice,
  makeDoc,
  makeEnvelope,
  makeIdentity,
  startRelay,
  TestClient,
  T0,
  type Device,
  type TestRelay,
} from "./helpers.js";

let r: TestRelay | undefined;
let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "p2p-relay-r3-"));
});
afterEach(async () => {
  await r?.close();
  r = undefined;
  rmSync(dir, { recursive: true, force: true });
});

const R = () => r as TestRelay;
const to = (d: Device) => ({ userId: d.identity.userId, did: d.did });
const sendWith = (c: TestClient, from: Device, dest: Device, extra: Record<string, unknown> = {}, envOpts = {}) =>
  c.request({ t: "send", to: dest.identity.userId, tdid: dest.did, env: makeEnvelope(from, to(dest), envOpts), ...extra });

/** Fills a SQLite store directly with `n` small envelopes received at `at`. */
function seed(path: string, n: number, at: number): void {
  const s = new SqliteStore(path);
  const caps = { maxEnvelopes: 1e9, maxBytes: 1e12 };
  s.transaction(() => {
    for (let i = 0; i < n; i++) {
      s.putEnvelope({ to: `p2p:u${i % 200}`, tdid: `d_${i % 300}`, env: "x".repeat(100), size: 100, receivedAt: at, src: `s${i % 7}` }, caps);
    }
  });
  s.close();
}

// ---------------------------------------------------------------------------

describe("N-M1: expiry and startup never hold the event loop", () => {
  it("expires a large store in bounded batches, yielding to the event loop between every two", { timeout: 60_000 }, async () => {
    // Deterministic (pre-release review: this measured wall-clock milliseconds and failed under load):
    // what keeps the loop free is that every batch is bounded in rows and followed by a yield,
    // so that is what is checked, not how long a batch took on this machine.
    const path = join(dir, "relay.db");
    seed(path, 20_000, T0 - 8 * DAY * 1000);
    const store = new SqliteStore(path);
    const limits: number[] = [];
    let yielded = true;
    let alwaysYielded = true;
    const orig = store.expireBatch.bind(store);
    store.expireBatch = (before, limit) => {
      // A macrotask queued during the previous batch must have run before this one starts.
      if (!yielded) alwaysYielded = false;
      yielded = false;
      setImmediate(() => {
        yielded = true;
      });
      limits.push(limit);
      return orig(before, limit);
    };
    r = await startRelay({ store });
    await R().relay.sweep();
    expect(R().store.counts()).toMatchObject({ envelopes: 0, envelopeBytes: 0 });
    // 20,000 rows at most 2,000 (EXPIRE_ROWS_MAX) a batch: at least 10 batches, each bounded.
    expect(limits.length).toBeGreaterThanOrEqual(10);
    expect(Math.max(...limits)).toBeLessThanOrEqual(2000);
    expect(alwaysYielded).toBe(true);
  });

  it("rebuilds totals at startup in chunks that yield, before accepting connections", { timeout: 60_000 }, async () => {
    const path = join(dir, "relay.db");
    seed(path, 30_000, T0);
    // Deterministic (pre-release review): count how often the event loop got a turn during startup,
    // rather than timing it. 30,000 rows in 2,000-row chunks yield at least 15 times; a startup
    // that read them in one go would give a self-rescheduling macrotask almost no turns.
    let turns = 0;
    let counting = true;
    const tick = () => {
      if (!counting) return;
      turns++;
      setImmediate(tick);
    };
    setImmediate(tick);
    r = await startRelay({ store: new SqliteStore(path) });
    counting = false;
    expect(turns).toBeGreaterThanOrEqual(15);
    expect(R().store.counts()).toMatchObject({ envelopes: 30_000, envelopeBytes: 3_000_000 });
  });
});

describe("N-M2: shared-IP budgets", () => {
  it("the accepted-bytes budget refills within the hour", async () => {
    r = await startRelay({ limits: { sourceAcceptedBytesPerHour: 8_000 } });
    const alice = makeDevice(makeIdentity(), R().nowSec());
    const ac = await authed(R(), alice);
    const bob = makeDevice(makeIdentity(), R().nowSec());
    await authed(R(), bob);
    const cap = makeCap(bob, R().nowSec()).jws;
    // Sends until the budget refuses: never a fixed count, since an envelope's size varies with
    // its seq (pre-release review: a fixed 10 could end just under the 8,000-byte budget). Half an hour
    // then refills half the budget, more than one envelope.
    let limited = false;
    let size = 0;
    for (let i = 0; i < 100 && !limited; i++) {
      const env = makeEnvelope(alice, to(bob));
      size = Math.max(size, env.length);
      limited = (await ac.request({ t: "send", to: bob.identity.userId, tdid: bob.did, env, cap })).code === "rate-limited";
    }
    expect(limited).toBe(true);
    expect(size).toBeLessThan(4_000);
    R().clock.advance(30 * 60_000);
    expect(await sendWith(ac, alice, bob, { cap })).toMatchObject({ t: "sent" });
  });

  it("the stored-bytes source share evicts that source's own oldest and never refuses", async () => {
    r = await startRelay({ config: { trustProxy: 1 }, limits: { sourceMaxBytes: 6_000 } });
    const heavy = makeDevice(makeIdentity(), R().nowSec());
    const other = makeDevice(makeIdentity(), R().nowSec());
    const hc = await TestClient.connect(R().url, { "x-forwarded-for": "198.51.100.9" });
    await hc.auth(heavy);
    const oc = await TestClient.connect(R().url, { "x-forwarded-for": "203.0.113.9" });
    await oc.auth(other);
    const bob = makeDevice(makeIdentity(), R().nowSec());
    await (await authed(R(), bob)).close();
    const cap = makeCap(bob, R().nowSec()).jws;
    await sendWith(oc, other, bob, { cap });
    const otherEnv = R().store.envelopesAfter(bob.identity.userId, bob.did, 0, 0, 10)[0].env;
    const sent: string[] = [];
    for (let i = 0; i < 10; i++) {
      const env = makeEnvelope(heavy, to(bob));
      sent.push(env);
      expect(await hc.request({ t: "send", to: bob.identity.userId, tdid: bob.did, env, cap })).toMatchObject({ t: "sent" });
    }
    const left = R().store.envelopesAfter(bob.identity.userId, bob.did, 0, 0, 100).map((e) => e.env);
    expect(left).toContain(otherEnv);
    const heavyLeft = left.filter((e) => e !== otherEnv);
    expect(heavyLeft.length).toBeLessThan(10);
    expect(heavyLeft).toEqual(sent.slice(10 - heavyLeft.length));
    expect(heavyLeft.reduce((n, e) => n + e.length, 0)).toBeLessThanOrEqual(6_000);
  });
});

describe("N-M3: the source key never reaches disk", () => {
  it("keeps the key in memory only; rows from before a restart keep their (now anonymous) source group", async () => {
    const path = join(dir, "relay.db");
    r = await startRelay({ store: new SqliteStore(path), limits: { storeMaxBytes: 12_000 } });
    const alice = makeDevice(makeIdentity(), R().nowSec());
    const ac = await authed(R(), alice);
    const bob = makeDevice(makeIdentity(), R().nowSec());
    await (await authed(R(), bob)).close();
    for (let i = 0; i < 3; i++) await sendWith(ac, alice, bob, { cap: makeCap(bob, R().nowSec()).jws });
    const key = (R().relay as unknown as { srcKey: Buffer }).srcKey;
    expect(R().store.getMeta("src_key")).toBeUndefined();
    await R().close();
    const disk = readdirSync(dir)
      .map((f) => readFileSync(join(dir, f)))
      .map((b) => b.toString("latin1"))
      .join("");
    for (const enc of ["base64url", "hex", "base64"] as const) expect(disk).not.toContain(key.toString(enc));
    expect(disk).not.toContain(key.toString("latin1"));

    r = await startRelay({ store: new SqliteStore(path), limits: { storeMaxBytes: 12_000 } });
    const before = R().store.counts().envelopeBytes;
    expect(before).toBeGreaterThan(0);
    const probe = new DatabaseSync(path);
    const tags = (probe.prepare("SELECT DISTINCT src FROM envelopes").all() as { src: string }[]).map((t) => t.src);
    probe.close();
    expect(tags).toHaveLength(1);
    expect(R().store.sourceBytes(tags[0])).toBe(before);
    // Legacy rows are evictable like any source.
    expect(R().store.evictGlobal(1)).toBeGreaterThan(0);
  });
});

describe("N-L2: device eviction can't be pinned by a page of busy rows", () => {
  it("finds the evictable binding past more than 64 unevictable ones", async () => {
    const lots = { authsPerIpPerMinute: 1000, connectsPerIpPerMinute: 1000, newDevicesPerIpPerDay: 1000, sendsPerMinute: 1000, maxConnectionsPerIp: 1000 };
    r = await startRelay({ limits: { ...lots, maxDevices: 72 } });
    const sender = makeDevice(makeIdentity(), R().nowSec());
    const sc = await authed(R(), sender);
    for (let i = 0; i < 70; i++) {
      const d = makeDevice(makeIdentity(), R().nowSec());
      await (await authed(R(), d)).close();
      await sendWith(sc, sender, d, { cap: makeCap(d, R().nowSec()).jws }); // pinned: has mail
    }
    R().clock.advance(1000);
    const idle = makeDevice(makeIdentity(), R().nowSec());
    await (await authed(R(), idle)).close();
    expect(R().store.counts().devices).toBe(72);
    await authed(R(), makeDevice(makeIdentity(), R().nowSec()));
    expect(R().store.deviceIssuer(idle.did)).toBeUndefined();
  });
});

describe("malformed request targets never crash the relay", () => {
  function raw(port: number, payload: string): Promise<string> {
    return new Promise((res) => {
      const s = connect(port, "127.0.0.1", () => s.write(payload));
      let out = "";
      s.on("data", (d) => (out += d.toString()));
      s.on("close", () => res(out.split("\r\n")[0] ?? ""));
      s.on("error", () => res(""));
      setTimeout(() => {
        s.destroy();
        res(out.split("\r\n")[0] ?? "");
      }, 500);
    });
  }
  const up = "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nHost: x\r\n\r\n";
  const targets = ["http://[::1", "http://[", "http://a:b:c/", "//[", "http://%zz/", "http://[::1]:99999/v3"];

  it("answers 400 (or drops the socket) on the WebSocket, HTTP and metrics listeners, and keeps serving", async () => {
    const uncaught: unknown[] = [];
    const onErr = (e: unknown) => uncaught.push(e);
    process.on("uncaughtException", onErr);
    try {
      r = await startRelay({ config: { metricsPort: 0 } });
      const mport = R().relay.metricsPort!;
      for (const t of targets) {
        const a = await raw(R().port, `GET ${t} HTTP/1.1\r\n${up}`);
        const b = await raw(R().port, `GET ${t} HTTP/1.1\r\nHost: x\r\n\r\n`);
        const c = await raw(mport, `GET ${t} HTTP/1.1\r\nHost: x\r\n\r\n`);
        for (const line of [a, b, c]) expect(line === "" || /^HTTP\/1\.1 (400|404)/.test(line), `${t}: ${line}`).toBe(true);
      }
      expect((await fetch(`${R().http}/healthz`)).status).toBe(200);
      const c = await TestClient.connect(R().url);
      expect(c.hello.t).toBe("hello");
      await c.close();
      expect(uncaught).toEqual([]);
    } finally {
      process.off("uncaughtException", onErr);
    }
  }, 30_000);
});

describe("verified-cert cache", () => {
  it("skips re-verifying identical cert bytes, but re-checks the validity window", () => {
    const c = createRelayCrypto();
    const now = 2_000_000_000;
    const dev = makeDevice(makeIdentity(), now, { iat: now - 10, exp: now + DAY });
    const first = c.verifyDeviceCert(dev.cert, { now });
    expect(c.verifyDeviceCert(dev.cert, { now })).toBe(first); // cache hit: same object
    expect(() => c.verifyDeviceCert(dev.cert, { now: now + DAY })).toThrow(expect.objectContaining({ code: "expired" }));
    // A forged variant (different bytes) is a different key and fails.
    const forged = makeDevice(dev.identity, now, { signWith: makeIdentity().ikSecret });
    expect(() => c.verifyDeviceCert(forged.cert, { now })).toThrow();
  });

  it("is bounded (LRU)", () => {
    const c = createRelayCrypto({ certCacheSize: 2 });
    const now = 2_000_000_000;
    const certs = [0, 1, 2].map(() => makeDevice(makeIdentity(), now).cert);
    const first = c.verifyDeviceCert(certs[0], { now });
    c.verifyDeviceCert(certs[1], { now });
    c.verifyDeviceCert(certs[2], { now }); // evicts certs[0]
    expect(c.verifyDeviceCert(certs[0], { now })).not.toBe(first);
  });

  it("revocation and the allowlist still apply to every send with a cached cap cert", async () => {
    r = await startRelay();
    const alice = makeDevice(makeIdentity(), R().nowSec());
    const ac = await authed(R(), alice);
    const bob = makeDevice(makeIdentity(), R().nowSec());
    const bob2 = makeDevice(bob.identity, R().nowSec());
    const bc = await authed(R(), bob);
    const cap = makeCap(bob2, R().nowSec());
    expect(await sendWith(ac, alice, bob, { cap: cap.jws })).toMatchObject({ t: "sent" }); // warms the cache
    expect(await sendWith(ac, alice, bob, { cap: cap.jws })).toMatchObject({ t: "sent" });
    // bob2 is dropped from bob's document: the cached cert no longer helps.
    expect(await bc.request({ t: "identity", doc: makeDoc(bob.identity, R().nowSec(), { devices: [bob.did] }).jws })).toMatchObject({ t: "ok" });
    expect(await sendWith(ac, alice, bob, { cap: cap.jws })).toMatchObject({ code: "undeliverable" });
    // And a revoked cap stays revoked.
    const cap2 = makeCap(bob, R().nowSec());
    expect(await sendWith(ac, alice, bob, { cap: cap2.jws })).toMatchObject({ t: "sent" });
    await bc.request({ t: "revoke", capid: cap2.capid });
    expect(await sendWith(ac, alice, bob, { cap: cap2.jws })).toMatchObject({ code: "undeliverable" });
  });
});

describe("unauthenticated slots", () => {
  it("defaults to a short unauthenticated timeout", () => {
    expect(DEFAULT_LIMITS.unauthTimeoutSec).toBeLessThanOrEqual(15);
    expect(DEFAULT_LIMITS.maxUnauthPerIp).toBeGreaterThan(0);
  });

  it("caps unauthenticated sockets per IP bucket", async () => {
    r = await startRelay({ limits: { maxUnauthPerIp: 2 } });
    const a = await TestClient.connect(R().url);
    await TestClient.connect(R().url);
    await expect(TestClient.connect(R().url)).rejects.toThrow(/429/);
    // Authenticating frees the slot.
    expect(await a.auth(makeDevice(makeIdentity(), R().nowSec()))).toEqual({ t: "ok" });
    await (await TestClient.connect(R().url)).close();
  });

  it("when the global cap is full, drops the oldest unauthenticated socket instead of refusing", async () => {
    r = await startRelay({ limits: { maxUnauthConnections: 2, maxUnauthPerIp: 10 } });
    const oldest = await TestClient.connect(R().url);
    const middle = await TestClient.connect(R().url);
    const newest = await TestClient.connect(R().url);
    expect(newest.hello.t).toBe("hello");
    expect(await oldest.closed).toBe(CLOSE.unauthTimeout);
    expect(middle.closeCode).toBeUndefined();
    expect(await newest.auth(makeDevice(makeIdentity(), R().nowSec()))).toEqual({ t: "ok" });
  });
});
