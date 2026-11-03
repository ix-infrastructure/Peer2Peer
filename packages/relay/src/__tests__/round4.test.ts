// Copyright 2026 Ix Infrastructure Inc.
// Regression tests for the fourth hardening round: R-M1, R-L1, R-L2.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SqliteStore } from "../sqlite-store.js";
import {
  authed,
  makeCap,
  makeDevice,
  makeDoc,
  makeEnvelope,
  makeIdentity,
  startRelay,
  TestClient,
  type Device,
  type TestRelay,
} from "./helpers.js";

let r: TestRelay | undefined;
let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "p2p-relay-r4-"));
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

async function authedFrom(d: Device, ip: string): Promise<TestClient> {
  const c = await TestClient.connect(R().url, { "x-forwarded-for": ip });
  const ok = await c.auth(d);
  if (ok.t !== "ok") throw new Error(JSON.stringify(ok));
  return c;
}

const stored = (d: Device) => R().store.envelopesAfter(d.identity.userId, d.did, 0, 0, 100_000).map((e) => e.env);

describe("R-M1: eviction stays source-fair across a restart", () => {
  it("after a restart, a flooder evicts its own data first and other senders' older mail survives", async () => {
    const path = join(dir, "relay.db");
    const honest = makeDevice(makeIdentity(), 0);
    const flooder = makeDevice(makeIdentity(), 0);
    const carol = makeDevice(makeIdentity(), 0);
    const bob = makeDevice(makeIdentity(), 0);
    r = await startRelay({ store: new SqliteStore(path), config: { trustProxy: 1 } });
    for (const d of [honest, flooder, carol, bob]) d.cert = makeDevice(d.identity, R().nowSec(), {}, d.spkSecret).cert;
    await (await authed(R(), carol)).close();
    await (await authed(R(), bob)).close();
    const hc = await authedFrom(honest, "198.51.100.1");
    const fc = await authedFrom(flooder, "203.0.113.66");
    // Before the restart: the honest sender has 5 envelopes waiting for carol,
    // the flooder 2 for bob.
    for (let i = 0; i < 5; i++) await sendWith(hc, honest, carol, { cap: makeCap(carol, R().nowSec()).jws });
    for (let i = 0; i < 2; i++) await sendWith(fc, flooder, bob, { cap: makeCap(bob, R().nowSec()).jws });
    const carolMail = stored(carol);
    const bytesBefore = R().store.counts().envelopeBytes;
    const envSize = bytesBefore / 7;
    await R().close();

    // Restart: a new source key. The flooder comes back and fills past quota.
    // Eviction starts once its new data is 6 envelopes: more than the honest
    // group (5), but less than all pre-restart rows lumped together (7), which
    // is what a single "legacy" source would have been.
    const max = Math.floor(bytesBefore + 6.5 * envSize);
    r = await startRelay({ store: new SqliteStore(path), config: { trustProxy: 1 }, limits: { storeMaxBytes: max } });
    const fc2 = await authedFrom(flooder, "203.0.113.66");
    for (let i = 0; i < 20; i++) {
      const t = i % 2 ? bob : carol;
      expect(await sendWith(fc2, flooder, t, { cap: makeCap(t, R().nowSec()).jws })).toMatchObject({ t: "sent" });
    }
    const left = stored(carol);
    for (const e of carolMail) expect(left).toContain(e);
    expect(R().store.counts().envelopeBytes).toBeLessThanOrEqual(max);
  });
});

describe("R-L1: link pollers learn the unauthenticated timeout", () => {
  it("is advertised in hello.limits and the relay-info document", async () => {
    r = await startRelay({ limits: { unauthTimeoutSec: 12 } });
    const c = await TestClient.connect(R().url);
    expect(c.hello.limits.unauthTimeoutSec).toBe(12);
    await c.close();
    const info = await (await fetch(`${R().http}/.well-known/p2p-relay.json`)).json();
    expect(info.limits.unauthTimeoutSec).toBe(12);
  });
});

describe("R-L2: device eviction reads a partial index with a keyset cursor", () => {
  it("the evictable query uses the partial index and the path has no OFFSET", async () => {
    const path = join(dir, "relay.db");
    const traced: string[] = [];
    r = await startRelay({ store: new SqliteStore(path, { trace: (sql) => traced.push(sql) }), limits: { maxDevices: 2 } });
    await (await authed(R(), makeDevice(makeIdentity(), R().nowSec()))).close();
    await (await authed(R(), makeDevice(makeIdentity(), R().nowSec()))).close();
    traced.length = 0;
    await authed(R(), makeDevice(makeIdentity(), R().nowSec())); // evicts one
    expect(R().store.counts().devices).toBe(2);
    const sql = traced.find((q) => /evictable = 1/.test(q));
    expect(sql).toBeDefined();
    for (const q of traced) expect(q).not.toMatch(/\bOFFSET\b/i);
    const probe = new DatabaseSync(path);
    try {
      const plan = (probe.prepare(`EXPLAIN QUERY PLAN ${sql}`).all() as { detail: string }[]).map((p) => p.detail).join(" | ");
      expect(plan).toMatch(/devices_evictable/);
      expect(plan).not.toMatch(/\bSCAN devices\b(?! USING)/);
    } finally {
      probe.close();
    }
  });

  it("keeps the evictable flag current through mail, acks and allowlist changes", async () => {
    const path = join(dir, "relay.db");
    r = await startRelay({ store: new SqliteStore(path) });
    const sender = makeDevice(makeIdentity(), R().nowSec());
    const sc = await authed(R(), sender);
    const bobId = makeIdentity();
    const bob = makeDevice(bobId, R().nowSec());
    const bc = await authed(R(), bob);
    const evictable = () => new Set(R().store.evictableDevices(1000).map((d) => d.did));
    expect(evictable().has(bob.did)).toBe(true);
    // Mail pins it...
    await sendWith(sc, sender, bob, { cap: makeCap(bob, R().nowSec()).jws });
    expect(evictable().has(bob.did)).toBe(false);
    // ...an ack of the last envelope releases it.
    const env = await bc.next((f) => f.t === "env");
    bc.send({ t: "ack", rids: [env.rid] });
    await new Promise((res) => setTimeout(res, 50));
    expect(evictable().has(bob.did)).toBe(true);
    // Being in a held allowlist pins it.
    const v1 = makeDoc(bobId, R().nowSec(), { devices: [bob.did] });
    expect(await bc.request({ t: "identity", doc: v1.jws })).toMatchObject({ t: "ok" });
    expect(evictable().has(bob.did)).toBe(false);
    // Leaving the relay keeps a tombstone with the allowlist: still pinned.
    const bob2 = makeDevice(bobId, R().nowSec());
    const v2 = makeDoc(bobId, R().nowSec(), { ver: 2, prev: v1.hash, devices: [bob.did, bob2.did] });
    await bc.request({ t: "identity", doc: v2.jws });
    const v3 = makeDoc(bobId, R().nowSec(), { ver: 3, prev: v2.hash, devices: [bob2.did] });
    await bc.request({ t: "identity", doc: v3.jws }); // drops bob from the allowlist
    expect(evictable().has(bob.did)).toBe(true);
  });

  for (const [name, mk] of [
    ["sqlite", () => new SqliteStore(join(dir, "relay.db"))],
    ["memory", () => undefined],
  ] as const) {
    it(`a document listing someone else's did doesn't pin that device (${name})`, async () => {
      r = await startRelay({ store: mk(), limits: { maxDevices: 3 } });
      const victim = makeDevice(makeIdentity(), R().nowSec());
      await (await authed(R(), victim)).close();
      // Another identity lists the victim's did in its own document.
      const attackerId = makeIdentity();
      const attacker = makeDevice(attackerId, R().nowSec());
      const ac = await authed(R(), attacker);
      const doc = makeDoc(attackerId, R().nowSec(), { devices: [attacker.did, victim.did] });
      expect(await ac.request({ t: "identity", doc: doc.jws })).toMatchObject({ t: "ok" });
      expect(R().store.evictableDevices(1000).map((d) => d.did)).toContain(victim.did);
      // At the cap, the victim's idle binding is still the one evicted.
      await authed(R(), makeDevice(makeIdentity(), R().nowSec())); // fills the cap (3)
      await authed(R(), makeDevice(makeIdentity(), R().nowSec())); // needs an eviction
      expect(R().store.deviceIssuer(victim.did)).toBeUndefined();
    });
  }

  it("init recomputes the flags for an existing store", async () => {
    const path = join(dir, "relay.db");
    r = await startRelay({ store: new SqliteStore(path) });
    const sender = makeDevice(makeIdentity(), R().nowSec());
    const sc = await authed(R(), sender);
    const bob = makeDevice(makeIdentity(), R().nowSec());
    await (await authed(R(), bob)).close();
    await sendWith(sc, sender, bob, { cap: makeCap(bob, R().nowSec()).jws });
    await R().close();
    // Corrupt the flags, then restart: init puts them right.
    const db = new DatabaseSync(path);
    db.exec("UPDATE devices SET evictable = 1");
    db.close();
    r = await startRelay({ store: new SqliteStore(path) });
    const ev = new Set(R().store.evictableDevices(1000).map((d) => d.did));
    expect(ev.has(bob.did)).toBe(false);
    expect(ev.has(sender.did)).toBe(true);
  });
});
