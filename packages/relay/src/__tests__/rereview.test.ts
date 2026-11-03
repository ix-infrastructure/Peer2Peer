// Copyright 2026 Ix Infrastructure Inc.
// Regression tests for the pre-release re-review (H-1, M-1..M-4, L-a..L-d).

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { b32Encode } from "../crypto.js";
import { DEFAULT_LIMITS } from "../config.js";
import { SqliteStore } from "../sqlite-store.js";
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
  type Device,
  type TestRelay,
} from "./helpers.js";

let r: TestRelay;
let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "p2p-relay-rr-"));
});
afterEach(async () => {
  await r?.close();
  rmSync(dir, { recursive: true, force: true });
});

const to = (d: Device) => ({ userId: d.identity.userId, did: d.did });
const sendWith = (c: TestClient, from: Device, dest: Device, extra: Record<string, unknown> = {}, envOpts = {}) =>
  c.request({ t: "send", to: dest.identity.userId, tdid: dest.did, env: makeEnvelope(from, to(dest), envOpts), ...extra });
const publish = (c: TestClient, doc: string) => c.request({ t: "identity", doc });
const stored = (d: Device) => r.store.envelopesAfter(d.identity.userId, d.did, 0, 0, 100_000);

/** Connects and authenticates `d` as if from `ip` (relay started with trustProxy 1). */
async function authedFrom(d: Device, ip: string): Promise<TestClient> {
  const c = await TestClient.connect(r.url, { "x-forwarded-for": ip });
  const ok = await c.auth(d);
  if (ok.t !== "ok") throw new Error(JSON.stringify(ok));
  return c;
}

async function offline(): Promise<Device> {
  const d = makeDevice(makeIdentity(), r.nowSec());
  await (await authed(r, d)).close();
  return d;
}

// ---------------------------------------------------------------------------

describe("H-1: quota and eviction never aggregate over envelopes", () => {
  it("every statement on the send/ack/evict path is aggregate-free and an index search", async () => {
    const path = join(dir, "relay.db");
    const traced: string[] = [];
    let tracing = false;
    const store = new SqliteStore(path, { trace: (sql) => tracing && traced.push(sql) });
    r = await startRelay({ store, limits: { storeMaxBytes: 15_000, recipientMaxBytes: 8_000 } });
    const alice = makeDevice(makeIdentity(), r.nowSec());
    const ac = await authed(r, alice);
    const bob = makeDevice(makeIdentity(), r.nowSec());
    const bc = await authed(r, bob);
    const carol = await offline();
    tracing = true;
    const capB = makeCap(bob, r.nowSec()).jws;
    const capC = makeCap(carol, r.nowSec()).jws;
    for (let i = 0; i < 12; i++) {
      await sendWith(ac, alice, i % 2 ? bob : carol, { cap: i % 2 ? capB : capC });
      await sendWith(ac, alice, carol, {}, { kind: "contact" });
    }
    const envs = await bc.drainEnvs();
    bc.send({ t: "ack", rids: envs.map((e) => e.rid) });
    await new Promise((res) => setTimeout(res, 50));
    tracing = false;

    const onEnvelopes = [...new Set(traced)].filter((sql) => /\benvelopes\b/i.test(sql));
    expect(onEnvelopes.length).toBeGreaterThan(3);
    for (const sql of onEnvelopes) expect(sql).not.toMatch(/\b(sum|count)\s*\(|\bgroup\s+by\b/i);
    // Query plans: no full scan of envelopes anywhere on the hot path.
    const probe = new DatabaseSync(path);
    try {
      for (const sql of onEnvelopes.filter((q) => /^\s*(select|delete)/i.test(q))) {
        const plan = (probe.prepare(`EXPLAIN QUERY PLAN ${sql}`).all() as { detail: string }[]).map((p) => p.detail);
        expect(plan.join(" | "), sql).not.toMatch(/\bSCAN envelopes\b/);
      }
    } finally {
      probe.close();
    }
  });

  it("the running totals always equal a recount, through insert, ack, eviction and expiry", async () => {
    const path = join(dir, "relay.db");
    r = await startRelay({ store: new SqliteStore(path), limits: { storeMaxBytes: 12_000, recipientMaxBytes: 7_000 } });
    const alice = makeDevice(makeIdentity(), r.nowSec());
    const ac = await authed(r, alice);
    const bob = makeDevice(makeIdentity(), r.nowSec());
    const bc = await authed(r, bob);
    const carol = await offline();
    const check = () => {
      const db = new DatabaseSync(path);
      try {
        const all = db.prepare("SELECT count(*) AS n, coalesce(sum(size), 0) AS b FROM envelopes").get() as { n: number; b: number };
        expect(r.store.counts()).toMatchObject({ envelopes: Number(all.n), envelopeBytes: Number(all.b) });
        for (const d of [bob, carol]) {
          const t = db.prepare("SELECT coalesce(sum(size), 0) AS b FROM envelopes WHERE mbox_to = ?").get(d.identity.userId) as { b: number };
          expect(r.store.bytesForRecipient(d.identity.userId)).toBe(Number(t.b));
          expect(r.store.mailboxBytes(d.identity.userId, d.did)).toBe(Number(t.b));
        }
      } finally {
        db.close();
      }
    };
    for (let i = 0; i < 10; i++) await sendWith(ac, alice, i % 3 ? carol : bob, { cap: makeCap(i % 3 ? carol : bob, r.nowSec()).jws });
    check();
    const envs = await bc.drainEnvs();
    bc.send({ t: "ack", rids: envs.slice(0, 1).map((e) => e.rid) });
    await new Promise((res) => setTimeout(res, 50));
    check();
    r.clock.advance(8 * DAY * 1000);
    await r.relay.sweep();
    check();
    expect(r.store.counts().envelopes).toBe(0);
  });
});

describe("M-1/M-2: eviction goes by source, so it can't be aimed at someone else's mail", () => {
  it("a flooder spreading over many mailboxes can't push out another sender's envelopes globally", async () => {
    r = await startRelay({ config: { trustProxy: 1 }, limits: { storeMaxBytes: 20_000 } });
    const honest = makeDevice(makeIdentity(), r.nowSec());
    const flooder = makeDevice(makeIdentity(), r.nowSec());
    const hc = await authedFrom(honest, "198.51.100.1");
    const fc = await authedFrom(flooder, "203.0.113.66");
    const carol = await offline();
    const targets = await Promise.all([0, 1, 2, 3, 4].map(() => offline()));
    for (let i = 0; i < 2; i++) await sendWith(hc, honest, carol, { cap: makeCap(carol, r.nowSec()).jws });
    const keep = stored(carol).map((e) => e.env);
    for (let i = 0; i < 30; i++) {
      const t = targets[i % targets.length];
      expect(await sendWith(fc, flooder, t, { cap: makeCap(t, r.nowSec()).jws })).toMatchObject({ t: "sent" });
    }
    const flooderLeft = targets.reduce((n, t) => n + stored(t).length, 0);
    expect(flooderLeft).toBeGreaterThan(0); // the flooder still has its own stored...
    expect(stored(carol).map((e) => e.env)).toEqual(keep); // ...so nothing of the honest sender went
    expect(r.store.counts().envelopeBytes).toBeLessThanOrEqual(20_000);
  });

  it("over a recipient's quota, the source with the most bytes for that recipient goes first", async () => {
    r = await startRelay({ config: { trustProxy: 1 }, limits: { recipientMaxBytes: 10_000 } });
    const friend = makeDevice(makeIdentity(), r.nowSec());
    const flooder = makeDevice(makeIdentity(), r.nowSec());
    const frc = await authedFrom(friend, "198.51.100.1");
    const flc = await authedFrom(flooder, "203.0.113.66");
    const bob = await offline();
    const cap = makeCap(bob, r.nowSec()).jws;
    for (let i = 0; i < 2; i++) await sendWith(frc, friend, bob, { cap });
    const friendEnvs = stored(bob).map((e) => e.env);
    for (let i = 0; i < 20; i++) await sendWith(flc, flooder, bob, { cap });
    const left = stored(bob).map((e) => e.env);
    for (const e of friendEnvs) expect(left).toContain(e);
    expect(left.length).toBeGreaterThan(friendEnvs.length); // flooder still has some
    expect(r.store.bytesForRecipient(bob.identity.userId)).toBeLessThanOrEqual(10_000);
  });
});

describe("M-3: the source budget counts accepted bytes, not stored ones", () => {
  it("silently dropped contacts spend it exactly like stored ones, and acks don't refund it", async () => {
    const envSize = makeEnvelope(makeDevice(makeIdentity(), 0), { userId: makeIdentity().userId, did: "d_aaaaaaaaaaaaaaaaaaaaaaaaaa" }, { kind: "contact" }).length;
    const budget = Math.floor(envSize * 3.5);
    const run = async (known: boolean) => {
      r = await startRelay({ limits: { sourceAcceptedBytesPerHour: budget, contactPerPairPerHour: 100 } });
      const alice = makeDevice(makeIdentity(), r.nowSec());
      const ac = await authed(r, alice);
      const dest = known ? await offline() : makeDevice(makeIdentity(), r.nowSec());
      const out: string[] = [];
      for (let i = 0; i < 5; i++) out.push((await sendWith(ac, alice, dest, {}, { kind: "contact" })).t === "sent" ? "sent" : "limited");
      await r.close();
      return out;
    };
    const unknown = await run(false);
    const known = await run(true);
    expect(unknown).toEqual(known);
    expect(unknown).toContain("limited");

    r = await startRelay({ limits: { sourceAcceptedBytesPerHour: Math.floor(envSize * 2.5) } });
    const alice = makeDevice(makeIdentity(), r.nowSec());
    const ac = await authed(r, alice);
    const bob = makeDevice(makeIdentity(), r.nowSec());
    const bc = await authed(r, bob);
    const cap = makeCap(bob, r.nowSec()).jws;
    expect(await sendWith(ac, alice, bob, { cap })).toMatchObject({ t: "sent" });
    expect(await sendWith(ac, alice, bob, { cap })).toMatchObject({ t: "sent" });
    const envs = await bc.drainEnvs();
    bc.send({ t: "ack", rids: envs.map((e) => e.rid) });
    await new Promise((res) => setTimeout(res, 50));
    expect(r.store.counts().envelopes).toBe(0);
    expect(await sendWith(ac, alice, bob, { cap })).toMatchObject({ code: "rate-limited" });
  });
});

describe("M-4: the device-row cap can't lock new devices out", () => {
  it("when full, evicts the least recently seen idle binding", async () => {
    r = await startRelay({ limits: { maxDevices: 2 } });
    const d1 = await offline();
    r.clock.advance(1000);
    await offline();
    const d3 = makeDevice(makeIdentity(), r.nowSec());
    await authed(r, d3);
    expect(r.store.deviceIssuer(d1.did)).toBeUndefined();
    expect(r.store.counts().devices).toBe(2);
  });

  it("never evicts a binding with stored envelopes", async () => {
    r = await startRelay({ limits: { maxDevices: 3 } });
    const sender = makeDevice(makeIdentity(), r.nowSec());
    const sc = await authed(r, sender);
    const d1 = await offline();
    r.clock.advance(1000);
    const d2 = await offline();
    await sendWith(sc, sender, d1, { cap: makeCap(d1, r.nowSec()).jws });
    await authed(r, makeDevice(makeIdentity(), r.nowSec()));
    expect(r.store.deviceIssuer(d1.did)).toBe(d1.identity.userId);
    expect(r.store.deviceIssuer(d2.did)).toBeUndefined();
  });

  it("always admits a did listed in its issuer's held identity document", async () => {
    r = await startRelay({ limits: { maxDevices: 3 } });
    await authed(r, makeDevice(makeIdentity(), r.nowSec()));
    await authed(r, makeDevice(makeIdentity(), r.nowSec()));
    const z = makeIdentity();
    const z1 = makeDevice(z, r.nowSec());
    const z2 = makeDevice(z, r.nowSec());
    const zc = await authed(r, z1);
    expect(await publish(zc, makeDoc(z, r.nowSec(), { devices: [z1.did, z2.did] }).jws)).toMatchObject({ t: "ok" });
    const stranger = await TestClient.connect(r.url);
    expect(await stranger.auth(makeDevice(makeIdentity(), r.nowSec()))).toEqual({ t: "error", code: "full" });
    await authed(r, z2);
  });

  it("caps new bindings per IP bucket per day", async () => {
    r = await startRelay({ limits: { newDevicesPerIpv4PerDay: 2 } });
    await authed(r, makeDevice(makeIdentity(), r.nowSec()));
    await authed(r, makeDevice(makeIdentity(), r.nowSec()));
    const c = await TestClient.connect(r.url);
    expect(await c.auth(makeDevice(makeIdentity(), r.nowSec()))).toEqual({ t: "error", code: "rate-limited" });
    r.clock.advance(DAY * 1000);
    await authed(r, makeDevice(makeIdentity(), r.nowSec()));
  });
});

describe("low findings", () => {
  it("L-b: a tombstoned identity has no mailboxes, but its allowlist still gates auth", async () => {
    r = await startRelay();
    const alice = makeDevice(makeIdentity(), r.nowSec());
    const ac = await authed(r, alice);
    const bid = makeIdentity();
    const bob = makeDevice(bid, r.nowSec());
    const revoked = makeDevice(bid, r.nowSec());
    const bc = await authed(r, bob);
    const v1 = makeDoc(bid, r.nowSec(), { devices: [bob.did] });
    await publish(bc, v1.jws);
    const leave = makeDoc(bid, r.nowSec(), { ver: 2, prev: v1.hash, devices: [bob.did], relays: ["wss://elsewhere.test/v3"] });
    expect(await publish(bc, leave.jws)).toMatchObject({ t: "ok" });
    expect(await sendWith(ac, alice, bob, { id: "x", cap: makeCap(bob, r.nowSec()).jws })).toEqual({ t: "error", id: "x", code: "undeliverable" });
    expect(await sendWith(ac, alice, bob, {}, { kind: "contact" })).toMatchObject({ t: "sent" });
    expect(r.store.counts().envelopes).toBe(0);
    const rc = await TestClient.connect(r.url);
    expect(await rc.auth(revoked)).toEqual({ t: "ok", restricted: true });
    expect(await rc.request({ t: "ack", rids: [] })).toMatchObject({ t: "error", code: "forbidden" });
    await rc.close();
    await authed(r, bob);
  });

  it("L-c: during a fork, leaving takes a merge of every tip; extending one branch isn't enough", async () => {
    r = await startRelay();
    const id = makeIdentity();
    const k = makeDevice(id, r.nowSec());
    const c = await authed(r, k);
    const v1 = makeDoc(id, r.nowSec(), { devices: [k.did] });
    await publish(c, v1.jws);
    const a = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [k.did], name: "a" });
    const b = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [k.did], name: "b" });
    await publish(c, a.jws);
    await publish(c, b.jws);
    const [hi, lo] = a.hash > b.hash ? [a, b] : [b, a];
    const elsewhere = ["wss://elsewhere.test/v3"];
    const oneBranch = makeDoc(id, r.nowSec(), { ver: 3, prev: hi.hash, devices: [k.did], relays: elsewhere });
    expect(await publish(c, oneBranch.jws)).toMatchObject({ code: "forbidden" });
    expect((await fetch(`${r.http}/v3/identity/${id.userId}`)).status).toBe(200);
    const merged = makeDoc(id, r.nowSec(), { ver: 3, prev: hi.hash, merge: lo.hash, devices: [k.did], relays: elsewhere });
    expect(await publish(c, merged.jws)).toMatchObject({ t: "ok" });
    expect((await fetch(`${r.http}/v3/identity/${id.userId}`)).status).toBe(404);
  });

  it("L-d: maxOpen never exceeds what the link byte budget can reserve", async () => {
    const perBox = (DEFAULT_LIMITS.linkReqEntries + 1) * DEFAULT_LIMITS.linkEntryBytes;
    r = await startRelay();
    const maxOpen = (r.relay as unknown as { links: { limits: { maxOpen: number } } }).links.limits.maxOpen;
    expect(maxOpen * perBox).toBeLessThanOrEqual(DEFAULT_LIMITS.linkTotalBytes);
    await r.close();
    r = await startRelay({ limits: { linkTotalBytes: 2 * perBox, linkOpenPerIp: 100 } });
    const lid = (n: number) => b32Encode(new Uint8Array(20).fill(n)).slice(0, 26);
    const res = [];
    for (let i = 0; i < 3; i++) {
      const c = await authed(r, makeDevice(makeIdentity(), r.nowSec()));
      res.push((await c.request({ t: "link-open", lid: lid(i) })).code ?? "ok");
    }
    expect(res).toEqual(["ok", "ok", "full"]);
  });
});
