// Copyright 2026 Ix Infrastructure Inc.
// Regression tests for the pre-release re-review hardening (N1–N8).

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { b32Encode, jwsHash } from "../crypto.js";
import { clientAddress, ipBucket } from "../net.js";
import { CLOSE } from "../server.js";
import { SqliteStore } from "../sqlite-store.js";
import type { StoredIdentityDoc } from "../store.js";
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
  type StartOptions,
  type TestRelay,
} from "./helpers.js";

let r: TestRelay;
afterEach(async () => {
  await r?.close();
});

const to = (d: Device) => ({ userId: d.identity.userId, did: d.did });
const sendWith = (c: TestClient, from: Device, dest: Device, extra: Record<string, unknown> = {}, envOpts = {}) =>
  c.request({ t: "send", to: dest.identity.userId, tdid: dest.did, env: makeEnvelope(from, to(dest), envOpts), ...extra });
const publish = (c: TestClient, doc: string) => c.request({ t: "identity", doc });
const internals = () => r.relay as unknown as Record<string, any>;

async function online(opts: StartOptions = {}) {
  r = await startRelay(opts);
  const alice = makeDevice(makeIdentity(), r.nowSec());
  const ac = await authed(r, alice);
  const mk = async () => {
    const d = makeDevice(makeIdentity(), r.nowSec());
    (await authed(r, d)).close();
    return d;
  };
  return { alice, ac, mk };
}

const storedFor = (d: Device) => r.store.envelopesAfter(d.identity.userId, d.did, 0, 0, 10_000);

// ---------------------------------------------------------------------------

describe("N1: quotas evict instead of denying everyone", () => {
  it("past storeMaxBytes, the largest mailbox's oldest envelopes are evicted and other users still get through", async () => {
    const { alice, ac, mk } = await online({ limits: { storeMaxBytes: 12_000 } });
    const bob = await mk();
    const carol = await mk();
    const capBob = makeCap(bob, r.nowSec()).jws;
    const flood: string[] = [];
    for (let i = 0; i < 10; i++) {
      const env = makeEnvelope(alice, to(bob));
      flood.push(env);
      expect(await ac.request({ t: "send", to: bob.identity.userId, tdid: bob.did, env, cap: capBob })).toMatchObject({ t: "sent" });
    }
    expect(await sendWith(ac, alice, carol, { cap: makeCap(carol, r.nowSec()).jws })).toMatchObject({ t: "sent" });
    expect(storedFor(carol)).toHaveLength(1);
    const bobLeft = storedFor(bob).map((e) => e.env);
    expect(bobLeft.length).toBeLessThan(10);
    expect(bobLeft).toEqual(flood.slice(10 - bobLeft.length)); // the newest survive
    expect(r.store.counts().envelopeBytes).toBeLessThanOrEqual(12_000);
  });

  it("a per-recipient quota evicts that recipient's oldest", async () => {
    const { alice, ac, mk } = await online({ limits: { recipientMaxBytes: 6_000 } });
    const bob = await mk();
    const cap = makeCap(bob, r.nowSec()).jws;
    for (let i = 0; i < 8; i++) expect(await sendWith(ac, alice, bob, { cap })).toMatchObject({ t: "sent" });
    expect(r.store.bytesForRecipient(bob.identity.userId)).toBeLessThanOrEqual(6_000);
    expect(storedFor(bob).length).toBeGreaterThan(0);
  });

  it("a per-source quota rate-limits that source, identically for known and unknown mailboxes", async () => {
    const { alice, ac, mk } = await online({ limits: { sourceAcceptedBytesPerHour: 6_000, contactPerPairPerHour: 100 } });
    const bob = await mk();
    const ghost = makeDevice(makeIdentity(), r.nowSec());
    let limited = false;
    for (let i = 0; i < 10 && !limited; i++) limited = (await sendWith(ac, alice, bob, { id: "x" }, { kind: "contact" })).code === "rate-limited";
    expect(limited).toBe(true);
    expect(await sendWith(ac, alice, bob, { id: "x" }, { kind: "contact" })).toEqual({ t: "error", id: "x", code: "rate-limited" });
    expect(await sendWith(ac, alice, ghost, { id: "x" }, { kind: "contact" })).toEqual({ t: "error", id: "x", code: "rate-limited" });
  });
});

describe("N2: wire rids need no per-connection state", () => {
  it("round-trips through one AES block and rejects anything else", async () => {
    r = await startRelay();
    const rel = internals();
    for (const rid of [1, 2, 1234567, Number.MAX_SAFE_INTEGER]) {
      const w = rel.wireRid(rid);
      expect(w).toMatch(/^[A-Za-z0-9_-]{22}$/);
      expect(rel.ridFromWire(w)).toBe(rid);
    }
    expect(rel.wireRid(5)).toBe(rel.wireRid(5));
    expect(rel.wireRid(5)).not.toBe(rel.wireRid(6));
    expect(rel.ridFromWire("A".repeat(22))).toBeUndefined();
  });

  it("acks work from any connection of the mailbox, with no map to grow", async () => {
    const { alice, ac } = await online();
    const bob = makeDevice(makeIdentity(), r.nowSec());
    const b1 = await authed(r, bob);
    const cap = makeCap(bob, r.nowSec()).jws;
    for (let i = 0; i < 3; i++) await sendWith(ac, alice, bob, { cap });
    const rids = (await b1.drainEnvs()).map((e) => e.rid);
    const b2 = await authed(r, bob);
    await b2.drainEnvs();
    b2.send({ t: "ack", rids });
    await new Promise((res) => setTimeout(res, 50));
    expect(r.store.counts().envelopes).toBe(0);
    for (const c of internals().conns) expect(c.sentRids).toBeUndefined();
    // A rid from another relay process (another key) acks nothing.
    const other = await startRelay();
    const foreign = (other.relay as unknown as Record<string, any>).wireRid(1);
    await other.close();
    await sendWith(ac, alice, bob, { cap });
    b2.send({ t: "ack", rids: [foreign] });
    await new Promise((res) => setTimeout(res, 50));
    expect(r.store.counts().envelopes).toBe(1);
  });
});

describe("N3: auth and device rows are rate-limited and capped", () => {
  it("limits auth attempts per IP bucket", async () => {
    r = await startRelay({ limits: { authsPerIpv4PerMinute: 2 } });
    await authed(r, makeDevice(makeIdentity(), r.nowSec()));
    await authed(r, makeDevice(makeIdentity(), r.nowSec()));
    const c = await TestClient.connect(r.url);
    expect(await c.auth(makeDevice(makeIdentity(), r.nowSec()))).toEqual({ t: "error", code: "rate-limited" });
    expect(await c.closed).toBe(CLOSE.tooManyConnections);
  });

  it("limits new connections per IP bucket", async () => {
    r = await startRelay({ limits: { connectsPerIpPerMinute: 2 } });
    const a = await TestClient.connect(r.url);
    const b = await TestClient.connect(r.url);
    await expect(TestClient.connect(r.url)).rejects.toThrow(/429/);
    r.clock.advance(60_000);
    const c = await TestClient.connect(r.url);
    for (const x of [a, b, c]) await x.close();
  });

  it("caps device rows; known devices still get in", async () => {
    r = await startRelay({ limits: { maxDevices: 2 } });
    const d1 = makeDevice(makeIdentity(), r.nowSec());
    const d2 = makeDevice(makeIdentity(), r.nowSec());
    // Both stay connected, so neither binding can be evicted.
    const c1 = await authed(r, d1);
    await authed(r, d2);
    const c = await TestClient.connect(r.url);
    expect(await c.auth(makeDevice(makeIdentity(), r.nowSec()))).toEqual({ t: "error", code: "full" });
    expect(r.store.counts().devices).toBe(2);
    await authed(r, d1); // known: always gets in
    await c1.close();
  });
});


describe("N4: tombstones keep rule 6 after documents go", () => {
  async function setup() {
    r = await startRelay();
    const id = makeIdentity();
    const keeper = makeDevice(id, r.nowSec());
    const revoked = makeDevice(id, r.nowSec());
    const kc = await authed(r, keeper);
    const v1 = makeDoc(id, r.nowSec(), { devices: [keeper.did, revoked.did] });
    await publish(kc, v1.jws);
    const v2 = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [keeper.did] });
    await publish(kc, v2.jws);
    return { id, keeper, revoked, kc, v1, v2 };
  }

  it("the owner leaving keeps the last allowlist: a revoked device still can't authenticate", async () => {
    const { id, keeper, revoked, kc, v2 } = await setup();
    const leave = makeDoc(id, r.nowSec(), { ver: 3, prev: v2.hash, devices: [keeper.did], relays: ["wss://elsewhere.test/v3"] });
    expect(await publish(kc, leave.jws)).toMatchObject({ t: "ok" });
    expect(r.store.counts().identityDocs).toBe(0);
    expect((await fetch(`${r.http}/v3/identity/${id.userId}`)).status).toBe(404);
    // Its did was dropped (retired), so it isn't even restricted.
    expect(await (await TestClient.connect(r.url)).auth(revoked)).toEqual({ t: "error", code: "auth-failed" });
    await authed(r, keeper);
  });

  it("'owner left' needs a document chaining from the current head, not an older version", async () => {
    const { id, keeper, kc, v1 } = await setup();
    const fromOld = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [keeper.did], relays: ["wss://elsewhere.test/v3"], name: "x" });
    expect(await publish(kc, fromOld.jws)).toMatchObject({ code: "forbidden" });
    expect((await fetch(`${r.http}/v3/identity/${id.userId}`)).status).toBe(200);
  });

  it("re-entry after a tombstone needs a higher ver, and its allowlist is capped until a document chains", async () => {
    const { id, keeper, revoked, kc, v1, v2 } = await setup();
    const leave = makeDoc(id, r.nowSec(), { ver: 3, prev: v2.hash, devices: [keeper.did], relays: ["wss://elsewhere.test/v3"] });
    await publish(kc, leave.jws);
    const kc2 = await authed(r, keeper);
    // Replaying the old v1 (which lists the revoked device) is refused: not newer than the tombstone.
    expect(await publish(kc2, v1.jws)).toMatchObject({ code: "identity-gap" });
    // A newer root re-listing the revoked device: state-based acceptance takes it (clients enforce
    // no-return), but the allowlist is capped by the tombstone's and the revoked did stays out.
    const fresh = makeDevice(id, r.nowSec());
    const v4 = makeDoc(id, r.nowSec(), { ver: 4, prev: leave.hash, devices: [keeper.did, revoked.did, fresh.did] });
    expect(await publish(kc2, v4.jws)).toMatchObject({ t: "ok" });
    expect(new Set(r.store.identityIndex(id.userId)!.allowed)).toEqual(new Set([keeper.did]));
    // A revoked did gets no connection at all, not even restricted.
    expect(await (await TestClient.connect(r.url)).auth(revoked)).toEqual({ t: "error", code: "auth-failed" });
    // The owner's next version chains onto it: the cap lifts.
    const v5 = makeDoc(id, r.nowSec(), { ver: 5, prev: v4.hash, devices: [keeper.did, fresh.did] });
    expect(await publish(kc2, v5.jws)).toMatchObject({ t: "ok" });
    expect(r.store.identityIndex(id.userId)!.cap).toBeNull();
    await authed(r, fresh);
  });

  it("replacing an unanchored history caps the allowlist by the previous one", async () => {
    r = await startRelay();
    const id = makeIdentity();
    const a = makeDevice(id, r.nowSec());
    const added = makeDevice(id, r.nowSec());
    const ac = await authed(r, a);
    const v5 = makeDoc(id, r.nowSec(), { ver: 5, prev: jwsHash("fake-A"), devices: [a.did] });
    await publish(ac, v5.jws);
    const v7 = makeDoc(id, r.nowSec(), { ver: 7, prev: jwsHash("fake-B"), devices: [a.did, added.did] });
    expect(await publish(ac, v7.jws)).toMatchObject({ t: "ok" });
    // Listed in a held version but outside the (capped) allowlist: refused until a version chains.
    expect(await (await TestClient.connect(r.url)).auth(added)).toEqual({ t: "error", code: "auth-failed" });
    const v8 = makeDoc(id, r.nowSec(), { ver: 8, prev: v7.hash, devices: [a.did, added.did] });
    expect(await publish(ac, v8.jws)).toMatchObject({ t: "ok" });
    await authed(r, added);
  });

  it("the expiry sweep tombstones rather than forgets", async () => {
    const { id, revoked } = await setup();
    r.clock.advance(120 * DAY * 1000);
    await r.relay.sweep();
    expect(r.store.counts().identityDocs).toBe(0);
    expect(r.store.identityIndex(id.userId)?.leftAt).not.toBeNull();
    expect(r.relay.identity.allowedDevices(id.userId)?.has(revoked.did)).toBe(false);
  });
});

describe("N5: a kicked connection leaves at once", () => {
  it("is out of the mailbox and userId maps, ignores frames, and is gone", async () => {
    r = await startRelay();
    const id = makeIdentity();
    const keeper = makeDevice(id, r.nowSec());
    const lost = makeDevice(id, r.nowSec());
    const kc = await authed(r, keeper);
    const lc = await authed(r, lost);
    const v1 = makeDoc(id, r.nowSec(), { devices: [keeper.did, lost.did] });
    await publish(kc, v1.jws);
    const v2 = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [keeper.did] });
    expect(await publish(kc, v2.jws)).toMatchObject({ t: "ok" });
    // By the time the publisher sees `ok`, the lost device is unregistered.
    expect(internals().byMailbox.has(`${id.userId}\n${lost.did}`)).toBe(false);
    expect([...internals().byIss.get(id.userId)].length).toBe(1);
    const lostConn = [...internals().conns].find((c: any) => c.kicked);
    expect(lostConn?.auth).toBeUndefined();
    expect(await lc.closed).toBe(CLOSE.authFailed);
    expect(internals().unauthConns.size).toBe(0);
  });
});

describe("N7: publish is atomic; anchoring is recomputed", () => {
  let dir: string;
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("a failure mid-publish leaves the documents and index untouched", async () => {
    dir = mkdtempSync(join(tmpdir(), "p2p-relay-n7-"));
    let failNext = false;
    class FlakyStore extends SqliteStore {
      putIdentityDoc(d: StoredIdentityDoc): boolean {
        if (failNext) throw new Error("disk full");
        return super.putIdentityDoc(d);
      }
    }
    r = await startRelay({ store: new FlakyStore(join(dir, "relay.db")), limits: { identityMaxVersions: 3 } });
    const id = makeIdentity();
    const dev = makeDevice(id, r.nowSec());
    const c = await authed(r, dev);
    let prev: string | null = null;
    for (let ver = 1; ver <= 3; ver++) {
      const d = makeDoc(id, r.nowSec(), { ver, prev, devices: [dev.did] });
      await publish(c, d.jws);
      prev = d.hash;
    }
    const before = r.store.identityIndex(id.userId);
    failNext = true;
    expect(await publish(c, makeDoc(id, r.nowSec(), { ver: 4, prev, devices: [dev.did] }).jws)).toMatchObject({ t: "error" });
    // The prune of v1 rolled back with the failed insert.
    expect(r.store.identityDocs(id.userId).map((d) => d.ver)).toEqual([1, 2, 3]);
    expect(r.store.identityIndex(id.userId)).toEqual(before);
  });

  it("once the ver-1 root is swept, the history counts as unanchored", async () => {
    dir = mkdtempSync(join(tmpdir(), "p2p-relay-n7b-"));
    r = await startRelay();
    const id = makeIdentity();
    const dev = makeDevice(id, r.nowSec());
    const c = await authed(r, dev);
    const v1 = makeDoc(id, r.nowSec(), { devices: [dev.did] });
    await publish(c, v1.jws);
    const gap = () => makeDoc(id, r.nowSec(), { ver: 9, prev: jwsHash("fake-C"), devices: [dev.did] });
    expect(await publish(c, gap().jws)).toMatchObject({ code: "identity-gap" });
    r.clock.advance(10 * DAY * 1000);
    const c2 = await authed(r, makeDevice(id, r.nowSec(), {}, dev.spkSecret));
    const v2 = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [dev.did] });
    await publish(c2, v2.jws);
    r.clock.advance(85 * DAY * 1000); // v1 is 95 days old, v2's head not yet expired 90 days
    await r.relay.sweep();
    expect(r.store.identityDocs(id.userId).map((d) => d.ver)).toEqual([2]);
    const c3 = await authed(r, makeDevice(id, r.nowSec(), {}, dev.spkSecret));
    expect(await publish(c3, gap().jws)).toMatchObject({ t: "ok" });
  });
});

describe("N8: TRUST_PROXY addresses", () => {
  it("strips brackets and ports before bucketing", () => {
    expect(ipBucket("[2001:db8:1:2::1]:443")).toBe("2001:db8:1:2::/64");
    expect(ipBucket("[2001:db8:1:2::1]")).toBe("2001:db8:1:2::/64");
    expect(ipBucket("203.0.113.5:4433")).toBe("203.0.113.5");
    expect(clientAddress("10.0.0.1", "203.0.113.5:4433, 10.0.0.2", 2)).toBe("203.0.113.5");
  });

  it("warns (rate-limited) when X-Forwarded-For has fewer hops than configured", async () => {
    let short = -1;
    expect(clientAddress("10.0.0.1", "203.0.113.5", 2, (h) => (short = h))).toBe("10.0.0.1");
    expect(short).toBe(1);
    r = await startRelay({ config: { trustProxy: 2 } });
    for (let i = 0; i < 3; i++) await (await TestClient.connect(r.url, { "x-forwarded-for": "203.0.113.5" })).close();
    const warns = r.logs.filter((l) => l.includes("fewer hops than TRUST_PROXY"));
    expect(warns).toHaveLength(1);
    expect(JSON.parse(warns[0])).toMatchObject({ level: "warn", hops: 1, trustProxy: 2 });
  });
});

describe("N6: link budget per IP still holds with reservations", () => {
  it("per-IP open cap still applies", async () => {
    r = await startRelay({ limits: { linkOpenPerIp: 1 } });
    const lid = (n: number) => b32Encode(new Uint8Array(20).fill(n)).slice(0, 26);
    const a = await authed(r, makeDevice(makeIdentity(), r.nowSec()));
    const b = await authed(r, makeDevice(makeIdentity(), r.nowSec()));
    expect(await a.request({ t: "link-open", lid: lid(1) })).toMatchObject({ t: "ok" });
    expect(await b.request({ t: "link-open", lid: lid(2) })).toMatchObject({ code: "full" });
  });
});
