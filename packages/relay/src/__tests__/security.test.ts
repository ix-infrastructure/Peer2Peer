// Copyright 2026 Ix Infrastructure Inc.
// Regression tests for the pre-release security review (H1–H2, M1–M5, L1–L5, nits).

import { afterEach, describe, expect, it } from "vitest";
import { randomBytes } from "@peer2peer/core";
import { b32Encode, jwsHash, testRelayCrypto } from "../crypto.js";
import { clientAddress, ipBucket } from "../net.js";
import { RateLimiter } from "../ratelimit.js";
import { CLOSE } from "../server.js";
import { MemoryStore, type NewEnvelope, type MailboxCaps } from "../store.js";
import {
  authed,
  crypto,
  DAY,
  makeCap,
  makeDevice,
  makeDoc,
  makeEnvelope,
  makeIdentity,
  startRelay,
  TestClient,
  type Device,
  type Identity,
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
const get = async (path: string) => (await fetch(`${r.http}${path}`)).status;

async function pair(opts: StartOptions = {}) {
  r = await startRelay(opts);
  const alice = makeDevice(makeIdentity(), r.nowSec());
  const bob = makeDevice(makeIdentity(), r.nowSec());
  const ac = await authed(r, alice);
  const bc = await authed(r, bob);
  return { alice, bob, ac, bc };
}

// ---------------------------------------------------------------------------

describe("H1: identity documents are bounded", () => {
  let id: Identity;
  let dev: Device;
  let c: TestClient;
  async function setup(opts: StartOptions = {}) {
    r = await startRelay(opts);
    id = makeIdentity();
    dev = makeDevice(id, r.nowSec());
    c = await authed(r, dev);
  }

  it("refuses documents that don't list this relay", async () => {
    await setup();
    const d = makeDoc(id, r.nowSec(), { devices: [dev.did], relays: ["wss://elsewhere.test/v3"] });
    expect(await publish(c, d.jws)).toMatchObject({ code: "forbidden" });
    expect(r.store.counts().identityDocs).toBe(0);
  });

  it("a chained version that drops this relay deletes the identity here", async () => {
    await setup();
    const v1 = makeDoc(id, r.nowSec(), { devices: [dev.did] });
    await publish(c, v1.jws);
    const v2 = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [dev.did], relays: ["wss://elsewhere.test/v3"] });
    expect(await publish(c, v2.jws)).toMatchObject({ t: "ok" });
    expect(r.store.counts().identityDocs).toBe(0);
    expect(await get(`/v3/identity/${id.userId}`)).toBe(404);
  });

  it("caps branch tips per userId (4) and refuses further siblings", async () => {
    await setup();
    const v1 = makeDoc(id, r.nowSec(), { devices: [dev.did] });
    await publish(c, v1.jws);
    for (let i = 0; i < 4; i++) {
      const sib = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [dev.did], name: `s${i}` });
      expect(await publish(c, sib.jws)).toMatchObject({ t: "ok" });
    }
    const fifth = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [dev.did], name: "s4" });
    expect(await publish(c, fifth.jws)).toMatchObject({ code: "full" });
    expect(r.store.identityIndex(id.userId)!.tips).toHaveLength(4);
  });

  it("caps versions per userId, dropping the oldest non-tips", async () => {
    await setup({ limits: { identityMaxVersions: 4 } });
    let prev: string | null = null;
    let last = "";
    for (let ver = 1; ver <= 8; ver++) {
      const d = makeDoc(id, r.nowSec(), { ver, prev, devices: [dev.did] });
      expect(await publish(c, d.jws)).toMatchObject({ t: "ok" });
      prev = d.hash;
      last = d.jws;
    }
    expect(r.store.identityDocs(id.userId).map((d) => d.ver)).toEqual([5, 6, 7, 8]);
    expect((await (await fetch(`${r.http}/v3/identity/${id.userId}`)).json()).doc).toBe(last);
  });

  it("rate-limits publishes per userId and per IP", async () => {
    await setup({ limits: { identityPublishPerIssPerHour: 2 } });
    let prev: string | null = null;
    const results = [];
    for (let ver = 1; ver <= 3; ver++) {
      const d = makeDoc(id, r.nowSec(), { ver, prev, devices: [dev.did] });
      results.push((await publish(c, d.jws)).t === "ok" ? "ok" : "limited");
      prev = d.hash;
    }
    expect(results).toEqual(["ok", "ok", "limited"]);
    await r.close();

    r = await startRelay({ limits: { identityPublishPerIpPerHour: 2 } });
    const out = [];
    for (let i = 0; i < 3; i++) {
      const other = makeIdentity();
      const od = makeDevice(other, r.nowSec());
      const oc = await authed(r, od);
      out.push((await publish(oc, makeDoc(other, r.nowSec(), { devices: [od.did] }).jws)).t);
    }
    expect(out).toEqual(["ok", "ok", "error"]);
  });

  it("request paths read the index, never every document", async () => {
    let scans = 0;
    class CountingStore extends MemoryStore {
      identityDocs(iss: string) {
        scans++;
        return super.identityDocs(iss);
      }
    }
    await setup({ store: new CountingStore() });
    const other = makeDevice(makeIdentity(), r.nowSec());
    const oc = await authed(r, other);
    await publish(c, makeDoc(id, r.nowSec(), { devices: [dev.did] }).jws);
    const before = scans;
    expect(await get(`/v3/identity/${id.userId}`)).toBe(200);
    expect(await get(`/v3/identity/${id.userId}/tips`)).toBe(200);
    await authed(r, dev);
    expect(await sendWith(oc, other, dev, { cap: makeCap(dev, r.nowSec()).jws })).toMatchObject({ t: "sent" });
    expect(scans).toBe(before);
  });
});

describe("H2: disk writes have budgets", () => {
  it("per-connection byte budget", async () => {
    const { alice, bob, ac } = await pair({ limits: { sendBytesPerConnPerMinute: 3000 } });
    const cap = makeCap(bob, r.nowSec()).jws;
    const replies = [];
    for (let i = 0; i < 4; i++) replies.push((await sendWith(ac, alice, bob, { cap })).t);
    expect(replies).toContain("error");
    expect(await sendWith(ac, alice, bob, { cap })).toMatchObject({ code: "rate-limited" });
    r.clock.advance(60_000);
    expect(await sendWith(ac, alice, bob, { cap })).toMatchObject({ t: "sent" });
  });

  it("per-IP byte budget across connections", async () => {
    const { alice, bob, ac } = await pair({ limits: { sendBytesPerIpPerMinute: 4000 } });
    const carol = makeDevice(makeIdentity(), r.nowSec());
    const cc = await authed(r, carol);
    expect(await sendWith(ac, alice, bob, { cap: makeCap(bob, r.nowSec()).jws })).toMatchObject({ t: "sent" });
    // Carol's connection is new but shares the IP.
    let limited = false;
    for (let i = 0; i < 3 && !limited; i++) {
      limited = (await sendWith(cc, carol, bob, { cap: makeCap(bob, r.nowSec()).jws })).code === "rate-limited";
    }
    expect(limited).toBe(true);
  });

  it("past the hard store ceiling (eviction not keeping up), caps and contacts alike get undeliverable", async () => {
    class NoEvictStore extends MemoryStore {
      evictGlobal(): number {
        return 0;
      }
    }
    const { alice, bob, ac, bc } = await pair({ store: new NoEvictStore(), limits: { storeMaxBytes: 1000, storeHardMaxBytes: 6000 } });
    const cap = makeCap(bob, r.nowSec()).jws;
    const ghost = makeDevice(makeIdentity(), r.nowSec());
    let full = false;
    for (let i = 0; i < 10 && !full; i++) full = (await sendWith(ac, alice, bob, { cap })).code === "undeliverable";
    expect(full).toBe(true);
    expect(await sendWith(ac, alice, bob, { id: "q" }, { kind: "contact" })).toEqual({ t: "error", id: "q", code: "undeliverable" });
    expect(await sendWith(ac, alice, ghost, { id: "q" }, { kind: "contact" })).toEqual({ t: "error", id: "q", code: "undeliverable" });
    // Acking frees quota.
    const envs = await bc.drainEnvs();
    bc.send({ t: "ack", rids: envs.map((e) => e.rid) });
    await new Promise((res) => setTimeout(res, 50));
    expect(await sendWith(ac, alice, bob, { cap })).toMatchObject({ t: "sent" });
  });

  it("revoke is rate-limited per connection and per userId", async () => {
    const { alice, ac } = await pair({ limits: { revokesPerConnPerMinute: 2, revokesPerIssPerHour: 3 } });
    const capid = () => Buffer.from(randomBytes(16)).toString("base64url");
    const a = [];
    for (let i = 0; i < 3; i++) a.push((await ac.request({ t: "revoke", capid: capid() })).t);
    expect(a).toEqual(["ok", "ok", "error"]);
    const ac2 = await authed(r, makeDevice(alice.identity, r.nowSec()));
    expect(await ac2.request({ t: "revoke", capid: capid() })).toMatchObject({ t: "ok" });
    expect(await ac2.request({ t: "revoke", capid: capid() })).toMatchObject({ code: "rate-limited" }); // iss budget (3) spent
  });

  it("device bindings are refreshed on auth and pruned after 90 days unseen", async () => {
    r = await startRelay();
    const id = makeIdentity();
    const old = makeDevice(id, r.nowSec());
    const fresh = makeDevice(id, r.nowSec());
    (await authed(r, old)).close();
    (await authed(r, fresh)).close();
    r.clock.advance(60 * DAY * 1000);
    const fresh2 = { ...fresh, cert: makeDevice(id, r.nowSec(), {}, fresh.spkSecret).cert };
    (await authed(r, fresh2)).close();
    r.clock.advance(31 * DAY * 1000);
    await r.relay.sweep();
    expect(r.store.deviceIssuer(old.did)).toBeUndefined();
    expect(r.store.deviceIssuer(fresh.did)).toBe(id.userId);
  });
});

describe("M1: rule 6 holds for live sessions, sends and mailboxes", () => {
  it("publishing a version without a device closes that device's live connections", async () => {
    r = await startRelay();
    const id = makeIdentity();
    const keeper = makeDevice(id, r.nowSec());
    const lost = makeDevice(id, r.nowSec());
    const kc = await authed(r, keeper);
    const lc = await authed(r, lost);
    const v1 = makeDoc(id, r.nowSec(), { devices: [keeper.did, lost.did] });
    expect(await publish(kc, v1.jws)).toMatchObject({ t: "ok" });
    const v2 = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [keeper.did] });
    expect(await publish(kc, v2.jws)).toMatchObject({ t: "ok" });
    expect(await lc.closed).toBe(CLOSE.authFailed);
    expect(kc.closeCode).toBeUndefined();
  });

  it("checks rule 6 on send from the cached allowlist", async () => {
    const { alice, bob, ac } = await pair();
    // The allowlist changes underneath the session (as if by another path).
    r.store.putIdentityIndex({ iss: alice.identity.userId, head: "h", headVer: 1, headExp: r.nowSec() + DAY, tips: ["h"], allowed: [], cap: null, leftAt: null });
    expect(await sendWith(ac, alice, bob, { cap: makeCap(bob, r.nowSec()).jws })).toMatchObject({ code: "auth-failed" });
    expect(await ac.closed).toBe(CLOSE.authFailed);
  });

  it("a bound did that the held document no longer lists is not a mailbox", async () => {
    const { alice, bob, ac, bc } = await pair();
    const bob2 = makeDevice(bob.identity, r.nowSec());
    const doc = makeDoc(bob.identity, r.nowSec(), { devices: [bob2.did] });
    const b2c = await authed(r, bob2);
    expect(await publish(b2c, doc.jws)).toMatchObject({ t: "ok" });
    await bc.closed; // bob's old device was kicked
    expect(await sendWith(ac, alice, bob, { id: "x", cap: makeCap(bob2, r.nowSec()).jws })).toEqual({ t: "error", id: "x", code: "undeliverable" });
    expect(await sendWith(ac, alice, bob, {}, { kind: "contact" })).toMatchObject({ t: "sent" });
    expect(r.store.counts().envelopes).toBe(0);
  });
});

describe("M3: cheap checks first", () => {
  it("rejects a foreign sender before any signature work, and reuses the authenticated cert", async () => {
    let certChecks = 0;
    const counting = testRelayCrypto({
      verifyDeviceCert: (jws, opts) => {
        certChecks++;
        return crypto.verifyDeviceCert(jws, opts);
      },
    });
    const { alice, bob, ac } = await pair({ crypto: counting });
    certChecks = 0;
    // Bob's envelope on Alice's connection: rejected without verifying a cert.
    const env = makeEnvelope(bob, to(alice), { kind: "contact" });
    expect(await ac.request({ t: "send", to: alice.identity.userId, tdid: alice.did, env })).toMatchObject({ code: "bad-envelope" });
    expect(certChecks).toBe(0);
    // Alice's own envelope carries the cert she authenticated with: no re-verification.
    expect(await sendWith(ac, alice, bob, {}, { kind: "contact" })).toMatchObject({ t: "sent" });
    expect(certChecks).toBe(0);
  });

  it("limits frames of every type per connection", async () => {
    r = await startRelay({ limits: { framesPerConnPerMinute: 3 } });
    const c = await TestClient.connect(r.url);
    const lid = b32Encode(new Uint8Array(20)).slice(0, 26);
    const got = [];
    for (let i = 0; i < 4; i++) {
      const reply = c.next((f) => f.t === "error");
      c.send({ t: "link-get", lid, slot: "req" });
      got.push((await reply).code);
    }
    expect(got).toEqual(["not-found", "not-found", "not-found", "rate-limited"]);
    await c.close();
  });
});

describe("M4: IPv6 /64 buckets, per-userId and unauthenticated connection caps", () => {
  it("buckets IPv6 by /64 and unwraps IPv4-mapped addresses", () => {
    expect(ipBucket("203.0.113.9")).toBe("203.0.113.9");
    expect(ipBucket("::ffff:203.0.113.9")).toBe("203.0.113.9");
    expect(ipBucket("2001:db8:1:2:aaaa::1")).toBe("2001:db8:1:2::/64");
    expect(ipBucket("2001:0db8:0001:0002:ffff:ffff:ffff:ffff")).toBe("2001:db8:1:2::/64");
    expect(ipBucket("2001:db8::1")).toBe("2001:db8:0:0::/64");
    expect(ipBucket("2001:db8:1:3::1")).not.toBe(ipBucket("2001:db8:1:2::1"));
    expect(ipBucket("fe80::1%eth0")).toBe("fe80:0:0:0::/64");
  });

  it("applies the per-IP connection cap to a whole /64", async () => {
    r = await startRelay({ config: { trustProxy: 1 }, limits: { maxConnectionsPerIp: 2 } });
    const from = (ip: string) => TestClient.connect(r.url, { "x-forwarded-for": ip });
    const a = await from("2001:db8:1:2::1");
    const b = await from("2001:db8:1:2::ffff");
    await expect(from("2001:db8:1:2:9::9")).rejects.toThrow(/429/);
    const other = await from("2001:db8:1:3::1");
    for (const c of [a, b, other]) await c.close();
  });

  it("caps connections per userId", async () => {
    r = await startRelay({ limits: { maxConnectionsPerIss: 2 } });
    const id = makeIdentity();
    await authed(r, makeDevice(id, r.nowSec()));
    await authed(r, makeDevice(id, r.nowSec()));
    const c = await TestClient.connect(r.url);
    expect(await c.auth(makeDevice(id, r.nowSec()))).toEqual({ t: "error", code: "full" });
    expect(await c.closed).toBe(CLOSE.tooManyConnections);
  });

  it("TRUST_PROXY names the hop: the n-th X-Forwarded-For entry from the right", () => {
    expect(clientAddress("10.0.0.1", "198.51.100.7, 203.0.113.5, 10.0.0.2", 0)).toBe("10.0.0.1");
    expect(clientAddress("10.0.0.1", "198.51.100.7, 203.0.113.5, 10.0.0.2", 1)).toBe("10.0.0.2");
    expect(clientAddress("10.0.0.1", "198.51.100.7, 203.0.113.5, 10.0.0.2", 2)).toBe("203.0.113.5");
    // Fewer hops than proxies: trust only the socket.
    expect(clientAddress("10.0.0.1", "203.0.113.5", 2)).toBe("10.0.0.1");
  });
});

describe("M5: link mailboxes are bounded", () => {
  const lid = (n: number) => b32Encode(new Uint8Array(20).fill(n)).slice(0, 26);

  it("rate-limits link-open per userId and per IP", async () => {
    r = await startRelay({ limits: { linkOpenPerIssPerHour: 2, linkOpenPerIp: 100 } });
    const id = makeIdentity();
    const out = [];
    for (let i = 0; i < 3; i++) {
      const c = await authed(r, makeDevice(id, r.nowSec()));
      out.push((await c.request({ t: "link-open", lid: lid(i) })).t === "ok" ? "ok" : "limited");
    }
    expect(out).toEqual(["ok", "ok", "limited"]);
    await r.close();

    r = await startRelay({ limits: { linkOpenPerIpPerHour: 2, linkOpenPerIp: 100 } });
    const res = [];
    for (let i = 0; i < 3; i++) {
      const c = await authed(r, makeDevice(makeIdentity(), r.nowSec()));
      res.push((await c.request({ t: "link-open", lid: lid(i) })).code ?? "ok");
    }
    expect(res).toEqual(["ok", "ok", "rate-limited"]);
  });

  it("caps open mailboxes per IP", async () => {
    r = await startRelay({ limits: { linkOpenPerIp: 2 } });
    const res = [];
    for (let i = 0; i < 3; i++) {
      const c = await authed(r, makeDevice(makeIdentity(), r.nowSec()));
      res.push((await c.request({ t: "link-open", lid: lid(i) })).code ?? "ok");
    }
    expect(res).toEqual(["ok", "ok", "full"]);
  });

  it("N6: the global byte budget is reserved at open; a full budget refuses opens, never puts", async () => {
    const perBox = 5 * 16 * 1024; // 4 req entries + 1 resp entry
    r = await startRelay({ limits: { linkTotalBytes: 2 * perBox, linkOpsPerIpPerMinute: 1000 } });
    const c = await authed(r, makeDevice(makeIdentity(), r.nowSec()));
    const c2 = await authed(r, makeDevice(makeIdentity(), r.nowSec()));
    expect(await c.request({ t: "link-open", lid: lid(1) })).toMatchObject({ t: "ok" });
    expect(await c2.request({ t: "link-open", lid: lid(2) })).toMatchObject({ t: "ok" });
    expect(await c2.request({ t: "link-open", lid: lid(3) })).toMatchObject({ code: "full" });
    // Both open mailboxes can be filled completely: puts never hit the budget.
    const anon = await TestClient.connect(r.url);
    for (const l of [lid(1), lid(2)]) {
      for (let i = 0; i < 4; i++) expect(await anon.request({ t: "link-put", lid: l, slot: "req", data: "x".repeat(16 * 1024) })).toMatchObject({ t: "ok" });
    }
    expect(await c.request({ t: "link-put", lid: lid(1), slot: "resp", data: "x".repeat(16 * 1024) })).toMatchObject({ t: "ok" });
    // Expiry returns the reservation.
    r.clock.advance(11 * 60_000);
    expect(await c2.request({ t: "link-open", lid: lid(3) })).toMatchObject({ t: "ok" });
    await anon.close();
  });
});

describe("low findings", () => {
  it("L1: a cap signed by a device the issuer's document doesn't list is undeliverable", async () => {
    const { alice, bob, ac } = await pair();
    const bob2 = makeDevice(bob.identity, r.nowSec());
    const capByBob2 = makeCap(bob2, r.nowSec());
    const b2c = await authed(r, bob2);
    // Bob's document lists only bob (bob2 was revoked).
    expect(await publish(b2c, makeDoc(bob.identity, r.nowSec(), { devices: [bob.did] }).jws)).toMatchObject({ t: "ok" });
    expect(await sendWith(ac, alice, bob, { id: "l1", cap: capByBob2.jws })).toEqual({ t: "error", id: "l1", code: "undeliverable" });
    expect(await sendWith(ac, alice, bob, { cap: makeCap(bob, r.nowSec()).jws })).toMatchObject({ t: "sent" });
  });

  it("L2: `sent` is answered before any store work", async () => {
    class FailingStore extends MemoryStore {
      putEnvelope(_e: NewEnvelope, _c: MailboxCaps): never {
        throw new Error("disk on fire");
      }
    }
    const { alice, bob, ac } = await pair({ store: new FailingStore() });
    expect(await sendWith(ac, alice, bob, { id: "s" }, { kind: "contact" })).toEqual({ t: "sent", id: "s" });
    expect(await sendWith(ac, alice, bob, { id: "c", cap: makeCap(bob, r.nowSec()).jws })).toEqual({ t: "sent", id: "c" });
    await new Promise((res) => setTimeout(res, 50));
    expect(ac.frames.filter((f) => f.t === "error")).toEqual([]);
  });

  it("L3: rids are opaque, not a global counter", async () => {
    const { alice, bob, ac, bc } = await pair();
    const cap = makeCap(bob, r.nowSec()).jws;
    for (let i = 0; i < 3; i++) await sendWith(ac, alice, bob, { cap });
    const rids = (await bc.drainEnvs()).map((e) => e.rid as string);
    expect(rids).toHaveLength(3);
    for (const rid of rids) expect(rid).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(rids.some((x) => /^\d+$/.test(x))).toBe(false);
    // A numeric (internal) rid is not accepted as an ack.
    expect(await bc.request({ t: "ack", rids: ["1"] })).toMatchObject({ code: "bad-request" });
  });

  it("L4: RateLimiter holds at most maxKeys buckets, evicting the least recently used", () => {
    const t = 0;
    const rl = new RateLimiter(1, 60_000, () => t, 3);
    rl.take("a");
    rl.take("b");
    rl.take("c");
    rl.has("a"); // a is now most recently used
    rl.take("d"); // evicts b
    expect(rl.size).toBe(3);
    expect(rl.has("a")).toBe(false); // still spent: kept
    expect(rl.has("c")).toBe(false);
    for (let i = 0; i < 100; i++) rl.take(`k${i}`);
    expect(rl.size).toBe(3);
  });

  it("L5: a higher version from the same key replaces an unanchored root; an anchored history needs back-fill", async () => {
    r = await startRelay();
    const id = makeIdentity();
    const owner = makeDevice(id, r.nowSec());
    const revoked = makeDevice(id, r.nowSec());
    const rc = await authed(r, revoked);
    // The revoked device replays an old v5 that still lists it, to a relay holding nothing.
    const v5 = makeDoc(id, r.nowSec(), { ver: 5, prev: jwsHash("fake-A"), devices: [owner.did, revoked.did] });
    expect(await publish(rc, v5.jws)).toMatchObject({ t: "ok" });
    // The owner's current v7 doesn't chain to it, but replaces it.
    const oc = await authed(r, owner);
    const v7 = makeDoc(id, r.nowSec(), { ver: 7, prev: jwsHash("fake-B"), devices: [owner.did] });
    expect(await publish(oc, v7.jws)).toMatchObject({ t: "ok" });
    expect((await (await fetch(`${r.http}/v3/identity/${id.userId}`)).json()).doc).toBe(v7.jws);
    expect(await rc.closed).toBe(CLOSE.authFailed);
    // A lower or equal version can't replace it back.
    const v6 = makeDoc(id, r.nowSec(), { ver: 6, prev: jwsHash("fake-C"), devices: [owner.did, revoked.did] });
    expect(await publish(oc, v6.jws)).toMatchObject({ code: "identity-gap" });
  });

  it("L5: an anchored history (ver 1 held) is never replaced by a gap", async () => {
    r = await startRelay();
    const id = makeIdentity();
    const dev = makeDevice(id, r.nowSec());
    const c = await authed(r, dev);
    await publish(c, makeDoc(id, r.nowSec(), { devices: [dev.did] }).jws);
    const v9 = makeDoc(id, r.nowSec(), { ver: 9, prev: jwsHash("fake-D"), devices: [dev.did] });
    expect(await publish(c, v9.jws)).toMatchObject({ code: "identity-gap" });
  });
});

describe("nits", () => {
  it("keyholders is required in identity documents", async () => {
    r = await startRelay();
    const id = makeIdentity();
    const dev = makeDevice(id, r.nowSec());
    const c = await authed(r, dev);
    expect(await publish(c, makeDoc(id, r.nowSec(), { devices: [dev.did], keyholders: null }).jws)).toMatchObject({ code: "bad-identity" });
  });

  it("an identity document's iat may be at most 300 s in the future", async () => {
    r = await startRelay();
    const id = makeIdentity();
    const dev = makeDevice(id, r.nowSec());
    const c = await authed(r, dev);
    expect(await publish(c, makeDoc(id, r.nowSec(), { devices: [dev.did], iat: r.nowSec() + 301 }).jws)).toMatchObject({ code: "bad-identity" });
    expect(await publish(c, makeDoc(id, r.nowSec(), { devices: [dev.did], iat: r.nowSec() + 299 }).jws)).toMatchObject({ t: "ok" });
  });
});
