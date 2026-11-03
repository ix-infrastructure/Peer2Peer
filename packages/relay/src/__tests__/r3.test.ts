// Copyright 2026 Ix Infrastructure Inc.
//
// pre-release third re-review, with the agreed design: the relay keeps no permanent
// revocation history (R3-M1), and a restoring device back-fills a lagging
// relay (R3-M2).

import { afterEach, describe, expect, it } from "vitest";
import { MAX_SEEN_PER_ISS, MemoryStore } from "../store.js";
import { authed, DAY, makeDevice, makeDoc, makeIdentity, startRelay, TestClient, type TestRelay } from "./helpers.js";

let r: TestRelay;
afterEach(async () => {
  await r?.close();
});

const publish = (c: TestClient, jws: string) => c.request({ t: "identity", doc: jws });
const authResult = async (d: Parameters<TestClient["auth"]>[0]) => (await TestClient.connect(r.url)).auth(d);

describe("R3-M1: restricted auth from held state, no revocation history", () => {
  it("a revoked device gets no connection while its version is held; a new (restore) did still gets a restricted one", async () => {
    r = await startRelay();
    const id = makeIdentity();
    const k = makeDevice(id, r.nowSec());
    const lost = makeDevice(id, r.nowSec());
    const kc = await authed(r, k);
    const v1 = makeDoc(id, r.nowSec(), { devices: [k.did, lost.did] });
    await publish(kc, v1.jws);
    const v2 = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [k.did] });
    await publish(kc, v2.jws);
    expect(await authResult(lost)).toEqual({ t: "error", code: "auth-failed" });
    expect(await authResult(makeDevice(id, r.nowSec()))).toEqual({ t: "ok", restricted: true });
  });

  it("after a tombstone a revoked did stays refused through the window; then every row for the identity is gone", async () => {
    r = await startRelay();
    const id = makeIdentity();
    const k = makeDevice(id, r.nowSec());
    const lost = makeDevice(id, r.nowSec());
    const kc = await authed(r, k);
    const v1 = makeDoc(id, r.nowSec(), { devices: [k.did, lost.did] });
    await publish(kc, v1.jws);
    const v2 = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [k.did] });
    await publish(kc, v2.jws);
    // The owner leaves this relay: tombstone (documents deleted, dids remembered).
    const leave = makeDoc(id, r.nowSec(), { ver: 3, prev: v2.hash, devices: [k.did], relays: ["wss://elsewhere.test/v3"] });
    expect(await publish(kc, leave.jws)).toMatchObject({ t: "ok" });
    await kc.close();
    expect(r.store.identityDocs(id.userId)).toEqual([]);
    expect(await authResult(lost)).toEqual({ t: "error", code: "auth-failed" });
    // 80 days on (its certificate, 89 days, still valid): still refused.
    r.clock.advance(80 * DAY * 1000);
    await r.relay.sweep();
    expect(await authResult(lost)).toEqual({ t: "error", code: "auth-failed" });
    // Past the 91-day window: the tombstone and the remembered dids are gone (any certificate
    // listed then has expired by now, so nothing is re-opened).
    r.clock.advance(12 * DAY * 1000);
    await r.relay.sweep();
    expect(r.store.identityIndex(id.userId)).toBeUndefined();
    expect(r.store.seenDevices(id.userId, 0)).toEqual([]);
    expect(await authResult(lost)).toEqual({ t: "error", code: "auth-failed" }); // expired certificate
  });

  // Many publishes in a row: a timeout for a loaded machine (pre-release review), the assertions are counts.
  it("storage stays bounded under a list-and-drop loop: held versions and the capped seen rows only", { timeout: 60_000 }, async () => {
    r = await startRelay({ limits: { identityPublishPerIssPerHour: 10_000, identityPublishPerIpPerHour: 10_000, identityMaxVersions: 16 } });
    const id = makeIdentity();
    const k = makeDevice(id, r.nowSec());
    const kc = await authed(r, k);
    let prev = makeDoc(id, r.nowSec(), { devices: [k.did] });
    await publish(kc, prev.jws);
    let ver = 1;
    for (let i = 0; i < 60; i++) {
      const fresh = makeDevice(id, r.nowSec());
      const listed = makeDoc(id, r.nowSec(), { ver: ++ver, prev: prev.hash, devices: [k.did, fresh.did] });
      expect(await publish(kc, listed.jws)).toMatchObject({ t: "ok" });
      prev = makeDoc(id, r.nowSec(), { ver: ++ver, prev: listed.hash, devices: [k.did] });
      expect(await publish(kc, prev.jws)).toMatchObject({ t: "ok" });
    }
    expect(r.store.identityDocs(id.userId).length).toBeLessThanOrEqual(16);
    // Each dropped did is remembered (R4-M1) for 91 days, capped per user.
    expect(r.store.seenDevices(id.userId, 0).length).toBe(60);
    // What restricted auth consults: the held versions (≤ 16 × 10 dids) and the seen rows.
    expect(r.relay.identity.revoked(id.userId).size).toBeLessThanOrEqual(160 + 60);
    // The seen rows are capped per user, however many drops there are.
    r.store.addSeen(id.userId, Array.from({ length: 3000 }, (_, i) => `d_${String(i).padStart(26, "a")}`), r.clock.t);
    expect(r.store.seenDevices(id.userId, 0).length).toBe(MAX_SEEN_PER_ISS);
  });

  it("every authenticated connection is closed when its certificate expires", async () => {
    r = await startRelay();
    const id = makeIdentity();
    const short = makeDevice(id, r.nowSec(), { iat: r.nowSec() - 10, exp: r.nowSec() + 1 });
    const c = await authed(r, short);
    const t0 = Date.now();
    // 4003: certificate expired, reconnect with a renewed one (not 4001, a revocation: R4-L1).
    expect(await c.closed).toBe(4003);
    expect(Date.now() - t0).toBeLessThan(5000);
  });
});

describe("R3-M2: a restoring device back-fills a lagging relay", () => {
  it("an unheld parent is `identity-gap` (not forbidden); back-filled versions are accepted; a fork stays forbidden", async () => {
    r = await startRelay();
    const id = makeIdentity();
    const old = makeDevice(id, r.nowSec());
    const oc = await authed(r, old);
    const v1 = makeDoc(id, r.nowSec(), { devices: [old.did] });
    expect(await publish(oc, v1.jws)).toMatchObject({ t: "ok" });
    await oc.close();
    // Elsewhere the identity moved on (v2, v3) without this relay; the restore builds v4.
    const v2 = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [old.did], name: "two" });
    const v3 = makeDoc(id, r.nowSec(), { ver: 3, prev: v2.hash, devices: [old.did], name: "three" });
    const restored = makeDevice(id, r.nowSec());
    const v4 = makeDoc(id, r.nowSec(), { ver: 4, prev: v3.hash, devices: [restored.did] });
    const c = await TestClient.connect(r.url);
    expect(await c.auth(restored)).toEqual({ t: "ok", restricted: true });
    expect(await publish(c, v4.jws)).toMatchObject({ code: "identity-gap" });
    expect(await publish(c, v2.jws)).toMatchObject({ t: "ok" });
    const fork = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [restored.did], name: "fork" });
    expect(await publish(c, fork.jws)).toMatchObject({ code: "forbidden" });
    expect(await publish(c, v3.jws)).toMatchObject({ t: "ok" });
    expect(await publish(c, v4.jws)).toMatchObject({ t: "ok" });
    expect(r.relay.identity.head(id.userId)?.hash).toBe(v4.hash);
    await c.close();
  });
});

describe("R4-M1: pruning can't re-open a restricted connection for a revoked device", () => {
  it("a revoked device stays refused after its versions are pruned by the cap and by the 90-day sweep", async () => {
    r = await startRelay({ limits: { identityPublishPerIssPerHour: 10_000, identityPublishPerIpPerHour: 10_000, identityMaxVersions: 4 } });
    const id = makeIdentity();
    const k = makeDevice(id, r.nowSec());
    const lost = makeDevice(id, r.nowSec());
    const kc = await authed(r, k);
    let prev = makeDoc(id, r.nowSec(), { devices: [k.did, lost.did] });
    await publish(kc, prev.jws);
    // Revoke, then push every version that listed `lost` out under the cap.
    for (let ver = 2; ver <= 8; ver++) {
      prev = makeDoc(id, r.nowSec(), { ver, prev: prev.hash, devices: [k.did], name: `v${ver}` });
      expect(await publish(kc, prev.jws)).toMatchObject({ t: "ok" });
    }
    expect(r.store.identityDocs(id.userId).some((d) => d.devices.includes(lost.did))).toBe(false);
    expect(await authResult(lost)).toEqual({ t: "error", code: "auth-failed" });
    // 85 days later (cert still valid, 89 days), after the sweep: still refused.
    r.clock.advance(85 * DAY * 1000);
    await r.relay.sweep();
    expect(await authResult(lost)).toEqual({ t: "error", code: "auth-failed" });
  });

  it("the sweep remembers the dids of swept versions outside the allowlist", async () => {
    const s = new MemoryStore();
    await s.init();
    const iss = makeIdentity().userId;
    const doc = (hash: string, prevH: string | null, devices: string[], receivedAt: number) => ({ hash, iss, ver: prevH ? 2 : 1, prev: prevH, merge: null, jws: `j.${hash}.x`, devices, iat: 1, exp: 2, receivedAt });
    s.putIdentityDoc(doc("h1", null, ["d_kkkkkkkkkkkkkkkkkkkkkkkkkk", "d_llllllllllllllllllllllllll"], 0));
    s.putIdentityDoc(doc("h2", "h1", ["d_kkkkkkkkkkkkkkkkkkkkkkkkkk"], 10_000));
    s.putIdentityIndex({ iss, head: "h2", headVer: 2, headExp: 2, tips: ["h2"], allowed: ["d_kkkkkkkkkkkkkkkkkkkkkkkkkk"], cap: null, leftAt: null });
    s.sweep({ capsBefore: 0, identityVersionsBefore: 5_000, devicesBefore: 0, nowMs: 7 } as never, 1e9);
    expect(s.identityDoc("h1")).toBeUndefined();
    expect(s.seenDevices(iss, 0)).toEqual(["d_llllllllllllllllllllllllll"]);
  });
});
