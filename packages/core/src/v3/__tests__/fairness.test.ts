// Copyright 2026 Ix Infrastructure Inc.
//
// Regression tests for the pre-release re-review: S1 (per-relay caps and timeouts,
// a budget that excludes fetch time, committing progress on overrun), S2 (a
// merge dropping a one-branch did isn't revocation), S3 (no keyholder
// denylist), S4 (the commit re-checks anchoring before jumping).

import { describe, expect, it } from "vitest";
import { createIdentityDoc, IdentityChain, mergeFields, verifyIdentityDocSignature, type VerifiedIdentityDoc } from "../identitydoc.js";
import { addIdentityVersion, getIdentityView, jumpIdentity, refreshIdentity, type IdentityFetcher } from "../state.js";
import { makeUser, NOW, RELAY, RELAY2, storeKnowing, type TestUser } from "./fixtures.js";

function doc(u: TestUser, f: { ver: number; prev: string; devices: string[]; keyholders: string[]; iat: number; merge?: string }): VerifiedIdentityDoc {
  return verifyIdentityDocSignature(
    createIdentityDoc(u.ik, {
      ver: f.ver,
      prev: f.prev,
      ...(f.merge ? { merge: f.merge } : {}),
      name: u.name,
      relays: [RELAY, RELAY2],
      devices: f.devices,
      keyholders: f.keyholders,
      by: f.keyholders[0],
      certs: u.devices.filter((d) => f.devices.includes(d.did)).map((d) => d.cert),
      iat: f.iat,
    }),
  );
}

/** v1..v17 list d2; v18 revokes it. The client holds v1..v10. */
async function revocationAtTheTop() {
  const u = makeUser("alice");
  u.relays = [RELAY, RELAY2];
  const d2 = u.addDevice({ keyholder: false });
  for (let i = 0; i < 16; i++) u.publish({ iat: NOW - 1000 + i });
  const revoking = u.publish({ devices: [u.dev.did], iat: NOW - 10 });
  const store = await storeKnowing();
  await store.putIdentity({ iss: u.userId, versions: u.docs.slice(0, 10).map((d) => d.jws) });
  return { u, d2, revoking, store };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("S1: one slow or hostile relay can't hide a revocation", () => {
  it("caps apply per relay: 16 older genuine versions from one relay don't push out the other's revoking head", async () => {
    const { u, d2, revoking, store } = await revocationAtTheTop();
    const older = u.docs.slice(1, 17).map((d) => d.jws); // v2..v17, all genuine
    const fetcher: IdentityFetcher = async () => ({ [RELAY2]: older, [RELAY]: [revoking.jws] });
    const view = await refreshIdentity(store, u.userId, fetcher, { now: NOW });
    expect(view.head.hash).toBe(revoking.hash);
    expect(view.devices).not.toContain(d2.did);
    expect(view.incomplete).toBeUndefined();
  });

  it("each relay keeps its highest-ver valid tips first", async () => {
    const { u, revoking, store } = await revocationAtTheTop();
    // One relay answers with the head buried after 16 older versions.
    const fetcher: IdentityFetcher = async () => [...u.docs.slice(1, 17).map((d) => d.jws), revoking.jws];
    const view = await refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: [RELAY] });
    expect(view.head.hash).toBe(revoking.hash);
  });

  it("fetch time doesn't count against the budget: a relay answering after 2.1 s still works", async () => {
    const { u, revoking, store } = await revocationAtTheTop();
    const fetcher: IdentityFetcher = async (_u, relays) => {
      if (relays[0] === RELAY) await sleep(2100);
      return relays[0] === RELAY ? u.docs.slice(9).map((d) => d.jws) : [];
    };
    const view = await refreshIdentity(store, u.userId, fetcher, { now: NOW });
    expect(view.head.hash).toBe(revoking.hash);
  }, 10_000);

  it("a relay that doesn't answer in time is skipped", async () => {
    const { u, revoking, store } = await revocationAtTheTop();
    const fetcher: IdentityFetcher = async (_u, relays) => {
      if (relays[0] === RELAY2) await new Promise(() => {}); // never answers
      return u.docs.slice(9).map((d) => d.jws);
    };
    const view = await refreshIdentity(store, u.userId, fetcher, { now: NOW, fetchTimeoutMs: 100 });
    expect(view.head.hash).toBe(revoking.hash);
  });

  it("an overrun commits what was placed instead of throwing, and reports it incomplete", async () => {
    const { u, store } = await revocationAtTheTop();
    const fetcher: IdentityFetcher = async () => u.docs.slice(10).map((d) => d.jws); // v11..v18
    // Only 3 documents may be examined: the three highest (v16..v18) gap against v10.
    let view = await refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: [RELAY], maxDocs: 3 });
    expect(view.incomplete).toBe(true);
    expect(view.head.ver).toBe(10);
    // With a chain the client can place the lower ones: v11..v13 get committed even though the cap is hit.
    const lowFirst: IdentityFetcher = async () => u.docs.slice(10, 13).map((d) => d.jws);
    view = await refreshIdentity(store, u.userId, lowFirst, { now: NOW, relays: [RELAY], maxDocs: 3 });
    expect(view.head.ver).toBe(13);
    expect((await getIdentityView(store, u.userId))?.head.ver).toBe(13);
  });
});

/** A fork where d3 is linked on branch B only; the merge drops it; the owner's next version re-adds it. */
function mergeDrop() {
  const u = makeUser("alice");
  u.relays = [RELAY, RELAY2];
  const v1 = u.doc;
  const kh = [u.dev.did];
  const d3 = u.addDevice({ keyholder: false });
  const a = doc(u, { ver: 2, prev: v1.hash, devices: kh, keyholders: kh, iat: NOW - 500 });
  const b = doc(u, { ver: 2, prev: v1.hash, devices: [...kh, d3.did], keyholders: kh, iat: NOW - 499 });
  const m = mergeFields(a, b);
  const v3 = doc(u, { ver: m.ver!, prev: m.prev!, merge: m.merge, devices: m.devices!, keyholders: m.keyholders!, iat: NOW - 400 });
  const v4 = doc(u, { ver: 4, prev: v3.hash, devices: [...v3.devices, d3.did], keyholders: kh, iat: NOW - 300 });
  return { u, v1, a, b, v3, v4, d3 };
}

describe("S2: a merge dropping a one-branch did isn't revocation", () => {
  it("the owner's next version may re-add it", () => {
    const { u, v1, a, b, v3, v4, d3 } = mergeDrop();
    const c = new IdentityChain(u.userId);
    for (const d of [v1, a, b, v3]) c.add(d.jws, { now: NOW });
    expect(c.view().devices).not.toContain(d3.did);
    expect(c.add(v4.jws, { now: NOW }).status).toBe("accepted");
    expect(c.view().devices).toContain(d3.did);
  });

  it("a did present in both parents and dropped by the merge is revoked", () => {
    const u = makeUser("alice");
    const d2 = u.addDevice({ keyholder: false });
    const v2 = u.publish(); // both branches inherit d2
    const kh = [u.dev.did];
    const a = doc(u, { ver: 3, prev: v2.hash, devices: [...kh, d2.did], keyholders: kh, iat: NOW - 500 });
    const b = doc(u, { ver: 3, prev: v2.hash, devices: [...kh, d2.did], keyholders: kh, iat: NOW - 499 });
    const m = mergeFields(a, b);
    const v4 = doc(u, { ver: m.ver!, prev: m.prev!, merge: m.merge, devices: kh, keyholders: kh, iat: NOW - 400 });
    const v5 = doc(u, { ver: 5, prev: v4.hash, devices: [...kh, d2.did], keyholders: kh, iat: NOW - 300 });
    const c = new IdentityChain(u.userId);
    for (const d of [u.docs[0], v2, a, b, v4]) c.add(d.jws, { now: NOW });
    expect(() => c.add(v5.jws, { now: NOW })).toThrow(/revoked-device-returned/);
  });

  it("the jump denylist follows the same rule", async () => {
    const { u, v1, a, b, v3, v4, d3 } = mergeDrop();
    const store = await storeKnowing();
    for (const d of [v1, a, b, v3]) await addIdentityVersion(store, d.jws, { now: NOW });
    const v5 = doc(u, { ver: 5, prev: v4.hash, devices: v4.devices, keyholders: v4.keyholders, iat: NOW - 200 });
    await jumpIdentity(store, v5.jws, { now: NOW });
    expect((await getIdentityView(store, u.userId))?.devices).toContain(d3.did);
  });
});

describe("S3: no keyholder denylist", () => {
  it("a key holder demoted on a jumped-over branch is the head's key holder again", async () => {
    const u = makeUser("alice");
    const phone = u.addDevice({ keyholder: true });
    const v2 = u.publish();
    const kh = [u.dev.did, phone.did];
    const a = doc(u, { ver: 3, prev: v2.hash, devices: kh, keyholders: [u.dev.did], iat: NOW - 500 }); // demotes the phone
    const b = doc(u, { ver: 3, prev: v2.hash, devices: kh, keyholders: kh, iat: NOW - 499 });
    const store = await storeKnowing();
    for (const d of [u.docs[0], v2, a, b]) await addIdentityVersion(store, d.jws, { now: NOW });
    const v9 = doc(u, { ver: 9, prev: b.hash.replace(/./, "A"), devices: kh, keyholders: kh, iat: NOW - 100 });
    await jumpIdentity(store, v9.jws, { now: NOW });
    const view = (await getIdentityView(store, u.userId))!;
    expect(view.keyholders).toContain(phone.did);
    // An old stored deniedKeyholders field is ignored.
    const stored = (await store.getIdentity(u.userId))!;
    expect(stored.deniedKeyholders).toBeUndefined();
    expect(IdentityChain.fromStored({ ...stored, deniedKeyholders: [phone.did] }).view().keyholders).toContain(phone.did);
  });
});

describe("S4: the commit re-checks anchoring before jumping", () => {
  it("a chain anchored by a concurrent writer isn't jumped over", async () => {
    const u = makeUser("alice");
    u.relays = [RELAY];
    for (let i = 0; i < 3; i++) u.publish();
    const head = u.doc;
    const store = await storeKnowing(); // nothing held: an automatic jump would be allowed
    // While the fetch is in flight, another writer anchors the chain at v1.
    const fetcher: IdentityFetcher = async () => {
      await addIdentityVersion(store, u.docs[0].jws, { now: NOW });
      return [u.docs[0].jws, head.jws]; // v1 and the head: in memory, a jump over unanchored history
    };
    await expect(refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: [RELAY] })).rejects.toThrow(/chain-broken/);
    const view = (await getIdentityView(store, u.userId))!;
    expect(view.head.ver).toBe(1);
    expect(view.historyGap).toBe(false);
  });
});
