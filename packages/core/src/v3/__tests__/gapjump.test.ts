// Copyright 2026 Ix Infrastructure Inc.
//
// Regression tests for a pre-release review's gap jump: N6 (never adopt a
// rejected version), N7 (no automatic jump over anchored or forked history;
// explicit jumps keep fork knowledge), N8 (re-verification is branded and
// recent), N9 (provisional entries hold relays only; views are frozen copies).

import { describe, expect, it } from "vitest";
import { createIdentityDoc, verifyIdentityDocSignature, type VerifiedIdentityDoc } from "../identitydoc.js";
import { createAcceptV3, createInviteV3, verifyFriendshipV3 } from "../friends.js";
import { addIdentityVersion, getIdentityView, jumpIdentity, recordFriendshipV3, refreshIdentity, reverifyFriendshipForApproval, REVERIFY_MAX_AGE_SEC, type IdentityFetcher } from "../state.js";
import { verifyIncomingV3 } from "../incoming.js";
import type { TrustStoreV3 } from "../store.js";
import { ctxFor, makeUser, NOW, NOW_MS, RELAY, seal, storeKnowing, TestUser } from "./fixtures.js";

function doc(u: TestUser, ver: number, prev: string, devices: string[], keyholders: string[], iat: number): VerifiedIdentityDoc {
  return verifyIdentityDocSignature(
    createIdentityDoc(u.ik, { ver, prev, name: u.name, relays: [RELAY], devices, keyholders, by: keyholders[0], certs: u.devices.filter((d) => devices.includes(d.did)).map((d) => d.cert), iat }),
  );
}

/** An honest fork: tip A revokes d2, tip B keeps it; B later extends to B4 → B5. */
function honestFork() {
  const u = makeUser("alice");
  const phone = u.addDevice({ keyholder: true });
  const d2 = u.addDevice({ keyholder: false });
  const v2 = u.publish();
  const kh = [u.dev.did, phone.did];
  const a = doc(u, 3, v2.hash, kh, kh, NOW - 300);
  const b = doc(u, 3, v2.hash, [...kh, d2.did], kh, NOW - 299);
  const b4 = doc(u, 4, b.hash, [...kh, d2.did], kh, NOW - 200);
  const b5 = doc(u, 5, b4.hash, [...kh, d2.did], kh, NOW - 100);
  return { u, d2, v1: u.docs[0], v2, a, b, b4, b5 };
}

async function heldFork() {
  const f = honestFork();
  const store = await storeKnowing();
  for (const d of [f.v1, f.v2, f.a, f.b]) await addIdentityVersion(store, d.jws, { now: NOW });
  const view = await getIdentityView(store, f.u.userId);
  expect(view?.forked).toBe(true);
  expect(view?.devices).not.toContain(f.d2.did);
  return { ...f, store };
}

describe("N7: no automatic jump over anchored or forked history", () => {
  it("a tips-only fetch that skips B's parent fails closed; the fork and the revocation survive", async () => {
    const { store, u, a, b5, d2 } = await heldFork();
    const tipsOnly: IdentityFetcher = async () => [a.jws, b5.jws];
    await expect(refreshIdentity(store, u.userId, tipsOnly, { now: NOW })).rejects.toThrow(/chain-broken/);
    const view = await getIdentityView(store, u.userId);
    expect(view?.forked).toBe(true);
    expect(view?.devices).not.toContain(d2.did);
    expect(view?.historyGap).toBe(false);
  });

  it("with the §5.6 chain walk, the gap is filled and the fork is still a fork", async () => {
    const { store, u, a, b4, b5, d2 } = await heldFork();
    const asked: string[] = [];
    const fetcher: IdentityFetcher = {
      tips: async () => [a.jws, b5.jws],
      chain: async (_u, _r, to) => {
        asked.push(to);
        return to === b4.hash ? [b4.jws] : [];
      },
    };
    const view = await refreshIdentity(store, u.userId, fetcher, { now: NOW });
    expect(asked).toEqual([b4.hash]);
    expect(view.tips.map((t) => t.hash).sort()).toEqual([a.hash, b5.hash].sort());
    expect(view.devices).not.toContain(d2.did);
    expect(view.historyGap).toBe(false);
  });

  it("a chain walk that still doesn't connect fails closed", async () => {
    const { store, u, a, b5 } = await heldFork();
    const fetcher: IdentityFetcher = { tips: async () => [a.jws, b5.jws], chain: async () => [] };
    await expect(refreshIdentity(store, u.userId, fetcher, { now: NOW })).rejects.toThrow(/chain-broken/);
  });

  it("an explicit jump surfaces historyGap and keeps branch A's revocation (as a denylist), so d2 stays out", async () => {
    const { store, u, b5, d2 } = await heldFork();
    await jumpIdentity(store, b5.jws, { now: NOW });
    const view = await getIdentityView(store, u.userId);
    expect(view?.historyGap).toBe(true);
    // review R1: no carried tips; the revocation travels as a denylist.
    expect(view?.forked).toBe(false);
    expect(view?.tips.map((t) => t.hash)).toEqual([b5.hash]);
    expect(view?.devices).not.toContain(d2.did);
    expect(b5.devices).toContain(d2.did);
  });

  it("over linear anchored history a non-connecting head fails closed too (no silent jump)", async () => {
    const u = makeUser("alice");
    u.publish();
    const v3 = u.publish();
    const store = await storeKnowing();
    await addIdentityVersion(store, u.docs[0].jws, { now: NOW });
    await expect(refreshIdentity(store, u.userId, async () => [v3.jws], { now: NOW })).rejects.toThrow(/chain-broken/);
  });
});

describe("N6: a version the chain rules reject is never adopted, not even by a jump", () => {
  it("revoked-device-returned: the rejected head isn't jumped to", async () => {
    const u = makeUser("alice");
    const d2 = u.addDevice({ keyholder: false });
    const v2 = u.publish(); // lists d2
    const v3 = u.publish({ devices: [u.dev.did] }); // revokes d2
    const v4 = doc(u, 4, v3.hash, [u.dev.did, d2.did], [u.dev.did], NOW - 10); // re-adds d2: rejected
    const store = await storeKnowing(); // no view: an automatic jump would be allowed
    const view = await refreshIdentity(store, u.userId, async () => [u.docs[0].jws, v2.jws, v3.jws, v4.jws], { now: NOW, relays: [RELAY] });
    expect(view.head.hash).toBe(v3.hash);
    expect(view.devices).not.toContain(d2.did);
  });

  it("a merge that adds a device isn't jumped to", async () => {
    const { u, v1, v2, a, b, d2 } = honestFork();
    const kh = a.keyholders;
    const badMerge = verifyIdentityDocSignature(
      createIdentityDoc(u.ik, { ver: 4, prev: b.hash > a.hash ? b.hash : a.hash, merge: b.hash > a.hash ? a.hash : b.hash, name: u.name, relays: [RELAY], devices: [...kh, d2.did], keyholders: kh, by: kh[0], iat: NOW - 50 }),
    );
    const store = await storeKnowing();
    const view = await refreshIdentity(store, u.userId, async () => [v1.jws, v2.jws, a.jws, b.jws, badMerge.jws], { now: NOW, relays: [RELAY] });
    expect(view.forked).toBe(true);
    expect(view.devices).not.toContain(d2.did);
  });
});

async function provisionalFriendship() {
  const a = makeUser("alice");
  const b = makeUser("bob");
  const store = await storeKnowing(b);
  const invite = createInviteV3(a.signer(), { aud: b.userId, iat: NOW - 100, doc: a.doc.jws });
  const proof = { invite, accept: createAcceptV3(b.signer(), invite, { iat: NOW - 50 }) };
  const fetch: IdentityFetcher = async () => a.docs.map((d) => d.jws);
  return { a, b, store, proof, fetch };
}

describe("N8: only a recent, genuine re-verification lets a provisional friendship be recorded", () => {
  it("a caller-set reverifiedAt, or a copy of a re-verified result, is refused", async () => {
    const { store, proof, b, fetch } = await provisionalFriendship();
    const f = await verifyFriendshipV3(proof, ctxFor(store));
    expect(f.provisional).toBe(true);
    await expect(recordFriendshipV3(store, { ...f, reverifiedAt: NOW }, { now: NOW })).rejects.toThrow(/provisional/);
    const genuine = await reverifyFriendshipForApproval(await storeKnowing(b), proof, fetch, { now: NOW, self: b.userId });
    // Forced back to provisional and copied: the copy carries no brand.
    await expect(recordFriendshipV3(store, { ...genuine, provisional: true }, { now: NOW })).rejects.toThrow(/provisional/);
  });

  it("a genuine re-verification is accepted within 10 minutes, and refused after", async () => {
    const { store, proof, b, fetch } = await provisionalFriendship();
    const genuine = await reverifyFriendshipForApproval(store, proof, fetch, { now: NOW, self: b.userId });
    const asProvisional = Object.assign(genuine, { provisional: true }); // same object: still branded
    await expect(recordFriendshipV3(store, asProvisional, { now: NOW + REVERIFY_MAX_AGE_SEC + 1 })).rejects.toThrow(/stale/);
    await recordFriendshipV3(store, asProvisional, { now: NOW + REVERIFY_MAX_AGE_SEC });
    expect(await store.listFriendships()).toHaveLength(1);
  });
});

async function receive(store: TrustStoreV3, to: TestUser, env: string) {
  return verifyIncomingV3(env, { self: { userId: to.userId, did: to.dev.did, agreementSecretKey: to.dev.agreementSecretKey, cert: to.dev.cert }, store, nowMs: NOW_MS });
}

describe("N9: provisional entries keep relays only; views are frozen copies", () => {
  it("the provisional cache holds no document", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(b);
    const invite = createInviteV3(a.signer(), { aud: b.userId, iat: NOW - 10, doc: a.doc.jws });
    expect((await receive(store, b, seal(a, b, "contact", { text: invite }))).ok).toBe(true);
    const entry = await store.getProvisional(a.userId, NOW);
    expect(entry).toEqual({ userId: a.userId, relays: [RELAY], at: NOW });
    expect(JSON.stringify(entry)).not.toContain(a.doc.jws.slice(0, 40));
  });

  it("a caller can't corrupt the cached view", async () => {
    const a = makeUser("alice");
    const store = await storeKnowing(a);
    const v = (await getIdentityView(store, a.userId))!;
    expect(Object.isFrozen(v)).toBe(true);
    expect(() => (v.devices as string[]).push("d_" + "x".repeat(26))).toThrow();
    expect(() => {
      (v as { exp: number }).exp = 0;
    }).toThrow();
    v.head.ikPublicKey[0] ^= 0xff; // typed arrays are copies
    const again = (await getIdentityView(store, a.userId))!;
    expect(again.devices).toEqual(a.doc.devices);
    expect(again.exp).toBe(a.doc.exp);
    expect(again.head.ikPublicKey).toEqual(a.doc.ikPublicKey);
  });
});
