// Copyright 2026 Ix Infrastructure Inc.
//
// Regression tests for #74: a relay replaying a friend's genuine public version 1 (or an old version,
// walked down to it) must not fork their unanchored identity view, narrow its trust, or mark it anchored.
// Forks of history anchored at version 1 are still detected, and stores poisoned before the fix heal.

import { describe, expect, it } from "vitest";
import { createIdentityDoc, IdentityChain, verifyIdentityDocSignature, type VerifiedIdentityDoc } from "../identitydoc.js";
import { addIdentityVersion, getIdentityView, lastRefreshed, refreshIdentity, type IdentityFetcher } from "../state.js";
import { MemoryTrustStoreV3 } from "../store.js";
import { makeUser, NOW, RELAY, RELAY2, TestUser } from "./fixtures.js";

/**
 * A friend whose identity reached v8: v1 lists only the first device; v2 adds two more; v3 retires the first
 * device, so v1's devices ∩ the head's devices is empty. Published on two relays.
 */
function friend(): { u: TestUser; head: VerifiedIdentityDoc; first: string } {
  const u = makeUser("alice");
  u.relays = [RELAY, RELAY2];
  const first = u.dev.did;
  const phone = u.addDevice({ keyholder: true });
  u.addDevice({ keyholder: false });
  u.publish(); // v2
  u.keyholders = [phone.did];
  u.publish({ devices: u.devices.slice(1).map((d) => d.did) }); // v3: first device retired
  for (let v = 4; v <= 8; v++) u.publish({ devices: u.devices.slice(1).map((d) => d.did) });
  return { u, head: u.doc, first };
}

/** A store that first saw the friend at their head (an unanchored root, as first contact stores it). */
async function storeAtHead(u: TestUser, head: VerifiedIdentityDoc): Promise<MemoryTrustStoreV3> {
  const store = new MemoryTrustStoreV3();
  const r = await addIdentityVersion(store, head.jws, { now: NOW });
  expect(r).toMatchObject({ status: "accepted", unanchored: true });
  const view = await getIdentityView(store, u.userId, { now: NOW });
  expect(view?.forked).toBe(false);
  expect(view?.devices).toEqual(head.devices);
  return store;
}

/** Each relay answers with its own list; `chain` serves a contiguous run of old versions on request. */
function relays(answers: Record<string, string[]>, chain?: (to: string) => string[]): IdentityFetcher & { asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    tips: async (_u, rs) => answers[rs[0]] ?? [],
    ...(chain ? { chain: async (_u: string, _r: readonly string[], to: string) => (asked.push(to), chain(to)) } : {}),
  };
}

describe("#74: replayed old history below an unanchored head is not a fork", () => {
  it("a genesis replay into an unanchored chain is kept but not counted: not a tip, not anchoring", () => {
    const { u, head } = friend();
    const c = new IdentityChain(u.userId);
    c.add(head.jws, { now: NOW });
    c.add(u.docs[0].jws, { now: NOW });
    expect(c.anchored).toBe(false);
    const view = c.view();
    expect(view.forked).toBe(false);
    expect(view.tips.map((t) => t.hash)).toEqual([head.hash]);
    expect(view.devices).toEqual(head.devices);
  });

  it("old versions walked down to v1 below an unanchored root don't count until they connect", () => {
    const { u, head } = friend();
    const c = new IdentityChain(u.userId);
    c.add(head.jws, { now: NOW });
    expect(c.add(u.docs[2].jws, { now: NOW })).toEqual({ status: "gap", need: u.docs[1].hash });
    for (const d of u.docs.slice(0, 3)) expect(c.add(d.jws, { now: NOW }).status).toBe("accepted");
    expect(c.anchored).toBe(false);
    expect(c.view().forked).toBe(false);
    expect(c.view().tips.map((t) => t.hash)).toEqual([head.hash]);
    expect(c.view().devices).toEqual(head.devices);
    // The rest of the genuine history connects them to the root: anchored, one tip.
    for (const d of u.docs.slice(3, 7)) c.add(d.jws, { now: NOW });
    expect(c.anchored).toBe(true);
    expect(c.view().forked).toBe(false);
    expect(c.view().tips.map((t) => t.hash)).toEqual([head.hash]);
  });

  it("a replayed genesis must still verify and carry the held ik", () => {
    const { u, head } = friend();
    const c = new IdentityChain(u.userId);
    c.add(head.jws, { now: NOW });
    const forged = u.docs[0].jws.slice(0, -4) + (u.docs[0].jws.endsWith("AAAA") ? "BBBB" : "AAAA");
    expect(() => c.add(forged, { now: NOW })).toThrow();
    expect(() => c.add(makeUser("mallory").docs[0].jws, { now: NOW })).toThrow(/issuer-mismatch/);
  });

  it("one relay answering with the genesis can't fork the view; honest refreshes stay unforked", async () => {
    const { u, head } = friend();
    const store = await storeAtHead(u, head);
    const hostile = relays({ [RELAY]: [head.jws], [RELAY2]: [u.docs[0].jws] });
    const view = await refreshIdentity(store, u.userId, hostile, { now: NOW });
    expect(view.forked).toBe(false);
    expect(view.devices).toEqual(head.devices);
    expect("incomplete" in view && view.incomplete).toBeFalsy();
    // The stored chain stays replaceable (unanchored).
    expect(IdentityChain.fromStored((await store.getIdentity(u.userId))!).anchored).toBe(false);
    const honest = await refreshIdentity(store, u.userId, relays({ [RELAY]: [head.jws], [RELAY2]: [head.jws] }), { now: NOW });
    expect(honest.forked).toBe(false);
    expect(honest.devices).toEqual(head.devices);
    expect(await lastRefreshed(store, u.userId)).toBeDefined();
  });

  it("an old-version replay with a chain walk down to v1 can't fork the view either", async () => {
    const { u, head } = friend();
    const store = await storeAtHead(u, head);
    const byHash = new Map(u.docs.map((d) => [d.hash, d]));
    const fetcher = relays({ [RELAY]: [head.jws], [RELAY2]: [u.docs[2].jws] }, (to) => {
      const out: string[] = [];
      for (let d = byHash.get(to); d; d = d.prev ? byHash.get(d.prev) : undefined) out.push(d.jws);
      return out;
    });
    const view = await refreshIdentity(store, u.userId, fetcher, { now: NOW });
    expect(view.forked).toBe(false);
    expect(view.devices).toEqual(head.devices);
    expect([...new Set(fetcher.asked)]).toEqual([u.docs[1].hash]);
    expect(IdentityChain.fromStored((await store.getIdentity(u.userId))!).anchored).toBe(false);
    const again = await refreshIdentity(store, u.userId, relays({ [RELAY]: [head.jws], [RELAY2]: [head.jws] }), { now: NOW });
    expect(again.forked).toBe(false);
    expect(again.devices).toEqual(head.devices);
  });

  it("a newer version still replaces the unanchored history after a replay (L5 isn't turned off)", async () => {
    const { u, head } = friend();
    const store = await storeAtHead(u, head);
    await addIdentityVersion(store, u.docs[0].jws, { now: NOW });
    u.publish({ devices: head.devices }); // v9
    const v10 = u.publish({ devices: head.devices });
    expect(await addIdentityVersion(store, v10.jws, { now: NOW })).toMatchObject({ status: "accepted", replacedUnanchored: true });
  });

  it("a version that connects to the held history is accepted as before", () => {
    const { u, head } = friend();
    const c = new IdentityChain(u.userId);
    c.add(u.docs[5].jws, { now: NOW }); // v6: unanchored root
    expect(c.add(u.docs[6].jws, { now: NOW }).status).toBe("accepted");
    expect(c.add(head.jws, { now: NOW }).status).toBe("accepted");
    expect(c.view().tips.map((t) => t.hash)).toEqual([head.hash]);
  });
});

describe("#74: genuine forks are still detected", () => {
  it("a second signed genesis on history anchored at v1 is a fork", () => {
    const { u } = friend();
    const c = new IdentityChain(u.userId);
    for (const d of u.docs.slice(0, 3)) expect(c.add(d.jws, { now: NOW }).status).toBe("accepted");
    const other = createIdentityDoc(u.ik, { ver: 1, prev: null, name: u.name, relays: [RELAY], devices: [u.dev.did], keyholders: [u.dev.did], by: u.dev.did, iat: NOW - 30 });
    expect(c.add(other, { now: NOW }).status).toBe("accepted");
    const view = c.view();
    expect(view.forked).toBe(true);
    expect(view.tips).toHaveLength(2);
    // And it survives a reload (not mistaken for a stray).
    expect(IdentityChain.fromStored(c.toStored()).view().forked).toBe(true);
  });

  it("two versions at the same ver on anchored history are a fork", () => {
    const { u } = friend();
    const c = new IdentityChain(u.userId);
    for (const d of u.docs.slice(0, 3)) c.add(d.jws, { now: NOW });
    const v3 = u.docs[2];
    const sibling = createIdentityDoc(u.ik, { ver: 3, prev: v3.prev, name: u.name, relays: [RELAY], devices: v3.devices, keyholders: v3.keyholders, by: v3.keyholders[0], iat: NOW - 20 });
    expect(c.add(sibling, { now: NOW }).status).toBe("accepted");
    expect(c.view().forked).toBe(true);
    expect(IdentityChain.fromStored(c.toStored()).view().forked).toBe(true);
  });

  it("two sibling tips over no history: the walk down to v1 connects both, and it's a fork (a restore mid-fork)", async () => {
    const { u } = friend();
    const base = u.docs[7];
    const sib = (iat: number) => verifyIdentityDocSignature(createIdentityDoc(u.ik, { ver: 9, prev: base.hash, name: u.name, relays: u.relays, devices: base.devices, keyholders: base.keyholders, by: base.keyholders[0], iat }));
    const x = sib(NOW - 20);
    const y = sib(NOW - 10);
    const byHash = new Map(u.docs.map((d) => [d.hash, d]));
    const fetcher = relays({ [RELAY]: [x.jws, y.jws], [RELAY2]: [x.jws, y.jws] }, (to) => {
      const out: string[] = [];
      for (let d = byHash.get(to); d; d = d.prev ? byHash.get(d.prev) : undefined) out.push(d.jws);
      return out;
    });
    const view = await refreshIdentity(new MemoryTrustStoreV3(), u.userId, fetcher, { now: NOW, relays: [RELAY, RELAY2] });
    expect(view.forked).toBe(true);
    expect(view.tips.map((t) => t.hash).sort()).toEqual([x.hash, y.hash].sort());
  });

  it("a fork within the held unanchored history is still a fork", () => {
    const { u } = friend();
    const c = new IdentityChain(u.userId);
    c.add(u.docs[4].jws, { now: NOW }); // v5 root
    c.add(u.docs[5].jws, { now: NOW }); // v6
    const v6 = u.docs[5];
    const sibling = createIdentityDoc(u.ik, { ver: 6, prev: v6.prev, name: u.name, relays: [RELAY], devices: v6.devices, keyholders: v6.keyholders, by: v6.keyholders[0], iat: NOW - 20 });
    expect(c.add(sibling, { now: NOW }).status).toBe("accepted");
    expect(c.view().forked).toBe(true);
  });
});

describe("#74: a store poisoned before the fix heals on load", () => {
  it("a stray genesis beside an unanchored head doesn't count: unforked, unanchored, the head's devices", async () => {
    const { u, head, first } = friend();
    const poisoned = { iss: u.userId, versions: [head.jws, u.docs[0].jws] };
    // What the bug left: forked, and the narrowed allowlist is empty.
    expect(head.devices).not.toContain(first);
    const c = IdentityChain.fromStored(poisoned);
    expect(c.anchored).toBe(false);
    expect(c.view().forked).toBe(false);
    expect(c.view().devices).toEqual(head.devices);
    const store = new MemoryTrustStoreV3();
    await store.putIdentity(poisoned);
    const view = await getIdentityView(store, u.userId, { now: NOW });
    expect(view?.forked).toBe(false);
    expect(view?.devices).toEqual(head.devices);
  });

  it("a stray v1..v3 branch (an old-version replay walked down) doesn't count", () => {
    const { u, head } = friend();
    const c = IdentityChain.fromStored({ iss: u.userId, versions: [head.jws, ...u.docs.slice(0, 3).map((d) => d.jws)] });
    expect(c.view().tips.map((t) => t.hash)).toEqual([head.hash]);
    expect(c.anchored).toBe(false);
    expect(c.view().forked).toBe(false);
  });

  it("a healed store is replaceable again, and a fresh refresh writes it back clean", async () => {
    const { u, head } = friend();
    const store = new MemoryTrustStoreV3();
    await store.putIdentity({ iss: u.userId, versions: [head.jws, u.docs[0].jws] });
    u.publish({ devices: head.devices }); // v9
    const v10 = u.publish({ devices: head.devices });
    const view = await refreshIdentity(store, u.userId, relays({ [RELAY]: [v10.jws], [RELAY2]: [v10.jws] }), { now: NOW });
    expect(view.head.hash).toBe(v10.hash);
    expect(view.forked).toBe(false);
    expect((await store.getIdentity(u.userId))!.versions).toEqual([v10.jws]);
  });

  it("a genesis the head's history connects to is kept (anchored history isn't touched)", () => {
    const { u, head } = friend();
    const c = IdentityChain.fromStored({ iss: u.userId, versions: u.docs.map((d) => d.jws) });
    expect(c.anchored).toBe(true);
    expect(c.size).toBe(u.docs.length);
    expect(c.view().head.hash).toBe(head.hash);
  });

  it("a genesis-rooted branch reaching the unanchored root's ver counts (a genuine fork, not a replay)", () => {
    const { u } = friend();
    const v6 = u.docs[5];
    // A signed v1..v7 branch beside an unanchored v6: only the identity key makes one, so it's a fork.
    const other = new TestUser("alice", u.ik);
    other.devices.push(...u.devices);
    other.keyholders = [u.dev.did];
    for (let v = 1; v <= 7; v++) other.publish({ devices: [u.dev.did], iat: NOW - 500 + v });
    const c = IdentityChain.fromStored({ iss: u.userId, versions: [v6.jws, ...other.docs.map((d) => d.jws)] });
    expect(c.size).toBe(8);
    expect(c.view().forked).toBe(true);
  });
});
