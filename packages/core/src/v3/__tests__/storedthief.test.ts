// Copyright 2026 Ix Infrastructure Inc.
//
// Regression tests for #92: a key holder's head stored first (unanchored) must not keep a device trusted that
// the owner's later revoking version, below that head, removed, when relays keep only the last few versions
// (the two can't be connected through version 1). Plus #87's review follow-ups: side roots at the cap, and a
// child dropped for a broken link.

import { describe, expect, it } from "vitest";
import { createIdentityDoc, IdentityChain, MAX_SIDE_ROOTS, verifyIdentityDocSignature, type VerifiedIdentityDoc } from "../identitydoc.js";
import { addIdentityVersion, getIdentityView, lastRefreshed, refreshIdentity, type IdentityFetcher } from "../state.js";
import { MemoryTrustStoreV3 } from "../store.js";
import { makeUser, NOW, RELAY, RELAY2 } from "./fixtures.js";

/** v1 [dev1], v2..v3 [dev1, D]; a key holder builds v4'..v8' off v3 keeping D; the owner revokes D at v4. */
function thief() {
  const u = makeUser("alice");
  u.relays = [RELAY, RELAY2];
  const stolen = u.addDevice({ keyholder: false });
  u.publish({ iat: NOW - 900 });
  const v3 = u.publish({ iat: NOW - 890 });
  const forged: VerifiedIdentityDoc[] = [];
  let p = v3;
  for (let v = 4; v <= 8; v++) {
    p = verifyIdentityDocSignature(
      createIdentityDoc(u.ik, { ver: v, prev: p.hash, name: u.name, relays: u.relays, devices: [u.dev.did, stolen.did], keyholders: [u.dev.did], by: u.dev.did, iat: NOW - 800 + v }),
    );
    forged.push(p);
  }
  const own4 = u.publish({ devices: [u.dev.did], iat: NOW - 700 });
  return { u, stolen, forged, own4, head: forged[4] };
}

/** The §5.6 walk back from `to` over `docs`, versions below `lowest` left out (pruned by the relay). */
function walkOf(docs: readonly VerifiedIdentityDoc[], lowest = 1) {
  const m = new Map(docs.filter((d) => d.ver >= lowest).map((d) => [d.hash, d]));
  return (to: string) => {
    const out: string[] = [];
    for (let d = m.get(to); d; d = d.prev ? m.get(d.prev) : undefined) out.push(d.jws);
    return out.slice(0, 64);
  };
}

function perRelay(tips: Record<string, string[]>, chain: Record<string, (to: string) => string[]>): IdentityFetcher {
  return {
    tips: async (_u, rs) => tips[rs[0]] ?? [],
    chain: async (_u, rs, to) => chain[rs[0]]?.(to) ?? [],
  };
}

describe("#92: a key holder's head stored first, the owner's revoking version below it arriving later", () => {
  it("the owner's relay keeps versions from v2 or v3 up, the key holder's relay serves only its head: the revoked device isn't trusted (a fork)", async () => {
    for (const lowest of [2, 3]) {
      for (const order of [
        [RELAY, RELAY2],
        [RELAY2, RELAY],
      ]) {
        const { u, stolen, own4, head } = thief();
        const [bad, good] = order;
        const store = new MemoryTrustStoreV3();
        expect(await addIdentityVersion(store, head.jws, { now: NOW })).toMatchObject({ status: "accepted", unanchored: true });
        const f = perRelay({ [bad]: [head.jws], [good]: [own4.jws] }, { [bad]: () => [], [good]: walkOf(u.docs, lowest) });
        const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: order });
        expect([lowest, v.devices.includes(stolen.did), v.keyholders.includes(stolen.did)]).toEqual([lowest, false, false]);
        expect([lowest, v.forked, v.tips.map((t) => t.ver)]).toEqual([lowest, true, [8, 4]]);
        // v4's revocation is known (v3 placed below it), so the fork holds and the refresh completes.
        expect([lowest, v.incomplete]).toEqual([lowest, undefined]);
        expect(await lastRefreshed(store, u.userId)).toBe(NOW);
        // Stored, reloaded, and refreshed again: still not trusted.
        expect((await getIdentityView(store, u.userId, { now: NOW }))?.devices).not.toContain(stolen.did);
        expect(IdentityChain.fromStored((await store.getIdentity(u.userId))!, { now: NOW }).view().devices).not.toContain(stolen.did);
        expect((await refreshIdentity(store, u.userId, f, { now: NOW + 60, relays: order })).devices).not.toContain(stolen.did);
        // Once v4 has expired, the fork (and v4's revocation) is still held: the device stays out.
        const later = own4.exp + 1;
        expect((await getIdentityView(store, u.userId, { now: later }))?.devices).not.toContain(stolen.did);
      }
    }
  });

  it("both relays serve both tips but keep only versions from v2 or v3 up of the owner's line (the key holder's v4'..v7' gone)", async () => {
    for (const lowest of [2, 3]) {
      const { u, stolen, own4, head } = thief();
      const store = new MemoryTrustStoreV3();
      await addIdentityVersion(store, head.jws, { now: NOW });
      const w = walkOf(u.docs, lowest);
      const f = perRelay({ [RELAY]: [head.jws, own4.jws], [RELAY2]: [head.jws, own4.jws] }, { [RELAY]: w, [RELAY2]: w });
      const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2] });
      expect([lowest, v.devices.includes(stolen.did), v.forked, v.incomplete]).toEqual([lowest, false, true, undefined]);
      expect((await getIdentityView(store, u.userId, { now: NOW }))?.devices).not.toContain(stolen.did);
    }
  });

  it("a later refresh with the key holder's whole chain served keeps the fork, and the device stays out", async () => {
    const { u, stolen, own4, head, forged } = thief();
    const store = new MemoryTrustStoreV3();
    await addIdentityVersion(store, head.jws, { now: NOW });
    await refreshIdentity(store, u.userId, perRelay({ [RELAY]: [head.jws], [RELAY2]: [own4.jws] }, { [RELAY]: () => [], [RELAY2]: walkOf(u.docs, 3) }), {
      now: NOW,
      relays: [RELAY, RELAY2],
    });
    const all = [...u.docs, ...forged];
    const v = await refreshIdentity(store, u.userId, perRelay({ [RELAY]: [head.jws], [RELAY2]: [own4.jws] }, { [RELAY]: walkOf(all, 3), [RELAY2]: walkOf(u.docs, 3) }), {
      now: NOW + 60,
      relays: [RELAY, RELAY2],
    });
    expect([v.devices.includes(stolen.did), v.forked, v.tips.map((t) => t.ver)]).toEqual([false, true, [8, 4]]);
    const c = IdentityChain.fromStored((await store.getIdentity(u.userId))!, { now: NOW + 60 });
    expect(c.view().devices).not.toContain(stolen.did);
  });

  it("retention from v4 up (v4's parent gone): nothing proves the fork, the refresh stays incomplete and v4 narrows the view while current", async () => {
    const { u, stolen, own4, head } = thief();
    const store = new MemoryTrustStoreV3();
    await addIdentityVersion(store, head.jws, { now: NOW });
    const f = perRelay({ [RELAY]: [head.jws], [RELAY2]: [own4.jws] }, { [RELAY]: () => [], [RELAY2]: walkOf(u.docs, 4) });
    const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2] });
    expect([v.incomplete, v.devices.includes(stolen.did)]).toEqual([true, false]);
    expect(await lastRefreshed(store, u.userId)).toBeUndefined();
    expect((await getIdentityView(store, u.userId, { now: NOW }))?.devices).not.toContain(stolen.did);
    // Not a fork: v4 isn't a tip, only evidence (v4 could yet be the head's ancestor, for all this client knows).
    expect((await store.getIdentity(u.userId))!.versions).toEqual([head.jws]);
  });

  it("a version from the key holder's own branch replayed below its head (an ancestor) is never placed as a fork", async () => {
    const { u, forged, head } = thief();
    const store = new MemoryTrustStoreV3();
    await addIdentityVersion(store, head.jws, { now: NOW });
    // A relay serves v6' as its tip, and v5' below it; nothing connects v6' to v8' (v7' gone).
    const f = perRelay({ [RELAY]: [head.jws], [RELAY2]: [forged[2].jws] }, { [RELAY]: () => [], [RELAY2]: walkOf([...u.docs.slice(0, 3), ...forged.slice(0, 3)], 5) });
    const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2] });
    expect([v.forked, v.tips.map((t) => t.hash)]).toEqual([false, [head.hash]]);
  });
});

describe("#92: IdentityChain.addForkRoot only places a proven fork", () => {
  it("placed when the line revokes a device every tip lists; refused for a broken link, a re-listed revoked device, nothing shared revoked, a connecting version", () => {
    const { u, stolen, own4, head, forged } = thief();
    const [v1, v2, v3] = u.docs;
    const fresh = () => {
      const c = new IdentityChain(u.userId);
      c.add(head.jws, { now: NOW });
      return c;
    };
    // The proof: v3 -> v4 revokes D, which v8' lists.
    const c = fresh();
    expect(c.addForkRoot(own4.jws, [v3, v2], { now: NOW })).toBe(true);
    expect([c.has(v3.hash), c.has(v2.hash), c.view().forked, c.view().devices.includes(stolen.did)]).toEqual([true, true, true, false]);
    expect(IdentityChain.fromStored(c.toStored(), { now: NOW }).view().devices).not.toContain(stolen.did);
    // No parent supplied, or one that isn't its parent: nothing proven.
    expect(fresh().addForkRoot(own4.jws, [], { now: NOW })).toBe(false);
    expect(fresh().addForkRoot(own4.jws, [v2, v1], { now: NOW })).toBe(false);
    // A version of the head's own line (v5' below v8', with v4'): revokes nothing v8' lists.
    expect(fresh().addForkRoot(forged[1].jws, [forged[0], v3], { now: NOW })).toBe(false);
    // A broken link: ver 5 naming v3.
    const broken = createIdentityDoc(u.ik, { ver: 5, prev: v3.hash, name: u.name, relays: u.relays, devices: [u.dev.did], keyholders: [u.dev.did], by: u.dev.did, iat: NOW - 600 });
    expect(fresh().addForkRoot(broken, [v3], { now: NOW })).toBe(false);
    // Expired: not placed.
    const old4 = createIdentityDoc(u.ik, { ver: 4, prev: v3.hash, name: u.name, relays: u.relays, devices: [u.dev.did], keyholders: [u.dev.did], by: u.dev.did, iat: NOW - 40 * 86_400 });
    expect(fresh().addForkRoot(old4, [v3], { now: NOW })).toBe(false);
    // The device already denied: nothing to narrow, not placed (no needless fork).
    const denied = IdentityChain.fromStored({ iss: u.userId, versions: [head.jws], denied: [stolen.did] }, { now: NOW });
    expect(denied.addForkRoot(own4.jws, [v3], { now: NOW })).toBe(false);
    // Anchored history: never.
    const anchored = new IdentityChain(u.userId);
    for (const d of [v1, v2, v3, ...forged]) anchored.add(d.jws, { now: NOW });
    expect(anchored.addForkRoot(own4.jws, [v3], { now: NOW })).toBe(false); // (its parent is held: an ordinary add)
  });

  it("our own identity: a held-back version isn't recorded to narrow the view (heldBackBy reports it)", async () => {
    const { u, own4, head } = thief();
    const store = new MemoryTrustStoreV3();
    await addIdentityVersion(store, head.jws, { now: NOW });
    const f = perRelay({ [RELAY]: [head.jws], [RELAY2]: [own4.jws] }, { [RELAY]: () => [], [RELAY2]: walkOf(u.docs, 4) });
    const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2], own: true });
    expect([v.incomplete, v.heldBackBy]).toEqual([true, [RELAY]]);
    expect((await store.getIdentity(u.userId))!.leftOut).toBeUndefined();
  });

  it("left-out versions are cleared by the next complete majority refresh", async () => {
    const { u, stolen, own4, head } = thief();
    const store = new MemoryTrustStoreV3();
    await addIdentityVersion(store, head.jws, { now: NOW });
    await refreshIdentity(store, u.userId, perRelay({ [RELAY]: [head.jws], [RELAY2]: [own4.jws] }, { [RELAY]: () => [], [RELAY2]: walkOf(u.docs, 4) }), {
      now: NOW,
      relays: [RELAY, RELAY2],
    });
    expect((await store.getIdentity(u.userId))!.leftOut).toEqual([own4.jws]);
    // Both relays now serve only the head (v4 gone): complete, cleared.
    const v = await refreshIdentity(store, u.userId, perRelay({ [RELAY]: [head.jws], [RELAY2]: [head.jws] }, {}), { now: NOW + 60, relays: [RELAY, RELAY2] });
    expect(v.incomplete).toBeUndefined();
    expect((await store.getIdentity(u.userId))!.leftOut).toBeUndefined();
    expect(v.devices).toContain(stolen.did); // what was only evidence lapses with it (no proof of a fork was ever seen)
  });
});

describe("#92: honest flows unchanged", () => {
  it("an honest head stored first, a stale relay serving an older current version (and its parent): no fork, nothing narrowed for good", async () => {
    const u = makeUser("alice");
    u.relays = [RELAY, RELAY2];
    const extra = u.addDevice({ keyholder: false });
    for (let i = 0; i < 4; i++) u.publish({ iat: NOW - 900 + i }); // v2..v5 [dev, extra]
    const v5 = u.doc;
    for (let i = 0; i < 3; i++) u.publish({ iat: NOW - 800 + i });
    const v9 = u.publish({ devices: [u.dev.did], iat: NOW - 700 }); // drops extra
    for (const lowest of [3, 4]) {
      const store = new MemoryTrustStoreV3();
      await addIdentityVersion(store, v9.jws, { now: NOW });
      // The stale relay serves v5 and its ancestry from `lowest`; v6..v8 are gone everywhere.
      const w = walkOf(
        u.docs.filter((d) => d.ver <= 5),
        lowest,
      );
      const v = await refreshIdentity(store, u.userId, perRelay({ [RELAY]: [v5.jws], [RELAY2]: [v9.jws] }, { [RELAY]: w, [RELAY2]: w }), { now: NOW, relays: [RELAY, RELAY2] });
      expect([lowest, v.incomplete, v.forked, v.head.hash]).toEqual([lowest, undefined, false, v9.hash]);
      expect((await store.getIdentity(u.userId))!.versions).toEqual([v9.jws]);
    }
    expect(extra.did).toBeTruthy();
  });

  it("an honest head stored first that added a device, a stale relay's current older version: held back as before, not a fork", async () => {
    const u = makeUser("alice");
    u.relays = [RELAY, RELAY2];
    for (let i = 0; i < 4; i++) u.publish({ iat: NOW - 900 + i });
    const v5 = u.doc;
    for (let i = 0; i < 3; i++) u.publish({ iat: NOW - 800 + i });
    const added = u.addDevice({ keyholder: false });
    const v9 = u.publish({ iat: NOW - 700 });
    const store = new MemoryTrustStoreV3();
    await addIdentityVersion(store, v9.jws, { now: NOW });
    const w = walkOf(
      u.docs.filter((d) => d.ver <= 5),
      3,
    );
    const v = await refreshIdentity(store, u.userId, perRelay({ [RELAY]: [v5.jws], [RELAY2]: [v9.jws] }, { [RELAY]: w, [RELAY2]: w }), { now: NOW, relays: [RELAY, RELAY2] });
    expect([v.incomplete, v.forked, v.head.hash]).toEqual([true, false, v9.hash]);
    expect((await store.getIdentity(u.userId))!.versions).toEqual([v9.jws]);
    // Once the stale version has expired, the head's device is trusted (nothing was kept as a fork).
    const later = v5.exp + 1;
    const after = await getIdentityView(store, u.userId, { now: later });
    expect(after?.devices).toContain(added.did);
  });

  it("an honest chain served in full still connects: the older served version is an ancestor, not a fork", async () => {
    const u = makeUser("alice");
    u.relays = [RELAY, RELAY2];
    for (let i = 0; i < 4; i++) u.publish({ iat: NOW - 900 + i });
    const v5 = u.doc;
    for (let i = 0; i < 5; i++) u.publish({ iat: NOW - 800 + i });
    const v10 = u.doc;
    const store = new MemoryTrustStoreV3();
    await addIdentityVersion(store, v10.jws, { now: NOW });
    const w = walkOf(u.docs, 3);
    const v = await refreshIdentity(store, u.userId, perRelay({ [RELAY]: [v5.jws], [RELAY2]: [v10.jws] }, { [RELAY]: w, [RELAY2]: w }), { now: NOW, relays: [RELAY, RELAY2] });
    expect([v.incomplete, v.forked, v.tips.map((t) => t.hash)]).toEqual([undefined, false, [v10.hash]]);
  });
});

describe("#92 follow-ups from #87's review", () => {
  it("side roots at the cap: the owner's same-ver tip that leaves out a trusted device is still placed (it only narrows)", () => {
    const u = makeUser("alice");
    const stolen = u.addDevice({ keyholder: false });
    u.publish({ iat: NOW - 900 });
    const v3 = u.publish({ iat: NOW - 890 });
    const sibling = (iat: number, devices: string[]) =>
      createIdentityDoc(u.ik, { ver: 4, prev: v3.hash, name: u.name, relays: u.relays, devices, keyholders: [u.dev.did], by: u.dev.did, iat });
    const c = new IdentityChain(u.userId);
    c.add(sibling(NOW - 200, [u.dev.did, stolen.did]), { now: NOW });
    // A key holder fills the side-root slots with same-ver forks keeping D.
    for (let i = 0; i < MAX_SIDE_ROOTS + 4; i++) c.add(sibling(NOW - 100 + i, [u.dev.did, stolen.did]), { now: NOW, replace: false, asRoot: true });
    expect(c.tips().length).toBe(MAX_SIDE_ROOTS);
    expect(c.view().devices).toContain(stolen.did);
    // The owner's v4 revoking D: placed beside them anyway, so D isn't trusted.
    const own4 = sibling(NOW - 50, [u.dev.did]);
    expect(c.add(own4, { now: NOW, replace: false, asRoot: true }).status).toBe("accepted");
    expect(c.view().devices).not.toContain(stolen.did);
    // A further sibling that narrows nothing more is still refused.
    expect(c.add(sibling(NOW - 40, [u.dev.did]), { now: NOW, replace: false, asRoot: true }).status).toBe("gap");
  });

  it("a key holder's child whose link to its genuine parent is broken: dropping it denies nothing relative to that parent", () => {
    const u = makeUser("alice");
    const keep = u.addDevice({ keyholder: false });
    u.publish({ iat: NOW - 900 }); // v2 [dev, keep]
    const v2 = u.doc;
    // ver 4 naming v2 (broken: should be ver 3), leaving out `keep`.
    const x = createIdentityDoc(u.ik, { ver: 4, prev: v2.hash, name: u.name, relays: u.relays, devices: [u.dev.did], keyholders: [u.dev.did], by: u.dev.did, iat: NOW - 650 });
    // add(): placed first, dropped when v2 arrives; `keep` isn't denied.
    const c = new IdentityChain(u.userId);
    c.add(x, { now: NOW });
    for (const d of u.docs) c.add(d.jws, { now: NOW });
    expect(c.has(verifyIdentityDocSignature(x).hash)).toBe(false);
    expect(c.view().devices).toContain(keep.did);
    expect(c.toStored().denied ?? []).not.toContain(keep.did);
    // fromStored(): the same store loads without denying it either.
    const loaded = IdentityChain.fromStored({ iss: u.userId, versions: [...u.docs.map((d) => d.jws), x] }, { now: NOW });
    expect(loaded.view().devices).toContain(keep.did);
    expect(loaded.toStored().denied ?? []).not.toContain(keep.did);
  });

  it("a child dropped for no-return (its link valid) still has its revocations denied, as before", () => {
    const u = makeUser("alice");
    const d = u.addDevice({ keyholder: false });
    for (let i = 0; i < 4; i++) u.publish({ iat: NOW - 900 + i }); // v2..v5 [dev, D]
    const v5 = u.doc;
    const e = u.addDevice({ keyholder: false });
    const v6 = u.publish({ devices: [u.dev.did, d.did, e.did], iat: NOW - 800 });
    const v7 = u.publish({ devices: [u.dev.did, e.did], iat: NOW - 790 });
    const c = IdentityChain.fromStored({ iss: u.userId, versions: [v6.jws, v7.jws], denied: [e.did] }, { now: NOW });
    c.add(v5.jws, { now: NOW });
    expect(c.has(v6.hash)).toBe(false);
    expect(c.view().devices).not.toContain(d.did);
  });
});
