// Copyright 2026 Ix Infrastructure Inc.
//
// Regression tests for #79: on a refresh over no (or only unanchored) history, a key thief's higher branch
// must not replace the owner's revoking version under the L5 rule before that version's ancestry is known,
// so a device the owner revoked never ends up trusted.

import { describe, expect, it } from "vitest";
import { createIdentityDoc, IdentityChain, MAX_CHAIN_VERSIONS, MAX_SIDE_ROOTS, pendingHeadSenders, verifyIdentityDocSignature, type VerifiedIdentityDoc } from "../identitydoc.js";
import { addIdentityVersion, getIdentityView, heldBackByOf, lastRefreshed, refreshIdentity, type IdentityFetcher } from "../state.js";
import { MemoryTrustStoreV3 } from "../store.js";
import { makeUser, NOW, RELAY, RELAY2 } from "./fixtures.js";

/** v1 [dev1], v2..v3 [dev1, stolen]; a key thief builds v4'..v8' off v3 keeping `stolen`; the owner revokes it at v4. */
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
  const all = new Map([...u.docs, ...forged].map((d) => [d.hash, d]));
  /** The §5.6 walk back from `to` over `docs`. */
  const walk = (docs: Map<string, VerifiedIdentityDoc>, to: string) => {
    const out: string[] = [];
    for (let d = docs.get(to); d; d = d.prev ? docs.get(d.prev) : undefined) out.push(d.jws);
    return out.slice(0, 32);
  };
  return { u, stolen, forged, own4, head: forged[4], all, walk };
}

/** Per-relay answers: the thief's relay and the owner's relay each answer for themselves. */
function perRelay(tips: Record<string, string[]>, chain: Record<string, (to: string) => string[]>): IdentityFetcher {
  return {
    tips: async (_u, rs) => tips[rs[0]] ?? [],
    chain: async (_u, rs, to) => chain[rs[0]]?.(to) ?? [],
  };
}

describe("#79: first contact keeps the owner's revocation", () => {
  it("the issue's repro: both tips from both relays, both chains served: the revoked device isn't trusted, the fork is shown", async () => {
    const { u, stolen, own4, head, all, walk } = thief();
    const f: IdentityFetcher = { tips: async () => [head.jws, own4.jws], chain: async (_u, _r, to) => walk(all, to) };
    const store = new MemoryTrustStoreV3();
    const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2] });
    expect(v.incomplete).toBeUndefined();
    expect(v.devices).not.toContain(stolen.did);
    expect(v.keyholders).not.toContain(stolen.did);
    expect(v.forked).toBe(true);
    expect(v.tips.map((t) => t.ver)).toEqual([8, 4]);
    // What was stored agrees, and so does every later refresh.
    expect((await getIdentityView(store, u.userId, { now: NOW }))?.devices).not.toContain(stolen.did);
    for (let i = 0; i < 2; i++) expect((await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2] })).devices).not.toContain(stolen.did);
  });

  it("the thief's relay serves only its head and withholds its chain: the owner's relay's v4 is walked down, its revocation carried", async () => {
    const { u, stolen, own4, head, all, walk } = thief();
    const owner = new Map(u.docs.map((d) => [d.hash, d]));
    for (const order of [
      [RELAY, RELAY2],
      [RELAY2, RELAY],
    ]) {
      const [bad, good] = order;
      const f = perRelay({ [bad]: [head.jws], [good]: [own4.jws] }, { [bad]: () => [], [good]: (to) => walk(owner, to) });
      const store = new MemoryTrustStoreV3();
      const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: order });
      expect(v.devices).not.toContain(stolen.did);
      expect(v.keyholders).not.toContain(stolen.did);
      // Reloaded from the store: the revocation is on the denylist, so it survives the dropped branch.
      const stored = (await store.getIdentity(u.userId))!;
      expect(IdentityChain.fromStored(stored, { now: NOW }).view().devices).not.toContain(stolen.did);
      // And the next refresh, with the thief's relay serving its whole chain this time, can't bring it back.
      const again = await refreshIdentity(store, u.userId, perRelay({ [bad]: [head.jws], [good]: [own4.jws] }, { [bad]: (to) => walk(all, to), [good]: (to) => walk(owner, to) }), {
        now: NOW,
        relays: order,
      });
      expect(again.devices).not.toContain(stolen.did);
      expect((await getIdentityView(store, u.userId, { now: NOW }))?.devices).not.toContain(stolen.did);
    }
  });

  it("the thief's relay answers the walk with junk and stalls: the owner's v4 still isn't replaced unseen", async () => {
    const { u, stolen, own4, head, walk } = thief();
    const owner = new Map(u.docs.map((d) => [d.hash, d]));
    const junk = Array.from({ length: 64 }, (_, i) => `eyJ0eXAiOiJ4In0.${"A".repeat(40 + i)}.sig`);
    const f = perRelay({ [RELAY]: [head.jws, ...junk], [RELAY2]: [own4.jws] }, { [RELAY]: () => junk, [RELAY2]: (to) => walk(owner, to) });
    const store = new MemoryTrustStoreV3();
    const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2] });
    expect(v.devices).not.toContain(stolen.did);
    expect((await getIdentityView(store, u.userId, { now: NOW }))?.devices).not.toContain(stolen.did);
  });

  it("the owner's v4 held from an earlier first copy: a refresh serving the thief's head doesn't replace it unseen", async () => {
    const { u, stolen, own4, head, walk } = thief();
    const owner = new Map(u.docs.map((d) => [d.hash, d]));
    const store = new MemoryTrustStoreV3();
    expect(await addIdentityVersion(store, own4.jws, { now: NOW })).toMatchObject({ status: "accepted", unanchored: true });
    const f = perRelay({ [RELAY]: [head.jws], [RELAY2]: [own4.jws] }, { [RELAY]: () => [], [RELAY2]: (to) => walk(owner, to) });
    const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2] });
    expect(v.devices).not.toContain(stolen.did);
    expect((await getIdentityView(store, u.userId, { now: NOW }))?.devices).not.toContain(stolen.did);
  });

  it("an honest newer head over unanchored history still gets in: walked when the relays serve the chain, replaced (no history gap) when they can't", async () => {
    const u = makeUser("alice");
    u.relays = [RELAY, RELAY2];
    for (let i = 0; i < 4; i++) u.publish({ iat: NOW - 900 + i });
    const v5 = u.doc;
    for (let i = 0; i < 6; i++) u.publish({ iat: NOW - 800 + i });
    const v11 = u.doc;
    const byHash = new Map(u.docs.map((d) => [d.hash, d]));
    const walk = (to: string) => {
      const out: string[] = [];
      for (let d = byHash.get(to); d; d = d.prev ? byHash.get(d.prev) : undefined) out.push(d.jws);
      return out;
    };
    // A stale relay still serves v5, the other v11; the chain is served.
    const store = new MemoryTrustStoreV3();
    const v = await refreshIdentity(store, u.userId, perRelay({ [RELAY]: [v5.jws], [RELAY2]: [v11.jws] }, { [RELAY]: walk, [RELAY2]: walk }), { now: NOW, relays: [RELAY, RELAY2] });
    expect(v.incomplete).toBeUndefined();
    expect(v.head.hash).toBe(v11.hash);
    expect(v.forked).toBe(false);
    expect(v.historyGap).toBe(false);
    expect(await lastRefreshed(store, u.userId)).toBe(NOW);
    // No chain request at all (a plain fetcher): the unanchored root is replaced as before (L5), no history gap.
    const plain = new MemoryTrustStoreV3();
    const w = await refreshIdentity(plain, u.userId, async (_u, rs) => (rs[0] === RELAY ? [v5.jws] : [v11.jws]), { now: NOW, relays: [RELAY, RELAY2] });
    expect(w.head.hash).toBe(v11.hash);
    expect(w.historyGap).toBe(false);
    expect((await plain.getIdentity(u.userId))!.versions).toEqual([v11.jws]);
  });

  it("relays that pruned old versions (the walk stops short of v1, of v2, or of everything below the root): the revoked device still isn't trusted", async () => {
    for (const lowest of [2, 3, 4, 5]) {
      const { u, stolen, own4, head, all, walk } = thief();
      // Every relay's chain answer leaves out everything below `lowest` (relays keep non-tip versions for a while only).
      const kept = new Map([...all].filter(([, d]) => d.ver >= lowest));
      const f: IdentityFetcher = { tips: async () => [head.jws, own4.jws], chain: async (_u, _r, to) => walk(kept, to) };
      const store = new MemoryTrustStoreV3();
      for (let i = 0; i < 2; i++) {
        const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2] });
        expect([lowest, v.devices.includes(stolen.did), v.keyholders.includes(stolen.did)]).toEqual([lowest, false, false]);
        if (lowest <= 3) {
          // v3 is placed below the owner's v4, and the thief's branch connects to it: the fork shows.
          expect([lowest, v.incomplete, v.forked, v.tips.map((t) => t.ver)]).toEqual([lowest, undefined, true, [8, 4]]);
        } else {
          // Nothing connects the two: not replaced, the refresh stays incomplete (no freshness).
          expect([lowest, v.incomplete]).toEqual([lowest, true]);
          expect(await lastRefreshed(store, u.userId)).toBeUndefined();
        }
        expect((await getIdentityView(store, u.userId, { now: NOW }))?.devices).not.toContain(stolen.did);
      }
    }
  });

  it("the walk extends an unanchored root downward: what the root revoked is known without version 1", () => {
    const { u, stolen, own4, forged } = thief();
    const c = new IdentityChain(u.userId);
    c.add(own4.jws, { now: NOW });
    expect(c.add(u.docs[2].jws, { now: NOW })).toMatchObject({ status: "accepted", unanchored: true }); // v3 below v4
    expect([...c.revokedAlong(own4.hash)]).toEqual([stolen.did]);
    expect(c.add(forged[0].jws, { now: NOW }).status).toBe("accepted"); // the thief's v4' connects to v3
    expect(c.view().forked).toBe(true);
    expect(c.view().devices).not.toContain(stolen.did);
    expect(c.anchored).toBe(false);
    // A version that isn't the root's parent stays a gap; a forged "parent" can't hash to it.
    const reloaded = IdentityChain.fromStored(c.toStored(), { now: NOW });
    expect(reloaded.view().devices).not.toContain(stolen.did);
  });

  it("an honest newer head over a current root, chain unavailable: replaced when it adds nothing; held back (incomplete, narrowed) when it adds a device; replaced once the root has expired", async () => {
    const u = makeUser("alice");
    u.relays = [RELAY, RELAY2];
    u.addDevice({ keyholder: false }); // dropped at v9
    for (let i = 0; i < 4; i++) u.publish({ iat: NOW - 900 + i }); // v2..v5 [dev1, extra]
    const v5 = u.doc;
    const v9 = (() => {
      for (let i = 0; i < 3; i++) u.publish({ iat: NOW - 800 + i });
      return u.publish({ devices: [u.dev.did], iat: NOW - 700 }); // v9 drops extra
    })();
    const plain = (tipsFor: Record<string, string[]>): IdentityFetcher => async (_u, rs) => tipsFor[rs[0]] ?? [];
    // Removes only: L5 replacement as before.
    const s1 = new MemoryTrustStoreV3();
    const a = await refreshIdentity(s1, u.userId, plain({ [RELAY]: [v5.jws], [RELAY2]: [v9.jws] }), { now: NOW, relays: [RELAY, RELAY2] });
    expect([a.incomplete, a.head.hash, a.historyGap]).toEqual([undefined, v9.hash, false]);
    // Adds a device the stale relay's current tip doesn't list: held back while that tip is current.
    const added = u.addDevice({ keyholder: false });
    u.publish({ devices: [u.dev.did, added.did], iat: NOW - 600 }); // v10
    const v11 = u.publish({ devices: [u.dev.did, added.did], iat: NOW - 590 });
    const s2 = new MemoryTrustStoreV3();
    const b = await refreshIdentity(s2, u.userId, plain({ [RELAY]: [v9.jws], [RELAY2]: [v11.jws] }), { now: NOW, relays: [RELAY, RELAY2] });
    expect(b.incomplete).toBe(true);
    expect(b.devices).toEqual([u.dev.did]);
    // Once that tip has expired, the newer head replaces it.
    const later = v9.exp + 1;
    const c = await refreshIdentity(s2, u.userId, plain({ [RELAY]: [v9.jws], [RELAY2]: [v11.jws] }), { now: later, relays: [RELAY, RELAY2] });
    expect([c.incomplete, c.head.hash, c.historyGap]).toEqual([undefined, v11.hash, false]);
    expect(c.devices).toContain(added.did);
  });

  it("a relay replaying old versions below an unanchored root doesn't turn an L5 replacement into a history-gap jump", async () => {
    const u = makeUser("alice");
    u.relays = [RELAY, RELAY2];
    for (let i = 0; i < 4; i++) u.publish({ iat: NOW - 900 + i });
    const v5 = u.doc;
    for (let i = 0; i < 5; i++) u.publish({ iat: NOW - 800 + i });
    const v10 = u.doc;
    const byHash = new Map(u.docs.map((d) => [d.hash, d]));
    const store = new MemoryTrustStoreV3();
    await addIdentityVersion(store, v5.jws, { now: NOW });
    // The honest relay can't connect v10 (its v6..v9 are gone); the other replays v4..v1 below v5.
    const f = perRelay(
      { [RELAY]: [v10.jws], [RELAY2]: [v5.jws] },
      {
        [RELAY]: () => [],
        [RELAY2]: (to) => {
          const out: string[] = [];
          for (let d = byHash.get(to); d && d.ver <= 4; d = d.prev ? byHash.get(d.prev) : undefined) out.push(d.jws);
          return out;
        },
      },
    );
    const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2] });
    expect([v.incomplete, v.head.hash, v.historyGap]).toEqual([undefined, v10.hash, false]);
  });
});

describe("#79 re-review: versions left out of the result, links checked below a root, the cap", () => {
  /** As thief(), but the thief's branch also adds its own device T from v5' on. */
  function thiefAdding() {
    const u = makeUser("alice");
    u.relays = [RELAY, RELAY2];
    const stolen = u.addDevice({ keyholder: false });
    const t = u.addDevice({ keyholder: false });
    u.publish({ devices: [u.dev.did, stolen.did], iat: NOW - 900 });
    const v3 = u.publish({ devices: [u.dev.did, stolen.did], iat: NOW - 890 });
    const forged: VerifiedIdentityDoc[] = [];
    let p = v3;
    for (let v = 4; v <= 8; v++) {
      const devices = v >= 5 ? [u.dev.did, stolen.did, t.did] : [u.dev.did, stolen.did];
      p = verifyIdentityDocSignature(createIdentityDoc(u.ik, { ver: v, prev: p.hash, name: u.name, relays: u.relays, devices, keyholders: [u.dev.did], by: u.dev.did, iat: NOW - 800 + v }));
      forged.push(p);
    }
    const own4 = u.publish({ devices: [u.dev.did], iat: NOW - 700 });
    return { u, stolen, t, forged, own4, head: forged[4] };
  }
  const walkOf = (docs: readonly VerifiedIdentityDoc[], lowest = 1) => {
    const m = new Map(docs.filter((d) => d.ver >= lowest).map((d) => [d.hash, d]));
    return (to: string) => {
      const out: string[] = [];
      for (let d = m.get(to); d; d = d.prev ? m.get(d.prev) : undefined) out.push(d.jws);
      return out.slice(0, 64);
    };
  };

  it("M1: the owner's v4 connected below (walked to v1, v2 or v3), the thief's relay withholding its chain: the thief's head doesn't replace it", async () => {
    for (const lowest of [1, 2, 3]) {
      const { u, stolen, t, own4, head } = thiefAdding();
      const f = perRelay({ [RELAY]: [head.jws], [RELAY2]: [own4.jws] }, { [RELAY]: () => [], [RELAY2]: walkOf(u.docs, lowest) });
      const store = new MemoryTrustStoreV3();
      const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2] });
      expect([lowest, v.incomplete, v.devices.includes(stolen.did), v.devices.includes(t.did)]).toEqual([lowest, true, false, false]);
      expect(await lastRefreshed(store, u.userId)).toBeUndefined();
      // The held-back head is a pending head with the relay that sent it recorded (#78).
      expect(pendingHeadSenders((await store.getIdentity(u.userId))!, { now: NOW })).toEqual([{ ver: 8, hash: head.hash, relays: [RELAY] }]);
      const stored = await getIdentityView(store, u.userId, { now: NOW });
      expect([stored?.devices.includes(stolen.did), stored?.devices.includes(t.did)]).toEqual([false, false]);
    }
  });

  it("M2a: the owner's v4 stored from a first copy, the owner's relay silent: the thief's head doesn't replace it", async () => {
    const { u, stolen, t, own4, head } = thiefAdding();
    const store = new MemoryTrustStoreV3();
    await addIdentityVersion(store, own4.jws, { now: NOW });
    const silent = () => new Promise<string[]>(() => {});
    const f: IdentityFetcher = {
      tips: async (_u, rs) => (rs[0] === RELAY ? [head.jws] : silent()),
      chain: async (_u, rs) => (rs[0] === RELAY ? [] : silent()),
    };
    const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2], fetchTimeoutMs: 50 });
    expect([v.incomplete, v.devices.includes(stolen.did), v.devices.includes(t.did)]).toEqual([true, false, false]);
    expect((await getIdentityView(store, u.userId, { now: NOW }))?.devices).toEqual([u.dev.did]);
  });

  it("M2b: a forged same-ver version placed first, whose link to the genuine parent is broken: the genuine parent isn't refused, the forgery is dropped (or the two show as a fork)", async () => {
    for (const lowest of [2, 3]) {
      const { u, stolen, own4 } = thiefAdding();
      const v2 = u.docs[1];
      // ver 4 naming v2 as prev: signed with the identity key, but not a valid next version of v2.
      const x = verifyIdentityDocSignature(
        createIdentityDoc(u.ik, { ver: 4, prev: v2.hash, name: u.name, relays: u.relays, devices: [u.dev.did, stolen.did], keyholders: [u.dev.did], by: u.dev.did, iat: NOW - 650 }),
      );
      const f = perRelay({ [RELAY]: [x.jws, own4.jws], [RELAY2]: [x.jws, own4.jws] }, { [RELAY]: walkOf(u.docs, lowest), [RELAY2]: walkOf(u.docs, lowest) });
      const store = new MemoryTrustStoreV3();
      const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2] });
      expect([lowest, v.devices.includes(stolen.did)]).toEqual([lowest, false]);
      // v2 served: it is placed and the forgery dropped, the owner's v4 is the head. Only v3 up: the forgery's
      // broken link isn't visible, and the two same-ver tips are a fork.
      if (lowest === 2) expect([v.head.hash, v.forked]).toEqual([own4.hash, false]);
      else expect([v.forked, v.tips.map((t) => t.hash).sort()]).toEqual([true, [own4.hash, x.hash].sort()]);
      expect((await getIdentityView(store, u.userId, { now: NOW }))?.devices).not.toContain(stolen.did);
    }
  });

  it("LOW: a branch re-adding a device that a link found below the root revoked: that branch is dropped, the parent kept", () => {
    const { u, stolen, own4 } = thiefAdding();
    const c = new IdentityChain(u.userId);
    c.add(own4.jws, { now: NOW });
    const v5 = verifyIdentityDocSignature(
      createIdentityDoc(u.ik, { ver: 5, prev: own4.hash, name: u.name, relays: u.relays, devices: [u.dev.did, stolen.did], keyholders: [u.dev.did], by: u.dev.did, iat: NOW - 600 }),
    );
    expect(c.add(v5.jws, { now: NOW }).status).toBe("accepted"); // own4's parent unknown: nothing to refuse yet
    expect(c.add(u.docs[2].jws, { now: NOW }).status).toBe("accepted"); // v3 below own4
    expect(c.has(u.docs[2].hash)).toBe(true);
    expect(c.has(v5.hash)).toBe(false); // what add() refuses in the other order
    expect(c.view().devices).not.toContain(stolen.did);
    expect(IdentityChain.fromStored(c.toStored(), { now: NOW }).view().devices).not.toContain(stolen.did);
  });

  it("M2b: a valid same-ver forgery placed first, nothing below served: the two same-ver tips are a fork", async () => {
    const { u, stolen, own4 } = thiefAdding();
    const v3 = u.docs[2];
    const x = verifyIdentityDocSignature(
      createIdentityDoc(u.ik, { ver: 4, prev: v3.hash, name: u.name, relays: u.relays, devices: [u.dev.did, stolen.did], keyholders: [u.dev.did], by: u.dev.did, iat: NOW - 650 }),
    );
    const f = perRelay({ [RELAY]: [x.jws, own4.jws], [RELAY2]: [x.jws, own4.jws] }, { [RELAY]: () => [], [RELAY2]: () => [] });
    const store = new MemoryTrustStoreV3();
    const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2] });
    expect([v.forked, v.devices.includes(stolen.did)]).toEqual([true, false]);
    expect((await getIdentityView(store, u.userId, { now: NOW }))?.devices).not.toContain(stolen.did);
  });

  it("LOW: an unanchored history at the cap: a root's parent isn't asked for, and a gap above the head still settles", async () => {
    const u = makeUser("alice");
    u.relays = [RELAY, RELAY2];
    for (let i = 0; i < 8; i++) u.publish({ iat: NOW - 500 });
    const c = new IdentityChain(u.userId);
    for (let i = 0; i < MAX_CHAIN_VERSIONS; i++) c.add(u.publish({ iat: NOW - 400 }).jws, { now: NOW }); // v10..v1033, rooted at v10
    expect(c.size).toBe(MAX_CHAIN_VERSIONS);
    expect(c.anchored).toBe(false);
    const store = new MemoryTrustStoreV3();
    await store.putIdentity(c.toStored());
    for (let i = 0; i < 7; i++) u.publish({ iat: NOW - 300 }); // v1034..v1040
    const top = u.doc;
    // The relays lost v1034..v1035; everything else is served.
    const f = perRelay({ [RELAY]: [top.jws], [RELAY2]: [top.jws] }, { [RELAY]: walkOf(u.docs.filter((d) => d.ver < 1034 || d.ver > 1035)), [RELAY2]: walkOf(u.docs.filter((d) => d.ver < 1034 || d.ver > 1035)) });
    const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2], budgetMs: 60_000 });
    expect([v.incomplete, v.head.hash]).toEqual([undefined, top.hash]);
    expect(await lastRefreshed(store, u.userId)).toBe(NOW);
  }, 60_000);
});

describe("#79 third review: relay support, versions placed before their parent, side roots", () => {
  const R3 = "wss://third.example/v3";
  const chainOf = (docs: readonly VerifiedIdentityDoc[]) => {
    const m = new Map(docs.map((d) => [d.hash, d]));
    return (to: string) => {
      const out: string[] = [];
      for (let d = m.get(to); d; d = d.prev ? m.get(d.prev) : undefined) out.push(d.jws);
      return out.slice(0, 64);
    };
  };

  it("T1: one relay replaying a genuine current old version can't hold back a head most listed relays serve", async () => {
    const u = makeUser("alice");
    u.relays = [RELAY, RELAY2, R3];
    for (let i = 0; i < 3; i++) u.publish({ iat: NOW - 900 + i });
    const v4 = u.doc;
    for (let i = 0; i < 5; i++) u.publish({ iat: NOW - 800 + i });
    const added = u.addDevice({ keyholder: false });
    u.publish({ iat: NOW - 700 }); // v9 adds a device
    const v10 = u.publish({ iat: NOW - 690 });
    // The honest relays kept only their last versions (v8..v10); the replaying relay serves v4 and its ancestry.
    const recent = chainOf(u.docs.filter((d) => d.ver >= 8));
    const old = chainOf(u.docs.filter((d) => d.ver <= 4));
    const f = perRelay({ [RELAY]: [v4.jws], [RELAY2]: [v10.jws], [R3]: [v10.jws] }, { [RELAY]: old, [RELAY2]: recent, [R3]: recent });
    const store = new MemoryTrustStoreV3();
    const first = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2, R3] });
    expect([first.incomplete, first.head.hash, first.devices.includes(added.did)]).toEqual([undefined, v10.hash, true]);
    // With v10 stored: complete and fresh.
    const again = await refreshIdentity(store, u.userId, f, { now: NOW + 60 });
    expect([again.incomplete, again.head.hash]).toEqual([undefined, v10.hash]);
    expect(await lastRefreshed(store, u.userId)).toBe(NOW + 60);
  });

  it("a forged version placed before its genuine parent is dropped when the parent arrives (not stored to break every load)", async () => {
    const { u, stolen, own4 } = (() => {
      const u = makeUser("alice");
      u.relays = [RELAY, RELAY2];
      const stolen = u.addDevice({ keyholder: false });
      u.publish({ iat: NOW - 900 });
      u.publish({ iat: NOW - 890 });
      const own4 = u.publish({ devices: [u.dev.did], iat: NOW - 700 });
      return { u, stolen, own4 };
    })();
    const v2 = u.docs[1];
    const x = verifyIdentityDocSignature(
      createIdentityDoc(u.ik, { ver: 4, prev: v2.hash, name: u.name, relays: u.relays, devices: [u.dev.did, stolen.did], keyholders: [u.dev.did], by: u.dev.did, iat: NOW - 650 }),
    );
    const walk = chainOf(u.docs);
    const f = perRelay({ [RELAY]: [x.jws, own4.jws], [RELAY2]: [x.jws, own4.jws] }, { [RELAY]: walk, [RELAY2]: walk });
    const store = new MemoryTrustStoreV3();
    const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2] });
    expect([v.head.hash, v.devices.includes(stolen.did)]).toEqual([own4.hash, false]);
    const stored = (await store.getIdentity(u.userId))!;
    expect(stored.versions).not.toContain(x.jws);
    expect(() => IdentityChain.fromStored(stored, { now: NOW })).not.toThrow();
    // And the next refresh works.
    expect((await refreshIdentity(store, u.userId, f, { now: NOW })).head.hash).toBe(own4.hash);
    // add() itself, in that order: the child is checked when its parent arrives.
    const c = new IdentityChain(u.userId);
    c.add(x.jws, { now: NOW });
    for (const d of u.docs.slice(0, 2)) c.add(d.jws, { now: NOW });
    expect(c.has(x.hash)).toBe(false);
    expect(c.has(v2.hash)).toBe(true);
  });

  it("a store already poisoned that way loads, without the bad version and what was placed on it", async () => {
    const u = makeUser("alice");
    u.publish({ iat: NOW - 900 });
    u.publish({ iat: NOW - 890 });
    const v2 = u.docs[1];
    const x = verifyIdentityDocSignature(
      createIdentityDoc(u.ik, { ver: 4, prev: v2.hash, name: u.name, relays: u.relays, devices: [u.dev.did], keyholders: [u.dev.did], by: u.dev.did, iat: NOW - 650 }),
    );
    const x5 = verifyIdentityDocSignature(
      createIdentityDoc(u.ik, { ver: 5, prev: x.hash, name: u.name, relays: u.relays, devices: [u.dev.did], keyholders: [u.dev.did], by: u.dev.did, iat: NOW - 640 }),
    );
    const store = new MemoryTrustStoreV3();
    await store.putIdentity({ iss: u.userId, versions: [...u.docs.map((d) => d.jws), x.jws, x5.jws] });
    const view = await getIdentityView(store, u.userId, { now: NOW });
    expect(view?.head.hash).toBe(u.doc.hash);
    expect(view?.tips.map((t) => t.hash)).toEqual([u.doc.hash]);
  });

  it("side roots: only current versions, and only while fewer than MAX_SIDE_ROOTS tips are held", () => {
    const u = makeUser("alice");
    u.publish({ iat: NOW - 900 });
    const v3 = u.publish({ iat: NOW - 890 });
    const c = new IdentityChain(u.userId);
    const v4 = u.publish({ iat: NOW - 880 });
    c.add(v4.jws, { now: NOW });
    const sibling = (iat: number) =>
      createIdentityDoc(u.ik, { ver: 4, prev: v3.hash, name: u.name, relays: u.relays, devices: [u.dev.did], keyholders: [u.dev.did], by: u.dev.did, iat });
    // Expired: not kept.
    expect(c.add(sibling(NOW - 40 * 86_400), { now: NOW, replace: false, asRoot: true }).status).toBe("gap");
    for (let i = 0; i < MAX_SIDE_ROOTS + 4; i++) c.add(sibling(NOW - 100 + i), { now: NOW, replace: false, asRoot: true });
    expect(c.allTips().length).toBeLessThanOrEqual(MAX_SIDE_ROOTS);
  });
});

describe("#79 fourth review: dropping only narrows", () => {
  /** v5 [dev, D]; v6 adds E; v7 revokes D. E is on the denylist (as after a replacement), so v6 can't follow v5. */
  function setup() {
    const u = makeUser("alice");
    const d = u.addDevice({ keyholder: false });
    for (let i = 0; i < 4; i++) u.publish({ iat: NOW - 900 + i }); // v2..v5 [dev, D]
    const v5 = u.doc;
    const e = u.addDevice({ keyholder: false });
    const v6 = u.publish({ devices: [u.dev.did, d.did, e.did], iat: NOW - 800 });
    const v7 = u.publish({ devices: [u.dev.did, e.did], iat: NOW - 790 });
    return { u, d, e, v5, v6, v7 };
  }

  it("a version placed below drops a no-return violator and its descendants, and what they revoked stays revoked", () => {
    const { u, d, e, v5, v6, v7 } = setup();
    const c = IdentityChain.fromStored({ iss: u.userId, versions: [v6.jws, v7.jws], denied: [e.did] }, { now: NOW });
    expect(c.view().devices).not.toContain(d.did);
    expect(c.add(v5.jws, { now: NOW }).status).toBe("accepted");
    expect(c.has(v6.hash)).toBe(false);
    expect(c.view().devices).not.toContain(d.did);
    expect(c.view().devices).not.toContain(e.did);
    expect(IdentityChain.fromStored(c.toStored(), { now: NOW }).view().devices).not.toContain(d.did);
  });

  it("loading the same versions with the same denylist: the dropped ones' revocations stay too", () => {
    const { u, d, e, v5, v6, v7 } = setup();
    const c = IdentityChain.fromStored({ iss: u.userId, versions: [v5.jws, v6.jws, v7.jws], denied: [e.did] }, { now: NOW });
    expect(c.has(v6.hash)).toBe(false);
    expect(c.view().devices).not.toContain(d.did);
    expect(c.view().devices).not.toContain(e.did);
  });

  it("side roots past their exp don't count toward MAX_SIDE_ROOTS", () => {
    const u = makeUser("alice");
    u.publish({ iat: NOW - 900 });
    const v3 = u.publish({ iat: NOW - 890 });
    const v4 = u.publish({ iat: NOW - 880 });
    const sibling = (iat: number) =>
      createIdentityDoc(u.ik, { ver: 4, prev: v3.hash, name: u.name, relays: u.relays, devices: [u.dev.did], keyholders: [u.dev.did], by: u.dev.did, iat, ttlSec: 3600 });
    const c = new IdentityChain(u.userId);
    c.add(v4.jws, { now: NOW });
    for (let i = 0; i < MAX_SIDE_ROOTS; i++) c.add(sibling(NOW - 100 + i), { now: NOW, replace: false, asRoot: true });
    const later = NOW + 7200; // every side root (and v4) still current? v4 yes; the short-lived siblings no
    expect(c.add(sibling(later - 10), { now: later, replace: false, asRoot: true }).status).toBe("accepted");
  });
});

describe("#79 post-merge: the relays a refresh of our own identity was held back for", () => {
  it("reported (own identity only) on the held-back result, and on chain-broken once the history is anchored", async () => {
    const u = makeUser("alice");
    u.relays = [RELAY, RELAY2];
    const stolen = u.addDevice({ keyholder: false });
    u.publish({ devices: [u.dev.did], iat: NOW - 900 });
    const v3 = u.publish({ devices: [u.dev.did], iat: NOW - 890 });
    const own4 = u.publish({ devices: [u.dev.did], iat: NOW - 700 });
    let p = v3;
    for (let v = 4; v <= 8; v++) {
      p = verifyIdentityDocSignature(createIdentityDoc(u.ik, { ver: v, prev: p.hash, name: u.name, relays: u.relays, devices: [u.dev.did, stolen.did], keyholders: [u.dev.did], by: u.dev.did, iat: NOW - 800 + v }));
    }
    const head = p;
    const owner = new Map(u.docs.map((d) => [d.hash, d]));
    const walk = (to: string) => {
      const out: string[] = [];
      for (let d = owner.get(to); d; d = d.prev ? owner.get(d.prev) : undefined) out.push(d.jws);
      return out;
    };
    const f = perRelay({ [RELAY]: [head.jws], [RELAY2]: [own4.jws] }, { [RELAY]: () => [], [RELAY2]: walk });
    for (const own of [false, true]) {
      const store = new MemoryTrustStoreV3();
      await addIdentityVersion(store, own4.jws, { now: NOW });
      const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2], own });
      expect([own, v.incomplete, v.heldBackBy]).toEqual([own, true, own ? [RELAY] : undefined]);
      // The walk anchored the history: the next refresh fails chain-broken, with the same relay reported.
      const e = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2], own }).catch((x: unknown) => x);
      expect([own, (e as { reason?: string }).reason, heldBackByOf(e)]).toEqual([own, "chain-broken", own ? [RELAY] : []]);
    }
  });
});
