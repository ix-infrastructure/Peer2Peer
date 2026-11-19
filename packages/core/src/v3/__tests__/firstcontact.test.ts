// Copyright 2026 Ix Infrastructure Inc.
//
// Regression tests for #79: on a refresh over no (or only unanchored) history, a key thief's higher branch
// must not replace the owner's revoking version under the L5 rule before that version's ancestry is known,
// so a device the owner revoked never ends up trusted.

import { describe, expect, it } from "vitest";
import { createIdentityDoc, IdentityChain, verifyIdentityDocSignature, type VerifiedIdentityDoc } from "../identitydoc.js";
import { addIdentityVersion, getIdentityView, lastRefreshed, refreshIdentity, type IdentityFetcher } from "../state.js";
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
