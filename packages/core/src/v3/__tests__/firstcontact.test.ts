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
});
