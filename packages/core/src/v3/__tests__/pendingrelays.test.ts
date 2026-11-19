// Copyright 2026 Ix Infrastructure Inc.
//
// #78: each pending head is stored with the relays that sent it (local only, like walkAnchorRelays), so the
// owner's strict refresh can refuse to build below a newer version a relay that is silent now sent earlier.
//  - recorded by an incomplete refresh; kept across a store round trip; stores written before this (no
//    senders) still load, and their pending heads have no known sender;
//  - another relay's higher version can't push out the one a relay sent (each relay's highest stays);
//  - for the client's own identity (`own`), a majority's complete refresh keeps the pending heads a relay that
//    didn't answer sent; for anyone else it still clears them all (#35 review M1).

import { describe, expect, it } from "vitest";
import { createIdentityDoc, IdentityChain, pendingHeadSenders, verifyIdentityDocSignature, type VerifiedIdentityDoc } from "../identitydoc.js";
import { addIdentityVersion, refreshIdentity, type IdentityFetcher } from "../state.js";
import { MemoryTrustStoreV3 } from "../store.js";
import { makeUser, NOW, type TestUser } from "./fixtures.js";

const A = "wss://a.example/v3";
const B = "wss://b.example/v3";
const C = "wss://c.example/v3";
const H = "wss://h.example/v3";

const walkFrom = (docs: readonly { hash: string; jws: string; prev: string | null }[]) => async (_u: string, _r: readonly string[], to: string, n: number) => {
  const byHash = new Map(docs.map((d) => [d.hash, d]));
  const out: string[] = [];
  for (let d = byHash.get(to); d && out.length < n; d = d.prev ? byHash.get(d.prev) : undefined) out.push(d.jws);
  return out;
};

async function storeWith(docs: readonly { jws: string }[]): Promise<MemoryTrustStoreV3> {
  const s = new MemoryTrustStoreV3();
  for (const d of docs) await addIdentityVersion(s, d.jws, { now: NOW });
  return s;
}

function doc(u: TestUser, f: { ver: number; prev: string | null; devices: string[]; keyholders: string[]; iat: number }): VerifiedIdentityDoc {
  return verifyIdentityDocSignature(
    createIdentityDoc(u.ik, {
      ver: f.ver,
      prev: f.prev,
      name: u.name,
      relays: u.relays,
      devices: f.devices,
      keyholders: f.keyholders,
      by: f.keyholders[0],
      certs: u.devices.filter((d) => f.devices.includes(d.did)).map((d) => d.cert),
      iat: f.iat,
    }),
  );
}

/** u at ver 60; a store holding ver 1..5; relay A holds it all, B and C lag at ver 5. */
function lagging() {
  const u = makeUser("alice");
  for (let i = 2; i <= 60; i++) u.publish({ iat: NOW - 1000 + i });
  const head = u.docs[59];
  const v5 = u.docs[4];
  return { u, head, v5 };
}

/** A's tips and walk; B and C answer ver 5; `silent` relays fail. */
function fetcherFor(u: TestUser, head: { jws: string }, v5: { jws: string }, silent: readonly string[] = []): IdentityFetcher {
  return {
    tips: async (_u, relays) => {
      if (silent.includes(relays[0])) throw new Error("timeout");
      return relays[0] === A ? [head.jws] : [v5.jws];
    },
    chain: async (uid, relays, to, n) => {
      if (silent.includes(relays[0])) throw new Error("timeout");
      return relays[0] === A ? walkFrom(u.docs)(uid, relays, to, n) : [];
    },
  };
}

describe("#78: the relays that sent each pending head", () => {
  it("an incomplete refresh records them; a later one that A doesn't answer keeps them, for our own identity only", async () => {
    for (const own of [true, false]) {
      const { u, head, v5 } = lagging();
      const store = await storeWith(u.docs.slice(0, 5));
      const first = await refreshIdentity(store, u.userId, fetcherFor(u, head, v5), { now: NOW, relays: [A, B, C], checkMs: 1, own });
      expect(first.incomplete).toBe(true);
      const stored = (await store.getIdentity(u.userId))!;
      expect(stored.pendingHeads).toContain(head.jws);
      expect(stored.pendingHeadRelays?.[head.hash]).toEqual([A]);
      expect(pendingHeadSenders(stored, { now: NOW }).find((p) => p.hash === head.hash)).toEqual({ ver: 60, hash: head.hash, relays: [A] });
      const committed = first.head.ver;
      expect(committed).toBeLessThan(60);

      // A times out; B and C (a majority of three) answer what is held: a complete refresh.
      const second = await refreshIdentity(store, u.userId, fetcherFor(u, head, v5, [A]), { now: NOW, relays: [A, B, C], own });
      expect(second.incomplete).toBeUndefined();
      expect(second.answeredRelays.sort()).toEqual([B, C]);
      expect(second.head.ver).toBe(committed);
      const after = (await store.getIdentity(u.userId))!;
      if (own) {
        // Ours: kept, with only the relay that didn't answer.
        expect(after.pendingHeads).toEqual([head.jws]);
        expect(after.pendingHeadRelays).toEqual({ [head.hash]: [A] });
      } else {
        // Anyone else's: cleared by the majority, as before (#35 review M1).
        expect(after.pendingHeads).toBeUndefined();
        expect(after.pendingHeadRelays).toBeUndefined();
      }
      if (own) {
        // A answers again: the refresh connects ver 60 (or goes on toward it); once a majority answers
        // completely with A among them, the pending head is gone.
        let v = second;
        for (let i = 0; i < 40 && (v.incomplete || v.head.ver < 60); i++) v = await refreshIdentity(store, u.userId, fetcherFor(u, head, v5), { now: NOW, relays: [A, B, C], own });
        expect(v.head.ver).toBe(60);
        expect((await store.getIdentity(u.userId))!.pendingHeads).toBeUndefined();
        expect((await store.getIdentity(u.userId))!.pendingHeadRelays).toBeUndefined();
      }
    }
  });

  it("a pending head kept for our own identity is dropped once the relay that sent it answers without it", async () => {
    const { u, head, v5 } = lagging();
    const store = await storeWith(u.docs.slice(0, 5));
    await refreshIdentity(store, u.userId, fetcherFor(u, head, v5), { now: NOW, relays: [A, B, C], checkMs: 1, own: true });
    // A now serves only ver 5 too (it lost the newer versions): every relay answered, so nothing is kept.
    const lost: IdentityFetcher = { tips: async () => [v5.jws], chain: async () => [] };
    await refreshIdentity(store, u.userId, lost, { now: NOW, relays: [A, B, C], own: true });
    expect((await store.getIdentity(u.userId))!.pendingHeads).toBeUndefined();
  });

  it("stores written before this (pending heads without senders) still load; their senders are unknown", () => {
    const u = makeUser("alice");
    const v2 = u.publish({ iat: NOW - 900 });
    const x3 = doc(u, { ver: 3, prev: v2.hash, devices: [u.dev.did], keyholders: [u.dev.did], iat: NOW - 800 });
    const legacy = { iss: u.userId, versions: [u.docs[0].jws, v2.jws], pendingHeads: [x3.jws] };
    const c = IdentityChain.fromStored(legacy, { now: NOW });
    expect(c.toStored().pendingHeads).toEqual([x3.jws]);
    expect(c.toStored().pendingHeadRelays).toBeUndefined();
    expect(pendingHeadSenders(legacy, { now: NOW })).toEqual([{ ver: 3, hash: x3.hash, relays: [] }]);
    // Junk in the local field is read defensively.
    const odd = { ...legacy, pendingHeadRelays: { [x3.hash]: [A, 7, null] as unknown as string[] } };
    expect(IdentityChain.fromStored(odd, { now: NOW }).toStored().pendingHeadRelays).toEqual({ [x3.hash]: [A] });
    expect(pendingHeadSenders(odd, { now: NOW })[0].relays).toEqual([A]);
  });

  it("another relay's higher version can't push out the one a relay sent; senders accumulate and round-trip", () => {
    const u = makeUser("alice");
    const v2 = u.publish({ iat: NOW - 900 });
    const me = [u.dev.did];
    const x3 = doc(u, { ver: 3, prev: v2.hash, devices: me, keyholders: me, iat: NOW - 800 });
    const y9 = doc(u, { ver: 9, prev: "A".repeat(43), devices: me, keyholders: me, iat: NOW - 700 });
    const at = { now: NOW };
    const c = IdentityChain.fromStored({ iss: u.userId, versions: [u.docs[0].jws, v2.jws] }, at);
    c.notePending([x3], at, () => [A]);
    // y9 (from H) leaves out nothing more and lasts as long: without senders x3 would be redundant (R3).
    expect(c.notePending([y9], at, () => [H])).toBe(true);
    expect(c.toStored().pendingHeads).toEqual([y9.jws, x3.jws]);
    expect(c.toStored().pendingHeadRelays).toEqual({ [y9.hash]: [H], [x3.hash]: [A] });
    // Without senders it is still dropped as before (nothing to keep it for).
    const plain = IdentityChain.fromStored({ iss: u.userId, versions: [u.docs[0].jws, v2.jws] }, at);
    plain.notePending([x3], at);
    plain.notePending([y9], at);
    expect(plain.toStored().pendingHeads).toEqual([y9.jws]);
    // The same head from another relay adds a sender; a round trip keeps them.
    const back = IdentityChain.fromStored(c.toStored(), at);
    expect(back.notePending([x3], at, () => [B])).toBe(true);
    expect(back.toStored().pendingHeadRelays?.[x3.hash]).toEqual([A, B]);
    expect(back.notePending([x3], at, () => [B])).toBe(false);
    // clearPending keeping a silent relay's: only those, with only that sender.
    expect(back.clearPending({ keepSentBy: [B] })).toBe(true);
    expect(back.toStored().pendingHeads).toEqual([x3.jws]);
    expect(back.toStored().pendingHeadRelays).toEqual({ [x3.hash]: [B] });
    expect(back.clearPending()).toBe(true);
    expect(back.toStored().pendingHeads).toBeUndefined();
  });
});
