// Copyright 2026 Ix Infrastructure Inc.
//
// Chain walk follow-ups (issue #35):
//  A. an incomplete refresh that commits an intermediate version (or nothing) applies what the verified
//     newest tip revokes, through the pending head, until the stored head reaches it;
//  B. a gap left at the end of the walk is "cut short" only when a relay held the missing version but it
//     wasn't checked in time: a junk relay cut short on every page no longer turns a genuine gap into
//     "incomplete" forever, and (T1) no hostile relay can turn an honest relay's slowness into chain-broken.

import { describe, expect, it } from "vitest";
import { createIdentityDoc, IdentityChain, verifyIdentityDocSignature, type VerifiedIdentityDoc } from "../identitydoc.js";
import { addIdentityVersion, getIdentityView, lastRefreshed, refreshIdentity, type IdentityFetcher } from "../state.js";
import { MemoryTrustStoreV3 } from "../store.js";
import { b64uEncode } from "../../encoding.js";
import { randomBytes } from "../../crypto.js";
import { decodeJws, signJws } from "../../jws.js";
import { makeUser, NOW, storeKnowing, type TestUser } from "./fixtures.js";

const RELAYS = [1, 2, 3, 4, 5].map((i) => `wss://r${i}.example/v3`);

/** Structurally valid, claims the user (right iss and ik), bad signature: costs a real verify. */
function sameKeyJunk(payload: Record<string, unknown>, i: number, ver = 500 + i): string {
  return signJws("p2p-identity+jws", "ik", { ...payload, ver, prev: b64uEncode(randomBytes(32)) }, randomBytes(32));
}

/** u's history as a relay serves the §5.6 walk: from `to` back, newest first, at most n; only what it holds. */
const walkFrom = (docs: readonly { hash: string; jws: string; prev: string | null }[]) => async (_u: string, _r: readonly string[], to: string, n: number) => {
  const byHash = new Map(docs.map((d) => [d.hash, d]));
  const out: string[] = [];
  for (let d = byHash.get(to); d && out.length < n; d = d.prev ? byHash.get(d.prev) : undefined) out.push(d.jws);
  return out;
};

/** Refreshes until complete: each one incomplete or complete (never chain-broken or a jump), the head never going back. */
async function catchUp<V extends { incomplete?: boolean; head: { ver: number; hash: string }; historyGap: boolean }>(refresh: () => Promise<V>, max: number) {
  let last = 0;
  for (let i = 1; i <= max; i++) {
    const v = await refresh();
    expect(v.head.ver).toBeGreaterThanOrEqual(last);
    expect(v.historyGap).toBe(false);
    last = v.head.ver;
    if (!v.incomplete) return { view: v, refreshes: i };
  }
  throw new Error(`still incomplete after ${max} refreshes (head ver ${last})`);
}

/** A store holding exactly these versions. */
async function storeWith(docs: readonly { jws: string }[]): Promise<MemoryTrustStoreV3> {
  const s = new MemoryTrustStoreV3();
  for (const d of docs) await addIdentityVersion(s, d.jws, { now: NOW });
  return s;
}

function doc(u: TestUser, f: { ver: number; prev: string; devices: string[]; keyholders: string[]; iat: number }): VerifiedIdentityDoc {
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

describe("A: an incomplete commit applies what the verified newest tip revokes", () => {
  /** v1 held; v2 adds a key-holding laptop; ... ; the newest version revokes it. */
  async function laptopRevokedAtHead(versions: number, storeHolds: number) {
    const u = makeUser("alice");
    const laptop = u.addDevice({ keyholder: true });
    for (let i = 2; i < versions; i++) u.publish({ iat: NOW - 1000 + i });
    const head = u.publish({ devices: [u.dev.did], keyholders: [u.dev.did], iat: NOW - 10 });
    const store = await storeWith(u.docs.slice(0, storeHolds));
    return { u, laptop, head, store };
  }

  it("an intermediate version that still lists the revoked laptop doesn't trust it, here or from the store", async () => {
    // 60 versions behind on a slow machine (checkMs 1): the first refresh is incomplete and commits an
    // intermediate version that lists the laptop. The verified head (ver 60) already revoked it.
    const { u, laptop, head, store } = await laptopRevokedAtHead(60, 1);
    const fetcher: IdentityFetcher = { tips: async () => [head.jws], chain: walkFrom(u.docs) };
    const first = await refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: [RELAYS[0]], checkMs: 1 });
    expect(first.incomplete).toBe(true);
    expect(first.head.ver).toBeGreaterThanOrEqual(2);
    expect(first.head.ver).toBeLessThan(head.ver);
    expect(first.head.devices).toContain(laptop.did); // what was committed still lists it...
    expect(first.devices).not.toContain(laptop.did); // ...but it isn't trusted
    expect(first.keyholders).not.toContain(laptop.did);
    // Later reads (the store resolvers) see the same narrowed view.
    const later = (await getIdentityView(store, u.userId))!;
    expect(later.devices).toEqual([u.dev.did]);
    expect(later.keyholders).toEqual([u.dev.did]);
    expect((await store.getIdentity(u.userId))!.pendingHead).toBe(head.jws);
    // Nothing is denied for good: the pending head is temporary.
    expect((await store.getIdentity(u.userId))!.denied).toBeUndefined();
    // Catching up: complete, the head reached, the pending head dropped, the laptop still out (chain rules).
    const { view } = await catchUp(() => refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: [RELAYS[0]], checkMs: 1 }), 80);
    expect(view.head.hash).toBe(head.hash);
    expect(view.devices).toEqual([u.dev.did]);
    expect((await store.getIdentity(u.userId))!.pendingHead).toBeUndefined();
    expect(await lastRefreshed(store, u.userId)).toBe(NOW);
  });

  it("an incomplete refresh that commits nothing new still applies it (the laptop was already trusted)", async () => {
    // The store holds v1 and v2 (the laptop trusted). 100 versions behind: the first page (ver 37..99)
    // doesn't reach the held chain, so nothing connects and nothing is accepted.
    const { u, laptop, head, store } = await laptopRevokedAtHead(101, 2);
    expect((await getIdentityView(store, u.userId))!.devices).toContain(laptop.did);
    const fetcher: IdentityFetcher = { tips: async () => [head.jws], chain: walkFrom(u.docs) };
    const first = await refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: [RELAYS[0]], checkMs: 1 });
    expect(first.incomplete).toBe(true);
    expect(first.head.ver).toBe(2);
    expect(first.devices).not.toContain(laptop.did);
    expect((await getIdentityView(store, u.userId))!.devices).not.toContain(laptop.did);
  });

  it("hostile relays can't plant or lower the pending head: forged high-ver tips are ignored, an older genuine one doesn't replace it", async () => {
    const { u, laptop, head, store } = await laptopRevokedAtHead(60, 1);
    const p = decodeJws(head.jws).payload;
    const forged = Array.from({ length: 8 }, (_, i) => sameKeyJunk({ ...p, devices: [] }, i, 900 + i)); // claims ver 900+, bad signature
    const older = u.docs[40]; // genuine, lists the laptop
    const hostileTips = [...forged, older.jws];
    const fetcher: IdentityFetcher = {
      tips: async (_u, relays) => (relays[0] === RELAYS[0] ? [head.jws] : hostileTips),
      chain: async (uid, relays, to, n) => (relays[0] === RELAYS[0] ? walkFrom(u.docs)(uid, relays, to, n) : forged),
    };
    const first = await refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: RELAYS.slice(0, 3), checkMs: 1 });
    expect(first.incomplete).toBe(true);
    expect((await store.getIdentity(u.userId))!.pendingHead).toBe(head.jws);
    // Next refresh: only the hostile relays answer the tips, with the older version. The pending head stays.
    const withheld: IdentityFetcher = { tips: async (_u, relays) => (relays[0] === RELAYS[0] ? [] : hostileTips), chain: fetcher.chain };
    const second = await refreshIdentity(store, u.userId, withheld, { now: NOW, relays: RELAYS.slice(0, 3), checkMs: 1 }).catch((e: Error) => e);
    if (!(second instanceof Error) && second.head.ver < head.ver) expect(second.devices).not.toContain(laptop.did);
    expect((await store.getIdentity(u.userId))!.pendingHead).toBe(head.jws);
    expect((await getIdentityView(store, u.userId))!.devices).not.toContain(laptop.did);
  });

  it("the pending head narrows only until the held head reaches its ver, and denies nothing for good", () => {
    // v3 lists the laptop. Pending: a v5 (branch X) that leaves it out. The held chain then reaches ver 5 on
    // another branch (Y) that keeps it, which the chain rules allow (X isn't held): the laptop is trusted again.
    const u = makeUser("alice");
    const laptop = u.addDevice({ keyholder: true });
    u.publish({ iat: NOW - 900 });
    const v3 = u.publish({ iat: NOW - 800 });
    const v4 = u.publish({ iat: NOW - 700 });
    const all = [u.dev.did, laptop.did];
    const x5 = doc(u, { ver: 5, prev: v4.hash, devices: [u.dev.did], keyholders: [u.dev.did], iat: NOW - 600 });
    const y5 = doc(u, { ver: 5, prev: v4.hash, devices: all, keyholders: all, iat: NOW - 599 });
    const c = IdentityChain.fromStored({ iss: u.userId, versions: [u.docs[0].jws, u.docs[1].jws, v3.jws] });
    expect(c.view().devices).toContain(laptop.did);
    expect(c.notePending(x5)).toBe(true);
    expect(c.view().devices).toEqual([u.dev.did]);
    expect(c.view().keyholders).toEqual([u.dev.did]);
    // Kept across a store round trip; a lower or equal ver doesn't replace it; one at or below the head is ignored.
    const back = IdentityChain.fromStored(c.toStored());
    expect(back.view().devices).toEqual([u.dev.did]);
    expect(back.notePending(v4)).toBe(false);
    expect(back.notePending(y5)).toBe(false);
    expect(back.notePending(v3)).toBe(false);
    // v4 (ver 4 < 5) is still below it: still narrowed.
    expect(back.add(v4.jws, { now: NOW }).status).toBe("accepted");
    expect(back.view().devices).toEqual([u.dev.did]);
    // y5 reaches ver 5: the pending head is dropped, and the laptop (never revoked on held history) is trusted.
    expect(back.add(y5.jws, { now: NOW }).status).toBe("accepted");
    expect(back.view().devices).toEqual(all);
    expect(back.toStored().pendingHead).toBeUndefined();
    expect(back.toStored().denied).toBeUndefined();
  });

  it("a stored pending head is re-verified: a forged or foreign one fails to load", () => {
    const u = makeUser("alice");
    const other = makeUser("bob");
    const p = decodeJws(u.doc.jws).payload;
    expect(() => IdentityChain.fromStored({ iss: u.userId, versions: [u.doc.jws], pendingHead: sameKeyJunk(p, 0) })).toThrow();
    expect(() => IdentityChain.fromStored({ iss: u.userId, versions: [u.doc.jws], pendingHead: other.doc.jws })).toThrow(/issuer-mismatch/);
  });
});

describe("B: a junk relay can't turn a genuine gap into 'incomplete' forever, and T1 holds", () => {
  /** The store holds v1; the relays hold only v19 and v20 (v2..v18 pruned): a genuine gap at v18. */
  async function prunedHistory() {
    const u = makeUser("alice");
    const store = await storeKnowing(u);
    for (let i = 0; i < 19; i++) u.publish({ iat: NOW - 100 + i });
    const kept = u.docs.slice(-2);
    return { u, store, kept, head: kept[1] };
  }

  for (const junkCount of [64, 256]) {
    it(`a junk relay cut short on every page (${junkCount} junk documents): chain-broken, not incomplete`, async () => {
      // Each page the honest relay has one new document to check (v19, then nothing), so it is never cut
      // short; the junk relay is cut on every page. Before, any relay cut on a page that gave documents
      // marked the walk cut short, so this stayed "incomplete" on every refresh.
      const { u, store, kept, head } = await prunedHistory();
      const p = decodeJws(head.jws).payload;
      const junk = Array.from({ length: junkCount }, (_, i) => sameKeyJunk(p, i, 2 + (i % 17)));
      const fetcher: IdentityFetcher = {
        tips: async () => [head.jws],
        chain: async (uid, relays, to, n) => (relays[0] === RELAYS[0] ? walkFrom(kept)(uid, relays, to, n) : junk),
      };
      for (const checkMs of [1, 2000]) {
        await expect(refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: RELAYS.slice(0, 2), checkMs })).rejects.toThrow(/chain-broken/);
      }
      expect((await getIdentityView(store, u.userId))!.head.ver).toBe(1);
    });
  }

  it("a hostile relay replaying the genuine documents it can get (plus junk) can't either", async () => {
    const { u, store, kept, head } = await prunedHistory();
    const p = decodeJws(head.jws).payload;
    const replay = [kept[0].jws, kept[1].jws, u.docs[0].jws, ...Array.from({ length: 60 }, (_, i) => sameKeyJunk(p, i, 2 + (i % 17)))];
    const fetcher: IdentityFetcher = {
      tips: async () => [head.jws],
      chain: async (uid, relays, to, n) => (relays[0] === RELAYS[0] ? walkFrom(kept)(uid, relays, to, n) : replay),
    };
    for (const checkMs of [1, 2000]) {
      await expect(refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: RELAYS.slice(0, 2), checkMs })).rejects.toThrow(/chain-broken/);
    }
  });

  it("T1: an honest relay cut short by its own share, a withholding relay and a junk relay: incomplete until caught up, never chain-broken", async () => {
    // The honest relay holds everything but, on a slow machine, runs out of its share after a check or two
    // and is asked no more. The withholding relay answers every chain request with v16 alone, so it is never
    // cut short and supplies the lowest gap's document; the junk relay is cut on every page. A rule keyed on
    // "the relay that supplied the lowest gap was cut" would end chain-broken here, and (thrown before the
    // commit) never make progress. The honest relay's unchecked answer (and the final probe) holds the
    // missing version, so each refresh is incomplete, commits what it checked, and the next goes on.
    const u = makeUser("alice");
    for (let i = 0; i < 30; i++) u.publish({ iat: NOW - 100 + i });
    const head = u.doc;
    const p = decodeJws(head.jws).payload;
    const junk = Array.from({ length: 64 }, (_, i) => sameKeyJunk(p, i, 2 + (i % 29)));
    const v16 = u.docs.find((d) => d.ver === 16)!;
    for (const order of [
      [0, 1, 2],
      [2, 1, 0],
    ]) {
      const s = await storeWith(u.docs.slice(0, 1));
      const [honest, withholder] = [RELAYS[order[0]], RELAYS[order[1]]];
      const fetcher: IdentityFetcher = {
        tips: async () => [head.jws],
        chain: async (uid, relays, to, n) => (relays[0] === honest ? walkFrom(u.docs)(uid, relays, to, n) : relays[0] === withholder ? [v16.jws] : junk),
      };
      const { view } = await catchUp(() => refreshIdentity(s, u.userId, fetcher, { now: NOW, relays: RELAYS.slice(0, 3), checkMs: 1 }), 80);
      expect(view.head.hash).toBe(head.hash);
    }
  });

  it("T1: an honest relay out of its walk allowance (never cut short) is probed for the gap: incomplete, not chain-broken", async () => {
    // 300 versions behind: the honest relay's 4 full pages (256 documents, its whole walk allowance) don't
    // reach the held chain, and it is asked no more. It wasn't cut short on any page, so nothing it left
    // unchecked names the gap; the final hash-only probe finds the missing version in its answer. A junk
    // relay beside it changes nothing.
    const u = makeUser("alice");
    for (let i = 0; i < 300; i++) u.publish({ iat: NOW - 1000 + i });
    const head = u.doc;
    const p = decodeJws(head.jws).payload;
    const junk = Array.from({ length: 64 }, (_, i) => sameKeyJunk(p, i, 2 + i));
    for (const relays of [[RELAYS[0]], RELAYS.slice(0, 2)]) {
      const store = await storeWith(u.docs.slice(0, 1));
      const fetcher: IdentityFetcher = { tips: async () => [head.jws], chain: async (uid, rs, to, n) => (rs[0] === RELAYS[0] ? walkFrom(u.docs)(uid, rs, to, n) : junk) };
      const view = await refreshIdentity(store, u.userId, fetcher, { now: NOW, relays });
      expect(view.incomplete).toBe(true);
      expect(view.historyGap).toBe(false);
    }
  });

  it("T1: with room to check, the same relays give one complete refresh", async () => {
    const u = makeUser("alice");
    for (let i = 0; i < 30; i++) u.publish({ iat: NOW - 100 + i });
    const store = await storeWith(u.docs.slice(0, 1));
    const head = u.doc;
    const p = decodeJws(head.jws).payload;
    const junk = Array.from({ length: 64 }, (_, i) => sameKeyJunk(p, i, 2 + (i % 29)));
    const v16 = u.docs.find((d) => d.ver === 16)!;
    const fetcher: IdentityFetcher = {
      tips: async () => [head.jws],
      chain: async (uid, relays, to, n) => (relays[0] === RELAYS[2] ? walkFrom(u.docs)(uid, relays, to, n) : relays[0] === RELAYS[1] ? [v16.jws] : junk),
    };
    const view = await refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: RELAYS.slice(0, 3), checkMs: 400 });
    expect(view.incomplete).toBeUndefined();
    expect(view.head.hash).toBe(head.hash);
  });
});
