// Copyright 2026 Ix Infrastructure Inc.
//
// Chain walk follow-ups (issue #35):
//  A. an incomplete refresh that commits an intermediate version (or nothing) applies what the verified
//     newest tip revokes, through the pending head, until the stored head reaches it;
//  B. a gap left at the end of the walk is "cut short" only when a relay held the missing version but it
//     wasn't checked in time: a junk relay cut short on every page no longer turns a genuine gap into
//     "incomplete" forever, and (T1) no hostile relay can turn an honest relay's slowness into chain-broken.
// Plus the review of #65: pending heads are cleared by a complete refresh, ignored when issued in the future
// or past exp, never narrow the owner's own view (M1), and follow every tip above the head (L1); over-long
// walk answers are dropped unread (L2); a spent relay's silent probe counts only if it gave the walk documents (L3).

import { describe, expect, it } from "vitest";
import { createIdentityDoc, IdentityChain, verifyIdentityDocSignature, type VerifiedIdentityDoc } from "../identitydoc.js";
import { addIdentityVersion, getIdentityView, lastRefreshed, refreshIdentity, storeSignerContext, type IdentityFetcher } from "../state.js";
import { MemoryTrustStoreV3 } from "../store.js";
import { b64uEncode } from "../../encoding.js";
import { randomBytes } from "../../crypto.js";
import { decodeJws, signJws } from "../../jws.js";
import { ctxFor, makeUser, NOW, NOW_MS, RELAY, seal, storeKnowing, type TestUser } from "./fixtures.js";
import { verifyIncomingV3 } from "../incoming.js";
import { createAcceptV3, createInviteV3, verifyFriendshipV3 } from "../friends.js";
import { recordFriendshipV3 } from "../state.js";

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

function doc(u: TestUser, f: { ver: number; prev: string | null; devices: string[]; keyholders: string[]; iat: number; ttlSec?: number; by?: string }): VerifiedIdentityDoc {
  return verifyIdentityDocSignature(
    createIdentityDoc(u.ik, {
      ver: f.ver,
      prev: f.prev,
      name: u.name,
      relays: u.relays,
      devices: f.devices,
      keyholders: f.keyholders,
      by: f.by ?? f.keyholders[0],
      certs: u.devices.filter((d) => f.devices.includes(d.did)).map((d) => d.cert),
      iat: f.iat,
      ...(f.ttlSec !== undefined ? { ttlSec: f.ttlSec } : {}),
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
    const first = await refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: [RELAY], checkMs: 1 });
    expect(first.incomplete).toBe(true);
    expect(first.head.ver).toBeGreaterThanOrEqual(2);
    expect(first.head.ver).toBeLessThan(head.ver);
    expect(first.head.devices).toContain(laptop.did); // what was committed still lists it...
    expect(first.devices).not.toContain(laptop.did); // ...but it isn't trusted
    expect(first.keyholders).not.toContain(laptop.did);
    // Later reads (the store resolvers) see the same narrowed view.
    const later = (await getIdentityView(store, u.userId, { now: NOW }))!;
    expect(later.devices).toEqual([u.dev.did]);
    expect(later.keyholders).toEqual([u.dev.did]);
    expect((await store.getIdentity(u.userId))!.pendingHeads).toEqual([head.jws]);
    // Nothing goes on the permanent denylist: the pending head is temporary.
    expect((await store.getIdentity(u.userId))!.denied).toBeUndefined();
    // Catching up: complete, the head reached, the pending head dropped, the laptop still out (chain rules).
    // (The relay the documents list, so a complete refresh counts as fresh: re-review R2.)
    const { view } = await catchUp(() => refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: [RELAY], checkMs: 1 }), 80);
    expect(view.head.hash).toBe(head.hash);
    expect(view.devices).toEqual([u.dev.did]);
    expect((await store.getIdentity(u.userId))!.pendingHeads).toBeUndefined();
    expect(await lastRefreshed(store, u.userId)).toBe(NOW);
  });

  it("an incomplete refresh that commits nothing new still applies it (the laptop was already trusted)", async () => {
    // The store holds v1 and v2 (the laptop trusted). 100 versions behind: the first page (ver 37..99)
    // doesn't reach the held chain, so nothing connects and nothing is accepted.
    const { u, laptop, head, store } = await laptopRevokedAtHead(101, 2);
    expect((await getIdentityView(store, u.userId, { now: NOW }))!.devices).toContain(laptop.did);
    const fetcher: IdentityFetcher = { tips: async () => [head.jws], chain: walkFrom(u.docs) };
    const first = await refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: [RELAYS[0]], checkMs: 1 });
    expect(first.incomplete).toBe(true);
    expect(first.head.ver).toBe(2);
    expect(first.devices).not.toContain(laptop.did);
    expect((await getIdentityView(store, u.userId, { now: NOW }))!.devices).not.toContain(laptop.did);
  });

  it("hostile relays can't plant or drop the pending head: forged high-ver tips are ignored, an older genuine one only adds to it", async () => {
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
    const planted = (await store.getIdentity(u.userId))!.pendingHeads!;
    expect(planted).toContain(head.jws); // the genuine head (and maybe the older genuine tip), never a forged one
    expect(planted.every((j) => j === head.jws || j === older.jws)).toBe(true);
    // Next (incomplete) refresh: only the hostile relays answer the tips, with the older version. It joins
    // the pending heads; the head's narrowing stays.
    const withheld: IdentityFetcher = { tips: async (_u, relays) => (relays[0] === RELAYS[0] ? [] : [older.jws]), chain: fetcher.chain };
    const second = await refreshIdentity(store, u.userId, withheld, { now: NOW, relays: RELAYS.slice(0, 3), checkMs: 1 });
    expect(second.incomplete).toBe(true);
    expect(second.devices).not.toContain(laptop.did);
    expect((await store.getIdentity(u.userId))!.pendingHeads).toContain(head.jws);
    expect((await getIdentityView(store, u.userId, { now: NOW }))!.devices).not.toContain(laptop.did);
  });

  it("pending heads narrow (every fork tip above the head) only until the held head reaches them, and deny nothing for good", () => {
    // v3 lists the laptop. Pending: a v5 (branch X) that leaves it out, then a v5 (branch Y) that keeps it:
    // the intersection still leaves it out (L1: a fork branch's revocation counts). The held chain then
    // reaches ver 5 on branch Y, which the chain rules allow (X isn't held): the laptop is trusted again.
    const u = makeUser("alice");
    const laptop = u.addDevice({ keyholder: true });
    u.publish({ iat: NOW - 900 });
    const v3 = u.publish({ iat: NOW - 800 });
    const v4 = u.publish({ iat: NOW - 700 });
    const all = [u.dev.did, laptop.did];
    const x5 = doc(u, { ver: 5, prev: v4.hash, devices: [u.dev.did], keyholders: [u.dev.did], iat: NOW - 600 });
    const y5 = doc(u, { ver: 5, prev: v4.hash, devices: all, keyholders: all, iat: NOW - 599 });
    const at = { now: NOW };
    const c = IdentityChain.fromStored({ iss: u.userId, versions: [u.docs[0].jws, u.docs[1].jws, v3.jws] }, at);
    expect(c.view().devices).toContain(laptop.did);
    expect(c.notePending([x5], at)).toBe(true);
    expect(c.view().devices).toEqual([u.dev.did]);
    expect(c.view().keyholders).toEqual([u.dev.did]);
    // Kept across a store round trip; the same one again changes nothing; one at or below the head is ignored.
    const back = IdentityChain.fromStored(c.toStored(), at);
    expect(back.view().devices).toEqual([u.dev.did]);
    expect(back.notePending([x5], at)).toBe(false);
    expect(back.notePending([v3], at)).toBe(false);
    // Another tip above the head that keeps the laptop (y5) can't lift x5's narrowing: the laptop stays out
    // (v4, below both and leaving nothing more out, is redundant and not kept; R3).
    back.notePending([v4, y5], at);
    expect(back.toStored().pendingHeads).toContain(x5.jws);
    expect(back.toStored().pendingHeads).not.toContain(v4.jws);
    expect(back.view().devices).toEqual([u.dev.did]);
    // v4 (ver 4 < 5) is still below it: still narrowed.
    expect(back.add(v4.jws, { now: NOW }).status).toBe("accepted");
    expect(back.view().devices).toEqual([u.dev.did]);
    // y5 reaches ver 5: the pending head is dropped, and the laptop (never revoked on held history) is trusted.
    expect(back.add(y5.jws, { now: NOW }).status).toBe("accepted");
    expect(back.view().devices).toEqual(all);
    expect(back.toStored().pendingHeads).toBeUndefined();
    expect(back.toStored().denied).toBeUndefined();
    // clearPending (a complete refresh) drops them all at once.
    const again = IdentityChain.fromStored({ iss: u.userId, versions: [u.docs[0].jws, u.docs[1].jws, v3.jws] }, at);
    again.notePending([x5], at);
    expect(again.clearPending()).toBe(true);
    expect(again.view().devices).toEqual(all);
  });

  it("a stored pending head is re-verified: a forged or foreign one fails to load", () => {
    const u = makeUser("alice");
    const other = makeUser("bob");
    const p = decodeJws(u.doc.jws).payload;
    expect(() => IdentityChain.fromStored({ iss: u.userId, versions: [u.doc.jws], pendingHeads: [sameKeyJunk(p, 0)] }, { now: NOW })).toThrow();
    expect(() => IdentityChain.fromStored({ iss: u.userId, versions: [u.doc.jws], pendingHeads: [other.doc.jws] }, { now: NOW })).toThrow(/issuer-mismatch/);
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
      expect((await getIdentityView(store, u.userId, { now: NOW }))!.head.ver).toBe(1);
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

describe("review of #65: pending heads can't narrow for good; walk answers", () => {
  /** v1..v5 held (the laptop trusted); an identity-key holder forges ~300 versions near MAX_SAFE_INTEGER listing only mallory. */
  async function forgedFarFuture(iat: number) {
    const u = makeUser("alice");
    const laptop = u.addDevice({ keyholder: true });
    const R = RELAYS.slice(0, 2);
    u.relays = R; // the versions held list both relays
    for (let i = 0; i < 4; i++) u.publish({ iat: NOW - 100 + i });
    const store = await storeWith(u.docs);
    const mallory = makeUser("mallory").dev.did;
    const BIG = Number.MAX_SAFE_INTEGER - 1;
    const forged: VerifiedIdentityDoc[] = [];
    let prev = b64uEncode(randomBytes(32));
    for (let v = BIG - 299; v <= BIG; v++) {
      const d = verifyIdentityDocSignature(createIdentityDoc(u.ik, { ver: v, prev, name: u.name, relays: u.relays, devices: [mallory], keyholders: [mallory], by: mallory, iat }));
      forged.push(d);
      prev = d.hash;
    }
    const top = forged[forged.length - 1];
    const hostile: IdentityFetcher = {
      tips: async (_u, rs) => (rs[0] === R[0] ? [u.doc.jws] : [top.jws]),
      chain: async (uid, rs, to, n) => (rs[0] === R[0] ? walkFrom(u.docs)(uid, rs, to, n) : walkFrom(forged)(uid, rs, to, n)),
    };
    const honest: IdentityFetcher = { tips: async () => [u.doc.jws], chain: walkFrom(u.docs) };
    return { u, laptop, store, R, hostile, honest, top };
  }

  it("M1: a forged far-future pending head issued in the future is ignored", async () => {
    const { u, laptop, store, R, hostile } = await forgedFarFuture(NOW + 10 * 86400);
    const v = await refreshIdentity(store, u.userId, hostile, { now: NOW, relays: R }).catch((e: Error) => e);
    if (!(v instanceof Error)) expect(v.devices).toEqual([u.dev.did, laptop.did]);
    expect((await store.getIdentity(u.userId))!.pendingHeads).toBeUndefined();
    expect((await getIdentityView(store, u.userId, { now: NOW }))!.devices).toEqual([u.dev.did, laptop.did]);
  });

  it("M1: an identity-key-signed forged head narrows only until the next complete refresh, and never the owner's own view", async () => {
    // A current iat: the identity key's holder (a thief) can sign this, and the client can't tell it from the
    // owner's own version, so while the refresh is incomplete it narrows trust in the owner's devices...
    const { u, laptop, store, R, hostile, honest, top } = await forgedFarFuture(NOW - 5);
    const first = await refreshIdentity(store, u.userId, hostile, { now: NOW, relays: R });
    expect(first.incomplete).toBe(true);
    expect(first.devices).toEqual([]);
    expect((await store.getIdentity(u.userId))!.pendingHeads).toEqual([top.jws]);
    // ...but never on the owner's own publishing path (ignorePending), so the owner can still edit or rotate.
    expect((await getIdentityView(store, u.userId, { now: NOW, ignorePending: true }))!.devices).toEqual([u.dev.did, laptop.did]);
    // Only one of the two listed relays answering honestly (a minority) isn't enough to clear it (R2)...
    const second = await refreshIdentity(store, u.userId, honest, { now: NOW, relays: [R[0]] });
    expect(second.incomplete).toBeUndefined();
    expect(second.devices).toEqual([]);
    // ...both answering honestly is: the next complete refresh answered by a majority clears it.
    const third = await refreshIdentity(store, u.userId, honest, { now: NOW, relays: R });
    expect(third.incomplete).toBeUndefined();
    expect(third.devices).toEqual([u.dev.did, laptop.did]);
    expect((await store.getIdentity(u.userId))!.pendingHeads).toBeUndefined();
  });

  it("M1: a pending head past its exp is ignored, when noted and when read later", () => {
    const u = makeUser("alice");
    const laptop = u.addDevice({ keyholder: true });
    const v2 = u.publish({ iat: NOW - 9000 });
    const all = [u.dev.did, laptop.did];
    const c = IdentityChain.fromStored({ iss: u.userId, versions: [u.docs[0].jws, v2.jws] }, { now: NOW });
    const lapsed = doc(u, { ver: 9, prev: v2.hash, devices: [u.dev.did], keyholders: [u.dev.did], iat: NOW - 7200, ttlSec: 3600 });
    expect(c.notePending([lapsed], { now: NOW })).toBe(false);
    expect(c.view().devices).toEqual(all);
    // Usable when noted, lapsed by the time it is read: ignored.
    const short = doc(u, { ver: 9, prev: v2.hash, devices: [u.dev.did], keyholders: [u.dev.did], iat: NOW - 60, ttlSec: 3600 });
    expect(c.notePending([short], { now: NOW })).toBe(true);
    expect(c.view().devices).toEqual([u.dev.did]);
    const stored = c.toStored();
    expect(IdentityChain.fromStored(stored, { now: NOW }).view().devices).toEqual([u.dev.did]);
    expect(IdentityChain.fromStored(stored, { now: short.exp }).view().devices).toEqual(all);
  });

  it("L2: a chain answer longer than the request asks for is dropped before it is decoded", async () => {
    const u = makeUser("alice");
    const store = await storeKnowing(u);
    for (let i = 0; i < 19; i++) u.publish({ iat: NOW - 100 + i });
    const p = decodeJws(u.doc.jws).payload;
    const long = Array.from({ length: 65 }, (_, i) => sameKeyJunk(p, i, 2 + (i % 17)));
    let reads = 0;
    const counted = new Proxy(long, {
      get(t, k, r) {
        if (typeof k === "string" && /^\d+$/.test(k)) reads++;
        return Reflect.get(t, k, r);
      },
    });
    const fetcher: IdentityFetcher = {
      tips: async () => [u.doc.jws],
      chain: async (uid, rs, to, n) => (rs[0] === RELAYS[0] ? walkFrom(u.docs)(uid, rs, to, n) : counted),
    };
    const view = await refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: RELAYS.slice(0, 2) });
    expect(view.head.hash).toBe(u.doc.hash);
    expect(reads).toBe(0);
  });

  it("L3: a spent relay that gave the walk documents and doesn't answer the probe makes the gap 'cut short'; a junk relay's silence doesn't", async () => {
    // 300 behind: the honest relay's allowance is spent after 4 pages (no connection yet). It then doesn't
    // answer the probe (a timeout): it can't be ruled out, so incomplete, not chain-broken.
    const u = makeUser("alice");
    for (let i = 0; i < 300; i++) u.publish({ iat: NOW - 1000 + i });
    let pages = 0;
    const hang = () => new Promise<string[]>(() => {});
    const silentProbe: IdentityFetcher = { tips: async () => [u.doc.jws], chain: async (uid, rs, to, n) => (++pages > 4 ? hang() : walkFrom(u.docs)(uid, rs, to, n)) };
    const view = await refreshIdentity(await storeWith(u.docs.slice(0, 1)), u.userId, silentProbe, { now: NOW, relays: [RELAYS[0]], fetchTimeoutMs: 50 });
    expect(view.incomplete).toBe(true);
    // A genuine gap and a junk relay that, once spent, goes silent: it never gave the walk a valid
    // document, so its silence counts for nothing: chain-broken.
    const g = makeUser("bob");
    const gStore = await storeKnowing(g);
    for (let i = 0; i < 19; i++) g.publish({ iat: NOW - 100 + i });
    const kept = g.docs.slice(-2);
    const p = decodeJws(g.doc.jws).payload;
    const junk = Array.from({ length: 64 }, (_, i) => sameKeyJunk(p, i, 2 + (i % 17)));
    let junkPages = 0;
    const fetcher: IdentityFetcher = {
      tips: async () => [g.doc.jws],
      chain: async (uid, rs, to, n) => (rs[0] === RELAYS[0] ? walkFrom(kept)(uid, rs, to, n) : ++junkPages > 1 ? hang() : junk),
    };
    await expect(refreshIdentity(gStore, g.userId, fetcher, { now: NOW, relays: RELAYS.slice(0, 2), checkMs: 1, fetchTimeoutMs: 50 })).rejects.toThrow(/chain-broken/);
  });

  it("re-review N2: a complete refresh answered only by a stale minority keeps the narrowing; a majority clears it", async () => {
    // A slow machine: v1 held, the genuine v60 revokes the laptop; the first refresh is incomplete (pending v60).
    const u = makeUser("alice");
    const laptop = u.addDevice({ keyholder: true });
    u.relays = RELAYS.slice(0, 2); // v2 on list both relays
    for (let i = 2; i < 60; i++) u.publish({ iat: NOW - 1000 + i });
    const head = u.publish({ devices: [u.dev.did], keyholders: [u.dev.did], iat: NOW - 10 });
    const store = await storeWith(u.docs.slice(0, 1));
    const R = RELAYS.slice(0, 2);
    const both: IdentityFetcher = { tips: async () => [head.jws], chain: walkFrom(u.docs) };
    const first = await refreshIdentity(store, u.userId, both, { now: NOW, relays: R, checkMs: 1 });
    expect(first.incomplete).toBe(true);
    const held = first.head;
    expect(held.devices).toContain(laptop.did);
    expect(first.devices).not.toContain(laptop.did);
    // Then the honest relay times out and the other answers the stale head the store already holds:
    // complete, but by a minority (1 of 2), so the pending head stays.
    const hang = () => new Promise<string[]>(() => {});
    const stale: IdentityFetcher = { tips: async (_u, rs) => (rs[0] === R[0] ? hang() : [held.jws]), chain: async () => [] };
    const second = await refreshIdentity(store, u.userId, stale, { now: NOW, relays: R, fetchTimeoutMs: 50 });
    expect(second.incomplete).toBeUndefined();
    expect(second.answeredRelays).toEqual([R[1]]);
    expect(second.devices).not.toContain(laptop.did);
    expect((await store.getIdentity(u.userId))!.pendingHeads).toEqual([head.jws]);
    // Both relays answering (a majority, even with the same stale head) clears it, as freshness does.
    const majority: IdentityFetcher = { tips: async () => [held.jws], chain: async () => [] };
    const third = await refreshIdentity(store, u.userId, majority, { now: NOW, relays: R });
    expect(third.incomplete).toBeUndefined();
    expect((await store.getIdentity(u.userId))!.pendingHeads).toBeUndefined();
  });

  it("re-review N3: a long run of one branch can't push another branch's revoking tip out", () => {
    // Held v1..v4 (the laptop trusted). Candidates: the main branch's v5..v13 (9, each naming the last) and a
    // fork x5 off v4 that drops the laptop. By ver alone, the 8 kept are v6..v13 and x5 is pushed out; the
    // tips (v13, x5) come first now, so the laptop stays out.
    const u = makeUser("alice");
    const laptop = u.addDevice({ keyholder: true });
    for (let i = 0; i < 3; i++) u.publish({ iat: NOW - 900 + i });
    const v4 = u.doc;
    const at = { now: NOW };
    const c = IdentityChain.fromStored({ iss: u.userId, versions: u.docs.map((d) => d.jws) }, at);
    expect(c.view().devices).toContain(laptop.did);
    const x5 = doc(u, { ver: 5, prev: v4.hash, devices: [u.dev.did], keyholders: [u.dev.did], iat: NOW - 500 });
    const run: VerifiedIdentityDoc[] = [];
    for (let i = 0; i < 9; i++) run.push(u.publish({ iat: NOW - 400 + i }));
    expect(c.notePending([x5, ...run], at)).toBe(true);
    // Kept: the highest (always) and x5 (it leaves the laptop out); the rest of the run is redundant.
    expect(c.toStored().pendingHeads).toEqual([run[8].jws, x5.jws]);
    expect(c.view().devices).toEqual([u.dev.did]);
  });

  it("re-review N1: the signer context resolves this device's own identity without pending heads, others' with them", async () => {
    const { u, laptop, store, R, hostile } = await forgedFarFuture(NOW - 5);
    await refreshIdentity(store, u.userId, hostile, { now: NOW, relays: R });
    const ctx = storeSignerContext(store, { now: NOW, own: u.userId });
    expect((await ctx.resolveIdentity(u.userId))!.devices).toEqual([u.dev.did, laptop.did]);
    expect((await storeSignerContext(store, { now: NOW }).resolveIdentity(u.userId))!.devices).toEqual([]);
  });

  it("re-review R1: the envelope gate reads our own identity without pending heads; a friend's stays narrowed", async () => {
    // Bob's phone (this device) and laptop are both listed. A pending head signed with Bob's identity key
    // (far ahead, listing only the phone) sits in the phone's store, and one of Alice's (listing only her
    // first device) too. The laptop's sync to the phone is accepted (it would be rejected in core before
    // any client check otherwise); Alice's second device stays out.
    const bob = makeUser("bob");
    const laptop = bob.addDevice({ keyholder: true });
    bob.publish({ iat: NOW - 500 });
    const alice = makeUser("alice");
    const alice2 = alice.addDevice();
    alice.publish({ iat: NOW - 500 });
    const store = await storeKnowing(bob, alice);
    const invite = createInviteV3(bob.signer(), { aud: alice.userId, iat: NOW - 400 });
    await recordFriendshipV3(store, await verifyFriendshipV3({ invite, accept: createAcceptV3(alice.signer(), invite, { iat: NOW - 300 }) }, ctxFor(store)));
    for (const [u, only] of [
      [bob, bob.dev.did],
      [alice, alice.dev.did],
    ] as const) {
      const far = doc(u, { ver: 999, prev: b64uEncode(randomBytes(32)), devices: [only], keyholders: [only], iat: NOW - 5 });
      await store.updateIdentity(u.userId, (cur) => ({ next: { ...cur!, pendingHeads: [far.jws] }, result: undefined }));
    }
    const receive = (env: string) =>
      verifyIncomingV3(env, { self: { userId: bob.userId, did: bob.dev.did, agreementSecretKey: bob.dev.agreementSecretKey, cert: bob.dev.cert }, store, nowMs: NOW_MS });
    const sync = await receive(seal(bob, bob, "sync", { note: "hi" }, { fromDev: laptop }));
    expect(sync.ok ? sync.rule : sync.reason).toBe("self-sync");
    // Alice's devices: her listed one gets past the device check (and is refused later, as any sync from
    // someone else is); the one her pending head left out is refused at the device check.
    const fromFirst = await receive(seal(alice, bob, "sync", { note: "x" }));
    expect(fromFirst.ok ? fromFirst.rule : fromFirst.reason).toBe("not-participant");
    const fromSecond = await receive(seal(alice, bob, "sync", { note: "x" }, { fromDev: alice2 }));
    expect(fromSecond.ok ? fromSecond.rule : fromSecond.reason).toBe("device-not-listed");
  });

  it("re-review R2: relays added from an unverified hint can't make up the majority that clears pending heads or marks freshness", async () => {
    // Alice's versions list two relays. On a slow machine the first refresh is incomplete (pending v60). Then
    // a caller adds 3 relays from an unverified hint (a circle link's bundled document): Alice's own two are
    // silent, the 3 answer the stale head. 3 of 5 asked, but 0 of the 2 her versions list: not a majority.
    const u = makeUser("alice");
    const laptop = u.addDevice({ keyholder: true });
    const own = RELAYS.slice(0, 2);
    const hinted = RELAYS.slice(2, 5);
    u.relays = own;
    for (let i = 2; i < 60; i++) u.publish({ iat: NOW - 1000 + i });
    const head = u.publish({ devices: [u.dev.did], keyholders: [u.dev.did], iat: NOW - 10 });
    const store = await storeWith(u.docs.slice(0, 2));
    const first = await refreshIdentity(store, u.userId, { tips: async () => [head.jws], chain: walkFrom(u.docs) }, { now: NOW, relays: own, checkMs: 1 });
    expect(first.incomplete).toBe(true);
    const held = first.head;
    const hang = () => new Promise<string[]>(() => {});
    const fetcher: IdentityFetcher = { tips: async (_u, rs) => (own.includes(rs[0]) ? hang() : [held.jws]), chain: async () => [] };
    const second = await refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: [...own, ...hinted], fetchTimeoutMs: 50 });
    expect(second.incomplete).toBeUndefined();
    expect(second.answeredRelays.sort()).toEqual([...hinted].sort());
    expect(second.devices).not.toContain(laptop.did);
    expect((await store.getIdentity(u.userId))!.pendingHeads).toEqual([head.jws]);
    expect(await lastRefreshed(store, u.userId)).toBeUndefined();
  });

  it("re-review R3: 8 genuine non-consecutive higher versions can't push out a revoking fork tip", () => {
    // Held v1..v13 (the laptop trusted). A fork x14 off v13 drops the laptop. The main line goes on to v44,
    // keeping it; a relay sends v30, v32, ..., v44 (8 versions, none naming another): all "unparented".
    const u = makeUser("alice");
    const laptop = u.addDevice({ keyholder: true });
    for (let i = 2; i <= 13; i++) u.publish({ iat: NOW - 2000 + i });
    const v13 = u.doc;
    const held = [...u.docs];
    for (let i = 14; i <= 44; i++) u.publish({ iat: NOW - 1000 + i });
    const x14 = doc(u, { ver: 14, prev: v13.hash, devices: [u.dev.did], keyholders: [u.dev.did], iat: NOW - 900 });
    const spread = u.docs.filter((d) => d.ver >= 30 && d.ver % 2 === 0);
    expect(spread).toHaveLength(8);
    const at = { now: NOW };
    // In one refresh, and across two (the fork tip first, the spread later).
    for (const batches of [[[x14, ...spread]], [[x14], spread]]) {
      const c = IdentityChain.fromStored({ iss: u.userId, versions: held.map((d) => d.jws) }, at);
      expect(c.view().devices).toContain(laptop.did);
      for (const b of batches) c.notePending(b, at);
      expect(c.toStored().pendingHeads).toContain(x14.jws);
      expect(c.view().devices).toEqual([u.dev.did]);
      expect(c.view().keyholders).toEqual([u.dev.did]);
    }
  });

  it("re-review E1: a higher head that expires sooner doesn't stand in for a lower one that lasts longer", () => {
    // Held v1..v3 (the laptop trusted). L: a disconnected fork tip (ver 5) dropping the laptop, issued 100 s
    // ago. H: a higher version (ver 9) also leaving it out, but issued 29 days ago, so it expires in a day.
    // Both are kept; once H expires, L still keeps the laptop out.
    const DAY = 86400;
    const u = makeUser("alice");
    const laptop = u.addDevice({ keyholder: true });
    u.publish({ iat: NOW - 40 * DAY });
    const v3 = u.publish({ iat: NOW - 39 * DAY });
    const only = [u.dev.did];
    const L = doc(u, { ver: 5, prev: b64uEncode(randomBytes(32)), devices: only, keyholders: only, iat: NOW - 100 });
    const H = doc(u, { ver: 9, prev: b64uEncode(randomBytes(32)), devices: only, keyholders: only, iat: NOW - 29 * DAY });
    expect(H.exp).toBeLessThan(L.exp);
    const c = IdentityChain.fromStored({ iss: u.userId, versions: [u.docs[0].jws, u.docs[1].jws, v3.jws] }, { now: NOW });
    expect(c.view().devices).toContain(laptop.did);
    expect(c.notePending([L, H], { now: NOW })).toBe(true);
    expect(c.toStored().pendingHeads).toEqual([H.jws, L.jws]);
    const later = NOW + 2 * DAY; // H past its exp, L not
    expect(later).toBeGreaterThanOrEqual(H.exp);
    expect(IdentityChain.fromStored(c.toStored(), { now: later }).view().devices).toEqual(only);
  });
});
