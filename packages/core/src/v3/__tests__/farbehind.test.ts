// Copyright 2026 Ix Infrastructure Inc.
//
// Chain walk, issue #67:
//  1. a client further behind than one refresh's walk catches up across refreshes (walk anchors), and the
//     anchors never enter the view; T1 holds (junk and replaying relays can't stop it);
//  2. a stall on the lowest gap tries the next gap before concluding;
//  3. a version a gap misses is checked even past the relay's share, so junk sorted ahead of it can't keep a
//     gap "cut short" forever;
//  4. a refresh names the relays that sent versions it couldn't connect (`unconnectedRelays`), each only for
//     what it sent itself: the owner's client uses this (packages/p2p) to set such a relay aside.

import { describe, expect, it } from "vitest";
import { createIdentityDoc, IdentityChain, MAX_WALK_ANCHORS, verifyIdentityDocSignature, type VerifiedIdentityDoc } from "../identitydoc.js";
import { addIdentityVersion, getIdentityView, refreshIdentity, unconnectedRelaysOf, unconnectedVersionsOf, type IdentityFetcher } from "../state.js";
import { MemoryTrustStoreV3 } from "../store.js";
import { b64uEncode } from "../../encoding.js";
import { randomBytes } from "../../crypto.js";
import { decodeJws, signJws } from "../../jws.js";
import { makeUser, NOW, type TestUser } from "./fixtures.js";

const RELAYS = [1, 2, 3, 4, 5].map((i) => `wss://r${i}.example/v3`);

/** Structurally valid, claims the user (right iss and ik), bad signature: costs a real verify. */
function sameKeyJunk(payload: Record<string, unknown>, i: number, ver = 500 + i): string {
  return signJws("p2p-identity+jws", "ik", { ...payload, ver, prev: b64uEncode(randomBytes(32)) }, randomBytes(32));
}

/** How a relay answers the §5.6 walk: from `to` back along prev, newest first, at most n; only what it holds. */
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

/** Refreshes until complete: each one incomplete or complete (never chain-broken or a jump), the head never going back. */
async function catchUp(refresh: () => Promise<{ incomplete?: boolean; head: { ver: number; hash: string }; historyGap: boolean }>, max: number) {
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

/** A linear history of `behind` versions past v1, signed with u's identity key. */
function history(u: TestUser, behind: number): void {
  for (let i = 0; i < behind; i++) u.publish({ iat: NOW - 5000 + i, certs: false });
}

function forgedChain(u: TestUser, from: number, count: number, devices: string[]): VerifiedIdentityDoc[] {
  const out: VerifiedIdentityDoc[] = [];
  let prev = b64uEncode(randomBytes(32)); // a version no relay holds: never connects
  for (let v = from; v < from + count; v++) {
    const d = verifyIdentityDocSignature(createIdentityDoc(u.ik, { ver: v, prev, name: u.name, relays: u.relays, devices, keyholders: devices, by: devices[0], iat: NOW - 5 }));
    out.push(d);
    prev = d.hash;
  }
  return out;
}

describe("#67: a client far behind catches up across refreshes", () => {
  // The issue's measurements: before, every one of these stayed incomplete at head 1 forever.
  for (const [behind, honest, junk] of [
    [300, 1, 0],
    [300, 1, 4],
    [1300, 5, 0],
    [2100, 5, 0],
  ] as const) {
    it(`${behind} behind, ${honest} honest relay(s)${junk ? ` + ${junk} junk` : ""}: each refresh makes progress until complete`, async () => {
      const u = makeUser("alice");
      history(u, behind);
      const head = u.doc;
      const p = decodeJws(head.jws).payload;
      const junkDocs = Array.from({ length: 64 }, (_, i) => sameKeyJunk(p, i, 2 + i));
      const relays = RELAYS.slice(0, honest + junk);
      const isHonest = (r: string) => relays.indexOf(r) < honest;
      const fetcher: IdentityFetcher = {
        tips: async (_u, rs) => (isHonest(rs[0]) ? [head.jws] : junkDocs.slice(0, 8)),
        chain: async (uid, rs, to, n) => (isHonest(rs[0]) ? walkFrom(u.docs)(uid, rs, to, n) : junkDocs),
      };
      const store = await storeWith(u.docs.slice(0, 1));
      const { view, refreshes } = await catchUp(() => refreshIdentity(store, u.userId, fetcher, { now: NOW, relays }), 40);
      expect(view.head.hash).toBe(head.hash);
      expect(refreshes).toBeGreaterThan(1);
      // A complete refresh leaves no anchors behind.
      expect((await store.getIdentity(u.userId))!.walkAnchors).toBeUndefined();
    }, 120_000);
  }

  it("on a slow machine (each relay's check share nearly nothing) too", async () => {
    const u = makeUser("alice");
    history(u, 300);
    const fetcher: IdentityFetcher = { tips: async () => [u.doc.jws], chain: walkFrom(u.docs) };
    const store = await storeWith(u.docs.slice(0, 1));
    const { view } = await catchUp(() => refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: [RELAYS[0]], checkMs: 20 }), 400);
    expect(view.head.hash).toBe(u.doc.hash);
  }, 120_000);

  it("anchors are only where to ask next: never in the view, re-verified when loaded, bounded", async () => {
    const u = makeUser("alice");
    const laptop = u.addDevice({ keyholder: true });
    history(u, 300);
    const fetcher: IdentityFetcher = { tips: async () => [u.doc.jws], chain: walkFrom(u.docs) };
    const store = await storeWith(u.docs.slice(0, 1));
    const before = (await getIdentityView(store, u.userId, { now: NOW, ignorePending: true }))!;
    const first = await refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: [RELAYS[0]] });
    expect(first.incomplete).toBe(true);
    const stored = (await store.getIdentity(u.userId))!;
    expect(stored.walkAnchors?.length).toBeGreaterThan(0);
    expect(stored.walkAnchors!.length).toBeLessThanOrEqual(MAX_WALK_ANCHORS);
    // Nothing they list is trusted: the held view (pending heads aside) is what it was.
    const after = (await getIdentityView(store, u.userId, { now: NOW, ignorePending: true }))!;
    expect(after.head.hash).toBe(before.head.hash);
    expect(after.devices).toEqual(before.devices);
    expect(after.devices).not.toContain(laptop.did);
    // A forged (bad signature) or foreign stored anchor fails to load, like a pending head.
    const p = decodeJws(u.doc.jws).payload;
    expect(() => IdentityChain.fromStored({ ...stored, walkAnchors: [sameKeyJunk(p, 0)] }, { now: NOW })).toThrow();
    expect(() => IdentityChain.fromStored({ ...stored, walkAnchors: [makeUser("bob").doc.jws] }, { now: NOW })).toThrow(/issuer-mismatch/);
    // At most MAX_WALK_ANCHORS kept, the lowest vers.
    const c = IdentityChain.fromStored(stored, { now: NOW });
    c.setWalkAnchors(u.docs.slice(100, 140).map((d) => verifyIdentityDocSignature(d.jws)));
    expect(c.walkAnchors().map((d) => d.ver)).toEqual(u.docs.slice(100, 100 + MAX_WALK_ANCHORS).map((d) => d.ver));
  }, 60_000);

  it("T1: a relay replaying genuine documents and junk beside the honest one can't stop it", async () => {
    const u = makeUser("alice");
    history(u, 700);
    const head = u.doc;
    const p = decodeJws(head.jws).payload;
    let k = 0;
    // Each answer: a few genuine documents from anywhere in the history (as anyone can fetch them), then junk.
    const replay = async () => {
      k++;
      const genuine = [u.docs[(k * 97) % u.docs.length], u.docs[(k * 31) % u.docs.length]].map((d) => d.jws);
      return [...genuine, ...Array.from({ length: 62 }, (_, i) => sameKeyJunk(p, i, 2 + ((i * 11 + k) % 690)))];
    };
    const fetcher: IdentityFetcher = {
      tips: async (_u, rs) => (rs[0] === RELAYS[0] ? [head.jws] : (await replay()).slice(0, 8)),
      chain: async (uid, rs, to, n) => (rs[0] === RELAYS[0] ? walkFrom(u.docs)(uid, rs, to, n) : replay()),
    };
    for (const checkMs of [2000, 200]) {
      const store = await storeWith(u.docs.slice(0, 1));
      const { view } = await catchUp(() => refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: RELAYS.slice(0, 2), checkMs }), 120);
      expect(view.head.hash).toBe(head.hash);
    }
  }, 180_000);

  it("a stored anchor nothing serves any more is dropped, and doesn't make a refresh incomplete or broken", async () => {
    const u = makeUser("alice");
    history(u, 10);
    const store = await storeWith(u.docs);
    // An anchor whose ancestors no relay holds (as after the relays pruned them).
    const [orphan] = forgedChain(u, 20, 1, [u.dev.did]);
    await store.updateIdentity(u.userId, (cur) => ({ next: { ...cur!, walkAnchors: [orphan.jws] }, result: undefined }));
    const fetcher: IdentityFetcher = { tips: async () => [u.doc.jws], chain: walkFrom(u.docs) };
    const v = await refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: [RELAYS[0]] });
    expect(v.incomplete).toBeUndefined();
    expect(v.head.hash).toBe(u.doc.hash);
    expect((await store.getIdentity(u.userId))!.walkAnchors).toBeUndefined();
  });
});

describe("#67: stalling on the lowest gap tries the next one", () => {
  it("a side branch whose history no relay holds doesn't stop the main line from filling", async () => {
    // Held v1..v5. The relays serve the main line up to v40, and a side-branch tip at v20 whose parent no
    // relay holds (pruned). The side branch's gap is the lowest; before, the walk asked only for it, found
    // nothing, stopped, and the main line's newest version didn't connect: chain-broken.
    const u = makeUser("alice");
    history(u, 39);
    const store = await storeWith(u.docs.slice(0, 5));
    const [side] = forgedChain(u, 20, 1, [u.dev.did]);
    const fetcher: IdentityFetcher = { tips: async () => [u.doc.jws, side.jws], chain: walkFrom(u.docs) };
    const v = await refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: RELAYS.slice(0, 2) });
    expect(v.incomplete).toBeUndefined();
    expect(v.head.hash).toBe(u.doc.hash);
  });
});

describe("#67: a version a gap misses is checked even past the relay's share", () => {
  it("a hostile relay holding a pruned version behind junk can't keep the gap 'cut short' on a slow machine", async () => {
    // Held v1..v10. The honest relays hold v12..v30 (v11 pruned there); a hostile relay holds v11 and answers
    // every chain request with 63 junk entries claiming older vers, then v11. On a slow machine its share runs
    // out on the junk; before, v11 was never checked and every refresh was incomplete.
    const u = makeUser("alice");
    history(u, 29);
    const store = await storeWith(u.docs.slice(0, 10));
    const v11 = u.docs[10];
    const kept = u.docs.slice(11);
    const p = decodeJws(u.doc.jws).payload;
    const junk = Array.from({ length: 63 }, (_, i) => sameKeyJunk(p, i, 1 + (i % 9)));
    const fetcher: IdentityFetcher = {
      tips: async () => [u.doc.jws],
      chain: async (uid, rs, to, n) => (rs[0] === RELAYS[0] ? walkFrom(kept)(uid, rs, to, n) : [...junk, v11.jws]),
    };
    const { view } = await catchUp(() => refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: RELAYS.slice(0, 2), checkMs: 1 }), 60);
    expect(view.head.hash).toBe(u.doc.hash);
  });
});

describe("#67: a refresh names the relays that sent versions it couldn't connect", () => {
  it("a forged chain signed with the identity key: only the relay that sent it is named, once its gap is known dead", async () => {
    const u = makeUser("alice");
    u.relays = RELAYS.slice(0, 3);
    history(u, 4);
    const mallory = makeUser("mallory").dev.did;
    const forged = forgedChain(u, 1000, 300, [mallory]);
    const top = forged[forged.length - 1];
    const p = decodeJws(u.doc.jws).payload;
    const junk = Array.from({ length: 64 }, (_, i) => sameKeyJunk(p, i));
    // R0 honest, R1 serves the forged chain, R2 junk.
    const fetcher = (serveChain: boolean): IdentityFetcher => ({
      tips: async (_u, rs) => (rs[0] === RELAYS[0] ? [u.doc.jws] : rs[0] === RELAYS[1] ? [top.jws] : junk.slice(0, 8)),
      chain: async (uid, rs, to, n) => (rs[0] === RELAYS[0] ? walkFrom(u.docs)(uid, rs, to, n) : rs[0] === RELAYS[1] ? (serveChain ? walkFrom(forged)(uid, rs, to, n) : []) : junk),
    });
    // Serving a forged chain longer than its walk allowance: incomplete (it holds what it serves), and nobody is
    // named yet (its bottom wasn't reached, so no gap is known dead: #67 review F1); the forged versions are
    // listed as sent by R1 alone.
    const v = await refreshIdentity(await storeWith(u.docs), u.userId, fetcher(true), { now: NOW, relays: u.relays });
    expect(v.incomplete).toBe(true);
    expect(v.unconnectedRelays).toEqual([]);
    expect((v.unconnectedVersions ?? []).every((x) => x.relays.length === 1 && x.relays[0] === RELAYS[1])).toBe(true);
    // Refresh after refresh, the walk goes on down the forged chain (anchors) until its bottom, which no relay
    // holds: then R1 is named.
    const store = await storeWith(u.docs);
    let named: string[] = [];
    for (let i = 0; i < 6 && named.length === 0; i++) {
      const w = await refreshIdentity(store, u.userId, fetcher(true), { now: NOW, relays: u.relays }).catch((x: Error) => x);
      named = w instanceof Error ? unconnectedRelaysOf(w) : (w.unconnectedRelays ?? []);
    }
    expect(named).toEqual([RELAYS[1]]);
    // Serving only the forged tip: chain-broken, R1 named on the error.
    const e = await refreshIdentity(await storeWith(u.docs), u.userId, fetcher(false), { now: NOW, relays: u.relays }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(Error);
    expect(String(e)).toMatch(/chain-broken/);
    expect(unconnectedRelaysOf(e)).toEqual([RELAYS[1]]);
    // Without that relay, the others confirm the held head: complete.
    const rest = await refreshIdentity(await storeWith(u.docs), u.userId, fetcher(true), { now: NOW, relays: [RELAYS[0], RELAYS[2]] });
    expect(rest.incomplete).toBeUndefined();
    expect(rest.head.hash).toBe(u.doc.hash);
  });

  it("a relay replaying the forged version it got elsewhere is named for what it sent; an honest one never is", async () => {
    const u = makeUser("alice");
    u.relays = RELAYS.slice(0, 2);
    history(u, 4);
    const forged = forgedChain(u, 1000, 3, [makeUser("mallory").dev.did]);
    const top = forged[forged.length - 1];
    const fetcher: IdentityFetcher = {
      tips: async (_u, rs) => (rs[0] === RELAYS[0] ? [u.doc.jws] : [u.doc.jws, top.jws]),
      chain: async (uid, rs, to, n) => (rs[0] === RELAYS[0] ? walkFrom(u.docs)(uid, rs, to, n) : walkFrom(forged)(uid, rs, to, n)),
    };
    const e = await refreshIdentity(await storeWith(u.docs), u.userId, fetcher, { now: NOW, relays: u.relays }).catch((x: unknown) => x);
    expect(unconnectedRelaysOf(e)).toEqual([RELAYS[1]]);
  });
});

describe("#67 review F1: a relay serving forgeries can't get an honest relay named, or use up the walk", () => {
  // The review's proof of concept. This device holds v1..v5; another of the owner's devices published v6..v10.
  // Honest A holds v10, honest-but-lagging B holds v5, and H (an identity-key holder) answers with fresh forged
  // ver-6 versions whose parents nobody holds: 8 tips, and 64 to every chain request.
  const [A, B, H] = ["wss://a.example/v3", "wss://b.example/v3", "wss://h.example/v3"];
  function setup() {
    const u = makeUser("alice");
    for (let i = 0; i < 4; i++) u.publish({ iat: NOW - 900 + i });
    const held = [...u.docs];
    for (let i = 0; i < 5; i++) u.publish({ iat: NOW - 500 + i });
    const forge = () =>
      createIdentityDoc(u.ik, { ver: 6, prev: b64uEncode(randomBytes(32)), name: u.name, relays: u.relays, devices: [u.dev.did], keyholders: [u.dev.did], by: u.dev.did, iat: NOW - 50 });
    const f: IdentityFetcher = {
      tips: async (_u, rs) => (rs[0] === A ? [u.doc.jws] : rs[0] === B ? [held[held.length - 1].jws] : Array.from({ length: 8 }, forge)),
      chain: async (uid, rs, to, n) => (rs[0] === A ? walkFrom(u.docs)(uid, rs, to, n) : rs[0] === B ? walkFrom(held)(uid, rs, to, n) : Array.from({ length: 64 }, forge)),
    };
    return { u, held, f };
  }

  it("A's genuine gap is still asked for (turns), the head reaches v10, and only H can be named", async () => {
    const { u, held, f } = setup();
    for (const checkMs of [2000, 50]) {
      const store = await storeWith(held);
      const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [A, B, H], checkMs }).catch((e: Error) => e);
      if (v instanceof Error) {
        expect(unconnectedRelaysOf(v)).not.toContain(A);
        expect(unconnectedRelaysOf(v)).not.toContain(B);
      } else {
        expect(v.head.hash).toBe(u.doc.hash);
        expect(v.unconnectedRelays ?? []).not.toContain(A);
        expect(v.unconnectedRelays ?? []).not.toContain(B);
      }
      expect((await getIdentityView(store, u.userId, { now: NOW, ignorePending: true }))!.head.hash).toBe(u.doc.hash);
    }
  });

  it("an honest relay whose genuine gap the walk didn't reach is never named, and its version is reported with its sender", async () => {
    // Without H, but the walk can't reach A's gap at all (the request cap is spent elsewhere: here, no chain
    // request is answered for it in time). A's v10 is listed as unconnected, sent by A; A isn't named.
    const { u, held } = setup();
    const hang = () => new Promise<string[]>(() => {});
    const f: IdentityFetcher = {
      tips: async (_u, rs) => (rs[0] === A ? [u.doc.jws] : [held[held.length - 1].jws]),
      chain: async (uid, rs, to, n) => (rs[0] === A ? hang() : walkFrom(held)(uid, rs, to, n)),
    };
    const store = await storeWith(held);
    const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [A, B], fetchTimeoutMs: 50 }).catch((e: Error) => e);
    const named = v instanceof Error ? unconnectedRelaysOf(v) : (v.unconnectedRelays ?? []);
    const versions = v instanceof Error ? unconnectedVersionsOf(v) : (v.unconnectedVersions ?? []);
    expect(named).toEqual([]);
    expect(versions).toContainEqual({ ver: 10, relays: [A] });
  });
});

describe("#67 re-review G1/G2: honest relays far ahead or lagging are never named; a forger can't stop progress", () => {
  const [A, B, H] = ["wss://a.example/v3", "wss://b.example/v3", "wss://h.example/v3"];

  it("G1: A far ahead (its share spent), B lagging: nobody is named, so the owner's fallback has nothing to set aside", async () => {
    for (const checkMs of [undefined, 1]) {
      const u = makeUser("alice");
      for (let i = 0; i < 4; i++) u.publish({ iat: NOW - 5000 + i, certs: false });
      const held = [...u.docs];
      for (let i = 0; i < 600; i++) u.publish({ iat: NOW - 4000 + i, certs: false });
      const f: IdentityFetcher = {
        tips: async (_u, rs) => (rs[0] === A ? [u.doc.jws] : [held[held.length - 1].jws]),
        chain: async (uid, rs, to, n) => (rs[0] === A ? walkFrom(u.docs)(uid, rs, to, n) : walkFrom(held)(uid, rs, to, n)),
      };
      const store = await storeWith(held);
      const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [A, B], checkMs });
      expect(v.incomplete).toBe(true);
      expect(v.unconnectedRelays).toEqual([]);
      // A's newest version is listed as sent by A: a fallback over B alone would be refused for it.
      expect(v.unconnectedVersions).toContainEqual({ ver: 605, relays: [A] });
    }
  }, 120_000);

  it("G2: one forging relay beside one honest relay, 300 behind: refresh after refresh makes progress until complete", async () => {
    const u = makeUser("alice");
    for (let i = 0; i < 4; i++) u.publish({ iat: NOW - 5000 + i, certs: false });
    const held = [...u.docs];
    for (let i = 0; i < 300; i++) u.publish({ iat: NOW - 4000 + i, certs: false });
    const forge = () =>
      createIdentityDoc(u.ik, { ver: 6, prev: b64uEncode(randomBytes(32)), name: u.name, relays: u.relays, devices: [u.dev.did], keyholders: [u.dev.did], by: u.dev.did, iat: NOW - 50 });
    const f: IdentityFetcher = {
      tips: async (_u, rs) => (rs[0] === A ? [u.doc.jws] : Array.from({ length: 8 }, forge)),
      chain: async (uid, rs, to, n) => (rs[0] === A ? walkFrom(u.docs)(uid, rs, to, n) : Array.from({ length: 64 }, forge)),
    };
    const store = await storeWith(held);
    let last = 0;
    for (let i = 0; i < 30; i++) {
      const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [A, H] });
      expect(v.head.ver).toBeGreaterThanOrEqual(last);
      expect(v.unconnectedRelays ?? []).not.toContain(A);
      last = v.head.ver;
      if (v.head.hash === u.doc.hash) break;
    }
    expect(last).toBe(u.doc.ver);
    void B;
  }, 120_000);
});
