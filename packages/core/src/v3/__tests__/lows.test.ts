// Copyright 2026 Ix Infrastructure Inc.
//
// Regression tests for the pre-release re-review lows: a freshness quorum, the
// chain walk's own allowance (walking from the lowest gap), and hash-first
// admission.

import { describe, expect, it } from "vitest";
import { verifyIdentityDocSignature } from "../identitydoc.js";
import { generateIdentityKey } from "../identity.js";
import { lastRefreshed, refreshIdentity, type IdentityFetcher } from "../state.js";
import { b64uEncode } from "../../encoding.js";
import { randomBytes } from "../../crypto.js";
import { decodeJws, signJws } from "../../jws.js";
import { makeUser, NOW, storeKnowing } from "./fixtures.js";

const R = [1, 2, 3, 4, 5].map((i) => `wss://q${i}.example/v3`);

describe("freshness needs a majority of the listed relays", () => {
  it("one of two relays unreachable: the (stale) answer isn't recorded as fresh", async () => {
    const u = makeUser("alice");
    const store = await storeKnowing(u);
    const fetcher: IdentityFetcher = async (_u, relays) => {
      if (relays[0] === R[0]) await new Promise(() => {}); // the honest relay is unreachable
      return [u.doc.jws]; // the other answers with what the client already has
    };
    const view = await refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: R.slice(0, 2), fetchTimeoutMs: 50 });
    expect(view.answeredRelays).toEqual([R[1]]);
    expect(await lastRefreshed(store, u.userId)).toBeUndefined();
    // Two of three answering is a majority.
    const v3 = await refreshIdentity(store, u.userId, fetcher, { now: NOW + 1, relays: R.slice(0, 3), fetchTimeoutMs: 50 });
    expect(v3.answeredRelays.sort()).toEqual([R[1], R[2]].sort());
    expect(await lastRefreshed(store, u.userId)).toBe(NOW + 1);
  });
});

describe("the chain walk has its own allowance and starts from the lowest gap", () => {
  async function behind() {
    const u = makeUser("alice");
    for (let i = 0; i < 9; i++) u.publish({ iat: NOW - 2000 + i }); // v1..v10
    const store = await storeKnowing();
    await store.putIdentity({ iss: u.userId, versions: u.docs.map((d) => d.jws) });
    for (let i = 0; i < 20; i++) u.publish({ iat: NOW - 1000 + i }); // v11..v30, unknown to the client
    return { u, store };
  }

  it("a hostile majority using up the tips allowance can't starve the walk", async () => {
    const { u, store } = await behind();
    const head = u.doc;
    const junkFor = (p: Record<string, unknown>) =>
      Array.from({ length: 8 }, (_, i) => signJws("p2p-identity+jws", "ik", { ...p, ver: 500 + i, prev: b64uEncode(randomBytes(32)) }, randomBytes(32)));
    const junk = junkFor(decodeJws(head.jws).payload);
    const honest = new Set([R[3], R[4]]);
    const byVer = new Map(u.docs.map((d) => [d.hash, d]));
    const fetcher: IdentityFetcher = {
      tips: async (_u, relays) => (honest.has(relays[0]) ? [head.jws] : junk),
      chain: async (_u, relays, to) => {
        if (!honest.has(relays[0])) return junk;
        const out: string[] = [];
        for (let d = byVer.get(to); d && out.length < 64; d = d.prev ? byVer.get(d.prev) : undefined) out.push(d.jws);
        return out;
      },
    };
    // maxDocs 40: the tips phase (8 per relay × 5) uses it all; before, the walk then had nothing left.
    const view = await refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: R, maxDocs: 40 });
    expect(view.head.hash).toBe(head.hash);
    expect(view.incomplete).toBeUndefined();
  });

  it("walks from the lowest gap first", async () => {
    const { u, store } = await behind();
    const v25 = u.docs[24];
    const v30 = u.doc;
    const byHash = new Map(u.docs.map((d) => [d.hash, d]));
    const asked: number[] = [];
    const fetcher: IdentityFetcher = {
      tips: async () => [v30.jws, v25.jws],
      chain: async (_u, _r, to) => {
        const start = byHash.get(to)!;
        asked.push(start.ver);
        const out: string[] = [];
        for (let d: typeof start | undefined = start; d && d.ver > 10 && out.length < 64; d = d.prev ? byHash.get(d.prev) : undefined) out.push(d.jws);
        return out;
      },
    };
    const view = await refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: [R[0]] });
    expect(view.head.hash).toBe(v30.hash);
    expect(asked[0]).toBe(24); // the gap below v25, not the one below v30
  });
});

describe("hash first: iss == H(ik) before any curve work", () => {
  it("a document whose iss doesn't match its (even small-order) ik fails on the hash", () => {
    const u = makeUser("alice");
    const p = decodeJws(u.doc.jws).payload;
    const smallOrder = new Uint8Array(32);
    smallOrder[0] = 1;
    const junk = signJws("p2p-identity+jws", "ik", { ...p, ik: b64uEncode(smallOrder) }, randomBytes(32));
    expect(() => verifyIdentityDocSignature(junk)).toThrow(/issuer-mismatch/);
    const stranger = generateIdentityKey();
    const foreign = signJws("p2p-identity+jws", "ik", { ...p, ik: b64uEncode(stranger.publicKey) }, stranger.secretKey);
    expect(() => verifyIdentityDocSignature(foreign)).toThrow(/issuer-mismatch/);
  });

  it("admission drops iss/ik mismatches without spending quota", async () => {
    const u = makeUser("alice");
    const store = await storeKnowing(); // no held ik: only the hash check can catch it
    const head = u.publish({ iat: NOW - 10 });
    const p = decodeJws(head.jws).payload;
    const stranger = generateIdentityKey();
    const junk = Array.from({ length: 50 }, (_, i) => signJws("p2p-identity+jws", "ik", { ...p, ver: 900 + i, ik: b64uEncode(stranger.publicKey) }, stranger.secretKey));
    const view = await refreshIdentity(store, u.userId, async () => [...junk, ...u.docs.map((d) => d.jws)], { now: NOW, relays: [R[0]], maxDocs: 2 });
    expect(view.head.hash).toBe(head.hash);
  });
});
