// Copyright 2026 Ix Infrastructure Inc.
//
// Regression tests for the pre-release re-review: T1 (each relay gets its own share
// of the document cap; an incomplete refresh isn't a refresh) and T2
// (foreign-key junk is filtered on the decoded payload, before curve work).

import { describe, expect, it } from "vitest";
import { generateIdentityKey } from "../identity.js";
import { lastRefreshed, refreshIdentity, type IdentityFetcher } from "../state.js";
import { b64uEncode } from "../../encoding.js";
import { randomBytes } from "../../crypto.js";
import { decodeJws, signJws } from "../../jws.js";
import { makeUser, NOW, storeKnowing } from "./fixtures.js";

const RELAYS = [1, 2, 3, 4, 5].map((i) => `wss://r${i}.example/v3`);

/** Structurally valid, claims the user (right iss and ik), high ver, bad signature: costs a real verify. */
function sameKeyJunk(payload: Record<string, unknown>, i: number): string {
  return signJws("p2p-identity+jws", "ik", { ...payload, ver: 500 + i, prev: b64uEncode(randomBytes(32)) }, randomBytes(32));
}

async function behindByOne() {
  const u = makeUser("alice");
  const store = await storeKnowing(u);
  const head = u.publish({ iat: NOW - 10 });
  return { u, store, head };
}

describe("T1: hostile relays can't starve an honest one", () => {
  it("4 relays × 256 junk documents and an honest 5th: complete, current head", async () => {
    const { u, store, head } = await behindByOne();
    const p = decodeJws(head.jws).payload;
    const junk = Array.from({ length: 256 }, (_, i) => sameKeyJunk(p, i));
    const fetcher: IdentityFetcher = async (_u, relays) => (relays[0] === RELAYS[4] ? [head.jws] : junk);
    const view = await refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: RELAYS });
    expect(view.incomplete).toBeUndefined();
    expect(view.head.hash).toBe(head.hash);
    expect(await lastRefreshed(store, u.userId)).toBe(NOW);
  });

  it("on slower hardware too: the junk relays use up only their own share of the checking time", async () => {
    // A smaller CPU budget stands in for a slower machine (a Raspberry Pi, a loaded CI runner): with one
    // shared budget, the 4 junk relays spent it all before the honest 5th was checked, and the refresh
    // stayed incomplete (the honest head never adopted). Each relay's share is its own now, and every
    // relay gets at least one check, however slow the machine. Deterministic: no timing is asserted.
    for (const budgetMs of [400, 50, 1]) {
      const { u, store, head } = await behindByOne();
      const p = decodeJws(head.jws).payload;
      const junk = Array.from({ length: 256 }, (_, i) => sameKeyJunk(p, i));
      // The honest relay last (the order a hostile majority would want), and first.
      for (const honest of [4, 0]) {
        const fetcher: IdentityFetcher = async (_u, relays) => (relays[0] === RELAYS[honest] ? [head.jws] : junk);
        const view = await refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: RELAYS, budgetMs });
        expect([budgetMs, honest, view.incomplete]).toEqual([budgetMs, honest, undefined]);
        expect(view.head.hash).toBe(head.hash);
      }
    }
  });

  it("only junk answers, cut short by their share of the time: incomplete, not a refresh", async () => {
    const { u, store, head } = await behindByOne();
    const p = decodeJws(head.jws).payload;
    const junk = Array.from({ length: 256 }, (_, i) => sameKeyJunk(p, i));
    const view = await refreshIdentity(store, u.userId, async () => junk, { now: NOW, relays: RELAYS.slice(0, 2), budgetMs: 1 }).catch((e: Error) => e);
    // Either nothing usable came back (identity-unknown), or what came back is incomplete: never a fresh refresh.
    if (!(view instanceof Error)) expect(view.incomplete).toBe(true);
    expect(await lastRefreshed(store, u.userId)).toBeUndefined();
    void head;
  });

  it("the chain walk too: the junk relays' pages use up only their own share of the time", async () => {
    // A client 19 versions behind (more than the 8 tips a relay gives) fills the gap with the chain walk.
    // The 4 hostile relays answer every chain request with 256 junk documents; the honest one with the
    // real history. Each relay's share of the walk's checking time is its own: complete, current head,
    // on any checking budget (a smaller one stands in for slower hardware), the honest relay first or last.
    // (The chain work, placing the 19 real versions, keeps its own budget: checkMs bounds only the checks.)
    for (const checkMs of [400, 50, 1]) {
      for (const honest of [4, 0]) {
        const u = makeUser("alice");
        const store = await storeKnowing(u);
        for (let i = 0; i < 19; i++) u.publish({ iat: NOW - 100 + i });
        const head = u.docs[u.docs.length - 1];
        const p = decodeJws(head.jws).payload;
        const junk = Array.from({ length: 256 }, (_, i) => sameKeyJunk(p, i));
        const fetcher: IdentityFetcher = {
          tips: async () => [head.jws],
          // As a relay walks (§5.6): from `to` back, newest first, at most n.
          chain: async (_u, relays, to, n) => {
            if (relays[0] !== RELAYS[honest]) return junk;
            const at = u.docs.findIndex((d) => d.hash === to);
            return at < 0 ? [] : u.docs.slice(Math.max(0, at - n + 1), at + 1).reverse().map((d) => d.jws);
          },
        };
        const view = await refreshIdentity(store, u.userId, fetcher, { now: NOW, relays: RELAYS, checkMs });
        expect([checkMs, honest, view.incomplete]).toEqual([checkMs, honest, undefined]);
        expect(view.head.hash).toBe(head.hash);
      }
    }
  });

  it("an incomplete refresh doesn't count as a refresh", async () => {
    const { u, store, head } = await behindByOne();
    const p = decodeJws(head.jws).payload;
    const junk = Array.from({ length: 50 }, (_, i) => sameKeyJunk(p, i));
    // Every relay is cut short by its quota: incomplete.
    const view = await refreshIdentity(store, u.userId, async () => [...junk, head.jws], { now: NOW, relays: RELAYS.slice(0, 2), maxDocs: 20 });
    expect(view.incomplete).toBe(true);
    expect(await lastRefreshed(store, u.userId)).toBeUndefined();
    const ok = await refreshIdentity(store, u.userId, async () => [head.jws], { now: NOW + 5, relays: RELAYS.slice(0, 2) });
    expect(ok.incomplete).toBeUndefined();
    expect(await lastRefreshed(store, u.userId)).toBe(NOW + 5);
  });
});

describe("T2: foreign-key junk costs only a decode", () => {
  it("documents naming another userId, or another ik, use no quota", async () => {
    const { u, store, head } = await behindByOne();
    const p = decodeJws(head.jws).payload;
    const other = generateIdentityKey();
    const sk = randomBytes(32);
    // Another identity's documents, and documents claiming this userId under another ik; all with higher vers.
    const foreign = Array.from({ length: 300 }, (_, i) =>
      signJws("p2p-identity+jws", "ik", { ...p, ver: 900 + i, ...(i % 2 ? { iss: other.userId } : { ik: b64uEncode(other.publicKey) }) }, sk),
    );
    // A quota of a single signature check is enough: the junk never reaches one. (That is the proof;
    // no wall-clock bound is asserted, which a slower runner could miss.)
    const view = await refreshIdentity(store, u.userId, async () => [...foreign, head.jws], { now: NOW, relays: [RELAYS[0]], maxDocs: 1 });
    expect(view.incomplete).toBeUndefined();
    expect(view.head.hash).toBe(head.hash);
  });
});
