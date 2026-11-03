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
    // A quota of a single signature check is enough: the junk never reaches one.
    const t0 = performance.now();
    const view = await refreshIdentity(store, u.userId, async () => [...foreign, head.jws], { now: NOW, relays: [RELAYS[0]], maxDocs: 1 });
    expect(performance.now() - t0).toBeLessThan(500);
    expect(view.incomplete).toBeUndefined();
    expect(view.head.hash).toBe(head.hash);
  });
});
