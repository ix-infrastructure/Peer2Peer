// Copyright 2026 Ix Infrastructure Inc.
//
// Regression tests for #81: on a history longer than MAX_CHAIN_VERSIONS (its oldest versions pruned), a relay
// replaying a pruned old version must not keep every refresh incomplete (no freshness, approvals refused).
// A genuine second-genesis fork below the pruned range is still detected.

import { describe, expect, it } from "vitest";
import { createIdentityDoc, IdentityChain, MAX_CHAIN_VERSIONS, verifyIdentityDocSignature, type VerifiedIdentityDoc } from "../identitydoc.js";
import { lastRefreshed, refreshIdentity, type IdentityFetcher } from "../state.js";
import { MemoryTrustStoreV3 } from "../store.js";
import { makeUser, NOW, RELAY, RELAY2 } from "./fixtures.js";

/** A history of MAX_CHAIN_VERSIONS + 8 versions, stored with v1..v8 pruned; two relays. */
async function longHistory() {
  const u = makeUser("alice");
  u.relays = [RELAY, RELAY2];
  const c = new IdentityChain(u.userId);
  c.add(u.doc.jws, { now: NOW });
  for (let i = 0; i < MAX_CHAIN_VERSIONS + 7; i++) c.add(u.publish({ iat: NOW - 400 }).jws, { now: NOW });
  expect(c.has(u.docs[7].hash)).toBe(false);
  expect(c.has(u.docs[8].hash)).toBe(true);
  const store = new MemoryTrustStoreV3();
  await store.putIdentity(c.toStored());
  const byHash = new Map(u.docs.map((d) => [d.hash, d]));
  const walk = (docs: Map<string, VerifiedIdentityDoc>, to: string) => {
    const out: string[] = [];
    for (let d = docs.get(to); d; d = d.prev ? docs.get(d.prev) : undefined) out.push(d.jws);
    return out.slice(0, 64);
  };
  return { u, store, byHash, walk };
}

/** Per-relay tips; every relay walks `docs`. */
function fetcher(tips: Record<string, string[]>, chain: (to: string) => string[]): IdentityFetcher & { asked: string[] } {
  const asked: string[] = [];
  return { asked, tips: async (_u, rs) => tips[rs[0]] ?? [], chain: async (_u, _r, to) => (asked.push(to), chain(to)) };
}

/** Generous work bounds: rebuilding a 1024-version chain is slow on hosted runners, and isn't what is tested. */
const SLOW = { budgetMs: 60_000 };

describe("#81: a replayed pruned version on a long history", () => {
  it("the pruned v2 replayed as a tip: the refresh completes, records freshness, and the view is unchanged", async () => {
    const { u, store, byHash, walk } = await longHistory();
    const head = u.doc;
    const f = fetcher({ [RELAY]: [head.jws, u.docs[1].jws], [RELAY2]: [head.jws] }, (to) => walk(byHash, to));
    for (let i = 0; i < 2; i++) {
      const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2], ...SLOW });
      expect(v.incomplete).toBeUndefined();
      expect(v.forked).toBe(false);
      expect(v.head.hash).toBe(head.hash);
      expect(v.devices).toEqual(head.devices);
    }
    expect(await lastRefreshed(store, u.userId)).toBe(NOW);
    // The pruned genesis is known history: never asked for.
    expect(f.asked).not.toContain(u.docs[0].hash);
  }, 60_000);

  it("a pruned v5 replayed with its ancestry walked down to the pruned v1: still complete and fresh", async () => {
    const { u, store, byHash, walk } = await longHistory();
    const head = u.doc;
    const f = fetcher({ [RELAY]: [head.jws, u.docs[4].jws], [RELAY2]: [head.jws, u.docs[4].jws] }, (to) => walk(byHash, to));
    const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2], ...SLOW });
    expect(v.incomplete).toBeUndefined();
    expect(v.forked).toBe(false);
    expect(v.devices).toEqual(head.devices);
    expect(await lastRefreshed(store, u.userId)).toBe(NOW);
    // Nothing of the pruned range was stored again.
    const stored = (await store.getIdentity(u.userId))!;
    expect(stored.versions).not.toContain(u.docs[0].jws);
  }, 60_000);

  it("a second-genesis branch below the pruned range is still a fork (fork detection on anchored history holds)", async () => {
    const { u, store, byHash, walk } = await longHistory();
    const head = u.doc;
    const g = verifyIdentityDocSignature(
      createIdentityDoc(u.ik, { ver: 1, prev: null, name: u.name, relays: u.relays, devices: [u.dev.did], keyholders: [u.dev.did], by: u.dev.did, iat: NOW - 30 }),
    );
    const g2 = verifyIdentityDocSignature(
      createIdentityDoc(u.ik, { ver: 2, prev: g.hash, name: u.name, relays: u.relays, devices: [u.dev.did], keyholders: [u.dev.did], by: u.dev.did, iat: NOW - 29 }),
    );
    const all = new Map([...byHash, [g.hash, g], [g2.hash, g2]]);
    const f = fetcher({ [RELAY]: [head.jws, g2.jws], [RELAY2]: [head.jws] }, (to) => walk(all, to));
    const v = await refreshIdentity(store, u.userId, f, { now: NOW, relays: [RELAY, RELAY2], ...SLOW });
    expect(v.forked).toBe(true);
    expect(v.tips.map((t) => t.hash)).toContain(g2.hash);
  }, 60_000);
});
