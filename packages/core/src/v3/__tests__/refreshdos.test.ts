// Copyright 2026 Ix Infrastructure Inc.
//
// Regression tests for the pre-release re-review: R1 (a jump carries a revocation
// denylist, not whole tips, so the view isn't stuck forked) and R2 (hostile
// fetch results can't stall the refresh).

import { describe, expect, it } from "vitest";
import { createIdentityDoc, mergeFields, verifyIdentityDocSignature, type VerifiedIdentityDoc } from "../identitydoc.js";
import { addIdentityVersion, getIdentityView, jumpIdentity, refreshIdentity, type IdentityFetcher } from "../state.js";
import { b64uEncode } from "../../encoding.js";
import { randomBytes } from "../../crypto.js";
import { decodeJws, signJws } from "../../jws.js";
import { makeUser, NOW, RELAY, storeKnowing, type TestUser } from "./fixtures.js";

function doc(u: TestUser, f: { ver: number; prev: string; devices: string[]; keyholders: string[]; iat: number; merge?: string }): VerifiedIdentityDoc {
  return verifyIdentityDocSignature(
    createIdentityDoc(u.ik, {
      ver: f.ver,
      prev: f.prev,
      ...(f.merge ? { merge: f.merge } : {}),
      name: u.name,
      relays: [RELAY],
      devices: f.devices,
      keyholders: f.keyholders,
      by: f.keyholders[0],
      certs: u.devices.filter((d) => f.devices.includes(d.did)).map((d) => d.cert),
      iat: f.iat,
    }),
  );
}

describe("R1: a jump carries a revocation denylist, not whole tips", () => {
  it("after a merge inside the gap, the jumped view isn't stuck forked, keeps d2 out and lets d3 in", async () => {
    const u = makeUser("alice");
    const phone = u.addDevice({ keyholder: true });
    const d2 = u.addDevice({ keyholder: false });
    const v2 = u.publish();
    const kh = [u.dev.did, phone.did];
    // The fork: v3a revokes d2 and demotes the phone; v3b keeps both.
    const v3a = doc(u, { ver: 3, prev: v2.hash, devices: kh, keyholders: [u.dev.did], iat: NOW - 500 });
    const v3b = doc(u, { ver: 3, prev: v2.hash, devices: [...kh, d2.did], keyholders: kh, iat: NOW - 499 });
    const store = await storeKnowing();
    for (const d of [u.docs[0], v2, v3a, v3b]) await addIdentityVersion(store, d.jws, { now: NOW });
    expect((await getIdentityView(store, u.userId))?.forked).toBe(true);
    // The owner merges (v4), adds d3 (v5), publishes v6. The client misses v4 and v5.
    const m = mergeFields(v3a, v3b);
    const v4 = doc(u, { ver: m.ver!, prev: m.prev!, merge: m.merge, devices: m.devices!, keyholders: m.keyholders!, iat: NOW - 400 });
    const d3 = u.addDevice({ keyholder: false });
    const v5 = doc(u, { ver: 5, prev: v4.hash, devices: [...v4.devices, d3.did], keyholders: v4.keyholders, iat: NOW - 300 });
    const v6 = doc(u, { ver: 6, prev: v5.hash, devices: v5.devices, keyholders: [u.dev.did, phone.did].filter((k) => v5.devices.includes(k)), iat: NOW - 200 });
    await jumpIdentity(store, v6.jws, { now: NOW });
    let view = (await getIdentityView(store, u.userId))!;
    expect(view.forked).toBe(false);
    expect(view.historyGap).toBe(true);
    expect(view.devices).toContain(d3.did);
    expect(view.devices).not.toContain(d2.did);
    // review S3: a demotion on branch A isn't revocation; the head names the phone a key holder.
    expect(view.keyholders).toContain(phone.did);
    // v7 extends normally; the denylist survives storage and later versions.
    const v7 = doc(u, { ver: 7, prev: v6.hash, devices: v6.devices, keyholders: [u.dev.did], iat: NOW - 100 });
    expect((await addIdentityVersion(store, v7.jws, { now: NOW })).status).toBe("accepted");
    view = (await getIdentityView(store, u.userId))!;
    expect(view.forked).toBe(false);
    expect(view.devices).toContain(d3.did);
    expect(view.devices).not.toContain(d2.did);
    // And d2 can't be re-listed later.
    const v8 = doc(u, { ver: 8, prev: v7.hash, devices: [...v7.devices, d2.did], keyholders: [u.dev.did], iat: NOW - 50 });
    await expect(addIdentityVersion(store, v8.jws, { now: NOW })).rejects.toThrow(/revoked-device-returned/);
  });

  it("a linear jump denies only what was actually revoked", async () => {
    const u = makeUser("alice");
    const d2 = u.addDevice({ keyholder: false });
    u.publish(); // lists d2
    const v3 = u.publish({ devices: [u.dev.did] }); // revokes d2
    const store = await storeKnowing(u);
    const later = u.addDevice({ keyholder: false });
    u.publish();
    const v5 = u.publish();
    await jumpIdentity(store, v5.jws, { now: NOW });
    const view = (await getIdentityView(store, u.userId))!;
    expect(view.devices).toContain(later.did);
    expect(view.devices).not.toContain(d2.did);
    expect(v3.devices).not.toContain(d2.did);
  });
});

/** A structurally valid document claiming `userId` with a random prev and a high ver, but a bad signature. */
function junk(real: VerifiedIdentityDoc, i: number): string {
  const p = decodeJws(real.jws).payload;
  return signJws("p2p-identity+jws", "ik", { ...p, ver: 100 + i, prev: b64uEncode(randomBytes(32)) }, randomBytes(32));
}

async function longChain() {
  const u = makeUser("alice");
  for (let i = 0; i < 60; i++) u.publish({ iat: NOW - 1000 + i });
  const store = await storeKnowing();
  await store.putIdentity({ iss: u.userId, versions: u.docs.map((d) => d.jws) }); // 61 versions
  return { u, store };
}

/**
 * The time budget for a refresh that does linear work: what verifying every document once costs on
 * this machine right now (`docs`: each is signature-checked once, valid or not), times 8,
 * with a floor. A refresh storm (junk tips × chain walk, ~12,000 verifications here, ~45× the
 * calibration) blows through it; ordinary scheduling noise under a parallel test run (the
 * calibration slows down with it) doesn't. A fixed wall-clock limit flaked at 1085 ms vs 1000 ms.
 */
function linearBudgetMs(docs: readonly string[]): number {
  const t0 = performance.now();
  for (const d of docs) {
    try {
      verifyIdentityDocSignature(d);
    } catch {
      // junk: the failing check is the cost being measured
    }
  }
  return Math.max(1500, 8 * (performance.now() - t0));
}

describe("R2: hostile fetch results can't stall the refresh", () => {
  it("1 real version and 200 junk tips against a 61-version chain: linear work, not a storm", async () => {
    const { u, store } = await longChain();
    const real = u.publish({ iat: NOW - 10 });
    const junkTips = Array.from({ length: 200 }, (_, i) => junk(real, i));
    let tipCalls = 0;
    let chainCalls = 0;
    const fetcher: IdentityFetcher = {
      tips: async () => {
        tipCalls++;
        return [real.jws, ...junkTips];
      },
      chain: async () => {
        chainCalls++;
        return junkTips;
      },
    };
    const budget = linearBudgetMs([...u.docs.map((d) => d.jws), real.jws, ...junkTips]);
    const t0 = performance.now();
    const view = await refreshIdentity(store, u.userId, fetcher, { now: NOW });
    const ms = performance.now() - t0;
    expect(view.head.hash).toBe(real.hash);
    // No storm: one tips fetch, no chain walk (the real tip chains onto the held head) ...
    expect(tipCalls).toBe(1);
    expect(chainCalls).toBe(0);
    // ... and time linear in the documents seen, measured against this machine's own speed.
    expect(ms).toBeLessThan(budget);
  });

  it("a junk chain walk over a real gap fails closed quickly", async () => {
    const { u, store } = await longChain();
    u.publish({ iat: NOW - 20 }); // v62, withheld
    const v63 = u.publish({ iat: NOW - 10 });
    const junkPage = Array.from({ length: 200 }, (_, i) => junk(v63, i));
    let requests = 0;
    const fetcher: IdentityFetcher = {
      tips: async () => [v63.jws, ...junkPage],
      chain: async () => {
        requests++;
        return junkPage;
      },
    };
    const budget = linearBudgetMs([...u.docs.map((d) => d.jws), v63.jws, ...junkPage]);
    const t0 = performance.now();
    await expect(refreshIdentity(store, u.userId, fetcher, { now: NOW })).rejects.toThrow(/chain-broken/);
    expect(performance.now() - t0).toBeLessThan(budget);
    expect(requests).toBe(1); // a page with nothing valid ends the walk
    expect((await getIdentityView(store, u.userId))?.head.ver).toBe(61);
  });

  it("documents of another identity, or under another ik, are ignored before any chain work", async () => {
    const { u, store } = await longChain();
    const other = makeUser("mallory");
    const real = u.publish({ iat: NOW - 10 });
    const view = await refreshIdentity(store, u.userId, async () => [other.doc.jws, real.jws], { now: NOW });
    expect(view.head.hash).toBe(real.hash);
  });
});
