// Copyright 2026 Ix Infrastructure Inc.
//
// Regression tests for the pre-release re-review: N1 (a planted provisional
// document must not disable M1), and the lows N2–N5. Each reproduces the
// reviewer's proof of concept.

import { describe, expect, it } from "vitest";
import {
  CircleChain,
  createCircle,
  createCircleTransferAccept,
  createMembershipStatement,
  createNextCircleVersion,
  membershipFact,
  OPEN_JOIN_CAP_MAX_TTL_SEC,
  verifyCircleGenesis,
  verifyCircleLink,
  verifyMembershipStatement,
  type VerifiedCircleVersion,
} from "../circles.js";
import { createAcceptV3, createInviteV3, verifyFriendshipV3 } from "../friends.js";
import { createRosterV3 } from "../roster.js";

import {
  applyCircleBundle,
  decideOpenJoinFor,
  freshnessLookup,
  getIdentityView,
  outgoingCircleBundle,
  recordFriendshipV3,
  recordOwnJoin,
  refreshIdentity,
  reverifyFriendshipForApproval,
  storeOfferedCircle,
  type IdentityFetcher,
} from "../state.js";
import { verifyIncomingV3 } from "../incoming.js";
import { MemoryTrustStoreV3, PROVISIONAL_MAX, PROVISIONAL_TTL_SEC, type TrustStoreV3 } from "../store.js";
import { b32Encode, b64uEncode, utf8 } from "../../encoding.js";
import { sha256 } from "../../crypto.js";
import { jwsHash } from "../base.js";
import { addIdentityVersion } from "../state.js";
import { DAYS, ctxFor, makeUser, NOW, NOW_MS, RELAY, seal, storeKnowing, TestUser } from "./fixtures.js";

async function receive(store: TrustStoreV3, to: TestUser, env: string, nowMs = NOW_MS) {
  return verifyIncomingV3(env, { self: { userId: to.userId, did: to.dev.did, agreementSecretKey: to.dev.agreementSecretKey, cert: to.dev.cert }, store, nowMs });
}

/** User U with a device D that was later revoked, and U's old document that still lists D. */
function revokedDeviceSetup() {
  const u = makeUser("alice");
  const d = u.addDevice({ keyholder: false });
  const oldDoc = u.publish(); // lists D
  u.publish({ devices: [u.dev.did] }); // D revoked
  return { u, d, oldDoc };
}

describe("N1: a planted provisional document doesn't disable M1", () => {
  it("A: a replayed invite in a new envelope stays provisional", async () => {
    const { u, d, oldDoc } = revokedDeviceSetup();
    const b = makeUser("bob");
    const store = await storeKnowing(b);
    const invite = createInviteV3(u.signer(d), { aud: b.userId, iat: NOW - 10, doc: oldDoc.jws });
    for (let i = 0; i < 2; i++) {
      const r = await receive(store, b, seal(u, b, "contact", { text: invite }, { fromDev: d }));
      expect(r.ok && r.contact?.type === "invite" && r.contact.invite.provisional).toBe(true);
    }
    expect(await getIdentityView(store, u.userId)).toBeUndefined();
  });

  it("B: a provisional friendship can't be recorded, and D can't send any other kind as U", async () => {
    const { u, d, oldDoc } = revokedDeviceSetup();
    const b = makeUser("bob");
    const store = await storeKnowing(b);
    // D plants the old document through a contact, then tries to become a friend.
    const invite = createInviteV3(u.signer(d), { aud: b.userId, iat: NOW - 100, doc: oldDoc.jws });
    expect((await receive(store, b, seal(u, b, "contact", { text: invite }, { fromDev: d }))).ok).toBe(true);
    const f = await verifyFriendshipV3({ invite, accept: createAcceptV3(b.signer(), invite, { iat: NOW - 50 }) }, ctxFor(store));
    expect(f.provisional).toBe(true);
    await expect(recordFriendshipV3(store, f)).rejects.toThrow(/provisional/);
    // Approval refreshes U's real head: D is refused.
    const fetch: IdentityFetcher = async () => u.docs.map((x) => x.jws);
    await expect(
      reverifyFriendshipForApproval(store, f.proof, fetch, { now: NOW, self: b.userId, resolveCert: (_u, did) => (did === d.did ? d.cert : undefined) }),
    ).rejects.toThrow(/device-not-listed/);
    expect(await store.listFriendships()).toHaveLength(0);
    // Any non-contact kind from D: the planted document is no view for rule 6.
    const roster = createRosterV3(u.signer(d), { sid: "s1", ver: 1, vis: "private", parts: [u.userId, b.userId], iat: NOW - 10 });
    const r = await receive(await storeKnowing(b), b, seal(u, b, "msg", { text: "I am U", roster }, { fromDev: d }));
    expect(r.ok ? "ok" : r.reason).toBe("identity-unknown");
    const r2 = await receive(store, b, seal(u, b, "msg", { text: "I am U", roster }, { fromDev: d }));
    expect(r2.ok ? "ok" : r2.reason).toBe("device-not-listed"); // U's real chain is stored now
  });

  it("a genuine friendship goes through re-verification and is then recorded", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(b);
    const invite = createInviteV3(a.signer(), { aud: b.userId, iat: NOW - 100, doc: a.doc.jws });
    const proof = { invite, accept: createAcceptV3(b.signer(), invite, { iat: NOW - 50 }) };
    const f = await reverifyFriendshipForApproval(store, proof, async () => a.docs.map((x) => x.jws), { now: NOW, self: b.userId });
    expect(f.reverifiedAt).toBe(NOW);
    await recordFriendshipV3(store, f);
    expect(await store.listFriendships()).toHaveLength(1);
  });

  it("C: a planted (or stale) version 1 never pins the identity", async () => {
    // U's first device D was later revoked; the relays pruned everything between v1 and the head.
    const u = new TestUser("alice");
    const d = u.addDevice({ keyholder: true });
    const v1 = u.publish();
    const real = u.addDevice({ keyholder: true });
    u.keyholders = [real.did];
    for (let i = 0; i < 3; i++) u.publish({ devices: [real.did] });
    const head = u.doc;
    const b = makeUser("bob");
    const store = await storeKnowing(b);
    // D delivers an invite bundling v1: cached provisionally only.
    const invite = createInviteV3(u.signer(d), { aud: b.userId, iat: NOW - 10, doc: v1.jws });
    expect((await receive(store, b, seal(u, b, "contact", { text: invite }, { fromDev: d }))).ok).toBe(true);
    expect(await getIdentityView(store, u.userId)).toBeUndefined();
    // A refresh that gets v1 and the head (nothing between) gap-jumps to the head.
    const view = await refreshIdentity(store, u.userId, async () => [v1.jws, head.jws], { now: NOW });
    expect(view.head.hash).toBe(head.hash);
    expect(view.historyGap).toBe(true);
    expect(await store.getProvisional(u.userId, NOW)).toBeUndefined();
    // U's real device is accepted (rule 6), D is refused.
    const roster = createRosterV3(u.signer(real), { sid: "s1", ver: 1, vis: "private", parts: [u.userId, b.userId], iat: NOW - 10 });
    const fromD = await receive(store, b, seal(u, b, "msg", { text: "x", roster }, { fromDev: d }));
    expect(fromD.ok ? "ok" : fromD.reason).toBe("device-not-listed");
    const fromReal = await receive(store, b, seal(u, b, "msg", { text: "x", roster }, { fromDev: real }));
    expect(fromReal.ok ? "ok" : fromReal.reason).toBe("viewer-no-friendship"); // past rule 6; Bob just isn't a friend
  });
});

describe("N2: strangers can't grow the store; freshness lookups are cheap", () => {
  it("the provisional cache is bounded and expires", async () => {
    const s = new MemoryTrustStoreV3();
    for (let i = 0; i < PROVISIONAL_MAX + 20; i++) {
      await s.putProvisional({ userId: `p2p:${b32Encode(sha256(utf8(String(i))))}`, relays: [RELAY], at: NOW });
    }
    expect(await s.countProvisional()).toBe(PROVISIONAL_MAX);
    await s.putProvisional({ userId: "p2p:" + "z".repeat(52), relays: [RELAY], at: NOW });
    expect(await s.getProvisional("p2p:" + "z".repeat(52), NOW + PROVISIONAL_TTL_SEC - 1)).toBeDefined();
    expect(await s.getProvisional("p2p:" + "z".repeat(52), NOW + PROVISIONAL_TTL_SEC)).toBeUndefined();
    // A later put sweeps expired entries.
    await s.putProvisional({ userId: "p2p:" + "y".repeat(52), relays: [RELAY], at: NOW + PROVISIONAL_TTL_SEC });
    expect(await s.countProvisional()).toBe(1);
  });

  it("strangers' contacts leave the identity store untouched", async () => {
    const b = makeUser("bob");
    const store = await storeKnowing(b);
    for (let i = 0; i < 5; i++) {
      const s = makeUser(`s${i}`);
      const invite = createInviteV3(s.signer(), { aud: b.userId, iat: NOW - 10, doc: s.doc.jws });
      expect((await receive(store, b, seal(s, b, "contact", { text: invite }))).ok).toBe(true);
    }
    expect(await store.listIdentities()).toEqual([b.userId]);
    expect(await store.countProvisional()).toBe(5);
  });

  it("views are cached per stored chain; freshnessLookup can load only the possible signers", async () => {
    const a = makeUser("alice");
    const c = makeUser("carol");
    const store = await storeKnowing(a, c);
    const v1 = await getIdentityView(store, a.userId);
    expect(await getIdentityView(store, a.userId)).toEqual(v1); // served from the verified-view cache
    a.publish();
    await storeKnowing(); // unrelated store doesn't share the cache

    await addIdentityVersion(store, a.doc.jws, { now: NOW });
    expect((await getIdentityView(store, a.userId))?.head.hash).toBe(a.doc.hash); // a changed chain invalidates
    const f = await freshnessLookup(store, NOW, [a.userId]);
    expect(f(a.userId)).toBe("fresh");
    expect(f(c.userId)).toBeUndefined();
  });
});

function transferTo(owner: TestUser, head: VerifiedCircleVersion, to: TestUser): string {
  const transfer = createCircleTransferAccept(to.ik, { cid: head.cid, ver: head.ver + 1, prev: head.hash, iat: NOW });
  return createNextCircleVersion(owner.ik, head, { members: [...new Set([...head.members, to.userId])], newOwner: { userId: to.userId, ik: b64uEncode(to.ik.publicKey), transfer }, iat: NOW });
}

describe("N3: the side store can't be flooded, and receive() is linear", () => {
  it("a former owner's dead siblings from before the transfer are not kept", () => {
    const owner = makeUser("owen");
    const bob = makeUser("bob");
    const g = verifyCircleGenesis(createCircle(owner.ik, { name: "c", members: [bob.userId], iat: NOW - 1000 }));
    const c = CircleChain.bootstrap([g.jws, transferTo(owner, g, bob)]);
    for (let i = 0; i < 300; i++) c.receive(createNextCircleVersion(owner.ik, g, { name: `dead-${i}`, iat: NOW }));
    expect(c.sideCount).toBe(0);
    expect(c.head.owner).toBe(bob.userId);
  });

  it("losing siblings that could still win are kept; they go once the chain passes a transfer", () => {
    const owner = makeUser("owen");
    const bob = makeUser("bob");
    const g = verifyCircleGenesis(createCircle(owner.ik, { name: "c", members: [bob.userId], iat: NOW - 1000 }));
    const c = CircleChain.bootstrap([g.jws]);
    for (let i = 0; i < 5; i++) c.receive(createNextCircleVersion(owner.ik, g, { name: `s-${i}`, iat: NOW }));
    expect(c.sideCount).toBe(4);
    c.receive(transferTo(owner, c.head, bob));
    expect(c.sideCount).toBe(0);
  });

  it("500 versions in one batch take under a second", () => {
    const owner = makeUser("owen");
    let head = verifyCircleGenesis(createCircle(owner.ik, { name: "c", iat: NOW - 1000 }));
    const all = [head.jws];
    for (let i = 0; i < 499; i++) {
      const j = createNextCircleVersion(owner.ik, head, { name: `v${i}`, iat: NOW });
      head = verifyCircleLink(head, j);
      all.push(j);
    }
    const shuffled = [...all.slice(1)].reverse();
    const t0 = performance.now();
    const c = CircleChain.bootstrap([all[0], ...shuffled]);
    const ms = performance.now() - t0;
    expect(c.head.ver).toBe(500);
    expect(ms).toBeLessThan(1000);
  });
});


async function openCircleStore() {
  const owner = makeUser("owen");
  const carol = makeUser("carol");
  const bob = makeUser("bob");
  const store = await storeKnowing(owner, carol, bob);
  const ctx = ctxFor(store);
  const g = createCircle(owner.ik, { name: "open", members: [carol.userId, bob.userId], policy: "open", iat: NOW - 1000 });
  const chain = await storeOfferedCircle(store, [g], { now: NOW });
  const join = (u: TestUser, n: number, at: string, ttlSec = OPEN_JOIN_CAP_MAX_TTL_SEC) =>
    createMembershipStatement(u.signer(), { cid: chain.cid, n, op: "join", at, cap: u.joinCap({ ttlSec, iat: NOW - 60 }), iat: NOW - 30 + n });
  return { owner, carol, bob, store, ctx, chain, join, self: owner.userId };
}

describe("N4: the removed record is applied by the state-level open-join decision", () => {
  it("decideOpenJoinFor holds a removed member's leave-then-join, and keeps the limiter", async () => {
    const { owner, carol, store, ctx, chain, join, self } = await openCircleStore();
    await applyCircleBundle(store, { circles: [], joins: [join(carol, 0, chain.head.hash)], ops: [] }, { ...ctx, self });
    const v2 = createNextCircleVersion(owner.ik, chain.head, { members: chain.head.members.filter((m) => m !== carol.userId), iat: NOW - 500 });
    await applyCircleBundle(store, { circles: [v2], joins: [], ops: [] }, { ...ctx, self });
    const leave = createMembershipStatement(carol.signer(), { cid: chain.cid, n: 1, op: "leave", iat: NOW - 20 });
    await applyCircleBundle(store, { circles: [], joins: [leave], ops: [] }, { ...ctx, self });
    const rejoin = await verifyMembershipStatement(join(carol, 2, jwsHash(v2)), ctx);
    expect(await decideOpenJoinFor(store, rejoin, { now: NOW })).toEqual({ decision: "hold", reason: "previously-removed" });
    const stranger = makeUser("stranger");
    const st = await storeKnowing(stranger);
    const sj = await verifyMembershipStatement(
      createMembershipStatement(stranger.signer(), { cid: chain.cid, n: 0, op: "join", at: jwsHash(v2), cap: stranger.joinCap({ ttlSec: OPEN_JOIN_CAP_MAX_TTL_SEC, iat: NOW - 60 }), iat: NOW - 1 }),
      ctxFor(st),
    );
    expect(await decideOpenJoinFor(store, sj, { now: NOW, maxPerHour: 1 })).toEqual({ decision: "accept" });
    expect((await store.getCircle(chain.cid))?.openJoins?.acceptedAt).toEqual([NOW]);
  });
});

describe("review H1: every former member's open re-join is held (main's rule)", () => {
  it("a voluntary leaver's re-join is held for the owner", async () => {
    const { owner, carol, store, ctx, chain, join, self } = await openCircleStore();
    await applyCircleBundle(store, { circles: [], joins: [join(carol, 0, chain.head.hash)], ops: [] }, { ...ctx, self });
    const leave = createMembershipStatement(carol.signer(), { cid: chain.cid, n: 1, op: "leave", iat: NOW - 20 });
    await applyCircleBundle(store, { circles: [], joins: [leave], ops: [] }, { ...ctx, self });
    const v2 = createNextCircleVersion(owner.ik, chain.head, { members: chain.head.members.filter((m) => m !== carol.userId), iat: NOW - 15 });
    await applyCircleBundle(store, { circles: [v2], joins: [], ops: [] }, { ...ctx, self });
    const res = await applyCircleBundle(store, { circles: [], joins: [join(carol, 2, jwsHash(v2))], ops: [] }, { ...ctx, self });
    expect(await decideOpenJoinFor(store, res.joins[0].statement!, { now: NOW })).toEqual({ decision: "hold", reason: "previously-removed" });
  });

  it("reviewer's repro: the removed member relays {circles:[v2], joins:[its leave]} to a store that hadn't applied v2, then joins: held", async () => {
    const { owner, carol, store, ctx, chain, join, self } = await openCircleStore();
    await applyCircleBundle(store, { circles: [], joins: [join(carol, 0, chain.head.hash)], ops: [] }, { ...ctx, self });
    // The owner removed carol on another device; this one hasn't seen v2 yet.
    const v2 = createNextCircleVersion(owner.ik, chain.head, { members: chain.head.members.filter((m) => m !== carol.userId), iat: NOW - 500 });
    const leave = createMembershipStatement(carol.signer(), { cid: chain.cid, n: 1, op: "leave", iat: NOW - 20 });
    await applyCircleBundle(store, { circles: [v2], joins: [leave], ops: [] }, { ...ctx, self });
    const res = await applyCircleBundle(store, { circles: [], joins: [join(carol, 2, jwsHash(v2))], ops: [] }, { ...ctx, self });
    expect(await decideOpenJoinFor(store, res.joins[0].statement!, { now: NOW })).toEqual({ decision: "hold", reason: "previously-removed" });
  });

  it("and the leave relayed before the version: held", async () => {
    const { owner, carol, store, ctx, chain, join, self } = await openCircleStore();
    await applyCircleBundle(store, { circles: [], joins: [join(carol, 0, chain.head.hash)], ops: [] }, { ...ctx, self });
    const v2 = createNextCircleVersion(owner.ik, chain.head, { members: chain.head.members.filter((m) => m !== carol.userId), iat: NOW - 500 });
    await applyCircleBundle(store, { circles: [], joins: [createMembershipStatement(carol.signer(), { cid: chain.cid, n: 1, op: "leave", iat: NOW - 20 })], ops: [] }, { ...ctx, self });
    await applyCircleBundle(store, { circles: [v2], joins: [], ops: [] }, { ...ctx, self });
    const res = await applyCircleBundle(store, { circles: [], joins: [join(carol, 2, jwsHash(v2))], ops: [] }, { ...ctx, self });
    expect(await decideOpenJoinFor(store, res.joins[0].statement!, { now: NOW })).toEqual({ decision: "hold", reason: "previously-removed" });
  });
});

describe("N5: outgoing bundles withhold join statements whose caps don't fit the policy", () => {
  it("an open circle's bundle never carries a 90-day join cap", async () => {
    const { carol, bob, store, ctx, chain, join, self, owner } = await openCircleStore();
    await recordOwnJoin(store, self, await verifyMembershipStatement(join(owner, 0, chain.head.hash), ctx));
    // Bob's join carries a 90-day cap (signed before the circle opened): the book holds it.
    const longJws = join(bob, 0, chain.head.hash, DAYS(90));
    const bobLong = await verifyMembershipStatement(longJws, ctx);
    await store.updateCircle(chain.cid, (cur) => ({ next: { ...cur!, statements: { ...cur!.statements, [bob.userId]: membershipFact(bobLong) } }, result: undefined }));
    await applyCircleBundle(store, { circles: [], joins: [join(carol, 0, chain.head.hash)], ops: [] }, { ...ctx, self });
    const out = await outgoingCircleBundle(store, chain.cid);
    expect(out?.withheld).toEqual([bob.userId]);
    expect(out?.joins).not.toContain(longJws);
    expect(out?.joins).toHaveLength(2);
    expect(out?.circles).toEqual([chain.head.jws]);
  });

  it("an invite-policy circle sends every statement", async () => {
    const owner = makeUser("owen");
    const bob = makeUser("bob");
    const store = await storeKnowing(owner, bob);
    const g = createCircle(owner.ik, { name: "c", members: [bob.userId], iat: NOW - 1000 });
    const chain = await storeOfferedCircle(store, [g], { now: NOW });
    const long = createMembershipStatement(bob.signer(), { cid: chain.cid, n: 0, op: "join", at: chain.head.hash, cap: bob.joinCap(), iat: NOW - 30 });
    await applyCircleBundle(store, { circles: [], joins: [long], ops: [] }, { ...ctxFor(store), self: owner.userId });
    expect((await outgoingCircleBundle(store, chain.cid))?.joins).toEqual([long]);

  });
});
