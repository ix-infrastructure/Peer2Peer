// Copyright 2026 Ix Infrastructure Inc.
//
// Regression tests for the pre-release security review (mediums M1–M4, lows
// L1–L9), one or more per finding, named after it.

import { describe, expect, it } from "vitest";
import {
  applyProposals,
  CircleChain,
  createCircle,
  createCircleTransferAccept,
  createMembershipStatement,
  createNextCircleVersion,
  createProposal,
  decideOpenJoin,
  MAX_PENDING_AHEAD,
  MAX_PENDING_VERSIONS,
  OPEN_JOIN_CAP_MAX_TTL_SEC,
  verifyCircleGenesis,
  verifyMembershipStatement,
  type VerifiedCircleVersion,
} from "../circles.js";
import { createAcceptV3, createInviteV3, verifyFriendshipV3, verifyInviteV3 } from "../friends.js";
import { createDeviceCert } from "../device.js";
import { createIdentityDoc, IdentityChain } from "../identitydoc.js";
import { verifyCapForSend } from "../caps.js";
import { isSafeRelativePath, sanitizeFiles } from "../sanitize.js";
import {
  addIdentityVersion,
  applyCircleBundle,
  applyOwnerProposals,
  getIdentityView,
  liveFriendshipsV3,
  longestLived,
  openCircleCapActions,
  recordFriendshipV3,
  recordOwnJoin,
  reverifyFriendshipForApproval,
  reverifyInviteForApproval,
  storeOfferedCircle,
  type IdentityFetcher,
} from "../state.js";
import { verifyIncomingV3 } from "../incoming.js";
import { MemoryTrustStoreV3, type TrustStoreV3 } from "../store.js";
import { asciiCompare, jwsHash } from "../base.js";
import { b64uEncode } from "../../encoding.js";
import { decodeJws, signJws } from "../../jws.js";
import { ctxFor, DAYS, learn, makeUser, NOW, NOW_MS, RELAY, seal, storeKnowing, type TestUser } from "./fixtures.js";

const empty = { now: NOW, resolveCert: () => undefined, resolveIdentity: () => undefined };

function relaysServing(...users: TestUser[]): IdentityFetcher {
  return async (userId) => users.find((u) => u.userId === userId)?.docs.map((d) => d.jws) ?? [];
}

async function receive(store: TrustStoreV3, to: TestUser, env: string, nowMs = NOW_MS) {
  return verifyIncomingV3(env, { self: { userId: to.userId, did: to.dev.did, agreementSecretKey: to.dev.agreementSecretKey, cert: to.dev.cert }, store, nowMs });
}

// ---------------------------------------------------------------------------

describe("M1: a stranger's bundled document is provisional", () => {
  it("a bundled document more than 60 days past exp is refused (fail closed)", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    // A document 80 days past its exp, and a fresh certificate.
    const oldDoc = createIdentityDoc(a.ik, { ver: 2, prev: a.doc.hash, name: "alice", relays: [RELAY], devices: [a.dev.did], keyholders: [a.dev.did], by: a.dev.did, certs: [a.dev.cert], iat: NOW - DAYS(110), ttlSec: DAYS(30) });
    const invite = createInviteV3(a.signer(), { aud: b.userId, iat: NOW - 10, doc: oldDoc });
    await expect(verifyInviteV3(invite, empty)).rejects.toThrow(/identity-fail-closed/);
    const r = await receive(await storeKnowing(b), b, seal(a, b, "contact", { text: invite }));
    expect(r.ok ? "ok" : r.reason).toBe("identity-fail-closed");
  });

  it("a revoked device's invite carrying an old document that lists it: provisional at receipt, refused at approval", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const stolen = a.addDevice({ keyholder: false });
    const oldDoc = a.publish(); // lists the stolen device
    a.publish({ devices: [a.dev.did] }); // revoked
    const invite = createInviteV3(a.signer(stolen), { aud: b.userId, iat: NOW - 10, doc: oldDoc.jws });
    const store = await storeKnowing(b);
    const r = await receive(store, b, seal(a, b, "contact", { text: invite }, { fromDev: stolen }));
    expect(r.ok && r.contact?.type === "invite" && r.contact.invite.provisional).toBe(true);
    // The bundled document is only cached provisionally: it never becomes the stored view (review N1).
    expect(await getIdentityView(store, a.userId)).toBeUndefined();
    expect((await store.getProvisional(a.userId, NOW))?.relays).toEqual(oldDoc.relays);
    // Approval refreshes the head from the listed relays and re-verifies against the stored chain.
    // (The certificate is at hand: it came as the envelope's fcert.)
    await expect(reverifyInviteForApproval(store, invite, relaysServing(a), { now: NOW, resolveCert: (_u, d) => (d === stolen.did ? stolen.cert : undefined) })).rejects.toThrow(/device-not-listed/);
    expect((await getIdentityView(store, a.userId))?.head.ver).toBe(a.doc.ver);
  });

  it("an honest invite passes approval; approval fails closed when no relay answers", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const invite = createInviteV3(a.signer(), { aud: b.userId, iat: NOW - 10, doc: a.doc.jws });
    const store = await storeKnowing(b);
    expect((await receive(store, b, seal(a, b, "contact", { text: invite }))).ok).toBe(true);
    expect((await reverifyInviteForApproval(store, invite, relaysServing(a), { now: NOW })).provisional).toBe(false);
    await expect(reverifyInviteForApproval(store, invite, async () => [], { now: NOW })).rejects.toThrow(/identity-unknown/);
  });

  it("an accept from a stranger is re-verified before the friendship is adopted", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const stolen = a.addDevice({ keyholder: false });
    const oldDoc = a.publish();
    a.publish({ devices: [a.dev.did] });
    const store = await storeKnowing(b);
    const invite = createInviteV3(b.signer(), { aud: "*", iat: NOW - 100 });
    const accept = createAcceptV3(a.signer(stolen), invite, { iat: NOW - 50, doc: oldDoc.jws });
    const f = await verifyFriendshipV3({ invite, accept }, ctxFor(store));
    expect(f.provisional).toBe(true);
    await expect(reverifyFriendshipForApproval(store, { invite, accept }, relaysServing(a), { now: NOW, self: b.userId, resolveCert: (_u, d) => (d === stolen.did ? stolen.cert : undefined) })).rejects.toThrow(/device-not-listed/);
  });

  it("stored friendships re-verify only against stored chains, never the bundled document", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(b); // Bob holds no chain for Alice
    const invite = createInviteV3(a.signer(), { aud: b.userId, iat: NOW - 100, doc: a.doc.jws });
    const f = await verifyFriendshipV3({ invite, accept: createAcceptV3(b.signer(), invite, { iat: NOW - 50 }) }, ctxFor(store));
    expect(f.provisional).toBe(true);
    // A provisional friendship can't be recorded without re-verification (review N1).
    await expect(recordFriendshipV3(store, f)).rejects.toThrow(/provisional/);
    await store.addFriendship({ inviter: f.inviter, invitee: f.invitee, inv: f.inv, aud: f.aud, iat: f.iat, inviteIat: f.inviteIat, inviteDid: f.invite.did, acceptDid: f.accept.did, proof: f.proof });
    expect(await liveFriendshipsV3(store, ctxFor(store))).toHaveLength(0);
    await learn(store, a);
    expect(await liveFriendshipsV3(store, ctxFor(store))).toHaveLength(1);
    // An old invite's bundled document aging past exp + 60 d doesn't kill a friendship the stored chain still backs.
    expect(await verifyFriendshipV3(f.proof, ctxFor(store), { bundled: false })).toBeDefined();
  });
});

describe("M2: concurrent identity adds don't lose versions", () => {
  it("two fork tips added at once are both kept", async () => {
    const a = makeUser("alice");
    const phone = a.addDevice({ keyholder: true });
    const v2 = a.publish();
    const store = await storeKnowing(a);
    const tip = (devices: string[], by: string, iat: number) =>
      createIdentityDoc(a.ik, { ver: 3, prev: v2.hash, name: "alice", relays: [RELAY], devices, keyholders: devices, by, iat });
    const t1 = tip([a.dev.did], a.dev.did, NOW - 100);
    const t2 = tip([a.dev.did, phone.did], phone.did, NOW - 99);
    await Promise.all([addIdentityVersion(store, t1, { now: NOW }), addIdentityVersion(store, t2, { now: NOW })]);
    const view = await getIdentityView(store, a.userId);
    expect(view?.tips.map((t) => t.hash).sort()).toEqual([jwsHash(t1), jwsHash(t2)].sort());
    expect(view?.forked).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Open circles: the owner's store.

async function openCircle() {
  const owner = makeUser("owen");
  const carol = makeUser("carol");
  const bob = makeUser("bob");
  const store = await storeKnowing(owner, carol, bob);
  const ctx = ctxFor(store);
  const g = createCircle(owner.ik, { name: "open", members: [carol.userId, bob.userId], policy: "open", iat: NOW - 1000 });
  await storeOfferedCircle(store, [g], { now: NOW });
  const short = { ttlSec: OPEN_JOIN_CAP_MAX_TTL_SEC, iat: NOW - 60 };
  const stmt = (u: TestUser, n: number, op: "join" | "leave", at?: string, cap?: string) =>
    createMembershipStatement(u.signer(), { cid: verifyCircleGenesis(g).cid, n, op, ...(op === "join" ? { at, cap: cap ?? u.joinCap(short) } : {}), iat: NOW - 30 + n });
  const self = owner.userId;
  return { owner, carol, bob, store, ctx, g: verifyCircleGenesis(g), stmt, self, short };
}

describe("M3: a removed member can't rejoin an open circle by leave-then-join", () => {
  it("the owner's removal is recorded and holds every later join", async () => {
    const { owner, carol, store, ctx, g, stmt, self } = await openCircle();
    await recordOwnJoin(store, self, await verifyMembershipStatement(stmt(owner, 0, "join", g.hash), ctx));
    await applyCircleBundle(store, { circles: [], joins: [stmt(carol, 0, "join", g.hash)], ops: [] }, { ...ctx, self });
    // The owner removes Carol.
    const v2 = createNextCircleVersion(owner.ik, g, { members: g.members.filter((m) => m !== carol.userId), iat: NOW - 500 });
    await applyCircleBundle(store, { circles: [v2], joins: [], ops: [] }, { ...ctx, self });
    const rec = await store.getCircle(g.cid);
    expect(rec?.removed).toEqual([carol.userId]);
    // Carol signs a leave, then a fresh join.
    await applyCircleBundle(store, { circles: [], joins: [stmt(carol, 1, "leave")], ops: [] }, { ...ctx, self });
    const rejoin = await verifyMembershipStatement(stmt(carol, 2, "join", jwsHash(v2)), ctx);
    const chain = CircleChain.fromStored((await store.getCircle(g.cid))!.chain);
    const book = (await store.getCircle(g.cid))!.statements;
    expect(decideOpenJoin(chain, rejoin, book, { acceptedAt: [] }, { now: NOW, removed: (await store.getCircle(g.cid))!.removed ?? [] })).toEqual({
      decision: "hold",
      reason: "previously-removed",
    });
  });

  it("a member who left voluntarily is not recorded as removed; a version re-adding a member clears the record", async () => {
    const { owner, carol, bob, store, ctx, g, stmt, self } = await openCircle();
    await applyCircleBundle(store, { circles: [], joins: [stmt(carol, 0, "join", g.hash), stmt(bob, 0, "join", g.hash), stmt(carol, 1, "leave")], ops: [] }, { ...ctx, self });
    const v2 = createNextCircleVersion(owner.ik, g, { members: [owner.userId], iat: NOW - 500 });
    await applyCircleBundle(store, { circles: [v2], joins: [], ops: [] }, { ...ctx, self });
    expect((await store.getCircle(g.cid))?.removed).toEqual([bob.userId]);
    const v3 = createNextCircleVersion(owner.ik, CircleChain.fromStored((await store.getCircle(g.cid))!.chain).head, { members: [owner.userId, bob.userId], iat: NOW - 400 });
    await applyCircleBundle(store, { circles: [v3], joins: [], ops: [] }, { ...ctx, self });
    expect((await store.getCircle(g.cid))?.removed).toBeUndefined();
  });
});

describe("M4: open circles keep join caps short and re-key them after a removal", () => {
  it("a join with a cap longer than 14 days is rejected in an open circle, and not auto-accepted", async () => {
    const { carol, store, ctx, g, stmt, self } = await openCircle();
    const long = stmt(carol, 0, "join", g.hash, carol.joinCap({ iat: NOW - 60 }));
    const r = await applyCircleBundle(store, { circles: [], joins: [long], ops: [] }, { ...ctx, self });
    expect(r.joins[0]).toMatchObject({ status: "rejected", reason: "cap-invalid" });
    const stranger = makeUser("stranger");
    const st = await storeKnowing(stranger);
    const sj = await verifyMembershipStatement(
      createMembershipStatement(stranger.signer(), { cid: g.cid, n: 0, op: "join", at: g.hash, cap: stranger.joinCap({ iat: NOW - 60 }), iat: NOW - 1 }),
      ctxFor(st),
    );
    const chain = CircleChain.fromStored((await store.getCircle(g.cid))!.chain);
    expect(decideOpenJoin(chain, sj, {}, { acceptedAt: [] }, { removed: [], now: NOW })).toEqual({ decision: "ignore", reason: "cap-too-long" });
  });

  it("returns the re-sign and revoke actions: after a removal, near expiry, and when a cap outlives 14 days", async () => {
    const { owner, carol, bob, ctx, stmt } = await openCircle();
    // Bob's own store: Bob joined with a short cap.
    const bobStore = await storeKnowing(owner, carol, bob);
    const g2 = createCircle(owner.ik, { name: "open2", members: [carol.userId, bob.userId], policy: "open", iat: NOW - 1000 });
    const chain2 = await storeOfferedCircle(bobStore, [g2], { now: NOW });
    const bobJoin = await verifyMembershipStatement(
      createMembershipStatement(bob.signer(), { cid: chain2.cid, n: 0, op: "join", at: chain2.head.hash, cap: bob.joinCap({ ttlSec: OPEN_JOIN_CAP_MAX_TTL_SEC, iat: NOW - 60 }), iat: NOW - 50 }),
      ctxFor(bobStore),
    );
    await recordOwnJoin(bobStore, bob.userId, bobJoin);
    expect(await openCircleCapActions(bobStore, bob.userId, NOW)).toEqual([]);
    // Near expiry: renew.
    const soon = await openCircleCapActions(bobStore, bob.userId, NOW + OPEN_JOIN_CAP_MAX_TTL_SEC - DAYS(2));
    expect(soon.map((a) => a.reason)).toEqual(["renew"]);
    // The owner removes Carol: re-key at once and revoke the old capid.
    const carolJoin = createMembershipStatement(carol.signer(), { cid: chain2.cid, n: 0, op: "join", at: chain2.head.hash, cap: carol.joinCap({ ttlSec: OPEN_JOIN_CAP_MAX_TTL_SEC, iat: NOW - 60 }), iat: NOW - 40 });
    await applyCircleBundle(bobStore, { circles: [], joins: [carolJoin], ops: [] }, { ...ctxFor(bobStore), self: bob.userId });
    const v2 = createNextCircleVersion(owner.ik, chain2.head, { members: [owner.userId, bob.userId], iat: NOW - 10 });
    await applyCircleBundle(bobStore, { circles: [v2], joins: [], ops: [] }, { ...ctxFor(bobStore), self: bob.userId, now: NOW });
    const acts = await openCircleCapActions(bobStore, bob.userId, NOW + 1);
    expect(acts).toHaveLength(1);
    expect(acts[0]).toMatchObject({ reason: "removal", nextN: 1, at: jwsHash(v2), capTtlSec: OPEN_JOIN_CAP_MAX_TTL_SEC });
    expect(acts[0].revoke).toEqual({ capid: bobJoin.joinCap!.capid, relays: [RELAY] });
    void stmt;
    void ctx;
  });

  it("a circle that becomes open asks members holding a 90-day cap to re-sign", async () => {
    const owner = makeUser("owen");
    const bob = makeUser("bob");
    const bobStore = await storeKnowing(owner, bob);
    const g = createCircle(owner.ik, { name: "c", members: [bob.userId], iat: NOW - 1000 });
    const chain = await storeOfferedCircle(bobStore, [g], { now: NOW });
    await recordOwnJoin(
      bobStore,
      bob.userId,
      await verifyMembershipStatement(createMembershipStatement(bob.signer(), { cid: chain.cid, n: 0, op: "join", at: chain.head.hash, cap: bob.joinCap(), iat: NOW - 50 }), ctxFor(bobStore)),
    );
    expect(await openCircleCapActions(bobStore, bob.userId, NOW)).toEqual([]);
    const opened = createNextCircleVersion(owner.ik, chain.head, { policy: "open", iat: NOW - 10 });
    await applyCircleBundle(bobStore, { circles: [opened], joins: [], ops: [] }, { ...ctxFor(bobStore), self: bob.userId });
    expect((await openCircleCapActions(bobStore, bob.userId, NOW)).map((a) => a.reason)).toEqual(["too-long"]);
  });
});

// ---------------------------------------------------------------------------
// Circle chain lows

function transferTo(owner: TestUser, head: VerifiedCircleVersion, to: TestUser): string {
  const transfer = createCircleTransferAccept(to.ik, { cid: head.cid, ver: head.ver + 1, prev: head.hash, iat: NOW });
  return createNextCircleVersion(owner.ik, head, { members: [...new Set([...head.members, to.userId])], newOwner: { userId: to.userId, ik: b64uEncode(to.ik.publicKey), transfer }, iat: NOW });
}

/** v1 → v2 → v3 (transfer to Bob) → v4 (Bob), plus the old owner's v2' sibling of v2 with a lower hash than v2. */
function preTransferSibling() {
  const owner = makeUser("owen");
  const bob = makeUser("bob");
  const g = verifyCircleGenesis(createCircle(owner.ik, { name: "c", members: [bob.userId], iat: NOW - 1000 }));
  for (let k = 0; ; k++) {
    const v2 = CircleChain.bootstrap([g.jws, createNextCircleVersion(owner.ik, g, { name: `v2-${k}`, iat: NOW })]).head;
    const v2b = createNextCircleVersion(owner.ik, g, { name: `rewrite-${k}`, members: [owner.userId], iat: NOW });
    if (asciiCompare(jwsHash(v2b), v2.hash) >= 0) continue; // we want the rewrite to have the LOWER hash
    const c = CircleChain.bootstrap([g.jws, v2.jws]);
    const v3 = transferTo(owner, v2, bob);
    c.receive(v3);
    const v4 = createNextCircleVersion(bob.ik, c.head, { name: "bob's", iat: NOW });
    return { owner, bob, g, v2: v2.jws, v2b, v3, v4 };
  }
}

describe("L1: bootstrap applies transfer finality (H1/R1 with a sibling before the transfer)", () => {
  it("every arrival order and bootstrap reach the transfer branch, even against a lower-hash sibling before it", () => {
    const { g, v2, v2b, v3, v4, bob } = preTransferSibling();
    const want = [g.jws, v2, v3, v4];
    // Incremental, in the honest order: v2b arrives last and is final history.
    const c1 = CircleChain.bootstrap([g.jws]);
    c1.receive([v2, v3, v4]);
    const r = c1.receive(v2b)[0];
    expect(r.status).toBe("ignored");
    expect(c1.versions.map((v) => v.jws)).toEqual(want);
    // Incremental, the rewrite first: it wins against v2 until the transfer branch completes.
    const c2 = CircleChain.bootstrap([g.jws]);
    c2.receive(v2b);
    c2.receive(v2);
    expect(c2.head.jws).toBe(v2b);
    expect(c2.receive(v3)[0].status).toBe("replaced");
    c2.receive(v4);
    expect(c2.versions.map((v) => v.jws)).toEqual(want);
    // Bootstrap with the sibling supplied, in any order.
    for (const order of [[v2b, v2, v3, v4], [v4, v3, v2, v2b], [v2, v2b, v4, v3]]) {
      const b = CircleChain.bootstrap([g.jws, ...order]);
      expect(b.versions.map((v) => v.jws)).toEqual(want);
      expect(b.head.owner).toBe(bob.userId);
    }
  });

  it("a stored chain keeps its off-chain versions, so the branch can still complete after a restart", () => {
    const { g, v2, v2b, v3, v4 } = preTransferSibling();
    const c = CircleChain.bootstrap([g.jws]);
    c.receive([v2b, v2]);
    const restored = CircleChain.fromStored(c.toStored());
    restored.receive([v3, v4]);
    expect(restored.head.jws).toBe(v4);
  });
});

describe("L2: pending versions can't be filled with junk", () => {
  it("refuses versions not signed by a known owner, or too far ahead; evicts the oldest first", () => {
    const owner = makeUser("owen");
    const mallory = makeUser("mallory");
    const g = verifyCircleGenesis(createCircle(owner.ik, { name: "c", iat: NOW - 1000 }));
    const c = CircleChain.bootstrap([g.jws]);
    const p = decodeJws(g.jws).payload;
    const forge = (ver: number, sk: Uint8Array, salt = "") => signJws("p2p-circle+jws", "ik", { ...p, ver, prev: jwsHash(`missing${salt}`), name: `x${salt}` }, sk);
    expect(c.receive(forge(3, mallory.ik.secretKey))[0]).toMatchObject({ status: "ignored", reason: "not signed by a known owner" });
    expect(c.receive(forge(2 + MAX_PENDING_AHEAD, owner.ik.secretKey))[0]).toMatchObject({ status: "ignored", reason: "too far ahead of the head" });
    expect(c.receive(forge(1 + MAX_PENDING_AHEAD, owner.ik.secretKey))[0].status).toBe("gap");
    for (let i = 0; i < MAX_PENDING_VERSIONS + 5; i++) c.receive(forge(3, owner.ik.secretKey, String(i)));
    expect(c.pendingCount).toBe(MAX_PENDING_VERSIONS);
  });

  it("accepts pending versions from an owner a pending transfer hands over to", () => {
    const owner = makeUser("owen");
    const bob = makeUser("bob");
    const g = verifyCircleGenesis(createCircle(owner.ik, { name: "c", members: [bob.userId], iat: NOW - 1000 }));
    const v2 = createNextCircleVersion(owner.ik, g, { iat: NOW });
    const v2v = CircleChain.bootstrap([g.jws, v2]).head;
    const v3 = transferTo(owner, v2v, bob);
    const v4 = createNextCircleVersion(bob.ik, CircleChain.bootstrap([g.jws, v2, v3]).head, { iat: NOW });
    const c = CircleChain.bootstrap([g.jws]);
    expect(c.receive(v3)[0].status).toBe("gap");
    expect(c.receive(v4)[0].status).toBe("gap");
    c.receive(v2);
    expect(c.head.jws).toBe(v4);
  });
});

describe("L3: the rule-2 owner freshness check is on by default in the store paths", () => {
  it("applyCircleBundle refuses a new head from an owner more than 60 days past exp", async () => {
    const owner = makeUser("owen");
    const bob = makeUser("bob");
    const store = await storeKnowing(owner, bob);
    const g = createCircle(owner.ik, { name: "c", members: [bob.userId], iat: NOW - 1000 });
    const chain = await storeOfferedCircle(store, [g], { now: NOW });
    const v2 = createNextCircleVersion(owner.ik, chain.head, { iat: NOW });
    const later = owner.doc.exp + DAYS(61);
    const r = await applyCircleBundle(store, { circles: [v2], joins: [], ops: [] }, { ...ctxFor(store, later), self: bob.userId });
    expect(r.versions[chain.cid][0]).toMatchObject({ status: "rejected", reason: "circle-owner-unavailable" });
    const ok = await applyCircleBundle(store, { circles: [v2], joins: [], ops: [] }, { ...ctxFor(store, NOW), self: bob.userId });
    expect(ok.versions[chain.cid][0].status).toBe("accepted");
    // Bootstrapping an offered circle checks it too.
    await expect(storeOfferedCircle(new MemoryTrustStoreV3(), [g], { now: NOW })).resolves.toBeDefined();
    const fresh = await storeKnowing(owner);
    await expect(storeOfferedCircle(fresh, [g, v2], { now: later })).rejects.toThrow(/circle-owner-unavailable/);
  });
});

describe("L4: applyOwnerProposals is atomic", () => {
  it("two concurrent runs apply each proposal once", async () => {
    const owner = makeUser("owen");
    const dave = makeUser("dave");
    const carol = makeUser("carol");
    const store = await storeKnowing(owner, dave, carol);
    const g = createCircle(owner.ik, { name: "c", members: [dave.userId, carol.userId], admins: [dave.userId], iat: NOW - 1000 });
    const chain = await storeOfferedCircle(store, [g], { now: NOW });
    const op = createProposal(dave.signer(), { cid: chain.cid, base: 1, op: "remove", target: carol.userId, iat: NOW - 10 });
    await applyCircleBundle(store, { circles: [], joins: [], ops: [op] }, { ...ctxFor(store), self: owner.userId });
    const [a, b] = await Promise.all([applyOwnerProposals(store, chain.cid, ctxFor(store)), applyOwnerProposals(store, chain.cid, ctxFor(store))]);
    const applied = [...a!.results, ...b!.results].filter((x) => x.status === "applied");
    expect(applied).toHaveLength(1);
    expect((await store.getCircle(chain.cid))?.proposals).toEqual([]);
    void applyProposals;
  });
});

describe("L6: recordOwnJoin records only the viewer's own statement", () => {
  it("refuses someone else's join", async () => {
    const owner = makeUser("owen");
    const bob = makeUser("bob");
    const store = await storeKnowing(owner, bob);
    const g = createCircle(owner.ik, { name: "c", members: [bob.userId], iat: NOW - 1000 });
    const chain = await storeOfferedCircle(store, [g], { now: NOW });
    const ownersJoin = await verifyMembershipStatement(
      createMembershipStatement(owner.signer(), { cid: chain.cid, n: 0, op: "join", at: chain.head.hash, cap: owner.joinCap(), iat: NOW - 5 }),
      ctxFor(store),
    );
    await expect(recordOwnJoin(store, bob.userId, ownersJoin)).rejects.toThrow(/cert-mismatch/);
    expect((await store.getCircle(chain.cid))?.joinedByMe).toBe(false);
  });
});

describe("L7: path segments of dots and spaces, and colons", () => {
  it("rejects them", () => {
    for (const bad of ["a/.../b", "a/.. /b", "a/ ./b", "a/   /b", "...", "a:b", "dir/file.txt:stream", "x/C:/y"]) expect(isSafeRelativePath(bad)).toBe(false);
    for (const ok of ["a/.hidden", "a/b.c", "a/ spaced name/b", "a..b/c"]) expect(isSafeRelativePath(ok)).toBe(true);
    expect(sanitizeFiles(["ok.ts", "a/../b", ".. ", "f:x"])).toEqual(["ok.ts"]);
  });
});

describe("L8: unanchored roots", () => {
  it("a client holding only an unanchored root replaces it with a higher-ver version that doesn't chain", () => {
    const a = makeUser("alice");
    a.addDevice();
    const v2 = a.publish();
    a.publish();
    const v4 = a.publish();
    const c = new IdentityChain(a.userId);
    expect(c.add(v2.jws, { now: NOW })).toMatchObject({ status: "accepted", unanchored: true });
    expect(c.anchored).toBe(false);
    expect(c.add(v4.jws, { now: NOW })).toMatchObject({ status: "accepted", replacedUnanchored: true });
    expect(c.view().head.hash).toBe(v4.hash);
    expect(c.size).toBe(1);
  });

  it("anchored history is never replaced this way", () => {
    const a = makeUser("alice");
    const v1 = a.doc;
    a.publish();
    const v3 = a.publish();
    const c = new IdentityChain(a.userId);
    c.add(v1.jws, { now: NOW });
    expect(c.anchored).toBe(true);
    expect(c.add(v3.jws, { now: NOW }).status).toBe("gap");
  });
});

describe("L9: certificates are verified before ranking; revocations are keyed by issuer", () => {
  it("longestLived never prefers an invalid certificate with a later exp", () => {
    const a = makeUser("alice");
    const mallory = makeUser("mallory");
    const p = decodeJws(a.dev.cert).payload;
    const forged = signJws("p2p-device+jws", "ik", { ...p, iat: NOW, exp: NOW + DAYS(90) }, mallory.ik.secretKey);
    expect(longestLived([forged, a.dev.cert], { now: NOW })).toBe(a.dev.cert);
    const renewed = createDeviceCert(a.ik, a.dev, { iat: NOW });
    expect(longestLived([a.dev.cert, renewed], { now: NOW })).toBe(renewed);
    // None valid: the latest exp comes back so the caller reports why.
    expect(longestLived([forged], { now: NOW })).toBe(forged);
  });

  it("isRevoked takes (iss, capid)", () => {
    const bob = makeUser("bob");
    const alice = makeUser("alice");
    const cap = bob.friendCap(alice.userId);
    const capid = decodeJws(cap).payload.capid as string;
    const seen: string[] = [];
    const isRevoked = (iss: string, id: string) => (seen.push(`${iss}|${id}`), iss === "p2p:" + "x".repeat(52) && id === capid);
    expect(verifyCapForSend(cap, { relayUrl: RELAY, to: bob.userId, envFrom: alice.userId, kind: "msg", now: NOW, isRevoked }).capid).toBe(capid);
    expect(seen).toEqual([`${bob.userId}|${capid}`]);
    expect(() => verifyCapForSend(cap, { relayUrl: RELAY, to: bob.userId, envFrom: alice.userId, kind: "msg", now: NOW, isRevoked: (iss, id) => iss === bob.userId && id === capid })).toThrow(/revoked/);
  });
});
