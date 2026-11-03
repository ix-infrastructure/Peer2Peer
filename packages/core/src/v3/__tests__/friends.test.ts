// Copyright 2026 Ix Infrastructure Inc.
//
// §3.1 friends: v2 invite, accept and unfriend semantics on v3 ids and
// certificates (v2 C4, H1), the new invite fields, invite links; ported
// from the v2 security tests and run end to end through verifyIncomingV3.

import { describe, expect, it } from "vitest";
import {
  createAcceptV3,
  createInviteV3,
  createUnfriendV3,
  inviteHashV3,
  inviteIatAfterUnfriends,
  inviteLink,
  parseInviteLink,
  unfriendApplies,
  unfriendEndingInvite,
  verifyFriendshipV3,
  verifyInviteV3,
  verifyUnfriendV3,
} from "../friends.js";
import { createCap } from "../caps.js";
import { createRosterV3 } from "../roster.js";
import { recordFriendshipV3 } from "../state.js";
import { verifyIncomingV3 } from "../incoming.js";
import { b64uEncode } from "../../encoding.js";
import { randomBytes } from "../../crypto.js";
import type { MemoryTrustStoreV3 } from "../store.js";
import { DAYS, ctxFor, makeUser, NOW, RELAY, seal, staticCtx, storeKnowing, type TestUser } from "./fixtures.js";

describe("§3.1 invites and accepts (v2 C4 on v3 ids)", () => {
  it("invite + accept -> friendship", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const invite = createInviteV3(b.signer(), { aud: a.userId, iat: NOW - 100 });
    const accept = createAcceptV3(a.signer(), invite, { iat: NOW - 50 });
    const f = await verifyFriendshipV3({ invite, accept }, staticCtx([a, b]));
    expect([f.inviter, f.invitee, f.inv]).toEqual([b.userId, a.userId, inviteHashV3(invite)]);
  });

  it("aud '*' binds any accepter; explicit aud binds only that user; no self-friendship", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const c = makeUser("carol");
    const ctx = staticCtx([a, b, c]);
    const star = createInviteV3(b.signer(), { aud: "*", iat: NOW - 100 });
    expect((await verifyFriendshipV3({ invite: star, accept: createAcceptV3(c.signer(), star, { iat: NOW - 50 }) }, ctx)).invitee).toBe(c.userId);
    const forA = createInviteV3(b.signer(), { aud: a.userId, iat: NOW - 100 });
    await expect(verifyFriendshipV3({ invite: forA, accept: createAcceptV3(c.signer(), forA, { iat: NOW - 50 }) }, ctx)).rejects.toThrow(/audience-mismatch/);
    await expect(verifyFriendshipV3({ invite: star, accept: createAcceptV3(b.signer(), star, { iat: NOW - 50 }) }, ctx)).rejects.toThrow(/self-friendship/);
  });

  it("an accept after invite expiry, or before it was issued, is rejected; the invite must hash", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const ctx = staticCtx([a, b]);
    const invite = createInviteV3(b.signer(), { aud: a.userId, iat: NOW - DAYS(15), ttlSec: DAYS(14) });
    await expect(verifyFriendshipV3({ invite, accept: createAcceptV3(a.signer(), invite, { iat: NOW - 10 }) }, ctx)).rejects.toThrow(/invite-expired/);
    const fresh = createInviteV3(b.signer(), { aud: a.userId, iat: NOW - 100 });
    await expect(verifyFriendshipV3({ invite: fresh, accept: createAcceptV3(a.signer(), fresh, { iat: NOW - 1000 }) }, ctx)).rejects.toThrow(/before the invite/);
    const other = createInviteV3(b.signer(), { aud: a.userId, iat: NOW - 100 });
    await expect(verifyFriendshipV3({ invite: fresh, accept: createAcceptV3(a.signer(), other, { iat: NOW - 50 }) }, ctx)).rejects.toThrow(/invite-mismatch/);
    expect(() => createInviteV3(b.signer(), { aud: a.userId, ttlSec: DAYS(15) })).toThrow(/14d/);
    await expect(verifyInviteV3(invite, ctx)).rejects.toThrow(/invite-expired/);
  });

  it("C4: revoking either signing device ends the friendship (rule 6 now)", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const laptop = b.addDevice({ keyholder: false });
    b.publish();
    const invite = createInviteV3(b.signer(laptop), { aud: a.userId, iat: NOW - 100 });
    const proof = { invite, accept: createAcceptV3(a.signer(), invite, { iat: NOW - 50 }) };
    expect((await verifyFriendshipV3(proof, staticCtx([a, b]))).inviter).toBe(b.userId);
    b.publish({ devices: [b.dev.did] });
    await expect(verifyFriendshipV3(proof, staticCtx([a, b]))).rejects.toThrow(/device-not-listed/);
  });

  it("[v3] invite fields: ik, relays, doc and a contact-only cap let a stranger reach the inviter", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const cap = createCap(b.dev, b.dev.cert, { purpose: "contact", sub: a.userId, relays: [RELAY], iat: NOW - 10 });
    const invite = createInviteV3(b.signer(), { aud: a.userId, iat: NOW - 100, ik: b.doc.ik, relays: [RELAY], doc: b.doc.jws, cap });
    // Alice knows nothing about Bob: no certificates, no documents.
    const empty = { now: NOW, resolveCert: () => undefined, resolveIdentity: () => undefined };
    const v = await verifyInviteV3(invite, empty);
    expect(v.inviterDoc?.iss).toBe(b.userId);
    expect(v.contactCap?.kinds).toEqual(["contact"]);
    // A doc of someone else, or a full cap, is refused.
    const m = makeUser("mallory");
    await expect(verifyInviteV3(createInviteV3(b.signer(), { aud: a.userId, iat: NOW - 100, doc: m.doc.jws }), empty)).rejects.toThrow(/another identity/);
    const full = b.friendCap(a.userId);
    await expect(verifyInviteV3(createInviteV3(b.signer(), { aud: a.userId, iat: NOW - 100, doc: b.doc.jws, cap: full }), empty)).rejects.toThrow(/cap-invalid/);
    expect(() => createInviteV3(b.signer(), { aud: a.userId, ik: m.doc.ik })).toThrow(/issuer-mismatch/);
  });

  it("invite links: p2p://invite/ and the web fragment form", () => {
    const b = makeUser("bob");
    const invite = createInviteV3(b.signer(), { aud: "*", iat: NOW });
    expect(inviteLink(invite)).toMatch(/^p2p:\/\/invite\/[A-Za-z0-9_-]+$/);
    expect(parseInviteLink(inviteLink(invite))).toBe(invite);
    expect(parseInviteLink(inviteLink(invite, { web: true }))).toBe(invite);
    expect(inviteLink(invite, { web: true })).toMatch(/^https:\/\/ix-infra\.com\/p2p\/i#/);
    // The deprecated web form still parses (older clients printed it); it is never generated.
    expect(parseInviteLink(inviteLink(invite, { web: true }).replace("https://ix-infra.com/p2p/i#", "https://peer2peer.dev/i#"))).toBe(invite);
    expect(() => parseInviteLink("https://evil.example/i#abc")).toThrow(/not an invite link/);
  });

  it("unfriend round-trips and applies (H1: the named invite, and any invite issued at or before it)", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const inv = b64uEncode(randomBytes(32));
    const u = await verifyUnfriendV3(createUnfriendV3(b.signer(), { peer: a.userId, inv, iat: NOW }), staticCtx([a, b]));
    expect(unfriendApplies({ inviter: b.userId, invitee: a.userId, inv, inviteIat: NOW + 100 }, u)).toBe(true);
    expect(unfriendApplies({ inviter: a.userId, invitee: b.userId, inv: "other", inviteIat: NOW }, u)).toBe(true);
    expect(unfriendApplies({ inviter: a.userId, invitee: b.userId, inv: "other", inviteIat: NOW + 1 }, u)).toBe(false);
    expect(() => createUnfriendV3(b.signer(), { peer: "bob@x.com", inv })).toThrow(/v3 userId/);
  });
});

describe("re-friending after an unfriend (same second, clock skew)", () => {
  it("a new invite is dated after every unfriend known for the pair, so it is never refused by the rule", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const c = makeUser("carol");
    const ctx = staticCtx([a, b, c]);
    const old = createInviteV3(a.signer(), { aud: b.userId, iat: NOW - 100 });
    const oldF = await verifyFriendshipV3({ invite: old, accept: createAcceptV3(b.signer(), old, { iat: NOW - 90 }) }, ctx);
    // Bob unfriends in the same second Alice then re-invites (and, below, with his clock 120 s ahead).
    for (const ahead of [0, 120]) {
      const u = await verifyUnfriendV3(createUnfriendV3(b.signer(), { peer: a.userId, inv: oldF.inv, iat: NOW + ahead }), staticCtx([a, b], NOW + ahead));
      // Without the floor the invite (iat NOW) is ended by the unfriend it follows.
      const naive = createInviteV3(a.signer(), { aud: b.userId, iat: NOW });
      const naiveF = await verifyFriendshipV3({ invite: naive, accept: createAcceptV3(b.signer(), naive, { iat: NOW + ahead }) }, staticCtx([a, b], NOW + ahead));
      expect(unfriendApplies(naiveF, u)).toBe(true);
      expect(unfriendEndingInvite({ iss: a.userId, iat: NOW }, b.userId, [u])).toEqual(u);
      const iat = inviteIatAfterUnfriends(a.userId, b.userId, [u], NOW);
      expect(iat).toBe(NOW + ahead + 1);
      const fresh = createInviteV3(a.signer(), { aud: b.userId, iat });
      const f = await verifyFriendshipV3({ invite: fresh, accept: createAcceptV3(b.signer(), fresh, { iat: NOW + ahead + 1 }) }, staticCtx([a, b], NOW + ahead + 1));
      expect(unfriendApplies(f, u)).toBe(false);
      expect(unfriendEndingInvite({ iss: a.userId, iat }, b.userId, [u])).toBeUndefined();
      // The old invite still never resurrects the friendship (the rule's purpose).
      expect(unfriendApplies(oldF, u)).toBe(true);
    }
    // Only the pair counts for a named invite; "*" can reach anyone, so every unfriend of ours counts.
    const withCarol = { iss: c.userId, peer: a.userId, iat: NOW + 50 };
    expect(inviteIatAfterUnfriends(a.userId, b.userId, [withCarol], NOW)).toBe(NOW);
    expect(inviteIatAfterUnfriends(a.userId, "*", [withCarol], NOW)).toBe(NOW + 51);
    expect(inviteIatAfterUnfriends(a.userId, "*", [{ iss: b.userId, peer: c.userId, iat: NOW + 50 }], NOW)).toBe(NOW);
    // Older unfriends change nothing.
    expect(inviteIatAfterUnfriends(a.userId, b.userId, [{ iss: a.userId, peer: b.userId, iat: NOW - 5 }], NOW)).toBe(NOW);
  });
});

// ---------------------------------------------------------------------------
// H1 end to end (ported from the v2 security tests)

async function receive(store: MemoryTrustStoreV3, to: TestUser, env: string, nowMs = NOW * 1000) {
  return verifyIncomingV3(env, { self: { userId: to.userId, did: to.dev.did, agreementSecretKey: to.dev.agreementSecretKey, cert: to.dev.cert }, store, nowMs });
}

function outcome(r: Awaited<ReturnType<typeof receive>>): string {
  return r.ok ? (r.viewerRule ? `${r.rule}/${r.viewerRule}` : r.rule) : r.reason;
}

async function setupH1() {
  const alice = makeUser("alice");
  const bob = makeUser("bob");
  const store = await storeKnowing(alice, bob);
  const inv1 = createInviteV3(bob.signer(), { aud: alice.userId, iat: NOW - DAYS(3) });
  const invStar = createInviteV3(bob.signer(), { aud: "*", iat: NOW - DAYS(3) + 10 });
  const acc1 = createAcceptV3(alice.signer(), inv1, { iat: NOW - DAYS(3) + 60 });
  await recordFriendshipV3(store, await verifyFriendshipV3({ invite: inv1, accept: acc1 }, ctxFor(store)));
  const rosterBob = createRosterV3(bob.signer(), { sid: "s1", ver: 1, vis: "private", parts: [alice.userId, bob.userId], iat: NOW - DAYS(3) });
  const rosterAlice = createRosterV3(alice.signer(), { sid: "s1", ver: 1, vis: "private", parts: [alice.userId, bob.userId], iat: NOW - DAYS(3) });
  const unfriend = async () => {
    const T1 = NOW - DAYS(1);
    const inv = inviteHashV3(inv1);
    await store.addUnfriend({ iss: bob.userId, peer: alice.userId, inv, iat: T1, jws: createUnfriendV3(bob.signer(), { peer: alice.userId, inv, iat: T1 }) });
  };
  return { alice, bob, store, inv1, invStar, acc1, rosterBob, rosterAlice, unfriend };
}

describe("H1: an unfriend can't be undone by re-signing an accept", () => {
  it("before the unfriend, a friend in parts is accepted both ways", async () => {
    const { alice, bob, store, rosterAlice } = await setupH1();
    expect(outcome(await receive(store, bob, seal(alice, bob, "msg", { text: "hi", roster: rosterAlice })))).toBe("owner/participant-friend");
  });

  it("rejects a fresh accept for a burned invite (viewer side)", async () => {
    const { alice, bob, store, inv1, rosterAlice, unfriend } = await setupH1();
    await unfriend();
    expect(outcome(await receive(store, bob, seal(alice, bob, "msg", { text: "hi", roster: rosterAlice })))).toBe("viewer-unfriended");
    const accept2 = createAcceptV3(alice.signer(), inv1, { iat: NOW });
    const r = await receive(store, bob, seal(alice, bob, "msg", { text: "hi", roster: rosterAlice, friendship: { invite: inv1, accept: accept2 } }));
    expect(outcome(r)).toBe("viewer-unfriended");
    expect((await store.listFriendships()).filter((f) => f.inv === inviteHashV3(inv1))).toHaveLength(1);
  });

  it("a re-signed accept for the named invite doesn't satisfy the sender side", async () => {
    const { alice, bob, store, inv1, rosterBob, unfriend } = await setupH1();
    await unfriend();
    const friendship = { invite: inv1, accept: createAcceptV3(alice.signer(), inv1, { iat: NOW }) };
    const r = await receive(store, bob, seal(alice, bob, "msg", { text: "hi", roster: rosterBob, friendship }, { own: bob.userId }));
    expect(outcome(r)).toBe("unfriended");
  });

  it("another invite issued before the unfriend (a '*' code) can't re-friend", async () => {
    const { alice, bob, store, invStar, rosterBob, rosterAlice, unfriend } = await setupH1();
    await unfriend();
    const fStar = { invite: invStar, accept: createAcceptV3(alice.signer(), invStar, { iat: NOW }) };
    expect(outcome(await receive(store, bob, seal(alice, bob, "msg", { text: "x", roster: rosterBob, friendship: fStar }, { own: bob.userId })))).toBe("unfriended");
    expect(outcome(await receive(store, bob, seal(alice, bob, "msg", { text: "x", roster: rosterAlice, friendship: fStar })))).toBe("viewer-unfriended");
    await expect(recordFriendshipV3(store, await verifyFriendshipV3(fStar, ctxFor(store)))).rejects.toThrow(/unfriended/);
  });

  it("the viewer's standing ignores sender-presented friendships", async () => {
    const alice = makeUser("alice");
    const bob = makeUser("bob");
    const store = await storeKnowing(alice, bob); // no stored friendship
    const invite = createInviteV3(bob.signer(), { aud: alice.userId, iat: NOW - 100 });
    const friendship = { invite, accept: createAcceptV3(alice.signer(), invite, { iat: NOW - 50 }) };
    const roster = createRosterV3(alice.signer(), { sid: "s1", ver: 1, vis: "private", parts: [alice.userId, bob.userId], iat: NOW - 100 });
    expect(outcome(await receive(store, bob, seal(alice, bob, "msg", { text: "x", roster, friendship })))).toBe("viewer-no-friendship");
  });

  it("an unfriend-kind or sync-kind envelope can't plant a friendship", async () => {
    const { alice, bob, store, invStar, rosterAlice, unfriend } = await setupH1();
    await unfriend();
    const before = (await store.listFriendships()).length;
    const bogus = createUnfriendV3(alice.signer(), { peer: bob.userId, inv: b64uEncode(randomBytes(32)), iat: NOW });
    expect(outcome(await receive(store, bob, seal(alice, bob, "unfriend", { text: bogus })))).toBe("unfriend");
    expect(outcome(await receive(store, bob, seal(alice, bob, "sync", { friendship: { invite: invStar } })))).toBe("not-participant");
    expect(await store.listFriendships()).toHaveLength(before);
    expect(outcome(await receive(store, bob, seal(alice, bob, "msg", { text: "x", roster: rosterAlice })))).toBe("viewer-unfriended");
    expect(await store.getRoster(alice.userId, "s1")).toBeUndefined();
  });

  it("a genuinely new invite after the unfriend re-friends", async () => {
    const { alice, bob, store, rosterAlice, unfriend } = await setupH1();
    await unfriend();
    const inv3 = createInviteV3(bob.signer(), { aud: alice.userId, iat: NOW - 60 });
    await recordFriendshipV3(store, await verifyFriendshipV3({ invite: inv3, accept: createAcceptV3(alice.signer(), inv3, { iat: NOW - 30 }) }, ctxFor(store)));
    expect(outcome(await receive(store, bob, seal(alice, bob, "msg", { text: "x", roster: rosterAlice })))).toBe("owner/participant-friend");
  });

  it("an '*' invite already bound to someone else is refused", async () => {
    const alice = makeUser("alice");
    const bob = makeUser("bob");
    const carol = makeUser("carol");
    const store = await storeKnowing(alice, bob, carol);
    const star = createInviteV3(bob.signer(), { aud: "*", iat: NOW - 100 });
    await recordFriendshipV3(store, await verifyFriendshipV3({ invite: star, accept: createAcceptV3(alice.signer(), star, { iat: NOW - 50 }) }, ctxFor(store)));
    const second = await verifyFriendshipV3({ invite: star, accept: createAcceptV3(carol.signer(), star, { iat: NOW - 40 }) }, ctxFor(store));
    await expect(recordFriendshipV3(store, second)).rejects.toThrow(/invite-already-bound/);
  });
});
