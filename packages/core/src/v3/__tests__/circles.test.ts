// Copyright 2026 Ix Infrastructure Inc.
//
// §3.3 circles: version rules 1–4, single owner and transfers, replacement
// and finality, transfer equivocation, lowest-jwsHash siblings, full-chain
// bootstrap, membership statements, proposals, standing, and the Phase 2
// open-community additions. Attack tests are named after the review
// findings (C1, H1/R1, R2, N4, review 5–7).

import { describe, expect, it } from "vitest";
import {
  applyMembership,
  applyProposals,
  chainsConsistent,
  CircleChain,
  circleInviteLink,
  compareMembership,
  confirmJoin,
  createCircle,
  createCircleTransferAccept,
  createMembershipStatement,
  createNextCircleVersion,
  createProposal,
  decideOpenJoin,
  describeCircleInvite,
  membershipFact,
  membershipNeedsResign,
  parseCircleInviteLink,
  pickConfirmers,
  standsInCircle,
  verifyCircleGenesis,
  verifyCircleLink,
  verifyCircleVersionAlone,
  verifyMembershipStatement,
  verifyProposal,
  type MembershipBook,
  type VerifiedCircleVersion,
  type VerifiedMembership,
} from "../circles.js";
import { asciiCompare, circleIdFor, HOUR, jwsHash } from "../base.js";
import { b64uEncode } from "../../encoding.js";
import { decodeJws, signJws } from "../../jws.js";
import { ctxFor, DAYS, makeUser, NOW, storeKnowing, type TestUser } from "./fixtures.js";
import { storeSignerContext } from "../state.js";

function v(jws: string, parent?: VerifiedCircleVersion): VerifiedCircleVersion {
  return parent ? verifyCircleLink(parent, jws) : verifyCircleGenesis(jws);
}

function transferTo(owner: TestUser, head: VerifiedCircleVersion, to: TestUser, extra: { members?: string[]; iat?: number } = {}): string {
  const transfer = createCircleTransferAccept(to.ik, { cid: head.cid, ver: head.ver + 1, prev: head.hash, iat: NOW });
  const members = extra.members ?? [...new Set([...head.members, to.userId])];
  return createNextCircleVersion(owner.ik, head, { members, newOwner: { userId: to.userId, ik: b64uEncode(to.ik.publicKey), transfer }, iat: extra.iat ?? NOW });
}

function setup() {
  const owner = makeUser("owen");
  const bob = makeUser("bob");
  const carol = makeUser("carol");
  const dave = makeUser("dave");
  const g = v(createCircle(owner.ik, { name: "team", members: [bob.userId, carol.userId, dave.userId], admins: [dave.userId], iat: NOW - 1000 }));
  return { owner, bob, carol, dave, g };
}

describe("verifyCircleVersionAlone (a P4 code's preview)", () => {
  it("verifies a genesis and a later version by the owner it names; refuses a bad signature and a transfer", () => {
    const { owner, bob, g } = setup();
    expect(verifyCircleVersionAlone(g.jws)).toMatchObject({ cid: g.cid, ver: 1, signer: owner.userId });
    const v2 = createNextCircleVersion(owner.ik, g, { name: "renamed", iat: NOW });
    expect(verifyCircleVersionAlone(v2)).toMatchObject({ ver: 2, name: "renamed", signer: owner.userId });
    // Another key's signature over the same payload.
    const [h, payload] = v2.split(".");
    const forged = `${h}.${payload}.${signJws("x", "y", { a: 1 }, bob.ik.secretKey).split(".")[2]}`;
    expect(() => verifyCircleVersionAlone(forged)).toThrow(/circle-signer|signature/);
    expect(() => verifyCircleVersionAlone(transferTo(owner, g, bob))).toThrow(/only against its parent/);
  });
});

describe("§3.3 version rules", () => {
  it("rule 1–4 hold for a valid genesis and child", () => {
    const { owner, g, bob } = setup();
    expect(g.cid).toBe(circleIdFor(owner.userId, g.nonce));
    expect(g.signer).toBe(owner.userId);
    const v2 = v(createNextCircleVersion(owner.ik, g, { members: g.members.filter((m) => m !== bob.userId), iat: NOW }), g);
    expect(v2.ver).toBe(2);
    expect(v2.prev).toBe(g.hash);
    expect(v2.isTransfer).toBe(false);
  });

  it("rule 1: cid must recompute from founder and nonce", () => {
    const { owner, g } = setup();
    const p = decodeJws(g.jws).payload;
    expect(() => verifyCircleGenesis(signJws("p2p-circle+jws", "ik", { ...p, nonce: b64uEncode(new Uint8Array(16)) }, owner.ik.secretKey))).toThrow(/cid does not recompute/);
  });

  it("rule 2: owner == H(ik), and the version is signed by the owner of ver-1", () => {
    const { owner, g, bob } = setup();
    const p = decodeJws(g.jws).payload;
    expect(() => verifyCircleGenesis(signJws("p2p-circle+jws", "ik", { ...p, ik: b64uEncode(bob.ik.publicKey) }, bob.ik.secretKey))).toThrow(/circle-signer|ver 1 owner/);
    // A child signed by a member, not the owner.
    const child = { ...p, ver: 2, prev: g.hash, name: "pwned" };
    expect(() => verifyCircleLink(g, signJws("p2p-circle+jws", "ik", child, bob.ik.secretKey))).toThrow(/circle-signer/);
    expect(() => createNextCircleVersion(bob.ik, g, {})).toThrow(/only the current owner/);
    void owner;
  });

  it("rule 3: ver 1 needs prev null and owner == founder; later versions chain by prev and never skip", () => {
    const { owner, g } = setup();
    const v2 = v(createNextCircleVersion(owner.ik, g, { iat: NOW }), g);
    const v3jws = createNextCircleVersion(owner.ik, v2, { iat: NOW });
    expect(() => verifyCircleLink(g, v3jws)).toThrow(/circle-chain-broken/);
    const p = decodeJws(v2.jws).payload;
    expect(() => verifyCircleLink(g, signJws("p2p-circle+jws", "ik", { ...p, prev: jwsHash("x") }, owner.ik.secretKey))).toThrow(/circle-chain-broken/);
  });

  it("rule 3: a change of owner needs `transfer`, signed by the new owner over exactly {cid, ver, prev}", () => {
    const { owner, g, bob, carol } = setup();
    const ok = v(transferTo(owner, g, bob), g);
    expect(ok.isTransfer).toBe(true);
    expect(ok.owner).toBe(bob.userId);
    expect(ok.signer).toBe(owner.userId);
    // Without transfer.
    const p = decodeJws(ok.jws).payload;
    const { transfer: _t, ...noTransfer } = p;
    expect(() => verifyCircleLink(g, signJws("p2p-circle+jws", "ik", noTransfer, owner.ik.secretKey))).toThrow(/without transfer/);
    // Consent signed by someone else (carol consents on bob's behalf).
    const byCarol = createCircleTransferAccept(carol.ik, { cid: g.cid, ver: 2, prev: g.hash });
    expect(() => verifyCircleLink(g, signJws("p2p-circle+jws", "ik", { ...p, transfer: byCarol }, owner.ik.secretKey))).toThrow(/circle-transfer/);
    // Consent to another state (a different prev).
    const otherState = createCircleTransferAccept(bob.ik, { cid: g.cid, ver: 2, prev: jwsHash("other") });
    expect(() => verifyCircleLink(g, signJws("p2p-circle+jws", "ik", { ...p, transfer: otherState }, owner.ik.secretKey))).toThrow(/another state/);
    // A transfer field without a change of owner.
    const same = createNextCircleVersion(owner.ik, g, { iat: NOW });
    const sp = decodeJws(same).payload;
    expect(() => verifyCircleLink(g, signJws("p2p-circle+jws", "ik", { ...sp, transfer: byCarol }, owner.ik.secretKey))).toThrow(/without a change of owner/);
  });

  it("rule 4: every admin and the owner are members", () => {
    const { owner, bob } = setup();
    expect(() => createCircle(owner.ik, { name: "x", admins: [bob.userId] })).toThrow(/admin .* is not a member/);
    const g = v(createCircle(owner.ik, { name: "x" }));
    expect(() => createNextCircleVersion(owner.ik, g, { members: [] })).toThrow(/owner must be a member/);
  });
});

describe("§3.3 chain: gaps, bootstrap (R2) and freshness", () => {
  it("a version past a gap is held until the missing ones arrive", () => {
    const { owner, g } = setup();
    const v2 = v(createNextCircleVersion(owner.ik, g, { iat: NOW }), g);
    const v3 = v(createNextCircleVersion(owner.ik, v2, { iat: NOW }), v2);
    const c = CircleChain.bootstrap([g.jws]);
    expect(c.receive(v3.jws)[0]).toMatchObject({ status: "gap", want: { cid: g.cid, fromVer: 2 } });
    expect(c.head.ver).toBe(1);
    expect(c.receive(v2.jws)[0].status).toBe("accepted");
    expect(c.head.hash).toBe(v3.hash);
    expect(c.receive(v3.jws)[0].status).toBe("duplicate");
  });

  it("R2: bootstrap needs the full chain from version 1; a forged head is not on it", () => {
    const { owner, g, bob } = setup();
    const v2 = v(createNextCircleVersion(owner.ik, g, { iat: NOW }), g);
    expect(() => CircleChain.bootstrap([v2.jws])).toThrow(/circle-gap/);
    const c = CircleChain.bootstrap([v2.jws, g.jws], { head: v2.jws });
    expect(c.head.hash).toBe(v2.hash);
    // Bob forges a head claiming the circle: signed with his own key, it can't link.
    const forged = signJws("p2p-circle+jws", "ik", { ...decodeJws(v2.jws).payload, ver: 3, prev: v2.hash, name: "bob's now" }, bob.ik.secretKey);
    expect(() => CircleChain.bootstrap([g.jws, v2.jws, forged], { head: forged })).toThrow(/circle-gap/);
    // Nor does a forged version 1 under the founder's name.
    const fakeGenesis = signJws("p2p-circle+jws", "ik", decodeJws(g.jws).payload, bob.ik.secretKey);
    expect(() => CircleChain.bootstrap([fakeGenesis])).toThrow(/circle-signer/);
    const stored = CircleChain.fromStored(c.toStored());
    expect(stored.head.hash).toBe(v2.hash);
  });

  it("rule 2 freshness: a new head from an owner in the fail-closed state is refused", () => {
    const { owner, g } = setup();
    const c = CircleChain.bootstrap([g.jws]);
    const v2 = createNextCircleVersion(owner.ik, g, { iat: NOW });
    const r = c.receive(v2, { identityFreshness: (u) => (u === owner.userId ? "fail-closed" : "fresh") });
    expect(r[0]).toMatchObject({ status: "rejected", reason: "circle-owner-unavailable" });
    expect(c.receive(v2, { identityFreshness: () => "expired" })[0].status).toBe("accepted");
  });

  it("members catch up when their head is > 72 h older than the newest heard of", () => {
    const { g } = setup();
    const c = CircleChain.bootstrap([g.jws]);
    expect(c.needsCatchUp(g.iat + 72 * HOUR)).toBe(false);
    expect(c.needsCatchUp(g.iat + 72 * HOUR + 1)).toBe(true);
  });
});

describe("§3.3 concurrency: siblings, transfers, finality", () => {
  it("between the current owner's siblings, every client converges on the lowest jwsHash", () => {
    const { owner, g } = setup();
    const a = createNextCircleVersion(owner.ik, g, { name: "a", iat: NOW });
    const b = createNextCircleVersion(owner.ik, g, { name: "b", iat: NOW });
    const low = asciiCompare(jwsHash(a), jwsHash(b)) < 0 ? a : b;
    const c1 = CircleChain.bootstrap([g.jws]);
    const c2 = CircleChain.bootstrap([g.jws]);
    c1.receive(a);
    c1.receive(b);
    c2.receive(b);
    const r = c2.receive(a);
    expect(c1.head.jws).toBe(low);
    expect(c2.head.jws).toBe(low);
    expect(["replaced", "ignored"]).toContain(r[0].status);
    // Bootstrap reaches the same chain from the same set.
    expect(CircleChain.bootstrap([g.jws, a, b]).head.jws).toBe(low);
  });

  it("a replacement discards the versions built on the losing sibling", () => {
    const { owner, g } = setup();
    let x = createNextCircleVersion(owner.ik, g, { name: "x", iat: NOW });
    let y = createNextCircleVersion(owner.ik, g, { name: "y", iat: NOW });
    if (asciiCompare(jwsHash(x), jwsHash(y)) < 0) [x, y] = [y, x]; // y is the lower one
    const c = CircleChain.bootstrap([g.jws, x]);
    const x2 = createNextCircleVersion(owner.ik, c.head, { name: "x2", iat: NOW });
    c.receive(x2);
    const r = c.receive(y)[0];
    expect(r.status).toBe("replaced");
    expect(r.discarded).toEqual([jwsHash(x), jwsHash(x2)]);
    expect(c.head.jws).toBe(y);
  });

  it("transfer beats non-transfer, whatever the hashes, and is never replaced by one", () => {
    const { owner, g, bob } = setup();
    const plain = createNextCircleVersion(owner.ik, g, { name: "plain", iat: NOW });
    const t = transferTo(owner, g, bob);
    const c1 = CircleChain.bootstrap([g.jws, plain]);
    expect(c1.receive(t)[0].status).toBe("replaced");
    expect(c1.head.owner).toBe(bob.userId);
    const c2 = CircleChain.bootstrap([g.jws, t]);
    expect(c2.receive(plain)[0].status).toBe("ignored");
    expect(c2.head.owner).toBe(bob.userId);
    expect(CircleChain.bootstrap([g.jws, plain, t]).head.jws).toBe(t);
  });

  it("H1/R1: a former owner can't rewrite anything at or before the transfer", () => {
    const { owner, g, bob, carol } = setup();
    const t = v(transferTo(owner, g, bob), g);
    const b3 = createNextCircleVersion(bob.ik, t, { name: "bob's", iat: NOW });
    const c = CircleChain.bootstrap([g.jws, t.jws, b3]);
    // The old owner signs a sibling of the transfer (no transfer), with a lower hash or not.
    const rewrite = createNextCircleVersion(owner.ik, g, { members: [owner.userId], admins: [], iat: NOW + 1 });
    const r1 = c.receive(rewrite)[0];
    expect(r1.status).toBe("ignored");
    expect(r1.alert).toMatch(/rewrite final history|conflicting transfer/);
    // ...or a child of the transfer version: it doesn't even verify (the owner of ver 2 is Bob).
    const p = decodeJws(b3).payload;
    const forged = signJws("p2p-circle+jws", "ik", { ...p, name: "owner strikes back" }, owner.ik.secretKey);
    expect(c.receive(forged)[0]).toMatchObject({ status: "rejected", reason: "circle-signer" });
    expect(c.head.jws).toBe(b3);
    void carol;
  });

  it("H1/R1: an ex-admin has nothing to sign; its proposals stop counting once demoted", async () => {
    const { owner, g, dave, bob, carol } = setup();
    // Dave (admin) can't sign a version at all.
    expect(() => createNextCircleVersion(dave.ik, g, {})).toThrow(/only the current owner/);
    const demoted = v(createNextCircleVersion(owner.ik, g, { admins: [], iat: NOW - 100 }), g);
    const c = CircleChain.bootstrap([g.jws, demoted.jws]);
    const store = await storeKnowing(owner, bob, carol, dave);
    // A proposal made while Dave was still an admin (base 1) arrives after the demotion.
    const prop = await verifyProposal(createProposal(dave.signer(), { cid: g.cid, base: 1, op: "remove", target: bob.userId, iat: NOW - 200 }), ctxFor(store));
    const r = applyProposals(c, [prop], {}, { now: NOW });
    expect(r.results[0].status).toBe("not-admin");
    expect(r.draft).toBeUndefined();
  });

  it("transfer equivocation: two different transfers freeze the circle at their parent (batch)", () => {
    const { owner, g, bob, carol } = setup();
    const tb = transferTo(owner, g, bob);
    const tc = transferTo(owner, g, carol);
    const c = CircleChain.bootstrap([g.jws]);
    const rs = c.receive([tb, tc]);
    expect(c.frozen?.at).toBe(g.hash);
    expect(rs.every((r) => r.status === "frozen")).toBe(true);
    expect(c.receive(createNextCircleVersion(owner.ik, g, { iat: NOW }))[0].status).toBe("frozen");
    expect(CircleChain.fromStored(c.toStored()).frozen?.at).toBe(g.hash);
  });

  it("transfer equivocation during bootstrap freezes too", () => {
    const { owner, g, bob, carol } = setup();
    const c = CircleChain.bootstrap([g.jws, transferTo(owner, g, bob), transferTo(owner, g, carol)]);
    expect(c.frozen).toBeDefined();
    expect(c.head.hash).toBe(g.hash);
  });

  it("review 7: a client already past a transfer ignores a second transfer and only alerts (no freeze)", () => {
    const { owner, g, bob, carol } = setup();
    const tb = transferTo(owner, g, bob);
    const c = CircleChain.bootstrap([g.jws, tb]);
    const r = c.receive(transferTo(owner, g, carol))[0];
    expect(r.status).toBe("ignored");
    expect(r.alert).toBeDefined();
    expect(c.frozen).toBeUndefined();
    expect(c.head.owner).toBe(bob.userId);
    // Also when the client has moved on past the transfer.
    const b3 = createNextCircleVersion(bob.ik, c.head, { iat: NOW });
    c.receive(b3);
    expect(c.receive(transferTo(owner, g, carol))[0].status).toBe("ignored");
    expect(c.frozen).toBeUndefined();
  });
});

describe("§3.3 confirm before joining", () => {
  it("picks the owner plus a known member (not the inviter); refuses on a conflicting answer", () => {
    const { owner, g, bob, carol, dave } = setup();
    const known = new Set([carol.userId]);
    expect(pickConfirmers(g, { inviter: dave.userId, self: bob.userId, known })).toEqual({ owner: owner.userId, other: carol.userId });
    const offered = CircleChain.bootstrap([g.jws]);
    const v2 = createNextCircleVersion(owner.ik, g, { name: "v2", iat: NOW });
    const v2b = createNextCircleVersion(owner.ik, g, { name: "v2b", iat: NOW });
    const ahead = CircleChain.bootstrap([g.jws, v2]);
    const who = { inviter: dave.userId, self: bob.userId };
    expect(confirmJoin(offered, [{ from: owner.userId, chain: ahead }, { from: carol.userId, chain: offered }], who)).toBe("confirmed");
    expect(confirmJoin(offered, [{ from: owner.userId, chain: ahead }], who)).toBe("unconfirmed");
    const offered2 = CircleChain.bootstrap([g.jws, v2b]);
    expect(confirmJoin(offered2, [{ from: owner.userId, chain: ahead }], who)).toBe("conflict");
    expect(chainsConsistent(["a", "b"], ["a"])).toBe(true);
    // L5: the "other" confirmer must be a listed member, not the inviter, not the viewer.
    const outsider = makeUser("outsider");
    expect(confirmJoin(offered, [{ from: owner.userId, chain: ahead }, { from: dave.userId, chain: offered }], who)).toBe("unconfirmed");
    expect(confirmJoin(offered, [{ from: owner.userId, chain: ahead }, { from: bob.userId, chain: offered }], who)).toBe("unconfirmed");
    expect(confirmJoin(offered, [{ from: owner.userId, chain: ahead }, { from: outsider.userId, chain: offered }], who)).toBe("unconfirmed");
    expect(describeCircleInvite(g, dave.userId)).toMatchObject({ founder: owner.userId, owner: owner.userId, inviter: dave.userId, ownershipChanged: false });
  });
});

// ---------------------------------------------------------------------------
// Membership statements, standing and proposals need signer checks: a store.

async function world() {
  const s = setup();
  const store = await storeKnowing(s.owner, s.bob, s.carol, s.dave);
  const ctx = ctxFor(store);
  const chain = CircleChain.bootstrap([s.g.jws]);
  const join = async (u: TestUser, n = 0, at = chain.head.hash, iat = NOW - 10, capTtl?: number) =>
    verifyMembershipStatement(createMembershipStatement(u.signer(), { cid: chain.cid, n, op: "join", at, cap: u.joinCap({ ttlSec: capTtl }), iat }), ctx);
  const leave = async (u: TestUser, n: number) => verifyMembershipStatement(createMembershipStatement(u.signer(), { cid: chain.cid, n, op: "leave", iat: NOW - 5 }), ctx);
  return { ...s, store, ctx, chain, join, leave };
}

describe("§3.3 membership statements", () => {
  it("highest n is current; on a tie leave wins, then the lowest jwsHash", async () => {
    const { bob, join, leave } = await world();
    const j0 = await join(bob, 0);
    const j1 = await join(bob, 1);
    const l1 = await leave(bob, 1);
    const book: MembershipBook = {};
    expect(applyMembership(book, j0)).toBe(true);
    expect(applyMembership(book, j1)).toBe(true);
    expect(applyMembership(book, j0)).toBe(false);
    expect(applyMembership(book, l1)).toBe(true);
    expect(book[bob.userId].op).toBe("leave");
    expect(applyMembership(book, j1)).toBe(false);
    const j1b = await join(bob, 1, undefined, NOW - 9);
    expect(compareMembership(j1, j1b)).toBe(asciiCompare(j1.hash, j1b.hash));
  });

  it("a join's cap must be the member's own sub * / kinds * cap", async () => {
    const { bob, carol, chain, ctx } = await world();
    const wrongCap = createMembershipStatement(bob.signer(), { cid: chain.cid, n: 0, op: "join", at: chain.head.hash, cap: bob.friendCap(carol.userId), iat: NOW - 1 });
    await expect(verifyMembershipStatement(wrongCap, ctx)).rejects.toThrow(/cap-invalid/);
    const othersCap = createMembershipStatement(bob.signer(), { cid: chain.cid, n: 0, op: "join", at: chain.head.hash, cap: carol.joinCap(), iat: NOW - 1 });
    await expect(verifyMembershipStatement(othersCap, ctx)).rejects.toThrow(/cap-invalid|issuer-mismatch/);
  });

  it("N4 backdating: a statement from a device revoked before receipt is rejected, whatever its iat", async () => {
    const { bob, chain, owner, carol, dave } = await world();
    const old = bob.addDevice({ keyholder: false });
    bob.publish();
    // Signed (and backdated) by the old device, then the device is revoked.
    const backdated = createMembershipStatement(bob.signer(old), { cid: chain.cid, n: 3, op: "join", at: chain.head.hash, cap: bob.joinCap(), iat: NOW - DAYS(5) });
    bob.publish({ devices: [bob.dev.did] });
    const store = await storeKnowing(owner, bob, carol, dave);
    // The old device's certificate is still at hand (e.g. cached): rule 6 is what fails.
    const ctx = storeSignerContext(store, { now: NOW, resolveCert: (_u, d) => (d === old.did ? old.cert : undefined) });
    await expect(verifyMembershipStatement(backdated, ctx)).rejects.toThrow(/device-not-listed/);
    // Statements accepted earlier are kept (the book holds facts, not re-checked).
    expect(membershipNeedsResign({ signer: { did: old.did, exp: NOW + DAYS(80) } as never, joinCap: undefined }, [bob.dev.did], NOW)).toBe(true);
  });

  it("re-sign triggers: cert within 7 days of exp, cap within 30 days", async () => {
    const { bob, join } = await world();
    const j = await join(bob);
    expect(membershipNeedsResign(j, [bob.dev.did], NOW)).toBe(false);
    expect(membershipNeedsResign(j, [bob.dev.did], j.signer.exp - DAYS(7))).toBe(true);
    expect(membershipNeedsResign(j, [bob.dev.did], j.joinCap!.exp - DAYS(30))).toBe(true);
  });
});

describe("§3.3 standing: membership counts only with consent", () => {
  it("u stands when in members, with a current join naming an ancestor of the held version", async () => {
    const { bob, carol, owner, chain, join, leave } = await world();
    const book: MembershipBook = {};
    for (const u of [owner, bob]) applyMembership(book, await join(u));
    const ctx = { viewer: owner.userId, joinedByMe: true };
    expect(standsInCircle(bob.userId, chain, book, ctx)).toBe(true);
    // Carol is listed but never joined.
    expect(standsInCircle(carol.userId, chain, book, ctx)).toBe(false);
    // A leave with a higher n ends it at once.
    applyMembership(book, await leave(bob, 1));
    expect(standsInCircle(bob.userId, chain, book, ctx)).toBe(false);
    // A join naming a version not on the held chain doesn't count.
    const odd = await join(carol, 0, jwsHash("elsewhere"));
    applyMembership(book, odd);
    expect(standsInCircle(carol.userId, chain, book, ctx)).toBe(false);
    expect(membershipFact(odd).jws).toBe(odd.jws);
  });

  it("members stop counting someone the moment they hold the version that dropped them", async () => {
    const { bob, owner, chain, join } = await world();
    const book: MembershipBook = {};
    for (const u of [owner, bob]) applyMembership(book, await join(u));
    chain.receive(createNextCircleVersion(owner.ik, chain.head, { members: chain.head.members.filter((m) => m !== bob.userId), iat: NOW }));
    expect(standsInCircle(bob.userId, chain, book, { viewer: owner.userId, joinedByMe: true })).toBe(false);
  });

  it("C1 forced enrolment: a circle the viewer never joined grants nobody anything on its device", async () => {
    const { bob, owner, chain, join } = await world();
    // The owner lists Bob and even holds Bob's (stale) join; Bob's own device never joined.
    const book: MembershipBook = {};
    for (const u of [owner, bob]) applyMembership(book, await join(u));
    const onBob = { viewer: bob.userId, joinedByMe: false };
    expect(standsInCircle(bob.userId, chain, book, onBob)).toBe(false);
    expect(standsInCircle(owner.userId, chain, book, onBob)).toBe(false);
    expect(standsInCircle(owner.userId, chain, book, { ...onBob, joinedByMe: true })).toBe(true);
    // Blocks override.
    expect(standsInCircle(owner.userId, chain, book, { viewer: bob.userId, joinedByMe: true, isBlocked: (u) => u === owner.userId })).toBe(false);
  });
});

describe("§3.3 proposals", () => {
  async function proposalWorld() {
    const w = await world();
    const prop = async (p: { op: "add" | "remove" | "promote" | "demote" | "rename"; target?: string; name?: string; base?: number; iat?: number; nonce?: string }, by = w.dave) =>
      verifyProposal(createProposal(by.signer(), { cid: w.chain.cid, base: p.base ?? w.chain.head.ver, ...p, iat: p.iat ?? NOW - 10 }), w.ctx);
    return { ...w, prop };
  }

  it("an admin's proposals apply in arrival order and yield the next version's fields", async () => {
    const { chain, prop, bob, carol, owner } = await proposalWorld();
    const mallory = makeUser("mallory");
    const r = applyProposals(chain, [await prop({ op: "add", target: mallory.userId }), await prop({ op: "promote", target: bob.userId }), await prop({ op: "remove", target: carol.userId }), await prop({ op: "rename", name: "renamed" })], {}, { now: NOW });
    expect(r.results.map((x) => x.status)).toEqual(["applied", "applied", "applied", "applied"]);
    expect(r.draft?.members).toContain(mallory.userId);
    expect(r.draft?.members).not.toContain(carol.userId);
    expect(r.draft?.admins).toContain(bob.userId);
    expect(r.draft?.name).toBe("renamed");
    const next = createNextCircleVersion(owner.ik, chain.head, { ...r.draft!, iat: NOW });
    expect(chain.receive(next)[0].status).toBe("accepted");
  });

  it("only an admin of the current head; nonces are de-duplicated and pruned after 30 days", async () => {
    const { chain, prop, bob, carol } = await proposalWorld();
    const notAdmin = await prop({ op: "remove", target: carol.userId }, bob);
    const p = await prop({ op: "remove", target: carol.userId });
    let r = applyProposals(chain, [notAdmin, p, p], {}, { now: NOW });
    expect(r.results.map((x) => x.status)).toEqual(["not-admin", "applied", "duplicate"]);
    // Re-sent later: still a duplicate while the nonce is remembered.
    r = applyProposals(chain, [p], r.applied, { now: NOW + DAYS(29) });
    expect(r.results[0].status).toBe("duplicate");
    // After 30 days the nonce is pruned, but the proposal is then too old anyway.
    r = applyProposals(chain, [p], r.applied, { now: NOW + DAYS(31) });
    expect(r.results[0].status).toBe("expired");
    expect(r.applied[p.nonce]).toBeUndefined();
  });

  it("stale against `base` per target; effects that already hold are skipped; the owner can't be targeted", async () => {
    const { chain, prop, owner, bob, carol } = await proposalWorld();
    // A version after base 1 removed Bob.
    chain.receive(createNextCircleVersion(owner.ik, chain.head, { members: chain.head.members.filter((m) => m !== bob.userId), iat: NOW }));
    const stale = await prop({ op: "promote", target: bob.userId, base: 1 });
    const fine = await prop({ op: "remove", target: carol.userId, base: 1 });
    const already = await prop({ op: "add", target: carol.userId, base: 2 });
    const atOwner = await prop({ op: "demote", target: owner.userId });
    const nonMember = await prop({ op: "promote", target: makeUser("x").userId });
    const r = applyProposals(chain, [stale, already, fine, atOwner, nonMember], {}, { now: NOW });
    expect(r.results.map((x) => x.status)).toEqual(["stale", "skipped", "applied", "refused", "refused"]);
    expect(r.draft?.members).not.toContain(carol.userId);
  });

  it("the owner can hold proposals for approval", async () => {
    const { chain, prop, carol } = await proposalWorld();
    const r = applyProposals(chain, [await prop({ op: "remove", target: carol.userId })], {}, { now: NOW, hold: true });
    expect(r.results[0].status).toBe("held");
    expect(r.draft).toBeUndefined();
  });
});

describe("Draft 3 additions: open communities", () => {
  async function openWorld() {
    const w = await world();
    const open = v(createNextCircleVersion(w.owner.ik, w.chain.head, { policy: "open", iat: NOW - 50 }), w.chain.head);
    w.chain.receive(open.jws);
    return w;
  }

  it("invite links carry the head version: p2p://circle/ and the web fragment form", async () => {
    const { chain } = await openWorld();
    const link = circleInviteLink(chain.head.jws);
    expect(link).toMatch(/^p2p:\/\/circle\//);
    expect(parseCircleInviteLink(link)).toBe(chain.head.jws);
    expect(parseCircleInviteLink(circleInviteLink(chain.head.jws, { web: true }))).toBe(chain.head.jws);
    expect(circleInviteLink(chain.head.jws, { web: true })).toMatch(/^https:\/\/ix-infra\.com\/p2p\/c#/);
    // The deprecated web form still parses (older clients printed it); it is never generated.
    expect(parseCircleInviteLink(circleInviteLink(chain.head.jws, { web: true }).replace("https://ix-infra.com/p2p/c#", "https://peer2peer.dev/c#"))).toBe(chain.head.jws);
    expect(() => parseCircleInviteLink("https://evil.example/c#" + circleInviteLink(chain.head.jws).slice("p2p://circle/".length))).toThrow(/not a circle link/);
    expect(() => parseCircleInviteLink("p2p://circle/AAAA")).toThrow();
  });

  it("auto-accepts a valid join from a link holder, up to the hourly cap; then holds", async () => {
    const { chain } = await openWorld();
    const store = await storeKnowing();
    void store;
    const strangers = Array.from({ length: 3 }, (_, i) => makeUser(`s${i}`));
    const st = await storeKnowing(...strangers);
    const ctx = ctxFor(st);
    const limiter = { acceptedAt: [] as number[] };
    const decisions = [];
    for (const s of strangers) {
      const j = await verifyMembershipStatement(createMembershipStatement(s.signer(), { cid: chain.cid, n: 0, op: "join", at: chain.head.hash, cap: s.joinCap({ ttlSec: DAYS(14) }), iat: NOW - 1 }), ctx);
      decisions.push(decideOpenJoin(chain, j, {}, limiter, { removed: [], now: NOW, maxPerHour: 2 }).decision);
    }
    expect(decisions).toEqual(["accept", "accept", "hold"]);
    // An hour later the window has room again.
    const late = strangers[2];
    const j = await verifyMembershipStatement(createMembershipStatement(late.signer(), { cid: chain.cid, n: 1, op: "join", at: chain.head.hash, cap: late.joinCap({ ttlSec: DAYS(14) }), iat: NOW - 1 }), ctx);
    expect(decideOpenJoin(chain, j, {}, limiter, { removed: [], now: NOW + HOUR, maxPerHour: 2 }).decision).toBe("accept");
  });

  it("holds under invite policy, for removed members, and ignores members, blocked users and unknown versions", async () => {
    const w = await world();
    const { chain, bob, carol, join, owner } = w;
    const book: MembershipBook = {};
    const limiter = { acceptedAt: [] as number[] };
    const stranger = makeUser("stranger");
    const st = await storeKnowing(stranger);
    const sj = await verifyMembershipStatement(createMembershipStatement(stranger.signer(), { cid: chain.cid, n: 0, op: "join", at: chain.head.hash, cap: stranger.joinCap({ ttlSec: DAYS(14) }), iat: NOW - 1 }), ctxFor(st));
    // Invite policy (the default): held.
    expect(decideOpenJoin(chain, sj, book, limiter, { removed: [], now: NOW })).toEqual({ decision: "hold", reason: "not-open" });
    // Open the circle; remove Carol (she never left).
    chain.receive(createNextCircleVersion(owner.ik, chain.head, { policy: "open", members: chain.head.members.filter((m) => m !== carol.userId), iat: NOW - 40 }));
    applyMembership(book, await join(carol, 0, chain.versions[0].hash));
    const carolAgain = await join(carol, 1, chain.head.hash, NOW - 10, DAYS(14));
    expect(decideOpenJoin(chain, carolAgain, book, limiter, { removed: [], now: NOW })).toEqual({ decision: "hold", reason: "previously-removed" });
    expect(decideOpenJoin(chain, await join(bob, 0, chain.head.hash), book, limiter, { removed: [], now: NOW })).toEqual({ decision: "ignore", reason: "already-member" });
    expect(decideOpenJoin(chain, sj, book, limiter, { removed: [], now: NOW, isBlocked: (u) => u === stranger.userId })).toEqual({ decision: "ignore", reason: "blocked" });
    const odd = { ...sj, at: jwsHash("nowhere") } as VerifiedMembership;
    expect(decideOpenJoin(chain, odd, book, limiter, { removed: [], now: NOW })).toEqual({ decision: "ignore", reason: "unknown-version" });
    expect(decideOpenJoin(chain, sj, book, limiter, { removed: [], now: NOW })).toEqual({ decision: "accept" });
  });

  it("an open circle's chain rules are unchanged: a link holder still can't sign versions", async () => {
    const { chain } = await openWorld();
    const stranger = makeUser("stranger");
    const p = decodeJws(chain.head.jws).payload;
    const forged = signJws("p2p-circle+jws", "ik", { ...p, ver: chain.head.ver + 1, prev: chain.head.hash, members: [...chain.head.members, stranger.userId] }, stranger.ik.secretKey);
    expect(chain.receive(forged)[0]).toMatchObject({ status: "rejected", reason: "circle-signer" });
    expect(() => createCircle(stranger.ik, { name: "x", policy: "weird" as never })).toThrow(/policy/);
  });
});
