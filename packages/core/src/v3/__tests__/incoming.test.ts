// Copyright 2026 Ix Infrastructure Inc.
//
// §4 envelopes end to end through verifyIncomingV3: the p2p/v3 AAD and KDF,
// the receiver checks before opening, two-sided authorisation with circles,
// every §4.3 kind, the 7-day replay window and its retention, blocks, and the
// 60-day fail-closed rule.

import { describe, expect, it } from "vitest";
import { verifyIncomingV3, type IncomingResultV3 } from "../incoming.js";
import {
  CIRCLE_SID,
  decodeEnvelopeV3,
  displayStatus,
  envelopeAadV3,
  envelopeKdfInfoV3,
  extensionFallbackText,
  isLive,
  openEnvelopeV3,
} from "../envelope.js";
import { createRosterV3 } from "../roster.js";
import { createDeviceCert } from "../device.js";
import { createAcceptV3, createInviteV3, createUnfriendV3, inviteHashV3, verifyFriendshipV3 } from "../friends.js";
import { createCap } from "../caps.js";
import {
  CircleChain,
  createCircle,
  createMembershipStatement,
  createNextCircleVersion,
  verifyMembershipStatement,
} from "../circles.js";
import {
  addIdentityVersion,
  applyCircleBundle,
  blockUser,
  recordFriendshipV3,
  recordOwnJoin,
  storeOfferedCircle,
} from "../state.js";
import { createIdentityDoc } from "../identitydoc.js";
import { REPLAY_CLAIM_TTL_MS, REPLAY_MAX_ABANDONS, REPLAY_MAX_ATTEMPTS, type TrustStoreV3 } from "../store.js";
import { REPLAY_MAX_AGE_MS_V3 } from "../../replay.js";
import { decodeJws, signJws } from "../../jws.js";
import { b64uEncode } from "../../encoding.js";
import { ctxFor, DAYS, learn, makeUser, NOW, NOW_MS, RELAY, seal, storeKnowing, type TestUser } from "./fixtures.js";

async function receive(store: TrustStoreV3, to: TestUser, env: string, nowMs = NOW_MS, warnings: string[] = []): Promise<IncomingResultV3> {
  return verifyIncomingV3(env, {
    self: { userId: to.userId, did: to.dev.did, agreementSecretKey: to.dev.agreementSecretKey, cert: to.dev.cert },
    store,
    nowMs,
    onWarning: (m) => warnings.push(m),
  });
}

function outcome(r: IncomingResultV3): string {
  return r.ok ? (r.viewerRule ? `${r.rule}/${r.viewerRule}` : r.rule) : r.reason;
}

async function friends(a: TestUser, b: TestUser, store: TrustStoreV3) {
  const invite = createInviteV3(b.signer(), { aud: a.userId, iat: NOW - 1000 });
  await recordFriendshipV3(store, await verifyFriendshipV3({ invite, accept: createAcceptV3(a.signer(), invite, { iat: NOW - 900 }) }, ctxFor(store)));
}

function roster(owner: TestUser, parts: TestUser[], opts: { vis?: "private" | "circle"; circle?: string; ver?: number } = {}) {
  return createRosterV3(owner.signer(), { sid: "s1", ver: opts.ver ?? 1, vis: opts.vis ?? "private", ...(opts.circle ? { circle: opts.circle } : {}), parts: parts.map((p) => p.userId), iat: NOW - 500 });
}

describe("§4.1 envelope format", () => {
  it("v 3, with the p2p/v3 AAD and KDF info; seals and opens", () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const env = seal(a, b, "msg", { text: "hi" });
    const p = decodeEnvelopeV3(env).payload;
    expect(p.v).toBe(3);
    expect(new TextDecoder().decode(envelopeAadV3(p))).toBe(`p2p/v3|${a.userId}|${a.dev.did}|${b.userId}|${b.dev.did}|${a.userId}|s1|${p.seq}|${p.ts}|msg`);
    expect(new TextDecoder().decode(envelopeKdfInfoV3(p.fdid, p.tdid))).toBe(`p2p/v3/msg|${a.dev.did}|${b.dev.did}`);
    expect(JSON.parse(new TextDecoder().decode(openEnvelopeV3(p, b.dev.agreementSecretKey, a.dev.agreementPublicKey)))).toEqual({ text: "hi" });
  });

  it("reserved sids: contact and circle need ~contact/~circle and own == from; nothing else may use them", () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    expect(() => seal(a, b, "circle", { want: { cid: "c_" + "a".repeat(26), fromVer: 1 } }, { sid: "s1" })).toThrow(/requires sid ~circle/);
    expect(() => seal(a, b, "msg", { text: "x" }, { sid: CIRCLE_SID })).toThrow(/reserved/);
    expect(() => seal(a, b, "contact", { text: "x" }, { own: b.userId })).toThrow(/own == from/);
    expect(() => seal(a, b, "x:BAD" as never, {})).toThrow(/unknown kind/);
    expect(() => seal(a, b, "msg", { text: "x" }, { sid: "a|b" })).toThrow(/\|/);
  });
});

describe("§4.1 receiver checks before opening", () => {
  it("baseline: a friend in parts", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    await friends(a, b, store);
    const r = await receive(store, b, seal(a, b, "msg", { text: "hi", roster: roster(a, [a, b]) }));
    expect(outcome(r)).toBe("owner/participant-friend");
    expect(await store.getRoster(a.userId, "s1")).toBeDefined();
    expect(await store.getDeviceCert(a.dev.did)).toBeDefined();
  });

  it("an envelope for another device, or an unknown sender identity, is rejected", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const b2 = b.addDevice();
    const store = await storeKnowing(b);
    expect(outcome(await receive(store, b, seal(a, b, "msg", { text: "x" }, { toDev: b2 })))).toBe("wrong-recipient");
    expect(outcome(await receive(store, b, seal(a, b, "msg", { text: "x" })))).toBe("identity-unknown");
  });

  it("fcert.iss must be from, and fcert.did == fdid == kid", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const m = makeUser("mallory");
    const store = await storeKnowing(a, b, m);
    const env = seal(a, b, "msg", { text: "x" });
    const p = decodeJws(env).payload;
    const spoof = signJws("p2p-msg+jws", m.dev.did, { ...p, fdid: m.dev.did, fcert: m.dev.cert }, m.dev.signingSecretKey);
    expect(outcome(await receive(store, b, spoof))).toBe("cert-mismatch");
    const a2 = a.addDevice();
    a.publish();
    await learn(store, a);
    const swapped = signJws("p2p-msg+jws", a.dev.did, { ...p, fcert: a2.cert }, a.dev.signingSecretKey);
    expect(outcome(await receive(store, b, swapped))).toBe("kid-mismatch");
    const tampered = signJws("p2p-msg+jws", a.dev.did, { ...p, seq: 999 }, m.dev.signingSecretKey);
    expect(outcome(await receive(store, b, tampered))).toBe("bad-signature");
    // Re-signed by the sender with an altered AAD field: the AEAD fails.
    const altered = signJws("p2p-msg+jws", a.dev.did, { ...p, seq: 1000 }, a.dev.signingSecretKey);
    expect(outcome(await receive(store, b, altered))).toBe("decrypt-failed");
  });

  it("a revoked device after a document update: rejected as soon as the receiver holds the new version", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const laptop = a.addDevice({ keyholder: false });
    a.publish();
    const store = await storeKnowing(a, b);
    await friends(a, b, store);
    expect(outcome(await receive(store, b, seal(a, b, "msg", { text: "x", roster: roster(a, [a, b]) }, { fromDev: laptop })))).toBe("owner/participant-friend");
    a.publish({ devices: [a.dev.did] });
    await learn(store, a);
    expect(outcome(await receive(store, b, seal(a, b, "msg", { text: "x" }, { fromDev: laptop })))).toBe("device-not-listed");
    // ...and its signatures on stored friendships stop counting too.
    expect(outcome(await receive(store, b, seal(a, b, "msg", { text: "x" })))).toBe("owner/participant-friend");
  });

  it("a forked sender: the intersection applies, so a revocation in either branch applies", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const phone = a.addDevice({ keyholder: true });
    const laptop = a.addDevice({ keyholder: false });
    const v2 = a.publish();
    const store = await storeKnowing(a, b);
    await friends(a, b, store);
    const branch = (devices: string[], by: string, iat: number) =>
      createIdentityDoc(a.ik, { ver: 3, prev: v2.hash, name: "alice", relays: [RELAY], devices, keyholders: [a.dev.did, phone.did].filter((d) => devices.includes(d)), certs: a.devices.filter((d) => devices.includes(d.did)).map((d) => d.cert), by, iat });
    await addIdentityVersion(store, branch([a.dev.did, phone.did], a.dev.did, NOW - 100), { now: NOW });
    await addIdentityVersion(store, branch([a.dev.did, phone.did, laptop.did], phone.did, NOW - 99), { now: NOW });
    expect(outcome(await receive(store, b, seal(a, b, "msg", { text: "x", roster: roster(a, [a, b]) }, { fromDev: laptop })))).toBe("device-not-listed");
    expect(outcome(await receive(store, b, seal(a, b, "msg", { text: "x", roster: roster(a, [a, b]) }, { fromDev: phone })))).toBe("owner/participant-friend");
  });

  it("expiry: warn past exp; fail closed at exp + 60 d + 1 s; the user's own sync is exempt", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    await friends(a, b, store);
    const exp = a.doc.exp;
    const r1 = roster(a, [a, b]);
    const warnings: string[] = [];
    // The certificates must still be valid at these times: re-issue long-lived ones.
    const late = exp + DAYS(60);
    const at = (t: number) => t * 1000;
    const reissue = (u: TestUser, iat: number) => {
      for (const d of u.devices) d.cert = (createDeviceCertFor(u, d, iat));
    };
    reissue(a, late - DAYS(1));
    reissue(b, late - DAYS(1));
    const ok = await receive(store, b, seal(a, b, "msg", { text: "x", roster: r1 }, { tsMs: at(late) }), at(late), warnings);
    expect(outcome(ok)).toBe("owner/participant-friend");
    expect(ok.ok && ok.expiredDays).toBe(60);
    expect(warnings[0]).toMatch(/hasn't been online for 60 days/);
    const closed = await receive(store, b, seal(a, b, "msg", { text: "x", roster: r1 }, { tsMs: at(late + 1) }), at(late + 1));
    expect(outcome(closed)).toBe("identity-fail-closed");
    // Own sync: Bob's other device, Bob's own document long expired.
    const b2 = b.addDevice({ iat: late - DAYS(1) });
    b.publish();
    await learn(store, b);
    const bExp = b.doc.exp;
    reissue(b, bExp + DAYS(80));
    const t = bExp + DAYS(81);
    const sync = await receive(store, b, seal(b, b, "sync", { note: "hi" }, { fromDev: b2, tsMs: at(t) }), at(t));
    expect(outcome(sync)).toBe("self-sync");
  });

  it("blocks override everything, and blocking takes back the caps issued to that user", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    await friends(a, b, store);
    const cap = b.friendCap(a.userId);
    await store.addCapIssued({ capid: decodeJws(cap).payload.capid as string, iss: b.userId, sub: a.userId, relays: [RELAY], kinds: ["*"], exp: NOW + DAYS(90), jws: cap });
    const revoked = await blockUser(store, a.userId, NOW);
    expect(revoked.map((c) => c.sub)).toEqual([a.userId]);
    expect(await store.listCapsIssued()).toHaveLength(0);
    expect(outcome(await receive(store, b, seal(a, b, "msg", { text: "x", roster: roster(a, [a, b]) })))).toBe("blocked");
  });
});

describe("§4.4 replay across the 7-day window", () => {
  it("accepts an envelope 6 days late once; rejects a replay; rejects > 7d10m and > 10 min ahead", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    await friends(a, b, store);
    const r1 = roster(a, [a, b]);
    const env = seal(a, b, "msg", { text: "late", roster: r1 }, { tsMs: NOW_MS - DAYS(6) * 1000 });
    expect((await receive(store, b, env)).ok).toBe(true);
    expect(outcome(await receive(store, b, env))).toBe("replayed-seq");
    const tooOld = seal(a, b, "msg", { text: "x", roster: r1 }, { tsMs: NOW_MS - REPLAY_MAX_AGE_MS_V3 - 1 });
    expect(outcome(await receive(store, b, tooOld))).toBe("stale-timestamp");
    const edge = seal(a, b, "msg", { text: "x", roster: r1 }, { tsMs: NOW_MS - REPLAY_MAX_AGE_MS_V3 });
    expect((await receive(store, b, edge)).ok).toBe(true);
    const future = seal(a, b, "msg", { text: "x", roster: r1 }, { tsMs: NOW_MS + 10 * 60_000 + 1 });
    expect(outcome(await receive(store, b, future))).toBe("stale-timestamp");
  });

  it("replay windows are retained at least 7d10m after their last admit, even after the session ends", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    await friends(a, b, store);
    const env = seal(a, b, "msg", { text: "x", roster: roster(a, [a, b]) }, { tsMs: NOW_MS });
    expect((await receive(store, b, env)).ok).toBe(true);
    expect(await store.pruneReplay(NOW_MS + REPLAY_MAX_AGE_MS_V3, 1000)).toBe(0);
    // The relay re-delivers within the window: still a replay.
    expect(outcome(await receive(store, b, env, NOW_MS + REPLAY_MAX_AGE_MS_V3))).toBe("replayed-seq");
    expect(await store.pruneReplay(NOW_MS + 2 * REPLAY_MAX_AGE_MS_V3 + 1)).toBe(1);
    // Once pruned, the envelope is too old to pass the ts check anyway.
    expect(outcome(await receive(store, b, env, NOW_MS + 2 * REPLAY_MAX_AGE_MS_V3 + 1))).toBe("stale-timestamp");
  });

  it("concurrent duplicates are admitted once", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    await friends(a, b, store);
    const env = seal(a, b, "msg", { text: "x", roster: roster(a, [a, b]) });
    const rs = await Promise.all([receive(store, b, env), receive(store, b, env), receive(store, b, env)]);
    expect(rs.filter((r) => r.ok)).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Circles in authorisation

async function circleWorld(opts: { bobJoins?: boolean } = {}) {
  const owner = makeUser("owen");
  const bob = makeUser("bob");
  const carol = makeUser("carol");
  const g = createCircle(owner.ik, { name: "team", members: [bob.userId, carol.userId], iat: NOW - 1000 });
  const chain = CircleChain.bootstrap([g]);
  const storeB = await storeKnowing(owner, bob, carol);
  await storeOfferedCircle(storeB, [g]);
  const join = async (u: TestUser) =>
    createMembershipStatement(u.signer(), { cid: chain.cid, n: 0, op: "join", at: chain.head.hash, cap: u.joinCap(), iat: NOW - 100 });
  const joins = [await join(owner), await join(carol)];
  if (opts.bobJoins ?? true) {
    const own = await join(bob);
    await recordOwnJoin(storeB, bob.userId, await verifyMembershipStatement(own, ctxFor(storeB)));
  }
  await applyCircleBundle(storeB, { circles: [], joins, ops: [] }, { ...ctxFor(storeB), self: bob.userId });
  return { owner, bob, carol, chain, storeB, g };
}

describe("§4.2 two-sided authorisation with circles", () => {
  it("(b) vis circle: both the roster owner and the sender stand; the viewer has joined", async () => {
    const { owner, bob, carol, chain, storeB } = await circleWorld();
    const r = roster(carol, [carol], { vis: "circle", circle: chain.cid });
    expect(outcome(await receive(storeB, bob, seal(carol, bob, "msg", { text: "x", roster: r })))).toBe("owner/circle");
    const ro = roster(owner, [owner], { vis: "circle", circle: chain.cid });
    expect(outcome(await receive(storeB, bob, seal(carol, bob, "msg", { text: "x", roster: ro }, { own: owner.userId })))).toBe("circle/circle");
  });

  it("(c) participant via the circle in a private roster", async () => {
    const { bob, carol, chain, storeB } = await circleWorld();
    const r = roster(carol, [carol, bob], { vis: "private", circle: chain.cid });
    expect(outcome(await receive(storeB, bob, seal(carol, bob, "msg", { text: "x", roster: r })))).toBe("owner/participant-circle");
    const noCircle = roster(carol, [carol, bob], { vis: "private", ver: 2 });
    expect(outcome(await receive(storeB, bob, seal(carol, bob, "msg", { text: "x", roster: noCircle })))).toBe("viewer-no-friendship");
  });

  it("C1 forced enrolment: a circle Bob never joined grants nobody anything on Bob's device", async () => {
    const { bob, carol, chain, storeB } = await circleWorld({ bobJoins: false });
    const r = roster(carol, [carol], { vis: "circle", circle: chain.cid });
    expect(outcome(await receive(storeB, bob, seal(carol, bob, "msg", { text: "x", roster: r })))).toBe("viewer-not-standing");
    const r2 = roster(carol, [carol, bob], { vis: "private", circle: chain.cid, ver: 2 });
    expect(outcome(await receive(storeB, bob, seal(carol, bob, "msg", { text: "x", roster: r2 })))).toBe("viewer-no-friendship");
  });

  it("a member the owner removed stops counting once the viewer holds that version", async () => {
    const { owner, bob, carol, chain, storeB } = await circleWorld();
    const r = roster(carol, [carol], { vis: "circle", circle: chain.cid });
    expect((await receive(storeB, bob, seal(carol, bob, "msg", { text: "x", roster: r }))).ok).toBe(true);
    const v2 = createNextCircleVersion(owner.ik, chain.head, { members: chain.head.members.filter((m) => m !== carol.userId), iat: NOW - 10 });
    await applyCircleBundle(storeB, { circles: [v2], joins: [], ops: [] }, { ...ctxFor(storeB), self: bob.userId });
    // Carol is the roster's owner, so her own side passes (rule a); Bob's side needs her standing.
    expect(outcome(await receive(storeB, bob, seal(carol, bob, "msg", { text: "y", roster: r })))).toBe("viewer-not-standing");
  });

  it("the owner must stand too: a circle roster from a non-member owner grants nothing", async () => {
    const { bob, chain, storeB } = await circleWorld();
    const mallory = makeUser("mallory");
    await learn(storeB, mallory);
    const r = roster(mallory, [mallory], { vis: "circle", circle: chain.cid });
    expect(outcome(await receive(storeB, bob, seal(mallory, bob, "msg", { text: "x", roster: r })))).toBe("viewer-not-standing");
  });
});

describe("§4.3 kinds", () => {
  it("status: sanitized for display; liveness is measured by ts, not arrival", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    await friends(a, b, store);
    const status = { state: "busy", label: "fixing\u0007 <b>auth</b>", files: ["src/a.ts", "../../etc/passwd", "/abs", "C:\\x", "ok/\u202egnp.ts"], summary: "a\nb" };
    const r = await receive(store, b, seal(a, b, "status", { status, roster: roster(a, [a, b]) }, { tsMs: NOW_MS - 200_000 }));
    expect(r.ok).toBe(true);
    if (!r.ok || r.plaintext.kind !== "status") throw new Error("expected status");
    const shown = displayStatus(r.plaintext.status);
    expect(shown.label).toBe("fixing bauth/b");
    expect(shown.files).toEqual(["src/a.ts"]);
    expect(shown.summary).toBe("a b");
    expect(isLive(r.envelope.ts, NOW_MS)).toBe(false); // 200 s old, though it arrived just now
    expect(isLive(NOW_MS - 150_000, NOW_MS)).toBe(true);
    expect(outcome(await receive(store, b, seal(a, b, "status", { status: { state: "weird", label: "x" } })))).toBe("malformed");
  });

  it("x:<ns>.<type>: authorised by §4.2, fallback ≤ 200 chars, shown with the sender's address", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    await friends(a, b, store);
    const r = await receive(store, b, seal(a, b, "x:ix.note", { ext: { v: 1, body: { anything: true } }, fallback: "shared an Ix note", roster: roster(a, [a, b]) }));
    expect(outcome(r)).toBe("owner/participant-friend");
    expect(extensionFallbackText("alice@abcd-efgh-ijkl-mnop", "<script>shared</script>\n")).toBe("alice@abcd-efgh-ijkl-mnop: scriptshared/script");
    expect(outcome(await receive(store, b, seal(a, b, "x:ix.note", { ext: { v: 1, body: 1 }, fallback: "x".repeat(201) })))).toBe("malformed");
    // Not authorised without standing, like any session kind.
    const m = makeUser("mallory");
    await learn(store, m);
    expect(outcome(await receive(store, b, seal(m, b, "x:ix.note", { ext: { v: 1, body: 1 }, fallback: "x", roster: roster(m, [m, b]) })))).toBe("viewer-no-friendship");
  });

  it("sync only from the same user", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    expect(outcome(await receive(store, b, seal(a, b, "sync", { anything: 1 })))).toBe("not-participant");
  });

  it("contact: an invite from a stranger (with its doc) is returned for approval; only its document is kept, provisionally", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(b); // Bob knows nothing about Alice
    const invite = createInviteV3(a.signer(), { aud: b.userId, iat: NOW - 10, doc: a.doc.jws, ik: a.doc.ik, relays: [RELAY] });
    const r = await receive(store, b, seal(a, b, "contact", { text: invite }));
    expect(r.ok && r.contact?.type).toBe("invite");
    expect(await store.listFriendships()).toHaveLength(0);
    expect(r.ok && r.contact?.type === "invite" && r.contact.invite.provisional).toBe(true);
    // The bundled document is only cached provisionally, never stored as the identity (review N1).
    expect(await store.getIdentity(a.userId)).toBeUndefined();
    expect((await store.getProvisional(a.userId, NOW))?.relays).toEqual(a.doc.relays);
    // Without a document, a stranger's device can't pass rule 6.
    const bare = createInviteV3(a.signer(), { aud: b.userId, iat: NOW - 10 });
    expect(outcome(await receive(await storeKnowing(b), b, seal(a, b, "contact", { text: bare })))).toMatch(/identity-unknown|unknown-device/);
  });

  it("contact: an accept for an invite this user issued returns the friendship (not stored)", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(b);
    const invite = createInviteV3(b.signer(), { aud: "*", iat: NOW - 100, doc: b.doc.jws });
    await store.addOutgoingInvite({ inv: inviteHashV3(invite), aud: "*", exp: NOW + 100, jws: invite });
    const accept = createAcceptV3(a.signer(), invite, { iat: NOW - 50, doc: a.doc.jws, cap: a.friendCap(b.userId) });
    const r = await receive(store, b, seal(a, b, "contact", { text: accept }));
    expect(r.ok && r.contact?.type).toBe("accept");
    if (r.ok && r.contact?.type === "accept") expect(r.contact.friendship.inviteeCap?.sub).toBe(b.userId);
    expect(await store.listFriendships()).toHaveLength(0);
    // An accept for an unknown invite.
    const other = createInviteV3(b.signer(), { aud: "*", iat: NOW - 100 });
    expect(outcome(await receive(store, b, seal(a, b, "contact", { text: createAcceptV3(a.signer(), other, { iat: NOW - 50, doc: a.doc.jws }) })))).toBe("unknown-invite");
  });

  it("contact: a cap grant only from a stored friend", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    const cap = a.friendCap(b.userId);
    expect(outcome(await receive(store, b, seal(a, b, "contact", { text: cap })))).toBe("no-friendship");
    await friends(a, b, store);
    const r = await receive(store, b, seal(a, b, "contact", { text: a.friendCap(b.userId) }));
    expect(r.ok && r.contact?.type).toBe("cap");
    const forOther = createCap(a.dev, a.dev.cert, { purpose: "friend", sub: makeUser("x").userId, relays: [RELAY], iat: NOW - 1 });
    expect(outcome(await receive(store, b, seal(a, b, "contact", { text: forOther })))).toBe("cap-invalid");
  });

  it("contact: a circle invite with its full chain is bootstrapped and held", async () => {
    const owner = makeUser("owen");
    const b = makeUser("bob");
    const store = await storeKnowing(owner, b);
    const g = createCircle(owner.ik, { name: "team", members: [b.userId], iat: NOW - 100 });
    const v2 = createNextCircleVersion(owner.ik, CircleChain.bootstrap([g]).head, { name: "team2", iat: NOW - 50 });
    const r = await receive(store, b, seal(owner, b, "contact", { circle: v2, chain: [g] }));
    expect(r.ok && r.contact?.type).toBe("circle-invite");
    if (r.ok && r.contact?.type === "circle-invite") expect(r.contact.chain?.head.ver).toBe(2);
    expect(await store.listCircles()).toHaveLength(0);
  });

  it("circle: from a friend, a standing member or a listed member; otherwise held as an invite", async () => {
    const { owner, bob, carol, chain, storeB } = await circleWorld();
    const v2 = createNextCircleVersion(owner.ik, chain.head, { name: "renamed", iat: NOW - 10 });
    const r = await receive(storeB, bob, seal(owner, bob, "circle", { circles: [v2], joins: [], ops: [] }));
    expect(r.ok && r.circle).toEqual({ authorizedBy: "stands", cids: [chain.cid] });
    const stranger = makeUser("stranger");
    await learn(storeB, stranger);
    const r2 = await receive(storeB, bob, seal(stranger, bob, "circle", { want: { cid: chain.cid, fromVer: 1 } }));
    expect(r2.ok && r2.circle?.authorizedBy).toBe("held");
    void carol;
  });

  it("unfriend: from the sender, naming this user; stored", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    const uf = createUnfriendV3(a.signer(), { peer: b.userId, inv: b64uEncode(new Uint8Array(32)), iat: NOW });
    expect(outcome(await receive(store, b, seal(a, b, "unfriend", { text: uf })))).toBe("unfriend");
    expect(await store.listUnfriends()).toHaveLength(1);
    const c = makeUser("carol");
    const aboutCarol = createUnfriendV3(a.signer(), { peer: c.userId, inv: b64uEncode(new Uint8Array(32)), iat: NOW });
    expect(outcome(await receive(store, b, seal(a, b, "unfriend", { text: aboutCarol })))).toBe("friendship-mismatch");
  });

  it("roster rules carry over: owner mismatch, stale and conflicting versions", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    await friends(a, b, store);
    const r2 = roster(a, [a, b], { ver: 2 });
    expect((await receive(store, b, seal(a, b, "msg", { text: "x", roster: r2 }))).ok).toBe(true);
    expect(outcome(await receive(store, b, seal(a, b, "msg", { text: "x", roster: roster(a, [a, b], { ver: 1 }) })))).toBe("stale-roster");
    const r2b = createRosterV3(a.signer(), { sid: "s1", ver: 2, vis: "private", parts: [a.userId], iat: NOW - 1 });
    expect(outcome(await receive(store, b, seal(a, b, "msg", { text: "x", roster: r2b })))).toBe("roster-conflict");
    expect(outcome(await receive(store, b, seal(a, b, "msg", { text: "x", roster: roster(b, [a, b]) })))).toBe("roster-owner-mismatch");
    expect(outcome(await receive(store, b, seal(a, b, "msg", { text: "x" }, { sid: "nope" })))).toBe("no-roster");
  });
});

function createDeviceCertFor(u: TestUser, d: TestUser["devices"][number], iat: number): string {
  return createDeviceCert(u.ik, { ...d, label: d.label }, { iat });
}

describe("§4.3 owner-only session kinds (pre-release review M2)", () => {
  it("a participant's status, idle or roster for the owner's session is rejected; its msg is not", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const c = makeUser("carol");
    const store = await storeKnowing(a, b, c);
    await friends(a, c, store);
    await friends(a, b, store);
    await friends(b, c, store);
    const ro = roster(a, [a, b, c]);
    const own = { own: a.userId };
    // The control: bob may write a message into alice's session.
    expect(outcome(await receive(store, c, seal(b, c, "msg", { text: "x", roster: ro }, own)))).toMatch(/participant/);
    for (const [kind, pt] of [
      ["status", { status: { state: "busy", label: "spoofed" }, roster: ro }],
      ["idle", { reason: "exited", roster: ro }],
      ["roster", { roster: ro }],
    ] as const) {
      expect(outcome(await receive(store, c, seal(b, c, kind, pt, own)))).toBe("not-session-owner");
    }
    // The owner still may.
    expect(outcome(await receive(store, c, seal(a, c, "status", { status: { state: "busy", label: "web" }, roster: ro })))).toMatch(/owner/);
  });
});

// Deferred replay recording (IncomingContextV3.replayClaim): the window records an envelope only
// once the receiver applied it, so a crash in between doesn't turn the redelivery into a drop.
describe("§4.4 replay claims: record only what was applied", () => {
  // `alive`: the tokens whose holders are known to run (a process on this machine); undefined
  // means nobody can tell (a claim from another host), so the TTL decides.
  const claimCtx = (store: TrustStoreV3, to: TestUser, token: string, alive: Set<string> | undefined, nowMs = NOW_MS) => ({
    self: { userId: to.userId, did: to.dev.did, agreementSecretKey: to.dev.agreementSecretKey, cert: to.dev.cert },
    store,
    nowMs,
    replayClaim: {
      claimant: { token, host: "h", pid: 1 },
      isAlive: (c: { token: string }) => (alive ? alive.has(c.token) : undefined),
      // As the CLI does: only a clearly local, transient failure (a lock timeout) is retried.
      retryable: (e: unknown) => /is locked/.test(String((e as Error)?.message)),
    },
  });

  it("a crash after the claim (no commit) leaves the redelivery to be applied, then it is replayed", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    await friends(a, b, store);
    const env = seal(a, b, "msg", { text: "x", roster: roster(a, [a, b]) });
    const alive = new Set<string>(["t1"]);
    const first = await verifyIncomingV3(env, claimCtx(store, b, "t1", alive));
    expect(first.ok && typeof first.commitReplay).toBe("function");
    // While the first attempt is alive, a duplicate (another process, another relay) must wait.
    expect(outcome(await verifyIncomingV3(env, claimCtx(store, b, "t2", alive)))).toBe("replay-in-progress");
    // The first attempt dies before applying it: never committed.
    alive.delete("t1");
    const again = await verifyIncomingV3(env, claimCtx(store, b, "t3", alive));
    expect(again.ok).toBe(true);
    if (again.ok) await again.commitReplay!();
    // Applied once: every later copy is a replay, with or without claims.
    expect(outcome(await verifyIncomingV3(env, claimCtx(store, b, "t4", alive)))).toBe("replayed-seq");
    expect(outcome(await receive(store, b, env))).toBe("replayed-seq");
  });

  it("a duplicate learns of a live claim without the store's lock; a dead claim still goes to claimReplay", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    await friends(a, b, store);
    const env = seal(a, b, "msg", { text: "x", roster: roster(a, [a, b]) });
    const alive = new Set<string>(["t1"]);
    const first = await verifyIncomingV3(env, claimCtx(store, b, "t1", alive));
    expect(first.ok).toBe(true);
    // The locked read-modify-write is never reached while the holder lives.
    const claim = store.claimReplay.bind(store);
    let locked = 0;
    store.claimReplay = (...args: Parameters<TrustStoreV3["claimReplay"]>) => {
      locked++;
      return claim(...args);
    };
    expect(outcome(await verifyIncomingV3(env, claimCtx(store, b, "t2", alive)))).toBe("replay-in-progress");
    expect(locked).toBe(0);
    // The holder died: only claimReplay may take the claim over.
    alive.delete("t1");
    const again = await verifyIncomingV3(env, claimCtx(store, b, "t3", alive));
    expect(again.ok).toBe(true);
    expect(locked).toBe(1);
    if (again.ok) await again.commitReplay!();
    expect(outcome(await verifyIncomingV3(env, claimCtx(store, b, "t4", alive)))).toBe("replayed-seq");
  });

  it("a claim nobody can vouch for (another host) expires after REPLAY_CLAIM_TTL_MS", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    await friends(a, b, store);
    const env = seal(a, b, "msg", { text: "x", roster: roster(a, [a, b]) });
    expect((await verifyIncomingV3(env, claimCtx(store, b, "t1", undefined))).ok).toBe(true);
    expect(outcome(await verifyIncomingV3(env, claimCtx(store, b, "t2", undefined, NOW_MS + 1000)))).toBe("replay-in-progress");
    expect((await verifyIncomingV3(env, claimCtx(store, b, "t2", undefined, NOW_MS + REPLAY_CLAIM_TTL_MS))).ok).toBe(true);
  });

  it("a live holder on this machine keeps its claim past the TTL (review M-1): no second apply", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    await friends(a, b, store);
    const env = seal(a, b, "msg", { text: "x", roster: roster(a, [a, b]) });
    const alive = new Set(["slow"]);
    const slow = await verifyIncomingV3(env, claimCtx(store, b, "slow", alive));
    expect(slow.ok).toBe(true);
    // Still applying an hour later (a stalled fetch, a sleeping laptop): another local process waits.
    expect(outcome(await verifyIncomingV3(env, claimCtx(store, b, "second", alive, NOW_MS + 3600_000)))).toBe("replay-in-progress");
    if (slow.ok) expect(await slow.commitReplay!()).toBeUndefined();
    expect(outcome(await verifyIncomingV3(env, claimCtx(store, b, "third", alive, NOW_MS + 3600_000)))).toBe("replayed-seq");
  });

  it("a non-protocol failure after the claim releases it, unrecorded (review L-1): the redelivery is applied", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    await friends(a, b, store);
    const env = seal(a, b, "msg", { text: "x", roster: roster(a, [a, b]) });
    const put = store.putDeviceCert.bind(store);
    store.putDeviceCert = async () => {
      throw new Error("trust store is locked");
    };
    const alive = new Set(["t1", "t2"]);
    await expect(verifyIncomingV3(env, claimCtx(store, b, "t1", alive))).rejects.toThrow(/locked/);
    store.putDeviceCert = put;
    // t1's holder is still alive, but it gave the claim up: nothing waits, nothing was recorded.
    const again = await verifyIncomingV3(env, claimCtx(store, b, "t2", alive));
    expect(again.ok).toBe(true);
  });

  it("an envelope rejected after its signature verified still spends its seq", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    // Not friends, roster doesn't let them in: rejected at authorisation, after the claim.
    const env = seal(a, b, "msg", { text: "x", roster: roster(a, [a]) });
    const r = await verifyIncomingV3(env, claimCtx(store, b, "t1", new Set(["t1"])));
    expect(r.ok).toBe(false);
    expect(outcome(await receive(store, b, env))).toBe("replayed-seq");
  });

  it("a poison envelope is given up after REPLAY_MAX_ATTEMPTS attempts (review M-A), then is a replay", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    await friends(a, b, store);
    const env = seal(a, b, "msg", { text: "x", roster: roster(a, [a, b]) });
    const alive = new Set<string>();
    for (let i = 1; i <= REPLAY_MAX_ATTEMPTS; i++) {
      // Each attempt claims it and dies (or times out) before applying it.
      const r = await verifyIncomingV3(env, claimCtx(store, b, `t${i}`, alive));
      expect(r.ok && r.attempt).toBe(i);
    }
    expect(outcome(await verifyIncomingV3(env, claimCtx(store, b, "t-last", alive)))).toBe("gave-up");
    expect(outcome(await verifyIncomingV3(env, claimCtx(store, b, "t-after", alive)))).toBe("replayed-seq");
  });

  it("attempts abandoned by their process exiting don't count as failures, but are capped at REPLAY_MAX_ABANDONS (review F1)", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    await friends(a, b, store);
    const env = seal(a, b, "msg", { text: "x", roster: roster(a, [a, b]) });
    const alive = new Set<string>();
    // Every short command runs out of time on it and gives the claim back uncounted.
    for (let i = 1; i <= REPLAY_MAX_ABANDONS; i++) {
      const r = await verifyIncomingV3(env, claimCtx(store, b, `t${i}`, alive));
      expect(r.ok && r.attempt).toBe(1); // never a failed attempt
      if (r.ok) await r.releaseReplay!({ uncount: true });
    }
    // An envelope whose handling always outlives a command can't come back forever.
    expect(outcome(await verifyIncomingV3(env, claimCtx(store, b, "t-last", alive)))).toBe("gave-up");
    expect(outcome(await verifyIncomingV3(env, claimCtx(store, b, "t-after", alive)))).toBe("replayed-seq");
  });

  it("an abandoned attempt still leaves room for real ones: two abandons, then a success applies it", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    await friends(a, b, store);
    const env = seal(a, b, "msg", { text: "x", roster: roster(a, [a, b]) });
    const alive = new Set<string>();
    for (let i = 1; i <= 2; i++) {
      const r = await verifyIncomingV3(env, claimCtx(store, b, `t${i}`, alive));
      if (r.ok) await r.releaseReplay!({ uncount: true });
    }
    const r = await verifyIncomingV3(env, claimCtx(store, b, "t-ok", alive));
    expect(r.ok).toBe(true);
    if (r.ok) expect(await r.commitReplay!()).toBeUndefined();
    expect(outcome(await verifyIncomingV3(env, claimCtx(store, b, "t-after", alive)))).toBe("replayed-seq");
  });

  it("a failure that isn't clearly transient is final at once: the seq is spent", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    await friends(a, b, store);
    const env = seal(a, b, "msg", { text: "x", roster: roster(a, [a, b]) });
    const put = store.putDeviceCert.bind(store);
    store.putDeviceCert = async () => {
      throw new TypeError("a bug");
    };
    await expect(verifyIncomingV3(env, claimCtx(store, b, "t1", new Set(["t1"])))).rejects.toThrow(/a bug/);
    store.putDeviceCert = put;
    expect(outcome(await verifyIncomingV3(env, claimCtx(store, b, "t2", new Set(["t1", "t2"]))))).toBe("replayed-seq");
  });
});
