// Copyright 2026 Ix Infrastructure Inc.
//
// The rejection matrix for verifyIncoming, plus the two-user cross-org
// scenario from docs/protocol-v2.md run end to end in memory.

import { beforeEach, describe, expect, it } from "vitest";
import { FakeKartr, NOW, NOW_MS, Peer } from "./fixtures.js";
import {
  createAccept,
  createInvite,
  createRoster,
  createUnfriend,
  inviteHash,
  signDeviceCert,
  TYP,
  verifyFriendship,
  verifyInvite,
  type FriendshipProof,
} from "../objects.js";
import { decodeEnvelope } from "../envelope.js";
import { signJws } from "../jws.js";
import { b64uDecode, b64uEncode } from "../encoding.js";
import { randomBytes } from "../crypto.js";
import { recordFriendship, recordRoster, updateRevocations, verifyIncoming, type IncomingResult } from "../verify.js";

function expectReject(r: IncomingResult, reason: string) {
  if (r.ok) throw new Error(`expected ${reason}, got accepted (${r.rule})`);
  expect(r.reason).toBe(reason);
}

function expectAccept(r: IncomingResult, rule?: string) {
  if (!r.ok) throw new Error(`expected accept, got ${r.reason}: ${r.message}`);
  if (rule) expect(r.rule).toBe(rule);
  return r;
}

/** Re-sign an envelope after editing its payload (an insider-sender forgery). */
function resign(env: string, sk: Uint8Array, edit: (p: Record<string, unknown>) => void, kid?: string) {
  const d = decodeEnvelope(env);
  const p = { ...d.payload } as Record<string, unknown>;
  edit(p);
  return signJws(TYP.msg, kid ?? (p.fdid as string), p, sk);
}

async function befriend(kartr: FakeKartr, inviter: Peer, invitee: Peer): Promise<FriendshipProof> {
  const invite = createInvite(inviter.keys, { aud: invitee.userId, iat: NOW - 600 });
  const proof = { invite, accept: createAccept(invitee.keys, invite, { iat: NOW - 300 }) };
  const f = await verifyFriendship(proof, kartr.verifyOpts());
  await recordFriendship(inviter.trust, f);
  await recordFriendship(invitee.trust, f);
  inviter.friendships.set(invitee.userId, proof);
  invitee.friendships.set(inviter.userId, proof);
  return proof;
}

describe("verifyIncoming rejection matrix", () => {
  let kartr: FakeKartr;
  let alice: Peer; // session owner, org A
  let bob: Peer; // cross-org friend, in parts
  let roster: string;

  beforeEach(async () => {
    kartr = new FakeKartr();
    alice = new Peer(kartr, "alice@a.example");
    alice.workspace = kartr.attest(alice.userId, ["orgA"]);
    bob = new Peer(kartr, "bob@b.example");
    await befriend(kartr, alice, bob);
    roster = createRoster(alice.keys, { sid: "s1", ver: 1, vis: "private", org: "orgA", parts: [bob.userId], iat: NOW - 60 });
  });

  it("baseline: a friend in parts is accepted", async () => {
    const r = expectAccept(await alice.receive(bob.seal(alice, { sid: "s1", roster })), "participant-friend");
    expect(r.plaintext.text).toBe("hello");
    expect(r.roster?.ver).toBe(1);
  });

  it("forged Kartr signature on the sender cert", async () => {
    const d = bob.keys;
    bob.cert = signDeviceCert(
        { sub: d.userId, did: d.deviceId, spk: b64uEncode(d.signingPublicKey), kpk: b64uEncode(d.agreementPublicKey), iat: NOW - 10, exp: NOW + 100 },
        randomBytes(32),
        kartr.kid,
    );
    expectReject(await alice.receive(bob.seal(alice, { sid: "s1", roster })), "kartr-signature-invalid");
  });

  it("expired sender cert", async () => {
    bob.cert = kartr.issueCert(bob.keys, { iat: NOW - 31 * 24 * 3600, exp: NOW - 24 * 3600 });
    expectReject(await alice.receive(bob.seal(alice, { sid: "s1", roster })), "expired");
  });

  it("revoked sender device", async () => {
    kartr.revoked.add(bob.keys.deviceId);
    expect(await updateRevocations(alice.trust, kartr.revocations(), { kartr: kartr.keys(), now: NOW })).toBe(true);
    expectReject(await alice.receive(bob.seal(alice, { sid: "s1", roster })), "device-revoked");
  });

  it("revoked inviter device ends the stored friendship", async () => {
    // Friendship made by a second alice device that is later revoked.
    const kartr2 = kartr;
    const alice2 = new Peer(kartr2, "alice@a.example");
    const carol = new Peer(kartr2, "carol@c.example");
    const invite = createInvite(alice2.keys, { aud: carol.userId, iat: NOW - 600 });
    const f = await verifyFriendship({ invite, accept: createAccept(carol.keys, invite, { iat: NOW - 300 }) }, kartr2.verifyOpts());
    await recordFriendship(alice.trust, f);
    const r2 = createRoster(alice.keys, { sid: "s2", ver: 1, vis: "private", org: "orgA", parts: [carol.userId], iat: NOW });
    expectAccept(await alice.receive(carol.seal(alice, { sid: "s2", roster: r2 })), "participant-friend");
    kartr2.revoked.add(alice2.keys.deviceId);
    await updateRevocations(alice.trust, kartr2.revocations(NOW + 1), { kartr: kartr2.keys(), now: NOW + 1 });
    expectReject(await alice.receive(carol.seal(alice, { sid: "s2" })), "no-friendship");
  });

  it("kid mismatch (header kid != fdid)", async () => {
    const env = resign(bob.seal(alice, { sid: "s1", roster }), bob.keys.signingSecretKey, () => {}, alice.keys.deviceId);
    expectReject(await alice.receive(env), "kid-mismatch");
  });

  it("typ confusion: a roster presented as an invite", async () => {
    const env = bob.seal(alice, { sid: "s1", roster, friendship: { invite: roster, accept: roster } });
    expectReject(await alice.receive(env), "typ-mismatch");
    await expect(verifyInvite(roster, kartr.verifyOpts())).rejects.toThrow(/typ-mismatch/);
  });

  it("typ confusion: an invite presented as the fcert", async () => {
    const invite = createInvite(bob.keys, { aud: "*", iat: NOW });
    const env = bob.seal(alice, { sid: "s1", roster, fcert: invite });
    expectReject(await alice.receive(env), "typ-mismatch");
  });

  it("non-participant (a friend of the owner not in parts)", async () => {
    const carol = new Peer(kartr, "carol@c.example");
    await befriend(kartr, alice, carol);
    expectReject(await alice.receive(carol.seal(alice, { sid: "s1", roster })), "not-participant");
  });

  it("unfriended", async () => {
    expectAccept(await alice.receive(bob.seal(alice, { sid: "s1", roster })));
    const inv = (await alice.trust.listFriendships())[0].inv;
    const u = createUnfriend(alice.keys, { peer: bob.userId, inv, iat: NOW });
    await alice.trust.addUnfriend({ iss: alice.userId, peer: bob.userId, inv, iat: NOW, jws: u });
    expectReject(await alice.receive(bob.seal(alice, { sid: "s1" })), "unfriended");
    // Re-presenting the old friendship proof doesn't help.
    expectReject(await alice.receive(bob.seal(alice, { sid: "s1", roster })), "unfriended");
  });

  it("private roster: a workspace member not in parts", async () => {
    const dave = new Peer(kartr, "dave@a.example");
    dave.workspace = kartr.attest(dave.userId, ["orgA"]);
    expectReject(await alice.receive(dave.seal(alice, { sid: "s1", roster })), "not-participant");
    // The same member is fine on a workspace roster, relaying the owner's attestation (D9).
    dave.ownerWorkspaces.set(alice.userId, alice.workspace!);
    const ws = createRoster(alice.keys, { sid: "s1", ver: 2, vis: "workspace", org: "orgA", parts: [], iat: NOW });
    expectAccept(await alice.receive(dave.seal(alice, { sid: "s1", roster: ws })), "workspace");
  });

  it("a workspace attestation for someone else", async () => {
    bob.workspace = kartr.attest("dave@a.example", ["orgA"]);
    expectReject(await alice.receive(bob.seal(alice, { sid: "s1", roster })), "workspace-mismatch");
  });

  it("replayed envelope (seq window first, nonce LRU as backup)", async () => {
    const env = bob.seal(alice, { sid: "s1", roster });
    expectAccept(await alice.receive(env));
    expectReject(await alice.receive(env), "replayed-seq");
    // The nonce is recorded too, as defence in depth behind the seq window.
    const rec = (await alice.trust.getReplay(bob.keys.deviceId))!;
    expect(rec.nonces).toHaveLength(1);
  });

  describe("D6: late delivery from the relay's 24h store", () => {
    it("accepts an envelope 2h late once; a replay hits the seq window", async () => {
      const late = bob.seal(alice, { sid: "s1", roster, ts: NOW_MS - 2 * 3600_000 });
      expectAccept(await alice.receive(late));
      expectReject(await alice.receive(late), "replayed-seq");
    });

    it("rejects ts more than 10 min in the future", async () => {
      expectReject(await alice.receive(bob.seal(alice, { sid: "s1", roster, ts: NOW_MS + 10 * 60_000 + 1 })), "stale-timestamp");
      expectAccept(await alice.receive(bob.seal(alice, { sid: "s1", roster, ts: NOW_MS + 9 * 60_000 })));
    });

    it("rejects an envelope older than 24h10m", async () => {
      const ts = NOW_MS - (24 * 60 + 10) * 60_000 - 1;
      expectReject(await alice.receive(bob.seal(alice, { sid: "s1", roster, ts })), "stale-timestamp");
      expectAccept(await alice.receive(bob.seal(alice, { sid: "s1", roster, ts: ts + 2 })));
    });
  });

  it("replayed seq", async () => {
    expectAccept(await alice.receive(bob.seal(alice, { sid: "s1", roster, seq: 5 })));
    expectReject(await alice.receive(bob.seal(alice, { sid: "s1", seq: 5 })), "replayed-seq");
    // Reordered delivery inside the window is accepted once (D7).
    expectAccept(await alice.receive(bob.seal(alice, { sid: "s1", seq: 4 })));
    expectReject(await alice.receive(bob.seal(alice, { sid: "s1", seq: 4 })), "replayed-seq");
    expectAccept(await alice.receive(bob.seal(alice, { sid: "s1", seq: 6 })));
  });

  it("stale timestamp", async () => {
    expectReject(await alice.receive(bob.seal(alice, { sid: "s1", roster, ts: NOW_MS - 24 * 3600_000 - 11 * 60_000 })), "stale-timestamp");
    expectReject(await alice.receive(bob.seal(alice, { sid: "s1", roster, ts: NOW_MS + 11 * 60_000 })), "stale-timestamp");
  });

  it("old roster version", async () => {
    const v2 = createRoster(alice.keys, { sid: "s1", ver: 2, vis: "private", org: "orgA", parts: [bob.userId], iat: NOW });
    expectAccept(await alice.receive(bob.seal(alice, { sid: "s1", roster: v2 })));
    expectReject(await alice.receive(bob.seal(alice, { sid: "s1", roster })), "stale-roster");
  });

  it("an older roster can't readmit a removed participant", async () => {
    const carol = new Peer(kartr, "carol@c.example");
    await befriend(kartr, alice, carol);
    const v1 = createRoster(alice.keys, { sid: "s3", ver: 1, vis: "private", org: "orgA", parts: [carol.userId], iat: NOW });
    const v2 = createRoster(alice.keys, { sid: "s3", ver: 2, vis: "private", org: "orgA", parts: [], iat: NOW });
    expectAccept(await alice.receive(carol.seal(alice, { sid: "s3", roster: v1 })));
    expect(await recordRoster(alice.trust, v2, kartr.verifyOpts())).toBe("stored");
    expectReject(await alice.receive(carol.seal(alice, { sid: "s3" })), "not-participant");
    expectReject(await alice.receive(carol.seal(alice, { sid: "s3", roster: v1 })), "stale-roster");
  });

  it("a roster whose signer isn't the envelope's session owner", async () => {
    // Bob signs a roster for alice's sid and claims the session is alice's.
    const fake = createRoster(bob.keys, { sid: "s1", ver: 99, vis: "private", org: "orgA", parts: [bob.userId], iat: NOW });
    expectReject(await alice.receive(bob.seal(alice, { sid: "s1", own: alice.userId, roster: fake })), "roster-owner-mismatch");
  });

  it("the same sid under another owner is a different session", async () => {
    expect(await recordRoster(alice.trust, roster, kartr.verifyOpts())).toBe("stored");
    // Bob owns his own "s1"; alice is not in it, so she (the viewer) refuses it.
    const bobs = createRoster(bob.keys, { sid: "s1", ver: 1, vis: "private", org: "orgB", parts: [], iat: NOW });
    expectReject(await alice.receive(bob.seal(alice, { sid: "s1", own: bob.userId, roster: bobs })), "viewer-not-participant");
    // Alice's (alice, s1) roster is untouched and still authorises bob there.
    expect((await alice.trust.getRoster(alice.userId, "s1"))?.jws).toBe(roster);
    expect(await alice.trust.getRoster(bob.userId, "s1")).toBeUndefined();
    expectAccept(await alice.receive(bob.seal(alice, { sid: "s1", own: alice.userId })), "participant-friend");
  });

  it("the fcert alone authenticates the sender: no directory lookup", async () => {
    // No proofs signed by other devices, so nothing else needs resolving.
    alice.friendships.clear();
    await updateRevocations(bob.trust, kartr.revocations(), { kartr: kartr.keys(), now: NOW, nowMs: NOW_MS });
    const r = await verifyIncoming(alice.seal(bob, { sid: "s1", roster }), {
      self: bob.keys,
      kartr: kartr.keys(),
      trust: bob.trust,
      nowMs: NOW_MS,
    });
    expectAccept(r, "owner");
  });

  it("tampered ciphertext (outer signature)", async () => {
    const env = resign(bob.seal(alice, { sid: "s1", roster }), randomBytes(32), () => {});
    expectReject(await alice.receive(env), "bad-signature");
    const [h, p, s] = bob.seal(alice, { sid: "s1", roster }).split(".");
    const payload = JSON.parse(Buffer.from(p, "base64url").toString());
    const ct = b64uDecode(payload.ct);
    ct[0] ^= 1;
    payload.ct = b64uEncode(ct);
    expectReject(await alice.receive(`${h}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${s}`), "bad-signature");
  });

  it("tampered ciphertext (re-signed by the sender)", async () => {
    const env = resign(bob.seal(alice, { sid: "s1", roster }), bob.keys.signingSecretKey, (p) => {
      const ct = b64uDecode(p.ct as string);
      ct[ct.length - 1] ^= 1;
      p.ct = b64uEncode(ct);
    });
    expectReject(await alice.receive(env), "decrypt-failed");
  });

  it("tampered AAD fields (re-signed by the sender)", async () => {
    // Replay state is recorded once the signature verifies, so the seq edit
    // (which slides the window far ahead) goes last.
    for (const edit of [
      (p: Record<string, unknown>) => (p.kind = "idle"),
      (p: Record<string, unknown>) => (p.ts = (p.ts as number) + 1),
      (p: Record<string, unknown>) => (p.seq = 1000),
    ]) {
      expectReject(await alice.receive(resign(bob.seal(alice, { sid: "s1", roster }), bob.keys.signingSecretKey, edit)), "decrypt-failed");
    }
  });

  it("an envelope addressed to another device", async () => {
    const alice2 = new Peer(kartr, "alice@a.example");
    const env = bob.seal(alice, { sid: "s1", roster });
    expectReject(await alice2.receive(env), "wrong-recipient");
    // Rewriting tdid to the receiving device breaks the signature (and the AAD).
    const rewritten = resign(env, randomBytes(32), (p) => (p.tdid = alice2.keys.deviceId));
    expectReject(await alice2.receive(rewritten), "bad-signature");
  });

  it("an fcert for another device", async () => {
    const carol = new Peer(kartr, "carol@c.example");
    expectReject(await alice.receive(bob.seal(alice, { sid: "s1", roster, fcert: carol.cert })), "kid-mismatch");
  });

  it("an fcert for the right device but another user", async () => {
    const d = bob.keys;
    const wrongSub = signDeviceCert(
      { sub: "carol@c.example", did: d.deviceId, spk: b64uEncode(d.signingPublicKey), kpk: b64uEncode(d.agreementPublicKey), iat: NOW - 10, exp: NOW + 100 },
      kartr.sk,
      kartr.kid,
    );
    expectReject(await alice.receive(bob.seal(alice, { sid: "s1", roster, fcert: wrongSub })), "cert-mismatch");
  });

  it("an fcert whose keys aren't the signer's", async () => {
    const mallory = new Peer(kartr, "mallory@m.example");
    // Mallory sends bob's genuine cert as fcert but signs with her own key.
    const env = resign(mallory.seal(alice, { sid: "s1", roster }), mallory.keys.signingSecretKey, (p) => {
      p.from = bob.userId;
      p.fdid = bob.keys.deviceId;
      p.fcert = bob.cert;
    });
    expectReject(await alice.receive(env), "bad-signature");
  });

  it("no roster for the session", async () => {
    expectReject(await alice.receive(bob.seal(alice, { sid: "unknown" })), "no-roster");
  });

  it("a roster for a different session", async () => {
    expectReject(await alice.receive(bob.seal(alice, { sid: "s9", roster })), "roster-session-mismatch");
  });

  it("an '*' invite already bound to someone else", async () => {
    const carol = new Peer(kartr, "carol@c.example");
    const dave = new Peer(kartr, "dave@d.example");
    const open = createInvite(alice.keys, { aud: "*", iat: NOW - 100 });
    const fc = await verifyFriendship({ invite: open, accept: createAccept(carol.keys, open, { iat: NOW - 50 }) }, kartr.verifyOpts());
    await recordFriendship(alice.trust, fc);
    const r = createRoster(alice.keys, { sid: "s4", ver: 1, vis: "private", org: "orgA", parts: [dave.userId], iat: NOW });
    const proof = { invite: open, accept: createAccept(dave.keys, open, { iat: NOW - 40 }) };
    expectReject(await alice.receive(dave.seal(alice, { sid: "s4", roster: r, friendship: proof })), "invite-already-bound");
  });

  it("rejections leave no state behind", async () => {
    const env = bob.seal(alice, { sid: "s1", roster, ts: NOW_MS + 11 * 60_000 });
    expectReject(await alice.receive(env), "stale-timestamp");
    expect(await alice.trust.getReplay(bob.keys.deviceId)).toBeUndefined();
    expect(await alice.trust.getRoster(alice.userId, "s1")).toBeUndefined();
  });
});

describe("two-user cross-org scenario", () => {
  it("invite, accept, share, chat both ways, unfriend", async () => {
    const kartr = new FakeKartr();
    // A works in org A, B in org B: they share no workspace.
    const a = new Peer(kartr, "alice@a.example");
    a.workspace = kartr.attest(a.userId, ["orgA"]);
    const b = new Peer(kartr, "bob@b.example");
    b.workspace = kartr.attest(b.userId, ["orgB"]);

    // 1. A invites B (the code travels out of band).
    const invite = createInvite(a.keys, { aud: b.userId, iat: NOW - 120 });

    // 2. B verifies the invite against A's cert and accepts.
    const vi = await verifyInvite(invite, { kartr: kartr.keys(), now: NOW, resolveCert: kartr.resolver() });
    expect(vi.iss).toBe(a.userId);
    const accept = createAccept(b.keys, invite, { iat: NOW - 60 });
    const friendship = { invite, accept };
    await recordFriendship(b.trust, await verifyFriendship(friendship, kartr.verifyOpts()));

    // 3. A shares a private session with B; the first envelope carries the
    //    roster, and B's first reply carries the friendship proof.
    const roster = createRoster(a.keys, { sid: "sess", ver: 1, vis: "private", org: "orgA", parts: [b.userId], iat: NOW });
    expect(await recordRoster(a.trust, roster, kartr.verifyOpts())).toBe("stored");
    const share = expectAccept(await b.receive(a.seal(b, { sid: "sess", kind: "roster", roster, text: "joining?" })), "owner");
    expect(share.roster?.ver).toBe(1);

    const hi = expectAccept(
      await a.receive(b.seal(a, { sid: "sess", text: "hi A", friendship })),
      "participant-friend",
    );
    expect(hi.plaintext.text).toBe("hi A");
    // verifyIncoming never stores friendships; A's app adopts the accept for
    // the invite A issued.
    expect(await a.trust.listFriendships()).toHaveLength(0);
    expect(hi.friendship?.inv).toBe(inviteHash(invite));
    await recordFriendship(a.trust, hi.friendship!);
    expect(await a.trust.listFriendships()).toHaveLength(1);

    // 4. Messages flow both ways without re-sending proofs.
    for (let i = 0; i < 3; i++) {
      a.nowMs += 1000;
      b.nowMs += 1000;
      expect(expectAccept(await b.receive(a.seal(b, { sid: "sess", text: `a${i}` }))).plaintext.text).toBe(`a${i}`);
      expect(expectAccept(await a.receive(b.seal(a, { sid: "sess", text: `b${i}` })), "participant-friend").plaintext.text).toBe(`b${i}`);
    }

    // 5. B unfriends A; the unfriend rides in an envelope of kind "unfriend".
    const inv = (await b.trust.listFriendships())[0].inv;
    const unfriend = createUnfriend(b.keys, { peer: a.userId, inv, iat: NOW + 10 });
    await b.trust.addUnfriend({ iss: b.userId, peer: a.userId, inv, iat: NOW + 10, jws: unfriend });
    a.nowMs += 1000;
    b.nowMs += 1000;
    expectAccept(await a.receive(b.seal(a, { sid: "sess", kind: "unfriend", text: unfriend })), "unfriend");

    // 6. B's messages into A's session are now rejected...
    b.nowMs += 1000;
    a.nowMs += 1000;
    expectReject(await a.receive(b.seal(a, { sid: "sess", text: "still there?" })), "unfriended");
    expectReject(await a.receive(b.seal(a, { sid: "sess", text: "proof!", friendship })), "unfriended");
    // ...and, authorisation being two-sided (C6), B also refuses A's messages
    // into A's own session: B no longer stands in it through a friendship,
    // and B's workspace (orgB) isn't the session's org.
    expectReject(await b.receive(a.seal(b, { sid: "sess", text: "bye" })), "viewer-unfriended");
    expectReject(await b.receive(a.seal(b, { sid: "sess", text: "bye", roster })), "viewer-unfriended");
  });
});
