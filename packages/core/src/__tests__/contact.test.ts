// Copyright 2026 Ix Infrastructure Inc.
//
// Draft 2 D8: `kind: "contact"` envelopes carrying one invite, accept or
// unfriend between users who share no session.

import { beforeEach, describe, expect, it } from "vitest";
import { FakeKartr, NOW, NOW_MS, Peer } from "./fixtures.js";
import { CONTACT_SID, decodeEnvelope, sealContact, sealEnvelope } from "../envelope.js";
import { signJws } from "../jws.js";
import { createAccept, createInvite, createRoster, createUnfriend, inviteHash, TYP } from "../objects.js";
import { matchOutgoingInvite, recordFriendship, recordOutgoingInvite, type IncomingResult } from "../verify.js";

function contact(from: Peer, to: Peer, object: string, seq = 1): string {
  return sealContact({
    from: from.userId,
    fdid: from.keys.deviceId,
    fcert: from.cert,
    to: to.userId,
    tdid: to.keys.deviceId,
    seq,
    ts: NOW_MS,
    object,
    sender: from.keys,
    recipientKpk: to.keys.agreementPublicKey,
  });
}

const reason = (r: IncomingResult) => (r.ok ? `accepted:${r.rule}` : r.reason);

describe("D8: contact envelopes", () => {
  let kartr: FakeKartr;
  let alice: Peer;
  let bob: Peer;
  beforeEach(() => {
    kartr = new FakeKartr();
    alice = new Peer(kartr, "alice@a.example");
    bob = new Peer(kartr, "bob@b.example");
  });

  it("is own = from, sid = ~contact, kind = contact", () => {
    const p = decodeEnvelope(contact(alice, bob, createInvite(alice.keys, { aud: bob.userId, iat: NOW }))).payload;
    expect(p).toMatchObject({ kind: "contact", own: alice.userId, sid: CONTACT_SID });
    expect(CONTACT_SID).toBe("~contact");
  });

  it("invite round trip (explicit aud and '*'), storing nothing", async () => {
    const invite = createInvite(alice.keys, { aud: bob.userId, iat: NOW });
    const r = await bob.receive(contact(alice, bob, invite));
    if (!r.ok || r.object?.type !== "invite") throw new Error(reason(r));
    expect(r.rule).toBe("contact");
    expect(r.object.invite).toMatchObject({ iss: alice.userId, aud: bob.userId, hash: inviteHash(invite) });
    const open = createInvite(alice.keys, { aud: "*", iat: NOW });
    const r2 = await bob.receive(contact(alice, bob, open, 2));
    expect(r2.ok && r2.object?.type).toBe("invite");
    expect(await bob.trust.listFriendships()).toEqual([]);
    expect(await bob.trust.getDeviceCert(alice.keys.deviceId)).toBeUndefined();
  });

  it("an invite for someone else is rejected", async () => {
    const invite = createInvite(alice.keys, { aud: "carol@c.example", iat: NOW });
    expect(reason(await bob.receive(contact(alice, bob, invite)))).toBe("audience-mismatch");
  });

  it("an invite relayed by someone other than its issuer is rejected", async () => {
    const carol = new Peer(kartr, "carol@c.example");
    const invite = createInvite(carol.keys, { aud: bob.userId, iat: NOW });
    expect(reason(await bob.receive(contact(alice, bob, invite)))).toBe("cert-mismatch");
  });

  it("accept round trip: matched to an outgoing invite, adopted only by the app", async () => {
    const invite = createInvite(alice.keys, { aud: bob.userId, iat: NOW - 60 });
    const stored = await recordOutgoingInvite(alice.trust, invite);
    expect(await matchOutgoingInvite(alice.trust, stored.inv)).toEqual(stored);
    const accept = createAccept(bob.keys, invite, { iat: NOW - 30 });
    const r = await alice.receive(contact(bob, alice, accept));
    if (!r.ok || r.object?.type !== "accept") throw new Error(reason(r));
    expect(r.object.friendship).toMatchObject({ inviter: alice.userId, invitee: bob.userId, inv: stored.inv });
    expect(await alice.trust.listFriendships()).toEqual([]); // verifyIncoming never stores
    await recordFriendship(alice.trust, r.object.friendship);
    expect(await alice.trust.listFriendships()).toHaveLength(1);
  });

  it("an accept for an unknown invite is ignored with unknown-invite", async () => {
    const invite = createInvite(alice.keys, { aud: bob.userId, iat: NOW - 60 }); // never recorded
    const accept = createAccept(bob.keys, invite, { iat: NOW - 30 });
    expect(reason(await alice.receive(contact(bob, alice, accept)))).toBe("unknown-invite");
  });

  it("unfriend round trip, storing nothing", async () => {
    const u = createUnfriend(bob.keys, { peer: alice.userId, inv: inviteHash("x"), iat: NOW });
    const r = await alice.receive(contact(bob, alice, u));
    if (!r.ok || r.object?.type !== "unfriend") throw new Error(reason(r));
    expect(r.object.unfriend).toMatchObject({ iss: bob.userId, peer: alice.userId });
    expect(await alice.trust.listUnfriends()).toEqual([]);
    // An unfriend naming someone else is rejected.
    const other = createUnfriend(bob.keys, { peer: "carol@c.example", inv: inviteHash("x"), iat: NOW });
    expect(reason(await alice.receive(contact(bob, alice, other, 2)))).toBe("friendship-mismatch");
  });

  it("free text, a non-JWS, an oversized or a wrong-typ object is rejected", async () => {
    let seq = 1;
    expect(reason(await bob.receive(contact(alice, bob, "hi bob, add me?", seq++)))).toBe("malformed");
    expect(reason(await bob.receive(contact(alice, bob, "a.b", seq++)))).toBe("malformed");
    const invite = createInvite(alice.keys, { aud: bob.userId, iat: NOW });
    expect(reason(await bob.receive(contact(alice, bob, `${invite} trailing`, seq++)))).toBe("malformed");
    expect(reason(await bob.receive(contact(alice, bob, `${invite}\n${invite}`, seq++)))).toBe("malformed");
    const big = signJws(TYP.invite, alice.keys.deviceId, { pad: "x".repeat(17_000) }, alice.keys.signingSecretKey);
    expect(reason(await bob.receive(contact(alice, bob, big, seq++)))).toBe("malformed");
    const roster = createRoster(alice.keys, { sid: "s", ver: 1, vis: "private", org: "o", parts: [], iat: NOW });
    expect(reason(await bob.receive(contact(alice, bob, roster, seq)))).toBe("typ-mismatch");
  });

  it("a contact envelope with a roster or sender proofs is rejected", async () => {
    const invite = createInvite(alice.keys, { aud: bob.userId, iat: NOW });
    alice.workspace = kartr.attest(alice.userId, ["orgA"]);
    const env = alice.seal(bob, { sid: CONTACT_SID, own: alice.userId, kind: "contact", text: invite });
    expect(reason(await bob.receive(env))).toBe("malformed");
  });

  it("~contact only with kind contact, and kind contact only with ~contact and own = from", () => {
    const base = {
      from: alice.userId,
      fdid: alice.keys.deviceId,
      fcert: alice.cert,
      to: bob.userId,
      tdid: bob.keys.deviceId,
      seq: 1,
      ts: NOW_MS,
      plaintext: { text: "x", sender: {} },
      sender: alice.keys,
      recipientKpk: bob.keys.agreementPublicKey,
    };
    expect(() => sealEnvelope({ ...base, own: alice.userId, sid: CONTACT_SID, kind: "msg" })).toThrow(/reserved for kind contact/);
    expect(() => sealEnvelope({ ...base, own: alice.userId, sid: "s1", kind: "contact" })).toThrow(/requires sid/);
    expect(() => sealEnvelope({ ...base, own: bob.userId, sid: CONTACT_SID, kind: "contact" })).toThrow(/own == from/);
  });

  it("a received ~contact sid under kind msg is rejected", async () => {
    // Built by hand (sealEnvelope refuses it), as Phase 4's improvised form was.
    const env = contact(alice, bob, createInvite(alice.keys, { aud: bob.userId, iat: NOW }));
    const d = decodeEnvelope(env);
    const forged = signJws(TYP.msg, alice.keys.deviceId, { ...d.payload, kind: "msg" }, alice.keys.signingSecretKey);
    expect(reason(await bob.receive(forged))).toBe("malformed");
  });

  it("the replay window applies", async () => {
    const env = contact(alice, bob, createInvite(alice.keys, { aud: bob.userId, iat: NOW }));
    expect(reason(await bob.receive(env))).toBe("accepted:contact");
    expect(reason(await bob.receive(env))).toBe("replayed-seq");
    expect(await bob.trust.getReplay(alice.keys.deviceId)).toBeDefined();
  });
});
