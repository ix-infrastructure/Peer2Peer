// Copyright 2026 Ix Infrastructure Inc.
//
// Regression tests for the pre-release security review (H1, M1), ported from the
// reviewer's proofs of concept.

import { describe, expect, it } from "vitest";
import { FakeKartr, NOW, NOW_MS, Peer } from "./fixtures.js";
import { randomBytes } from "../crypto.js";
import {
  createAccept,
  createInvite,
  createRoster,
  createUnfriend,
  createDevregProof,
  inviteHash,
  signDeviceCert,
  verifyDeviceCert,
  verifyDevregProof,
  verifyFriendship,
  verifyRoster,
  type FriendshipProof,
} from "../objects.js";
import { decodeEnvelope, sealEnvelope } from "../envelope.js";
import { decodeJws, MAX_ENVELOPE_BYTES, MAX_JWS_BYTES } from "../jws.js";
import { b64uEncode } from "../encoding.js";
import { generateDeviceKeys } from "../keys.js";
import { FileTrustStore, MemoryTrustStore, type TrustStore } from "../truststore.js";
import { advanceWindow, checkSeq, mergeWindows, REPLAY_WINDOW } from "../replay.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { recordFriendship, updateRevocations, verifyIncoming, type IncomingResult } from "../verify.js";

const DAY = 86_400;

async function setup() {
  const kartr = new FakeKartr();
  const A = kartr.device("alice@x.com");
  const B = kartr.device("bob@x.com");
  // Bob invites Alice (Alice is the invitee); Alice accepts.
  const invite = createInvite(B, { aud: A.userId, iat: NOW - 600 });
  const accept1 = createAccept(A, invite, { iat: NOW - 540 });
  const trustB = new MemoryTrustStore();
  await recordFriendship(trustB, await verifyFriendship({ invite, accept: accept1 }, kartr.verifyOpts()));
  // Alice's private session with Bob as a participant.
  const roster = createRoster(A, { sid: "s1", ver: 1, vis: "private", org: "acme", parts: [A.userId, B.userId], iat: NOW - 500 });
  let seq = 1;
  const send = (tSec: number, opts: { friendship?: FriendshipProof; seq?: number } = {}) =>
    sealEnvelope({
      from: A.userId,
      fdid: A.deviceId,
      fcert: A.cert,
      to: B.userId,
      tdid: B.deviceId,
      own: A.userId,
      sid: "s1",
      seq: opts.seq ?? seq++,
      ts: tSec * 1000,
      kind: "msg",
      plaintext: { text: "hi", roster, sender: opts.friendship ? { friendship: opts.friendship } : {} },
      sender: A,
      recipientKpk: B.agreementPublicKey,
    });
  const receive = async (env: string, tSec: number, trust: TrustStore = trustB): Promise<IncomingResult> => {
    await updateRevocations(trust, kartr.revocations(tSec - 1), { kartr: kartr.keys(), now: tSec, nowMs: tSec * 1000 });
    return verifyIncoming(env, {
      self: { userId: B.userId, deviceId: B.deviceId, agreementSecretKey: B.agreementSecretKey, cert: B.cert },
      kartr: kartr.keys(),
      trust,
      resolveCert: kartr.resolver(),
      nowMs: tSec * 1000,
    });
  };
  return { kartr, A, B, invite, accept1, trustB, send, receive };
}

describe("H1: an unfriend can't be undone by re-signing an accept", () => {
  it("rejects a fresh accept for a burned invite", async () => {
    const { A, B, invite, accept1, trustB, send, receive } = await setup();
    const T1 = NOW + 2 * DAY;
    const inv = inviteHash(invite);
    const uf = createUnfriend(B, { peer: A.userId, inv, iat: T1 });
    await trustB.addUnfriend({ iss: B.userId, peer: A.userId, inv, iat: T1, jws: uf });
    const T2 = T1 + 3600;

    expect((await receive(send(T2), T2)).ok).toBe(false);
    expect((await receive(send(T2, { friendship: { invite, accept: accept1 } }), T2)).ok).toBe(false);
    // Alice re-signs an accept for the same, still unexpired invite, newer than the unfriend.
    const accept2 = createAccept(A, invite, { iat: T2 });
    const r = await receive(send(T2, { friendship: { invite, accept: accept2 } }), T2);
    expect(r.ok).toBe(false);
    expect(r.ok ? r.rule : r.reason).toBe("viewer-unfriended");
    // ...and the burned friendship was not stored.
    expect((await trustB.listFriendships()).filter((f) => f.inv === inv)).toHaveLength(1);
  });

  it("the viewer's standing ignores sender-presented friendships", async () => {
    const { kartr, A, B, send, receive } = await setup();
    // Bob's device has no stored friendship with Alice (fresh store). Alice
    // presents a genuine friendship proof; it may help only Alice's side.
    const empty = new MemoryTrustStore();
    const invite = createInvite(B, { aud: A.userId, iat: NOW - 100 });
    const proof = { invite, accept: createAccept(A, invite, { iat: NOW - 50 }) };
    await verifyFriendship(proof, kartr.verifyOpts());
    const r = await receive(send(NOW, { friendship: proof }), NOW, empty);
    expect(r.ok ? r.rule : r.reason).toBe("viewer-no-friendship");
  });
});

describe("H1 variant: other pre-unfriend invites, and carrier envelopes", () => {
  async function setupVariant() {
    const kartr = new FakeKartr();
    const alice = new Peer(kartr, "alice@x.com");
    const bob = new Peer(kartr, "bob@x.com");
    const inv1 = createInvite(bob.keys, { aud: alice.userId, iat: NOW - 3 * DAY });
    // Bob also has a shareable code issued before the unfriend.
    const invStar = createInvite(bob.keys, { aud: "*", iat: NOW - 3 * DAY + 10 });
    const acc1 = createAccept(alice.keys, inv1, { iat: NOW - 3 * DAY + 60 });
    await recordFriendship(bob.trust, await verifyFriendship({ invite: inv1, accept: acc1 }, kartr.verifyOpts()));
    // Bob unfriends Alice a day ago, naming inv1.
    const T1 = NOW - DAY;
    const inv = inviteHash(inv1);
    await bob.trust.addUnfriend({ iss: bob.userId, peer: alice.userId, inv, iat: T1, jws: createUnfriend(bob.keys, { peer: alice.userId, inv, iat: T1 }) });
    const rosterBob = createRoster(bob.keys, { sid: "s1", ver: 1, vis: "private", org: "acme", parts: [alice.userId, bob.userId], iat: NOW - 3 * DAY });
    const rosterAlice = createRoster(alice.keys, { sid: "s1", ver: 1, vis: "private", org: "acme", parts: [alice.userId, bob.userId], iat: NOW - 3 * DAY });
    return { kartr, alice, bob, inv1, invStar, rosterBob, rosterAlice };
  }

  it("a re-signed accept for the named invite doesn't satisfy the sender side", async () => {
    const { alice, bob, inv1, rosterBob } = await setupVariant();
    const friendship = { invite: inv1, accept: createAccept(alice.keys, inv1, { iat: NOW }) };
    const r = await bob.receive(alice.seal(bob, { sid: "s1", own: bob.userId, roster: rosterBob, friendship }));
    expect(r.ok ? r.rule : r.reason).toBe("unfriended");
  });

  it("another invite issued before the unfriend (a '*' code) can't re-friend", async () => {
    const { kartr, alice, bob, invStar, rosterBob, rosterAlice } = await setupVariant();
    const fStar = { invite: invStar, accept: createAccept(alice.keys, invStar, { iat: NOW }) };
    // Sender side, into Bob's session.
    let r = await bob.receive(alice.seal(bob, { sid: "s1", own: bob.userId, roster: rosterBob, friendship: fStar }));
    expect(r.ok ? r.rule : r.reason).toBe("unfriended");
    // Viewer side, Alice's session.
    r = await bob.receive(alice.seal(bob, { sid: "s1", own: alice.userId, roster: rosterAlice, friendship: fStar }));
    expect(r.ok ? r.rule : r.reason).toBe("viewer-unfriended");
    // Bob's app can't adopt it either.
    await expect(recordFriendship(bob.trust, await verifyFriendship(fStar, kartr.verifyOpts()))).rejects.toThrow(/unfriended/);
  });

  it("an unfriend-kind envelope can't plant a friendship", async () => {
    const { alice, bob, invStar, rosterAlice } = await setupVariant();
    const fStar = { invite: invStar, accept: createAccept(alice.keys, invStar, { iat: NOW }) };
    const bogus = createUnfriend(alice.keys, { peer: bob.userId, inv: b64uEncode(randomBytes(32)), iat: NOW });
    const before = (await bob.trust.listFriendships()).length;
    const r = await bob.receive(alice.seal(bob, { sid: "s1", own: alice.userId, kind: "unfriend", text: bogus, friendship: fStar }));
    expect(r.ok ? r.rule : r.reason).toBe("unfriend");
    expect(await bob.trust.listFriendships()).toHaveLength(before);
    const after = await bob.receive(alice.seal(bob, { sid: "s1", own: alice.userId, roster: rosterAlice }));
    expect(after.ok ? after.rule : after.reason).toBe("viewer-unfriended");
  });

  it("a sync-kind or failed envelope stores nothing either", async () => {
    const { alice, bob, invStar, rosterAlice } = await setupVariant();
    const fStar = { invite: invStar, accept: createAccept(alice.keys, invStar, { iat: NOW }) };
    const sync = await bob.receive(alice.seal(bob, { sid: "s1", own: alice.userId, kind: "sync", friendship: fStar }));
    expect(sync.ok ? sync.rule : sync.reason).toBe("not-participant");
    const failed = await bob.receive(alice.seal(bob, { sid: "s1", own: alice.userId, roster: rosterAlice, friendship: fStar }));
    expect(failed.ok).toBe(false);
    expect((await bob.trust.listFriendships()).map((f) => f.aud)).toEqual(["alice@x.com"]);
    expect(await bob.trust.getRoster(alice.userId, "s1")).toBeUndefined();
  });

  it("a genuinely new invite after the unfriend re-friends", async () => {
    const { kartr, alice, bob, rosterAlice } = await setupVariant();
    const inv3 = createInvite(bob.keys, { aud: alice.userId, iat: NOW - 60 });
    const f3 = await verifyFriendship({ invite: inv3, accept: createAccept(alice.keys, inv3, { iat: NOW - 30 }) }, kartr.verifyOpts());
    await recordFriendship(bob.trust, f3);
    const r = await bob.receive(alice.seal(bob, { sid: "s1", own: alice.userId, roster: rosterAlice }));
    expect(r.ok ? r.viewerRule : r.reason).toBe("participant-friend");
  });
});

describe("M1: replay check and record are atomic", () => {
  it("a duplicate delivered concurrently is accepted once", async () => {
    const { send, receive } = await setup();
    const env = send(NOW);
    const res = await Promise.all([receive(env, NOW), receive(env, NOW), receive(env, NOW)]);
    expect(res.filter((r) => r.ok)).toHaveLength(1);
    expect(res.filter((r) => !r.ok).map((r) => (r.ok ? "" : r.reason))).toEqual(["replayed-seq", "replayed-seq"]);
  });

  it("concurrent envelopes don't lose replay state", async () => {
    const { A, trustB, send, receive } = await setup();
    const e1 = send(NOW);
    const e2 = send(NOW);
    expect((await Promise.all([receive(e1, NOW), receive(e2, NOW)])).map((r) => r.ok)).toEqual([true, true]);
    const rec = await trustB.getReplay(A.deviceId);
    expect(rec?.nonces).toHaveLength(2);
    expect((await receive(e1, NOW)).ok).toBe(false);
    expect((await receive(e2, NOW)).ok).toBe(false);
  });

  it("an out-of-order concurrent pair is accepted exactly once each (D7)", async () => {
    const { send, receive } = await setup();
    const f7 = send(NOW, { seq: 7 });
    const f8 = send(NOW, { seq: 8 });
    // Reproduced by the re-review: seq 8 then 7 used to give [true, false].
    expect((await Promise.all([receive(f8, NOW), receive(f7, NOW)])).map((r) => r.ok)).toEqual([true, true]);
    for (const env of [f7, f8]) {
      const again = await receive(env, NOW);
      expect(again.ok ? "accepted" : again.reason).toBe("replayed-seq");
    }
  });

  it("the store merges replay records instead of overwriting", async () => {
    const s = new MemoryTrustStore();
    const k5 = advanceWindow(5, undefined);
    const k3 = advanceWindow(3, undefined);
    const j1 = advanceWindow(1, undefined);
    await Promise.all([
      s.putReplay("d_x", { nonces: ["a"], windows: { k: k5 } }),
      s.putReplay("d_x", { nonces: ["b"], windows: { k: k3, j: j1 } }),
    ]);
    const r = await s.getReplay("d_x");
    expect(new Set(r!.nonces)).toEqual(new Set(["a", "b"]));
    expect(r!.windows).toEqual({ k: mergeWindows(k5, k3), j: j1 });
    expect(checkSeq(3, r!.windows.k)?.reason).toBe("replayed-seq");
    expect(checkSeq(4, r!.windows.k)).toBeUndefined();
  });
});

describe("D7: sliding anti-replay window end to end", () => {
  it("a duplicate is rejected, anything older than the window is rejected", async () => {
    const { send, receive } = await setup();
    expect((await receive(send(NOW, { seq: 1000 }), NOW)).ok).toBe(true);
    expect((await receive(send(NOW, { seq: 600 }), NOW)).ok).toBe(true); // 400 behind: inside W
    const tooOld = await receive(send(NOW, { seq: 1000 - REPLAY_WINDOW }), NOW);
    expect(tooOld.ok ? "accepted" : tooOld.reason).toBe("seq-too-old");
  });

  it("the window survives a restart (FileTrustStore) and merges across processes", async () => {
    const { kartr, invite, accept1, send, receive } = await setup();
    const dir = mkdtempSync(join(tmpdir(), "p2p-window-"));
    try {
      const first = new FileTrustStore(dir);
      await recordFriendship(first, await verifyFriendship({ invite, accept: accept1 }, kartr.verifyOpts()));
      const e10 = send(NOW, { seq: 10 });
      const e12 = send(NOW, { seq: 12 });
      expect((await receive(e12, NOW, first)).ok).toBe(true);
      // "Restart": a fresh store instance on the same directory.
      const second = new FileTrustStore(dir);
      const again = await receive(e12, NOW, second);
      expect(again.ok ? "accepted" : again.reason).toBe("replayed-seq");
      expect((await receive(e10, NOW, second)).ok).toBe(true);
      // Two "processes" admitting concurrently: both seqs land in the window.
      const e11 = send(NOW, { seq: 11 });
      const e13 = send(NOW, { seq: 13 });
      const third = new FileTrustStore(dir);
      expect((await Promise.all([receive(e11, NOW, second), receive(e13, NOW, third)])).map((r) => r.ok)).toEqual([true, true]);
      const fourth = new FileTrustStore(dir);
      for (const env of [e10, e11, e12, e13]) {
        const r = await receive(env, NOW, fourth);
        expect(r.ok ? "accepted" : r.reason).toBe("replayed-seq");
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("L4: revocation list freshness and friendship signer expiry", () => {
  async function matrix() {
    const kartr = new FakeKartr();
    const alice = new Peer(kartr, "alice@a.example");
    const bob = new Peer(kartr, "bob@b.example");
    const invite = createInvite(alice.keys, { aud: bob.userId, iat: NOW - 600 });
    const proof = { invite, accept: createAccept(bob.keys, invite, { iat: NOW - 300 }) };
    await recordFriendship(alice.trust, await verifyFriendship(proof, kartr.verifyOpts()));
    const roster = createRoster(alice.keys, { sid: "s1", ver: 1, vis: "private", org: "orgA", parts: [bob.userId], iat: NOW - 60 });
    return { kartr, alice, bob, roster };
  }

  it("fails closed with no revocation list", async () => {
    const { alice, bob, roster } = await matrix();
    alice.autoPoll = false;
    const r = await alice.receive(bob.seal(alice, { sid: "s1", roster }));
    expect(r.ok ? "accepted" : r.reason).toBe("revocations-stale");
  });

  it("fails closed after 24h without a successful poll, warns after 1h", async () => {
    const { kartr, alice, bob, roster } = await matrix();
    alice.autoPoll = false;
    await updateRevocations(alice.trust, kartr.revocations(), { kartr: kartr.keys(), now: NOW, nowMs: NOW_MS - 25 * 3600_000 });
    let r = await alice.receive(bob.seal(alice, { sid: "s1", roster }));
    expect(r.ok ? "accepted" : r.reason).toBe("revocations-stale");
    // A later successful poll of the same list refreshes it.
    await updateRevocations(alice.trust, kartr.revocations(), { kartr: kartr.keys(), now: NOW, nowMs: NOW_MS - 2 * 3600_000 });
    const warnings: string[] = [];
    r = await verifyIncoming(bob.seal(alice, { sid: "s1", roster }), {
      self: alice.keys,
      kartr: kartr.keys(),
      trust: alice.trust,
      resolveCert: kartr.resolver(),
      nowMs: NOW_MS,
      onWarning: (m) => warnings.push(m),
    });
    expect(r.ok).toBe(true);
    expect(warnings).toHaveLength(1);
  });

  it("a stored friendship dies when a signer's certificate has expired", async () => {
    const { kartr, alice } = await matrix();
    const alice2 = new Peer(kartr, "alice@a.example");
    const carol = new Peer(kartr, "carol@c.example");
    const invite = createInvite(alice2.keys, { aud: carol.userId, iat: NOW - 600 });
    const f = await verifyFriendship({ invite, accept: createAccept(carol.keys, invite, { iat: NOW - 300 }) }, kartr.verifyOpts());
    await recordFriendship(alice.trust, f);
    const r2 = createRoster(alice.keys, { sid: "s2", ver: 1, vis: "private", org: "orgA", parts: [carol.userId], iat: NOW });
    expect((await alice.receive(carol.seal(alice, { sid: "s2", roster: r2 }))).ok).toBe(true);
    // alice2's certificate lapses (not renewed).
    kartr.issueCert(alice2.keys, { iat: NOW - 31 * DAY, exp: NOW - DAY });
    const r = await alice.receive(carol.seal(alice, { sid: "s2" }));
    expect(r.ok ? "accepted" : r.reason).toBe("no-friendship");
  });
});

describe("L6: size caps", () => {
  it("rejects a non-envelope JWS over 16 KiB", async () => {
    const kartr = new FakeKartr();
    const a = kartr.device("alice@a.example");
    const big = createRoster(a, { sid: "s", ver: 1, vis: "private", org: "o", parts: Array.from({ length: 800 }, (_, i) => `u${i}@example.com`), iat: NOW });
    expect(big.length).toBeGreaterThan(MAX_JWS_BYTES);
    expect(() => decodeJws(big)).toThrow(/max 16384/);
    await expect(verifyRoster(big, kartr.verifyOpts())).rejects.toThrow(/malformed/);
  });

  it("allows envelopes up to 64 KiB and no more", async () => {
    const kartr = new FakeKartr();
    const alice = new Peer(kartr, "alice@a.example");
    const bob = new Peer(kartr, "bob@b.example");
    const roster = createRoster(alice.keys, { sid: "s", ver: 1, vis: "private", org: "o", parts: [bob.userId], iat: NOW });
    const mid = alice.seal(bob, { sid: "s", roster, text: "x".repeat(20_000) });
    expect(mid.length).toBeGreaterThan(MAX_JWS_BYTES);
    expect(decodeEnvelope(mid).payload.sid).toBe("s");
    expect(() => alice.seal(bob, { sid: "s", roster, text: "x".repeat(MAX_ENVELOPE_BYTES) })).toThrow(/max 65536/);
    // A receiver also refuses an oversized envelope (whoever built it).
    const [h, p] = mid.split(".");
    expect(() => decodeEnvelope(`${h}.${p}${"A".repeat(MAX_ENVELOPE_BYTES)}.x`)).toThrow(/malformed/);
  });
});

describe("small-order keys", () => {
  const identity = new Uint8Array(32);
  identity[0] = 1; // Ed25519 identity point; also X25519 u = 1 (low order)

  it("rejects a device cert with a small-order spk or low-order kpk", async () => {
    const kartr = new FakeKartr();
    const d = kartr.device("alice@a.example");
    for (const [spk, kpk] of [
      [identity, d.agreementPublicKey],
      [d.signingPublicKey, identity],
    ]) {
      const cert = signDeviceCert(
        { sub: d.userId, did: d.deviceId, spk: b64uEncode(spk), kpk: b64uEncode(kpk), iat: NOW - 10, exp: NOW + 100 },
        kartr.sk,
        kartr.kid,
      );
      await expect(verifyDeviceCert(cert, kartr.verifyOpts())).rejects.toThrow(/small-order-key/);
    }
  });

  it("rejects a devreg proof with a low-order kpk even when correctly signed", () => {
    const kartr = new FakeKartr();
    const d = kartr.device("alice@a.example");
    const proof = createDevregProof(d, { signingPublicKey: d.signingPublicKey, agreementPublicKey: identity }, { iat: NOW });
    expect(() => verifyDevregProof(proof)).toThrow(/small-order-key/);
  });

  it("rejects a devreg proof whose spk is the identity point", () => {
    const d = generateDeviceKeys("alice@a.example");
    const payload = { did: d.deviceId, spk: b64uEncode(identity), kpk: b64uEncode(d.agreementPublicKey), sub: d.userId, nonce: "n", iat: NOW };
    // R = identity, S = 0: passes a bare (cofactored, non-strict) Ed25519 check.
    const sig = new Uint8Array(64);
    sig.set(identity, 0);
    const h = b64uEncode(new TextEncoder().encode(JSON.stringify({ alg: "EdDSA", typ: "p2p-devreg+jws", kid: d.deviceId })));
    const p = b64uEncode(new TextEncoder().encode(JSON.stringify(payload)));
    expect(() => verifyDevregProof(`${h}.${p}.${b64uEncode(sig)}`)).toThrow(/small-order-key/);
  });
});
