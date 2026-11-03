// Copyright 2026 Ix Infrastructure Inc.
import { describe, expect, it } from "vitest";
import { FakeKartr, NOW } from "./fixtures.js";
import {
  createAccept,
  createDevregProof,
  createInvite,
  createRoster,
  createUnfriend,
  inviteHash,
  normalizeUserId,
  newDeviceId,
  unfriendApplies,
  verifyDeviceCert,
  verifyDevregProof,
  verifyFriendship,
  verifyInvite,
  verifyRevocationList,
  verifyRoster,
  verifyUnfriend,
  verifyWorkspaceAttestation,
  signDeviceCert,
} from "../objects.js";
import { kartrKeyId, parseJwks, staticKartrKeys, JwksCache, jwkFromPublicKey } from "../jwks.js";
import { ed25519PublicKey, randomBytes, sha256 } from "../crypto.js";
import { b64uEncode, utf8 } from "../encoding.js";
import { signJws } from "../jws.js";

const kartr = new FakeKartr();
const alice = kartr.device("alice@a.example");
const bob = kartr.device("bob@b.example");

describe("identities", () => {
  it("normalises userIds and makes deviceIds", () => {
    expect(normalizeUserId("  Alice@A.Example ")).toBe("alice@a.example");
    expect(newDeviceId()).toMatch(/^d_[A-Za-z0-9_-]{22}$/);
  });
  it("derives the Kartr kid as b64u(sha256(name))[:16]", () => {
    const name = "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1";
    expect(kartrKeyId(name)).toBe(b64uEncode(sha256(utf8(name))).slice(0, 16));
    expect(kartrKeyId(name)).toHaveLength(16);
  });
});

describe("Kartr-signed objects", () => {
  it("device cert round-trips", async () => {
    const c = await verifyDeviceCert(alice.cert, kartr.verifyOpts());
    expect(c.sub).toBe("alice@a.example");
    expect(c.did).toBe(alice.deviceId);
    expect([...c.signingPublicKey]).toEqual([...alice.signingPublicKey]);
    expect([...c.agreementPublicKey]).toEqual([...alice.agreementPublicKey]);
  });

  it("device cert rejects >30d lifetime", async () => {
    const cert = kartr.issueCert(alice, { iat: NOW - 10, exp: NOW - 10 + 31 * 24 * 3600 });
    await expect(verifyDeviceCert(cert, kartr.verifyOpts())).rejects.toThrow(/malformed: lifetime/);
    kartr.issueCert(alice);
  });

  it("workspace attestation round-trips", async () => {
    const a = await verifyWorkspaceAttestation(kartr.attest("alice@a.example", ["org1", "org2"]), kartr.verifyOpts());
    expect(a.orgs).toEqual(["org1", "org2"]);
    expect(a.sub).toBe("alice@a.example");
  });

  it("workspace attestation expires after 24h", async () => {
    const a = kartr.attest("alice@a.example", ["org1"], { iat: NOW - 24 * 3600 - 1 });
    await expect(verifyWorkspaceAttestation(a, kartr.verifyOpts())).rejects.toThrow(/^expired/);
  });

  it("revocation list round-trips", async () => {
    const k = new FakeKartr();
    k.revoked.add(alice.deviceId);
    const r = await verifyRevocationList(k.revocations(), k.verifyOpts());
    expect(r.dids).toEqual([alice.deviceId]);
  });

  it("an unknown kid is rejected", async () => {
    const other = new FakeKartr();
    await expect(verifyDeviceCert(alice.cert, other.verifyOpts())).rejects.toThrow(/unknown-kartr-key/);
  });
});

describe("JWKS", () => {
  it("parses, skips foreign keys and rejects duplicates", () => {
    const pk = ed25519PublicKey(randomBytes(32));
    const keys = parseJwks({ keys: [jwkFromPublicKey("a", pk), { kty: "EC", crv: "P-256", kid: "b" }] });
    expect([...keys.keys()]).toEqual(["a"]);
    expect(() => parseJwks({ keys: [jwkFromPublicKey("a", pk), jwkFromPublicKey("a", pk)] })).toThrow(/duplicate/);
  });

  it("caches for 1h, refetches on unknown kid, survives Kartr outage", async () => {
    let t = 0;
    let calls = 0;
    let down = false;
    const k1 = new FakeKartr();
    const k2 = new FakeKartr();
    let doc: unknown = k1.jwks;
    const cache = new JwksCache({
      fetchJwks: async () => {
        calls++;
        if (down) throw new Error("down");
        return doc;
      },
      now: () => t,
    });
    expect(await cache.resolve(k1.kid)).toBeDefined();
    expect(await cache.resolve(k1.kid)).toBeDefined();
    expect(calls).toBe(1);
    doc = { keys: [...k1.jwks.keys, ...k2.jwks.keys] };
    t = 60_000;
    expect(await cache.resolve(k2.kid)).toBeDefined(); // unknown kid -> refetch
    expect(calls).toBe(2);
    expect(await cache.resolve("nope")).toBeUndefined(); // rate-limited
    expect(calls).toBe(2);
    down = true;
    t = 2 * 3_600_000;
    expect(await cache.resolve(k1.kid)).toBeDefined(); // stale but usable offline
  });
});

describe("device-signed objects", () => {
  it("invite + accept -> friendship", async () => {
    const invite = createInvite(alice, { aud: "Bob@B.example", iat: NOW - 100 });
    const vi = await verifyInvite(invite, kartr.verifyOpts());
    expect(vi.aud).toBe("bob@b.example");
    const accept = createAccept(bob, invite, { iat: NOW - 50 });
    const f = await verifyFriendship({ invite, accept }, kartr.verifyOpts());
    expect(f).toMatchObject({ inviter: "alice@a.example", invitee: "bob@b.example", inv: inviteHash(invite), iat: NOW - 50 });
  });

  it("aud '*' binds any accepter; explicit aud binds only that user", async () => {
    const open = createInvite(alice, { aud: "*", iat: NOW - 100 });
    const f = await verifyFriendship({ invite: open, accept: createAccept(bob, open, { iat: NOW }) }, kartr.verifyOpts());
    expect(f.aud).toBe("*");
    const carol = kartr.device("carol@c.example");
    const forBob = createInvite(alice, { aud: "bob@b.example", iat: NOW - 100 });
    await expect(
      verifyFriendship({ invite: forBob, accept: createAccept(carol, forBob, { iat: NOW }) }, kartr.verifyOpts()),
    ).rejects.toThrow(/audience-mismatch/);
  });

  it("an accept after invite expiry is rejected", async () => {
    const invite = createInvite(alice, { aud: "*", iat: NOW - 1000, ttlSec: 500 });
    await expect(verifyInvite(invite, kartr.verifyOpts())).rejects.toThrow(/invite-expired/);
    await expect(
      verifyFriendship({ invite, accept: createAccept(bob, invite, { iat: NOW - 400 }) }, kartr.verifyOpts()),
    ).rejects.toThrow(/invite-expired/);
  });

  it("an accept for a different invite is rejected", async () => {
    const i1 = createInvite(alice, { aud: "*", iat: NOW - 10 });
    const i2 = createInvite(alice, { aud: "*", iat: NOW - 10 });
    await expect(
      verifyFriendship({ invite: i1, accept: createAccept(bob, i2, { iat: NOW }) }, kartr.verifyOpts()),
    ).rejects.toThrow(/invite-mismatch/);
  });

  it("unfriend round-trips and applies to the friendship", async () => {
    const invite = createInvite(alice, { aud: "bob@b.example", iat: NOW - 100 });
    const f = await verifyFriendship(
      { invite, accept: createAccept(bob, invite, { iat: NOW - 50 }) },
      kartr.verifyOpts(),
    );
    const u = await verifyUnfriend(createUnfriend(bob, { peer: "alice@a.example", inv: f.inv, iat: NOW }), kartr.verifyOpts());
    expect(u).toMatchObject({ iss: "bob@b.example", peer: "alice@a.example", inv: f.inv });
    expect(unfriendApplies(f, u)).toBe(true);
    // The invite is burned: iat doesn't matter (H1).
    const laterAccept = { inviter: f.inviter, invitee: f.invitee, inv: f.inv, iat: NOW + 1000, inviteIat: f.inviteIat };
    expect(unfriendApplies(laterAccept, u)).toBe(true); // a later accept doesn't escape it
    // Any invite of the pair issued at or before the unfriend is dead too...
    expect(unfriendApplies(f, { ...u, inv: "x".repeat(43) })).toBe(true);
    // ...but one issued after it can re-friend.
    expect(unfriendApplies({ ...f, inv: "y".repeat(43), inviteIat: u.iat + 1 }, u)).toBe(false);
    expect(unfriendApplies(f, { ...u, peer: "carol@c.example" })).toBe(false);
  });

  it("roster round-trips", async () => {
    const r = await verifyRoster(
      createRoster(alice, { sid: "s1", ver: 3, vis: "private", org: "orgA", parts: ["Bob@B.example"], iat: NOW }),
      kartr.verifyOpts(),
    );
    expect(r).toMatchObject({ iss: "alice@a.example", sid: "s1", ver: 3, vis: "private", org: "orgA", parts: ["bob@b.example"] });
  });

  it("devreg proof round-trips and binds spk", () => {
    const proof = createDevregProof(alice, alice, { nonce: "abc", iat: NOW });
    expect(verifyDevregProof(proof)).toMatchObject({ did: alice.deviceId, sub: "alice@a.example", nonce: "abc" });
    // Signed by a different key than the spk it claims.
    const forged = createDevregProof({ ...alice, signingSecretKey: bob.signingSecretKey }, alice, { iat: NOW });
    expect(() => verifyDevregProof(forged)).toThrow(/bad-signature/);
  });

  it("a cert signed by a key not in the JWKS is forged", async () => {
    const forged = signDeviceCert(
      { sub: "alice@a.example", did: alice.deviceId, spk: b64uEncode(alice.signingPublicKey), kpk: b64uEncode(alice.agreementPublicKey), iat: NOW, exp: NOW + 100 },
      randomBytes(32),
      kartr.kid,
    );
    await expect(verifyDeviceCert(forged, kartr.verifyOpts())).rejects.toThrow(/kartr-signature-invalid/);
  });

  it("a device object whose kid isn't its did is rejected", async () => {
    const roster = signJws(
      "p2p-roster+jws",
      bob.deviceId,
      { iss: "alice@a.example", did: alice.deviceId, sid: "s", ver: 1, vis: "private", org: "o", parts: [], iat: NOW },
      alice.signingSecretKey,
    );
    await expect(verifyRoster(roster, kartr.verifyOpts())).rejects.toThrow(/kid-mismatch/);
  });

  it("a static key set resolves only its kids", async () => {
    const keys = staticKartrKeys(kartr.jwks);
    expect(await keys.resolve(kartr.kid)).toBeDefined();
    expect(await keys.resolve("x")).toBeUndefined();
  });
});
