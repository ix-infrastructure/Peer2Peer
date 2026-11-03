// Copyright 2026 Ix Infrastructure Inc.
//
// Cross-language check against the Go attestation authority's test vectors.
//
// testdata/go-vectors.json is vendored from the Go implementation's
// internal/p2p/testdata/vectors.json. Re-vendor it whenever the Go side
// changes the file. $P2P_GO_VECTORS overrides the
// path, to check a newer file before vendoring it.
//
// Layout (version 1): { now, keys: {deviceA, deviceB, kartr, smallOrder},
// jwks, valid: [{name, typ, signer, kid, jws, payload}], invalid: [{name,
// expect_typ, signer, jws, error}], derived: {...} }.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ed25519PublicKey, x25519PublicKey } from "../crypto.js";
import { b64uDecode, b64uEncode } from "../encoding.js";
import { P2PError, type RejectReason } from "../errors.js";
import { kartrKeyId, staticKartrKeys } from "../jwks.js";
import { decodeJws, signJws } from "../jws.js";
import {
  inviteHash,
  signDeviceCert,
  TYP,
  verifyDeviceCert,
  verifyDeviceSigned,
  verifyDevregProof,
  verifyFriendship,
  verifyInvite,
  verifyRevocationList,
  verifyWorkspaceAttestation,
} from "../objects.js";

interface KeyEntry {
  user?: string;
  did?: string;
  seed: string;
  x: string;
  kpk?: string;
  name?: string;
  kid?: string;
}

interface Vectors {
  version: number;
  now: number;
  keys: Record<string, KeyEntry>;
  jwks: unknown;
  valid: { name: string; typ: string; signer: string; kid: string; jws: string; payload: Record<string, unknown> }[];
  invalid: { name: string; expect_typ: string; signer: string; jws: string; error: string; description: string }[];
  derived: Record<string, string>;
}

const here = dirname(fileURLToPath(import.meta.url));
const path = process.env.P2P_GO_VECTORS ?? join(here, "testdata", "go-vectors.json");
const V = JSON.parse(readFileSync(path, "utf8")) as Vectors;
const kartr = staticKartrKeys(V.jwks);
const now = V.now;

// X25519 seeds documented in the key notes: deviceA 0x80..0x9f, deviceB 0xa0..0xbf.
const seq32 = (start: number) => Uint8Array.from({ length: 32 }, (_, i) => start + i);
const X25519_SEEDS: Record<string, Uint8Array> = { deviceA: seq32(0x80), deviceB: seq32(0xa0) };

// deviceB's certificate isn't in the file; mint one with the published Kartr seed.
const certA = V.valid.find((v) => v.name === "device_cert")!.jws;
const kB = V.keys.deviceB;
const certB = signDeviceCert(
  { sub: kB.user!, did: kB.did!, spk: kB.x, kpk: kB.kpk!, iat: now, exp: now + 86_400 },
  b64uDecode(V.keys.kartr.seed),
  V.keys.kartr.kid!,
);
const certs: Record<string, string> = { [V.keys.deviceA.did!]: certA, [kB.did!]: certB };
const opts = { kartr, now, skewSec: 0, resolveCert: async (_u: string, d: string) => certs[d] };

async function verifyAs(typ: string, jws: string): Promise<unknown> {
  switch (typ) {
    case TYP.device:
      return verifyDeviceCert(jws, opts);
    case TYP.workspace:
      return verifyWorkspaceAttestation(jws, opts);
    case TYP.revocations:
      return verifyRevocationList(jws, opts);
    case TYP.devreg:
      return verifyDevregProof(jws);
    case TYP.invite:
      return verifyInvite(jws, opts);
    case TYP.accept:
      return verifyDeviceSigned(jws, TYP.accept, opts);
    default:
      throw new Error(`no verifier for ${typ}`);
  }
}

// Go's error category -> the reasons the TS core may give for it.
const EXPECTED_REASONS: Record<string, RejectReason[]> = {
  typ: ["typ-mismatch", "malformed"],
  kid: ["unknown-kartr-key", "kid-mismatch"],
  alg: ["bad-alg"],
  signature: ["kartr-signature-invalid", "bad-signature"],
  expired: ["expired"],
  crit: ["malformed"],
  malformed: ["malformed"],
  small_order_key: ["small-order-key"],
};

describe(`Go authority test vectors (${path})`, () => {
  it("is the layout this test understands", () => {
    expect(V.version).toBe(1);
    expect(V.valid.length).toBeGreaterThan(0);
    expect(V.invalid.length).toBeGreaterThan(0);
  });

  describe("keys", () => {
    it("Kartr kid = b64u(sha256(name))[:16]", () => {
      expect(kartrKeyId(V.keys.kartr.name!)).toBe(V.keys.kartr.kid);
    });
    for (const [name, k] of Object.entries(V.keys)) {
      if (k.seed === "") {
        // e.g. smallOrder: a published point with no secret; only used by invalid vectors.
        it(`${name} has no seed (public-only test key)`, () => {
          expect(k.x).toMatch(/^[A-Za-z0-9_-]{43}$/);
        });
        continue;
      }
      it(`${name} Ed25519 public key from seed`, () => {
        expect(b64uEncode(ed25519PublicKey(b64uDecode(k.seed, 32)))).toBe(k.x);
      });
      if (k.kpk && X25519_SEEDS[name]) {
        it(`${name} X25519 public key from seed`, () => {
          expect(b64uEncode(x25519PublicKey(X25519_SEEDS[name]))).toBe(k.kpk);
        });
      }
    }
  });

  describe("valid", () => {
    for (const v of V.valid) {
      it(`${v.name}: verifies as ${v.typ}`, async () => {
        await expect(verifyAs(v.typ, v.jws)).resolves.toBeTruthy();
        const d = decodeJws(v.jws);
        expect(d.header).toEqual({ alg: "EdDSA", typ: v.typ, kid: v.kid });
        expect(d.payload).toEqual(v.payload);
      });
      it(`${v.name}: TS signer reproduces Go's bytes`, () => {
        expect(signJws(v.typ, v.kid, v.payload, b64uDecode(V.keys[v.signer].seed, 32))).toBe(v.jws);
      });
    }

    it("the revocation list revokes deviceB", async () => {
      const list = await verifyRevocationList(V.valid.find((v) => v.typ === TYP.revocations)!.jws, opts);
      await expect(verifyDeviceCert(certB, { ...opts, isRevoked: (d) => list.dids.includes(d) })).rejects.toThrow(
        /device-revoked/,
      );
    });
  });

  describe("invalid", () => {
    for (const v of V.invalid) {
      it(`${v.name}: rejected as ${v.expect_typ} (${v.error})`, async () => {
        let err: unknown;
        try {
          await verifyAs(v.expect_typ, v.jws);
        } catch (e) {
          err = e;
        }
        expect(err, v.description).toBeInstanceOf(P2PError);
        const allowed = EXPECTED_REASONS[v.error];
        expect(allowed, `unmapped Go error category ${v.error}`).toBeDefined();
        expect(allowed).toContain((err as P2PError).reason);
      });
    }
  });

  describe("derived", () => {
    const invite = V.valid.find((v) => v.name === "friend_invite")!.jws;
    const accept = V.valid.find((v) => v.name === "friend_accept")!.jws;
    it("invite hash", () => {
      expect(inviteHash(invite)).toBe(V.derived["friend_invite.sha256_b64u"]);
    });
    it("X-P2P-Proof formats", () => {
      expect(V.derived["x_p2p_proof.invite"]).toBe(invite);
      expect(V.derived["x_p2p_proof.friendship"]).toBe(`${invite}~${accept}`);
    });
    it("the invite + accept form a friendship", async () => {
      const f = await verifyFriendship({ invite, accept }, { ...opts, now: now + 120 });
      expect(f).toMatchObject({ inviter: V.keys.deviceA.user, invitee: V.keys.deviceB.user, inv: V.derived["friend_invite.sha256_b64u"] });
    });
  });
});
