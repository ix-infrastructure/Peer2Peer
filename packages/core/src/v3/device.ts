// Copyright 2026 Ix Infrastructure Inc.
//
// Device keys and device certificates (docs/protocol.md §2.3).
//
// A certificate (`typ: "p2p-device+jws"`, `kid: "ik"`) is signed by the
// user's own identity key. It is valid when all of these hold:
//   1. iss == "p2p:" + b32(H(ik));
//   2. the JWS verifies under ik;
//   3. did recomputes from spk (`"d_" + b32(H(spk))[:26]`), so nobody can
//      claim another device's mailbox (review H4);
//   4. spk, kpk and ik pass the small-order checks (v2 C13);
//   5. it is unexpired (lifetime at most 90 days);
//   6. did is listed in `devices` of the issuer's current identity document
//      (§2.5), which makes the document an allowlist. While the identity is
//      forked, the allowlist is the intersection of the branches.
// Rule 6 needs the document; relays apply it when they hold one (§5.2).

import { b64uDecode, b64uEncode } from "../encoding.js";
import {
  assertStrongEd25519PublicKey,
  assertStrongX25519PublicKey,
  ed25519PublicKey,
  randomBytes,
  x25519PublicKey,
} from "../crypto.js";
import { signJws, verifyJws } from "../jws.js";
import { fail } from "../errors.js";
import {
  bytesField,
  checkExpiry,
  DEFAULT_SKEW_SEC,
  DEVICE_CERT_MAX_TTL_SEC,
  didField,
  didFromSpk,
  decodeTyped,
  IK_KID,
  int,
  checkFields,
  nowSec,
  optStr,
  TYP3,
  userIdField,
  userIdFromIk,
  type TimeOptions,
} from "./base.js";
import type { IdentityKey } from "./identity.js";
import { verifyIdentityDocSignature } from "./identitydoc.js";

/** A v3 device's keys. `did` is derived from `spk`. */
export interface DeviceKeysV3 {
  userId: string;
  did: string;
  /** Ed25519 seed (32 bytes). */
  signingSecretKey: Uint8Array;
  signingPublicKey: Uint8Array;
  /** X25519 secret (32 bytes). */
  agreementSecretKey: Uint8Array;
  agreementPublicKey: Uint8Array;
}

export function generateDeviceKeysV3(userId: string): DeviceKeysV3 {
  return deviceKeysV3FromSecrets(userId, randomBytes(32), randomBytes(32));
}

export function deviceKeysV3FromSecrets(userId: string, signingSecretKey: Uint8Array, agreementSecretKey: Uint8Array): DeviceKeysV3 {
  const signingPublicKey = ed25519PublicKey(signingSecretKey);
  return {
    userId,
    did: didFromSpk(signingPublicKey),
    signingSecretKey,
    signingPublicKey,
    agreementSecretKey,
    agreementPublicKey: x25519PublicKey(agreementSecretKey),
  };
}

export interface DeviceCertV3Payload {
  iss: string;
  ik: string;
  did: string;
  spk: string;
  kpk: string;
  label?: string;
  iat: number;
  exp: number;
}

export interface VerifiedDeviceCertV3 extends DeviceCertV3Payload {
  jws: string;
  ikPublicKey: Uint8Array;
  signingPublicKey: Uint8Array;
  agreementPublicKey: Uint8Array;
}

/**
 * Signs a certificate for a device with the identity key. Renewal (§2.3)
 * re-signs with the same did, spk and kpk and a new iat/exp.
 */
export function createDeviceCert(
  ik: IdentityKey,
  device: { signingPublicKey: Uint8Array; agreementPublicKey: Uint8Array; label?: string },
  opts: { iat?: number; ttlSec?: number } = {},
): string {
  const iat = opts.iat ?? nowSec();
  const ttl = opts.ttlSec ?? DEVICE_CERT_MAX_TTL_SEC;
  if (ttl <= 0 || ttl > DEVICE_CERT_MAX_TTL_SEC) fail("malformed", "certificate ttl must be in (0, 90d]");
  assertStrongEd25519PublicKey(device.signingPublicKey);
  assertStrongX25519PublicKey(device.agreementPublicKey);
  const payload: DeviceCertV3Payload = {
    iss: ik.userId,
    ik: b64uEncode(ik.publicKey),
    did: didFromSpk(device.signingPublicKey),
    spk: b64uEncode(device.signingPublicKey),
    kpk: b64uEncode(device.agreementPublicKey),
    ...(device.label !== undefined ? { label: device.label } : {}),
    iat,
    exp: iat + ttl,
  };
  return signJws(TYP3.device, IK_KID, payload, ik.secretKey);
}

/**
 * What rule 6 checks against: the issuer's current document, either as a
 * compact JWS (its signature and `iss`/`ik` are checked, its `exp` is not,
 * because relays keep authenticating against expired documents, §2.5) or as
 * an already-verified view whose `devices` is the effective allowlist (the
 * intersection of the branches while forked).
 *
 * Relays (pre-release review L8): while an identity is forked, pass the OBJECT form
 * carrying the intersection of every held tip's `devices` (and that
 * identity's `ik`). Passing one tip's JWS would let through a device that
 * the other branch revoked.
 */
export type AllowlistSource = string | { iss: string; devices: readonly string[]; ik?: string };

export interface DeviceCertVerifyOptions extends TimeOptions {
  /** Applies rule 6 when given. */
  identityDoc?: AllowlistSource;
}

function parseCertPayload(p: Record<string, unknown>): DeviceCertV3Payload {
  checkFields(p, ["iss", "ik", "did", "spk", "kpk", "label", "iat", "exp"], "device certificate");
  const label = optStr(p, "label");
  return {
    iss: userIdField(p, "iss"),
    ik: bytesField(p, "ik", 32),
    did: didField(p, "did"),
    spk: bytesField(p, "spk", 32),
    kpk: bytesField(p, "kpk", 32),
    ...(label !== undefined ? { label } : {}),
    iat: int(p, "iat"),
    exp: int(p, "exp"),
  };
}

/** Rule 6 against a document or an effective allowlist. */
export function checkDeviceListed(cert: Pick<DeviceCertV3Payload, "iss" | "ik" | "did">, source: AllowlistSource): void {
  let iss: string;
  let ik: string | undefined;
  let devices: readonly string[];
  if (typeof source === "string") {
    const doc = verifyIdentityDocSignature(source);
    iss = doc.iss;
    ik = doc.ik;
    devices = doc.devices;
  } else {
    iss = source.iss;
    ik = source.ik;
    devices = source.devices;
  }
  if (iss !== cert.iss) fail("issuer-mismatch", `identity document is for ${iss}, certificate for ${cert.iss}`);
  if (ik !== undefined && ik !== cert.ik) fail("issuer-mismatch", "identity document and certificate name different keys");
  if (!devices.includes(cert.did)) fail("device-not-listed", `${cert.did} is not in ${cert.iss}'s identity document`);
}

/**
 * §2.3 rules 1–5, and rule 6 when `identityDoc` is supplied. Relays call it
 * with whatever document they hold (§5.2); clients always supply the
 * effective allowlist.
 */
export function verifyDeviceCertV3(jws: string, opts: DeviceCertVerifyOptions = {}): VerifiedDeviceCertV3 {
  const now = opts.now ?? nowSec();
  const skew = opts.skewSec ?? DEFAULT_SKEW_SEC;
  const d = decodeTyped(jws, TYP3.device);
  if (d.header.kid !== IK_KID) fail("kid-mismatch", `kid ${d.header.kid} != ${IK_KID}`);
  const p = parseCertPayload(d.payload);
  const ikPublicKey = b64uDecode(p.ik, 32);
  const signingPublicKey = b64uDecode(p.spk, 32);
  const agreementPublicKey = b64uDecode(p.kpk, 32);
  // Rule 4 before the signature: a small-order key can make a forged signature verify.
  assertStrongEd25519PublicKey(ikPublicKey);
  assertStrongEd25519PublicKey(signingPublicKey);
  assertStrongX25519PublicKey(agreementPublicKey);
  // Rule 1.
  if (userIdFromIk(ikPublicKey) !== p.iss) fail("issuer-mismatch", "iss is not the fingerprint of ik");
  // Rule 2.
  verifyJws(jws, { typ: TYP3.device, kid: IK_KID, publicKey: ikPublicKey });
  // Rule 3 (H4).
  if (didFromSpk(signingPublicKey) !== p.did) fail("did-mismatch", `did ${p.did} does not derive from spk`);
  // Rule 5.
  checkExpiry(p.iat, p.exp, DEVICE_CERT_MAX_TTL_SEC, now, skew);
  // Rule 6.
  if (opts.identityDoc !== undefined) checkDeviceListed(p, opts.identityDoc);
  return { ...p, jws, ikPublicKey, signingPublicKey, agreementPublicKey };
}

/** True when the certificate is within `withinSec` of expiry (renewal and §3.3 re-sign triggers). */
export function certExpiresWithin(cert: Pick<DeviceCertV3Payload, "exp">, withinSec: number, now: number = nowSec()): boolean {
  return cert.exp - now <= withinSec;
}
