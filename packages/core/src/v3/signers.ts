// Copyright 2026 Ix Infrastructure Inc.
//
// Device-signed v3 objects (invites, accepts, unfriends, membership
// statements, proposals, rosters): the signer's certificate is checked first,
// under all six rules of docs/protocol.md §2.3 (rule 6 against the issuer's
// effective allowlist), then the object against the certificate's `spk`.
// Validity is judged when the object is received, never by its own `iat`
// (review N4: a backdated object from a revoked device fails).

import { verifyJws, type DecodedJws } from "../jws.js";
import { fail } from "../errors.js";
import { DEFAULT_SKEW_SEC, decodeTyped, isDid, nowSec, userIdField, type TimeOptions } from "./base.js";
import { verifyDeviceCertV3, type VerifiedDeviceCertV3 } from "./device.js";

type MaybePromise<T> = T | Promise<T>;

/** Finds a device certificate (compact JWS) by owner and did. */
export type CertResolverV3 = (userId: string, did: string) => MaybePromise<string | undefined>;

/** What rule 6 needs about an identity: its ik and effective allowlist. */
export interface AllowlistView {
  iss: string;
  ik: string;
  devices: readonly string[];
}

/** The effective identity of a userId (an IdentityView), or undefined if unknown. */
export type IdentityResolver = (userId: string) => MaybePromise<AllowlistView | undefined>;

export interface SignerContext extends TimeOptions {
  resolveCert: CertResolverV3;
  resolveIdentity: IdentityResolver;
}

export interface VerifiedSigned {
  decoded: DecodedJws;
  payload: Record<string, unknown>;
  signer: VerifiedDeviceCertV3;
}

/**
 * Verifies a device-signed object of type `typ`: header kid is the signer's
 * did (and equals payload `did` when the payload has one), the signer's
 * certificate is valid now under rules 1–6, `cert.iss == iss`, and the JWS
 * verifies under the certificate's `spk`.
 */
export async function verifyDeviceSignedV3(
  jws: string,
  typ: string,
  ctx: SignerContext,
  opts: { extraCerts?: readonly string[] } = {},
): Promise<VerifiedSigned> {
  const now = ctx.now ?? nowSec();
  const d = decodeTyped(jws, typ);
  // Untrusted until the signature passes: used only to find the certificate.
  const iss = userIdField(d.payload, "iss");
  const kid = d.header.kid;
  if (!isDid(kid)) fail("kid-mismatch", `kid ${kid} is not a device id`);
  if (d.payload.did !== undefined && d.payload.did !== kid) fail("kid-mismatch", `kid ${kid} != did ${String(d.payload.did)}`);
  const identity = await ctx.resolveIdentity(iss);
  if (!identity) fail("identity-unknown", `no identity document for ${iss}`);
  let certJws = await ctx.resolveCert(iss, kid);
  if (!certJws) certJws = opts.extraCerts?.find((c) => certIsFor(c, iss, kid));
  if (!certJws) fail("unknown-device", `${iss}/${kid}`);
  const signer = verifyDeviceCertV3(certJws, { now, skewSec: ctx.skewSec ?? DEFAULT_SKEW_SEC, identityDoc: identity });
  if (signer.did !== kid) fail("kid-mismatch", `kid ${kid} != cert did ${signer.did}`);
  if (signer.iss !== iss) fail("cert-mismatch", `cert is for ${signer.iss}, object from ${iss}`);
  verifyJws(jws, { typ, kid: signer.did, publicKey: signer.signingPublicKey });
  return { decoded: d, payload: d.payload, signer };
}

function certIsFor(certJws: string, iss: string, did: string): boolean {
  try {
    const p = decodeTyped(certJws, "p2p-device+jws").payload;
    return p.iss === iss && p.did === did;
  } catch {
    return false;
  }
}
