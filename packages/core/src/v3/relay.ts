// Copyright 2026 Ix Infrastructure Inc.
//
// Relay-facing helpers (docs/protocol.md §5): what `packages/relay` imports
// to authenticate devices, check sends and store identity documents. A relay
// sees only outer envelope fields, capability tokens, identity documents and
// connection metadata; nothing here opens an envelope.
//
//   canonicalRelayUrl(url)                                  §5.1
//   relayAuthMessage(relay, nonce) / signRelayAuth / verifyRelayAuth   §5.2
//   checkHelloRelay(helloRelay, dialledUrl)                 §5.2 (client, H5)
//   verifyDeviceCertV3(jws, {now, identityDoc?})            §2.3 rules 1–5 (+6)
//   parseOuterEnvelope(jws) / verifyOuterEnvelope(jws, ...) §5.4 steps 1–2
//   verifyCapForSend(cap, {relayUrl, to, envFrom, kind, now})  §5.4 step 3
//   powOk(envBytes, powNonce, bits)                         §5.4 step 4
//   verifyIdentityDocLink(prevDocJws | undefined, docJws, {merge?})  §5.6
//   docListsRelay(doc, relayUrl)                            §5.6 scope

import { b64uDecode, b64uEncode, concat, utf8 } from "../encoding.js";
import { ed25519Sign, ed25519Verify, sha256 } from "../crypto.js";
import { fail } from "../errors.js";
import type { TimeOptions } from "./base.js";
import { verifyDeviceCertV3, type AllowlistSource, type VerifiedDeviceCertV3 } from "./device.js";
import { decodeEnvelopeV3, verifyEnvelopeV3Signature, type EnvelopeV3Payload } from "./envelope.js";
import type { IdentityDocPayload } from "./identitydoc.js";
import { canonicalRelayUrl } from "./relayurl.js";

export { canonicalRelayUrl, isCanonicalRelayUrl } from "./relayurl.js";
export { verifyDeviceCertV3 } from "./device.js";
export { verifyCapForSend } from "./caps.js";
export { verifyIdentityDocLink, verifyIdentityDocSignature, peekIdentityDoc } from "./identitydoc.js";

export const RELAY_AUTH_PREFIX = "p2p/v3/relay-auth|";
/** §5.2: frames are at most 96 KiB. */
export const MAX_RELAY_FRAME_BYTES = 96 * 1024;
/** §5.2: `hello.pow` is 0..24 bits. */
export const MAX_POW_BITS = 24;

/** The bytes a device signs to authenticate: UTF-8("p2p/v3/relay-auth|" + hello.relay + "|" + nonce). */
export function relayAuthMessage(relay: string, nonce: string): Uint8Array {
  return utf8(`${RELAY_AUTH_PREFIX}${relay}|${nonce}`);
}

/** Client: `sig` for the `auth` frame, over the relay URL from `hello` (already checked against the dialled URL). */
export function signRelayAuth(relay: string, nonce: string, signingSecretKey: Uint8Array): string {
  return b64uEncode(ed25519Sign(relayAuthMessage(relay, nonce), signingSecretKey));
}

/**
 * Client (review H5): `hello.relay` must equal the canonical form of the URL
 * actually dialled; otherwise close the connection.
 */
export function checkHelloRelay(helloRelay: string, dialledUrl: string): string {
  const dialled = canonicalRelayUrl(dialledUrl);
  if (helloRelay !== dialled) fail("relay-mismatch", `hello.relay ${helloRelay} != dialled ${dialled}`);
  return dialled;
}

export interface RelayAuthParams extends TimeOptions {
  /** The device certificate from the `auth` frame. */
  cert: string;
  /** b64u Ed25519 signature from the `auth` frame. */
  sig: string;
  /** The relay's own canonical URL, as it sent in `hello`. */
  relay: string;
  /** The nonce the relay sent in `hello`. */
  nonce: string;
  /** The issuer's identity document, when the relay holds one (rule 6). */
  identityDoc?: AllowlistSource;
}

/**
 * Relay (§5.2 step 3): the certificate is valid under §2.3 rules 1–5 (and 6
 * with a document), and `sig` verifies under its `spk` over this relay's URL
 * and nonce. The connection is then bound to the mailbox (cert.iss, cert.did).
 */
export function verifyRelayAuth(p: RelayAuthParams): VerifiedDeviceCertV3 {
  const cert = verifyDeviceCertV3(p.cert, { now: p.now, skewSec: p.skewSec, identityDoc: p.identityDoc });
  let sig: Uint8Array;
  try {
    sig = b64uDecode(p.sig, 64);
  } catch {
    return fail("bad-signature", "auth sig is not a 64-byte b64u signature");
  }
  if (!ed25519Verify(sig, relayAuthMessage(canonicalRelayUrl(p.relay), p.nonce), cert.signingPublicKey)) {
    fail("bad-signature", "auth signature does not verify for this relay and nonce");
  }
  return cert;
}

export interface OuterEnvelope {
  payload: EnvelopeV3Payload;
  /** The exact bytes received (what `pow` and size caps apply to). */
  bytes: Uint8Array;
}

/** §5.4 step 1 (structure): parses, ≤ 64 KiB, typ, payload shape, kid == fdid. No signature check. */
export function parseOuterEnvelope(jws: string): OuterEnvelope {
  const d = decodeEnvelopeV3(jws);
  return { payload: d.payload, bytes: utf8(jws) };
}

export interface VerifiedOuterEnvelope extends OuterEnvelope {
  cert: VerifiedDeviceCertV3;
}

/**
 * §5.4 step 2 without opening: `fcert` verifies (rules 1–5, 6 with a
 * document), `fcert.iss == from`, `fcert.did == fdid == kid`, and the
 * envelope signature verifies under `fcert.spk`, so the sender fields can't be
 * spoofed. `to`/`tdid` against the send frame are the caller's check (step 1).
 */
export function verifyOuterEnvelope(jws: string, opts: TimeOptions & { identityDoc?: AllowlistSource } = {}): VerifiedOuterEnvelope {
  const outer = parseOuterEnvelope(jws);
  const p = outer.payload;
  const cert = verifyDeviceCertV3(p.fcert, { now: opts.now, skewSec: opts.skewSec, identityDoc: opts.identityDoc });
  if (cert.iss !== p.from) fail("cert-mismatch", `fcert is for ${cert.iss}, envelope from ${p.from}`);
  if (cert.did !== p.fdid) fail("kid-mismatch", `fcert is for ${cert.did}, envelope from ${p.fdid}`);
  verifyEnvelopeV3Signature(jws, cert.signingPublicKey);
  return { ...outer, cert };
}

/** Number of leading zero bits of `h`. */
export function leadingZeroBits(h: Uint8Array): number {
  let n = 0;
  for (const b of h) {
    if (b === 0) {
      n += 8;
      continue;
    }
    return n + Math.clz32(b) - 24;
  }
  return n;
}

/**
 * §5.4: the pow condition is H(env_bytes || pow) having at least `bits`
 * leading zero bits. `envBytes` is the envelope JWS (string: its ASCII bytes);
 * `powNonce` is the frame's b64u `pow` (or its decoded bytes).
 */
export function powOk(envBytes: Uint8Array | string, powNonce: string | Uint8Array, bits: number): boolean {
  if (!Number.isInteger(bits) || bits < 0 || bits > 256) return false;
  if (bits === 0) return true;
  let nonce: Uint8Array;
  try {
    nonce = typeof powNonce === "string" ? b64uDecode(powNonce) : powNonce;
  } catch {
    return false;
  }
  if (nonce.length === 0 || nonce.length > 64) return false;
  const env = typeof envBytes === "string" ? utf8(envBytes) : envBytes;
  return leadingZeroBits(sha256(concat(env, nonce))) >= bits;
}

/** Client: finds a `pow` nonce (b64u) for `bits` by counting; fine for the ≤ 24 bits relays ask. */
export function solvePow(envBytes: Uint8Array | string, bits: number, maxTries = 1 << 28): string {
  const env = typeof envBytes === "string" ? utf8(envBytes) : envBytes;
  const nonce = new Uint8Array(8);
  const view = new DataView(nonce.buffer);
  for (let i = 0; i < maxTries; i++) {
    view.setUint32(0, Math.floor(i / 2 ** 32));
    view.setUint32(4, i >>> 0);
    if (leadingZeroBits(sha256(concat(env, nonce))) >= bits) return b64uEncode(nonce);
  }
  return fail("rate-limited", `no pow solution for ${bits} bits within ${maxTries} tries`);
}

/** §5.6 scope: a relay serves only documents whose `relays` include its canonical URL. */
export function docListsRelay(doc: Pick<IdentityDocPayload, "relays">, relayUrl: string): boolean {
  return doc.relays.includes(canonicalRelayUrl(relayUrl));
}
