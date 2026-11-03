// Copyright 2026 Ix Infrastructure Inc.
//
// JWS compact serialization, EdDSA (RFC 8037) only. The signature covers the
// exact bytes `b64u(header) + "." + b64u(payload)` as received; nothing is
// ever re-serialized before verification.

import { b64uDecode, b64uEncode, fromUtf8, utf8 } from "./encoding.js";
import { ed25519Sign, ed25519Verify, ED25519_SIG_LEN } from "./crypto.js";
import { fail, type RejectReason } from "./errors.js";

/** Size cap for every non-envelope JWS (matches the Go authority). */
export const MAX_JWS_BYTES = 16 * 1024;
/** Size cap for a `p2p-msg+jws` envelope. */
export const MAX_ENVELOPE_BYTES = 64 * 1024;

export interface JwsHeader {
  alg: "EdDSA";
  typ: string;
  kid: string;
  [k: string]: unknown;
}

export interface DecodedJws<P = Record<string, unknown>> {
  compact: string;
  header: JwsHeader;
  payload: P;
  /** ASCII bytes of `b64u(header).b64u(payload)`, exactly as received. */
  signingInput: Uint8Array;
  signature: Uint8Array;
}

export function signJws(typ: string, kid: string, payload: object, secretKey: Uint8Array): string {
  const header = { alg: "EdDSA", typ, kid };
  const signingInput = `${b64uEncode(utf8(JSON.stringify(header)))}.${b64uEncode(utf8(JSON.stringify(payload)))}`;
  const sig = ed25519Sign(utf8(signingInput), secretKey);
  return `${signingInput}.${b64uEncode(sig)}`;
}

function parseJsonObject(bytes: Uint8Array, what: string): Record<string, unknown> {
  let v: unknown;
  try {
    v = JSON.parse(fromUtf8(bytes));
  } catch {
    return fail("malformed", `${what} is not JSON`);
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) fail("malformed", `${what} is not a JSON object`);
  return v as Record<string, unknown>;
}

/**
 * Structural decode only: NO signature check. Checks alg == EdDSA and that typ
 * and kid are present strings. Use verifyJws() before trusting any field.
 */
export function decodeJws(compact: string, maxBytes: number = MAX_JWS_BYTES): DecodedJws {
  if (typeof compact !== "string") fail("malformed", "JWS must be a string");
  // Compact JWS is ASCII, so length in chars is length in bytes.
  if (compact.length > maxBytes) fail("malformed", `JWS is ${compact.length} bytes, max ${maxBytes}`);
  const parts = compact.split(".");
  if (parts.length !== 3) fail("malformed", "JWS compact must have 3 parts");
  const [h, p, s] = parts;
  const header = parseJsonObject(b64uDecode(h), "header");
  if (header.alg !== "EdDSA") fail("bad-alg", `alg ${JSON.stringify(header.alg)}`);
  if (typeof header.typ !== "string" || header.typ === "") fail("malformed", "missing typ");
  if (typeof header.kid !== "string" || header.kid === "") fail("malformed", "missing kid");
  if ("crit" in header) fail("malformed", "crit is not supported");
  const payload = parseJsonObject(b64uDecode(p), "payload");
  const signature = b64uDecode(s, ED25519_SIG_LEN);
  return { compact, header: header as JwsHeader, payload, signingInput: utf8(`${h}.${p}`), signature };
}

export interface VerifyJwsOptions {
  typ: string;
  /** Expected kid; when set, a different kid is rejected with kid-mismatch. */
  kid?: string;
  publicKey: Uint8Array;
  /** Reason used when the signature does not verify. */
  badSignature?: RejectReason;
  /** Size cap (default MAX_JWS_BYTES). */
  maxBytes?: number;
}

/** Checks alg, typ and kid, then the Ed25519 signature over the exact bytes. */
export function verifyJws(compact: string, opts: VerifyJwsOptions): DecodedJws {
  const d = decodeJws(compact, opts.maxBytes);
  expectTyp(d, opts.typ);
  if (opts.kid !== undefined && d.header.kid !== opts.kid) {
    fail("kid-mismatch", `kid ${d.header.kid} != ${opts.kid}`);
  }
  if (!ed25519Verify(d.signature, d.signingInput, opts.publicKey)) fail(opts.badSignature ?? "bad-signature");
  return d;
}

export function expectTyp(d: DecodedJws, typ: string): void {
  if (d.header.typ !== typ) fail("typ-mismatch", `typ ${d.header.typ} != ${typ}`);
}
