// Copyright 2026 Ix Infrastructure Inc.
//
// The only module that touches the noble primitives. Everything else in the
// package goes through these wrappers.

import { ed25519, x25519 as nobleX25519 } from "@noble/curves/ed25519.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { randomBytes as nobleRandomBytes } from "@noble/hashes/utils.js";
import { b64uEncode } from "./encoding.js";
import { fail } from "./errors.js";

export const ED25519_KEY_LEN = 32;
export const ED25519_SIG_LEN = 64;
export const X25519_KEY_LEN = 32;
export const XCHACHA_NONCE_LEN = 24;

export function randomBytes(n: number): Uint8Array {
  return nobleRandomBytes(n);
}

export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

/** Ed25519 public key from a 32-byte secret (seed), per RFC 8032. */
export function ed25519PublicKey(secretKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(secretKey);
}

export function ed25519Sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ed25519.sign(message, secretKey);
}

// ---------------------------------------------------------------------------
// Memoised checks (pure functions of their input bytes)
//
// The same certificates, rosters, friendship proofs and identity documents are
// verified again and again: once per envelope that cites them, and several
// times within one (longestLived ranks every candidate certificate, then the
// signer is verified once more). The curve work is the same every time, so
// positive results are remembered by the exact input bytes: a signature by
// SHA-256(publicKey || signature || message) (fixed-length fields first, so
// the encoding is unambiguous), a public key by its 32 bytes. Only successes
// are kept (a failure is recomputed, so junk can't fill the memo), the memo
// is bounded (oldest first out), and everything that depends on anything but
// those bytes (time, revocation, allowlists, chain rules) is still checked by
// the callers on every call.

const MEMO_MAX = 8192;

class PositiveMemo {
  private readonly seen = new Map<string, true>();
  has(key: string): boolean {
    if (!this.seen.has(key)) return false;
    // Refresh: a hot entry stays in.
    this.seen.delete(key);
    this.seen.set(key, true);
    return true;
  }
  add(key: string): void {
    this.seen.set(key, true);
    if (this.seen.size > MEMO_MAX) this.seen.delete(this.seen.keys().next().value!);
  }
  clear(): void {
    this.seen.clear();
  }
}

const verifiedSignatures = new PositiveMemo();
const strongEd25519Keys = new PositiveMemo();
const strongX25519Keys = new PositiveMemo();

/** Forgets every memoised result (tests and benchmarks measure the cold path with it). */
export function clearVerifyMemo(): void {
  verifiedSignatures.clear();
  strongEd25519Keys.clear();
  strongX25519Keys.clear();
}

function signatureKey(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): string {
  const buf = new Uint8Array(ED25519_KEY_LEN + ED25519_SIG_LEN + message.length);
  buf.set(publicKey, 0);
  buf.set(signature, ED25519_KEY_LEN);
  buf.set(message, ED25519_KEY_LEN + ED25519_SIG_LEN);
  return b64uEncode(nobleSha256(buf));
}

/**
 * Strict RFC 8032 verification (not ZIP-215); never throws.
 *
 * One rule on every path (protocol P3, "Ed25519 R"): a signature whose R has
 * a torsion component is rejected. noble's zip215:false check is cofactored
 * and would accept R = rB + T for a small-order T, while a cofactorless
 * verifier (OpenSSL, which relays use) rejects it. With R (and the key,
 * checked by assertStrongEd25519PublicKey) torsion-free, the two equations
 * agree, so every verifier gives the same answer for the same bytes. Honest
 * signers never produce a torsioned R.
 */
export function ed25519Verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  if (signature.length !== ED25519_SIG_LEN || publicKey.length !== ED25519_KEY_LEN) return false;
  const key = signatureKey(signature, message, publicKey);
  if (verifiedSignatures.has(key)) return true;
  let ok: boolean;
  try {
    ok = ed25519.Point.fromBytes(signature.subarray(0, 32), false).isTorsionFree() && ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    ok = false;
  }
  if (ok) verifiedSignatures.add(key);
  return ok;
}

/**
 * Rejects Ed25519 public keys that don't decode canonically to a curve point,
 * are of small order (e.g. the identity), or carry a torsion component.
 * Honest keys from keygen always pass.
 */
export function assertStrongEd25519PublicKey(publicKey: Uint8Array): void {
  const key = publicKey.length === ED25519_KEY_LEN ? b64uEncode(publicKey) : undefined;
  if (key !== undefined && strongEd25519Keys.has(key)) return;
  let ok: boolean;
  try {
    const P = ed25519.Point.fromBytes(publicKey, false);
    ok = !P.isSmallOrder() && P.isTorsionFree();
  } catch {
    ok = false;
  }
  if (!ok) fail("small-order-key", "Ed25519 public key is non-canonical or of small order");
  if (key !== undefined) strongEd25519Keys.add(key);
}

const PROBE_SCALAR = new Uint8Array(32).fill(1);

/**
 * Rejects low-order X25519 public keys: a clamped scalar is a multiple of the
 * cofactor 8, so X25519(k, u) is all-zero exactly when u has order dividing 8.
 */
export function assertStrongX25519PublicKey(publicKey: Uint8Array): void {
  let ok = publicKey.length === X25519_KEY_LEN;
  const key = ok ? b64uEncode(publicKey) : undefined;
  if (key !== undefined && strongX25519Keys.has(key)) return;
  if (ok) {
    try {
      nobleX25519.getSharedSecret(PROBE_SCALAR, publicKey);
    } catch {
      ok = false;
    }
  }
  if (!ok) fail("small-order-key", "X25519 public key is of low order");
  strongX25519Keys.add(key!);
}

export function x25519PublicKey(secretKey: Uint8Array): Uint8Array {
  return nobleX25519.getPublicKey(secretKey);
}

/** X25519(k, u). Rejects low-order points (all-zero shared secret). */
export function x25519(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  try {
    return nobleX25519.getSharedSecret(secretKey, publicKey);
  } catch {
    return fail("decrypt-failed", "invalid X25519 public key");
  }
}

export function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  return hkdf(nobleSha256, ikm, salt, info, length);
}

export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  return hmac(nobleSha256, key, message);
}

export function aeadSeal(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
  return xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
}

export function aeadOpen(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Uint8Array {
  try {
    return xchacha20poly1305(key, nonce, aad).decrypt(ciphertext);
  } catch {
    return fail("decrypt-failed", "AEAD authentication failed");
  }
}
