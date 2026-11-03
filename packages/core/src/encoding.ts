// Copyright 2026 Ix Infrastructure Inc.
//
// base64url (no padding), base32 (RFC 4648, lowercase, no padding) and UTF-8
// helpers. Decoding is strict: padding, characters outside the alphabet and
// non-canonical trailing bits are all rejected, so one byte string has exactly
// one textual form. Pure: no Node-only APIs, so it runs in any JS runtime.

import { fail } from "./errors.js";

const B64U_RE = /^[A-Za-z0-9_-]*$/;

const B64U_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64U_INDEX = new Map([...B64U_ALPHABET].map((c, i) => [c, i]));

export function b64uEncode(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const v = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64U_ALPHABET[v >> 18] + B64U_ALPHABET[(v >> 12) & 63] + B64U_ALPHABET[(v >> 6) & 63] + B64U_ALPHABET[v & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const v = bytes[i] << 16;
    out += B64U_ALPHABET[v >> 18] + B64U_ALPHABET[(v >> 12) & 63];
  } else if (rest === 2) {
    const v = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64U_ALPHABET[v >> 18] + B64U_ALPHABET[(v >> 12) & 63] + B64U_ALPHABET[(v >> 6) & 63];
  }
  return out;
}

export function b64uDecode(s: string, expectedLength?: number): Uint8Array {
  if (typeof s !== "string" || !B64U_RE.test(s) || s.length % 4 === 1) fail("malformed", "invalid base64url");
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const c of s) {
    acc = (acc << 6) | B64U_INDEX.get(c)!;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
    acc &= (1 << bits) - 1;
  }
  if (acc !== 0) fail("malformed", "non-canonical base64url");
  if (expectedLength !== undefined && out.length !== expectedLength) {
    fail("malformed", `expected ${expectedLength} bytes, got ${out.length}`);
  }
  return out;
}

const B32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
const B32_INDEX = new Map([...B32_ALPHABET].map((c, i) => [c, i]));

/** RFC 4648 base32, lowercase, without padding (the v3 `b32`). */
export function b32Encode(bytes: Uint8Array): string {
  let out = "";
  let acc = 0;
  let bits = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32_ALPHABET[(acc >> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32_ALPHABET[(acc << (5 - bits)) & 31];
  return out;
}

/** Strict inverse of b32Encode: lowercase only, no padding, canonical trailing bits. */
export function b32Decode(s: string, expectedLength?: number): Uint8Array {
  if (typeof s !== "string" || !/^[a-z2-7]*$/.test(s) || [1, 3, 6].includes(s.length % 8)) {
    fail("malformed", "invalid base32");
  }
  const out = new Uint8Array(Math.floor((s.length * 5) / 8));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const c of s) {
    acc = (acc << 5) | B32_INDEX.get(c)!;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
    acc &= (1 << bits) - 1;
  }
  if (acc !== 0) fail("malformed", "non-canonical base32");
  if (expectedLength !== undefined && out.length !== expectedLength) {
    fail("malformed", `expected ${expectedLength} bytes, got ${out.length}`);
  }
  return out;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export function utf8(s: string): Uint8Array {
  return encoder.encode(s);
}

export function fromUtf8(bytes: Uint8Array): string {
  try {
    return decoder.decode(bytes);
  } catch {
    return fail("malformed", "invalid UTF-8");
  }
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
