// Copyright 2026 Ix Infrastructure Inc.
// F-2: native Ed25519 must reject everything core's noble-strict verifier
// (zip215:false, plus the small-order/torsion key checks) rejects, and accept
// what it accepts. Differential over core's test vectors, random keys, and
// malformed signatures, keys and messages.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { b64uDecode, randomBytes } from "@peer2peer/core";
import { assertStrongEd25519PublicKey, ed25519Verify as nobleStrict } from "@peer2peer/core/v3";
import { ed25519VerifyNative, ed25519VerifyStrict, NATIVE_VERIFY_MAX_BYTES } from "../crypto.js";

const hex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));
const enc = new TextEncoder();

/** The relay's composite: a key is checked strong once (at cert time), then signatures natively. */
function relayStrict(sig: Uint8Array, msg: Uint8Array, pk: Uint8Array): boolean {
  try {
    assertStrongEd25519PublicKey(pk);
  } catch {
    return false;
  }
  return ed25519VerifyNative(sig, msg, pk);
}
/** The reference: the same key check, then noble strict. */
function reference(sig: Uint8Array, msg: Uint8Array, pk: Uint8Array): boolean {
  try {
    assertStrongEd25519PublicKey(pk);
  } catch {
    return false;
  }
  return nobleStrict(sig, msg, pk);
}

interface Case {
  name: string;
  sig: Uint8Array;
  msg: Uint8Array;
  pk: Uint8Array;
}

function jwsCase(name: string, jws: string, pk: Uint8Array): Case {
  const i = jws.lastIndexOf(".");
  return { name, msg: enc.encode(jws.slice(0, i)), sig: b64uDecode(jws.slice(i + 1)), pk };
}

/** Every signed object in core's test vectors, with the key it is signed under. */
function vectorCases(): Case[] {
  const base = new URL("../../../core/src/", import.meta.url);
  const out: Case[] = [];
  const v2 = JSON.parse(readFileSync(new URL("__tests__/testdata/go-vectors.json", base), "utf8"));
  const keyOf = (signer: string): Uint8Array | undefined => {
    const k = v2.keys?.[signer];
    if (k?.x) return b64uDecode(k.x);
    const j = (v2.jwks?.keys ?? []).find((x: { kid?: string }) => x.kid);
    return j?.x ? b64uDecode(j.x) : undefined;
  };
  for (const v of [...v2.valid, ...v2.invalid]) {
    const pk = keyOf(v.signer);
    if (pk && typeof v.jws === "string" && v.jws.split(".").length === 3) {
      try {
        out.push(jwsCase(`v2 ${v.name}`, v.jws, pk));
      } catch {
        // a deliberately malformed signature encoding: not a signature case
      }
    }
  }
  const v3 = JSON.parse(readFileSync(new URL("v3/__tests__/testdata/v3-vectors.json", base), "utf8"));
  const ik = b64uDecode(v3.identity.ikPub);
  const spk = b64uDecode(v3.device.spk);
  out.push(jwsCase("v3 device cert", v3.device.cert, ik));
  out.push(jwsCase("v3 identity doc", v3.identityDoc.jws, ik));
  out.push({ name: "v3 relay auth", msg: enc.encode(v3.relayAuth.message), sig: b64uDecode(v3.relayAuth.sig), pk: spk });
  if (typeof v3.envelope?.jws === "string") out.push(jwsCase("v3 envelope", v3.envelope.jws, spk));
  return out;
}

function randomCases(n: number): Case[] {
  return Array.from({ length: n }, (_, i) => {
    const sk = randomBytes(32);
    const msg = randomBytes(1 + (i % 300));
    return { name: `random ${i}`, sig: ed25519.sign(msg, sk), msg, pk: ed25519.getPublicKey(sk) };
  });
}

const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const SMALL_ORDER = [
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
].map(hex);
const NON_CANONICAL = [
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "0100000000000000000000000000000000000000000000000000000000000080",
].map(hex);

function leToBig(b: Uint8Array): bigint {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]);
  return x;
}
function bigToLe(x: bigint, n = 32): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    out[i] = Number(x & 255n);
    x >>= 8n;
  }
  return out;
}

/** Malformed variants of a valid case. */
function mutations(c: Case): Case[] {
  const out: Case[] = [];
  const withSig = (name: string, sig: Uint8Array) => out.push({ ...c, name: `${c.name} / ${name}`, sig });
  const R = c.sig.slice(0, 32);
  const S = c.sig.slice(32);
  for (const bit of [0, 7, 100, 255, 256, 300, 511]) {
    const s = c.sig.slice();
    s[bit >> 3] ^= 1 << (bit & 7);
    withSig(`flip bit ${bit}`, s);
  }
  withSig("S + L (non-canonical)", Uint8Array.from([...R, ...bigToLe(leToBig(S) + L)]));
  withSig("S = L", Uint8Array.from([...R, ...bigToLe(L)]));
  withSig("S high bit", Uint8Array.from([...R, ...S.slice(0, 31), S[31] | 0x80]));
  withSig("all zero", new Uint8Array(64));
  withSig("all 0xff", new Uint8Array(64).fill(255));
  withSig("short", c.sig.slice(0, 63));
  withSig("long", Uint8Array.from([...c.sig, 0]));
  for (const [i, p] of SMALL_ORDER.entries()) withSig(`R small-order ${i}`, Uint8Array.from([...p, ...S]));
  for (const [i, p] of NON_CANONICAL.entries()) withSig(`R non-canonical ${i}`, Uint8Array.from([...p, ...S]));
  for (const [i, p] of [...SMALL_ORDER, ...NON_CANONICAL].entries()) out.push({ ...c, name: `${c.name} / bad key ${i}`, pk: p });
  const m = c.msg.slice();
  if (m.length > 0) m[0] ^= 1;
  out.push({ ...c, name: `${c.name} / message changed`, msg: m });
  out.push({ ...c, name: `${c.name} / message extended`, msg: Uint8Array.from([...c.msg, 0]) });
  return out;
}

describe("native Ed25519 vs core noble-strict (differential)", () => {
  const vectors = vectorCases();
  const valid = [...vectors, ...randomCases(64)];

  it("loads core's vectors", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(15);
  });

  it("agrees on every vector and random signature", () => {
    for (const c of valid) expect(relayStrict(c.sig, c.msg, c.pk), c.name).toBe(reference(c.sig, c.msg, c.pk));
    // The honest ones verify.
    expect(randomCases(16).every((c) => relayStrict(c.sig, c.msg, c.pk))).toBe(true);
  });

  // CPU-bound (thousands of curve operations): a generous timeout, so a loaded machine (pre-release review) slows it, never fails it.
  it("rejects everything noble-strict rejects, over malformed signatures, keys and messages", { timeout: 120_000 }, () => {
    let checked = 0;
    let bothReject = 0;
    for (const base of valid.filter((c) => reference(c.sig, c.msg, c.pk))) {
      for (const m of mutations(base)) {
        const ref = reference(m.sig, m.msg, m.pk);
        const nat = relayStrict(m.sig, m.msg, m.pk);
        if (!ref) expect(nat, m.name).toBe(false);
        else expect(nat, m.name).toBe(true);
        checked++;
        if (!ref && !nat) bothReject++;
      }
    }
    expect(checked).toBeGreaterThan(1000);
    expect(bothReject).toBeGreaterThan(900);
    // ~4.4s alone: past vitest's 5s default under load (bounded by the timeout option above).
  });

  it("rejects R with a torsion component on every path and at every size (the reviewer's vector, T of order 2)", () => {
    // R = rB + T: noble's cofactored zip215:false check alone accepts it,
    // OpenSSL's cofactorless check rejects it. One rule everywhere (P3): reject.
    const Lc = ed25519.Point.Fn.ORDER;
    const T2 = ed25519.Point.fromBytes(hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"));
    const { scalar, pointBytes: pk } = ed25519.utils.getExtendedPublicKey(new Uint8Array(32).fill(7));
    for (const n of [100, 20_000]) {
      const msg = new Uint8Array(n).fill(65);
      const r = 987654321987654321n % Lc;
      const R = ed25519.Point.BASE.multiply(r).add(T2).toBytes();
      const k = leToBig(sha512(Uint8Array.from([...R, ...pk, ...msg]))) % Lc;
      const sig = Uint8Array.from([...R, ...bigToLe((r + k * scalar) % Lc)]);
      expect(ed25519.verify(sig, msg, pk, { zip215: false }), `noble cofactored ${n}`).toBe(true);
      expect(nobleStrict(sig, msg, pk), `core ${n}`).toBe(false);
      expect(ed25519VerifyNative(sig, msg, pk), `native ${n}`).toBe(false);
      expect(ed25519VerifyStrict(sig, msg, pk), `relay ${n}`).toBe(false);
      expect(relayStrict(sig, msg, pk)).toBe(reference(sig, msg, pk));
    }
  });

  it("uses core's strict verifier above the native size bound, with the same verdicts", () => {
    const sk = randomBytes(32);
    const pk = ed25519.getPublicKey(sk);
    const msg = randomBytes(NATIVE_VERIFY_MAX_BYTES + 100);
    const sig = ed25519.sign(msg, sk);
    expect(ed25519VerifyStrict(sig, msg, pk)).toBe(true);
    for (const m of mutations({ name: "large", sig, msg, pk }).filter((x) => x.pk === pk)) {
      expect(ed25519VerifyStrict(m.sig, m.msg, m.pk), m.name).toBe(nobleStrict(m.sig, m.msg, m.pk));
    }
  });
});
