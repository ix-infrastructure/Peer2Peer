// Copyright 2026 Ix Infrastructure Inc.
import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";
import {
  assertStrongEd25519PublicKey,
  assertStrongX25519PublicKey,
  clearVerifyMemo,
  ed25519PublicKey,
  ed25519Sign,
  ed25519Verify,
  hkdfSha256,
  x25519,
  x25519PublicKey,
  aeadOpen,
  aeadSeal,
} from "../crypto.js";
import { b64uDecode, b64uEncode } from "../encoding.js";
import { P2PError } from "../errors.js";

const hex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

// RFC 8032 section 7.1.
const ED25519_VECTORS = [
  {
    name: "TEST 1",
    sk: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    pk: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    msg: "",
    sig: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  },
  {
    name: "TEST 2",
    sk: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    pk: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    msg: "72",
    sig: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  },
  {
    name: "TEST 3",
    sk: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    pk: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    msg: "af82",
    sig: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
  },
  {
    name: "TEST SHA(abc)",
    sk: "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
    pk: "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
    msg: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    sig: "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
  },
];

describe("Ed25519 (RFC 8032 known answers)", () => {
  for (const v of ED25519_VECTORS) {
    it(v.name, () => {
      expect(toHex(ed25519PublicKey(hex(v.sk)))).toBe(v.pk);
      expect(toHex(ed25519Sign(hex(v.msg), hex(v.sk)))).toBe(v.sig);
      expect(ed25519Verify(hex(v.sig), hex(v.msg), hex(v.pk))).toBe(true);
      const bad = hex(v.sig);
      bad[0] ^= 1;
      expect(ed25519Verify(bad, hex(v.msg), hex(v.pk))).toBe(false);
    });
  }
  it("rejects wrong-length inputs without throwing", () => {
    expect(ed25519Verify(new Uint8Array(63), new Uint8Array(0), new Uint8Array(32))).toBe(false);
    expect(ed25519Verify(new Uint8Array(64), new Uint8Array(0), new Uint8Array(31))).toBe(false);
  });
});

describe("X25519 (RFC 7748 known answers)", () => {
  it("section 5.2 scalar multiplication", () => {
    const out = x25519(
      hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
      hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    );
    expect(toHex(out)).toBe("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
  });

  it("section 5.2 iterated (1 and 1000 iterations)", () => {
    let k: Uint8Array = hex("0900000000000000000000000000000000000000000000000000000000000000");
    let u: Uint8Array = k.slice();
    for (let i = 1; i <= 1000; i++) {
      const r = x25519(k, u);
      u = k;
      k = r;
      if (i === 1) expect(toHex(k)).toBe("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
    }
    expect(toHex(k)).toBe("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
  });

  it("section 6.1 Diffie-Hellman", () => {
    const aSk = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const bSk = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    const aPk = x25519PublicKey(aSk);
    const bPk = x25519PublicKey(bSk);
    expect(toHex(aPk)).toBe("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    expect(toHex(bPk)).toBe("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    expect(toHex(x25519(aSk, bPk))).toBe(shared);
    expect(toHex(x25519(bSk, aPk))).toBe(shared);
  });

  it("rejects a low-order point", () => {
    expect(() => x25519(new Uint8Array(32).fill(7), new Uint8Array(32))).toThrow(P2PError);
  });
});

describe("HKDF-SHA256 (RFC 5869 test case 1)", () => {
  it("derives the expected OKM", () => {
    const okm = hkdfSha256(
      new Uint8Array(22).fill(0x0b),
      hex("000102030405060708090a0b0c"),
      hex("f0f1f2f3f4f5f6f7f8f9"),
      42,
    );
    expect(toHex(okm)).toBe(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
  });
});

describe("XChaCha20-Poly1305", () => {
  it("round-trips and authenticates the AAD", () => {
    const key = new Uint8Array(32).fill(1);
    const nonce = new Uint8Array(24).fill(2);
    const ct = aeadSeal(key, nonce, new Uint8Array([1, 2, 3]), new Uint8Array([9]));
    expect([...aeadOpen(key, nonce, ct, new Uint8Array([9]))]).toEqual([1, 2, 3]);
    expect(() => aeadOpen(key, nonce, ct, new Uint8Array([8]))).toThrow(/decrypt-failed/);
  });
});

describe("base64url", () => {
  it("is unpadded and strict", () => {
    expect(b64uEncode(new Uint8Array([0xfb, 0xff]))).toBe("-_8");
    expect([...b64uDecode("-_8")]).toEqual([0xfb, 0xff]);
    for (const bad of ["-_8=", "+/8", "a", "-_9"]) expect(() => b64uDecode(bad)).toThrow(P2PError);
    expect(() => b64uDecode("AAAA", 4)).toThrow(/expected 4 bytes/);
  });
});

describe("Ed25519 R with a torsion component (P3 reading)", () => {
  // R = rB + T with T the point of order 2: noble's cofactored zip215:false
  // check accepts this, a cofactorless verifier (OpenSSL) rejects it. Core
  // rejects it too, so every verifier agrees.
  const L = ed25519.Point.Fn.ORDER;
  const le = (b: Uint8Array) => b.reduceRight((x, v) => (x << 8n) | BigInt(v), 0n);
  const toLe = (x: bigint) => Uint8Array.from({ length: 32 }, (_, i) => Number((x >> BigInt(8 * i)) & 255n));
  const T2 = ed25519.Point.fromBytes(hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"));

  function torsionedSignature(msg: Uint8Array) {
    const { scalar, pointBytes } = ed25519.utils.getExtendedPublicKey(new Uint8Array(32).fill(7));
    const r = 12345678901234567890n % L;
    const R = ed25519.Point.BASE.multiply(r).add(T2).toBytes();
    const k = le(sha512(Uint8Array.from([...R, ...pointBytes, ...msg]))) % L;
    const S = (r + k * scalar) % L;
    return { sig: Uint8Array.from([...R, ...toLe(S)]), pk: pointBytes };
  }

  for (const n of [100, 20_000]) {
    it(`is rejected at ${n} B (noble's cofactored check alone would accept it)`, () => {
      const msg = new Uint8Array(n).fill(65);
      const { sig, pk } = torsionedSignature(msg);
      expect(ed25519.verify(sig, msg, pk, { zip215: false })).toBe(true);
      expect(ed25519Verify(sig, msg, pk)).toBe(false);
    });
  }

  it("honest signatures still verify", () => {
    const sk = new Uint8Array(32).fill(9);
    const msg = new Uint8Array(500).fill(1);
    expect(ed25519Verify(ed25519Sign(msg, sk), msg, ed25519PublicKey(sk))).toBe(true);
  });
});

// The positive memo (crypto.ts "Memoised checks"): a remembered success never lets anything else through.
describe("verification memo", () => {
  const sk = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  const pk = ed25519PublicKey(sk);
  const msg = new TextEncoder().encode("memo");
  const sig = ed25519Sign(msg, sk);

  it("answers a repeat verification the same, and a changed byte anywhere still fails", () => {
    clearVerifyMemo();
    expect(ed25519Verify(sig, msg, pk)).toBe(true);
    expect(ed25519Verify(sig, msg, pk)).toBe(true);
    const badMsg = new TextEncoder().encode("memO");
    expect(ed25519Verify(sig, badMsg, pk)).toBe(false);
    const badSig = sig.slice();
    badSig[63] ^= 1;
    expect(ed25519Verify(badSig, msg, pk)).toBe(false);
    const otherPk = ed25519PublicKey(hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"));
    expect(ed25519Verify(sig, msg, otherPk)).toBe(false);
    // The fields are fixed-length, so moving bytes between them can't collide with the remembered key.
    expect(ed25519Verify(sig.subarray(0, 63), msg, pk)).toBe(false);
  });

  it("never remembers a failure, and a weak key fails after a strong one passed", () => {
    clearVerifyMemo();
    const badSig = sig.slice();
    badSig[0] ^= 1;
    expect(ed25519Verify(badSig, msg, pk)).toBe(false);
    expect(ed25519Verify(badSig, msg, pk)).toBe(false);
    assertStrongEd25519PublicKey(pk);
    assertStrongEd25519PublicKey(pk);
    const identity = new Uint8Array(32);
    identity[0] = 1; // the identity point: small order
    expect(() => assertStrongEd25519PublicKey(identity)).toThrow(P2PError);
    expect(() => assertStrongEd25519PublicKey(identity)).toThrow(P2PError);
    const xpk = x25519PublicKey(sk);
    assertStrongX25519PublicKey(xpk);
    assertStrongX25519PublicKey(xpk);
    expect(() => assertStrongX25519PublicKey(new Uint8Array(32))).toThrow(P2PError);
    expect(() => assertStrongX25519PublicKey(new Uint8Array(32))).toThrow(P2PError);
  });
});
