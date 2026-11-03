// Copyright 2026 Ix Infrastructure Inc.
//
// The pure base64url and base32 codecs against Node's Buffer and RFC 4648.

import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { b32Decode, b32Encode, b64uDecode, b64uEncode } from "../encoding.js";

describe("b64u", () => {
  it("matches Buffer base64url for every length and round-trips", () => {
    for (let n = 0; n < 70; n++) {
      for (let k = 0; k < 10; k++) {
        const b = new Uint8Array(randomBytes(n));
        const e = b64uEncode(b);
        expect(e).toBe(Buffer.from(b).toString("base64url"));
        expect(b64uDecode(e)).toEqual(b);
      }
    }
  });

  it("rejects non-canonical trailing bits, padding and bad lengths", () => {
    expect(() => b64uDecode("AB")).toThrow(/non-canonical/);
    expect(() => b64uDecode("AA==")).toThrow(/invalid/);
    expect(() => b64uDecode("AAAAA")).toThrow(/invalid/);
    expect(() => b64uDecode("AA", 2)).toThrow(/expected 2 bytes/);
  });
});

describe("b32", () => {
  it("matches the RFC 4648 test vectors, lowercased and unpadded", () => {
    const vectors: [string, string][] = [
      ["", ""],
      ["f", "my"],
      ["fo", "mzxq"],
      ["foo", "mzxw6"],
      ["foob", "mzxw6yq"],
      ["fooba", "mzxw6ytb"],
      ["foobar", "mzxw6ytboi"],
    ];
    for (const [plain, enc] of vectors) {
      expect(b32Encode(new TextEncoder().encode(plain))).toBe(enc);
      expect(new TextDecoder().decode(b32Decode(enc))).toBe(plain);
    }
  });

  it("round-trips every length", () => {
    for (let n = 0; n < 70; n++) {
      const b = new Uint8Array(randomBytes(n));
      expect(b32Decode(b32Encode(b))).toEqual(b);
    }
  });

  it("rejects uppercase, padding, impossible lengths and non-canonical bits", () => {
    expect(() => b32Decode("MZXW6")).toThrow(/invalid/);
    expect(() => b32Decode("my======")).toThrow(/invalid/);
    expect(() => b32Decode("m")).toThrow(/invalid/);
    expect(() => b32Decode("mz")).toThrow(/non-canonical/);
  });
});
