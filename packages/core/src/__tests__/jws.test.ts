// Copyright 2026 Ix Infrastructure Inc.
import { describe, expect, it } from "vitest";
import { decodeJws, signJws, verifyJws } from "../jws.js";
import { ed25519PublicKey, ed25519Sign, randomBytes } from "../crypto.js";
import { b64uEncode, utf8 } from "../encoding.js";

const sk = randomBytes(32);
const pk = ed25519PublicKey(sk);

describe("JWS compact EdDSA", () => {
  it("signs and verifies", () => {
    const jws = signJws("p2p-test+jws", "k1", { a: 1 }, sk);
    const d = verifyJws(jws, { typ: "p2p-test+jws", kid: "k1", publicKey: pk });
    expect(d.header).toEqual({ alg: "EdDSA", typ: "p2p-test+jws", kid: "k1" });
    expect(d.payload).toEqual({ a: 1 });
  });

  it("verifies the exact bytes, not a re-serialization", () => {
    // Non-canonical JSON (whitespace, key order) that a re-serializing
    // verifier would mangle.
    const h = b64uEncode(utf8('{ "typ":"p2p-test+jws","kid":"k1",  "alg":"EdDSA" }'));
    const p = b64uEncode(utf8('{"b":2,  "a":1}'));
    const sig = b64uEncode(ed25519Sign(utf8(`${h}.${p}`), sk));
    const d = verifyJws(`${h}.${p}.${sig}`, { typ: "p2p-test+jws", kid: "k1", publicKey: pk });
    expect(d.payload).toEqual({ a: 1, b: 2 });
  });

  it("rejects alg, typ, kid and signature problems", () => {
    const jws = signJws("p2p-test+jws", "k1", { a: 1 }, sk);
    expect(() => verifyJws(jws, { typ: "p2p-other+jws", publicKey: pk })).toThrow(/typ-mismatch/);
    expect(() => verifyJws(jws, { typ: "p2p-test+jws", kid: "k2", publicKey: pk })).toThrow(/kid-mismatch/);
    expect(() => verifyJws(jws, { typ: "p2p-test+jws", publicKey: ed25519PublicKey(randomBytes(32)) })).toThrow(
      /bad-signature/,
    );
    const [, p, s] = jws.split(".");
    const none = `${b64uEncode(utf8('{"alg":"none","typ":"p2p-test+jws","kid":"k1"}'))}.${p}.${s}`;
    expect(() => decodeJws(none)).toThrow(/bad-alg/);
    const tampered = `${jws.split(".")[0]}.${b64uEncode(utf8('{"a":2}'))}.${s}`;
    expect(() => verifyJws(tampered, { typ: "p2p-test+jws", publicKey: pk })).toThrow(/bad-signature/);
    expect(() => decodeJws("a.b")).toThrow(/malformed/);
  });
});
