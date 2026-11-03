// Copyright 2026 Ix Infrastructure Inc.
//
// §4.3 "Delivery receipts": `msg.rcpt` and the `receipt` kind are strict, `receipt` uses the
// reserved sid ~receipt with own == from, and carries an id and an outcome only.

import { describe, expect, it } from "vitest";
import { verifyIncomingV3 } from "../incoming.js";
import { parsePlaintextV3, RECEIPT_SID } from "../envelope.js";
import { utf8 } from "../../encoding.js";
import { makeUser, NOW_MS, seal, storeKnowing } from "./fixtures.js";

const parse = (kind: "msg" | "receipt", o: unknown) => parsePlaintextV3(kind, utf8(JSON.stringify(o)));

describe("§4.3 delivery receipts", () => {
  it("msg.rcpt: an optional receipt id, nothing else", () => {
    expect(parse("msg", { text: "hi", rcpt: "abcDEF12_-" })).toEqual({ kind: "msg", text: "hi", rcpt: "abcDEF12_-" });
    expect(parse("msg", { text: "hi" })).toEqual({ kind: "msg", text: "hi" });
    for (const rcpt of ["short", "x".repeat(33), "has space!", 42, { id: "abcdefgh" }]) expect(() => parse("msg", { text: "hi", rcpt })).toThrow(/rcpt/);
  });

  it("receipt: {receipt: {id, outcome}} with a known outcome, no other field (no text)", () => {
    for (const outcome of ["shown", "held", "declined", "expired", "ended"]) {
      expect(parse("receipt", { receipt: { id: "abcdefgh", outcome } })).toEqual({ kind: "receipt", receipt: { id: "abcdefgh", outcome } });
    }
    expect(() => parse("receipt", { receipt: { id: "abcdefgh", outcome: "read" } })).toThrow(/outcome/);
    // An unknown field is ignored, never copied (so a receipt still carries no text); refused when critical.
    expect(parse("receipt", { receipt: { id: "abcdefgh", outcome: "shown", text: "x" } })).toEqual({ kind: "receipt", receipt: { id: "abcdefgh", outcome: "shown" } });
    expect(parse("receipt", { receipt: { id: "abcdefgh", outcome: "shown" }, text: "x" })).toEqual({ kind: "receipt", receipt: { id: "abcdefgh", outcome: "shown" } });
    expect(() => parse("receipt", { receipt: { id: "abcdefgh", outcome: "shown" }, text: "x", crit: ["text"] })).toThrow(/critical/);
    expect(() => parse("receipt", { receipt: { id: "bad id", outcome: "shown" } })).toThrow(/receipt.id/);
    // Never receipted: a receipt can't ask for one.
    expect(parse("receipt", { receipt: { id: "abcdefgh", outcome: "shown" }, rcpt: "abcdefgh" })).not.toHaveProperty("rcpt");
  });

  it("receipt needs sid ~receipt and own == from; nothing else may use ~receipt", () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const ok = { receipt: { id: "abcdefgh", outcome: "shown" } };
    expect(() => seal(a, b, "receipt", ok, { sid: "s1" })).toThrow(/requires sid ~receipt/);
    expect(() => seal(a, b, "receipt", ok, { sid: RECEIPT_SID, own: b.userId })).toThrow(/own == from/);
    expect(() => seal(a, b, "msg", { text: "x" }, { sid: RECEIPT_SID })).toThrow(/reserved/);
  });

  it("an authentic receipt verifies with rule `receipt` (whether it was asked for is the client's check)", async () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const store = await storeKnowing(a, b);
    const env = seal(a, b, "receipt", { receipt: { id: "abcdefgh", outcome: "held" } }, { sid: RECEIPT_SID });
    const r = await verifyIncomingV3(env, { self: { userId: b.userId, did: b.dev.did, agreementSecretKey: b.dev.agreementSecretKey, cert: b.dev.cert }, store, nowMs: NOW_MS });
    expect(r.ok && r.rule).toBe("receipt");
    expect(r.ok && r.plaintext).toEqual({ kind: "receipt", receipt: { id: "abcdefgh", outcome: "held" } });
  });
});
