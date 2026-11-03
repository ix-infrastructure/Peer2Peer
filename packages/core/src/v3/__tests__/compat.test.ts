// Copyright 2026 Ix Infrastructure Inc.
//
// Forward compatibility (docs/compatibility.md, protocol.md "Forward compatibility"):
//  - signed objects: a field this version doesn't know is ignored (never copied into what the
//    verifier returns), unless the object lists it in `crit`, which refuses the object;
//  - the signature and the jwsHash still cover the whole object as received;
//  - plaintexts: unknown fields are ignored too, known ones keep their checks;
//  - an envelope of a kind this version doesn't know is verified (signature, sender, replay
//    window) and returned as rule "unknown-kind", never parsed;
//  - leniency relaxes nothing else: authorisation, signature, replay and size checks stand.

import { describe, expect, it } from "vitest";
import { decodeJws, signJws } from "../../jws.js";
import { utf8 } from "../../encoding.js";
import { checkFields, jwsHash, TYP3 } from "../base.js";
import { verifyCap } from "../caps.js";
import { CircleChain, createCircle, createMembershipStatement, parseCircleVersion, verifyCircleGenesis, verifyMembershipStatement } from "../circles.js";
import { verifyDeviceCertV3 } from "../device.js";
import { decodeEnvelopeV3, isFutureKind, parsePlaintextV3 } from "../envelope.js";
import { createRotation, verifyRotationSignatures } from "../identity.js";
import { verifyIdentityDocSignature } from "../identitydoc.js";
import { verifyIncomingV3, type IncomingResultV3 } from "../incoming.js";
import { createRosterV3 } from "../roster.js";
import { recordFriendshipV3 } from "../state.js";
import { createAcceptV3, createInviteV3, verifyFriendshipV3 } from "../friends.js";
import type { TrustStoreV3 } from "../store.js";
import { ctxFor, makeUser, NOW, NOW_MS, seal, storeKnowing, type TestUser } from "./fixtures.js";

/** The same object re-signed by the same key with `extra` fields added. */
function resign(jws: string, extra: Record<string, unknown>, key: Uint8Array): string {
  const d = decodeJws(jws);
  return signJws(d.header.typ as string, d.header.kid as string, { ...d.payload, ...extra }, key);
}

describe("the crit rule (checkFields)", () => {
  it("ignores unknown fields; refuses an unknown critical one; checks crit's own shape", () => {
    expect(() => checkFields({ a: 1, later: 2 }, ["a"], "x")).not.toThrow();
    expect(() => checkFields({ a: 1, later: 2, crit: ["later"] }, ["a"], "x")).toThrow(/unsupported-critical|critical/);
    // A known field may be critical: understood, so accepted.
    expect(() => checkFields({ a: 1, crit: ["a"] }, ["a"], "x")).not.toThrow();
    for (const crit of [[], "later", ["later", "later"], [1], ["crit"], ["missing"], Array.from({ length: 17 }, (_, i) => `f${i}`)]) {
      expect(() => checkFields({ a: 1, later: 2, crit }, ["a"], "x"), JSON.stringify(crit)).toThrow(/malformed/);
    }
  });
});

describe("signed security objects: unknown fields ignored, critical ones refused, signatures intact", () => {
  it("identity document", () => {
    const u = makeUser("ann");
    const later = resign(u.doc.jws, { later: { anything: 1 } }, u.ik.secretKey);
    const v = verifyIdentityDocSignature(later);
    expect(v).not.toHaveProperty("later");
    expect(v.devices).toEqual(u.doc.devices);
    // The hash is over the bytes as received: a version differing only in an unknown field is another version.
    expect(jwsHash(later)).not.toBe(u.doc.hash);
    expect(() => verifyIdentityDocSignature(resign(u.doc.jws, { later: 1, crit: ["later"] }, u.ik.secretKey))).toThrow(/critical/);
    // Signed by someone else: refused whatever its fields.
    expect(() => verifyIdentityDocSignature(resign(u.doc.jws, { later: 1 }, makeUser("eve").ik.secretKey))).toThrow();
  });

  it("identity document device info (dinfo): validated, for listed devices only", () => {
    const u = makeUser("ann");
    const ok = resign(u.doc.jws, { dinfo: { [u.dev.did]: { caps: ["receipts.v1", "proto.3.1"], client: "0.2.0" } } }, u.ik.secretKey);
    expect(verifyIdentityDocSignature(ok).dinfo).toEqual({ [u.dev.did]: { caps: ["receipts.v1", "proto.3.1"], client: "0.2.0" } });
    for (const bad of [{ d_notlisted: { caps: [] } }, { [u.dev.did]: { caps: ["Not A Cap"] } }, { [u.dev.did]: { caps: [], client: "x y" } }, { [u.dev.did]: { caps: Array.from({ length: 17 }, (_, i) => `c${i}.v1`) } }]) {
      expect(() => verifyIdentityDocSignature(resign(u.doc.jws, { dinfo: bad }, u.ik.secretKey)), JSON.stringify(bad)).toThrow(/dinfo/);
    }
  });

  it("device certificate", () => {
    const u = makeUser("ann");
    expect(verifyDeviceCertV3(resign(u.dev.cert, { later: 1 }, u.ik.secretKey), { now: NOW })).not.toHaveProperty("later");
    expect(() => verifyDeviceCertV3(resign(u.dev.cert, { later: 1, crit: ["later"] }, u.ik.secretKey), { now: NOW })).toThrow(/critical/);
  });

  it("cap: a restricting field an older relay or client can't enforce must be critical, and is then refused", () => {
    const u = makeUser("ann");
    const cap = u.friendCap(makeUser("ben").userId);
    expect(verifyCap(resign(cap, { later: 1 }, u.dev.signingSecretKey), { now: NOW })).not.toHaveProperty("later");
    expect(() => verifyCap(resign(cap, { maxBytes: 10, crit: ["maxBytes"] }, u.dev.signingSecretKey), { now: NOW })).toThrow(/critical/);
  });

  it("circle version", () => {
    const u = makeUser("ann");
    const g = createCircle(u.ik, { name: "team" });
    const later = resign(g, { later: 1 }, u.ik.secretKey);
    expect(parseCircleVersion(later)).not.toHaveProperty("later");
    expect(verifyCircleGenesis(later).members).toEqual([u.userId]);
    expect(() => parseCircleVersion(resign(g, { later: 1, crit: ["later"] }, u.ik.secretKey))).toThrow(/critical/);
  });

  it("join statement", async () => {
    const u = makeUser("ann");
    const store = await storeKnowing(u);
    const chain = CircleChain.bootstrap([createCircle(u.ik, { name: "team" })]);
    const j = createMembershipStatement(u.signer(), { cid: chain.cid, n: 0, op: "join", at: chain.head.hash, cap: u.joinCap(), iat: NOW - 10 });
    expect(await verifyMembershipStatement(resign(j, { later: 1 }, u.dev.signingSecretKey), ctxFor(store))).not.toHaveProperty("later");
    await expect(verifyMembershipStatement(resign(j, { later: 1, crit: ["later"] }, u.dev.signingSecretKey), ctxFor(store))).rejects.toThrow(/critical/);
  });

  it("rotation statement (both halves)", () => {
    const oldU = makeUser("old");
    const newU = makeUser("new");
    const st = createRotation(oldU.ik, newU.ik, { iat: NOW - 10 });
    const later = { ...st, old: resign(st.old, { later: 1 }, oldU.ik.secretKey) };
    expect(verifyRotationSignatures(later).to).toBe(newU.userId);
    expect(() => verifyRotationSignatures({ ...st, old: resign(st.old, { later: 1, crit: ["later"] }, oldU.ik.secretKey) })).toThrow(/critical/);
  });
});

describe("plaintexts: must-ignore, with every known check kept", () => {
  const parse = (kind: "msg" | "status" | "x:ix.note", o: unknown) => parsePlaintextV3(kind, utf8(JSON.stringify(o)));
  it("msg, status and extension plaintexts drop unknown fields; known fields keep their types", () => {
    expect(parse("msg", { text: "hi", later: { x: 1 } })).toEqual({ kind: "msg", text: "hi" });
    expect(() => parse("msg", { text: 5, later: 1 })).toThrow(/text/);
    expect(parse("status", { status: { state: "idle", label: "x", later: 1 }, later: 2 })).toEqual({ kind: "status", status: { state: "idle", label: "x" } });
    expect(() => parse("status", { status: { state: "sleeping", label: "x" }, later: 1 })).toThrow(/state/);
    expect(parse("x:ix.note", { ext: { v: 1, body: { a: 1 } }, fallback: "f", later: 1 })).toEqual({ kind: "x:ix.note", ext: { v: 1, body: { a: 1 } }, fallback: "f" });
    expect(() => parse("x:ix.note", { ext: { v: 1, body: {} }, fallback: "x".repeat(201), later: 1 })).toThrow(/fallback/);
  });
});

async function friends(store: TrustStoreV3, a: TestUser, b: TestUser) {
  const invite = createInviteV3(b.signer(), { aud: a.userId, iat: NOW - 1000 });
  await recordFriendshipV3(store, await verifyFriendshipV3({ invite, accept: createAcceptV3(a.signer(), invite, { iat: NOW - 900 }) }, ctxFor(store)));
}

describe("envelopes", () => {
  const receive = (store: TrustStoreV3, to: TestUser, env: string): Promise<IncomingResultV3> =>
    verifyIncomingV3(env, { self: { userId: to.userId, did: to.dev.did, agreementSecretKey: to.dev.agreementSecretKey, cert: to.dev.cert }, store, nowMs: NOW_MS });

  it("a future kind passes structure; anything not shaped like a kind is still malformed", () => {
    expect(isFutureKind("futurekind")).toBe(true);
    expect(isFutureKind("msg")).toBe(false);
    for (const k of ["Future", "x:bad", "a".repeat(33), "with space", ""]) expect(isFutureKind(k)).toBe(false);
    const a = makeUser("ann");
    const b = makeUser("ben");
    expect(decodeEnvelopeV3(seal(a, b, "futurekind" as never, { any: 1 })).payload.kind).toBe("futurekind");
    expect(() => seal(a, b, "Not-A-Kind" as never, {})).toThrow(/unknown kind/);
  });

  it("an unknown-kind envelope is verified and admitted to the replay window: its copy is a replay, its forgery refused", async () => {
    const a = makeUser("ann");
    const b = makeUser("ben");
    const store = await storeKnowing(a, b);
    await friends(store, a, b);
    const env = seal(a, b, "futurekind" as never, { whatever: true }, { sid: "s1", own: a.userId });
    const r = await receive(store, b, env);
    expect(r.ok && r.rule).toBe("unknown-kind");
    expect(r.ok && r.plaintext).toEqual({ kind: "unknown", envKind: "futurekind" });
    const again = await receive(store, b, env);
    expect(!again.ok && again.reason).toMatch(/replayed/);
    // Signed by a key that isn't the sender's device: refused like any envelope.
    const forged = signJws(TYP3.msg, a.dev.did, decodeJws(seal(a, b, "otherkind" as never, {})).payload, makeUser("eve").dev.signingSecretKey);
    expect((await receive(store, b, forged)).ok).toBe(false);
    // From someone with no identity document here: refused (no stranger gets an unknown kind through).
    const eve = makeUser("eve");
    expect((await receive(store, b, seal(eve, b, "futurekind" as never, {}))).ok).toBe(false);
  });

  it("an unknown outer field is ignored and dropped; a critical one refused; the signature still covers it", async () => {
    const a = makeUser("ann");
    const b = makeUser("ben");
    const env = seal(a, b, "msg", { text: "hi" });
    const d = decodeJws(env);
    const later = signJws(d.header.typ as string, d.header.kid as string, { ...d.payload, later: 1 }, a.dev.signingSecretKey);
    expect(decodeEnvelopeV3(later).payload).not.toHaveProperty("later");
    const crit = signJws(d.header.typ as string, d.header.kid as string, { ...d.payload, later: 1, crit: ["later"] }, a.dev.signingSecretKey);
    expect(() => decodeEnvelopeV3(crit)).toThrow(/critical/);
    // Authorisation is unchanged: a msg into a session the sender has no standing in is refused.
    const store = await storeKnowing(a, b);
    const roster = createRosterV3(b.signer(), { sid: "s9", ver: 1, vis: "private", parts: [], iat: NOW - 500 });
    const into = seal(a, b, "msg", { text: "hi", later: 1, roster }, { own: b.userId, sid: "s9" });
    const r = await receive(store, b, into);
    expect(r.ok).toBe(false);
  });
});
