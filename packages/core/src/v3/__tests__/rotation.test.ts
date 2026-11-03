// Copyright 2026 Ix Infrastructure Inc.
//
// §2.8 identity rotation in the core (P3 readings): the `rotation` field on
// the old identity's final version (self-certifying, no devices, terminal),
// what it does to the old identity's devices (rule 6, the own-sync freshness
// exemption, the 60-day fail-closed rule), and the `contact` fast path
// `{rotation, invite}` and the `circle` bundle's `rotation`.

import { describe, expect, it } from "vitest";
import { createRotation, generateIdentityKey, rotationConflicts, verifyRotation, type RotationStatement } from "../identity.js";
import { createIdentityDoc, IdentityChain, mergeFields, peekIdentityDoc, verifyIdentityDocLink, verifyIdentityDocSignature } from "../identitydoc.js";
import { createInviteV3 } from "../friends.js";
import { parsePlaintextV3 } from "../envelope.js";
import { verifyIncomingV3, type IncomingResultV3 } from "../incoming.js";
import { addIdentityVersion, getIdentityView, jumpIdentity } from "../state.js";
import type { TrustStoreV3 } from "../store.js";
import { MAX_JWS_BYTES } from "../../jws.js";
import { DAYS, makeUser, NOW, NOW_MS, RELAY, seal, storeKnowing, TestUser } from "./fixtures.js";

/** Publishes `u`'s final version: no devices, carrying `rotation`. */
function finalVersion(u: TestUser, rotation: RotationStatement, opts: { iat?: number; ttlSec?: number; devices?: string[] } = {}) {
  const prev = u.doc;
  const jws = createIdentityDoc(u.ik, {
    ver: prev.ver + 1,
    prev: prev.hash,
    name: u.name,
    relays: u.relays,
    devices: opts.devices ?? [],
    keyholders: [],
    by: u.dev.did,
    rotation,
    iat: opts.iat ?? NOW - 60,
    ttlSec: opts.ttlSec,
  });
  const doc = verifyIdentityDocSignature(jws);
  u.docs.push(doc);
  return doc;
}

function rotated(name: string) {
  const old = makeUser(name);
  const next = new TestUser(`${name}2`, generateIdentityKey());
  next.addDevice();
  next.publish();
  const statement = createRotation(old.ik, next.ik, { iat: NOW - 120 });
  return { old, next, statement };
}

async function receive(store: TrustStoreV3, to: TestUser, env: string, nowMs = NOW_MS): Promise<IncomingResultV3> {
  return verifyIncomingV3(env, { self: { userId: to.userId, did: to.dev.did, agreementSecretKey: to.dev.agreementSecretKey, cert: to.dev.cert }, store, nowMs });
}

describe("P3 the rotation field on the final identity version (§2.8)", () => {
  it("is accepted on a version with no devices, is self-certifying, and shows in the view", async () => {
    const { old, next, statement } = rotated("ann");
    const fin = finalVersion(old, statement);
    expect(fin.rotation).toEqual(statement);
    expect(fin.devices).toEqual([]);
    verifyIdentityDocLink(old.docs[0].jws, fin.jws, { now: NOW });
    const store = await storeKnowing(old);
    const v = (await getIdentityView(store, old.userId))!;
    expect(v.devices).toEqual([]);
    expect(v.rotations).toEqual([statement]);
    expect(verifyRotation(v.rotations[0], { now: NOW }).to).toBe(next.userId);
    // A relay-sized document: no certificates, far under the §1 16 KiB cap.
    expect(fin.jws.length).toBeLessThan(MAX_JWS_BYTES / 4);
  });

  it("refuses a rotation on a version that still lists devices or key holders, or on a merge", () => {
    const { old, statement } = rotated("bea");
    expect(() => finalVersion(old, statement, { devices: [old.dev.did] })).toThrow(/no devices/);
    const a = old.doc;
    expect(() =>
      createIdentityDoc(old.ik, { ver: a.ver + 1, prev: a.hash, name: "bea", relays: [RELAY], devices: [], keyholders: [], by: old.dev.did, merge: a.hash.replace(/^./, "A"), rotation: statement }),
    ).toThrow(/merge|not a merge/);
  });

  it("refuses a rotation that is another identity's, has a forged half, or is newer than the document", () => {
    const { old, next, statement } = rotated("cy");
    const other = rotated("dee");
    // The document's own rotation must be from it.
    expect(() => finalVersion(old, other.statement)).toThrow(/rotation-invalid/);
    // Halves of two different statements.
    const second = createRotation(old.ik, generateIdentityKey(), { iat: NOW - 100 });
    expect(() => finalVersion(old, { old: statement.old, new: second.new })).toThrow(/rotation-invalid/);
    // Signed after the document (beyond skew).
    const late = createRotation(old.ik, next.ik, { iat: NOW + 3600 });
    expect(() => finalVersion(old, late, { iat: NOW - 60 })).toThrow(/rotation-invalid/);
  });

  it("is terminal: no version may follow it, merge it or jump over it, at clients and through the relay seam", async () => {
    const { old, statement } = rotated("eve");
    const v1 = old.doc;
    const fin = finalVersion(old, statement);
    // A thief with the old ik extends the final version with its own device.
    const thief = old.addDevice({ keyholder: true });
    const child = createIdentityDoc(old.ik, { ver: fin.ver + 1, prev: fin.hash, name: "eve", relays: [RELAY], devices: [thief.did], keyholders: [thief.did], by: thief.did, certs: [thief.cert], iat: NOW - 30 });
    expect(() => verifyIdentityDocLink(fin.jws, child, { now: NOW })).toThrow(/identity-rotated/);
    const store = await storeKnowing();
    await addIdentityVersion(store, v1.jws, { now: NOW });
    await addIdentityVersion(store, fin.jws, { now: NOW });
    await expect(addIdentityVersion(store, child, { now: NOW })).rejects.toThrow(/identity-rotated/);
    // A sibling of the final version (an honest-looking fork) leaves the allowlist empty.
    const sibling = createIdentityDoc(old.ik, { ver: fin.ver, prev: v1.hash, name: "eve", relays: [RELAY], devices: [thief.did], keyholders: [thief.did], by: thief.did, certs: [thief.cert], iat: NOW - 30 });
    expect((await addIdentityVersion(store, sibling, { now: NOW })).status).toBe("accepted");
    const v = (await getIdentityView(store, old.userId))!;
    expect(v.forked).toBe(true);
    expect(v.devices).toEqual([]);
    expect(v.rotations).toEqual([statement]);
    // A merge of the fork names the rotation version as a parent: refused.
    const sib = verifyIdentityDocSignature(sibling);
    const f = mergeFields(fin, sib);
    const merge = createIdentityDoc(old.ik, { ...f, by: f.keyholders[0] ?? thief.did, iat: NOW - 20 });
    await expect(addIdentityVersion(store, merge, { now: NOW })).rejects.toThrow(/identity-rotated/);
    // A gap jump to a later version is refused too: a rotated identity never comes back.
    const far = createIdentityDoc(old.ik, { ver: fin.ver + 5, prev: fin.hash.replace(/^./, "B"), name: "eve", relays: [RELAY], devices: [thief.did], keyholders: [thief.did], by: thief.did, certs: [thief.cert], iat: NOW - 10 });
    await expect(jumpIdentity(store, far, { now: NOW })).rejects.toThrow(/identity-rotated/);
    // Unanchored history (only the final version held) is not replaced by a higher version either.
    const chain = new IdentityChain(old.userId);
    chain.add(fin.jws, { now: NOW });
    expect(() => chain.add(far, { now: NOW })).toThrow(/identity-rotated/);
  });

  it("two different rotations from the same old id (a forked final version) are a conflict", async () => {
    const { old, statement } = rotated("fay");
    const v1 = old.doc;
    finalVersion(old, statement);
    const rival = createRotation(old.ik, generateIdentityKey(), { iat: NOW - 90 });
    const sibling = createIdentityDoc(old.ik, { ver: 2, prev: v1.hash, name: "fay", relays: [RELAY], devices: [], keyholders: [], by: old.dev.did, rotation: rival, iat: NOW - 50 });
    const store = await storeKnowing(old);
    await addIdentityVersion(store, sibling, { now: NOW });
    const v = (await getIdentityView(store, old.userId))!;
    expect(v.rotations).toHaveLength(2);
    const conflicts = rotationConflicts(v.rotations.map((r) => verifyRotation(r, { now: NOW })));
    expect(conflicts.get(old.userId)).toHaveLength(2);
  });
});

describe("the old identity after its final version", () => {
  it("its devices are refused by rule 6, own sync included; messages are refused whatever their freshness", async () => {
    const { old, statement } = rotated("gus");
    const second = old.addDevice({ keyholder: false });
    old.publish();
    const friend = makeUser("hal");
    const before = await storeKnowing(old, friend);
    // Before: the old identity's message is opened (and fails only authorisation).
    const pre = await receive(before, friend, seal(old, friend, "contact", { text: createInviteV3(old.signer(), { aud: friend.userId, iat: NOW - 10 }) }));
    expect(pre.ok).toBe(true);
    finalVersion(old, statement);
    const store = await storeKnowing(old, friend);
    const r = await receive(store, friend, seal(old, friend, "contact", { text: createInviteV3(old.signer(), { aud: friend.userId, iat: NOW - 10 }) }));
    expect(r).toMatchObject({ ok: false, reason: "device-not-listed" });
    // The user's own other device: a sync from the old identity is refused too (the
    // freshness exemption for own sync never lifts rule 6).
    const own = await storeKnowing(old);
    const sync = seal(old, old, "sync", { body: {} }, { toDev: second });
    const s = await verifyIncomingV3(sync, { self: { userId: old.userId, did: second.did, agreementSecretKey: second.agreementSecretKey, cert: second.cert }, store: own, nowMs: NOW_MS });
    expect(s).toMatchObject({ ok: false, reason: "device-not-listed" });
  });

  it("past exp the final version still empties the allowlist, and past 60 days it fails closed; the rotation stays visible", async () => {
    const { old, statement } = rotated("ida");
    const friend = makeUser("jon");
    finalVersion(old, statement, { iat: NOW - 120, ttlSec: DAYS(1) });
    const store = await storeKnowing(old, friend);
    const expired = await receive(store, friend, seal(old, friend, "msg", { text: "hi" }, { tsMs: NOW_MS + DAYS(2) * 1000 }), NOW_MS + DAYS(2) * 1000);
    expect(expired).toMatchObject({ ok: false, reason: "device-not-listed" });
    const late = NOW_MS + DAYS(70) * 1000;
    const closed = await receive(store, friend, seal(old, friend, "msg", { text: "hi" }, { tsMs: late }), late);
    expect(closed).toMatchObject({ ok: false, reason: "identity-fail-closed" });
    expect((await getIdentityView(store, old.userId))!.rotations).toEqual([statement]);
  });
});

describe("P3 contact {rotation, invite} and circle bundles with rotation", () => {
  it("parses only the two fields, each well-formed", () => {
    const { statement } = rotated("kim");
    const enc = (o: object) => new TextEncoder().encode(JSON.stringify(o));
    expect(parsePlaintextV3("contact", enc({ rotation: statement, invite: "a.b.c" }))).toEqual({ kind: "contact", rotation: statement, invite: "a.b.c" });
    // Two readings of one contact (a rotation and a text) are refused; an unknown field is ignored.
    expect(() => parsePlaintextV3("contact", enc({ rotation: statement, invite: "a.b.c", text: "x" }))).toThrow(/exactly one/);
    expect(parsePlaintextV3("contact", enc({ rotation: statement, invite: "a.b.c", extra: "x" }))).toEqual({ kind: "contact", rotation: statement, invite: "a.b.c" });
    expect(() => parsePlaintextV3("contact", enc({ rotation: { old: statement.old }, invite: "a.b.c" }))).toThrow(/malformed/);
    expect(parsePlaintextV3("circle", enc({ circles: [], joins: ["j.k.l"], ops: [], rotation: statement }))).toEqual({ kind: "circle", circles: [], joins: ["j.k.l"], ops: [], rotation: statement });
  });

  it("the new identity's bound invite with the statement arrives as a held rotation object", async () => {
    const { old, next, statement } = rotated("lea");
    const friend = makeUser("max");
    const store = await storeKnowing(old, friend);
    const invite = createInviteV3(next.signer(), { aud: friend.userId, iat: NOW - 10, doc: next.doc.jws, ik: next.doc.ik, relays: [RELAY] });
    const r = await receive(store, friend, seal(next, friend, "contact", { rotation: statement, invite }));
    expect(r.ok).toBe(true);
    if (!r.ok || r.contact?.type !== "rotation") throw new Error("expected a rotation contact");
    expect(r.contact.rotation.from).toBe(old.userId);
    expect(r.contact.rotation.to).toBe(next.userId);
    expect(r.contact.invite.provisional).toBe(true);
    // The new identity's document was not adopted (provisional cache only).
    expect(await getIdentityView(store, next.userId)).toBeUndefined();
    expect(peekIdentityDoc(next.doc.jws).iss).toBe(next.userId);
  });

  it("refuses a shareable invite, a statement naming someone else, and a forged half", async () => {
    const { old, next, statement } = rotated("ned");
    const friend = makeUser("ola");
    const store = await storeKnowing(old, friend);
    const bound = createInviteV3(next.signer(), { aud: friend.userId, iat: NOW - 10, doc: next.doc.jws });
    const star = createInviteV3(next.signer(), { aud: "*", iat: NOW - 10, doc: next.doc.jws });
    expect(await receive(store, friend, seal(next, friend, "contact", { rotation: statement, invite: star }))).toMatchObject({ ok: false, reason: "audience-mismatch" });
    const elsewhere = createRotation(old.ik, generateIdentityKey(), { iat: NOW - 10 });
    expect(await receive(store, friend, seal(next, friend, "contact", { rotation: elsewhere, invite: bound }))).toMatchObject({ ok: false, reason: "rotation-invalid" });
    const forged = createRotation(generateIdentityKey(), next.ik, { iat: NOW - 10 });
    expect(await receive(store, friend, seal(next, friend, "contact", { rotation: { old: forged.old, new: statement.new }, invite: bound }))).toMatchObject({ ok: false, reason: "rotation-invalid" });
  });
});
