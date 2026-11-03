// Copyright 2026 Ix Infrastructure Inc.
//
// §2.1 identity keys and addresses, §2.7 backup, §2.8 rotation.

import { describe, expect, it } from "vitest";
import {
  assertValidName,
  backupPhraseFromSeed,
  createRotation,
  displayAddress,
  displayFingerprint,
  generateIdentityKey,
  identityKeyFromBackupPhrase,
  identityKeyFromSeed,
  isValidName,
  rotationConflicts,
  rotationIsUnambiguous,
  seedFromBackupPhrase,
  verifyRotation,
} from "../identity.js";
import { didFromSpk, isUserId, userIdFromIk } from "../base.js";
import { b32Encode, b64uDecode, b64uEncode } from "../../encoding.js";
import { sha256 } from "../../crypto.js";
import { decodeJws, signJws } from "../../jws.js";
import { MemoryTrustStoreV3 } from "../store.js";
import { NOW } from "./fixtures.js";

describe("§2.1 userId and addresses", () => {
  it("userId is p2p: + b32(H(ik)) and never contains |", () => {
    const k = generateIdentityKey();
    expect(k.userId).toBe(`p2p:${b32Encode(sha256(k.publicKey))}`);
    expect(isUserId(k.userId)).toBe(true);
    expect(k.userId).not.toContain("|");
    expect(k.userId).toHaveLength(4 + 52);
    expect(userIdFromIk(k.publicKey)).toBe(k.userId);
  });

  it("the display fingerprint is the first 16 b32 chars in groups of four", () => {
    const k = generateIdentityKey();
    const fp = displayFingerprint(k.userId);
    expect(fp).toMatch(/^[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}$/);
    expect(fp.replace(/-/g, "")).toBe(k.userId.slice(4, 20));
    expect(() => displayFingerprint("p2p:short")).toThrow(/malformed/);
  });

  it("names match [a-z0-9._-]{1,32}", () => {
    for (const ok of ["carol", "a", "a.b_c-d", "x".repeat(32), "0"]) expect(isValidName(ok)).toBe(true);
    for (const bad of ["", "Carol", "a b", "x".repeat(33), "ä", "a@b", "a|b"]) expect(isValidName(bad)).toBe(false);
    expect(() => assertValidName("NO")).toThrow(/malformed/);
  });

  it("addresses always carry the fingerprint; a petname is shown in preference to name", () => {
    const k = generateIdentityKey();
    const fp = displayFingerprint(k.userId);
    expect(displayAddress(k.userId, "carol")).toBe(`carol@${fp}`);
    expect(displayAddress(k.userId, "carol", "Carol (work)")).toBe(`Carol (work)@${fp}`);
    expect(displayAddress(k.userId, "BAD NAME")).toBe(`?@${fp}`);
  });

  it("petnames are kept in the store per userId", async () => {
    const s = new MemoryTrustStoreV3();
    const k = generateIdentityKey();
    await s.setPetname(k.userId, "  Mom ");
    expect(await s.getPetname(k.userId)).toBe("Mom");
    await s.setPetname(k.userId, "");
    expect(await s.getPetname(k.userId)).toBeUndefined();
    await expect(s.setPetname(k.userId, "x".repeat(65))).rejects.toThrow(/petname/);
  });

  it("device ids derive from spk", () => {
    const k = generateIdentityKey();
    expect(didFromSpk(k.publicKey)).toBe(`d_${b32Encode(sha256(k.publicKey)).slice(0, 26)}`);
  });
});

describe("§2.7 backup phrase", () => {
  it("round-trips the 32-byte seed through 24 BIP-39 words", () => {
    const k = generateIdentityKey();
    const phrase = backupPhraseFromSeed(k.secretKey);
    expect(phrase.split(" ")).toHaveLength(24);
    expect(seedFromBackupPhrase(phrase)).toEqual(k.secretKey);
    expect(identityKeyFromBackupPhrase(`  ${phrase.toUpperCase().replace(/ /g, "\n ")}  `).userId).toBe(k.userId);
  });

  it("matches the BIP-39 reference vector for all-zero entropy", () => {
    const phrase = backupPhraseFromSeed(new Uint8Array(32));
    expect(phrase).toBe(`${"abandon ".repeat(23)}art`);
  });

  it("rejects wrong length, unknown words and a bad checksum", () => {
    const phrase = backupPhraseFromSeed(new Uint8Array(32).fill(7)).split(" ");
    expect(() => seedFromBackupPhrase(phrase.slice(0, 12).join(" "))).toThrow(/24 words/);
    expect(() => seedFromBackupPhrase([...phrase.slice(0, 23), "notaword"].join(" "))).toThrow(/checksum|word/);
    const swapped = [...phrase];
    [swapped[0], swapped[1]] = [swapped[1], swapped[0]];
    if (swapped.join(" ") !== phrase.join(" ")) expect(() => seedFromBackupPhrase(swapped.join(" "))).toThrow(/checksum|word/);
    expect(() => backupPhraseFromSeed(new Uint8Array(16))).toThrow(/32 bytes/);
  });

  it("identityKeyFromSeed is deterministic", () => {
    const seed = new Uint8Array(32).fill(9);
    expect(identityKeyFromSeed(seed).userId).toBe(identityKeyFromSeed(seed).userId);
  });
});

describe("§2.8 rotation", () => {
  it("verifies both halves over the same {from, to, iat}", () => {
    const a = generateIdentityKey();
    const b = generateIdentityKey();
    const r = verifyRotation(createRotation(a, b, { iat: NOW }), { now: NOW });
    expect(r.from).toBe(a.userId);
    expect(r.to).toBe(b.userId);
  });

  it("rejects halves that sign different statements, or are signed by the wrong key", () => {
    const a = generateIdentityKey();
    const b = generateIdentityKey();
    const c = generateIdentityKey();
    const r1 = createRotation(a, b, { iat: NOW });
    const r2 = createRotation(a, c, { iat: NOW });
    expect(() => verifyRotation({ old: r1.old, new: r2.new }, { now: NOW })).toThrow(/rotation-invalid/);
    // The new half signed by the old key.
    const forged = signJws("p2p-rotate+jws", "ik", { from: a.userId, to: b.userId, ik: b64uEncode(b.publicKey), iat: NOW }, a.secretKey);
    expect(() => verifyRotation({ old: r1.old, new: forged }, { now: NOW })).toThrow(/bad-signature/);
    // A half claiming another ik.
    const claim = decodeJws(r1.new).payload;
    const wrongIk = signJws("p2p-rotate+jws", "ik", { ...claim, ik: b64uEncode(a.publicKey) }, a.secretKey);
    expect(() => verifyRotation({ old: r1.old, new: wrongIk }, { now: NOW })).toThrow(/issuer-mismatch/);
    expect(() => createRotation(a, a)).toThrow(/different/);
    expect(b64uDecode(claim.ik as string, 32)).toEqual(b.publicKey);
  });

  it("two rotations from the same old id are a conflict and neither applies automatically", () => {
    const a = generateIdentityKey();
    const r1 = verifyRotation(createRotation(a, generateIdentityKey(), { iat: NOW }), { now: NOW });
    const r2 = verifyRotation(createRotation(a, generateIdentityKey(), { iat: NOW }), { now: NOW });
    const conflicts = rotationConflicts([r1, r2]);
    expect(conflicts.get(a.userId)).toHaveLength(2);
    expect(rotationIsUnambiguous(r1, [r1, r2])).toBe(false);
    expect(rotationIsUnambiguous(r1, [r1])).toBe(true);
  });
});
