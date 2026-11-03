// Copyright 2026 Ix Infrastructure Inc.
//
// Identity keys and addresses (docs/protocol.md §2.1), the BIP-39 backup
// (§2.7) and identity rotation statements (§2.8).
//
// Every user has one Ed25519 identity key `ik`; the userId is
// `"p2p:" + b32(H(ik_pub))`, so it is self-certifying. Display addresses are
// `<name>@<fp>`, with fp the first 16 b32 characters of the fingerprint in
// groups of four. Names are self-chosen and not unique: decisions always
// compare full userIds.

import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39";
import { wordlist as english } from "@scure/bip39/wordlists/english.js";
import { b64uDecode, b64uEncode } from "../encoding.js";
import { assertStrongEd25519PublicKey, ed25519PublicKey, randomBytes } from "../crypto.js";
import { signJws, verifyJws } from "../jws.js";
import { fail } from "../errors.js";
import {
  bytesField,
  checkIssued,
  decodeTyped,
  IK_KID,
  int,
  isUserId,
  checkFields,
  nowSec,
  TYP3,
  userIdField,
  userIdFromIk,
  type TimeOptions,
} from "./base.js";

export interface IdentityKey {
  userId: string;
  /** Ed25519 seed (32 bytes): what the backup phrase encodes. */
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

/** §2.1: a fresh identity key, generated on the user's first device. */
export function generateIdentityKey(): IdentityKey {
  return identityKeyFromSeed(randomBytes(32));
}

export function identityKeyFromSeed(seed: Uint8Array): IdentityKey {
  if (seed.length !== 32) fail("malformed", "identity seed must be 32 bytes");
  const publicKey = ed25519PublicKey(seed);
  assertStrongEd25519PublicKey(publicKey);
  return { userId: userIdFromIk(publicKey), secretKey: seed.slice(), publicKey };
}

/** The b32 fingerprint of a userId (everything after `p2p:`). */
export function fingerprintOf(userId: string): string {
  if (!isUserId(userId)) fail("malformed", `${userId} is not a v3 userId`);
  return userId.slice(4);
}

/** §2.1: the first 16 b32 characters of the fingerprint (80 bits), grouped by four: `k7f2-qx9a-3m4n-5p6q`. */
export function displayFingerprint(userId: string): string {
  const fp = fingerprintOf(userId).slice(0, 16);
  return `${fp.slice(0, 4)}-${fp.slice(4, 8)}-${fp.slice(8, 12)}-${fp.slice(12, 16)}`;
}

const NAME_RE = /^[a-z0-9._-]{1,32}$/;

/** §2.1: `name` matches `[a-z0-9._-]{1,32}`. It is self-chosen and not unique. */
export function isValidName(name: unknown): name is string {
  return typeof name === "string" && NAME_RE.test(name);
}

export function assertValidName(name: unknown): asserts name is string {
  if (!isValidName(name)) fail("malformed", "name must match [a-z0-9._-]{1,32}");
}

/**
 * §2.1 display address `<name>@<fp>`. With a local petname, the petname is
 * shown in preference to the self-chosen name, still with the fingerprint:
 * clients MUST show `fp` wherever they show a name.
 */
export function displayAddress(userId: string, name: string, petname?: string): string {
  const shown = petname !== undefined && petname.trim() !== "" ? petname.trim() : isValidName(name) ? name : "?";
  return `${shown}@${displayFingerprint(userId)}`;
}

// ---------------------------------------------------------------------------
// §2.7 Backup: a 24-word BIP-39 mnemonic of the 32-byte ik seed.

/** Encodes the 32-byte identity seed as a 24-word BIP-39 (English) mnemonic. */
export function backupPhraseFromSeed(seed: Uint8Array): string {
  if (seed.length !== 32) fail("malformed", "identity seed must be 32 bytes");
  return entropyToMnemonic(seed, english);
}

/**
 * Decodes a 24-word backup phrase back to the seed. Whitespace and case are
 * normalised; the BIP-39 checksum must match.
 */
export function seedFromBackupPhrase(phrase: string): Uint8Array {
  const words = phrase.trim().toLowerCase().split(/\s+/u);
  if (words.length !== 24) fail("malformed", `a backup phrase has 24 words, got ${words.length}`);
  const normal = words.join(" ");
  if (!validateMnemonic(normal, english)) fail("malformed", "backup phrase checksum or word list mismatch");
  const seed = mnemonicToEntropy(normal, english);
  if (seed.length !== 32) fail("malformed", "backup phrase does not encode 32 bytes");
  return seed;
}

export function identityKeyFromBackupPhrase(phrase: string): IdentityKey {
  return identityKeyFromSeed(seedFromBackupPhrase(phrase));
}

// ---------------------------------------------------------------------------
// §2.8 Identity rotation: `{old, new}`, each a `p2p-rotate+jws` over
// `{from, to, iat}`, one signed by the old ik and one by the new ik. Each
// half also carries its signer's `ik` so the statement is self-certifying.

export interface RotationHalfPayload {
  from: string;
  to: string;
  ik: string;
  iat: number;
}

export interface RotationStatement {
  old: string;
  new: string;
}

export interface VerifiedRotation {
  from: string;
  to: string;
  iat: number;
  oldIk: Uint8Array;
  newIk: Uint8Array;
  statement: RotationStatement;
}

export function createRotation(oldKey: IdentityKey, newKey: IdentityKey, opts: { iat?: number } = {}): RotationStatement {
  const iat = opts.iat ?? nowSec();
  if (oldKey.userId === newKey.userId) fail("malformed", "a rotation needs a different identity key");
  const base = { from: oldKey.userId, to: newKey.userId, iat };
  return {
    old: signJws(TYP3.rotate, IK_KID, { ...base, ik: b64uEncode(oldKey.publicKey) }, oldKey.secretKey),
    new: signJws(TYP3.rotate, IK_KID, { ...base, ik: b64uEncode(newKey.publicKey) }, newKey.secretKey),
  };
}

function rotationHalf(jws: string, expectSigner: "from" | "to"): RotationHalfPayload & { ikBytes: Uint8Array } {
  const d = decodeTyped(jws, TYP3.rotate);
  const p = d.payload;
  checkFields(p, ["from", "to", "ik", "iat"], "rotation");
  const half: RotationHalfPayload = {
    from: userIdField(p, "from"),
    to: userIdField(p, "to"),
    ik: bytesField(p, "ik", 32),
    iat: int(p, "iat"),
  };
  const ikBytes = b64uDecode(half.ik, 32);
  assertStrongEd25519PublicKey(ikBytes);
  if (userIdFromIk(ikBytes) !== half[expectSigner]) fail("issuer-mismatch", `rotation half is not signed by ${expectSigner}`);
  verifyJws(jws, { typ: TYP3.rotate, kid: IK_KID, publicKey: ikBytes });
  return { ...half, ikBytes };
}

/** Structural check of a `{old, new}` rotation statement (no signature work). */
export function parseRotationStatement(v: unknown): RotationStatement {
  if (typeof v !== "object" || v === null || Array.isArray(v)) fail("malformed", "rotation must be {old, new}");
  const o = v as Record<string, unknown>;
  checkFields(o, ["old", "new"], "rotation");
  if (typeof o.old !== "string" || o.old === "" || typeof o.new !== "string" || o.new === "") fail("malformed", "rotation must be {old, new}");
  return { old: o.old, new: o.new };
}

/**
 * Both halves, without a time check: the old half under the old ik
 * (H(ik) == from), the new half under the new ik (H(ik) == to), and both
 * over the same `{from, to, iat}`. Used for a rotation carried inside an
 * identity document (P3), which is judged by the document's own time.
 */
export function verifyRotationSignatures(statement: RotationStatement): VerifiedRotation {
  const st = parseRotationStatement(statement);
  const o = rotationHalf(st.old, "from");
  const n = rotationHalf(st.new, "to");
  if (o.from !== n.from || o.to !== n.to || o.iat !== n.iat) fail("rotation-invalid", "the halves sign different statements");
  if (o.from === o.to) fail("rotation-invalid", "rotation to the same identity");
  return { from: o.from, to: o.to, iat: o.iat, oldIk: o.ikBytes, newIk: n.ikBytes, statement: st };
}

/**
 * Verifies both halves (verifyRotationSignatures) and that the statement
 * isn't issued in the future. Receivers still carry a friendship over only
 * after asking their user (§2.8).
 */
export function verifyRotation(statement: RotationStatement, opts: TimeOptions = {}): VerifiedRotation {
  const r = verifyRotationSignatures(statement);
  checkIssued(r.iat, opts.now ?? nowSec(), opts.skewSec);
  return r;
}

/** A stable key for one statement (its two halves), for de-duplication. */
export function rotationKey(statement: RotationStatement): string {
  return `${statement.old}~${statement.new}`;
}

/**
 * §2.8: more than one rotation from the same old id is a conflict, shown to
 * the user, and none of them is applied automatically. Returns, per old
 * userId, the distinct targets (more than one means conflict).
 */
export function rotationConflicts(rotations: readonly VerifiedRotation[]): Map<string, string[]> {
  const by = new Map<string, Set<string>>();
  for (const r of rotations) {
    if (!by.has(r.from)) by.set(r.from, new Set());
    by.get(r.from)!.add(r.to);
  }
  const out = new Map<string, string[]>();
  for (const [from, tos] of by) if (tos.size > 1) out.set(from, [...tos].sort());
  return out;
}

/** True when `rotation` may be offered for automatic carry-over prompts: it has no conflicting sibling. */
export function rotationIsUnambiguous(rotation: VerifiedRotation, all: readonly VerifiedRotation[]): boolean {
  return !rotationConflicts([rotation, ...all]).has(rotation.from);
}
