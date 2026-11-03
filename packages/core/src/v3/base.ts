// Copyright 2026 Ix Infrastructure Inc.
//
// Shared v3 building blocks (docs/protocol.md §1): the `typ` registry, size
// caps, lifetimes, self-certifying ids (§2.1, §2.3), `jwsHash`, and the
// payload field validators every v3 codec uses. Pure: no Node-only APIs.

import { b32Encode, b64uDecode, b64uEncode, utf8 } from "../encoding.js";
import { randomBytes, sha256 } from "../crypto.js";
import { decodeJws, type DecodedJws } from "../jws.js";
import { fail } from "../errors.js";

export { MAX_ENVELOPE_BYTES, MAX_JWS_BYTES } from "../jws.js";

/** Every v3 signed-object type (§1: a mandatory `typ`, checked before any key lookup). */
export const TYP3 = {
  device: "p2p-device+jws",
  identity: "p2p-identity+jws",
  proof: "p2p-proof+jws",
  rotate: "p2p-rotate+jws",
  invite: "p2p-invite+jws",
  accept: "p2p-accept+jws",
  unfriend: "p2p-unfriend+jws",
  circle: "p2p-circle+jws",
  circleAccept: "p2p-circle-accept+jws",
  join: "p2p-join+jws",
  circleOp: "p2p-circle-op+jws",
  roster: "p2p-roster+jws",
  cap: "p2p-cap+jws",
  msg: "p2p-msg+jws",
} as const;

/** The `kid` of objects signed by the identity key. */
export const IK_KID = "ik";

export const MINUTE = 60;
export const HOUR = 3600;
export const DAY = 86_400;

/** §2.3: a device certificate lives at most 90 days. */
export const DEVICE_CERT_MAX_TTL_SEC = 90 * DAY;
/** §2.5: an identity document version lives at most 30 days. */
export const IDENTITY_DOC_MAX_TTL_SEC = 30 * DAY;
/** §2.5: receivers fail closed this long after a document's `exp`. */
export const IDENTITY_FAIL_CLOSED_AFTER_SEC = 60 * DAY;
/** §3.1 (v2): invites live at most 14 days. */
export const INVITE_MAX_TTL_SEC = 14 * DAY;
/** §5.3: a capability lives at most 90 days. */
export const CAP_MAX_TTL_SEC = 90 * DAY;
/**
 * An answer cap (§3.3, a `circle` `want`'s `cap`): the asker's short-lived cap for the member it
 * asks, so the answer can come as ordinary `circle` bundles. At most a day: the joiner waits up
 * to 24 h for answers.
 */
export const ANSWER_CAP_MAX_TTL_SEC = DAY;
/** Tolerated clock skew for "issued in the future" checks. */
export const DEFAULT_SKEW_SEC = 300;

/** §2.5 document limits. */
export const MAX_RELAYS = 5;
export const MAX_DEVICES = 10;

export function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

/** `jwsHash(j) = b64u(H(utf8(j)))` over the compact JWS bytes (§1). */
export function jwsHash(jws: string): string {
  return b64uEncode(sha256(utf8(jws)));
}

// ---------------------------------------------------------------------------
// Self-certifying ids

const USER_ID_RE = /^p2p:[a-z2-7]{52}$/;
const DID_RE = /^d_[a-z2-7]{26}$/;
const CID_RE = /^c_[a-z2-7]{26}$/;

/** §2.1: `"p2p:" + b32(H(ik_pub))`. */
export function userIdFromIk(ikPub: Uint8Array): string {
  if (ikPub.length !== 32) fail("malformed", "ik must be 32 bytes");
  return `p2p:${b32Encode(sha256(ikPub))}`;
}

/** §2.3: `"d_" + b32(H(spk))[:26]`. Derived, so nobody can claim another device's id (H4). */
export function didFromSpk(spk: Uint8Array): string {
  if (spk.length !== 32) fail("malformed", "spk must be 32 bytes");
  return `d_${b32Encode(sha256(spk)).slice(0, 26)}`;
}

/** §3.3: `"c_" + b32(H(founder + "|" + nonce))[:26]`, where nonce is the b64u string. */
export function circleIdFor(founder: string, nonce: string): string {
  return `c_${b32Encode(sha256(utf8(`${founder}|${nonce}`))).slice(0, 26)}`;
}

export function isUserId(s: unknown): s is string {
  return typeof s === "string" && USER_ID_RE.test(s);
}

export function isDid(s: unknown): s is string {
  return typeof s === "string" && DID_RE.test(s);
}

export function isCircleId(s: unknown): s is string {
  return typeof s === "string" && CID_RE.test(s);
}

export function newNonce(): string {
  return b64uEncode(randomBytes(16));
}

// ---------------------------------------------------------------------------
// Payload field validation

export type Obj = Record<string, unknown>;

export function str(o: Obj, k: string): string {
  const v = o[k];
  if (typeof v !== "string" || v === "") fail("malformed", `${k} must be a non-empty string`);
  return v;
}

export function optStr(o: Obj, k: string): string | undefined {
  return o[k] === undefined ? undefined : str(o, k);
}

export function userIdField(o: Obj, k: string): string {
  const v = o[k];
  if (!isUserId(v)) fail("malformed", `${k} is not a v3 userId`);
  return v;
}

export function didField(o: Obj, k: string): string {
  const v = o[k];
  if (!isDid(v)) fail("malformed", `${k} is not a v3 device id`);
  return v;
}

export function cidField(o: Obj, k: string): string {
  const v = o[k];
  if (!isCircleId(v)) fail("malformed", `${k} is not a circle id`);
  return v;
}

export function int(o: Obj, k: string, min = 0): number {
  const v = o[k];
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min) fail("malformed", `${k} must be an integer >= ${min}`);
  return v;
}

export function bytesField(o: Obj, k: string, len: number): string {
  const v = str(o, k);
  b64uDecode(v, len);
  return v;
}

export function strArray(o: Obj, k: string, opts: { max?: number; item?: (s: string) => void; unique?: boolean } = {}): string[] {
  const v = o[k];
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string" || x === "")) {
    fail("malformed", `${k} must be an array of strings`);
  }
  if (opts.max !== undefined && v.length > opts.max) fail("malformed", `${k} has more than ${opts.max} entries`);
  if (opts.unique !== false && new Set(v).size !== v.length) fail("malformed", `${k} has duplicate entries`);
  v.forEach((s) => opts.item?.(s));
  return v as string[];
}

/** At most this many fields in a `crit` list. */
export const CRIT_MAX = 16;
const CRIT_FIELD_RE = /^[A-Za-z][A-Za-z0-9_]{0,31}$/;

/**
 * The fields of an object this version understands are `allowed`; what about the rest
 * (docs/compatibility.md, protocol.md "Forward compatibility"):
 *  - a field this version doesn't know is ignored: the parsers copy known fields one by one, so it is
 *    never stored, shown or acted on (it is still covered by the object's signature and its jwsHash,
 *    which are over the bytes as received);
 *  - unless the object lists it in `crit` (an optional array of 1-16 field names, each one the object
 *    carries): then the object is refused (`unsupported-critical`). A field that restricts what the
 *    object allows MUST be listed in `crit` by its issuer, so an older client can never read the
 *    object as allowing more than it does.
 * Every known field keeps its own type, size and value checks.
 */
export function checkFields(o: Obj, allowed: readonly string[], what: string): void {
  const crit = o.crit;
  if (crit === undefined) return;
  if (!Array.isArray(crit) || crit.length === 0 || crit.length > CRIT_MAX || crit.some((c) => typeof c !== "string" || !CRIT_FIELD_RE.test(c)) || new Set(crit).size !== crit.length) {
    fail("malformed", `${what}.crit must be 1-${CRIT_MAX} distinct field names`);
  }
  for (const c of crit as string[]) {
    if (c === "crit" || !Object.prototype.hasOwnProperty.call(o, c)) fail("malformed", `${what}.crit names ${c}, which it doesn't carry`);
    if (!allowed.includes(c)) fail("unsupported-critical", `${what}: ${c} is critical and this version doesn't understand it: update to accept it`);
  }
}

/** @deprecated The strict check before forward compatibility; kept for callers outside core. Use checkFields. */
export function noExtraFields(o: Obj, allowed: readonly string[], what: string): void {
  checkFields(o, allowed, what);
}

export function checkIssued(iat: number, now: number, skew: number = DEFAULT_SKEW_SEC): void {
  if (iat > now + skew) fail("not-yet-valid", `iat ${iat} is in the future`);
}

/** Lifetime ≤ maxTtl, issued not in the future, and `now < exp` (exp is exclusive). */
export function checkExpiry(iat: number, exp: number, maxTtl: number, now: number, skew: number = DEFAULT_SKEW_SEC): void {
  if (exp <= iat) fail("malformed", "exp must be after iat");
  if (exp - iat > maxTtl) fail("malformed", `lifetime ${exp - iat}s exceeds ${maxTtl}s`);
  checkIssued(iat, now, skew);
  if (now >= exp) fail("expired", `expired at ${exp}`);
}

/** Structural decode plus the `typ` check, before any key lookup (§1). */
export function decodeTyped(jws: string, typ: string, maxBytes?: number): DecodedJws {
  const d = decodeJws(jws, maxBytes);
  if (d.header.typ !== typ) fail("typ-mismatch", `typ ${d.header.typ} != ${typ}`);
  return d;
}

export function setEq(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const s = new Set(a);
  return b.every((x) => s.has(x));
}

/** Byte-wise comparison of two ASCII strings (b32, b64u, ids): the "lowest" order of the spec. */
export function asciiCompare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export interface TimeOptions {
  /** Current time in seconds (default: wall clock). */
  now?: number;
  skewSec?: number;
}
