// Copyright 2026 Ix Infrastructure Inc.
//
// The hash-chained identity document (docs/protocol.md §2.5;
// `typ: "p2p-identity+jws"`, `kid: "ik"`, signed by the identity key).
//
//  - Chain: ver = prev.ver + 1 and prev = jwsHash(previous version). Merge
//    versions are the one exception: ver = max(tip vers) + 1, prev = the tip
//    with the higher ver (tie: higher jwsHash), merge = the other tip, and
//    devices ⊆ A.devices ∩ B.devices (a merge never adds or re-adds a device).
//  - Forks (two ik-signed versions with the same (iss, ver)) are honest and
//    kept; while forked the allowlist is the intersection of the branches'
//    `devices` (and `keyholders`).
//  - Expiry: past `exp` clients warn; more than 60 days past `exp` they fail
//    closed for that user, except for the user's own `sync` envelopes.
//  - Compromise is detected by the owner's own key-holding devices seeing a
//    version they didn't publish that adds a device, relay or proof.
//
// Draft 3 additions (Phase 2): an optional `profile` {bio, avatar, links}.
// P3 (§2.8): an optional `rotation` {old, new} on the old identity's final
// version, which lists no devices and is terminal (nothing may follow it).

import { b64uDecode, b64uEncode } from "../encoding.js";
import { assertStrongEd25519PublicKey } from "../crypto.js";
import { signJws, verifyJws, MAX_JWS_BYTES } from "../jws.js";
import { fail } from "../errors.js";
import {
  asciiCompare,
  bytesField,
  checkIssued,
  DAY,
  decodeTyped,
  DEFAULT_SKEW_SEC,
  didField,
  HOUR,
  IDENTITY_DOC_MAX_TTL_SEC,
  IDENTITY_FAIL_CLOSED_AFTER_SEC,
  IK_KID,
  int,
  isDid,
  jwsHash,
  MAX_DEVICES,
  MAX_RELAYS,
  checkFields,
  nowSec,
  str,
  strArray,
  TYP3,
  userIdField,
  userIdFromIk,
  type Obj,
  type TimeOptions,
} from "./base.js";
import { assertValidName, parseRotationStatement, verifyRotationSignatures, type IdentityKey, type RotationStatement } from "./identity.js";
import { isCanonicalRelayUrl } from "./relayurl.js";
import { sanitizePeerText, PEER_TEXT_CAPS } from "./sanitize.js";

// ---------------------------------------------------------------------------
// Profile (draft 3 additions, Phase 2)

export const PROFILE_BIO_MAX = 280;
export const PROFILE_LINKS_MAX = 5;
export const PROFILE_URL_MAX = 512;
/**
 * A `data:` avatar is at most 4 KiB so the document still fits the §1 16 KiB
 * cap with its certificates, and can still ride inside a 16 KiB invite (§3.1).
 */
export const PROFILE_AVATAR_DATA_MAX = 4 * 1024;

export interface Profile {
  bio?: string;
  avatar?: string;
  links?: string[];
}

const DATA_AVATAR_RE = /^data:image\/(png|jpeg|webp|gif);base64,[A-Za-z0-9+/]+={0,2}$/;

function isHttpsUrl(s: string): boolean {
  if (s.length > PROFILE_URL_MAX) return false;
  try {
    const u = new URL(s);
    return u.protocol === "https:" && u.hostname !== "" && u.username === "" && u.password === "";
  } catch {
    return false;
  }
}

function validateProfile(v: unknown): Profile {
  if (typeof v !== "object" || v === null || Array.isArray(v)) fail("malformed", "profile must be an object");
  const p = v as Obj;
  checkFields(p, ["bio", "avatar", "links"], "profile");
  const out: Profile = {};
  if (p.bio !== undefined) {
    if (typeof p.bio !== "string" || [...p.bio].length > PROFILE_BIO_MAX) fail("malformed", `profile.bio must be ≤ ${PROFILE_BIO_MAX} chars`);
    out.bio = p.bio;
  }
  if (p.avatar !== undefined) {
    const a = p.avatar;
    const ok =
      typeof a === "string" &&
      (isHttpsUrl(a) || (a.length <= PROFILE_AVATAR_DATA_MAX && DATA_AVATAR_RE.test(a)));
    if (!ok) fail("malformed", "profile.avatar must be an https URL or a ≤ 4 KiB data:image/(png|jpeg|webp|gif) URI");
    out.avatar = a as string;
  }
  if (p.links !== undefined) {
    out.links = strArray(p, "links", {
      max: PROFILE_LINKS_MAX,
      item: (s) => {
        if (!isHttpsUrl(s)) fail("malformed", "profile.links entries must be https URLs");
      },
    });
  }
  return out;
}

/** What a client may show of a peer's profile. Every string is sanitized (§4.3). */
export interface DisplayProfile {
  bio?: string;
  links: string[];
  /**
   * Avatars are untrusted. `inline` is a data: image that can be rendered
   * without a fetch; `remote` MUST NOT be fetched without the user's opt-in.
   */
  avatar?: { kind: "inline"; dataUri: string } | { kind: "remote"; url: string; requiresOptIn: true };
}

export function displayProfile(profile: Profile | undefined): DisplayProfile {
  const out: DisplayProfile = { links: [] };
  if (!profile) return out;
  if (profile.bio !== undefined) out.bio = sanitizePeerText(profile.bio, PEER_TEXT_CAPS.bio);
  for (const l of profile.links ?? []) {
    const s = sanitizePeerText(l, PROFILE_URL_MAX);
    if (s === l && isHttpsUrl(s)) out.links.push(s);
  }
  const a = profile.avatar;
  if (a !== undefined) {
    if (DATA_AVATAR_RE.test(a) && a.length <= PROFILE_AVATAR_DATA_MAX) out.avatar = { kind: "inline", dataUri: a };
    else if (isHttpsUrl(a) && sanitizePeerText(a, PROFILE_URL_MAX) === a) out.avatar = { kind: "remote", url: a, requiresOptIn: true };
  }
  return out;
}

// ---------------------------------------------------------------------------
// Payload

export interface IdentityDocPayload {
  iss: string;
  ik: string;
  ver: number;
  prev: string | null;
  name: string;
  relays: string[];
  devices: string[];
  keyholders: string[];
  certs?: string[];
  proofs?: string[];
  profile?: Profile;
  /** The key-holding device that published this version. */
  by: string;
  /** Merge versions only: jwsHash of the other tip. */
  merge?: string;
  /**
   * P3 (§2.8): set only on the old identity's final version, which lists no
   * devices and no key holders. Self-certifying (both halves verify, `from`
   * is this identity) and terminal: no version may follow it.
   */
  rotation?: RotationStatement;
  /**
   * Compatibility amendment (docs/compatibility.md): what each listed device's client understands,
   * by did: its feature caps (the status cap charset, e.g. `receipts.v1`, `proto.3.1`) and its client
   * version. Advisory only: it decides what a sender may send, never what anyone may do.
   */
  dinfo?: Record<string, DeviceInfo>;
  iat: number;
  exp: number;
}

/** One device's entry in `dinfo`. */
export interface DeviceInfo {
  caps: string[];
  client?: string;
}

/** A client version string: at most 40 of [A-Za-z0-9._+-]. */
export const CLIENT_VERSION_RE = /^[A-Za-z0-9._+-]{1,40}$/;
const DINFO_CAP_RE = /^(?:x:)?[a-z][a-z0-9_-]*(?:\.[a-z0-9_-]+)*$/;
/** At most this many caps per device, each at most 40 characters (as a status's caps). */
export const DINFO_CAPS_MAX = 16;

function validateDeviceInfo(v: unknown, devices: readonly string[]): Record<string, DeviceInfo> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) fail("malformed", "dinfo must be an object");
  const out: Record<string, DeviceInfo> = {};
  const entries = Object.entries(v as Obj);
  if (entries.length > MAX_DEVICES) fail("malformed", `dinfo has more than ${MAX_DEVICES} entries`);
  for (const [did, e] of entries) {
    if (!devices.includes(did)) fail("malformed", `dinfo names ${did.slice(0, 64)}, which isn't a listed device`);
    if (typeof e !== "object" || e === null || Array.isArray(e)) fail("malformed", "a dinfo entry must be an object");
    const o = e as Obj;
    checkFields(o, ["caps", "client"], "dinfo entry");
    const caps = o.caps;
    if (!Array.isArray(caps) || caps.length > DINFO_CAPS_MAX || caps.some((c) => typeof c !== "string" || c.length > 40 || !DINFO_CAP_RE.test(c)) || new Set(caps).size !== caps.length) {
      fail("malformed", `dinfo caps must be at most ${DINFO_CAPS_MAX} distinct caps of [a-z0-9._-]`);
    }
    if (o.client !== undefined && (typeof o.client !== "string" || !CLIENT_VERSION_RE.test(o.client))) fail("malformed", "dinfo client must be a version string");
    out[did] = { caps: [...(caps as string[])], ...(typeof o.client === "string" ? { client: o.client } : {}) };
  }
  return out;
}

export interface VerifiedIdentityDoc extends IdentityDocPayload {
  jws: string;
  /** jwsHash(jws). */
  hash: string;
  ikPublicKey: Uint8Array;
}

const DOC_FIELDS = ["iss", "ik", "ver", "prev", "name", "relays", "devices", "keyholders", "certs", "proofs", "profile", "by", "merge", "rotation", "dinfo", "iat", "exp"];

function hashField(o: Obj, k: string): string {
  return bytesField(o, k, 32);
}

/** Structural validation of a document payload. */
export function validateIdentityDocPayload(p: Obj): IdentityDocPayload {
  checkFields(p, DOC_FIELDS, "identity document");
  const ver = int(p, "ver", 1);
  let prev: string | null;
  if (ver === 1) {
    if (p.prev !== null) fail("malformed", "ver 1 must have prev: null");
    prev = null;
  } else {
    prev = hashField(p, "prev");
  }
  const name = str(p, "name");
  assertValidName(name);
  const relays = strArray(p, "relays", {
    max: MAX_RELAYS,
    item: (r) => {
      if (!isCanonicalRelayUrl(r)) fail("malformed", `relay ${r} is not canonical (§5.1)`);
    },
  });
  if (relays.length === 0) fail("malformed", "an identity document lists 1–5 relays");
  const devices = strArray(p, "devices", {
    max: MAX_DEVICES,
    item: (d) => {
      if (!isDid(d)) fail("malformed", `devices entry ${d} is not a device id`);
    },
  });
  const keyholders = strArray(p, "keyholders", {
    item: (d) => {
      if (!devices.includes(d)) fail("malformed", `keyholder ${d} is not in devices`);
    },
  });
  const by = didField(p, "by");
  const out: IdentityDocPayload = {
    iss: userIdField(p, "iss"),
    ik: bytesField(p, "ik", 32),
    ver,
    prev,
    name,
    relays,
    devices,
    keyholders,
    by,
    iat: int(p, "iat"),
    exp: int(p, "exp"),
  };
  if (p.certs !== undefined) out.certs = strArray(p, "certs", { max: MAX_DEVICES });
  if (p.proofs !== undefined) out.proofs = strArray(p, "proofs", { max: 16 });
  if (p.profile !== undefined) out.profile = validateProfile(p.profile);
  if (p.dinfo !== undefined) out.dinfo = validateDeviceInfo(p.dinfo, devices);
  if (p.merge !== undefined) {
    if (ver < 2) fail("malformed", "a merge version has ver ≥ 2");
    out.merge = hashField(p, "merge");
    if (out.merge === out.prev) fail("merge-invalid", "merge and prev name the same version");
  }
  if (p.rotation !== undefined) {
    out.rotation = parseRotationStatement(p.rotation);
    // §2.8: the final version lists no devices (P3: and no key holders).
    if (devices.length > 0 || keyholders.length > 0) fail("malformed", "a rotation version lists no devices and no key holders");
    if (out.merge !== undefined) fail("malformed", "a rotation version is not a merge");
  }
  // `by` published this version, so it holds ik: it is a key holder of it.
  // (A final rotation version, §2.8, lists no devices; `by` is then unconstrained.)
  if (devices.length > 0 && !keyholders.includes(by)) fail("malformed", "by must be one of keyholders");
  if (out.exp <= out.iat) fail("malformed", "exp must be after iat");
  if (out.exp - out.iat > IDENTITY_DOC_MAX_TTL_SEC) fail("malformed", "an identity document lives at most 30 days");
  return out;
}

export interface CreateIdentityDocParams {
  ver: number;
  prev: string | null;
  name: string;
  relays: string[];
  devices: string[];
  keyholders: string[];
  by: string;
  certs?: string[];
  proofs?: string[];
  profile?: Profile;
  merge?: string;
  rotation?: RotationStatement;
  dinfo?: Record<string, DeviceInfo>;
  iat?: number;
  ttlSec?: number;
}

export function createIdentityDoc(ik: IdentityKey, params: CreateIdentityDocParams): string {
  const iat = params.iat ?? nowSec();
  const payload: IdentityDocPayload = {
    iss: ik.userId,
    ik: b64uEncode(ik.publicKey),
    ver: params.ver,
    prev: params.prev,
    name: params.name,
    relays: params.relays,
    devices: params.devices,
    keyholders: params.keyholders,
    ...(params.certs !== undefined ? { certs: params.certs } : {}),
    ...(params.proofs !== undefined ? { proofs: params.proofs } : {}),
    ...(params.profile !== undefined ? { profile: params.profile } : {}),
    by: params.by,
    ...(params.merge !== undefined ? { merge: params.merge } : {}),
    ...(params.rotation !== undefined ? { rotation: params.rotation } : {}),
    ...(params.dinfo !== undefined ? { dinfo: params.dinfo } : {}),
    iat,
    exp: iat + (params.ttlSec ?? IDENTITY_DOC_MAX_TTL_SEC),
  };
  validateIdentityDocPayload(payload as unknown as Obj);
  const jws = signJws(TYP3.identity, IK_KID, payload, ik.secretKey);
  if (jws.length > MAX_JWS_BYTES) fail("malformed", `identity document is ${jws.length} bytes, max ${MAX_JWS_BYTES}`);
  return jws;
}

/** Structural decode (no signature check), for routing: a relay finding a version's parents. */
export function peekIdentityDoc(jws: string): IdentityDocPayload & { hash: string } {
  const d = decodeTyped(jws, TYP3.identity);
  return { ...validateIdentityDocPayload(d.payload), hash: jwsHash(jws) };
}

/**
 * The document on its own: typ, kid, structure, small-order ik,
 * iss == H(ik), and the signature. No time checks: relays serve and
 * authenticate against expired documents (§2.5).
 */
/** Identity keys already checked strong (the small-order and torsion checks are costly). */
const strongIks = new Set<string>();

export function verifyIdentityDocSignature(jws: string): VerifiedIdentityDoc {
  const d = decodeTyped(jws, TYP3.identity);
  if (d.header.kid !== IK_KID) fail("kid-mismatch", `kid ${d.header.kid} != ${IK_KID}`);
  const p = validateIdentityDocPayload(d.payload);
  const ikPublicKey = b64uDecode(p.ik, 32);
  // Hash first (pre-release review): a stranger's junk costs one SHA-256, no curve work.
  if (userIdFromIk(ikPublicKey) !== p.iss) fail("issuer-mismatch", "iss is not the fingerprint of ik");
  if (!strongIks.has(p.ik)) {
    assertStrongEd25519PublicKey(ikPublicKey);
    strongIks.add(p.ik);
    if (strongIks.size > 4096) strongIks.delete(strongIks.values().next().value!);
  }
  verifyJws(jws, { typ: TYP3.identity, kid: IK_KID, publicKey: ikPublicKey });
  if (p.rotation !== undefined) checkDocRotation(p);
  return { ...p, jws, hash: jwsHash(jws), ikPublicKey };
}

/**
 * P3: a rotation carried by a document is from this identity (its old half
 * is signed by this document's ik) and was signed no later than the document
 * (with the usual skew). Both halves must verify.
 */
function checkDocRotation(p: IdentityDocPayload): void {
  const r = verifyRotationSignatures(p.rotation!);
  if (r.from !== p.iss || b64uEncode(r.oldIk) !== p.ik) fail("rotation-invalid", "the document's rotation is another identity's");
  if (r.iat > p.iat + DEFAULT_SKEW_SEC) fail("rotation-invalid", "the rotation is newer than the document carrying it");
}

/** verifyIdentityDocSignature plus "not issued in the future". */
export function verifyIdentityDoc(jws: string, opts: TimeOptions = {}): VerifiedIdentityDoc {
  const doc = verifyIdentityDocSignature(jws);
  checkIssued(doc.iat, opts.now ?? nowSec(), opts.skewSec ?? DEFAULT_SKEW_SEC);
  return doc;
}

function sameIdentity(a: VerifiedIdentityDoc, b: VerifiedIdentityDoc): void {
  if (a.iss !== b.iss || a.ik !== b.ik) fail("issuer-mismatch", "versions of different identities");
}

function subset(a: readonly string[], ...of: (readonly string[])[]): boolean {
  return a.every((x) => of.every((s) => s.includes(x)));
}

/**
 * Of two fork tips, the one a merge names as `prev`: the higher ver, on a tie
 * the higher jwsHash (§2.5).
 */
export function mergePrevTip<T extends { ver: number; hash: string }>(a: T, b: T): { prev: T; other: T } {
  if (a.ver !== b.ver) return a.ver > b.ver ? { prev: a, other: b } : { prev: b, other: a };
  return asciiCompare(a.hash, b.hash) > 0 ? { prev: a, other: b } : { prev: b, other: a };
}

export interface DocLinkOptions extends TimeOptions {
  /** For a merge version: the version its `merge` field names. */
  merge?: string;
}

/**
 * Verifies `docJws` as a link of its chain (§2.5, §5.6):
 *  - `prevDocJws` undefined: no parent is known (genesis, or a relay's first
 *    copy). The document must verify on its own; a ver-1 document must have
 *    prev null. A merge can't be checked without its parents and is refused.
 *    A version accepted this way with ver > 1 is an UNANCHORED root: it may
 *    be an old version replayed by anyone holding a copy (for example a
 *    since-revoked device pinning a document that still lists it). Callers
 *    holding only unanchored history (no ver 1 behind it) SHOULD replace it
 *    outright with a later version from the same `ik` with a higher `ver`
 *    than everything held that doesn't chain; history anchored at ver 1 is
 *    never replaced this way (the relay's L5 rule; IdentityChain.add does
 *    this for clients).
 *  - otherwise: same iss and ik, prev == jwsHash(prevDocJws), and
 *    ver == prev.ver + 1;
 *  - merges (`merge` present): `opts.merge` must be the version `merge`
 *    names; ver == max(tip vers) + 1; prev is the tip with the higher ver
 *    (tie: higher jwsHash); devices ⊆ A.devices ∩ B.devices and
 *    keyholders ⊆ A.keyholders ∩ B.keyholders.
 */
export function verifyIdentityDocLink(prevDocJws: string | undefined, docJws: string, opts: DocLinkOptions = {}): VerifiedIdentityDoc {
  const doc = verifyIdentityDoc(docJws, opts);
  if (prevDocJws === undefined) {
    if (doc.merge !== undefined) fail("merge-invalid", "a merge needs both parents");
    return doc;
  }
  if (doc.merge !== undefined && opts.merge === undefined) fail("merge-invalid", "merge parent not supplied");
  checkLink(verifyIdentityDocSignature(prevDocJws), doc, opts.merge !== undefined ? verifyIdentityDocSignature(opts.merge) : undefined);
  return doc;
}

/** The link rules between already-verified versions (no signature work). */
function checkLink(prev: VerifiedIdentityDoc, doc: VerifiedIdentityDoc, other: VerifiedIdentityDoc | undefined): void {
  sameIdentity(prev, doc);
  // P3 (§2.8): a rotation version is the identity's last: nothing chains onto it, not even a merge.
  if (prev.rotation !== undefined || other?.rotation !== undefined) fail("identity-rotated", `${doc.iss} was rotated: no version may follow its final one`);
  if (doc.prev !== prev.hash) fail("chain-broken", `prev ${doc.prev} != jwsHash of the given version`);
  if (doc.merge === undefined) {
    if (doc.ver !== prev.ver + 1) fail("chain-broken", `ver ${doc.ver} != ${prev.ver} + 1`);
    return;
  }
  if (other === undefined) fail("merge-invalid", "merge parent not supplied");
  sameIdentity(other, doc);
  if (doc.merge !== other.hash) fail("merge-invalid", "merge does not name the given version");
  if (doc.ver !== Math.max(prev.ver, other.ver) + 1) fail("merge-invalid", "merge ver must be max(tip vers) + 1");
  if (mergePrevTip(prev, other).prev.hash !== prev.hash) {
    fail("merge-invalid", "prev must be the tip with the higher ver (tie: higher jwsHash)");
  }
  if (!subset(doc.devices, prev.devices, other.devices)) fail("merge-adds-device", "merge.devices ⊄ A.devices ∩ B.devices");
  if (!subset(doc.keyholders, prev.keyholders, other.keyholders)) {
    fail("merge-adds-device", "merge.keyholders ⊄ A.keyholders ∩ B.keyholders");
  }
}

// ---------------------------------------------------------------------------
// Expiry and freshness (§2.5)

export type IdentityFreshness = "fresh" | "expired" | "fail-closed";

/**
 * fresh before `exp`; expired (warn, keep authorising) from `exp`; fail-closed
 * when more than 60 days past `exp`, i.e. now > exp + 60d.
 */
export function identityFreshness(exp: number, now: number = nowSec()): IdentityFreshness {
  if (now < exp) return "fresh";
  if (now > exp + IDENTITY_FAIL_CLOSED_AFTER_SEC) return "fail-closed";
  return "expired";
}

/** Whole days past `exp` (0 when fresh), for "hasn't been online for N days". */
export function daysPastExp(exp: number, now: number = nowSec()): number {
  return now < exp ? 0 : Math.floor((now - exp) / DAY);
}

/**
 * Throws `identity-fail-closed` when authorisation for this user must stop.
 * `ownSync` (a `sync` from the user's own device, from == to) is exempt.
 */
export function assertNotFailClosed(exp: number, now: number, opts: { ownSync?: boolean } = {}): IdentityFreshness {
  const f = identityFreshness(exp, now);
  if (f === "fail-closed" && !opts.ownSync) {
    fail("identity-fail-closed", `identity document expired ${daysPastExp(exp, now)} days ago`);
  }
  return f;
}

// ---------------------------------------------------------------------------
// Single writer (§2.5)

/** The scheduled writer: the lowest `did` among the key holders. */
export function scheduledWriter(keyholders: readonly string[]): string | undefined {
  return [...keyholders].sort(asciiCompare)[0];
}

/** Non-scheduled key holders re-publish only when the head is within 3 days of exp. */
export const REPUBLISH_WINDOW_SEC = 3 * DAY;

/** May `self` re-publish now? The scheduled writer always may; others only near `exp`. */
export function mayRepublish(self: string, head: Pick<IdentityDocPayload, "keyholders" | "exp">, now: number = nowSec()): boolean {
  if (!head.keyholders.includes(self)) return false;
  return scheduledWriter(head.keyholders) === self || head.exp - now <= REPUBLISH_WINDOW_SEC;
}

/** After a fork is this old, any key holder may publish the merge. */
export const MERGE_TAKEOVER_SEC = 24 * HOUR;

/**
 * May `self` publish the merge? The scheduled writer (lowest did among the
 * intersected key holders) may at once; any other key holder once the fork is
 * 24 h old.
 */
export function mayPublishMerge(self: string, keyholders: readonly string[], forkSeenAt: number, now: number = nowSec()): boolean {
  if (!keyholders.includes(self)) return false;
  return scheduledWriter(keyholders) === self || now - forkSeenAt >= MERGE_TAKEOVER_SEC;
}

/** The merge fields for two tips: what a merge writer passes to createIdentityDoc. */
export function mergeFields(a: VerifiedIdentityDoc, b: VerifiedIdentityDoc): Pick<CreateIdentityDocParams, "ver" | "prev" | "merge" | "devices" | "keyholders" | "relays" | "name"> {
  const { prev, other } = mergePrevTip(a, b);
  return {
    ver: Math.max(a.ver, b.ver) + 1,
    prev: prev.hash,
    merge: other.hash,
    devices: prev.devices.filter((d) => other.devices.includes(d)),
    keyholders: prev.keyholders.filter((d) => other.keyholders.includes(d)),
    relays: prev.relays,
    name: prev.name,
  };
}

// ---------------------------------------------------------------------------
// The client's view of one identity: every chain-consistent version, its tips.

export type ChainAddResult =
  | {
      status: "accepted" | "duplicate";
      doc: VerifiedIdentityDoc;
      /** Accepted with no ver 1 behind it (a first copy): provisional until anchored or superseded. */
      unanchored?: boolean;
      /** It replaced unanchored history (the L5 rule, see verifyIdentityDocLink). */
      replacedUnanchored?: boolean;
    }
  /** A parent is missing: fetch the chain back from `need` (§5.6) and retry. */
  | { status: "gap"; need: string };

/** The effective identity: what authorisation uses (§2.5, §2.3 rule 6). */
export interface IdentityView {
  iss: string;
  ik: string;
  /** The highest-ver tip (tie: higher jwsHash). */
  head: VerifiedIdentityDoc;
  tips: VerifiedIdentityDoc[];
  forked: boolean;
  /** Allowlist: the intersection of the tips' devices. */
  devices: string[];
  /** The intersection of the tips' keyholders. */
  keyholders: string[];
  /** Every relay any tip lists (fetch and send to all of them). */
  relays: string[];
  /** The latest exp among the tips. */
  exp: number;
  /** True when the history was jumped over (§2.5 "history gap"). */
  historyGap: boolean;
  /**
   * P3 (§2.8): the rotation statements the tips carry (one normally; two
   * different ones are a conflict, rotationConflicts). Empty unless rotated.
   */
  rotations: RotationStatement[];
}

export interface StoredIdentityChain {
  iss: string;
  versions: string[];
  historyGap?: boolean;
  /** Devices revoked on history this client jumped over (pre-release review R1): never allowed again. */
  denied?: string[];
  /**
   * Obsolete (pre-release review S3: demotion isn't revocation). Ignored when read,
   * never written.
   */
  deniedKeyholders?: string[];
}

/** Upper bound on versions kept per identity; the oldest non-tips go first. */
export const MAX_CHAIN_VERSIONS = 1024;

export class IdentityChain {
  private readonly versions = new Map<string, VerifiedIdentityDoc>();
  private gap = false;
  /** Revocation denylist carried across jumps (R1). */
  private denied = new Set<string>();

  constructor(readonly iss: string) {}

  /** Rebuilds from storage, re-verifying every link. */
  static fromStored(s: StoredIdentityChain): IdentityChain {
    const c = new IdentityChain(s.iss);
    const docs = s.versions.map((j) => verifyIdentityDocSignature(j)).sort((a, b) => a.ver - b.ver);
    c.gap = s.historyGap ?? false;
    c.denied = new Set(s.denied ?? []);
    // Roots (versions whose parents aren't stored, after a gap jump or pruning) are trusted as stored.
    for (const d of docs) {
      if (d.iss !== s.iss) fail("issuer-mismatch", "stored version of another identity");
      const parentsHeld = (d.prev === null || c.versions.has(d.prev)) && (d.merge === undefined || c.versions.has(d.merge));
      if (parentsHeld && d.ver > 1) {
        // Signatures were checked above: only the link rules run here.
        const parent = c.versions.get(d.prev!)!;
        checkLink(parent, d, d.merge !== undefined ? c.versions.get(d.merge) : undefined);
        if (d.merge === undefined) c.checkNoReturn(d, parent);
        c.versions.set(d.hash, d);
      } else c.versions.set(d.hash, d);
    }
    return c;
  }

  toStored(): StoredIdentityChain {
    return {
      iss: this.iss,
      versions: [...this.versions.values()].map((d) => d.jws),
      ...(this.gap ? { historyGap: true } : {}),
      ...(this.denied.size > 0 ? { denied: [...this.denied] } : {}),
    };
  }

  get size(): number {
    return this.versions.size;
  }

  has(hash: string): boolean {
    return this.versions.has(hash);
  }

  get(hash: string): VerifiedIdentityDoc | undefined {
    return this.versions.get(hash);
  }

  private anyHeld(): VerifiedIdentityDoc | undefined {
    return this.versions.values().next().value;
  }

  /** True when some held version carries a rotation (P3): the identity is final. */
  get rotated(): boolean {
    for (const v of this.versions.values()) if (v.rotation !== undefined) return true;
    return false;
  }

  /** True when some held version is a ver-1 genesis: the history is anchored. */
  get anchored(): boolean {
    for (const v of this.versions.values()) if (v.prev === null) return true;
    return false;
  }

  /**
   * Adds a version when it is chain-consistent with what is held: a ver-1
   * genesis, or a version whose prev (and merge) are held. Into an empty
   * chain, any version that verifies on its own is accepted as an
   * unanchored root (a first copy, e.g. bundled with an invite). While the
   * history is unanchored, a version from the same ik with a higher ver than
   * everything held that doesn't chain replaces it outright (L5). Otherwise
   * a missing parent is reported as the gap to fill first.
   */
  add(jws: string, opts: TimeOptions = {}): ChainAddResult {
    const peek = peekIdentityDoc(jws);
    if (peek.iss !== this.iss) fail("issuer-mismatch", `document of ${peek.iss}, chain of ${this.iss}`);
    const known = this.versions.get(peek.hash);
    if (known) return { status: "duplicate", doc: known };
    const held = this.anyHeld();
    if (peek.prev === null) {
      const doc = verifyIdentityDocLink(undefined, jws, opts);
      if (held && held.ik !== doc.ik) fail("issuer-mismatch", "a different ik for this userId");
      // A second genesis is a fork at ver 1: keep it.
      this.put(doc);
      return { status: "accepted", doc };
    }
    if (!held) {
      const doc = verifyIdentityDoc(jws, opts);
      this.versions.set(doc.hash, doc);
      return { status: "accepted", doc, unanchored: true };
    }
    const missing = !this.versions.has(peek.prev) ? peek.prev : peek.merge !== undefined && !this.versions.has(peek.merge) ? peek.merge : undefined;
    if (missing !== undefined) {
      if (!this.anchored && peek.ver > this.view().head.ver) {
        const doc = verifyIdentityDoc(jws, opts);
        if (doc.ik !== held.ik) fail("issuer-mismatch", "a different ik for this userId");
        // Like a jump, the replacement keeps what the dropped history revoked (R1).
        this.replaceHistory(doc);
        return { status: "accepted", doc, unanchored: true, replacedUnanchored: true };
      }
      return { status: "gap", need: missing };
    }
    const parent = this.versions.get(peek.prev)!;
    const other = peek.merge !== undefined ? this.versions.get(peek.merge)! : undefined;
    // Parents held here are already verified: only the new version's signature is checked.
    const doc = verifyIdentityDoc(jws, opts);
    checkLink(parent, doc, other);
    if (doc.merge === undefined) this.checkNoReturn(doc, parent);
    this.put(doc);
    return { status: "accepted", doc };
  }

  /**
   * §2.5 gap jump: when no listed relay still holds the missing versions, a
   * client MAY jump to a head that verifies under the same ik. The held
   * history is replaced by that head and the view reports `historyGap` so the
   * client can warn its user.
   *
   * What the jumped-over history revoked survives as a denylist (review R1,
   * see replaceHistory), so a revocation on any held branch still applies.
   */
  jumpTo(jws: string, opts: TimeOptions = {}): VerifiedIdentityDoc {
    const doc = verifyIdentityDoc(jws, opts);
    if (doc.iss !== this.iss) fail("issuer-mismatch", `document of ${doc.iss}, chain of ${this.iss}`);
    const held = this.anyHeld();
    if (held && held.ik !== doc.ik) fail("issuer-mismatch", "a different ik for this userId");
    if (held && doc.ver <= this.view().head.ver) fail("chain-broken", "a gap jump must move forward");
    this.replaceHistory(doc);
    this.gap = true;
    return doc;
  }

  /**
   * Replaces the held history with `doc`, carrying a revocation denylist
   * instead of whole tips (pre-release review R1): for every held branch, the
   * devices its ancestors listed but its tip no longer lists were revoked
   * there, and a revoked did never returns (§2.5), so they stay excluded
   * from the allowlist for good. Devices added later are unaffected, and the
   * jumped view isn't stuck `forked`. Revocation follows revokedAlong (a
   * merge dropping a one-branch did isn't one). Demotions aren't carried.
   */
  private replaceHistory(doc: VerifiedIdentityDoc): void {
    // P3: a rotated identity never comes back, by a jump or an unanchored replacement either.
    if (this.rotated) fail("identity-rotated", `${this.iss} was rotated: its history can't be replaced`);
    for (const tip of this.tips()) for (const d of this.revokedAlong(tip.hash)) this.denied.add(d);
    this.versions.clear();
    this.versions.set(doc.hash, doc);
  }

  /**
   * The dids revoked somewhere in the held ancestry of `hash` (inclusive):
   * a non-merge version revokes what its parent listed and it doesn't; a
   * merge revokes only what BOTH parents listed and it doesn't. A did linked
   * on one branch only and dropped by the merge was not revoked: §2.5 says a
   * merge never adds a device, so the owner re-adds it in a later version
   * (pre-release review S2).
   */
  revokedAlong(hash: string): Set<string> {
    const out = new Set<string>();
    for (const v of this.ancestors(hash)) {
      const p = v.prev ? this.versions.get(v.prev) : undefined;
      if (!p) continue;
      const o = v.merge !== undefined ? this.versions.get(v.merge) : undefined;
      if (v.merge !== undefined && !o) continue;
      for (const d of p.devices) {
        if (v.devices.includes(d)) continue;
        if (o && !o.devices.includes(d)) continue; // merge drop of a one-branch did
        out.add(d);
      }
    }
    return out;
  }

  /** §2.5: a revoked did never returns (re-linking makes a new did). */
  private checkNoReturn(doc: VerifiedIdentityDoc, parent: VerifiedIdentityDoc): void {
    const added = doc.devices.filter((d) => !parent.devices.includes(d));
    if (added.length === 0) return;
    const back0 = added.find((d) => this.denied.has(d));
    if (back0) fail("revoked-device-returned", `${back0} was revoked on history jumped over and can't return`);
    // An added did may not have been revoked anywhere on the parent's held
    // ancestry. Being dropped by a merge from one branch only isn't revocation (S2).
    const revoked = this.revokedAlong(parent.hash);
    const back = added.find((d) => revoked.has(d));
    if (back) fail("revoked-device-returned", `${back} was revoked at or before ver ${parent.ver} and can't return`);
  }

  private put(doc: VerifiedIdentityDoc): void {
    this.versions.set(doc.hash, doc);
    if (this.versions.size > MAX_CHAIN_VERSIONS) {
      const tips = new Set(this.tips().map((t) => t.hash));
      const oldest = [...this.versions.values()].filter((v) => !tips.has(v.hash)).sort((a, b) => a.ver - b.ver)[0];
      if (oldest) this.versions.delete(oldest.hash);
    }
  }

  /** Versions that no held version names as prev or merge. */
  tips(): VerifiedIdentityDoc[] {
    const parents = new Set<string>();
    for (const v of this.versions.values()) {
      if (v.prev) parents.add(v.prev);
      if (v.merge) parents.add(v.merge);
    }
    return [...this.versions.values()].filter((v) => !parents.has(v.hash)).sort((a, b) => b.ver - a.ver || asciiCompare(b.hash, a.hash));
  }

  /** The effective identity; throws identity-unknown when nothing is held. */
  view(): IdentityView {
    const tips = this.tips();
    if (tips.length === 0) fail("identity-unknown", `no identity document for ${this.iss}`);
    const head = tips[0];
    const devices = head.devices.filter((d) => tips.every((t) => t.devices.includes(d)) && !this.denied.has(d));
    // S3: key holders are the head's (intersected across a fork), limited to the denied-filtered allowlist.
    const keyholders = head.keyholders.filter((d) => tips.every((t) => t.keyholders.includes(d)) && devices.includes(d));
    const relays = [...new Set(tips.flatMap((t) => t.relays))];
    return {
      iss: this.iss,
      ik: head.ik,
      head,
      tips,
      forked: tips.length > 1,
      devices,
      keyholders,
      relays,
      exp: Math.max(...tips.map((t) => t.exp)),
      historyGap: this.gap,
      rotations: tips.filter((t) => t.rotation !== undefined).map((t) => ({ ...t.rotation! })),
    };
  }

  /** The ver-ordered ancestors of `hash` (inclusive), following prev and merge. */
  ancestors(hash: string): VerifiedIdentityDoc[] {
    const out: VerifiedIdentityDoc[] = [];
    const seen = new Set<string>();
    const stack = [hash];
    while (stack.length > 0) {
      const h = stack.pop()!;
      if (seen.has(h)) continue;
      seen.add(h);
      const v = this.versions.get(h);
      if (!v) continue;
      out.push(v);
      if (v.prev) stack.push(v.prev);
      if (v.merge) stack.push(v.merge);
    }
    return out.sort((a, b) => a.ver - b.ver);
  }
}

// ---------------------------------------------------------------------------
// "A version I didn't publish" (§2.5, compromise detection)

/** What the owner's devices published, kept locally and synced across them. */
export interface PublishLog {
  /** jwsHash of every version an owner device published. */
  published: readonly string[];
  /** Everything an owner device added: device ids, relay URLs, proof JWS hashes. */
  addedDevices: readonly string[];
  addedRelays: readonly string[];
  addedProofs: readonly string[];
}

export interface ForeignVersionReport {
  /** True when the user MUST be alerted. */
  alert: boolean;
  devices: string[];
  relays: string[];
  proofs: string[];
  /** The `by` device, when it isn't one of the owner's known key holders. */
  unknownBy?: string;
}

/**
 * Run by each of the owner's key-holding devices on every version of its own
 * identity it sees. Alerts when a version none of the owner's devices
 * published adds a device, a relay or a proof none of them added, judged by
 * `by` and the local log.
 */
export function detectUnpublishedVersion(
  doc: VerifiedIdentityDoc,
  parents: readonly VerifiedIdentityDoc[],
  log: PublishLog,
  ownKeyholders: readonly string[] = [],
): ForeignVersionReport {
  const none = { alert: false, devices: [], relays: [], proofs: [] };
  if (log.published.includes(doc.hash)) return none;
  const was = (f: (p: VerifiedIdentityDoc) => readonly string[]) => new Set(parents.flatMap(f));
  const prevDevices = was((p) => p.devices);
  const prevRelays = was((p) => p.relays);
  const prevProofs = was((p) => (p.proofs ?? []).map(jwsHash));
  const devices = doc.devices.filter((d) => !prevDevices.has(d) && !log.addedDevices.includes(d));
  const relays = doc.relays.filter((r) => !prevRelays.has(r) && !log.addedRelays.includes(r));
  const proofs = (doc.proofs ?? []).map(jwsHash).filter((h) => !prevProofs.has(h) && !log.addedProofs.includes(h));
  const unknownBy = ownKeyholders.length > 0 && !ownKeyholders.includes(doc.by) ? doc.by : undefined;
  const alert = devices.length + relays.length + proofs.length > 0;
  return { alert, devices, relays, proofs, ...(unknownBy !== undefined ? { unknownBy } : {}) };
}

/** The certificate a document carries for `did`, if any (unverified: verify before use). */
export function docCertFor(doc: Pick<IdentityDocPayload, "certs">, did: string): string | undefined {
  for (const c of doc.certs ?? []) {
    try {
      const p = decodeTyped(c, TYP3.device).payload;
      if (p.did === did) return c;
    } catch {
      // skip malformed entries
    }
  }
  return undefined;
}
