// Copyright 2026 Ix Infrastructure Inc.
//
// Mailbox capabilities (docs/protocol.md §5.3; `typ: "p2p-cap+jws"`, `kid` =
// the signing device's id, which also carries its certificate as `cert`). A
// capability is the recipient's signed permission for one sender to reach
// their mailboxes:
//
//   { iss: recipient userId, sub: sender userId | "*", cert, capid,
//     relays: [canonical relay URL, ...], kinds: ["*"] | ["contact"],
//     iat, exp (≤ iat + 90d), uses? }
//
//  - friends: sub = the friend, kinds ["*"], in both directions;
//  - circle co-members (review M3): the join statement's cap, sub "*" and
//    kinds ["*"], naming no circle;
//  - every other sub "*" cap MUST be kinds ["contact"] and SHOULD have uses;
//  - answer caps (§3.3): a joiner's `want` carries one for the member it
//    asks, sub = that member, kinds ["*"], living at most a day, so the
//    answer travels as ordinary (chunked) `circle` bundles.
//
// verifyCapForSend() is the relay-side check of §5.4 step 3.

import { b64uDecode, b64uEncode } from "../encoding.js";
import { randomBytes } from "../crypto.js";
import { signJws, verifyJws } from "../jws.js";
import { fail } from "../errors.js";
import {
  ANSWER_CAP_MAX_TTL_SEC,
  CAP_MAX_TTL_SEC,
  checkExpiry,
  decodeTyped,
  DEFAULT_SKEW_SEC,
  int,
  isUserId,
  MAX_RELAYS,
  checkFields,
  nowSec,
  str,
  strArray,
  TYP3,
  userIdField,
  type TimeOptions,
} from "./base.js";
import { verifyDeviceCertV3, type AllowlistSource, type VerifiedDeviceCertV3 } from "./device.js";
import { canonicalRelayUrl, isCanonicalRelayUrl } from "./relayurl.js";

export type CapKinds = ["*"] | ["contact"];

export interface CapPayload {
  iss: string;
  sub: string;
  cert: string;
  capid: string;
  relays: string[];
  kinds: CapKinds;
  iat: number;
  exp: number;
  uses?: number;
}

export interface VerifiedCap extends CapPayload {
  jws: string;
  signer: VerifiedDeviceCertV3;
}

/**
 * Why a cap is made. `join` is the circle join cap (sub "*", kinds ["*"]);
 * `friend` needs a userId sub; `contact` is a shareable contact-only cap;
 * `answer` is a joiner's cap for the member it asks for a circle's history
 * (a userId sub, kinds ["*"], at most ANSWER_CAP_MAX_TTL_SEC).
 */
export type CapPurpose = "friend" | "join" | "contact" | "answer";

export interface CreateCapParams {
  purpose: CapPurpose;
  /** The sender userId (friend), or "*" (join, contact; the default for those). */
  sub?: string;
  relays: string[];
  iat?: number;
  ttlSec?: number;
  uses?: number;
  capid?: string;
}

/** Signs a cap with one of the recipient's devices (its cert rides inside). */
export function createCap(
  device: { userId: string; did: string; signingSecretKey: Uint8Array },
  certJws: string,
  p: CreateCapParams,
): string {
  const iat = p.iat ?? nowSec();
  const ttl = p.ttlSec ?? CAP_MAX_TTL_SEC;
  if (ttl <= 0 || ttl > CAP_MAX_TTL_SEC) fail("malformed", "cap ttl must be in (0, 90d]");
  let sub: string;
  let kinds: CapKinds;
  if (p.purpose === "friend" || p.purpose === "answer") {
    if (!isUserId(p.sub)) fail("malformed", `a ${p.purpose} cap names its sender`);
    if (p.purpose === "answer" && ttl > ANSWER_CAP_MAX_TTL_SEC) fail("malformed", "an answer cap lives at most a day");
    sub = p.sub;
    kinds = ["*"];
  } else if (p.purpose === "join") {
    if (p.sub !== undefined && p.sub !== "*") fail("malformed", 'a join cap has sub "*"');
    sub = "*";
    kinds = ["*"];
  } else {
    // contact-only: for one invitee, or "*" for a shareable code.
    sub = p.sub ?? "*";
    if (sub !== "*" && !isUserId(sub)) fail("malformed", "cap sub must be a userId or *");
    kinds = ["contact"];
  }
  const payload: CapPayload = {
    iss: device.userId,
    sub,
    cert: certJws,
    capid: p.capid ?? b64uEncode(randomBytes(16)),
    relays: p.relays.map(canonicalRelayUrl),
    kinds,
    iat,
    exp: iat + ttl,
    ...(p.uses !== undefined ? { uses: p.uses } : {}),
  };
  validateCapPayload(payload as unknown as Record<string, unknown>);
  return signJws(TYP3.cap, device.did, payload, device.signingSecretKey);
}

function validateCapPayload(p: Record<string, unknown>): CapPayload {
  checkFields(p, ["iss", "sub", "cert", "capid", "relays", "kinds", "iat", "exp", "uses"], "cap");
  const sub = str(p, "sub");
  if (sub !== "*" && !isUserId(sub)) fail("malformed", "cap sub must be a userId or *");
  const kinds = strArray(p, "kinds");
  if (kinds.length !== 1 || (kinds[0] !== "*" && kinds[0] !== "contact")) fail("malformed", 'cap kinds must be ["*"] or ["contact"]');
  const relays = strArray(p, "relays", {
    max: MAX_RELAYS,
    item: (r) => {
      if (!isCanonicalRelayUrl(r)) fail("malformed", `cap relay ${r} is not canonical`);
    },
  });
  if (relays.length === 0) fail("malformed", "a cap names at least one relay");
  const out: CapPayload = {
    iss: userIdField(p, "iss"),
    sub,
    cert: str(p, "cert"),
    capid: str(p, "capid"),
    relays,
    kinds: kinds as CapKinds,
    iat: int(p, "iat"),
    exp: int(p, "exp"),
  };
  b64uDecode(out.capid, 16);
  if (p.uses !== undefined) out.uses = int(p, "uses", 1);
  return out;
}

export interface CapVerifyOptions extends TimeOptions {
  /** Rule 6 for the cap's signer, when the issuer's document is known. */
  identityDoc?: AllowlistSource;
  /**
   * Client-side policy (§5.3): a sub "*" cap must be kinds ["contact"],
   * unless it is a join cap (`purpose: "join"`). Relays can't tell join caps
   * apart and skip this.
   */
  purpose?: CapPurpose;
}

/** Verifies a cap: the signer cert (rules 1–5, 6 with a document), `cert.iss == iss`, `kid == cert.did`, the signature and the lifetime. */
export function verifyCap(jws: string, opts: CapVerifyOptions = {}): VerifiedCap {
  const now = opts.now ?? nowSec();
  const d = decodeTyped(jws, TYP3.cap);
  const p = validateCapPayload(d.payload);
  const signer = verifyDeviceCertV3(p.cert, { now, skewSec: opts.skewSec, identityDoc: opts.identityDoc });
  if (signer.iss !== p.iss) fail("cap-invalid", `cap cert is for ${signer.iss}, cap issued by ${p.iss}`);
  if (d.header.kid !== signer.did) fail("kid-mismatch", `kid ${d.header.kid} != cert did ${signer.did}`);
  verifyJws(jws, { typ: TYP3.cap, kid: signer.did, publicKey: signer.signingPublicKey, badSignature: "cap-invalid" });
  checkExpiry(p.iat, p.exp, CAP_MAX_TTL_SEC, now, opts.skewSec ?? DEFAULT_SKEW_SEC);
  if (opts.purpose !== undefined) {
    if (opts.purpose === "friend" && p.sub === "*") fail("cap-invalid", "a friend cap names its sender");
    if (opts.purpose === "join" && (p.sub !== "*" || p.kinds[0] !== "*")) fail("cap-invalid", 'a join cap is sub "*", kinds ["*"]');
    if (opts.purpose === "contact" && p.kinds[0] !== "contact") fail("cap-invalid", "a contact cap is kinds [contact]");
    if (opts.purpose === "answer" && (p.sub === "*" || p.kinds[0] !== "*" || p.exp - p.iat > ANSWER_CAP_MAX_TTL_SEC)) {
      fail("cap-invalid", 'an answer cap names its sender, is kinds ["*"] and lives at most a day');
    }
  }
  return { ...p, jws, signer };
}

export function capAllowsKind(kinds: readonly string[], kind: string): boolean {
  return kinds[0] === "*" || kinds.includes(kind);
}

export interface CapSendContext {
  /** The relay's own URL (canonicalised here). */
  relayUrl: string;
  /** The send frame's recipient userId. */
  to: string;
  /** The envelope's `from`. */
  envFrom: string;
  /** The envelope's `kind`. */
  kind: string;
  /** Seconds since the epoch. */
  now?: number;
  skewSec?: number;
  /** The issuer's identity document, when the relay holds it (rule 6). */
  identityDoc?: AllowlistSource;
  /** Revocation lookup (§5.3 `revoke` frames). */
  /**
   * Revocation lookup (§5.3 `revoke` frames), keyed by issuer and capid: only
   * an authenticated device of `cap.iss` may revoke, so a revocation recorded
   * for one issuer never matches another issuer's capid (pre-release review L9).
   */
  isRevoked?: (iss: string, capid: string) => boolean;
}

/**
 * The relay's §5.4 step 3: the cap is valid and its cert verifies,
 * `cap.iss == to`, `cap.sub ∈ {env.from, "*"}`, `relays` includes this relay,
 * `kinds` allows `env.kind`, unexpired and not revoked. `uses` is returned for
 * the relay to enforce per relay. Every failure is a P2PError; the relay
 * answers all of them with the single code `undeliverable`.
 */
export function verifyCapForSend(capJws: string, ctx: CapSendContext): VerifiedCap {
  const cap = verifyCap(capJws, { now: ctx.now, skewSec: ctx.skewSec, identityDoc: ctx.identityDoc });
  if (cap.iss !== ctx.to) fail("cap-denied", "cap is for another recipient");
  if (cap.sub !== "*" && cap.sub !== ctx.envFrom) fail("cap-denied", "cap is for another sender");
  if (!cap.relays.includes(canonicalRelayUrl(ctx.relayUrl))) fail("cap-denied", "cap does not name this relay");
  if (!capAllowsKind(cap.kinds, ctx.kind)) fail("cap-denied", `cap does not allow kind ${ctx.kind}`);
  if (ctx.isRevoked?.(cap.iss, cap.capid)) fail("cap-denied", "cap revoked");
  return cap;
}

/** True when the cap is within `withinSec` of expiry (§3.3: re-join 30 days before). */
export function capExpiresWithin(cap: Pick<CapPayload, "exp">, withinSec: number, now: number = nowSec()): boolean {
  return cap.exp - now <= withinSec;
}
