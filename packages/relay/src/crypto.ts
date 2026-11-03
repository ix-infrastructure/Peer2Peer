// Copyright 2026 Ix Infrastructure Inc.
//
// The relay's only window onto Peer2Peer v3 cryptography (docs/protocol.md).
//
// Everything the relay needs to check (device certificates, the relay-auth
// signature, outer envelopes, capabilities, proof-of-work, identity-document
// links) goes through the RelayCrypto interface below. The rest of the relay
// never parses a JWS itself.
//
// The implementation here is a TEMPORARY ADAPTER built on @peer2peer/core's
// v2 primitives (decodeJws, verifyJws, sha256, b64u) plus @noble/curves for the
// two things core does not export (raw Ed25519 verify, small-order checks).
// When Phase 2 (`@peer2peer/core/v3`) merges, `createRelayCrypto()` is
// re-implemented on top of it and nothing else in packages/relay changes.
// Every place that must change at that point is marked `TODO(phase2-wire)`.

import { createPublicKey, verify as nodeVerify, type KeyObject } from "node:crypto";
import { b64uDecode, b64uEncode, decodeJws, sha256, type DecodedJws } from "@peer2peer/core";
import {
  assertStrongEd25519PublicKey,
  assertStrongX25519PublicKey,
  ed25519Verify as ed25519VerifyNoble,
  verifyIdentityDocLink as coreVerifyIdentityDocLink,
  verifyIdentityDocSignature,
} from "@peer2peer/core/v3";

// ---------------------------------------------------------------------------
// Types the relay consumes

/** A device certificate that passed §2.3 rules 1–5. */
export interface VerifiedDeviceCert {
  jws: string;
  iss: string;
  did: string;
  /** Raw Ed25519 device signing key. */
  spk: Uint8Array;
  iat: number;
  exp: number;
}

/** The outer, routing-visible fields of a `p2p-msg+jws` envelope (§4.1). Not yet signature-checked. */
export interface OuterEnvelope {
  jws: string;
  /** UTF-8 bytes of the compact JWS, exactly as received (the PoW input). */
  bytes: Uint8Array;
  v: number;
  from: string;
  fdid: string;
  fcert: string;
  to: string;
  tdid: string;
  kind: string;
  /** The JWS header `kid`. */
  kid: string;
}

/** A mailbox capability (§5.3) that passed every stateless check for one send. */
export interface VerifiedCap {
  iss: string;
  /** The did of the device that signed the cap (its `cert.did`). */
  signerDid: string;
  sub: string;
  capid: string;
  relays: string[];
  kinds: string[];
  iat: number;
  exp: number;
  uses?: number;
}

/** A self-signed identity document (§2.5) whose signature and shape verified. */
export interface IdentityDoc {
  jws: string;
  /** jwsHash(jws) = b64u(H(utf8(jws))). */
  hash: string;
  iss: string;
  ver: number;
  prev: string | null;
  merge?: string;
  relays: string[];
  devices: string[];
  keyholders: string[];
  iat: number;
  exp: number;
}

/**
 * Codes a RelayCrypto method throws (as RelayCryptoError). The relay maps them
 * onto its own wire codes and never forwards them, so they can be specific.
 */
export type RelayCryptoCode =
  | "malformed"
  | "too-large"
  | "bad-signature"
  | "weak-key"
  | "expired"
  | "not-yet-valid"
  | "mismatch"
  | "not-allowed"
  | "bad-link"
  // An object lists a field this relay doesn't understand in `crit` (docs/compatibility.md)
  | "unsupported-critical";

export class RelayCryptoError extends Error {
  constructor(
    readonly code: RelayCryptoCode,
    message?: string,
  ) {
    super(message ?? code);
    this.name = "RelayCryptoError";
  }
}

export interface CapSendContext {
  /** This relay's canonical URL. */
  relayUrl: string;
  /** `send.to`, the recipient userId. */
  to: string;
  /** `env.from`, already bound to a verified fcert. */
  envFrom: string;
  /** `env.kind`. */
  kind: string;
  /** Seconds since the epoch. */
  now: number;
}

/**
 * The seam between the relay and v3 cryptography. Methods throw
 * RelayCryptoError on any failure unless they return a boolean.
 * Times are seconds since the epoch, as on the wire.
 */
export interface RelayCrypto {
  /** §5.1 canonical relay URL. Throws `malformed` when it can't be canonicalised. */
  canonicalRelayUrl(url: string): string;
  /** `utf8("p2p/v3/relay-auth|" + relay + "|" + nonce)` (§5.2). */
  relayAuthMessage(relay: string, nonce: string): Uint8Array;
  /** Checks `auth.sig` (b64u) under the certificate's `spk`. */
  verifyRelayAuth(cert: VerifiedDeviceCert, relay: string, nonce: string, sig: string): boolean;
  /**
   * §2.3 rules 1–5. Rule 6 (the identity-document allowlist) is applied by the
   * relay itself, because during a fork it is the intersection over every tip.
   */
  verifyDeviceCert(jws: string, opts: { now: number }): VerifiedDeviceCert;
  /** §5.4 step 1: parse (≤ 64 KiB). No signature check. */
  parseOuterEnvelope(jws: string): OuterEnvelope;
  /** §5.4 step 2: binds `from`/`fdid`/`kid` to `fcert` and checks the JWS under `fcert.spk`. */
  verifyEnvelope(env: OuterEnvelope, fcert: VerifiedDeviceCert): void;
  /** §5.4 step 3, stateless part: validity, cert, iss, sub, relays, kinds, expiry. */
  verifyCapForSend(capJws: string, ctx: CapSendContext): VerifiedCap;
  /** `H(envBytes || powNonce)` has at least `bits` leading zero bits (§5.4). */
  powOk(envBytes: Uint8Array, powNonce: Uint8Array, bits: number): boolean;
  /** §2.5: signature under `ik`, `iss == H(ik)`, shape and caps. Expiry is NOT checked (relays ignore it). */
  parseIdentityDoc(jws: string): IdentityDoc;
  /**
   * §2.5/§5.6 chain link: `doc` extends `prev` (`ver = prev.ver + 1`), or, when
   * `doc.merge` is set, merges `prev` and `merge` (`ver = max + 1`, `prev` the
   * higher tip, devices only shrink). Throws `bad-link`.
   */
  verifyIdentityDocLink(prev: IdentityDoc, doc: IdentityDoc, merge?: IdentityDoc): void;
  isUserId(s: unknown): s is string;
  isDeviceId(s: unknown): s is string;
}

// ---------------------------------------------------------------------------
// Constants (§1, §2.3, §2.5, §5.3)

export const TYP_DEVICE = "p2p-device+jws";
export const TYP_MSG = "p2p-msg+jws";
export const TYP_CAP = "p2p-cap+jws";
export const TYP_IDENTITY = "p2p-identity+jws";
export const MAX_JWS_BYTES = 16 * 1024;
export const MAX_ENVELOPE_BYTES = 64 * 1024;
const DAY = 24 * 3600;
const CERT_MAX_TTL = 90 * DAY;
const CAP_MAX_TTL = 90 * DAY;
const SKEW = 300;

// ---------------------------------------------------------------------------
// Temporary helpers. TODO(phase2-wire): replace with core/v3's b32, userId and
// did derivations so there is exactly one implementation of each.

const B32 = "abcdefghijklmnopqrstuvwxyz234567";

/** RFC 4648 base32, lowercase, no padding (§1). */
export function b32Encode(bytes: Uint8Array): string {
  let out = "";
  let bits = 0;
  let acc = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(acc >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(acc << (5 - bits)) & 31];
  return out;
}

const enc = new TextEncoder();
const utf8 = (s: string): Uint8Array => enc.encode(s);

/** `"p2p:" + b32(H(ik_pub))` (§2.1). */
export function userIdFromIk(ik: Uint8Array): string {
  return `p2p:${b32Encode(sha256(ik))}`;
}

/** `"d_" + b32(H(spk))[:26]` (§2.3). */
export function didFromSpk(spk: Uint8Array): string {
  return `d_${b32Encode(sha256(spk)).slice(0, 26)}`;
}

/** `jwsHash(j) = b64u(H(utf8(j)))` (§1). */
export function jwsHash(jws: string): string {
  return b64uEncode(sha256(utf8(jws)));
}

const USER_ID_RE = /^p2p:[a-z2-7]{52}$/;
const DID_RE = /^d_[a-z2-7]{26}$/;

// ---------------------------------------------------------------------------
// The adapter

function err(code: RelayCryptoCode, message?: string): never {
  throw new RelayCryptoError(code, message);
}

/** Runs a core call and turns its P2PError (or anything else) into a RelayCryptoError. */
function guard<T>(code: RelayCryptoCode, fn: () => T): T {
  try {
    return fn();
  } catch (e) {
    if (e instanceof RelayCryptoError) throw e;
    const reason = (e as { reason?: string }).reason;
    if (reason === "bad-signature") err("bad-signature");
    if (reason === "small-order-key") err("weak-key");
    return err(code, e instanceof Error ? e.message : String(e));
  }
}

function str(p: Record<string, unknown>, k: string): string {
  const v = p[k];
  if (typeof v !== "string" || v === "") err("malformed", `${k} must be a non-empty string`);
  return v;
}

function int(p: Record<string, unknown>, k: string): number {
  const v = p[k];
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) err("malformed", `${k} must be a non-negative integer`);
  return v;
}

function strArray(p: Record<string, unknown>, k: string, max: number): string[] {
  const v = p[k];
  if (!Array.isArray(v) || v.length > max || !v.every((x) => typeof x === "string" && x !== "")) {
    err("malformed", `${k} must be an array of at most ${max} strings`);
  }
  if (new Set(v).size !== v.length) err("malformed", `${k} has duplicates`);
  return v as string[];
}

function key32(p: Record<string, unknown>, k: string): Uint8Array {
  return guard("malformed", () => b64uDecode(str(p, k), 32));
}

/** Core's strict key checks (canonical, not small order, torsion-free), mapped to `weak-key`. */
function assertStrongEd25519(pk: Uint8Array): void {
  guard("weak-key", () => assertStrongEd25519PublicKey(pk));
}

function assertStrongX25519(pk: Uint8Array): void {
  guard("weak-key", () => assertStrongX25519PublicKey(pk));
}

// ---------------------------------------------------------------------------
// Native Ed25519 (F-2)
//
// Signature checks run in node:crypto (OpenSSL), about 10x faster than the
// pure-JS verifier. The strict RFC 8032 rules the relay relied on noble for
// are kept explicitly:
//   - the public key was already checked by assertStrongEd25519 (canonical
//     encoding, not small order, torsion-free) before any signature under it
//     is verified: certs check ik/spk, identity docs check ik;
//   - S must be canonical (S < L), checked here;
//   - R must be canonical: OpenSSL compares the encoding of the recomputed R
//     with the received bytes, and uses the cofactorless equation, so it is at
//     least as strict as noble's zip215:false.
// A differential test checks native rejects everything noble-strict rejects.

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_L = 2n ** 252n + 27742317777372353535851937790883648493n;
const KEY_CACHE_SIZE = 4096;
const keyObjects = new Map<string, KeyObject>();

function ed25519KeyObject(pk: Uint8Array): KeyObject {
  const id = Buffer.from(pk).toString("base64url");
  let k = keyObjects.get(id);
  if (k) {
    keyObjects.delete(id);
  } else {
    k = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, pk]), format: "der", type: "spki" });
    if (keyObjects.size >= KEY_CACHE_SIZE) keyObjects.delete(keyObjects.keys().next().value as string);
  }
  keyObjects.set(id, k);
  return k;
}

/**
 * Messages up to this size are verified natively. Node copies the whole
 * message into a native buffer for every one-shot verify; for large inputs
 * (envelopes approach 64 KiB) that churn grew the relay's RSS by 20-40 MB
 * under a flood of large envelopes (resilience #7), so they use core's strict
 * pure-JS verifier instead. Hot traffic (statuses, messages, caps, certs,
 * auth) is far below this.
 */
export const NATIVE_VERIFY_MAX_BYTES = 16 * 1024;

/** Strict Ed25519 verification: native up to NATIVE_VERIFY_MAX_BYTES, core's noble-strict above. */
export function ed25519VerifyStrict(sig: Uint8Array, msg: Uint8Array, pk: Uint8Array): boolean {
  return msg.length <= NATIVE_VERIFY_MAX_BYTES ? ed25519VerifyNative(sig, msg, pk) : ed25519VerifyNoble(sig, msg, pk);
}

/**
 * Strict Ed25519 verification with native crypto. `pk` must already have
 * passed assertStrongEd25519.
 */
export function ed25519VerifyNative(sig: Uint8Array, msg: Uint8Array, pk: Uint8Array): boolean {
  if (sig.length !== 64 || pk.length !== 32) return false;
  let s = 0n;
  for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sig[i]);
  if (s >= ED25519_L) return false;
  try {
    return nodeVerify(null, msg, ed25519KeyObject(pk), sig);
  } catch {
    return false;
  }
}

/** Structural decode (core), typ/kid checks, then the native signature check over the exact bytes. */
function verifyJwsNative(jws: string, typ: string, kid: string, pk: Uint8Array, maxBytes = MAX_JWS_BYTES): DecodedJws {
  const d = guard("malformed", () => decodeJws(jws, maxBytes));
  if (d.header.typ !== typ) err("malformed", `typ ${d.header.typ} != ${typ}`);
  if (d.header.kid !== kid) err("mismatch", "kid mismatch");
  if (!ed25519VerifyStrict(d.signature, d.signingInput, pk)) err("bad-signature");
  return d;
}

function checkTimes(iat: number, exp: number, maxTtl: number, now: number): void {
  if (exp > iat + maxTtl) err("malformed", "lifetime too long");
  if (exp <= iat) err("malformed", "exp before iat");
  if (iat > now + SKEW) err("not-yet-valid");
  if (now >= exp) err("expired");
}

function decode(jws: unknown, typ: string, maxBytes: number): DecodedJws {
  if (typeof jws !== "string") err("malformed", "JWS must be a string");
  if (jws.length > maxBytes) err("too-large");
  const d = guard("malformed", () => decodeJws(jws, maxBytes));
  if (d.header.typ !== typ) err("malformed", `typ ${d.header.typ} != ${typ}`);
  return d;
}

/**
 * The temporary RelayCrypto, on core v2 primitives.
 *
 * TODO(phase2-wire): re-implement each method with `@peer2peer/core/v3`
 * (canonicalRelayUrl, relayAuthMessage + its verify, verifyDeviceCertV3,
 * parseOuterEnvelope + its signature check, verifyCapForSend, powOk,
 * verifyIdentityDocLink) and delete the local helpers above.
 */
interface CapCrypto {
  cap: VerifiedCap;
  certIat: number;
  certExp: number;
}

export interface RelayCryptoOptions {
  /**
   * Verified device certificates remembered, keyed by a hash of the exact
   * JWS bytes. A hit skips only the signature and small-order work (about
   * 3 ms, mostly the torsion check); the validity window is re-checked every
   * time, and revocation and allowlist checks are the relay's, on every send.
   */
  certCacheSize?: number;
}

/**
 * The crit rule (docs/compatibility.md): a field the relay doesn't know is ignored unless the object
 * lists it in `crit`, and then the object is refused. The relay's own parsers below read only the
 * fields they know, so this is the whole of it: an issuer that adds a field restricting what a cap,
 * cert or envelope allows lists it in `crit`, and this relay refuses rather than allow more.
 */
const CRIT_FIELD_RE = /^[A-Za-z][A-Za-z0-9_]{0,31}$/;

export function relayCritCheck(p: Record<string, unknown>, known: readonly string[], what: string): void {
  if (!Object.prototype.hasOwnProperty.call(p, "crit")) return;
  const crit = p.crit;
  // core's checkFields shape: 1-16 distinct names, each a field the object itself carries, never `crit`.
  if (!Array.isArray(crit) || crit.length === 0 || crit.length > 16 || crit.some((c) => typeof c !== "string" || !CRIT_FIELD_RE.test(c)) || new Set(crit).size !== crit.length) {
    err("malformed", `${what}.crit must be 1-16 distinct field names`);
  }
  for (const c of crit as string[]) {
    if (c === "crit" || !Object.prototype.hasOwnProperty.call(p, c)) err("malformed", `${what}.crit names ${c}, which it doesn't carry`);
    if (!known.includes(c)) err("unsupported-critical", `${what}: critical field ${c} isn't understood`);
  }
}

const CERT_FIELDS = ["iss", "ik", "did", "spk", "kpk", "label", "iat", "exp"];
const CAP_FIELDS = ["iss", "sub", "cert", "capid", "relays", "kinds", "iat", "exp", "uses"];
const ENVELOPE_FIELDS = ["v", "from", "fdid", "fcert", "to", "tdid", "own", "sid", "seq", "ts", "n", "epk", "ct", "kind"];

export function createRelayCrypto(opts: RelayCryptoOptions = {}): RelayCrypto {
  const cacheSize = opts.certCacheSize ?? 10_000;
  /** LRU (Map insertion order) of verified certs. Only successes are cached. */
  const certCache = new Map<string, VerifiedDeviceCert>();
  /** LRU of caps whose stateless checks passed (F-2). Only successes are cached. */
  const capCache = new Map<string, CapCrypto>();
  /** §2.3 rules 1–5, no cache. */
  function verifyDeviceCertUncached(jws: string, opts: { now: number }): VerifiedDeviceCert {
    // TODO(phase2-wire): core/v3 verifyDeviceCertV3(jws, {now}); keep the cache in front of it.
    const d = decode(jws, TYP_DEVICE, MAX_JWS_BYTES);
    if (d.header.kid !== "ik") err("malformed", "device cert kid must be ik");
    const p = d.payload;
    relayCritCheck(p, CERT_FIELDS, "device cert");
    const ik = key32(p, "ik");
    const spk = key32(p, "spk");
    const kpk = key32(p, "kpk");
    const iss = str(p, "iss");
    const did = str(p, "did");
    const iat = int(p, "iat");
    const exp = int(p, "exp");
    if ("label" in p && typeof p.label !== "string") err("malformed", "label must be a string");
    // Rule 4 before any signature work.
    assertStrongEd25519(ik);
    assertStrongEd25519(spk);
    assertStrongX25519(kpk);
    // Rule 1.
    if (iss !== userIdFromIk(ik)) err("mismatch", "iss != H(ik)");
    // Rule 2.
    verifyJwsNative(jws, TYP_DEVICE, "ik", ik);
    // Rule 3.
    if (did !== didFromSpk(spk)) err("mismatch", "did != H(spk)");
    // Rule 5.
    checkTimes(iat, exp, CERT_MAX_TTL, opts.now);
    return { jws, iss, did, spk, iat, exp };
  }

  /** The stateless part of a cap check: parse, cert (rules 1–5), signature. */
  function capCrypto(capJws: string, now: number): CapCrypto {
    const d = decode(capJws, TYP_CAP, MAX_JWS_BYTES);
    const p = d.payload;
    relayCritCheck(p, CAP_FIELDS, "cap");
    const cert = self.verifyDeviceCert(str(p, "cert"), { now });
    if (cert.did !== d.header.kid) err("mismatch", "cap kid != cert.did");
    const cap: VerifiedCap = {
      iss: str(p, "iss"),
      signerDid: cert.did,
      sub: str(p, "sub"),
      capid: str(p, "capid"),
      relays: strArray(p, "relays", 16),
      kinds: strArray(p, "kinds", 16),
      iat: int(p, "iat"),
      exp: int(p, "exp"),
    };
    guard("malformed", () => b64uDecode(cap.capid, 16));
    if ("uses" in p) {
      const uses = int(p, "uses");
      if (uses < 1) err("malformed", "uses must be positive");
      cap.uses = uses;
    }
    if (cert.iss !== cap.iss) err("mismatch", "cap cert.iss != cap.iss");
    verifyJwsNative(capJws, TYP_CAP, cert.did, cert.spk);
    // The cap's own lifetime shape (exp ≤ iat + 90 d) is stateless; the clock check runs per send.
    if (cap.exp > cap.iat + CAP_MAX_TTL || cap.exp <= cap.iat) err("malformed", "bad cap lifetime");
    return { cap, certIat: cert.iat, certExp: cert.exp };
  }

  const self: RelayCrypto = {
    canonicalRelayUrl(url: string): string {
      // TODO(phase2-wire): core/v3 canonicalRelayUrl.
      let u: URL;
      try {
        u = new URL(url);
      } catch {
        return err("malformed", "not a URL");
      }
      if (u.protocol !== "wss:") err("malformed", "relay URLs use wss");
      if (u.username || u.password || u.search || u.hash || url.includes("?") || url.includes("#")) {
        err("malformed", "relay URLs carry no credentials, query or fragment");
      }
      if (u.hostname === "") err("malformed", "missing host");
      // WHATWG URL lowercases the host, converts it to an IDNA A-label and
      // drops the scheme's default port (443 for wss).
      let path = u.pathname;
      if (path === "" || path === "/") path = "/v3";
      else if (path.endsWith("/")) path = path.slice(0, -1);
      return `wss://${u.host}${path}`;
    },

    relayAuthMessage(relay: string, nonce: string): Uint8Array {
      return utf8(`p2p/v3/relay-auth|${relay}|${nonce}`);
    },

    verifyRelayAuth(cert: VerifiedDeviceCert, relay: string, nonce: string, sig: string): boolean {
      // TODO(phase2-wire): core/v3's relay-auth verification.
      let s: Uint8Array;
      try {
        s = b64uDecode(sig, 64);
      } catch {
        return false;
      }
      return ed25519VerifyStrict(s, self.relayAuthMessage(relay, nonce), cert.spk);
    },

    verifyDeviceCert(jws: string, opts: { now: number }): VerifiedDeviceCert {
      if (typeof jws === "string" && jws.length <= MAX_JWS_BYTES && cacheSize > 0) {
        const key = jwsHash(jws);
        const hit = certCache.get(key);
        if (hit) {
          // Rule 5 again: a cached cert still expires on time.
          checkTimes(hit.iat, hit.exp, CERT_MAX_TTL, opts.now);
          certCache.delete(key);
          certCache.set(key, hit);
          return hit;
        }
        const v = verifyDeviceCertUncached(jws, opts);
        certCache.set(key, v);
        if (certCache.size > cacheSize) certCache.delete(certCache.keys().next().value as string);
        return v;
      }
      return verifyDeviceCertUncached(jws, opts);
    },


    parseOuterEnvelope(jws: string): OuterEnvelope {
      // TODO(phase2-wire): core/v3 parseOuterEnvelope.
      const d = decode(jws, TYP_MSG, MAX_ENVELOPE_BYTES);
      const p = d.payload;
      if (p.v !== 3) err("malformed", "envelope v must be 3");
      relayCritCheck(p, ENVELOPE_FIELDS, "envelope");
      const env: OuterEnvelope = {
        jws,
        bytes: utf8(jws),
        v: 3,
        from: str(p, "from"),
        fdid: str(p, "fdid"),
        fcert: str(p, "fcert"),
        to: str(p, "to"),
        tdid: str(p, "tdid"),
        kind: str(p, "kind"),
        kid: d.header.kid,
      };
      if (!self.isUserId(env.from) || !self.isUserId(env.to)) err("malformed", "bad userId");
      if (!self.isDeviceId(env.fdid) || !self.isDeviceId(env.tdid)) err("malformed", "bad device id");
      return env;
    },

    verifyEnvelope(env: OuterEnvelope, fcert: VerifiedDeviceCert): void {
      // TODO(phase2-wire): core/v3's outer-envelope signature check against fcert.
      if (fcert.iss !== env.from) err("mismatch", "fcert.iss != from");
      if (fcert.did !== env.fdid || env.kid !== env.fdid) err("mismatch", "fcert.did, fdid and kid differ");
      verifyJwsNative(env.jws, TYP_MSG, env.fdid, fcert.spk, MAX_ENVELOPE_BYTES);
    },

    verifyCapForSend(capJws: string, ctx: CapSendContext): VerifiedCap {
      // TODO(phase2-wire): core/v3 verifyCapForSend(cap, {relayUrl, to, envFrom, kind, now}); keep the cache in front.
      // F-2: the stateless crypto result (parse, cert, signature) is cached by
      // JWS hash. Times and the per-send context are checked on every call;
      // revocation, `uses` and the allowlist are the relay's, on every send.
      const key = cacheSize > 0 && typeof capJws === "string" && capJws.length <= MAX_JWS_BYTES ? jwsHash(capJws) : undefined;
      let entry = key !== undefined ? capCache.get(key) : undefined;
      if (entry) {
        // Rule 5 for the cap's cert, again on every send.
        checkTimes(entry.certIat, entry.certExp, CERT_MAX_TTL, ctx.now);
        capCache.delete(key!);
      } else {
        entry = capCrypto(capJws, ctx.now);
        if (key !== undefined && capCache.size >= cacheSize) capCache.delete(capCache.keys().next().value as string);
      }
      if (key !== undefined) capCache.set(key, entry);
      const cap = entry.cap;
      if (cap.iss !== ctx.to) err("not-allowed", "cap.iss != to");
      if (cap.sub !== "*" && cap.sub !== ctx.envFrom) err("not-allowed", "cap.sub");
      if (!cap.relays.includes(ctx.relayUrl)) err("not-allowed", "relay not in cap.relays");
      if (!cap.kinds.includes("*") && !cap.kinds.includes(ctx.kind)) err("not-allowed", "kind not in cap.kinds");
      checkTimes(cap.iat, cap.exp, CAP_MAX_TTL, ctx.now);
      return { ...cap, relays: [...cap.relays], kinds: [...cap.kinds] };
    },

    powOk(envBytes: Uint8Array, powNonce: Uint8Array, bits: number): boolean {
      // TODO(phase2-wire): core/v3 powOk.
      if (bits <= 0) return true;
      const buf = new Uint8Array(envBytes.length + powNonce.length);
      buf.set(envBytes, 0);
      buf.set(powNonce, envBytes.length);
      const h = sha256(buf);
      let remaining = bits;
      for (const byte of h) {
        if (remaining <= 0) return true;
        if (remaining >= 8) {
          if (byte !== 0) return false;
          remaining -= 8;
        } else {
          return byte >> (8 - remaining) === 0;
        }
      }
      return remaining <= 0;
    },

    parseIdentityDoc(jws: string): IdentityDoc {
      // core/v3: typ, kid, the full payload rules (keyholders ⊆ devices, `by` a key
      // holder, canonical relays, lifetime), small-order ik, iss == H(ik), signature.
      if (typeof jws !== "string") err("malformed", "JWS must be a string");
      if (jws.length > MAX_JWS_BYTES) err("too-large");
      const d = guard("malformed", () => verifyIdentityDocSignature(jws));
      const doc: IdentityDoc = {
        jws,
        hash: d.hash,
        iss: d.iss,
        ver: d.ver,
        prev: d.prev,
        relays: d.relays,
        devices: d.devices,
        keyholders: d.keyholders,
        iat: d.iat,
        exp: d.exp,
      };
      if (d.merge !== undefined) doc.merge = d.merge;
      return doc;
    },

    verifyIdentityDocLink(prev: IdentityDoc, doc: IdentityDoc, merge?: IdentityDoc): void {
      // core/v3 verifyIdentityDocLink: chain, merge shape, devices and keyholders
      // only shrink in a merge. Time checks are the relay's own (iat skew), so
      // `now` is the document's iat.
      if (doc.merge === undefined && merge !== undefined) err("bad-link", "unexpected merge parent");
      guard("bad-link", () => coreVerifyIdentityDocLink(prev.jws, doc.jws, { now: doc.iat, ...(merge ? { merge: merge.jws } : {}) }));
    },

    isUserId(s: unknown): s is string {
      return typeof s === "string" && USER_ID_RE.test(s);
    },

    isDeviceId(s: unknown): s is string {
      return typeof s === "string" && DID_RE.test(s);
    },
  };
  return self;
}

/**
 * Test double: the real adapter with any methods replaced. Lets a test force
 * one crypto outcome (a cap that "verifies", a PoW that always passes) without
 * minting objects, and proves the relay reaches crypto only through this seam.
 */
export function testRelayCrypto(overrides: Partial<RelayCrypto> = {}): RelayCrypto {
  return { ...createRelayCrypto(), ...overrides };
}
