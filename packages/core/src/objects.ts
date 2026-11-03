// Copyright 2026 Ix Infrastructure Inc.
//
// Codecs and verifiers for every signed object in the v2 protocol
// (docs/protocol-v2.md): Kartr-signed device certificates, workspace
// attestations and revocation lists; device-signed invites, accepts,
// unfriends and session rosters; and the friendship pair.
//
// Verifiers never trust a payload field before the JWS checks (alg, typ, kid,
// signature) have passed; for device-signed objects the signer's certificate
// is verified first and the object is then checked against its `spk`.

import { b64uDecode, b64uEncode, utf8 } from "./encoding.js";
import { assertStrongEd25519PublicKey, assertStrongX25519PublicKey, randomBytes, sha256 } from "./crypto.js";
import { decodeJws, signJws, verifyJws } from "./jws.js";
import { fail } from "./errors.js";
import type { KartrKeys } from "./jwks.js";

export const TYP = {
  device: "p2p-device+jws",
  workspace: "p2p-workspace+jws",
  revocations: "p2p-revocations+jws",
  invite: "p2p-invite+jws",
  accept: "p2p-accept+jws",
  unfriend: "p2p-unfriend+jws",
  roster: "p2p-roster+jws",
  msg: "p2p-msg+jws",
  devreg: "p2p-devreg+jws",
} as const;

export const DEVICE_CERT_MAX_TTL_SEC = 30 * 24 * 3600;
export const WORKSPACE_MAX_TTL_SEC = 24 * 3600;
export const INVITE_MAX_TTL_SEC = 14 * 24 * 3600;
/** Tolerated clock skew for "issued in the future" checks. */
export const DEFAULT_SKEW_SEC = 300;

const DEVICE_ID_RE = /^d_[A-Za-z0-9_-]{22}$/;

// ---------------------------------------------------------------------------
// Identities

/** The spec's person key: the email, trimmed and lowercased. */
export function normalizeUserId(email: string): string {
  return email.trim().toLowerCase();
}

/** `d_` + b64u(16 random bytes). */
export function newDeviceId(): string {
  return `d_${b64uEncode(randomBytes(16))}`;
}

export function isDeviceId(s: unknown): s is string {
  return typeof s === "string" && DEVICE_ID_RE.test(s);
}

export function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

// ---------------------------------------------------------------------------
// Payload field validation

type Obj = Record<string, unknown>;

function str(o: Obj, k: string): string {
  const v = o[k];
  if (typeof v !== "string" || v === "") fail("malformed", `${k} must be a non-empty string`);
  return v;
}

function userId(o: Obj, k: string): string {
  const v = str(o, k);
  if (v !== normalizeUserId(v)) fail("malformed", `${k} is not a normalised userId`);
  return v;
}

function deviceId(o: Obj, k: string): string {
  const v = o[k];
  if (!isDeviceId(v)) fail("malformed", `${k} is not a deviceId`);
  return v;
}

function int(o: Obj, k: string, min = 0): number {
  const v = o[k];
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min) fail("malformed", `${k} must be an integer`);
  return v;
}

function bytes(o: Obj, k: string, len: number): string {
  const v = str(o, k);
  b64uDecode(v, len);
  return v;
}

function strArray(o: Obj, k: string, item: (s: string) => void = () => {}): string[] {
  const v = o[k];
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string" || x === "")) {
    fail("malformed", `${k} must be an array of strings`);
  }
  v.forEach(item);
  return v as string[];
}

function eq(o: Obj, k: string, expected: string): void {
  if (o[k] !== expected) fail("malformed", `${k} must be ${JSON.stringify(expected)}`);
}

function checkIssued(iat: number, now: number, skew: number): void {
  if (iat > now + skew) fail("not-yet-valid", `iat ${iat} is in the future`);
}

function checkExpiry(iat: number, exp: number, maxTtl: number, now: number, skew: number): void {
  if (exp <= iat) fail("malformed", "exp must be after iat");
  if (exp - iat > maxTtl) fail("malformed", `lifetime ${exp - iat}s exceeds ${maxTtl}s`);
  checkIssued(iat, now, skew);
  if (now >= exp) fail("expired", `expired at ${exp}`);
}

export interface TimeOptions {
  /** Current time in seconds (default: wall clock). */
  now?: number;
  skewSec?: number;
}

export interface KartrVerifyOptions extends TimeOptions {
  kartr: KartrKeys;
}

export interface CertVerifyOptions extends KartrVerifyOptions {
  /** Revocation check; a listed deviceId fails with device-revoked. */
  isRevoked?: (did: string) => boolean;
}

async function verifyKartrSigned(jws: string, typ: string, opts: KartrVerifyOptions) {
  const d = decodeJws(jws);
  // typ before key lookup, so typ confusion is reported as such.
  if (d.header.typ !== typ) fail("typ-mismatch", `typ ${d.header.typ} != ${typ}`);
  const key = await opts.kartr.resolve(d.header.kid);
  if (!key) fail("unknown-kartr-key", `kid ${d.header.kid}`);
  const v = verifyJws(jws, { typ, kid: d.header.kid, publicKey: key, badSignature: "kartr-signature-invalid" });
  eq(v.payload, "iss", "kartr");
  return v;
}

// ---------------------------------------------------------------------------
// Kartr-signed: device certificate

export interface DeviceCertPayload {
  iss: "kartr";
  sub: string;
  did: string;
  spk: string;
  kpk: string;
  iat: number;
  exp: number;
}

export interface DeviceCert extends DeviceCertPayload {
  jws: string;
  kid: string;
  signingPublicKey: Uint8Array;
  agreementPublicKey: Uint8Array;
}

/** Kartr side (tests and local-dev authority only). */
export function signDeviceCert(payload: Omit<DeviceCertPayload, "iss">, kartrSecretKey: Uint8Array, kid: string): string {
  return signJws(TYP.device, kid, { iss: "kartr", ...payload }, kartrSecretKey);
}

export async function verifyDeviceCert(jws: string, opts: CertVerifyOptions): Promise<DeviceCert> {
  const now = opts.now ?? nowSec();
  const skew = opts.skewSec ?? DEFAULT_SKEW_SEC;
  const d = await verifyKartrSigned(jws, TYP.device, opts);
  const p = d.payload;
  const cert: DeviceCert = {
    iss: "kartr",
    sub: userId(p, "sub"),
    did: deviceId(p, "did"),
    spk: bytes(p, "spk", 32),
    kpk: bytes(p, "kpk", 32),
    iat: int(p, "iat"),
    exp: int(p, "exp"),
    jws,
    kid: d.header.kid,
    signingPublicKey: b64uDecode(p.spk as string),
    agreementPublicKey: b64uDecode(p.kpk as string),
  };
  assertStrongEd25519PublicKey(cert.signingPublicKey);
  assertStrongX25519PublicKey(cert.agreementPublicKey);
  checkExpiry(cert.iat, cert.exp, DEVICE_CERT_MAX_TTL_SEC, now, skew);
  if (opts.isRevoked?.(cert.did)) fail("device-revoked", cert.did);
  return cert;
}

// ---------------------------------------------------------------------------
// Kartr-signed: workspace attestation

export interface WorkspaceAttestationPayload {
  iss: "kartr";
  sub: string;
  orgs: string[];
  iat: number;
  exp: number;
}

export interface WorkspaceAttestation extends WorkspaceAttestationPayload {
  jws: string;
}

export function signWorkspaceAttestation(
  payload: Omit<WorkspaceAttestationPayload, "iss">,
  kartrSecretKey: Uint8Array,
  kid: string,
): string {
  return signJws(TYP.workspace, kid, { iss: "kartr", ...payload }, kartrSecretKey);
}

export async function verifyWorkspaceAttestation(jws: string, opts: KartrVerifyOptions): Promise<WorkspaceAttestation> {
  const now = opts.now ?? nowSec();
  const skew = opts.skewSec ?? DEFAULT_SKEW_SEC;
  const p = (await verifyKartrSigned(jws, TYP.workspace, opts)).payload;
  const a: WorkspaceAttestation = {
    iss: "kartr",
    sub: userId(p, "sub"),
    orgs: strArray(p, "orgs"),
    iat: int(p, "iat"),
    exp: int(p, "exp"),
    jws,
  };
  checkExpiry(a.iat, a.exp, WORKSPACE_MAX_TTL_SEC, now, skew);
  return a;
}

// ---------------------------------------------------------------------------
// Kartr-signed: revocation list

export interface RevocationListPayload {
  iss: "kartr";
  dids: string[];
  iat: number;
}

export interface RevocationList extends RevocationListPayload {
  jws: string;
}

export function signRevocationList(
  payload: Omit<RevocationListPayload, "iss">,
  kartrSecretKey: Uint8Array,
  kid: string,
): string {
  return signJws(TYP.revocations, kid, { iss: "kartr", ...payload }, kartrSecretKey);
}

export async function verifyRevocationList(jws: string, opts: KartrVerifyOptions): Promise<RevocationList> {
  const now = opts.now ?? nowSec();
  const p = (await verifyKartrSigned(jws, TYP.revocations, opts)).payload;
  const r: RevocationList = {
    iss: "kartr",
    dids: strArray(p, "dids", (s) => {
      if (!isDeviceId(s)) fail("malformed", `dids entry ${s} is not a deviceId`);
    }),
    iat: int(p, "iat"),
    jws,
  };
  checkIssued(r.iat, now, opts.skewSec ?? DEFAULT_SKEW_SEC);
  return r;
}

// ---------------------------------------------------------------------------
// Device-signed objects

/** What a device needs to sign: its identity and its Ed25519 secret key. */
export interface DeviceSigner {
  userId: string;
  deviceId: string;
  signingSecretKey: Uint8Array;
}

/** Looks up a device certificate (compact JWS) by owner and deviceId. */
export type CertResolver = (userId: string, did: string) => Promise<string | undefined>;

export interface DeviceVerifyOptions extends CertVerifyOptions {
  resolveCert: CertResolver;
}

export interface VerifiedDeviceObject {
  payload: Obj;
  signer: DeviceCert;
}

/**
 * Verifies a device-signed object: the signer's certificate first (Kartr
 * signature, expiry, revocation, `did == kid`, `sub == iss`), then the JWS
 * against the certificate's `spk`.
 */
export async function verifyDeviceSigned(
  jws: string,
  typ: string,
  opts: DeviceVerifyOptions,
): Promise<VerifiedDeviceObject> {
  const d = decodeJws(jws);
  if (d.header.typ !== typ) fail("typ-mismatch", `typ ${d.header.typ} != ${typ}`);
  // Untrusted until the signature passes: used only to find the certificate.
  const iss = userId(d.payload, "iss");
  const did = deviceId(d.payload, "did");
  if (d.header.kid !== did) fail("kid-mismatch", `kid ${d.header.kid} != did ${did}`);
  const certJws = await opts.resolveCert(iss, did);
  if (!certJws) fail("unknown-device", `${iss}/${did}`);
  const signer = await verifyDeviceCert(certJws, opts);
  if (signer.did !== d.header.kid) fail("kid-mismatch", `kid ${d.header.kid} != cert did ${signer.did}`);
  if (signer.sub !== iss) fail("cert-mismatch", `cert sub ${signer.sub} != iss ${iss}`);
  const v = verifyJws(jws, { typ, kid: signer.did, publicKey: signer.signingPublicKey });
  return { payload: v.payload, signer };
}

// --- invite -----------------------------------------------------------------

export interface InvitePayload {
  iss: string;
  did: string;
  aud: string;
  nonce: string;
  iat: number;
  exp: number;
}

export function createInvite(
  signer: DeviceSigner,
  opts: { aud: string; iat?: number; ttlSec?: number; nonce?: string },
): string {
  const iat = opts.iat ?? nowSec();
  const ttl = opts.ttlSec ?? INVITE_MAX_TTL_SEC;
  if (ttl <= 0 || ttl > INVITE_MAX_TTL_SEC) fail("malformed", "invite ttl must be in (0, 14d]");
  const payload: InvitePayload = {
    iss: signer.userId,
    did: signer.deviceId,
    aud: opts.aud === "*" ? "*" : normalizeUserId(opts.aud),
    nonce: opts.nonce ?? b64uEncode(randomBytes(16)),
    iat,
    exp: iat + ttl,
  };
  return signJws(TYP.invite, signer.deviceId, payload, signer.signingSecretKey);
}

function invitePayload(p: Obj): InvitePayload {
  const aud = str(p, "aud");
  if (aud !== "*") userId(p, "aud");
  const inv: InvitePayload = {
    iss: userId(p, "iss"),
    did: deviceId(p, "did"),
    aud,
    nonce: bytes(p, "nonce", 16),
    iat: int(p, "iat"),
    exp: int(p, "exp"),
  };
  if (inv.exp <= inv.iat || inv.exp - inv.iat > INVITE_MAX_TTL_SEC) fail("malformed", "invite exp must be in (iat, iat+14d]");
  return inv;
}

export interface VerifiedInvite extends InvitePayload {
  jws: string;
  hash: string;
  signer: DeviceCert;
}

/** `b64u(sha256(invite compact))`: the `inv` that accepts and unfriends cite. */
export function inviteHash(inviteJws: string): string {
  return b64uEncode(sha256(utf8(inviteJws)));
}

/** Verifies an invite for redemption now: it must also be unexpired. */
export async function verifyInvite(jws: string, opts: DeviceVerifyOptions): Promise<VerifiedInvite> {
  const now = opts.now ?? nowSec();
  const v = await verifyDeviceSigned(jws, TYP.invite, opts);
  const p = invitePayload(v.payload);
  checkIssued(p.iat, now, opts.skewSec ?? DEFAULT_SKEW_SEC);
  if (now >= p.exp) fail("invite-expired", `invite expired at ${p.exp}`);
  return { ...p, jws, hash: inviteHash(jws), signer: v.signer };
}

// --- accept -----------------------------------------------------------------

export interface AcceptPayload {
  iss: string;
  did: string;
  inv: string;
  iat: number;
}

export function createAccept(signer: DeviceSigner, inviteJws: string, opts: { iat?: number } = {}): string {
  const payload: AcceptPayload = {
    iss: signer.userId,
    did: signer.deviceId,
    inv: inviteHash(inviteJws),
    iat: opts.iat ?? nowSec(),
  };
  return signJws(TYP.accept, signer.deviceId, payload, signer.signingSecretKey);
}

// --- friendship (the pair) ----------------------------------------------------

export interface FriendshipProof {
  invite: string;
  accept: string;
}

export interface VerifiedFriendship {
  inviter: string;
  invitee: string;
  /** Hash of the invite: the friendship's identity. */
  inv: string;
  /** The invite's audience: an explicit userId, or "*" (first accepter binds). */
  aud: string;
  /** When the friendship came into being (the accept's iat). */
  iat: number;
  /** When its invite was issued: unfriends issued at or after this kill it. */
  inviteIat: number;
  invite: InvitePayload;
  accept: AcceptPayload;
  proof: FriendshipProof;
}

/**
 * Verifies `{invite, accept}`. Both signer certificates must currently be
 * valid. The invite must have been unexpired when accepted (accept.iat in
 * [invite.iat - skew, invite.exp)), and the accepter must be the invite's
 * `aud` or the invite must be `aud:"*"`.
 */
export async function verifyFriendship(proof: FriendshipProof, opts: DeviceVerifyOptions): Promise<VerifiedFriendship> {
  if (typeof proof !== "object" || proof === null) fail("malformed", "friendship must be {invite, accept}");
  const now = opts.now ?? nowSec();
  const skew = opts.skewSec ?? DEFAULT_SKEW_SEC;
  const iv = await verifyDeviceSigned(proof.invite, TYP.invite, opts);
  const invite = invitePayload(iv.payload);
  const av = await verifyDeviceSigned(proof.accept, TYP.accept, opts);
  const accept: AcceptPayload = {
    iss: userId(av.payload, "iss"),
    did: deviceId(av.payload, "did"),
    inv: bytes(av.payload, "inv", 32),
    iat: int(av.payload, "iat"),
  };
  const inv = inviteHash(proof.invite);
  if (accept.inv !== inv) fail("invite-mismatch", "accept.inv does not hash the invite");
  if (accept.iss === invite.iss) fail("self-friendship");
  if (invite.aud !== "*" && invite.aud !== accept.iss) fail("audience-mismatch", `invite is for ${invite.aud}`);
  if (accept.iat >= invite.exp) fail("invite-expired", "accepted after the invite expired");
  if (accept.iat < invite.iat - skew) fail("invite-mismatch", "accepted before the invite was issued");
  checkIssued(accept.iat, now, skew);
  return {
    inviter: invite.iss,
    invitee: accept.iss,
    inv,
    aud: invite.aud,
    iat: accept.iat,
    inviteIat: invite.iat,
    invite,
    accept,
    proof,
  };
}

// --- unfriend -----------------------------------------------------------------

export interface UnfriendPayload {
  iss: string;
  did: string;
  peer: string;
  inv: string;
  iat: number;
}

export interface VerifiedUnfriend extends UnfriendPayload {
  jws: string;
}

export function createUnfriend(signer: DeviceSigner, opts: { peer: string; inv: string; iat?: number }): string {
  const payload: UnfriendPayload = {
    iss: signer.userId,
    did: signer.deviceId,
    peer: normalizeUserId(opts.peer),
    inv: opts.inv,
    iat: opts.iat ?? nowSec(),
  };
  return signJws(TYP.unfriend, signer.deviceId, payload, signer.signingSecretKey);
}

export async function verifyUnfriend(jws: string, opts: DeviceVerifyOptions): Promise<VerifiedUnfriend> {
  const p = (await verifyDeviceSigned(jws, TYP.unfriend, opts)).payload;
  const u: VerifiedUnfriend = {
    iss: userId(p, "iss"),
    did: deviceId(p, "did"),
    peer: userId(p, "peer"),
    inv: bytes(p, "inv", 32),
    iat: int(p, "iat"),
    jws,
  };
  checkIssued(u.iat, opts.now ?? nowSec(), opts.skewSec ?? DEFAULT_SKEW_SEC);
  return u;
}

/**
 * True when `u` ends friendship `f`. An unfriend between a pair (from either
 * side) kills:
 *  - the friendship built on the invite it names (`inv`), whatever the
 *    accept's iat (H1), and
 *  - every friendship of that pair whose INVITE was issued at or before the
 *    unfriend (`invite.iat <= unfriend.iat`), whoever issued it. Other invites
 *    still open at unfriend time (a shared `aud:"*"` code, a second invite)
 *    can't be used to re-friend.
 * Only an invite issued after the unfriend can re-friend.
 */
export function unfriendApplies(
  f: Pick<VerifiedFriendship, "inviter" | "invitee" | "inv" | "inviteIat">,
  u: Pick<UnfriendPayload, "iss" | "peer" | "inv" | "iat">,
): boolean {
  const samePair =
    (u.iss === f.inviter && u.peer === f.invitee) || (u.iss === f.invitee && u.peer === f.inviter);
  return samePair && (u.inv === f.inv || f.inviteIat <= u.iat);
}

// --- roster -------------------------------------------------------------------

export type RosterVisibility = "workspace" | "private";

export interface RosterPayload {
  iss: string;
  did: string;
  sid: string;
  ver: number;
  vis: RosterVisibility;
  org: string;
  parts: string[];
  iat: number;
}

export interface VerifiedRoster extends RosterPayload {
  jws: string;
}

export function createRoster(
  signer: DeviceSigner,
  opts: { sid: string; ver: number; vis: RosterVisibility; org: string; parts: string[]; iat?: number },
): string {
  const payload: RosterPayload = {
    iss: signer.userId,
    did: signer.deviceId,
    sid: opts.sid,
    ver: opts.ver,
    vis: opts.vis,
    org: opts.org,
    parts: opts.parts.map(normalizeUserId),
    iat: opts.iat ?? nowSec(),
  };
  rosterPayload(payload as unknown as Obj);
  return signJws(TYP.roster, signer.deviceId, payload, signer.signingSecretKey);
}

function rosterPayload(p: Obj): RosterPayload {
  const vis = p.vis;
  if (vis !== "workspace" && vis !== "private") fail("malformed", "vis must be workspace|private");
  return {
    iss: userId(p, "iss"),
    did: deviceId(p, "did"),
    sid: str(p, "sid"),
    ver: int(p, "ver"),
    vis,
    org: str(p, "org"),
    parts: strArray(p, "parts", (s) => {
      if (s !== normalizeUserId(s)) fail("malformed", `parts entry ${s} is not a normalised userId`);
    }),
    iat: int(p, "iat"),
  };
}

export async function verifyRoster(jws: string, opts: DeviceVerifyOptions): Promise<VerifiedRoster> {
  const p = rosterPayload((await verifyDeviceSigned(jws, TYP.roster, opts)).payload);
  checkIssued(p.iat, opts.now ?? nowSec(), opts.skewSec ?? DEFAULT_SKEW_SEC);
  return { ...p, jws };
}

// --- device registration proof ------------------------------------------------

export interface DevregPayload {
  did: string;
  spk: string;
  kpk: string;
  sub: string;
  nonce: string;
  iat: number;
}

/**
 * `p2p-devreg+jws` over `{did, spk, kpk, sub, nonce, iat}`, signed with the
 * new device's own `spk` (kid = deviceId): proof of possession for
 * `POST /v1/p2p/devices`.
 */
export function createDevregProof(
  signer: DeviceSigner,
  keys: { signingPublicKey: Uint8Array; agreementPublicKey: Uint8Array },
  opts: { nonce?: string; iat?: number } = {},
): string {
  const payload: DevregPayload = {
    did: signer.deviceId,
    spk: b64uEncode(keys.signingPublicKey),
    kpk: b64uEncode(keys.agreementPublicKey),
    sub: signer.userId,
    nonce: opts.nonce ?? b64uEncode(randomBytes(16)),
    iat: opts.iat ?? nowSec(),
  };
  return signJws(TYP.devreg, signer.deviceId, payload, signer.signingSecretKey);
}

/** Verifies a devreg proof against the `spk` it carries (what Kartr does). */
export function verifyDevregProof(jws: string): DevregPayload {
  const d = decodeJws(jws);
  if (d.header.typ !== TYP.devreg) fail("typ-mismatch", `typ ${d.header.typ} != ${TYP.devreg}`);
  const p = d.payload;
  const out: DevregPayload = {
    did: deviceId(p, "did"),
    spk: bytes(p, "spk", 32),
    kpk: bytes(p, "kpk", 32),
    sub: userId(p, "sub"),
    nonce: str(p, "nonce"),
    iat: int(p, "iat"),
  };
  // Key validation before the signature: a small-order spk can make a forged
  // signature pass a bare Ed25519 check.
  assertStrongEd25519PublicKey(b64uDecode(out.spk));
  assertStrongX25519PublicKey(b64uDecode(out.kpk));
  verifyJws(jws, { typ: TYP.devreg, kid: out.did, publicKey: b64uDecode(out.spk) });
  return out;
}
