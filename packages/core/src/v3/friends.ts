// Copyright 2026 Ix Infrastructure Inc.
//
// Friends (docs/protocol.md §3.1): v2's `p2p-invite+jws`, `p2p-accept+jws`,
// `p2p-unfriend+jws` and the friendship certificate `{invite, accept}`, with
// every v2 rule (docs/protocol-v2.md, "Objects signed by a device",
// C4 and H1), on v3 userIds and §2.3 certificates.
//
//  - An accept is valid only if `inv` hashes an invite that was unexpired when
//    accepted (`invite.iat - skew <= accept.iat < invite.exp`), and whose
//    `aud` is the accepter or "*".
//  - Both signer certificates must be valid now (rules 1–6), so revoking
//    either signing device ends the friendship.
//  - [H1] An unfriend between a pair (either side) kills the friendship built
//    on the invite it names, whatever the accept's iat, and every friendship
//    of that pair whose invite was issued at or before the unfriend. Only an
//    invite issued after the unfriend can re-friend.
//  - [H1] The viewer's side of authorisation uses only friendships from the
//    viewer's own store; a presented proof counts for the sender's side only.
//
// [v3] New invite fields: `ik`, `relays` and `doc` (the inviter's identity
// document) let the invitee reach the inviter with no lookup; `cap` is a
// contact-only capability for the invitee's first `contact` envelope. The
// invitee's friend cap rides in the accept (§5.3), together with its
// identity document (`doc`), so the inviter can reach it in turn.

import { b64uDecode, b64uEncode, fromUtf8, utf8 } from "../encoding.js";
import { randomBytes } from "../crypto.js";
import { signJws, MAX_JWS_BYTES } from "../jws.js";
import { fail } from "../errors.js";
import { unfriendApplies } from "../objects.js";
import {
  bytesField,
  checkIssued,
  decodeTyped,
  DEFAULT_SKEW_SEC,
  didField,
  INVITE_MAX_TTL_SEC,
  int,
  isUserId,
  jwsHash,
  MAX_RELAYS,
  checkFields,
  nowSec,
  str,
  strArray,
  TYP3,
  userIdField,
  userIdFromIk,
} from "./base.js";
import { verifyCap, type VerifiedCap } from "./caps.js";
import type { VerifiedDeviceCertV3 } from "./device.js";
import { assertNotFailClosed, verifyIdentityDoc, type VerifiedIdentityDoc } from "./identitydoc.js";
import { isCanonicalRelayUrl } from "./relayurl.js";
import { verifyDeviceSignedV3, type AllowlistView, type SignerContext } from "./signers.js";

export { unfriendApplies };

/** A v3 device that signs: its user, did and Ed25519 secret. */
export interface DeviceSignerV3 {
  userId: string;
  did: string;
  signingSecretKey: Uint8Array;
}

// --- invite -----------------------------------------------------------------

export interface InviteV3Payload {
  iss: string;
  did: string;
  aud: string;
  nonce: string;
  iat: number;
  exp: number;
  ik?: string;
  relays?: string[];
  doc?: string;
  cap?: string;
}

export interface CreateInviteParams {
  aud: string;
  iat?: number;
  ttlSec?: number;
  nonce?: string;
  /** b64u of the inviter's ik. */
  ik?: string;
  relays?: string[];
  /** The inviter's current identity document. */
  doc?: string;
  /** A contact-only cap for the invitee (§5.3). */
  cap?: string;
}

export function createInviteV3(signer: DeviceSignerV3, p: CreateInviteParams): string {
  const iat = p.iat ?? nowSec();
  const ttl = p.ttlSec ?? INVITE_MAX_TTL_SEC;
  if (ttl <= 0 || ttl > INVITE_MAX_TTL_SEC) fail("malformed", "invite ttl must be in (0, 14d]");
  const payload: InviteV3Payload = {
    iss: signer.userId,
    did: signer.did,
    aud: p.aud,
    nonce: p.nonce ?? b64uEncode(randomBytes(16)),
    iat,
    exp: iat + ttl,
    ...(p.ik !== undefined ? { ik: p.ik } : {}),
    ...(p.relays !== undefined ? { relays: p.relays } : {}),
    ...(p.doc !== undefined ? { doc: p.doc } : {}),
    ...(p.cap !== undefined ? { cap: p.cap } : {}),
  };
  invitePayload(payload as unknown as Record<string, unknown>);
  const jws = signJws(TYP3.invite, signer.did, payload, signer.signingSecretKey);
  if (jws.length > MAX_JWS_BYTES) fail("malformed", `invite is ${jws.length} bytes, max ${MAX_JWS_BYTES}`);
  return jws;
}

function invitePayload(p: Record<string, unknown>): InviteV3Payload {
  checkFields(p, ["iss", "did", "aud", "nonce", "iat", "exp", "ik", "relays", "doc", "cap"], "invite");
  const aud = str(p, "aud");
  if (aud !== "*" && !isUserId(aud)) fail("malformed", "aud must be a userId or *");
  const inv: InviteV3Payload = {
    iss: userIdField(p, "iss"),
    did: didField(p, "did"),
    aud,
    nonce: bytesField(p, "nonce", 16),
    iat: int(p, "iat"),
    exp: int(p, "exp"),
  };
  if (inv.exp <= inv.iat || inv.exp - inv.iat > INVITE_MAX_TTL_SEC) fail("malformed", "invite exp must be in (iat, iat+14d]");
  if (p.ik !== undefined) {
    inv.ik = bytesField(p, "ik", 32);
    if (userIdFromIk(b64uDecode(inv.ik, 32)) !== inv.iss) fail("issuer-mismatch", "invite ik is not the inviter's");
  }
  if (p.relays !== undefined) {
    inv.relays = strArray(p, "relays", {
      max: MAX_RELAYS,
      item: (r) => {
        if (!isCanonicalRelayUrl(r)) fail("malformed", `invite relay ${r} is not canonical`);
      },
    });
  }
  if (p.doc !== undefined) inv.doc = str(p, "doc");
  if (p.cap !== undefined) inv.cap = str(p, "cap");
  return inv;
}

export interface VerifiedInviteV3 extends InviteV3Payload {
  jws: string;
  /** jwsHash(invite): the `inv` that accepts and unfriends cite. */
  hash: string;
  signer: VerifiedDeviceCertV3;
  /** The bundled identity document, verified (signature, iss and ik). */
  inviterDoc?: VerifiedIdentityDoc;
  /** The bundled contact-only cap, verified. */
  contactCap?: VerifiedCap;
  /** Rule 6 used the bundled document (the store knew nothing of the inviter): re-verify before acting on approval. */
  provisional: boolean;
}

/** `b64u(sha256(invite compact))`. */
export function inviteHashV3(inviteJws: string): string {
  return jwsHash(inviteJws);
}

/**
 * How a bundled identity document (an invite's or accept's `doc`) may be used.
 *  - `bundled: true` (the default, for a first contact): the document may
 *    stand in as the rule-6 allowlist when the store knows nothing of the
 *    signer. It must verify and must not be in the §2.5 fail-closed state,
 *    and the result is marked `provisional`: before acting on the user's
 *    approval the client refreshes the head from the relays the document
 *    lists and re-verifies against its stored chain (pre-release review M1;
 *    state.ts reverifyInviteForApproval / reverifyFriendshipForApproval).
 *  - `bundled: false`: bundled documents are ignored entirely; rule 6 runs
 *    only against the stored chain. Stored friendships always re-verify this
 *    way, so a stale document carried in an old invite never counts.
 */
export interface BundledDocOptions {
  bundled?: boolean;
}

function checkBundledDoc(docJws: string, iss: string, ctx: SignerContext, what: string): VerifiedIdentityDoc {
  const doc = verifyIdentityDoc(docJws, ctx);
  if (doc.iss !== iss) fail("issuer-mismatch", `${what} doc is another identity's`);
  assertNotFailClosed(doc.exp, ctx.now ?? nowSec());
  return doc;
}

/**
 * The bundled document as an allowlist source for a signer the store doesn't
 * know. A stored view of the signer, from `ctx.resolveIdentity`, always
 * takes precedence.
 */
function withBundledDoc(ctx: SignerContext, doc: VerifiedIdentityDoc | undefined): SignerContext {
  if (!doc) return ctx;
  return {
    ...ctx,
    resolveIdentity: async (u) => (await ctx.resolveIdentity(u)) ?? (u === doc.iss ? docView(doc) : undefined),
  };
}

export function docView(doc: VerifiedIdentityDoc): AllowlistView {
  return { iss: doc.iss, ik: doc.ik, devices: doc.devices };
}

async function verifyInviteObject(jws: string, ctx: SignerContext, opts: BundledDocOptions = {}): Promise<VerifiedInviteV3> {
  const useBundled = opts.bundled ?? true;
  const peek = invitePayload(decodeTyped(jws, TYP3.invite).payload);
  const stored = await ctx.resolveIdentity(peek.iss);
  let inviterDoc: VerifiedIdentityDoc | undefined;
  if (peek.doc !== undefined && useBundled) {
    inviterDoc = checkBundledDoc(peek.doc, peek.iss, ctx, "invite");
    if (peek.ik !== undefined && inviterDoc.ik !== peek.ik) fail("issuer-mismatch", "invite doc and ik differ");
  }
  const allowlist = stored ?? (inviterDoc ? docView(inviterDoc) : undefined);
  let contactCap: VerifiedCap | undefined;
  const extraCerts = [...(inviterDoc?.certs ?? [])];
  if (peek.cap !== undefined) {
    contactCap = verifyCap(peek.cap, { now: ctx.now, skewSec: ctx.skewSec, purpose: "contact", identityDoc: allowlist });
    if (contactCap.iss !== peek.iss) fail("cap-invalid", "invite cap is not the inviter's");
    if (contactCap.sub !== "*" && contactCap.sub !== peek.aud) fail("cap-invalid", "invite cap is for someone else");
    extraCerts.push(contactCap.cert);
  }
  const v = await verifyDeviceSignedV3(jws, TYP3.invite, withBundledDoc(ctx, inviterDoc), { extraCerts });
  return {
    ...invitePayload(v.payload),
    jws,
    hash: inviteHashV3(jws),
    signer: v.signer,
    provisional: !stored,
    ...(inviterDoc ? { inviterDoc } : {}),
    ...(contactCap ? { contactCap } : {}),
  };
}

/** Verifies an invite for redemption now: it must also be unexpired and not issued in the future. */
export async function verifyInviteV3(jws: string, ctx: SignerContext, opts: BundledDocOptions = {}): Promise<VerifiedInviteV3> {
  const now = ctx.now ?? nowSec();
  const inv = await verifyInviteObject(jws, ctx, opts);
  checkIssued(inv.iat, now, ctx.skewSec ?? DEFAULT_SKEW_SEC);
  if (now >= inv.exp) fail("invite-expired", `invite expired at ${inv.exp}`);
  return inv;
}

// --- invite links (§3.1) ---------------------------------------------------------

export const INVITE_LINK_PREFIX = "p2p://invite/";
export const INVITE_WEB_PREFIX = "https://ix-infra.com/p2p/i#";
/**
 * Deprecated web forms: still parsed (parsing is local, and older clients
 * printed them), never generated. See protocol.md §3.1.
 */
export const LEGACY_INVITE_WEB_PREFIXES: readonly string[] = ["https://peer2peer.dev/i#"];

/** `p2p://invite/<b64u(invite jws)>`; `web: true` gives `https://ix-infra.com/p2p/i#<same>` (the fragment never reaches the server). */
export function inviteLink(inviteJws: string, opts: { web?: boolean } = {}): string {
  return (opts.web ? INVITE_WEB_PREFIX : INVITE_LINK_PREFIX) + b64uEncode(utf8(inviteJws));
}

export function parseInviteLink(link: string): string {
  const s = typeof link === "string" ? link.trim() : "";
  const prefix = [INVITE_LINK_PREFIX, INVITE_WEB_PREFIX, ...LEGACY_INVITE_WEB_PREFIXES].find((p) => s.startsWith(p));
  if (prefix === undefined) fail("malformed", "not an invite link");
  const body = s.slice(prefix.length);
  return fromUtf8(b64uDecode(body));
}

// --- accept -----------------------------------------------------------------

export interface AcceptV3Payload {
  iss: string;
  did: string;
  inv: string;
  iat: number;
  /** The invitee's friend cap for the inviter (§5.3). */
  cap?: string;
  /** The invitee's identity document, so the inviter can reach it. */
  doc?: string;
}

export function createAcceptV3(signer: DeviceSignerV3, inviteJws: string, opts: { iat?: number; cap?: string; doc?: string } = {}): string {
  const payload: AcceptV3Payload = {
    iss: signer.userId,
    did: signer.did,
    inv: inviteHashV3(inviteJws),
    iat: opts.iat ?? nowSec(),
    ...(opts.cap !== undefined ? { cap: opts.cap } : {}),
    ...(opts.doc !== undefined ? { doc: opts.doc } : {}),
  };
  const jws = signJws(TYP3.accept, signer.did, payload, signer.signingSecretKey);
  if (jws.length > MAX_JWS_BYTES) fail("malformed", `accept is ${jws.length} bytes, max ${MAX_JWS_BYTES}`);
  return jws;
}

function acceptPayload(p: Record<string, unknown>): AcceptV3Payload {
  checkFields(p, ["iss", "did", "inv", "iat", "cap", "doc"], "accept");
  const a: AcceptV3Payload = { iss: userIdField(p, "iss"), did: didField(p, "did"), inv: bytesField(p, "inv", 32), iat: int(p, "iat") };
  if (p.cap !== undefined) a.cap = str(p, "cap");
  if (p.doc !== undefined) a.doc = str(p, "doc");
  return a;
}

// --- friendship -----------------------------------------------------------------

export interface FriendshipProofV3 {
  invite: string;
  accept: string;
}

export interface VerifiedFriendshipV3 {
  inviter: string;
  invitee: string;
  inv: string;
  aud: string;
  /** The accept's iat. */
  iat: number;
  /** The invite's iat: unfriends issued at or after it kill the friendship. */
  inviteIat: number;
  invite: InviteV3Payload;
  accept: AcceptV3Payload;
  inviteSigner: VerifiedDeviceCertV3;
  acceptSigner: VerifiedDeviceCertV3;
  /** The invitee's friend cap from the accept, verified, when present. */
  inviteeCap?: VerifiedCap;
  inviteeDoc?: VerifiedIdentityDoc;
  /** Rule 6 for a signer used a bundled document (the store knew nothing of it): re-verify before acting on approval. */
  provisional: boolean;
  /** Set by reverifyFriendshipForApproval: re-verified against refreshed, stored identities (seconds). */
  reverifiedAt?: number;
  proof: FriendshipProofV3;
}

/**
 * Verifies `{invite, accept}` (v2 C4 on v3 ids): both signer certificates
 * valid now (rules 1–6), accept.inv hashes the invite, no self-friendship,
 * the accepter is the invite's aud (or aud "*"), and the invite was unexpired
 * when accepted: `invite.iat - skew <= accept.iat < invite.exp`.
 */
export async function verifyFriendshipV3(proof: FriendshipProofV3, ctx: SignerContext, opts: BundledDocOptions = {}): Promise<VerifiedFriendshipV3> {
  if (typeof proof !== "object" || proof === null || typeof proof.invite !== "string" || typeof proof.accept !== "string") {
    fail("malformed", "friendship must be {invite, accept}");
  }
  const now = ctx.now ?? nowSec();
  const skew = ctx.skewSec ?? DEFAULT_SKEW_SEC;
  const iv = await verifyInviteObject(proof.invite, ctx, opts);
  const peekAccept = acceptPayload(decodeTyped(proof.accept, TYP3.accept).payload);
  const storedInvitee = await ctx.resolveIdentity(peekAccept.iss);
  let inviteeDoc: VerifiedIdentityDoc | undefined;
  if (peekAccept.doc !== undefined && (opts.bundled ?? true)) inviteeDoc = checkBundledDoc(peekAccept.doc, peekAccept.iss, ctx, "accept");
  const av = await verifyDeviceSignedV3(proof.accept, TYP3.accept, withBundledDoc(ctx, inviteeDoc), { extraCerts: inviteeDoc?.certs });
  const accept = acceptPayload(av.payload);
  const inv = inviteHashV3(proof.invite);
  if (accept.inv !== inv) fail("invite-mismatch", "accept.inv does not hash the invite");
  if (accept.iss === iv.iss) fail("self-friendship");
  if (iv.aud !== "*" && iv.aud !== accept.iss) fail("audience-mismatch", `invite is for ${iv.aud}`);
  if (accept.iat >= iv.exp) fail("invite-expired", "accepted after the invite expired");
  if (accept.iat < iv.iat - skew) fail("invite-mismatch", "accepted before the invite was issued");
  checkIssued(accept.iat, now, skew);
  let inviteeCap: VerifiedCap | undefined;
  if (accept.cap !== undefined) {
    inviteeCap = verifyCap(accept.cap, { now, skewSec: skew, purpose: "friend", identityDoc: storedInvitee ?? (inviteeDoc ? docView(inviteeDoc) : undefined) });
    if (inviteeCap.iss !== accept.iss || inviteeCap.sub !== iv.iss) fail("cap-invalid", "accept cap must be from the invitee for the inviter");
  }
  const { jws: _j, hash: _h, signer: _s, inviterDoc: _d, contactCap: _c, provisional: _p, ...invite } = iv;
  return {
    inviter: iv.iss,
    invitee: accept.iss,
    inv,
    aud: iv.aud,
    iat: accept.iat,
    inviteIat: iv.iat,
    invite,
    accept,
    inviteSigner: iv.signer,
    acceptSigner: av.signer,
    ...(inviteeCap ? { inviteeCap } : {}),
    ...(inviteeDoc ? { inviteeDoc } : {}),
    provisional: iv.provisional || !storedInvitee,
    proof,
  };
}

// --- unfriend -----------------------------------------------------------------

export interface UnfriendV3Payload {
  iss: string;
  did: string;
  peer: string;
  inv: string;
  iat: number;
}

export interface VerifiedUnfriendV3 extends UnfriendV3Payload {
  jws: string;
}

export function createUnfriendV3(signer: DeviceSignerV3, opts: { peer: string; inv: string; iat?: number }): string {
  if (!isUserId(opts.peer)) fail("malformed", "peer must be a v3 userId");
  const payload: UnfriendV3Payload = { iss: signer.userId, did: signer.did, peer: opts.peer, inv: opts.inv, iat: opts.iat ?? nowSec() };
  return signJws(TYP3.unfriend, signer.did, payload, signer.signingSecretKey);
}

export async function verifyUnfriendV3(jws: string, ctx: SignerContext): Promise<VerifiedUnfriendV3> {
  const p = (await verifyDeviceSignedV3(jws, TYP3.unfriend, ctx)).payload;
  checkFields(p, ["iss", "did", "peer", "inv", "iat"], "unfriend");
  const u: VerifiedUnfriendV3 = {
    iss: userIdField(p, "iss"),
    did: didField(p, "did"),
    peer: userIdField(p, "peer"),
    inv: bytesField(p, "inv", 32),
    iat: int(p, "iat"),
    jws,
  };
  if (u.peer === u.iss) fail("malformed", "unfriend names its own issuer");
  checkIssued(u.iat, ctx.now ?? nowSec(), ctx.skewSec ?? DEFAULT_SKEW_SEC);
  return u;
}

/**
 * The `iat` for a new invite from `self` to `aud` (a userId, or "*" for anyone), so that no
 * unfriend this client knows of ends the friendship it makes: `unfriendApplies` ends every
 * friendship of a pair whose invite was issued at or before the unfriend (whole seconds), so the
 * invite must be dated strictly after it. That is `now`, or one second past the latest unfriend
 * between `self` and `aud` (for "*", between `self` and anyone), whichever is later. Unfriends
 * are dated by their signer's clock, so this also covers a peer whose clock runs ahead of ours
 * (by up to the tolerated skew), once we hold their unfriend. The rule itself is unchanged: an
 * invite issued before an unfriend still never re-friends.
 */
export function inviteIatAfterUnfriends(
  self: string,
  aud: string,
  unfriends: readonly Pick<UnfriendV3Payload, "iss" | "peer" | "iat">[],
  now: number = nowSec(),
): number {
  let iat = now;
  for (const u of unfriends) {
    const other = u.iss === self ? u.peer : u.peer === self ? u.iss : undefined;
    if (other === undefined || (aud !== "*" && other !== aud)) continue;
    if (u.iat + 1 > iat) iat = u.iat + 1;
  }
  return iat;
}

/**
 * The latest known unfriend between an invite's issuer and `accepter` that would end the
 * friendship accepting it makes (the invite was issued at or before it), if any. An accepter
 * checks this before accepting, so it refuses at once, with a reason, instead of recording a
 * friendship every client refuses and spending a single-use code on it.
 */
export function unfriendEndingInvite(
  invite: { iss: string; iat: number },
  accepter: string,
  unfriends: readonly Pick<UnfriendV3Payload, "iss" | "peer" | "iat">[],
): Pick<UnfriendV3Payload, "iss" | "peer" | "iat"> | undefined {
  let worst: Pick<UnfriendV3Payload, "iss" | "peer" | "iat"> | undefined;
  for (const u of unfriends) {
    const pair = (u.iss === invite.iss && u.peer === accepter) || (u.iss === accepter && u.peer === invite.iss);
    if (pair && invite.iat <= u.iat && (!worst || u.iat > worst.iat)) worst = u;
  }
  return worst;
}

/** True when a friendship between `a` and `b` exists and no unfriend ends it (v2 semantics). */
export function liveFriendship(
  a: string,
  b: string,
  friendships: readonly Pick<VerifiedFriendshipV3, "inviter" | "invitee" | "inv" | "inviteIat">[],
  unfriends: readonly Pick<UnfriendV3Payload, "iss" | "peer" | "inv" | "iat">[],
): { any: boolean; live: boolean } {
  const between = friendships.filter((f) => (f.inviter === a && f.invitee === b) || (f.inviter === b && f.invitee === a));
  return { any: between.length > 0, live: between.some((f) => !unfriends.some((u) => unfriendApplies(f, u))) };
}
