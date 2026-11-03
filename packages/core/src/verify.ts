// Copyright 2026 Ix Infrastructure Inc.
//
// verifyIncoming: the full receive-side chain for one envelope.
//
//   decode (size cap) -> addressed to this device -> revocation list fresh
//   enough -> replay pre-check -> sender cert from the outer `fcert` (JWKS,
//   Kartr signature, expiry, revocation, did == fdid == kid, sub == from) ->
//   envelope signature -> atomic replay check-and-record -> open -> proofs
//   (workspace attestation, friendship, roster for (own, sid)) -> two-sided
//   mayExchange -> commit (roster, friendship, cert cache)
//
// Draft 2 (C2): the sender's certificate is in the outer payload, so it is
// verified before opening with no directory lookup. `resolveCert` is only
// needed for the signers of proofs (invites, accepts, rosters) signed by
// devices other than the sender's.
//
// Concurrency (M1): calls for the same sender device on the same TrustStore
// are serialised by a per-fdid lock, and the replay check-and-record is one
// atomic TrustStore operation (file-locked across processes).

import { authorizeExchange, type ExchangeRule, type FriendshipFact } from "./authz.js";
import {
  decodeEnvelope,
  openEnvelope,
  parsePlaintext,
  verifyEnvelopeSignature,
  type EnvelopePayload,
  type EnvelopePlaintext,
} from "./envelope.js";
import { fail, P2PError, type RejectReason } from "./errors.js";
import type { KartrKeys } from "./jwks.js";
import {
  DEFAULT_SKEW_SEC,
  unfriendApplies,
  verifyDeviceCert,
  verifyFriendship,
  verifyRevocationList,
  verifyRoster,
  verifyUnfriend,
  verifyWorkspaceAttestation,
  inviteHash,
  TYP,
  verifyDeviceSigned,
  verifyInvite,
  type AcceptPayload,
  type CertResolver,
  type DeviceCert,
  type DeviceVerifyOptions,
  type VerifiedFriendship,
  type VerifiedInvite,
  type VerifiedRoster,
  type VerifiedUnfriend,
  type WorkspaceAttestation,
} from "./objects.js";
import { checkReplay } from "./replay.js";
import type { RosterPutResult, StoredOutgoingInvite, StoredRoster, TrustStore } from "./truststore.js";
import { decodeJws, MAX_JWS_BYTES } from "./jws.js";

/** Warn when the revocation list hasn't been polled successfully for this long. */
export const REVOCATION_WARN_AGE_MS = 60 * 60 * 1000;
/** Fail closed (reject everything) when it hasn't been polled for this long. */
export const REVOCATION_MAX_AGE_MS = 24 * 60 * 60 * 1000;

export interface IncomingContext {
  /**
   * The receiving device: its own certificate (so proofs it signed can be
   * checked) and the receiving user's own workspace attestation (C6).
   */
  self: { userId: string; deviceId: string; agreementSecretKey: Uint8Array; cert?: string; workspace?: string };
  kartr: KartrKeys;
  trust: TrustStore;
  /** Directory lookup for proof signers' certificates not in the TrustStore cache. */
  resolveCert?: CertResolver;
  /** Milliseconds since the epoch (default: wall clock). */
  nowMs?: number;
  skewSec?: number;
  /** Revocation list staleness that rejects everything (default 24h). */
  revocationMaxAgeMs?: number;
  /** Revocation list staleness that triggers onWarning (default 1h). */
  revocationWarnAgeMs?: number;
  onWarning?: (message: string) => void;
}

export type IncomingRule = ExchangeRule | "self-sync" | "unfriend" | "contact";

/**
 * The single object a `kind: "contact"` envelope carried (D8), verified.
 * verifyIncoming never stores it; the app decides what to do:
 *  - invite: hold it for the user to accept or decline;
 *  - accept: matches an invite this device issued (checked); adopt it with
 *    recordFriendship(trust, friendship) if the user still wants it;
 *  - unfriend: apply it (TrustStore.addUnfriend).
 */
export type ContactObject =
  | { type: "invite"; invite: VerifiedInvite }
  | { type: "accept"; accept: AcceptPayload; friendship: VerifiedFriendship }
  | { type: "unfriend"; unfriend: VerifiedUnfriend };

export interface AcceptedMessage {
  ok: true;
  /** How the sender is authorised. */
  rule: IncomingRule;
  /** How the viewer is authorised (session traffic only). */
  viewerRule?: ExchangeRule;
  envelope: EnvelopePayload;
  plaintext: EnvelopePlaintext;
  sender: DeviceCert;
  /** The roster the message was authorised against (msg/roster/idle). */
  roster?: StoredRoster;
  workspace?: WorkspaceAttestation;
  friendship?: VerifiedFriendship;
  unfriend?: VerifiedUnfriend;
  /** For `kind: "contact"`: the verified object (D8). */
  object?: ContactObject;
}

export interface RejectedMessage {
  ok: false;
  reason: RejectReason;
  message: string;
}

export type IncomingResult = AcceptedMessage | RejectedMessage;

/** A certificate resolver that consults the TrustStore cache, then `fallback`. */
export function trustStoreResolver(trust: TrustStore, fallback?: CertResolver): CertResolver {
  return async (userId, did) => {
    const c = await trust.getDeviceCert(did);
    if (c && c.userId === userId) return c.jws;
    return fallback?.(userId, did);
  };
}

// Per-(TrustStore, fdid) async lock.
const locks = new WeakMap<TrustStore, Map<string, Promise<unknown>>>();

async function withFdidLock<T>(trust: TrustStore, fdid: string, fn: () => Promise<T>): Promise<T> {
  let m = locks.get(trust);
  if (!m) locks.set(trust, (m = new Map()));
  const prev = m.get(fdid) ?? Promise.resolve();
  const run = prev.then(fn, fn);
  const tail = run.catch(() => {});
  m.set(fdid, tail);
  try {
    return await run;
  } finally {
    if (m.get(fdid) === tail) m.delete(fdid);
  }
}

export async function verifyIncoming(envelope: string, ctx: IncomingContext): Promise<IncomingResult> {
  try {
    const p = decodeEnvelope(envelope).payload;
    return await withFdidLock(ctx.trust, p.fdid, () => verifyIncomingOrThrow(envelope, ctx));
  } catch (e) {
    if (e instanceof P2PError) return { ok: false, reason: e.reason, message: e.message };
    throw e;
  }
}

async function verifyIncomingOrThrow(jws: string, ctx: IncomingContext): Promise<AcceptedMessage> {
  const nowMs = ctx.nowMs ?? Date.now();
  const now = Math.floor(nowMs / 1000);
  const skewSec = ctx.skewSec ?? DEFAULT_SKEW_SEC;
  const { trust, self } = ctx;

  // 1. Outer structure, typ, kid == fdid, size, addressing, cheap replay pre-check.
  const p = decodeEnvelope(jws).payload;
  if (p.to !== self.userId || p.tdid !== self.deviceId) {
    fail("wrong-recipient", `addressed to ${p.to}/${p.tdid}`);
  }
  const pre = checkReplay(p, await trust.getReplay(p.fdid), nowMs);
  if (pre) fail(pre.reason, pre.message);

  // 2. Revocation list freshness (L4): fail closed once too stale.
  const revs = await trust.getRevocations();
  const revAge = revs ? nowMs - revs.fetchedAt : Infinity;
  if (revAge > (ctx.revocationMaxAgeMs ?? REVOCATION_MAX_AGE_MS)) {
    fail("revocations-stale", revs ? `revocation list last polled ${Math.round(revAge / 60_000)} min ago` : "no revocation list");
  }
  if (revAge > (ctx.revocationWarnAgeMs ?? REVOCATION_WARN_AGE_MS)) {
    ctx.onWarning?.(`revocation list last polled ${Math.round(revAge / 60_000)} min ago`);
  }
  const revoked = new Set(revs?.dids ?? []);

  // 3. Sender certificate (outer fcert): JWKS -> Kartr signature -> expiry -> revocation.
  const directory = trustStoreResolver(trust, ctx.resolveCert);
  const baseOpts = { kartr: ctx.kartr, now, skewSec, isRevoked: (d: string) => revoked.has(d) };
  const sender = await verifyDeviceCert(p.fcert, baseOpts);
  if (sender.did !== p.fdid) fail("kid-mismatch", `fcert is for ${sender.did}, envelope from ${p.fdid}`);
  if (sender.sub !== p.from) fail("cert-mismatch", `fcert is for ${sender.sub}, envelope from ${p.from}`);
  const resolveCert: CertResolver = async (userId, did) => {
    if (did === sender.did && userId === sender.sub) return sender.jws;
    if (did === self.deviceId && userId === self.userId && self.cert) return self.cert;
    return directory(userId, did);
  };
  const opts: DeviceVerifyOptions = { ...baseOpts, resolveCert };

  // 4. Envelope signature, then the atomic replay check-and-record: only
  //    authentic sender traffic touches replay state, and of two concurrent
  //    deliveries only one passes.
  verifyEnvelopeSignature(jws, sender.signingPublicKey);
  const admitted = await trust.admitReplay(p.fdid, p, nowMs);
  if (admitted) fail(admitted.reason, admitted.message);

  // 5. Open.
  const plaintext = parsePlaintext(openEnvelope(p, self.agreementSecretKey, sender.agreementPublicKey));

  // D8: contact envelopes carry exactly one object, need no roster or
  // friendship, and store nothing (beyond the replay record above).
  if (p.kind === "contact") {
    const object = await verifyContactObject(plaintext, p, opts, ctx);
    return { ok: true, rule: "contact", envelope: p, plaintext, sender, object };
  }

  // 6. Proofs.
  let workspace: WorkspaceAttestation | undefined;
  if (plaintext.sender.workspace !== undefined) {
    workspace = await verifyWorkspaceAttestation(plaintext.sender.workspace, opts);
    if (workspace.sub !== p.from) fail("workspace-mismatch", `attestation is for ${workspace.sub}`);
  }

  const storedFriendships = await trust.listFriendships();
  const unfriends = await trust.listUnfriends();
  let friendship: VerifiedFriendship | undefined;
  if (plaintext.sender.friendship !== undefined) {
    friendship = await verifyFriendship(plaintext.sender.friendship, opts);
    if (friendship.inviter !== p.from && friendship.invitee !== p.from) {
      fail("friendship-mismatch", "friendship does not involve the sender");
    }
    const bound = storedFriendships.find((f) => f.inv === friendship!.inv);
    if (bound && (bound.inviter !== friendship.inviter || bound.invitee !== friendship.invitee)) {
      fail("invite-already-bound", `invite already accepted by ${bound.invitee}`);
    }
  }
  const base = { ok: true as const, envelope: p, plaintext, sender, workspace, friendship };
  // Commit only state the kind's own rules allow. verifyIncoming NEVER stores
  // a friendship: a carried proof is evidence for this one message's sender
  // side, not a grant. Stored friendships come only from the viewer's own
  // invite/accept flows (recordFriendship).
  const commit = async () => {
    await trust.putDeviceCert({ userId: sender.sub, did: sender.did, exp: sender.exp, jws: sender.jws });
  };

  // 7. Kinds that are not session traffic (C5).
  if (p.kind === "sync") {
    // Sync is between a user's own devices.
    if (p.from !== self.userId) fail("not-participant", "sync is only accepted from the same user");
    await commit();
    return { ...base, rule: "self-sync" };
  }
  if (p.kind === "unfriend") {
    // The unfriend JWS rides in `text`.
    const unfriend = await verifyUnfriend(plaintext.text, opts);
    if (unfriend.iss !== p.from || unfriend.peer !== self.userId) {
      fail("friendship-mismatch", "unfriend must be from the sender and name this user");
    }
    await commit();
    await trust.addUnfriend({ iss: unfriend.iss, peer: unfriend.peer, inv: unfriend.inv, iat: unfriend.iat, jws: unfriend.jws });
    return { ...base, rule: "unfriend", unfriend };
  }

  // 8. Roster for the session (own, sid): the presented one (must be the
  //    owner's and not older than what we hold) or the stored one.
  let presented: VerifiedRoster | undefined;
  let roster: StoredRoster;
  if (plaintext.roster !== undefined) {
    presented = await verifyRoster(plaintext.roster, opts);
    if (presented.iss !== p.own) fail("roster-owner-mismatch", `roster is signed by ${presented.iss}, session owner is ${p.own}`);
    if (presented.sid !== p.sid) fail("roster-session-mismatch", `roster is for ${presented.sid}`);
    const held = await trust.getRoster(p.own, p.sid);
    if (held && presented.ver < held.ver) fail("stale-roster", `ver ${presented.ver} < held ${held.ver}`);
    if (held && presented.ver === held.ver && presented.jws !== held.jws) {
      fail("roster-conflict", `two different rosters at ver ${held.ver}`);
    }
    roster = { iss: presented.iss, sid: presented.sid, ver: presented.ver, jws: presented.jws };
  } else {
    const held = await trust.getRoster(p.own, p.sid);
    if (!held) fail("no-roster", `no roster for session ${p.own}/${p.sid}`);
    roster = held;
  }
  // Re-verify the roster we authorise against: its signer may since be revoked or expired.
  const rv = presented ?? (await verifyRoster(roster.jws, opts));

  // 9. Two-sided authorisation (C6).
  let viewerWorkspace: WorkspaceAttestation | undefined;
  if (self.workspace !== undefined) {
    try {
      viewerWorkspace = await verifyWorkspaceAttestation(self.workspace, opts);
      if (viewerWorkspace.sub !== self.userId) viewerWorkspace = undefined;
    } catch {
      // An expired or invalid own attestation just doesn't count.
      viewerWorkspace = undefined;
    }
  }
  // The viewer's own stored friendships with the owner, for the sender or the
  // viewer, re-verified now: a signer device that has since been revoked or
  // whose certificate has expired (L4) no longer counts.
  const relevant = storedFriendships.filter((f) => {
    const pair = [f.inviter, f.invitee];
    return pair.includes(rv.iss) && (pair.includes(p.from) || pair.includes(self.userId));
  });
  const friendships: FriendshipFact[] = [];
  for (const f of relevant) {
    if (revoked.has(f.inviteDid) || revoked.has(f.acceptDid)) continue;
    try {
      friendships.push(await verifyFriendship(f.proof, opts));
    } catch {
      // Expired/unresolvable signer certificate: not a live friendship now.
    }
  }
  // D9: the owner's attestation, from (in order):
  //  1. the envelope: plaintext.ownerWorkspace, or sender.workspace when the
  //     sender is the owner. Present but invalid is a rejection;
  //  2. this device's own attestation, when the viewer IS the owner;
  //  3. the TrustStore cache (newest verified per owner, re-verified now, so
  //     still bounded by its own 24h expiry).
  // None valid just means roster.org confers nothing.
  let ownerWorkspace: WorkspaceAttestation | undefined;
  let carriedOwnerWorkspace = false;
  const carried = plaintext.ownerWorkspace ?? (p.from === rv.iss ? plaintext.sender.workspace : undefined);
  if (carried !== undefined) {
    ownerWorkspace = await verifyWorkspaceAttestation(carried, opts);
    if (ownerWorkspace.sub !== rv.iss) {
      fail("owner-workspace-mismatch", `owner attestation is for ${ownerWorkspace.sub}, roster owner is ${rv.iss}`);
    }
    carriedOwnerWorkspace = true;
  } else if (self.userId === rv.iss) {
    ownerWorkspace = viewerWorkspace;
  } else {
    const cached = await trust.getOwnerWorkspace(rv.iss);
    if (cached) {
      try {
        const w = await verifyWorkspaceAttestation(cached.jws, opts);
        if (w.sub === rv.iss) ownerWorkspace = w;
      } catch {
        // Expired (or no longer verifiable): the cached copy doesn't count.
      }
    }
  }
  const decision = authorizeExchange(self.userId, p.from, rv, {
    chainValid: true, // step 3 threw otherwise
    signatureValid: true, // step 4 threw otherwise
    senderWorkspaceOrgs: workspace?.orgs,
    viewerWorkspaceOrgs: viewerWorkspace?.orgs,
    ownerWorkspaceOrgs: ownerWorkspace?.orgs,
    friendships,
    // Sender-presented proofs count only for the sender's side (H1).
    presentedFriendships: friendship ? [friendship] : [],
    unfriends,
  });
  if (!decision.ok) fail(decision.reason, `${p.from} -> ${self.userId} not authorised for ${p.own}/${p.sid}`);

  await commit();
  if (presented) await trust.putRoster(roster);
  if (ownerWorkspace && carriedOwnerWorkspace) {
    await trust.putOwnerWorkspace({ userId: ownerWorkspace.sub, exp: ownerWorkspace.exp, jws: ownerWorkspace.jws });
  }
  return { ...base, rule: decision.rule, viewerRule: decision.viewerRule, roster };
}

async function verifyContactObject(
  plaintext: EnvelopePlaintext,
  p: EnvelopePayload,
  opts: DeviceVerifyOptions,
  ctx: IncomingContext,
): Promise<ContactObject> {
  const { self, trust } = ctx;
  if (plaintext.roster !== undefined || Object.keys(plaintext.sender).length > 0) {
    fail("malformed", "a contact envelope carries no roster or sender proofs");
  }
  const text = plaintext.text;
  if (!CONTACT_JWS_RE.test(text) || text.length > MAX_JWS_BYTES) {
    fail("malformed", "contact text must be exactly one invite, accept or unfriend compact JWS");
  }
  const typ = decodeJws(text).header.typ;
  switch (typ) {
    case TYP.invite: {
      const invite = await verifyInvite(text, opts);
      if (invite.iss !== p.from) fail("cert-mismatch", `invite is from ${invite.iss}, envelope from ${p.from}`);
      if (invite.aud !== "*" && invite.aud !== self.userId) fail("audience-mismatch", `invite is for ${invite.aud}`);
      return { type: "invite", invite };
    }
    case TYP.accept: {
      const v = await verifyDeviceSigned(text, TYP.accept, opts);
      const inv = v.payload.inv;
      if (typeof inv !== "string") fail("malformed", "accept.inv missing");
      if (v.signer.sub !== p.from) fail("cert-mismatch", `accept is from ${v.signer.sub}, envelope from ${p.from}`);
      const outgoing = await matchOutgoingInvite(trust, inv);
      if (!outgoing) fail("unknown-invite", `no outgoing invite ${inv}`);
      const friendship = await verifyFriendship({ invite: outgoing.jws, accept: text }, opts);
      if (friendship.inviter !== self.userId) fail("unknown-invite", "the matched invite is not this user's");
      return { type: "accept", accept: friendship.accept, friendship };
    }
    case TYP.unfriend: {
      const unfriend = await verifyUnfriend(text, opts);
      if (unfriend.iss !== p.from || unfriend.peer !== self.userId) {
        fail("friendship-mismatch", "unfriend must be from the sender and name this user");
      }
      return { type: "unfriend", unfriend };
    }
    default:
      return fail("typ-mismatch", `a contact envelope can't carry ${typ}`);
  }
}

const CONTACT_JWS_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

/**
 * Remembers an invite this device issued, so an accept arriving in a contact
 * envelope can be matched to it (D8). Call it when the user creates an invite.
 */
export async function recordOutgoingInvite(trust: TrustStore, inviteJws: string): Promise<StoredOutgoingInvite> {
  const d = decodeJws(inviteJws);
  if (d.header.typ !== TYP.invite) fail("typ-mismatch", `typ ${d.header.typ} != ${TYP.invite}`);
  const { aud, exp } = d.payload;
  if (typeof aud !== "string" || typeof exp !== "number") fail("malformed", "invite aud/exp missing");
  const entry: StoredOutgoingInvite = { inv: inviteHash(inviteJws), aud, exp, jws: inviteJws };
  await trust.addOutgoingInvite(entry);
  return entry;
}

/** The stored outgoing invite an accept's `inv` cites, if this device issued it. */
export async function matchOutgoingInvite(trust: TrustStore, inv: string): Promise<StoredOutgoingInvite | undefined> {
  return trust.getOutgoingInvite(inv);
}

/**
 * Verifies a fetched revocation list and stores it if newer. Every successful
 * poll refreshes the list's `fetchedAt`, which verifyIncoming uses for its
 * staleness checks.
 */
export async function updateRevocations(
  trust: TrustStore,
  jws: string,
  opts: { kartr: KartrKeys; now?: number; skewSec?: number; nowMs?: number },
): Promise<boolean> {
  const r = await verifyRevocationList(jws, opts);
  const fetchedAt = opts.nowMs ?? (opts.now !== undefined ? opts.now * 1000 : Date.now());
  return trust.putRevocations({ iat: r.iat, dids: r.dids, jws: r.jws, fetchedAt });
}

/**
 * Stores a verified friendship. This is the ONLY way friendships enter a
 * TrustStore: the app calls it from its own explicit flows, i.e. right after
 * this user accepts an invite, or when an accept arrives for an invite this
 * user issued. A friendship already killed by a stored unfriend (same invite,
 * or invite issued at or before the unfriend) is refused with `unfriended`.
 */
export async function recordFriendship(trust: TrustStore, f: VerifiedFriendship): Promise<void> {
  const unfriends = await trust.listUnfriends();
  if (unfriends.some((u) => unfriendApplies(f, u))) fail("unfriended", `friendship ${f.inv} was ended by an unfriend`);
  await trust.addFriendship({
    inviter: f.inviter,
    invitee: f.invitee,
    inv: f.inv,
    aud: f.aud,
    iat: f.iat,
    inviteIat: f.inviteIat,
    inviteDid: f.invite.did,
    acceptDid: f.accept.did,
    proof: f.proof,
  });
}

/**
 * Verifies a roster and stores it if it is the highest ver for its (iss, sid).
 * An owner device calls this on the rosters it signs, so its own copy is the
 * one un-rostered traffic is authorised against.
 */
export async function recordRoster(
  trust: TrustStore,
  jws: string,
  opts: DeviceVerifyOptions,
): Promise<RosterPutResult> {
  const r = await verifyRoster(jws, opts);
  return trust.putRoster({ iss: r.iss, sid: r.sid, ver: r.ver, jws: r.jws });
}
