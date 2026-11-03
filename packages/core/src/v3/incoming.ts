// Copyright 2026 Ix Infrastructure Inc.
//
// verifyIncomingV3: the receive-side chain for one v3 envelope
// (docs/protocol.md §4).
//
//   decode (size cap, typ, kid == fdid) -> addressed to this device ->
//   replay pre-check (7d10m) -> sender not blocked -> sender identity view
//   (fail closed > 60 d past exp, except own sync; warn past exp; the
//   intersection allowlist while forked) -> fcert rules 1–6, fcert.iss ==
//   from, fcert.did == fdid == kid -> envelope signature -> atomic replay
//   check-and-record -> open -> per-kind checks and two-sided authorisation
//
// Like v2, verifyIncomingV3 never stores a friendship, an invite or a
// circle: those come back to the app, which applies them through its own
// explicit flows (recordFriendshipV3, storeOfferedCircle, recordOwnJoin,
// applyCircleBundle). It stores only the sender's certificate, unfriends
// addressed to this user, and an authorised session roster.
//
// Interpretation (§4.1 "not forked"): a forked sender is not rejected; rule 6
// runs against the intersection of its branches, as §2.5 requires.
// Interpretation (contact from a stranger): when nothing is known of the
// sender's identity, a `contact` envelope is opened after rules 1–5, and rule
// 6 is then applied against the identity document the carried invite or
// accept brings, before anything is returned. Every other kind needs the
// sender's document beforehand.

import { decodeJws, MAX_JWS_BYTES } from "../jws.js";
import { checkReplay, REPLAY_MAX_AGE_MS_V3, type ReplayVerdict } from "../replay.js";
import { fail, P2PError, type RejectReason } from "../errors.js";
import { DEFAULT_SKEW_SEC, nowSec, TYP3 } from "./base.js";
import { authorizeExchangeV3, type ExchangeRuleV3 } from "./authz.js";
import { verifyCap, type VerifiedCap } from "./caps.js";
import { CircleChain, parseCircleVersion } from "./circles.js";
import { checkDeviceListed, verifyDeviceCertV3, type VerifiedDeviceCertV3 } from "./device.js";
import {
  decodeEnvelopeV3,
  isFutureKind,
  isSessionKind,
  openEnvelopeV3,
  parsePlaintextV3,
  verifyEnvelopeV3Signature,
  type EnvelopeV3Payload,
  type PlaintextV3,
} from "./envelope.js";
import {
  docView,
  liveFriendship,
  verifyFriendshipV3,
  verifyInviteV3,
  verifyUnfriendV3,
  type VerifiedFriendshipV3,
  type VerifiedInviteV3,
  type VerifiedUnfriendV3,
} from "./friends.js";
import { assertNotFailClosed, daysPastExp, type IdentityView } from "./identitydoc.js";
import { verifyRotation, type VerifiedRotation } from "./identity.js";
import { compareRoster, verifyRosterV3, type VerifiedRosterV3 } from "./roster.js";
import type { CertResolverV3, SignerContext } from "./signers.js";
import { circleOwners, freshnessLookup, getIdentityView, liveFriendshipsV3, longestLived, standsLookup, storeSignerContext } from "./state.js";
import type { ClaimLiveness, ReplayClaimant, StoredRosterV3, TrustStoreV3 } from "./store.js";

/** Session kinds only the session's owner sends (§4.3). */
const OWNER_ONLY_KINDS: ReadonlySet<string> = new Set(["status", "idle", "roster"]);

export interface IncomingContextV3 {
  self: { userId: string; did: string; agreementSecretKey: Uint8Array; cert?: string };
  store: TrustStoreV3;
  /** Fallback certificate lookup (e.g. a directory or relay fetch) for proof signers. */
  resolveCert?: CertResolverV3;
  /** Fallback identity lookup (e.g. fetched from the sender's relays into an IdentityChain). */
  resolveIdentity?: (userId: string) => Promise<IdentityView | undefined>;
  /** Milliseconds since the epoch (default: wall clock). */
  nowMs?: number;
  skewSec?: number;
  onWarning?: (message: string) => void;
  /**
   * Record the envelope in the replay window only once the caller has applied it: verification
   * takes a claim instead (TrustStoreV3.claimReplay), and the accepted result carries
   * `commitReplay`, which the caller runs after the envelope's effects are written. A crash in
   * between leaves the claim, which a redelivery takes over once `isAlive` says its holder is gone
   * (or it is older than REPLAY_CLAIM_TTL_MS): the message is applied then instead of being dropped
   * as replayed. Another attempt still applying the same envelope makes this one fail with
   * `replay-in-progress` (don't ack it). Without this option, check and record are one step.
   */
  replayClaim?: {
    claimant: ReplayClaimant;
    isAlive?: ClaimLiveness;
    /**
     * Failures worth another attempt (review M-A): clearly local and transient (a lock timeout, a
     * full disk). Anything else, and every protocol rejection, is final at once: the seq is spent.
     * Default: none.
     */
    retryable?: (e: unknown) => boolean;
    /** Attempts before a failing envelope is recorded as given up (default REPLAY_MAX_ATTEMPTS). */
    maxAttempts?: number;
  };
}

export type IncomingRuleV3 = ExchangeRuleV3 | "self-sync" | "unfriend" | "contact" | "circle" | "receipt" | "unknown-kind";

/** The single object a `contact` envelope carried (§4.3), verified. Never stored here. */
export type ContactObjectV3 =
  /**
   * Hold for the user's approval (§3.1: strangers' invites are never acted on
   * automatically). When `invite.provisional`, rule 6 ran against the bundled
   * document only (now stored as an unanchored, provisional chain): call
   * reverifyInviteForApproval before acting on the approval (pre-release review M1).
   */
  | { type: "invite"; invite: VerifiedInviteV3 }
  /**
   * Matches an invite this user issued; adopt with recordFriendshipV3 if still
   * wanted. When `friendship.provisional`, call reverifyFriendshipForApproval
   * first.
   */
  | { type: "accept"; friendship: VerifiedFriendshipV3 }
  | { type: "unfriend"; unfriend: VerifiedUnfriendV3 }
  /** A friend cap from a stored, live friend (§5.3): store it with addCapHeld. */
  | { type: "cap"; cap: VerifiedCap }
  /** A circle invite, held for approval; `chain` is bootstrapped when the full chain came along. */
  | { type: "circle-invite"; head: string; chain?: CircleChain }
  /**
   * P3 (§2.8): the new identity's invite, bound to this user (`aud`), with the
   * rotation statement that names the sender as `to`. Both halves verified.
   * Never acted on here: §2.8 has the user approve carrying a friendship over
   * (the app checks rotationConflicts and holds it). Like any first contact,
   * `invite.provisional` means reverifyInviteForApproval runs before acting.
   */
  | { type: "rotation"; rotation: VerifiedRotation; invite: VerifiedInviteV3 };

export interface CircleEnvelopeInfo {
  /** Why the sender may send `circle` traffic, or "held" (treat as a circle invite, §4.3). */
  authorizedBy: "friend" | "stands" | "member" | "held";
  cids: string[];
}

export interface AcceptedMessageV3 {
  ok: true;
  rule: IncomingRuleV3;
  viewerRule?: ExchangeRuleV3;
  envelope: EnvelopeV3Payload;
  plaintext: PlaintextV3;
  sender: VerifiedDeviceCertV3;
  /** The sender's identity as used (absent only for a stranger's contact). */
  senderIdentity?: IdentityView;
  roster?: StoredRosterV3;
  contact?: ContactObjectV3;
  circle?: CircleEnvelopeInfo;
  unfriend?: VerifiedUnfriendV3;
  /** The sender's identity document is past `exp` (§2.5: warn, keep authorising). */
  expiredDays?: number;
  /**
   * With `replayClaim`: records the envelope in the replay window. Run it once it was applied.
   * Resolves with a verdict when another attempt recorded it first (a claim from another host
   * taken over after its TTL): a lost race, so this attempt's effects were a duplicate.
   */
  commitReplay?: () => Promise<ReplayVerdict>;
  /** With `replayClaim`: gives the claim up unrecorded (applying failed for a non-protocol reason). */
  releaseReplay?: (opts?: { uncount?: boolean }) => Promise<void>;
  /** With `replayClaim`: this attempt's number (1 for the first). */
  attempt?: number;
}

export interface RejectedMessageV3 {
  ok: false;
  reason: RejectReason;
  message: string;
}

export type IncomingResultV3 = AcceptedMessageV3 | RejectedMessageV3;

// Per-(store, fdid) async lock, as in v2 (M1).
const locks = new WeakMap<TrustStoreV3, Map<string, Promise<unknown>>>();

async function withFdidLock<T>(store: TrustStoreV3, fdid: string, fn: () => Promise<T>): Promise<T> {
  let m = locks.get(store);
  if (!m) locks.set(store, (m = new Map()));
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

export async function verifyIncomingV3(envelope: string, ctx: IncomingContextV3): Promise<IncomingResultV3> {
  try {
    const p = decodeEnvelopeV3(envelope).payload;
    return await withFdidLock(ctx.store, p.fdid, () => verifyOrThrow(envelope, ctx));
  } catch (e) {
    if (e instanceof P2PError) return { ok: false, reason: e.reason, message: e.message };
    throw e;
  }
}

async function verifyOrThrow(jws: string, ctx: IncomingContextV3): Promise<AcceptedMessageV3> {
  const nowMs = ctx.nowMs ?? Date.now();
  const now = Math.floor(nowMs / 1000);
  const skewSec = ctx.skewSec ?? DEFAULT_SKEW_SEC;
  const { store, self } = ctx;

  // 1. Structure and addressing; the cheap replay pre-check.
  const p = decodeEnvelopeV3(jws).payload;
  if (p.to !== self.userId || p.tdid !== self.did) fail("wrong-recipient", `addressed to ${p.to}/${p.tdid}`);
  const pre = checkReplay(p, await store.getReplay(p.fdid), nowMs, REPLAY_MAX_AGE_MS_V3);
  if (pre) fail(pre.reason, pre.message);

  // 2. Blocks override every rule (§3.2).
  if (await store.isBlocked(p.from)) fail("blocked", `${p.from} is blocked`);

  // 3. The sender's identity: freshness, then fcert under rules 1–6.
  const ownSync = p.kind === "sync" && p.from === self.userId;
  const view = (await getIdentityView(store, p.from)) ?? (await ctx.resolveIdentity?.(p.from));
  let expiredDays: number | undefined;
  if (view) {
    const f = assertNotFailClosed(view.exp, now, { ownSync });
    if (f !== "fresh") {
      expiredDays = daysPastExp(view.exp, now);
      ctx.onWarning?.(`${p.from}'s key device hasn't been online for ${expiredDays} days`);
    }
  } else if (p.kind !== "contact") {
    fail("identity-unknown", `no identity document for ${p.from}`);
  }
  // Rules 1–5, then fcert.iss == from and fcert.did == fdid (== kid), then rule 6.
  const sender = verifyDeviceCertV3(p.fcert, { now, skewSec });
  if (sender.iss !== p.from) fail("cert-mismatch", `fcert is for ${sender.iss}, envelope from ${p.from}`);
  if (sender.did !== p.fdid) fail("kid-mismatch", `fcert is for ${sender.did}, envelope from ${p.fdid}`);
  if (view) checkDeviceListed(sender, { iss: view.iss, ik: view.ik, devices: view.devices });

  // 4. Signature, then the atomic replay check-and-record (authentic traffic only).
  verifyEnvelopeV3Signature(jws, sender.signingPublicKey);
  let commit: (() => Promise<ReplayVerdict>) | undefined;
  let release: ((opts?: { uncount?: boolean }) => Promise<void>) | undefined;
  let attempt: number | undefined;
  if (ctx.replayClaim) {
    const { claimant, isAlive } = ctx.replayClaim;
    // Held by another live attempt: wait, without queueing for the store's lock to learn it.
    if (await store.claimHeldElsewhere(p.fdid, p, nowMs, claimant.token, isAlive)) fail("replay-in-progress", `seq ${p.seq} from ${p.fdid} is being handled by another process`);
    const c = await store.claimReplay(p.fdid, p, nowMs, claimant, isAlive, ctx.replayClaim.maxAttempts);
    if (c.verdict) fail(c.verdict.reason, c.verdict.message);
    if (c.busy) fail("replay-in-progress", `seq ${p.seq} from ${p.fdid} is being handled by another process`);
    attempt = c.attempt;
    commit = () => store.commitReplay(p.fdid, p, nowMs, claimant.token);
    release = (o) => store.releaseReplay(p.fdid, p, claimant.token, o);
  } else {
    const admitted = await store.admitReplay(p.fdid, p, nowMs);
    if (admitted) fail(admitted.reason, admitted.message);
  }
  if (!commit) return finishVerify(jws, ctx, p, sender, view, expiredDays, nowMs, now, skewSec);
  try {
    return { ...(await finishVerify(jws, ctx, p, sender, view, expiredDays, nowMs, now, skewSec)), commitReplay: commit, releaseReplay: release!, ...(attempt !== undefined ? { attempt } : {}) };
  } catch (e) {
    // Rejected by the protocol after the signature verified: the seq is spent, as with
    // admitReplay. A clearly transient local failure (a lock timeout) gives the claim up, so the
    // redelivery is verified again (review L-1), within the attempt limit; anything else is final.
    if (!(e instanceof P2PError) && ctx.replayClaim?.retryable?.(e)) await release!().catch(() => undefined);
    else await commit().catch(() => undefined);
    throw e;
  }
}

/** Steps 5 onward of verifyOrThrow, once the envelope is admitted (or claimed). */
async function finishVerify(
  jws: string,
  ctx: IncomingContextV3,
  p: EnvelopeV3Payload,
  sender: VerifiedDeviceCertV3,
  view: IdentityView | undefined,
  expiredDays: number | undefined,
  nowMs: number,
  now: number,
  skewSec: number,
): Promise<AcceptedMessageV3> {
  const { store, self } = ctx;
  // 5. Open.
  const opened = openEnvelopeV3(p, self.agreementSecretKey, sender.agreementPublicKey);
  if (isFutureKind(p.kind)) {
    // A kind defined after this version (protocol.md "Forward compatibility"): authentic, admitted to
    // the replay window like any other, opened (so it was really sealed for this device), never parsed
    // or authorised for anything. The client tells its user once that it can't show it. The sender's
    // device cert isn't stored here: the client stores it only for a sender it knows (pre-release review).
    return { ok: true as const, envelope: p, plaintext: { kind: "unknown", envKind: p.kind }, sender, ...(view ? { senderIdentity: view } : {}), ...(expiredDays !== undefined ? { expiredDays } : {}), rule: "unknown-kind" };
  }
  const plaintext = parsePlaintextV3(p.kind, opened);

  // Proof signers' certificates: the envelope's own fcert and this device's
  // cert are candidates alongside the store's (the longest-lived wins).
  const fromStore = storeSignerContext(store, { now, skewSec, resolveCert: ctx.resolveCert, resolveIdentity: ctx.resolveIdentity });
  const signerCtx: SignerContext = {
    ...fromStore,
    resolveCert: async (u, d) => {
      const own = [
        ...(u === sender.iss && d === sender.did ? [sender.jws] : []),
        ...(u === self.userId && d === self.did && self.cert ? [self.cert] : []),
      ];
      const stored = await fromStore.resolveCert(u, d);
      return longestLived([...own, ...(stored ? [stored] : [])], { now, skewSec });
    },
  };
  const base = { ok: true as const, envelope: p, plaintext, sender, ...(view ? { senderIdentity: view } : {}), ...(expiredDays !== undefined ? { expiredDays } : {}) };
  const commit = () => (view ? store.putDeviceCert({ userId: sender.iss, did: sender.did, exp: sender.exp, jws: sender.jws }) : Promise.resolve());

  // 6. Kinds that are not session traffic.
  if (plaintext.kind === "contact") {
    const contact = await verifyContactObject(plaintext, p, signerCtx, ctx, sender, view);
    return { ...base, rule: "contact", contact };
  }
  if (plaintext.kind === "sync") {
    if (p.from !== self.userId) fail("not-participant", "sync is only accepted from the same user");
    await commit();
    return { ...base, rule: "self-sync" };
  }
  if (plaintext.kind === "unfriend") {
    const unfriend = await verifyUnfriendV3(plaintext.text, signerCtx);
    if (unfriend.iss !== p.from || unfriend.peer !== self.userId) fail("friendship-mismatch", "unfriend must be from the sender and name this user");
    await commit();
    await store.addUnfriend({ iss: unfriend.iss, peer: unfriend.peer, inv: unfriend.inv, iat: unfriend.iat, jws: unfriend.jws });
    return { ...base, rule: "unfriend", unfriend };
  }
  if (plaintext.kind === "receipt") {
    // §4.3 "Delivery receipts": own == from and sid ~receipt (checked when decoded). Whether this
    // device asked `from` for it is the client's to check: a receipt for nothing it sent is dropped.
    await commit();
    return { ...base, rule: "receipt" };
  }
  if (plaintext.kind === "circle") {
    const circle = await authorizeCircle(plaintext, p, signerCtx, ctx);
    await commit();
    return { ...base, rule: "circle", circle };
  }
  if (!isSessionKind(p.kind)) fail("malformed", `unhandled kind ${p.kind}`);
  // §4.3: `status`, `idle` and `roster` describe the session itself, so only its owner sends them.
  // A participant (a circle-mate writing into the owner's session) may send `msg` and event kinds,
  // never these: otherwise its `status` would overwrite the owner's record of the session.
  if (OWNER_ONLY_KINDS.has(p.kind) && p.from !== p.own) fail("not-session-owner", `${p.from} may not send ${p.kind} for ${p.own}'s session ${p.sid}`);

  // 7. Session kinds: the roster for (own, sid), presented or held.
  const sx = plaintext as Extract<PlaintextV3, { roster?: string }>;
  let presented: VerifiedRosterV3 | undefined;
  let roster: StoredRosterV3;
  if (sx.roster !== undefined) {
    presented = await verifyRosterV3(sx.roster, signerCtx);
    if (presented.iss !== p.own) fail("roster-owner-mismatch", `roster is signed by ${presented.iss}, session owner is ${p.own}`);
    if (presented.sid !== p.sid) fail("roster-session-mismatch", `roster is for ${presented.sid}`);
    const held = await store.getRoster(p.own, p.sid);
    const cmp = compareRoster(held, presented);
    if (cmp === "stale") fail("stale-roster", `ver ${presented.ver} < held ${held!.ver}`);
    if (cmp === "conflict") fail("roster-conflict", `two different rosters at ver ${presented.ver}`);
    roster = { iss: presented.iss, sid: presented.sid, ver: presented.ver, jws: presented.jws };
  } else {
    const held = await store.getRoster(p.own, p.sid);
    if (!held) fail("no-roster", `no roster for session ${p.own}/${p.sid}`);
    roster = held;
  }
  // Re-verify the roster authorised against: its signer may since be revoked.
  const rv = presented ?? (await verifyRosterV3(roster.jws, signerCtx));

  // 8. Two-sided authorisation (§4.2).
  let presentedFriendship: VerifiedFriendshipV3 | undefined;
  if (sx.friendship !== undefined) {
    presentedFriendship = await verifyFriendshipV3(sx.friendship, signerCtx);
    if (presentedFriendship.inviter !== p.from && presentedFriendship.invitee !== p.from) {
      fail("friendship-mismatch", "friendship does not involve the sender");
    }
    const bound = (await store.listFriendships()).find((f) => f.inv === presentedFriendship!.inv);
    if (bound && (bound.inviter !== presentedFriendship.inviter || bound.invitee !== presentedFriendship.invitee)) {
      fail("invite-already-bound", `invite already accepted by ${bound.invitee}`);
    }
  }
  const friendships = await liveFriendshipsV3(store, signerCtx, (f) => [f.inviter, f.invitee].includes(rv.iss));
  const blocks = new Set((await store.listBlocks()).map((b) => b.userId));
  const decision = authorizeExchangeV3(self.userId, p.from, rv, {
    friendships,
    presentedFriendships: presentedFriendship ? [presentedFriendship] : [],
    unfriends: await store.listUnfriends(),
    stands: await standsLookup(store, self.userId),
    isBlocked: (u) => blocks.has(u),
  });
  if (!decision.ok) fail(decision.reason, `${p.from} -> ${self.userId} not authorised for ${p.own}/${p.sid}`);

  await commit();
  if (presented) await store.putRoster(roster);
  return { ...base, rule: decision.rule, viewerRule: decision.viewerRule, roster };
}

/**
 * A stranger's bundled document (review M1, review N1) goes only into the
 * provisional cache, never the identity store: no view, resolver or
 * authorisation path reads it, so a replayed envelope stays provisional and
 * a planted old document can't vouch for a revoked device. It only tells
 * refreshIdentity where to fetch the real head from.
 */
async function keepProvisional(store: TrustStoreV3, doc: { iss: string; relays: string[] }, now: number | undefined): Promise<void> {
  await store.putProvisional({ userId: doc.iss, relays: doc.relays, at: now ?? nowSec() });
}

const COMPACT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

async function verifyContactObject(
  pt: Extract<PlaintextV3, { kind: "contact" }>,
  p: EnvelopeV3Payload,
  signerCtx: SignerContext,
  ctx: IncomingContextV3,
  sender: VerifiedDeviceCertV3,
  view: IdentityView | undefined,
): Promise<ContactObjectV3> {
  const { self, store } = ctx;
  const now = signerCtx.now;
  // Rule 6 for a stranger, against the document the object brings.
  const requireListed = (doc: { iss: string; ik: string; devices: readonly string[] } | undefined) => {
    if (view) return;
    if (!doc) fail("identity-unknown", `no identity document for ${p.from}`);
    checkDeviceListed(sender, doc);
  };
  if ("rotation" in pt) {
    const rotation = verifyRotation(pt.rotation, { now, skewSec: signerCtx.skewSec });
    if (rotation.to !== p.from) fail("rotation-invalid", `the rotation is to ${rotation.to}, the envelope from ${p.from}`);
    if (rotation.from === self.userId) fail("rotation-invalid", "a rotation of this user's own identity arrives by sync, not contact");
    const text = pt.invite;
    if (!COMPACT_RE.test(text) || text.length > MAX_JWS_BYTES || decodeJws(text).header.typ !== TYP3.invite) fail("malformed", "a rotation contact carries one invite JWS");
    const invite = await verifyInviteV3(text, signerCtx);
    if (invite.iss !== p.from) fail("cert-mismatch", `invite is from ${invite.iss}, envelope from ${p.from}`);
    // The new identity re-invites each friend by name: a shareable (`*`) invite doesn't qualify.
    if (invite.aud !== self.userId) fail("audience-mismatch", `a rotation invite must name this user, not ${invite.aud}`);
    requireListed(invite.inviterDoc ? docView(invite.inviterDoc) : undefined);
    if (!view && invite.inviterDoc) await keepProvisional(store, invite.inviterDoc, now);
    return { type: "rotation", rotation, invite };
  }
  if ("circle" in pt) {
    const head = parseCircleVersion(pt.circle);
    requireListed(undefined);
    let chain: CircleChain | undefined;
    if (pt.chain !== undefined) {
      chain = CircleChain.bootstrap([...pt.chain, pt.circle], { now, head: pt.circle, identityFreshness: await freshnessLookup(store, now, circleOwners([...pt.chain, pt.circle])) });
    }
    if (!head.members.includes(p.from) && head.owner !== p.from) {
      // An invite from someone who isn't in the circle is still only a held invite; flag it via the caller's UI.
      ctx.onWarning?.(`circle invite from ${p.from}, who is not a member of ${head.cid}`);
    }
    return { type: "circle-invite", head: pt.circle, ...(chain ? { chain } : {}) };
  }
  const text = pt.text;
  if (!COMPACT_RE.test(text) || text.length > MAX_JWS_BYTES) fail("malformed", "contact text must be exactly one compact JWS");
  const typ = decodeJws(text).header.typ;
  switch (typ) {
    case TYP3.invite: {
      const invite = await verifyInviteV3(text, signerCtx);
      if (invite.iss !== p.from) fail("cert-mismatch", `invite is from ${invite.iss}, envelope from ${p.from}`);
      if (invite.aud !== "*" && invite.aud !== self.userId) fail("audience-mismatch", `invite is for ${invite.aud}`);
      requireListed(invite.inviterDoc ? docView(invite.inviterDoc) : undefined);
      if (!view && invite.inviterDoc) await keepProvisional(store, invite.inviterDoc, now);
      return { type: "invite", invite };
    }
    case TYP3.accept: {
      const inv = decodeJws(text).payload.inv;
      if (typeof inv !== "string") fail("malformed", "accept.inv missing");
      const outgoing = await store.getOutgoingInvite(inv);
      if (!outgoing) fail("unknown-invite", `no outgoing invite ${inv}`);
      const friendship = await verifyFriendshipV3({ invite: outgoing.jws, accept: text }, signerCtx);
      if (friendship.inviter !== self.userId) fail("unknown-invite", "the matched invite is not this user's");
      if (friendship.invitee !== p.from) fail("cert-mismatch", `accept is from ${friendship.invitee}, envelope from ${p.from}`);
      requireListed(friendship.inviteeDoc ? docView(friendship.inviteeDoc) : undefined);
      if (!view && friendship.inviteeDoc) await keepProvisional(store, friendship.inviteeDoc, now);
      return { type: "accept", friendship };
    }
    case TYP3.unfriend: {
      requireListed(undefined);
      const unfriend = await verifyUnfriendV3(text, signerCtx);
      if (unfriend.iss !== p.from || unfriend.peer !== self.userId) fail("friendship-mismatch", "unfriend must be from the sender and name this user");
      return { type: "unfriend", unfriend };
    }
    case TYP3.cap: {
      requireListed(undefined);
      const cap = verifyCap(text, { now, skewSec: signerCtx.skewSec, purpose: "friend", identityDoc: view });
      if (cap.iss !== p.from || cap.sub !== self.userId) fail("cap-invalid", "a cap grant must be from the sender for this user");
      // §4.3: a cap grant only from a stored, live friend.
      const friends = await liveFriendshipsV3(store, signerCtx, (f) => [f.inviter, f.invitee].includes(p.from));
      if (!liveFriendship(self.userId, p.from, friends, await store.listUnfriends()).live) fail("no-friendship", "cap grants come only from friends");
      return { type: "cap", cap };
    }
    default:
      return fail("typ-mismatch", `a contact envelope can't carry ${typ}`);
  }
}

/**
 * §4.3 `circle`: the sender is a friend, or stands in the circle, or is a
 * member of it (in the held version); otherwise the bundle is held for
 * approval as a circle invite. `want` requests are answered only for circles
 * the sender may see.
 */
async function authorizeCircle(
  pt: Extract<PlaintextV3, { kind: "circle" }>,
  p: EnvelopeV3Payload,
  signerCtx: SignerContext,
  ctx: IncomingContextV3,
): Promise<CircleEnvelopeInfo> {
  const { store, self } = ctx;
  const cids = new Set<string>();
  if ("want" in pt) cids.add(pt.want.cid);
  else {
    for (const j of pt.circles) {
      try {
        cids.add(parseCircleVersion(j).cid);
      } catch (e) {
        if (!(e instanceof P2PError)) throw e;
      }
    }
    for (const j of [...pt.joins, ...pt.ops]) {
      try {
        const cid = decodeJws(j).payload.cid;
        if (typeof cid === "string") cids.add(cid);
      } catch (e) {
        if (!(e instanceof P2PError)) throw e;
      }
    }
  }
  const friends = await liveFriendshipsV3(store, signerCtx, (f) => [f.inviter, f.invitee].includes(p.from));
  if (p.from === self.userId || liveFriendship(self.userId, p.from, friends, await store.listUnfriends()).live) {
    return { authorizedBy: "friend", cids: [...cids] };
  }
  const stands = await standsLookup(store, self.userId);
  const list = [...cids];
  if (list.length > 0 && list.every((cid) => stands(p.from, cid))) return { authorizedBy: "stands", cids: list };
  let allMember = list.length > 0;
  for (const cid of list) {
    const rec = await store.getCircle(cid);
    if (!rec) {
      allMember = false;
      break;
    }
    const head = CircleChain.fromStored(rec.chain).head;
    if (!head.members.includes(p.from)) allMember = false;
  }
  return { authorizedBy: allMember ? "member" : "held", cids: list };
}
