// Copyright 2026 Ix Infrastructure Inc.
//
// The receiving device's authorisation rule (docs/protocol-v2.md,
// "Authorisation"), as a pure function over facts the caller has already
// verified. Draft 2 makes it two-sided (C6): a message is accepted only when
//
//  1. the sender's device-certificate chain and the envelope signature are valid;
//  2. the SENDER satisfies one of (a), (b), (c) against the roster; and
//  3. the VIEWER (the receiving user) independently satisfies one of them too:
//     (a) user == roster.iss (the owner, from any device);
//     (b) roster.vis == "workspace" and the user's attestation includes roster.org;
//     (c) user in roster.parts AND (a live friendship between the user and
//         roster.iss OR the user's attestation includes roster.org).
//
// (c) is read as `parts AND (friendship OR attestation)` (C3). The viewer's
// side uses only the viewer's own stored friendships; friendships the sender
// presents count for the sender's side alone (H1). An unfriend burns its
// invite for both.

import type { RejectReason } from "./errors.js";
import { unfriendApplies, type RosterPayload } from "./objects.js";

export interface FriendshipFact {
  inviter: string;
  invitee: string;
  inv: string;
  /** The accept's iat. */
  iat: number;
  /** The invite's iat (unfriends at or after it kill the friendship). */
  inviteIat: number;
}

export interface UnfriendFact {
  iss: string;
  peer: string;
  inv: string;
  iat: number;
}

export interface ExchangeFacts {
  /** Sender certificate: Kartr signature, expiry and revocation all checked. */
  chainValid: boolean;
  /** Envelope signature verified against the certificate's spk. */
  signatureValid: boolean;
  /** Orgs from the sender's verified, unexpired workspace attestation. */
  senderWorkspaceOrgs?: readonly string[];
  /** Orgs from the viewer's own verified, unexpired workspace attestation. */
  viewerWorkspaceOrgs?: readonly string[];
  /**
   * D9: orgs from the roster OWNER's verified, unexpired workspace
   * attestation (sub == roster.iss). Unless it includes roster.org, no rule
   * grants standing through the org, on either side.
   */
  ownerWorkspaceOrgs?: readonly string[];
  /** Verified friendships from the viewer's own store. The only friendships the viewer's side may use. */
  friendships: readonly FriendshipFact[];
  /**
   * Verified friendships the sender presented in this envelope. They count
   * only towards the SENDER's standing, and still die on the viewer's stored
   * unfriends (H1).
   */
  presentedFriendships?: readonly FriendshipFact[];
  /** Verified unfriends from the viewer's own store; they apply to both sides. */
  unfriends: readonly UnfriendFact[];
}

export type ExchangeRule = "owner" | "workspace" | "participant-friend" | "participant-workspace";

export type ExchangeDecision =
  | { ok: true; rule: ExchangeRule; viewerRule: ExchangeRule }
  | { ok: false; reason: RejectReason };

export type RosterFacts = Pick<RosterPayload, "iss" | "vis" | "org" | "parts">;

/** True when a friendship between `a` and `b` exists and no unfriend ends it. */
export function hasLiveFriendship(a: string, b: string, facts: Pick<ExchangeFacts, "friendships" | "unfriends">) {
  const between = facts.friendships.filter(
    (f) => (f.inviter === a && f.invitee === b) || (f.inviter === b && f.invitee === a),
  );
  const live = between.some((f) => !facts.unfriends.some((u) => unfriendApplies(f, u)));
  return { any: between.length > 0, live };
}

type PartyResult =
  | { ok: true; rule: ExchangeRule }
  | { ok: false; why: "not-participant" | "no-friendship" | "unfriended" | "owner-not-in-org" };

/**
 * Rules (a)-(c) for one user against the roster. `ownerInOrg` (D9) says the
 * roster owner is attested in roster.org; without it the org confers nothing.
 */
export function partyAuthorized(
  user: string,
  orgs: readonly string[] | undefined,
  roster: RosterFacts,
  facts: Pick<ExchangeFacts, "friendships" | "unfriends">,
  ownerInOrg: boolean,
): PartyResult {
  if (user === roster.iss) return { ok: true, rule: "owner" };
  const claimsOrg = orgs?.includes(roster.org) ?? false;
  const inOrg = claimsOrg && ownerInOrg;
  if (roster.vis === "workspace" && inOrg) return { ok: true, rule: "workspace" };
  const blockedByOwner = claimsOrg && !ownerInOrg;
  if (!roster.parts.includes(user)) return { ok: false, why: blockedByOwner && roster.vis === "workspace" ? "owner-not-in-org" : "not-participant" };
  const f = hasLiveFriendship(user, roster.iss, facts);
  if (f.live) return { ok: true, rule: "participant-friend" };
  if (inOrg) return { ok: true, rule: "participant-workspace" };
  if (blockedByOwner && !f.any) return { ok: false, why: "owner-not-in-org" };
  return { ok: false, why: f.any ? "unfriended" : "no-friendship" };
}

/** mayExchange with the reason; `rule` is the sender's, `viewerRule` the viewer's. */
export function authorizeExchange(
  viewer: string,
  sender: string,
  roster: RosterFacts,
  facts: ExchangeFacts,
): ExchangeDecision {
  if (!facts.chainValid) return { ok: false, reason: "chain-invalid" };
  if (!facts.signatureValid) return { ok: false, reason: "bad-signature" };
  const senderFacts = { friendships: [...facts.friendships, ...(facts.presentedFriendships ?? [])], unfriends: facts.unfriends };
  const ownerInOrg = facts.ownerWorkspaceOrgs?.includes(roster.org) ?? false;
  const s = partyAuthorized(sender, facts.senderWorkspaceOrgs, roster, senderFacts, ownerInOrg);
  if (!s.ok) return { ok: false, reason: s.why };
  const v = partyAuthorized(viewer, facts.viewerWorkspaceOrgs, roster, { friendships: facts.friendships, unfriends: facts.unfriends }, ownerInOrg);
  if (!v.ok) return { ok: false, reason: v.why === "owner-not-in-org" ? v.why : `viewer-${v.why}` };
  return { ok: true, rule: s.rule, viewerRule: v.rule };
}

/** `mayExchange(viewer, sender, roster, facts) -> bool`. */
export function mayExchange(viewer: string, sender: string, roster: RosterFacts, facts: ExchangeFacts): boolean {
  return authorizeExchange(viewer, sender, roster, facts).ok;
}
