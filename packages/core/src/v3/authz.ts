// Copyright 2026 Ix Infrastructure Inc.
//
// v3 authorisation (docs/protocol.md §4.2): v2's two-sided mayExchange with
// circles in place of workspaces, as a pure function over facts the caller
// has already verified. A user satisfies the rules for a roster R when:
//   (a) user == R.iss;
//   (b) R.vis == "circle" and both R.iss and user stand in R.circle (§3.3);
//   (c) user ∈ R.parts and either a live friendship between user and R.iss,
//       or both R.iss and user stand in R.circle.
// Both the sender and the viewer must pass, independently:
//  - the viewer's side uses only the viewer's own stored friendships (v2 H1)
//    and circles it has joined (review C1); sender-presented friendships
//    count for the sender's side only, and still die on stored unfriends;
//  - blocks (§3.2) override every rule;
//  - (b) needs the owner to stand in the circle, replacing v2's D9
//    owner-attestation machinery.

import type { RejectReason } from "../errors.js";
import { liveFriendship } from "./friends.js";
import type { RosterV3Payload } from "./roster.js";

export interface FriendshipFactV3 {
  inviter: string;
  invitee: string;
  inv: string;
  inviteIat: number;
}

export interface UnfriendFactV3 {
  iss: string;
  peer: string;
  inv: string;
  iat: number;
}

export interface ExchangeFactsV3 {
  /** Verified friendships from the viewer's own store (re-verified now). */
  friendships: readonly FriendshipFactV3[];
  /** Friendships the sender presented in this envelope: the sender's side only (H1). */
  presentedFriendships?: readonly FriendshipFactV3[];
  /** Unfriends from the viewer's own store; they apply to both sides. */
  unfriends: readonly UnfriendFactV3[];
  /**
   * Does `user` stand in circle `cid` on this client (standsInCircle, which
   * already requires the viewer to have joined `cid`)?
   */
  stands: (user: string, cid: string) => boolean;
  /** Local blocks (§3.2). */
  isBlocked: (user: string) => boolean;
}

export type ExchangeRuleV3 = "owner" | "circle" | "participant-friend" | "participant-circle";

export type ExchangeDecisionV3 = { ok: true; rule: ExchangeRuleV3; viewerRule: ExchangeRuleV3 } | { ok: false; reason: RejectReason };

export type RosterFactsV3 = Pick<RosterV3Payload, "iss" | "vis" | "circle" | "parts">;

type PartyResult = { ok: true; rule: ExchangeRuleV3 } | { ok: false; why: "not-participant" | "no-friendship" | "unfriended" | "not-standing" };

/** Rules (a)–(c) for one user. */
export function partyAuthorizedV3(
  user: string,
  roster: RosterFactsV3,
  facts: Pick<ExchangeFactsV3, "friendships" | "unfriends" | "stands">,
): PartyResult {
  if (user === roster.iss) return { ok: true, rule: "owner" };
  const viaCircle = roster.circle !== undefined && facts.stands(roster.iss, roster.circle) && facts.stands(user, roster.circle);
  if (roster.vis === "circle" && viaCircle) return { ok: true, rule: "circle" };
  if (!roster.parts.includes(user)) return { ok: false, why: roster.vis === "circle" ? "not-standing" : "not-participant" };
  const f = liveFriendship(user, roster.iss, facts.friendships, facts.unfriends);
  if (f.live) return { ok: true, rule: "participant-friend" };
  if (viaCircle) return { ok: true, rule: "participant-circle" };
  return { ok: false, why: f.any ? "unfriended" : "no-friendship" };
}

/** Two-sided mayExchange with the reason. Sender failures first; viewer failures carry `viewer-`. */
export function authorizeExchangeV3(viewer: string, sender: string, roster: RosterFactsV3, facts: ExchangeFactsV3): ExchangeDecisionV3 {
  if (facts.isBlocked(sender) || facts.isBlocked(roster.iss)) return { ok: false, reason: "blocked" };
  const senderFacts = { ...facts, friendships: [...facts.friendships, ...(facts.presentedFriendships ?? [])] };
  const s = partyAuthorizedV3(sender, roster, senderFacts);
  if (!s.ok) return { ok: false, reason: s.why };
  const v = partyAuthorizedV3(viewer, roster, facts);
  if (!v.ok) return { ok: false, reason: `viewer-${v.why}` };
  return { ok: true, rule: s.rule, viewerRule: v.rule };
}

/** `mayExchange(viewer, sender, roster, facts) -> bool`. */
export function mayExchangeV3(viewer: string, sender: string, roster: RosterFactsV3, facts: ExchangeFactsV3): boolean {
  return authorizeExchangeV3(viewer, sender, roster, facts).ok;
}
