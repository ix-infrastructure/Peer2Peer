// Copyright 2026 Ix Infrastructure Inc.
import { describe, expect, it } from "vitest";
import { authorizeExchange, mayExchange, type ExchangeFacts } from "../authz.js";
import type { RosterFacts } from "../authz.js";

const OWNER = "owner@a.example";
const FRIEND = "friend@b.example";
const COLLEAGUE = "colleague@a.example";

const facts = (over: Partial<ExchangeFacts> = {}): ExchangeFacts => ({
  chainValid: true,
  signatureValid: true,
  friendships: [{ inviter: OWNER, invitee: FRIEND, inv: "i1", iat: 100, inviteIat: 100 }],
  unfriends: [],
  // D9: the owner is attested in orgA (the rosters' org) unless a test says otherwise.
  ownerWorkspaceOrgs: ["orgA"],
  ...over,
});
const priv: RosterFacts = { iss: OWNER, vis: "private", org: "orgA", parts: [FRIEND, COLLEAGUE] };
const ws: RosterFacts = { ...priv, vis: "workspace", parts: [] };

describe("mayExchange", () => {
  it("1: requires a valid chain and signature", () => {
    expect(authorizeExchange(OWNER, OWNER, priv, facts({ chainValid: false }))).toEqual({ ok: false, reason: "chain-invalid" });
    expect(authorizeExchange(OWNER, OWNER, priv, facts({ signatureValid: false }))).toEqual({ ok: false, reason: "bad-signature" });
  });

  it("2a: the owner, to a viewer who is authorised", () => {
    expect(authorizeExchange(FRIEND, OWNER, priv, facts())).toEqual({ ok: true, rule: "owner", viewerRule: "participant-friend" });
  });

  it("2b: workspace roster + attestation for roster.org", () => {
    expect(authorizeExchange(OWNER, "x@a.example", ws, facts({ senderWorkspaceOrgs: ["orgA"] }))).toEqual({ ok: true, rule: "workspace", viewerRule: "owner" });
    expect(authorizeExchange(OWNER, "x@a.example", ws, facts({ senderWorkspaceOrgs: ["orgB"] }))).toEqual({
      ok: false,
      reason: "not-participant",
    });
  });

  it("2c: participant with a live friendship to the owner", () => {
    expect(authorizeExchange(OWNER, FRIEND, priv, facts())).toEqual({ ok: true, rule: "participant-friend", viewerRule: "owner" });
    // Friendship direction doesn't matter.
    const rev = facts({ friendships: [{ inviter: FRIEND, invitee: OWNER, inv: "i2", iat: 1, inviteIat: 1 }] });
    expect(mayExchange(OWNER, FRIEND, priv, rev)).toBe(true);
  });

  it("2c: participant in roster.org", () => {
    expect(authorizeExchange(OWNER, COLLEAGUE, priv, facts({ senderWorkspaceOrgs: ["orgA"] }))).toEqual({
      ok: true,
      rule: "participant-workspace",
      viewerRule: "owner",
    });
  });

  it("2c: participant with neither", () => {
    expect(authorizeExchange(OWNER, COLLEAGUE, priv, facts())).toEqual({ ok: false, reason: "no-friendship" });
  });

  it("unfriend (newer, same invite) ends the friendship", () => {
    const f = facts({ unfriends: [{ iss: FRIEND, peer: OWNER, inv: "i1", iat: 200 }] });
    expect(authorizeExchange(OWNER, FRIEND, priv, f)).toEqual({ ok: false, reason: "unfriended" });
    // The invite is burned whatever the iats (H1).
    const old = facts({ unfriends: [{ iss: FRIEND, peer: OWNER, inv: "i1", iat: 50 }] });
    expect(mayExchange(OWNER, FRIEND, priv, old)).toBe(false);
    // Re-friending with a new invite revives it.
    const again = facts({
      friendships: [...facts().friendships, { inviter: FRIEND, invitee: OWNER, inv: "i3", iat: 300, inviteIat: 300 }],
      unfriends: [{ iss: FRIEND, peer: OWNER, inv: "i1", iat: 200 }],
    });
    expect(mayExchange(OWNER, FRIEND, priv, again)).toBe(true);
  });

  it("private roster: a workspace member not in parts is rejected", () => {
    expect(authorizeExchange(OWNER, "other@a.example", priv, facts({ senderWorkspaceOrgs: ["orgA"] }))).toEqual({
      ok: false,
      reason: "not-participant",
    });
  });

  it("a friend of the owner who is not in parts is rejected", () => {
    const f = facts({ friendships: [{ inviter: OWNER, invitee: "pal@c.example", inv: "x", iat: 1, inviteIat: 1 }] });
    expect(authorizeExchange(OWNER, "pal@c.example", priv, f)).toEqual({ ok: false, reason: "not-participant" });
  });

  describe("two-sided: the viewer must be authorised too", () => {
    it("an owner's message to a viewer who unfriended them is rejected", () => {
      const f = facts({ unfriends: [{ iss: FRIEND, peer: OWNER, inv: "i1", iat: 200 }] });
      expect(authorizeExchange(FRIEND, OWNER, priv, f)).toEqual({ ok: false, reason: "viewer-unfriended" });
      // ...unless the viewer is still authorised through the workspace.
      expect(authorizeExchange(FRIEND, OWNER, priv, { ...f, viewerWorkspaceOrgs: ["orgA"] })).toEqual({
        ok: true,
        rule: "owner",
        viewerRule: "participant-workspace",
      });
    });

    it("a viewer outside the roster rejects even the owner", () => {
      expect(authorizeExchange("stranger@z.example", OWNER, priv, facts())).toEqual({ ok: false, reason: "viewer-not-participant" });
    });

    it("a viewer in parts with no friendship and no workspace rejects", () => {
      expect(authorizeExchange(COLLEAGUE, OWNER, priv, facts())).toEqual({ ok: false, reason: "viewer-no-friendship" });
      expect(mayExchange(COLLEAGUE, OWNER, priv, facts({ viewerWorkspaceOrgs: ["orgA"] }))).toBe(true);
    });

    it("participant to participant: both need their own standing", () => {
      const both = facts({
        friendships: [
          { inviter: OWNER, invitee: FRIEND, inv: "i1", iat: 1, inviteIat: 1 },
          { inviter: OWNER, invitee: COLLEAGUE, inv: "i2", iat: 1, inviteIat: 1 },
        ],
      });
      expect(authorizeExchange(COLLEAGUE, FRIEND, priv, both)).toEqual({
        ok: true,
        rule: "participant-friend",
        viewerRule: "participant-friend",
      });
    });

    it("sender failures are reported before viewer failures", () => {
      expect(authorizeExchange("stranger@z.example", "other@z.example", priv, facts())).toEqual({
        ok: false,
        reason: "not-participant",
      });
    });

    it("workspace roster: a viewer in the org is enough", () => {
      expect(
        authorizeExchange("y@a.example", "x@a.example", ws, facts({ senderWorkspaceOrgs: ["orgA"], viewerWorkspaceOrgs: ["orgA"] })),
      ).toEqual({ ok: true, rule: "workspace", viewerRule: "workspace" });
    });
  });

  describe("D9: roster.org needs the owner's attestation", () => {
    const noOwner = { ownerWorkspaceOrgs: undefined };
    it("a workspace roster grants no org standing without it, on either side", () => {
      expect(authorizeExchange(OWNER, "x@a.example", ws, facts({ ...noOwner, senderWorkspaceOrgs: ["orgA"] }))).toEqual({
        ok: false,
        reason: "owner-not-in-org",
      });
      // The Mallory shape: owner sender, viewer only "in" the owner's claimed org.
      expect(authorizeExchange("victim@a.example", OWNER, ws, facts({ ...noOwner, viewerWorkspaceOrgs: ["orgA"] }))).toEqual({
        ok: false,
        reason: "owner-not-in-org",
      });
      expect(
        authorizeExchange("victim@a.example", OWNER, ws, facts({ ownerWorkspaceOrgs: ["evil"], viewerWorkspaceOrgs: ["orgA"] })),
      ).toEqual({ ok: false, reason: "owner-not-in-org" });
    });

    it("rule (c) via the org needs it too; friendship and owner rules don't", () => {
      expect(authorizeExchange(OWNER, COLLEAGUE, priv, facts({ ...noOwner, senderWorkspaceOrgs: ["orgA"] }))).toEqual({
        ok: false,
        reason: "owner-not-in-org",
      });
      expect(authorizeExchange(OWNER, FRIEND, priv, facts(noOwner))).toEqual({
        ok: true,
        rule: "participant-friend",
        viewerRule: "owner",
      });
      expect(authorizeExchange(FRIEND, OWNER, priv, facts(noOwner))).toEqual({
        ok: true,
        rule: "owner",
        viewerRule: "participant-friend",
      });
    });
  });
});
