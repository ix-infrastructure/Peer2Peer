// Copyright 2026 Ix Infrastructure Inc.
//
// Draft 2 D9: a roster's `org` confers workspace standing only when the
// roster OWNER is attested (Kartr workspace attestation) in that org.

import { beforeEach, describe, expect, it } from "vitest";
import { FakeKartr, NOW, Peer } from "./fixtures.js";
import { createInvite, createRoster } from "../objects.js";
import { decodeEnvelope, openEnvelope, parsePlaintext } from "../envelope.js";
import type { IncomingResult } from "../verify.js";

const outcome = (r: IncomingResult) => (r.ok ? `${r.rule}/${r.viewerRule}` : r.reason);

describe("D9: roster.org requires the owner's attestation", () => {
  let kartr: FakeKartr;
  beforeEach(() => {
    kartr = new FakeKartr();
  });

  it("the Mallory attack: a self-declared org grants the victim nothing", async () => {
    const mallory = new Peer(kartr, "mallory@evil.io");
    mallory.workspace = kartr.attest(mallory.userId, ["evil"]);
    const victim = new Peer(kartr, "victim@acme.com");
    victim.workspace = kartr.attest(victim.userId, ["acme"]);
    // Her invite doubles as her directory-lookup proof; it creates no friendship.
    createInvite(mallory.keys, { aud: victim.userId, iat: NOW });
    const roster = createRoster(mallory.keys, { sid: "s", ver: 1, vis: "workspace", org: "acme", parts: [], iat: NOW });
    expect(outcome(await victim.receive(mallory.seal(victim, { sid: "s", roster, text: "click me" })))).toBe(
      "owner-not-in-org",
    );
    // Same with no attestation at all, and as a private roster naming the victim.
    mallory.workspace = undefined;
    const priv = createRoster(mallory.keys, { sid: "p", ver: 1, vis: "private", org: "acme", parts: [victim.userId], iat: NOW });
    expect(outcome(await victim.receive(mallory.seal(victim, { sid: "p", roster: priv })))).toBe("owner-not-in-org");
    expect(outcome(await victim.receive(mallory.seal(victim, { sid: "s", roster: createRoster(mallory.keys, { sid: "s", ver: 2, vis: "workspace", org: "acme", parts: [], iat: NOW }) })))).toBe("owner-not-in-org");
  });

  it("a legitimate same-org workspace session still works, both directions", async () => {
    const owner = new Peer(kartr, "owner@acme.com");
    owner.workspace = kartr.attest(owner.userId, ["acme"]);
    const colleague = new Peer(kartr, "colleague@acme.com");
    colleague.workspace = kartr.attest(colleague.userId, ["acme"]);
    const roster = createRoster(owner.keys, { sid: "s", ver: 1, vis: "workspace", org: "acme", parts: [], iat: NOW });
    const env = owner.seal(colleague, { sid: "s", roster });
    // sealEnvelope added the owner's attestation as ownerWorkspace.
    const pt = parsePlaintext(openEnvelope(decodeEnvelope(env).payload, colleague.keys.agreementSecretKey, owner.keys.agreementPublicKey));
    expect(pt.ownerWorkspace).toBe(owner.workspace);
    expect(outcome(await colleague.receive(env))).toBe("owner/workspace");
    // The colleague (non-owner) replies, relaying the owner's attestation.
    colleague.ownerWorkspaces.set(owner.userId, owner.workspace!);
    expect(outcome(await owner.receive(colleague.seal(owner, { sid: "s", own: owner.userId, roster })))).toBe("workspace/owner");
  });

  it("a non-owner sender relays the owner's attestation to a third member", async () => {
    const owner = new Peer(kartr, "owner@acme.com");
    owner.workspace = kartr.attest(owner.userId, ["acme"]);
    const a = new Peer(kartr, "a@acme.com");
    a.workspace = kartr.attest(a.userId, ["acme"]);
    const b = new Peer(kartr, "b@acme.com");
    b.workspace = kartr.attest(b.userId, ["acme"]);
    const roster = createRoster(owner.keys, { sid: "s", ver: 1, vis: "workspace", org: "acme", parts: [], iat: NOW });
    // Without the relayed attestation, a's message gives b no org standing.
    expect(outcome(await b.receive(a.seal(b, { sid: "s", own: owner.userId, roster })))).toBe("owner-not-in-org");
    a.ownerWorkspaces.set(owner.userId, owner.workspace!);
    expect(outcome(await b.receive(a.seal(b, { sid: "s", own: owner.userId, roster })))).toBe("workspace/workspace");
  });

  it("a forged, expired or someone else's owner attestation is rejected", async () => {
    const owner = new Peer(kartr, "owner@acme.com");
    const a = new Peer(kartr, "a@acme.com");
    a.workspace = kartr.attest(a.userId, ["acme"]);
    const b = new Peer(kartr, "b@acme.com");
    b.workspace = kartr.attest(b.userId, ["acme"]);
    const roster = createRoster(owner.keys, { sid: "s", ver: 1, vis: "workspace", org: "acme", parts: [], iat: NOW });
    const forger = new FakeKartr(); // same kid scheme, wrong key: unknown kid
    a.ownerWorkspaces.set(owner.userId, forger.attest(owner.userId, ["acme"]));
    expect(outcome(await b.receive(a.seal(b, { sid: "s", own: owner.userId, roster })))).toBe("unknown-kartr-key");
    a.ownerWorkspaces.set(owner.userId, kartr.attest(owner.userId, ["acme"], { iat: NOW - 25 * 3600 }));
    expect(outcome(await b.receive(a.seal(b, { sid: "s", own: owner.userId, roster })))).toBe("expired");
    a.ownerWorkspaces.set(owner.userId, kartr.attest(a.userId, ["acme"])); // a's own, not the owner's
    expect(outcome(await b.receive(a.seal(b, { sid: "s", own: owner.userId, roster })))).toBe("owner-workspace-mismatch");
  });

  it("an owner attested in other orgs only doesn't confer roster.org", async () => {
    const owner = new Peer(kartr, "owner@acme.com");
    owner.workspace = kartr.attest(owner.userId, ["other"]);
    const colleague = new Peer(kartr, "colleague@acme.com");
    colleague.workspace = kartr.attest(colleague.userId, ["acme"]);
    const roster = createRoster(owner.keys, { sid: "s", ver: 1, vis: "private", org: "acme", parts: [colleague.userId], iat: NOW });
    expect(outcome(await colleague.receive(owner.seal(colleague, { sid: "s", roster })))).toBe("owner-not-in-org");
  });

  it("the owner as viewer uses its own attestation: a teammate needn't relay it", async () => {
    const owner = new Peer(kartr, "owner@acme.com");
    owner.workspace = kartr.attest(owner.userId, ["acme"]);
    const colleague = new Peer(kartr, "colleague@acme.com");
    colleague.workspace = kartr.attest(colleague.userId, ["acme"]);
    const roster = createRoster(owner.keys, { sid: "s", ver: 1, vis: "workspace", org: "acme", parts: [], iat: NOW });
    const env = colleague.seal(owner, { sid: "s", own: owner.userId, roster });
    const pt = parsePlaintext(openEnvelope(decodeEnvelope(env).payload, owner.keys.agreementSecretKey, colleague.keys.agreementPublicKey));
    expect(pt.ownerWorkspace).toBeUndefined();
    expect(outcome(await owner.receive(env))).toBe("workspace/owner");
    // ...but not if the owner's own attestation doesn't include the org.
    owner.workspace = kartr.attest(owner.userId, ["other"]);
    expect(outcome(await owner.receive(colleague.seal(owner, { sid: "s", own: owner.userId })))).toBe("owner-not-in-org");
  });

  it("caches the newest relayed owner attestation until it expires", async () => {
    const owner = new Peer(kartr, "owner@acme.com");
    const ownerAtt = kartr.attest(owner.userId, ["acme"], { iat: NOW - 60 }); // exp NOW + 24h - 60
    const a = new Peer(kartr, "a@acme.com");
    const b = new Peer(kartr, "b@acme.com");
    a.workspace = kartr.attest(a.userId, ["acme"]);
    b.workspace = kartr.attest(b.userId, ["acme"]);
    const roster = createRoster(owner.keys, { sid: "s", ver: 1, vis: "workspace", org: "acme", parts: [], iat: NOW });

    // Relayed once...
    a.ownerWorkspaces.set(owner.userId, ownerAtt);
    expect(outcome(await b.receive(a.seal(b, { sid: "s", own: owner.userId, roster })))).toBe("workspace/workspace");
    expect((await b.trust.getOwnerWorkspace(owner.userId))?.jws).toBe(ownerAtt);
    // ...then later envelopes without it still work from the cache.
    a.ownerWorkspaces.clear();
    for (const dt of [3600, 12 * 3600]) {
      a.nowMs = b.nowMs = (NOW + dt) * 1000;
      expect(outcome(await b.receive(a.seal(b, { sid: "s", own: owner.userId })))).toBe("workspace/workspace");
    }
    // An older attestation relayed later doesn't replace the newer cached one.
    const older = kartr.attest(owner.userId, ["acme"], { iat: NOW - 3600 });
    a.ownerWorkspaces.set(owner.userId, older);
    expect(outcome(await b.receive(a.seal(b, { sid: "s", own: owner.userId })))).toBe("workspace/workspace");
    expect((await b.trust.getOwnerWorkspace(owner.userId))?.jws).toBe(ownerAtt);
    a.ownerWorkspaces.clear();

    // Past the owner attestation's expiry (members' own attestations renewed),
    // the cached copy no longer counts.
    const later = NOW + 24 * 3600 + 60;
    a.nowMs = b.nowMs = later * 1000;
    a.workspace = kartr.attest(a.userId, ["acme"], { iat: later - 60 });
    b.workspace = kartr.attest(b.userId, ["acme"], { iat: later - 60 });
    expect(outcome(await b.receive(a.seal(b, { sid: "s", own: owner.userId })))).toBe("owner-not-in-org");
    // A fresh relayed attestation restores it.
    a.ownerWorkspaces.set(owner.userId, kartr.attest(owner.userId, ["acme"], { iat: later - 30 }));
    expect(outcome(await b.receive(a.seal(b, { sid: "s", own: owner.userId })))).toBe("workspace/workspace");
  });

  it("a rejected envelope doesn't populate the cache", async () => {
    const owner = new Peer(kartr, "owner@acme.com");
    const stranger = new Peer(kartr, "stranger@else.io");
    const b = new Peer(kartr, "b@acme.com");
    b.workspace = kartr.attest(b.userId, ["acme"]);
    const roster = createRoster(owner.keys, { sid: "s", ver: 1, vis: "private", org: "acme", parts: [b.userId], iat: NOW });
    stranger.ownerWorkspaces.set(owner.userId, kartr.attest(owner.userId, ["acme"]));
    expect(outcome(await b.receive(stranger.seal(b, { sid: "s", own: owner.userId, roster })))).toBe("not-participant");
    expect(await b.trust.getOwnerWorkspace(owner.userId)).toBeUndefined();
  });
});
