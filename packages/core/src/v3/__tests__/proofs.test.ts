// Copyright 2026 Ix Infrastructure Inc.
//
// §2.6 proofs: github and dns kinds with an injected fetch, canonical `loc`,
// and review M3 (a proof transplanted into another identity's document).

import { describe, expect, it } from "vitest";
import { canonicalProofLoc, createProof, dnsProofRecord, verifiedProofs, verifyProof, type ProofFetchers } from "../proofs.js";
import { makeUser, NOW } from "./fixtures.js";
import { decodeJws, signJws } from "../../jws.js";

function gist(owner: string, files: string[]): ProofFetchers {
  return { github: async () => ({ owner, files }) };
}

describe("§2.6 proofs", () => {
  it("github: a gist owned by `claim` containing this exact proof", async () => {
    const u = makeUser("alice");
    const loc = canonicalProofLoc("github", "alice", "abc123");
    const proof = createProof(u.ik, { kind: "github", claim: "alice", loc, iat: NOW });
    const doc = u.publish({ proofs: [proof] });
    const v = await verifyProof(proof, doc, gist("Alice", [`hello\n${proof}\n`]), { now: NOW });
    expect(v.display).toBe("✓ github: alice");
    await expect(verifyProof(proof, doc, gist("someone-else", [proof]), { now: NOW })).rejects.toThrow(/owned by/);
    await expect(verifyProof(proof, doc, gist("alice", ["another proof"]), { now: NOW })).rejects.toThrow(/does not contain/);
    await expect(verifyProof(proof, doc, { github: async () => undefined }, { now: NOW })).rejects.toThrow(/not found/);
    await expect(verifyProof(proof, doc, {}, { now: NOW })).rejects.toThrow(/proof-unsupported/);
  });

  it("dns: TXT _p2p.<claim> equal to p2p-proof=<iss>", async () => {
    const u = makeUser("alice");
    const proof = createProof(u.ik, { kind: "dns", claim: "ix-infra.com", loc: canonicalProofLoc("dns", "ix-infra.com"), iat: NOW });
    const asked: string[] = [];
    const fetchers: ProofFetchers = {
      dnsTxt: async (name) => {
        asked.push(name);
        return ["v=spf1", dnsProofRecord(u.userId)];
      },
    };
    expect((await verifyProof(proof, u.doc, fetchers, { now: NOW })).display).toBe("✓ dns: ix-infra.com");
    expect(asked).toEqual(["_p2p.ix-infra.com"]);
    await expect(verifyProof(proof, u.doc, { dnsTxt: async () => ["p2p-proof=p2p:other"] }, { now: NOW })).rejects.toThrow(/no TXT/);
  });

  it("M3: a proof transplanted into another identity's document fails rules 1–2", async () => {
    const victim = makeUser("alice");
    const thief = makeUser("mallory");
    const proof = createProof(victim.ik, { kind: "dns", claim: "ix-infra.com", loc: "_p2p.ix-infra.com", iat: NOW });
    const fetchers: ProofFetchers = { dnsTxt: async () => [dnsProofRecord(victim.userId)] };
    await expect(verifyProof(proof, thief.doc, fetchers, { now: NOW })).rejects.toThrow(/proof-invalid/);
    // Even claiming the thief's iss, the signature is the victim's ik.
    const relabeled = signJws("p2p-proof+jws", "ik", { ...decodeJws(proof).payload, iss: thief.userId }, victim.ik.secretKey);
    await expect(verifyProof(relabeled, thief.doc, { dnsTxt: async () => [dnsProofRecord(thief.userId)] }, { now: NOW })).rejects.toThrow(/proof-invalid/);
  });

  it("rule 4: loc must be the canonical location for the kind and claim", () => {
    const u = makeUser("alice");
    expect(() => createProof(u.ik, { kind: "github", claim: "alice", loc: "https://gist.github.com/evil/abc" })).toThrow(/canonical/);
    expect(() => createProof(u.ik, { kind: "github", claim: "alice", loc: "https://evil.example/alice/abc" })).toThrow(/canonical/);
    expect(() => createProof(u.ik, { kind: "dns", claim: "ix-infra.com", loc: "_p2p.evil.com" })).toThrow(/canonical/);
    expect(() => createProof(u.ik, { kind: "dns", claim: "IX-infra.com", loc: "_p2p.IX-infra.com" })).toThrow(/canonical/);
    expect(() => canonicalProofLoc("github", "Bad Handle", "x")).toThrow(/handle/);
  });

  it("extension kinds go to trust providers; verifiedProofs keeps only verified ones", async () => {
    const u = makeUser("alice");
    const ext = createProof(u.ik, { kind: "kartr.attest", claim: "alice@example.com", loc: "https://kartr.example/a", iat: NOW });
    await expect(verifyProof(ext, u.doc, {}, { now: NOW })).rejects.toThrow(/trust provider/);
    const dns = createProof(u.ik, { kind: "dns", claim: "ix-infra.com", loc: "_p2p.ix-infra.com", iat: NOW });
    const doc = u.publish({ proofs: [ext, dns] });
    const ok = await verifiedProofs(doc, { dnsTxt: async () => [dnsProofRecord(u.userId)] }, { now: NOW });
    expect(ok.map((p) => p.kind)).toEqual(["dns"]);
  });
});
