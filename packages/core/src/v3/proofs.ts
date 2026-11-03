// Copyright 2026 Ix Infrastructure Inc.
//
// Proofs (docs/protocol.md §2.6; `typ: "p2p-proof+jws"`, `kid: "ik"`): an
// optional claim that this identity also controls another name.
//
// A proof found in document D verifies when all of these hold:
//  1. proof.iss == D.iss;
//  2. the proof verifies under D.ik;
//  3. the counterpart at `loc` contains this exact proof (github: a public
//     gist owned by account `claim` whose content contains the proof JWS;
//     dns: a TXT record `_p2p.<claim>` equal to `p2p-proof=<D.iss>`);
//  4. `loc` is the canonical location for that kind and claim:
//     `https://gist.github.com/<claim>/<id>` for github, `_p2p.<claim>` for dns.
// Rules 1–2 stop a proof being transplanted into another identity's
// document (review M3). The network is injected, so this module stays pure.
// Extension kinds (`<ns>.<kind>`) belong to trust providers (§8.2).

import { b64uDecode } from "../encoding.js";
import { signJws, verifyJws } from "../jws.js";
import { fail, P2PError } from "../errors.js";
import { checkIssued, decodeTyped, IK_KID, int, checkFields, nowSec, str, TYP3, userIdField, type TimeOptions } from "./base.js";
import type { IdentityKey } from "./identity.js";
import type { IdentityDocPayload } from "./identitydoc.js";
import { sanitizePeerText } from "./sanitize.js";

export type ProofKind = "github" | "dns" | `${string}.${string}`;

export interface ProofPayload {
  iss: string;
  kind: ProofKind;
  claim: string;
  loc: string;
  iat: number;
}

const GITHUB_HANDLE_RE = /^[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){0,38}$/;
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
const EXT_KIND_RE = /^[a-z][a-z0-9]{0,15}\.[a-z][a-z0-9-]{0,31}$/;
const GIST_ID_RE = /^[A-Za-z0-9]{1,64}$/;

/** The canonical `loc` for a github or dns claim (gist id needed for github). */
export function canonicalProofLoc(kind: "github", claim: string, gistId: string): string;
export function canonicalProofLoc(kind: "dns", claim: string): string;
export function canonicalProofLoc(kind: "github" | "dns", claim: string, gistId?: string): string {
  if (kind === "github") {
    if (!GITHUB_HANDLE_RE.test(claim)) fail("malformed", "github claim must be a lowercase handle");
    if (gistId === undefined || !GIST_ID_RE.test(gistId)) fail("malformed", "gist id");
    return `https://gist.github.com/${claim}/${gistId}`;
  }
  if (!DOMAIN_RE.test(claim)) fail("malformed", "dns claim must be a lowercase domain");
  return `_p2p.${claim}`;
}

/** Rule 4, for the built-in kinds. */
export function isCanonicalProofLoc(kind: string, claim: string, loc: string): boolean {
  if (kind === "github") {
    const m = /^https:\/\/gist\.github\.com\/([^/]+)\/([^/]+)$/.exec(loc);
    return !!m && GITHUB_HANDLE_RE.test(claim) && m[1] === claim && GIST_ID_RE.test(m[2]);
  }
  if (kind === "dns") return DOMAIN_RE.test(claim) && loc === `_p2p.${claim}`;
  return false;
}

/** The TXT value a dns proof's record holds (§2.6). */
export function dnsProofRecord(iss: string): string {
  return `p2p-proof=${iss}`;
}

export function createProof(ik: IdentityKey, p: { kind: ProofKind; claim: string; loc: string; iat?: number }): string {
  const payload: ProofPayload = { iss: ik.userId, kind: p.kind, claim: p.claim, loc: p.loc, iat: p.iat ?? nowSec() };
  validateProofPayload(payload as unknown as Record<string, unknown>);
  return signJws(TYP3.proof, IK_KID, payload, ik.secretKey);
}

function validateProofPayload(p: Record<string, unknown>): ProofPayload {
  checkFields(p, ["iss", "kind", "claim", "loc", "iat"], "proof");
  const kind = str(p, "kind");
  if (kind !== "github" && kind !== "dns" && !EXT_KIND_RE.test(kind)) fail("malformed", `proof kind ${kind}`);
  const claim = str(p, "claim");
  const loc = str(p, "loc");
  if ((kind === "github" || kind === "dns") && !isCanonicalProofLoc(kind, claim, loc)) {
    fail("proof-invalid", `loc is not the canonical location for ${kind}:${claim}`);
  }
  return { iss: userIdField(p, "iss"), kind: kind as ProofKind, claim, loc, iat: int(p, "iat") };
}

/** What the injected counterpart fetchers return. */
export interface ProofFetchers {
  /** Fetches a gist by its canonical URL: its owner login and the text of its files. */
  github?: (loc: string) => Promise<{ owner: string; files: string[] } | undefined>;
  /** Resolves TXT records for a DNS name (each record's strings joined). */
  dnsTxt?: (name: string) => Promise<string[]>;
}

export interface VerifiedProof extends ProofPayload {
  jws: string;
  /** Display string, always prefixed with the kind: "✓ github: alice". */
  display: string;
}

/**
 * Rules 1 and 2 only (no network): the proof belongs to this document.
 * Use verifyProof for the full check before display.
 */
export function verifyProofSignature(jws: string, doc: Pick<IdentityDocPayload, "iss" | "ik">, opts: TimeOptions = {}): ProofPayload {
  const d = decodeTyped(jws, TYP3.proof);
  if (d.header.kid !== IK_KID) fail("kid-mismatch", `kid ${d.header.kid} != ${IK_KID}`);
  const p = validateProofPayload(d.payload);
  if (p.iss !== doc.iss) fail("proof-invalid", `proof is for ${p.iss}, document is ${doc.iss}`);
  verifyJws(jws, { typ: TYP3.proof, kid: IK_KID, publicKey: b64uDecode(doc.ik, 32), badSignature: "proof-invalid" });
  checkIssued(p.iat, opts.now ?? nowSec(), opts.skewSec);
  return p;
}

/** The full §2.6 check, with the counterpart fetched through `fetchers`. */
export async function verifyProof(
  jws: string,
  doc: Pick<IdentityDocPayload, "iss" | "ik">,
  fetchers: ProofFetchers,
  opts: TimeOptions = {},
): Promise<VerifiedProof> {
  const p = verifyProofSignature(jws, doc, opts);
  if (p.kind === "github") {
    if (!fetchers.github) fail("proof-unsupported", "no github fetcher");
    const gist = await fetchers.github(p.loc);
    if (!gist) fail("proof-invalid", "gist not found");
    if (gist.owner.toLowerCase() !== p.claim) fail("proof-invalid", `gist is owned by ${gist.owner}, not ${p.claim}`);
    if (!gist.files.some((f) => f.includes(jws))) fail("proof-invalid", "gist does not contain this proof");
  } else if (p.kind === "dns") {
    if (!fetchers.dnsTxt) fail("proof-unsupported", "no dns resolver");
    const records = await fetchers.dnsTxt(p.loc);
    if (!records.includes(dnsProofRecord(doc.iss))) fail("proof-invalid", `no TXT ${dnsProofRecord(doc.iss)} at ${p.loc}`);
  } else {
    fail("proof-unsupported", `${p.kind} is checked by a trust provider (§8.2)`);
  }
  return { ...p, jws, display: `✓ ${p.kind}: ${sanitizePeerText(p.claim, 64)}` };
}

/** Verifies every proof of a document; returns only those that verified. */
export async function verifiedProofs(
  doc: Pick<IdentityDocPayload, "iss" | "ik" | "proofs">,
  fetchers: ProofFetchers,
  opts: TimeOptions = {},
): Promise<VerifiedProof[]> {
  const out: VerifiedProof[] = [];
  for (const j of doc.proofs ?? []) {
    try {
      out.push(await verifyProof(j, doc, fetchers, opts));
    } catch (e) {
      if (!(e instanceof P2PError)) throw e;
    }
  }
  return out;
}
