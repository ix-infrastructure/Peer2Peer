// Copyright 2026 Ix Infrastructure Inc.
//
// Proof of work on a non-member's `want` (docs/protocol.md §3.3, re-review
// N3). An open circle's link is meant to be shared, so nothing a link carries
// can tell one joiner from a thousand throwaway identities; a per-joiner token
// signed by the owner would need the owner online to mint one per joiner,
// which a public link can't do. What the member can ask instead is work: each
// want from a non-member that wants the reserved budget carries a nonce bound
// to the asker, the member asked (its userId, the hash of its `ik`: one proof
// can't be spent at several members, review F1), the circle, `fromVer` and the
// asker's time, so filling the reserve costs CPU per want and per member, and
// each proof is accepted once. It raises the cost of draining the reserve; it
// can't stop a determined attacker from throttling open-circle joins (§3.3).

import { createHash, randomBytes } from "node:crypto";

/** Leading zero bits a want's proof needs (about 260k hashes, a fraction of a second). */
export const WANT_POW_BITS = 18;
/** How far a proof's `at` may be from the member's clock (the usual skew plus delivery). */
export const WANT_POW_WINDOW_SEC = 600;

export interface WantPow {
  at: number;
  nonce: string;
}

const digest = (from: string, to: string, cid: string, fromVer: number, at: number, nonce: string) =>
  createHash("sha256").update(`p2p/v3/want-pow|${from}|${to}|${cid}|${fromVer}|${at}|${nonce}`).digest();

function leadingZeroBits(b: Buffer): number {
  let n = 0;
  for (const byte of b) {
    if (byte === 0) {
      n += 8;
      continue;
    }
    return n + Math.clz32(byte) - 24;
  }
  return n;
}

/** Finds a proof for `from`'s want to member `to` (at `at`, seconds). */
export function solveWantPow(from: string, to: string, cid: string, fromVer: number, at: number, bits = WANT_POW_BITS): WantPow {
  const prefix = randomBytes(6).toString("base64url");
  for (let i = 0; ; i++) {
    const nonce = `${prefix}${i.toString(36)}`;
    if (leadingZeroBits(digest(from, to, cid, fromVer, at, nonce)) >= bits) return { at, nonce };
  }
}

/** The proof's id (its digest, hex) when it is valid for this want to `to` now, else undefined. */
export function checkWantPow(pow: WantPow | undefined, from: string, to: string, cid: string, fromVer: number, nowSec: number, bits = WANT_POW_BITS): string | undefined {
  if (!pow || Math.abs(nowSec - pow.at) > WANT_POW_WINDOW_SEC) return undefined;
  const d = digest(from, to, cid, fromVer, pow.at, pow.nonce);
  return leadingZeroBits(d) >= bits ? d.toString("hex") : undefined;
}
