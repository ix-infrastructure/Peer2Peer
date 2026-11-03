// Copyright 2026 Ix Infrastructure Inc.
//
// Session rosters (docs/protocol.md §3.4): v2's `p2p-roster+jws` with `ver`,
// `sid`, `parts` and the per-(own, sid) rules, signed by a device of the
// session owner. [v3] `vis` is "circle" or "private", and `org` is replaced by
// `circle: <cid>` (required with vis "circle", optional with "private", where
// it lets participants stand through the circle under §4.2 rule (c)).
// Receivers keep the highest `ver` per (iss, sid); two different rosters at
// the same ver are an equivocation (roster-conflict).

import { signJws } from "../jws.js";
import { fail } from "../errors.js";
import {
  checkIssued,
  cidField,
  DEFAULT_SKEW_SEC,
  didField,
  int,
  isUserId,
  MAX_JWS_BYTES,
  checkFields,
  nowSec,
  str,
  strArray,
  TYP3,
  userIdField,
} from "./base.js";
import type { VerifiedDeviceCertV3 } from "./device.js";
import type { DeviceSignerV3 } from "./friends.js";
import { verifyDeviceSignedV3, type SignerContext } from "./signers.js";

export type RosterVisibilityV3 = "circle" | "private";

export interface RosterV3Payload {
  iss: string;
  did: string;
  sid: string;
  ver: number;
  vis: RosterVisibilityV3;
  circle?: string;
  parts: string[];
  iat: number;
}

export interface VerifiedRosterV3 extends RosterV3Payload {
  jws: string;
  signer: VerifiedDeviceCertV3;
}

export const MAX_ROSTER_PARTS = 1000;

export function createRosterV3(
  signer: DeviceSignerV3,
  p: { sid: string; ver: number; vis: RosterVisibilityV3; circle?: string; parts: string[]; iat?: number },
): string {
  const payload: RosterV3Payload = {
    iss: signer.userId,
    did: signer.did,
    sid: p.sid,
    ver: p.ver,
    vis: p.vis,
    ...(p.circle !== undefined ? { circle: p.circle } : {}),
    parts: p.parts,
    iat: p.iat ?? nowSec(),
  };
  rosterPayload(payload as unknown as Record<string, unknown>);
  const jws = signJws(TYP3.roster, signer.did, payload, signer.signingSecretKey);
  if (jws.length > MAX_JWS_BYTES) fail("malformed", `roster is ${jws.length} bytes, max ${MAX_JWS_BYTES}`);
  return jws;
}

function rosterPayload(p: Record<string, unknown>): RosterV3Payload {
  checkFields(p, ["iss", "did", "sid", "ver", "vis", "circle", "parts", "iat"], "roster");
  const vis = p.vis;
  if (vis !== "circle" && vis !== "private") fail("malformed", "vis must be circle|private");
  const sid = str(p, "sid");
  if (sid.includes("|") || sid.startsWith("~")) fail("malformed", "a session id has no | and doesn't start with ~");
  const r: RosterV3Payload = {
    iss: userIdField(p, "iss"),
    did: didField(p, "did"),
    sid,
    ver: int(p, "ver"),
    vis,
    parts: strArray(p, "parts", {
      max: MAX_ROSTER_PARTS,
      item: (s) => {
        if (!isUserId(s)) fail("malformed", `parts entry ${s} is not a userId`);
      },
    }),
    iat: int(p, "iat"),
  };
  if (p.circle !== undefined) r.circle = cidField(p, "circle");
  if (vis === "circle" && r.circle === undefined) fail("malformed", 'vis "circle" needs a circle');
  return r;
}

/** Verifies a roster: its signer valid now (rules 1–6), and not issued in the future. */
export async function verifyRosterV3(jws: string, ctx: SignerContext): Promise<VerifiedRosterV3> {
  const v = await verifyDeviceSignedV3(jws, TYP3.roster, ctx);
  const r = rosterPayload(v.payload);
  checkIssued(r.iat, ctx.now ?? nowSec(), ctx.skewSec ?? DEFAULT_SKEW_SEC);
  return { ...r, jws, signer: v.signer };
}

export type RosterPutResultV3 = "stored" | "same" | "stale" | "conflict";

/** v2 C10: keep the highest ver; the same ver with different bytes is a conflict. */
export function compareRoster(held: { ver: number; jws: string } | undefined, r: { ver: number; jws: string }): RosterPutResultV3 {
  if (!held) return "stored";
  if (r.ver < held.ver) return "stale";
  if (r.ver === held.ver) return held.jws === r.jws ? "same" : "conflict";
  return "stored";
}
