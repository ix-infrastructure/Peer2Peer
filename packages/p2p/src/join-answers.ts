// Copyright 2026 Ix Infrastructure Inc.
//
// What a joiner holds of each confirmer's answer to its `want` (§3.3), while
// the answer arrives in parts. One document per (circle, confirmer), so a part
// rewrites only its sender's document, never the joins index. Bounded and
// filtered as it comes in (review M4): only versions of the circle being
// joined, at most MAX_NEWER_VERSIONS above the offered head, at most two per
// `ver`, each at most a JWS's 16 KiB; at most a few statements per member; at
// most 8 answers' part records; and a byte ceiling per confirmer. Anything
// beyond is dropped. (Versions newer than the offered head are kept, within
// that margin: the join confirms the newest head the members send, review M3.)

import { createHash } from "node:crypto";
import { decodeTyped, MAX_CHAIN_IN_BUNDLE, MAX_JWS_BYTES, parseCircleVersion, TYP3, type AnswerPart } from "@peer2peer/core/v3";
import type { App } from "./app.js";
import type { AnswerPartsRec } from "./state.js";

export interface JoinAnswerDoc {
  cid: string;
  from: string;
  versions: string[];
  joins: string[];
  parts: Record<string, AnswerPartsRec>;
  bytes: number;
}

/** Distinct versions kept per `ver` (a sibling, at most: more is someone else's noise). */
export const MAX_VERSIONS_PER_VER = 2;
/** Versions above the offered head kept per confirmer: a link can be older than the circle's head. */
export const MAX_NEWER_VERSIONS = 256;
/**
 * Answers a member sends one asker per rolling hour, and so the new answers (part ids) a joiner
 * takes from one confirmer per rolling hour: one limit on both sides (review N-D; the joiner took 4
 * while a member may send 10, so a legitimate fifth answer was dropped). Parts of answers already
 * tracked always count.
 */
export const ANSWERS_PER_HOUR = 10;
export const MAX_NEW_ANSWERS_PER_HOUR = ANSWERS_PER_HOUR;
/** Answers whose parts are tracked per confirmer (the newest): more than a confirmer may start in an hour. */
export const MAX_PART_RECORDS = ANSWERS_PER_HOUR + 2;

/** A statement for `cid` (a `p2p-join+jws` naming it), parsed before it is stored (review F4). */
function isStatementFor(j: unknown, cid: string): j is string {
  if (typeof j !== "string" || j.length > MAX_JWS_BYTES) return false;
  try {
    return decodeTyped(j, TYP3.join).payload.cid === cid;
  } catch {
    return false;
  }
}

/**
 * The fixed ceiling on what one confirmer's answer may take, whatever the offered head claims
 * (re-review N1: the head comes from a link, unverified, so whoever writes the link must not set
 * the ceiling).
 */
export const ANSWER_MAX_BYTES = 32 * 1024 * 1024;

/** The highest `ver` kept: no chain longer than a bundle may carry is bootstrapped (MAX_CHAIN_IN_BUNDLE). */
export function maxVerFor(offeredVer: number): number {
  return Math.min(Math.min(offeredVer, MAX_CHAIN_IN_BUNDLE) + MAX_NEWER_VERSIONS, MAX_CHAIN_IN_BUNDLE);
}

/**
 * A confirmer's byte ceiling: two full versions per `ver` up to the (clamped) offered head, plus 4
 * statements per member of 16 KiB, never more than ANSWER_MAX_BYTES.
 */
export function answerByteCap(offeredVer: number, members: number): number {
  const vers = Math.min(Math.max(0, offeredVer), MAX_CHAIN_IN_BUNDLE);
  const m = Math.min(Math.max(0, members), MAX_CHAIN_IN_BUNDLE);
  return Math.min(ANSWER_MAX_BYTES, vers * MAX_VERSIONS_PER_VER * MAX_JWS_BYTES + (m + 4) * 4 * MAX_JWS_BYTES);
}

export const answerDocName = (cid: string, from: string) => `joinans-${createHash("sha256").update(`${cid}|${from}`).digest("hex").slice(0, 16)}`;

/**
 * Adds what one envelope brought to `from`'s answer for `cid`, within the bounds above. Returns
 * whether anything was kept.
 */
export async function addToAnswer(
  app: App,
  cid: string,
  from: string,
  bound: { offeredVer: number; members: number },
  versions: readonly string[],
  joins: readonly string[],
  part?: AnswerPart,
): Promise<void> {
  const maxVer = maxVerFor(bound.offeredVer);
  const cap = answerByteCap(maxVer, bound.members);
  // Parsing is outside the lock: only what fits the circle and the offered head goes further.
  const fit: { jws: string; ver: number }[] = [];
  let top = 0;
  for (const v of versions) {
    if (typeof v !== "string" || v.length > MAX_JWS_BYTES) continue;
    try {
      const p = parseCircleVersion(v);
      if (p.cid !== cid || p.ver > maxVer) continue;
      fit.push({ jws: v, ver: p.ver });
      if (p.ver > top) top = p.ver;
    } catch {
      // not a version
    }
  }
  const stmts = joins.filter((j) => isStatementFor(j, cid));
  await app.state.updateDoc<JoinAnswerDoc, void>(answerDocName(cid, from), (cur) => {
    const doc: JoinAnswerDoc = cur && cur.cid === cid && cur.from === from ? cur : { cid, from, versions: [], joins: [], parts: {}, bytes: 0 };
    const have = new Set(doc.versions);
    const perVer = new Map<number, number>();
    for (const v of doc.versions) {
      try {
        const ver = parseCircleVersion(v).ver;
        perVer.set(ver, (perVer.get(ver) ?? 0) + 1);
      } catch {
        // kept versions parse
      }
    }
    let changed = false;
    let bytes = doc.bytes;
    const versionsNext = [...doc.versions];
    for (const f of fit) {
      if (have.has(f.jws) || (perVer.get(f.ver) ?? 0) >= MAX_VERSIONS_PER_VER || bytes + f.jws.length > cap) continue;
      have.add(f.jws);
      perVer.set(f.ver, (perVer.get(f.ver) ?? 0) + 1);
      versionsNext.push(f.jws);
      bytes += f.jws.length;
      changed = true;
    }
    const haveJ = new Set(doc.joins);
    const joinsNext = [...doc.joins];
    const maxJoins = (bound.members + 4) * 4;
    for (const j of stmts) {
      if (haveJ.has(j) || joinsNext.length >= maxJoins || bytes + j.length > cap) continue;
      haveJ.add(j);
      joinsNext.push(j);
      bytes += j.length;
      changed = true;
    }
    let parts = doc.parts;
    const now = Date.now();
    const newIds = Object.values(parts).filter((r) => r.at !== undefined && now - r.at < 3_600_000).length;
    // review F4: a new answer id is taken only while the confirmer hasn't started too many this hour.
    if (part && (parts[part.id] !== undefined || newIds < MAX_NEW_ANSWERS_PER_HOUR)) {
      const r = parts[part.id] ?? { n: part.n, got: [], top: 0, at: now };
      if (r.n === part.n && !r.got.includes(part.i)) {
        parts = { ...parts, [part.id]: { ...r, got: [...r.got, part.i], top: Math.max(r.top, top) } };
        changed = true;
        const ids = Object.keys(parts);
        // The newest records only (insertion order): an asker who re-asks often can't grow this.
        if (ids.length > MAX_PART_RECORDS) parts = Object.fromEntries(ids.slice(-MAX_PART_RECORDS).map((k) => [k, parts[k]]));
      }
    }
    // Re-review N5: a part that adds nothing (a duplicate, or all of it over a bound) writes nothing.
    if (!changed && cur) return { result: undefined };
    return { next: { cid, from, versions: versionsNext, joins: joinsNext, parts, bytes }, result: undefined };
  });
}

export async function readAnswer(app: App, cid: string, from: string): Promise<JoinAnswerDoc | undefined> {
  const d = await app.state.getDoc<JoinAnswerDoc>(answerDocName(cid, from));
  return d && d.cid === cid && d.from === from ? d : undefined;
}

export async function dropAnswers(app: App, cid: string, froms: readonly string[]): Promise<void> {
  for (const f of froms) await app.state.removeDoc(answerDocName(cid, f)).catch(() => undefined);
}
