// Copyright 2026 Ix Infrastructure Inc.
//
// Per-person trust for message delivery (`p2p trust`). A front end that holds peers' messages
// for a session approving its own tool calls (the Claude mod) delivers a trusted sender's
// messages without the hold. Trust only skips that hold: a trusted sender's messages are still
// peer data, never the user's instructions.
//
//  - Stored in <home>/config.json (`trust: {users, circles}`, 0600), by full userId and circle id
//    only. A `name@fingerprint` is resolved by its fingerprint among known identities; a bare
//    name or petname is refused (names are self-chosen).
//  - A trusted circle covers its members as the verified circle state has them when asked
//    (`trust check`, `trust ls`): a member removed from it, or who no longer stands in it, stops
//    being trusted, as does everyone once this user leaves the circle.
//  - A blocked user is never trusted (refused when added, left out when checked).

import { isCircleId, isUserId } from "@peer2peer/core/v3";
import type { App } from "./app.js";
import { circleMembers, resolveCircle } from "./circle-ops.js";
import { readFileConfig, updateFileConfigField } from "./config.js";
import { CliError } from "./errors.js";

const FP_ADDRESS = /^[^\s@]+@[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}$/;
/** At most this many trusted users and circles each. */
export const TRUST_MAX = 256;

export interface TrustList {
  users: { userId: string; address: string; blocked: boolean }[];
  /** `open`: the circle is open now, so it trusts nobody until it is invite-only again. */
  circles: { cid: string; name: string | null; joined: boolean; open: boolean; members: string[] }[];
  /** Everyone trusted right now: the users (unblocked) and the standing members of trusted circles. */
  trusted: string[];
}

type Stored = { users: string[]; circles: string[] };

function parseStored(t: unknown): Stored {
  const o = (typeof t === "object" && t !== null ? t : {}) as { users?: unknown; circles?: unknown };
  const strs = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
  return { users: strs(o.users).filter(isUserId), circles: strs(o.circles).filter((c) => isCircleId(c)) };
}

function stored(app: App): Stored {
  return parseStored(readFileConfig(app.home).trust);
}

/**
 * Changes the stored trust under the state lock, against what is stored at that moment (pre-release review
 * N3): a concurrent `p2p trust` or `p2p receipts` can't make this one lose its update, or lose theirs.
 */
function change<R>(app: App, fn: (cur: Stored) => { next?: Stored; result: R }): Promise<R> {
  return updateFileConfigField(app, "trust", (raw) => {
    const cur = parseStored(raw);
    const r = fn(cur);
    const next = r.next ?? cur;
    return { next: { users: [...new Set(next.users)].slice(0, TRUST_MAX), circles: [...new Set(next.circles)].slice(0, TRUST_MAX) }, result: r.result };
  });
}

/** `circle:<cid|name>` names a circle; anything else a user. */
function parseTarget(target: string): { circle: string } | { user: string } {
  const s = target.trim();
  return s.startsWith("circle:") ? { circle: s.slice("circle:".length).trim() } : { user: s };
}

/** A full userId, or name@fingerprint resolved by its fingerprint; never a bare name or petname. */
async function userOf(app: App, input: string): Promise<string> {
  if (isUserId(input)) return input;
  if (!FP_ADDRESS.test(input)) throw new CliError("usage", `trust takes a full userId (p2p:…) or name@fingerprint, never a bare name: names are self-chosen (${input})`);
  return app.resolveUser(input);
}

export async function trustAdd(app: App, target: string): Promise<{ added: string; kind: "user" | "circle"; address?: string; name?: string }> {
  const t = parseTarget(target);
  if ("circle" in t) {
    const c = await resolveCircle(app, t.circle);
    if (!c.record.joinedByMe) throw new CliError("usage", "you can only trust a circle you are in");
    // An open circle admits anyone who asks (P2: no owner decision): trusting it would trust strangers.
    if ((await circleMembers(app, c.record.cid)).circle.policy === "open") throw new CliError("open_circle", "an open circle admits anyone who asks, so it can't be trusted: trust its members one by one");
    const cid = c.record.cid;
    await change(app, (cur) => {
      if (cur.circles.length >= TRUST_MAX && !cur.circles.includes(cid)) throw new CliError("too_many", `at most ${TRUST_MAX} trusted circles`);
      return { next: { ...cur, circles: [...cur.circles, cid] }, result: undefined };
    });
    return { added: cid, kind: "circle", name: c.chain.head.name };
  }
  const userId = await userOf(app, t.user);
  if (userId === app.userId) throw new CliError("usage", "your own devices are always delivered");
  if (await app.store.isBlocked(userId)) throw new CliError("blocked", "you blocked that user: unblock them first");
  await change(app, (cur) => {
    if (cur.users.length >= TRUST_MAX && !cur.users.includes(userId)) throw new CliError("too_many", `at most ${TRUST_MAX} trusted users`);
    return { next: { ...cur, users: [...cur.users, userId] }, result: undefined };
  });
  return { added: userId, kind: "user", address: await app.addressOf(userId) };
}

export async function trustRemove(app: App, target: string): Promise<{ removed: string | null; kind: "user" | "circle" }> {
  const t = parseTarget(target);
  if ("circle" in t) {
    // By cid even when the circle is gone from this device; else by name.
    const cid = isCircleId(t.circle) ? t.circle : await resolveCircle(app, t.circle).then((c) => c.record.cid).catch(() => null);
    if (cid === null) return { removed: null, kind: "circle" };
    return change<{ removed: string | null; kind: "circle" }>(app, (cur) => (cur.circles.includes(cid) ? { next: { ...cur, circles: cur.circles.filter((c) => c !== cid) }, result: { removed: cid, kind: "circle" as const } } : { result: { removed: null, kind: "circle" as const } }));
  }
  const userId = isUserId(t.user) ? t.user : await userOf(app, t.user).catch(() => null);
  if (userId === null) return { removed: null, kind: "user" };
  return change<{ removed: string | null; kind: "user" }>(app, (cur) => (cur.users.includes(userId) ? { next: { ...cur, users: cur.users.filter((u) => u !== userId) }, result: { removed: userId, kind: "user" as const } } : { result: { removed: null, kind: "user" as const } }));
}

/** The standing, unblocked members (not this user) of a trusted circle this user is in, from its verified state. */
async function circleTrusted(app: App, cid: string): Promise<{ name: string | null; joined: boolean; open: boolean; members: string[] }> {
  try {
    const r = await circleMembers(app, cid);
    if (!r.circle.joined) return { name: r.circle.name, joined: false, open: false, members: [] };
    // Open now, per its verified current version: anyone who asks gets in, so it trusts nobody (review N1).
    if (r.circle.policy === "open") return { name: r.circle.name, joined: true, open: true, members: [] };
    const blocked = new Set((await app.store.listBlocks()).map((b) => b.userId));
    return { name: r.circle.name, joined: true, open: false, members: r.members.filter((m) => m.stands && !m.self && !blocked.has(m.userId)).map((m) => m.userId) };
  } catch {
    return { name: null, joined: false, open: false, members: [] };
  }
}

export async function trustList(app: App): Promise<TrustList> {
  const cur = stored(app);
  const users = await Promise.all(cur.users.map(async (u) => ({ userId: u, address: await app.addressOf(u), blocked: await app.store.isBlocked(u) })));
  const circles = await Promise.all(cur.circles.map(async (cid) => ({ cid, ...(await circleTrusted(app, cid)) })));
  const trusted = new Set([...users.filter((u) => !u.blocked).map((u) => u.userId), ...circles.flatMap((c) => c.members)]);
  return { users, circles, trusted: [...trusted] };
}

/** Whether `userId` is trusted right now, and why (the user itself, or a trusted circle). */
export async function trustCheck(app: App, userId: string): Promise<{ userId: string; trusted: boolean; via: string | null }> {
  if (!isUserId(userId)) throw new CliError("usage", "trust check takes a full userId");
  if (await app.store.isBlocked(userId)) return { userId, trusted: false, via: null };
  const cur = stored(app);
  if (cur.users.includes(userId)) return { userId, trusted: true, via: "user" };
  for (const cid of cur.circles) if ((await circleTrusted(app, cid)).members.includes(userId)) return { userId, trusted: true, via: `circle:${cid}` };
  return { userId, trusted: false, via: null };
}
