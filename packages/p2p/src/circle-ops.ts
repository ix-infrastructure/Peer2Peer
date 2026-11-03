// Copyright 2026 Ix Infrastructure Inc.
//
// Circles (docs/protocol.md §3.3 and draft 3 additions P2).
//
//  - Only the owner's identity key signs versions; this device does so when
//    it holds `ik` and the head names its user as owner. Admins send
//    proposals (`circle` envelopes, `ops`), which the owner's client applies.
//  - The owner sends every new version, with the membership statements it
//    holds, to every member and to its own devices (`distribute`).
//  - Joining confirms first (§3.3 "confirm before joining"): the client asks
//    the owner, and one other member it can reach, for the head (`want`),
//    and refuses on any conflict. With no other member to ask, the owner's
//    answer is enough; otherwise an unconfirmed join needs the user's say.
//  - Open circles (P2): the owner's client applies joins automatically under
//    `policy: "open"` (at most 20 an hour), holds the rest.
//
// Readings chosen here:
//  - CLI circle links append `~<b64u(hint)>` to the spec link, where the hint
//    is `{doc, join}`: the owner's identity document and current join
//    statement. A stranger needs them to reach the owner at all (the head
//    names only the owner's userId, and `circle` envelopes need a cap). A
//    plain spec link still works when the owner is already reachable.
//  - A stranger's `want` carries an answer cap (§3.3, draft 3 amendment), so
//    the answer goes as ordinary `circle` bundles, chunked like any other:
//    a long chain no longer has to fit one first-contact envelope. Answers to
//    non-members are rate-limited per asker and in bytes overall
//    (admitStrangerAnswer). An older client's want without a cap still gets
//    the single `contact` circle invite `{circle, chain}` when it fits.
//  - Transfer consent (`p2p-circle-accept+jws`) travels to the owner in a
//    `circle` envelope's `ops`; core ignores it there, the CLI stores it.

import {
  ANSWER_CAP_MAX_TTL_SEC,
  applyCircleBundle,
  applyOwnerProposals,
  b64uDecode,
  b64uEncode,
  CircleChain,
  circleDisplayName,
  circleInviteLink,
  circlePolicy,
  confirmJoin,
  createCap,
  createCircle,
  createCircleTransferAccept,
  createMembershipStatement,
  createNextCircleVersion,
  createProposal,
  decideOpenJoinFor,
  joinCapTtlFor,
  openCircleCapActions,
  outgoingCircleBundle,
  decodeTyped,
  freshnessLookup,
  jwsHash,
  liveFriendshipsV3,
  loadCircle,
  nextMembershipN,
  parseCircleInviteLink,
  parseCircleVersion,
  pickConfirmers,
  recordOwnJoin,
  recordOwnLeave,
  standsInCircle,
  storeOfferedCircle,
  TYP3,
  verifyMembershipStatement,
  type AcceptedMessageV3,
  type CirclePolicy,
  type LoadedCircle,
  type NextVersionParams,
  type ProposalOp,
  type RotationStatement,
  type VerifiedCircleVersion,
  type VerifiedMembership,
  verifyCap,
  P2PError,
  type AnswerPart,
  MAX_CHAIN_IN_BUNDLE,
  nowSec,
} from "@peer2peer/core/v3";
import { randomBytes } from "node:crypto";
import { App, capPeek, joinCapOf, type Delivery } from "./app.js";
import { guardForeignRelays } from "./social.js";
import { CliError } from "./errors.js";
import { fromOf, makeEvent, type NewEvent } from "./inbound.js";
import type { AnswerPartsRec, HeldItem, PendingJoin } from "./state.js";
import { dropHeld, hold, withHeldId } from "./social.js";
import { chunkBody, exportCircle, sendSync, SYNC_CHUNK_BYTES } from "./sync.js";
import { addToAnswer, ANSWERS_PER_HOUR, dropAnswers, readAnswer } from "./join-answers.js";
import { checkWantPow, solveWantPow, WANT_POW_WINDOW_SEC, type WantPow } from "./want-pow.js";
import { circleHeld, onRotationJoin } from "./rotation.js";

const CIRCLE_SID = { sid: "~circle" };

// ---------------------------------------------------------------------------
// Lookup and links

export async function resolveCircle(app: App, input: string): Promise<LoadedCircle> {
  const direct = await loadCircle(app.store, input);
  if (direct) return direct;
  const hits: LoadedCircle[] = [];
  for (const r of await app.store.listCircles()) {
    const c = await loadCircle(app.store, r.cid);
    if (c && (circleDisplayName(c.chain.head) === input || r.cid.startsWith(input))) hits.push(c);
  }
  if (hits.length === 1) return hits[0];
  if (hits.length > 1) throw new CliError("ambiguous", `more than one circle matches ${input}`, { candidates: hits.map((h) => h.record.cid) });
  throw new CliError("not_found", `no circle ${input} here (see \`p2p circle ls\`)`);
}

export interface CircleHint {
  doc?: string;
  join?: string;
}

export function encodeCircleLink(head: string, hint: CircleHint | undefined, web = false): string {
  const base = circleInviteLink(head, { web });
  if (!hint || (!hint.doc && !hint.join)) return base;
  return `${base}~${b64uEncode(new TextEncoder().encode(JSON.stringify(hint)))}`;
}

export function parseCircleLink(link: string): { head: string; hint?: CircleHint } {
  const s = link.trim();
  const i = s.indexOf("~");
  const head = parseCircleInviteLink(i >= 0 ? s.slice(0, i) : s);
  if (i < 0) return { head };
  let hint: CircleHint;
  try {
    const v = JSON.parse(new TextDecoder().decode(b64uDecode(s.slice(i + 1)))) as Record<string, unknown>;
    hint = {
      ...(typeof v.doc === "string" ? { doc: v.doc } : {}),
      ...(typeof v.join === "string" ? { join: v.join } : {}),
    };
  } catch {
    throw new CliError("usage", "the circle link's owner hint is damaged");
  }
  return { head, hint };
}

async function ownerHint(app: App, c: LoadedCircle): Promise<CircleHint> {
  const owner = c.chain.head.owner;
  const v = await app.view(owner);
  const join = c.book[owner]?.op === "join" ? c.book[owner].jws : undefined;
  return { ...(v ? { doc: v.head.jws } : {}), ...(join ? { join } : {}) };
}

export async function circleLink(app: App, cidOrName: string): Promise<{ cid: string; link: string; web: string; policy: CirclePolicy }> {
  const c = await resolveCircle(app, cidOrName);
  const hint = await ownerHint(app, c);
  return {
    cid: c.record.cid,
    link: encodeCircleLink(c.chain.head.jws, hint),
    web: encodeCircleLink(c.chain.head.jws, hint, true),
    policy: circlePolicy(c.chain.head),
  };
}

// ---------------------------------------------------------------------------
// Own membership

async function chainOpts(app: App) {
  return { ...app.signerCtx(), self: app.userId, identityFreshness: await freshnessLookup(app.store) };
}

/** Signs and records our own join (§3.3), with a fresh co-member cap. */
export async function signOwnJoin(app: App, cid: string, at: string): Promise<VerifiedMembership> {
  const rec = await app.store.getCircle(cid);
  const policy = rec ? circlePolicy(CircleChain.fromStored(rec.chain).head) : "invite";
  const cap = createCap(app.device!, app.keys!.cert, { purpose: "join", relays: app.relays, ttlSec: joinCapTtlFor(policy) });
  const jws = createMembershipStatement(app.signer(), { cid, n: nextMembershipN(rec?.myN), op: "join", at, cap });
  const v = await verifyMembershipStatement(jws, app.signerCtx());
  await recordJoin(app, v);
  await app.recordIssued(cap);
  return v;
}

/**
 * Re-signs our join in `cid` (n+1, a fresh co-member cap on our current
 * relays) and sends it to the members and our other devices (review L5).
 */
export async function resignJoin(app: App, cid: string): Promise<boolean> {
  const c = await loadCircle(app.store, cid);
  if (!c || !c.record.joinedByMe || c.book[app.userId]?.op !== "join") return false;
  await signOwnJoin(app, cid, c.chain.head.hash);
  const mine = (await loadCircle(app.store, cid))!.book[app.userId].jws;
  for (const m of c.chain.head.members) {
    // Never to someone we blocked: the block re-keyed our join so their copy stops working (R3-L1).
    if (m === app.userId || (await app.store.isBlocked(m))) continue;
    await deliverCircle(app, m, { joins: [mine] }, memberCaps(c, m)).catch(() => undefined);
  }
  const exp = await exportCircle(app, cid);
  if (exp) await sendSync(app, { circles: [exp] });
  return true;
}

/** Thin wrapper: the core hardening PR changes recordOwnJoin's signature (adds `self`). */
export async function recordJoin(app: App, v: VerifiedMembership): Promise<void> {
  await recordOwnJoin(app.store, app.userId, v);
}

export interface CircleSummary {
  cid: string;
  name: string;
  ver: number;
  policy: CirclePolicy;
  owner: string;
  ownerAddress: string;
  role: "owner" | "admin" | "member" | "invited" | "former";
  joined: boolean;
  members: number;
  standing: number;
  frozen?: string;
  isDefault: boolean;
}

async function summary(app: App, c: LoadedCircle): Promise<CircleSummary> {
  const h = c.chain.head;
  const blocks = new Set((await app.store.listBlocks()).map((b) => b.userId));
  const ctx = { viewer: app.userId, joinedByMe: c.record.joinedByMe, isBlocked: (u: string) => blocks.has(u) };
  const role = h.owner === app.userId ? "owner" : h.admins.includes(app.userId) ? "admin" : h.members.includes(app.userId) ? "member" : c.record.joinedByMe ? "invited" : "former";
  return {
    cid: c.record.cid,
    name: circleDisplayName(h),
    ver: h.ver,
    policy: circlePolicy(h),
    owner: h.owner,
    ownerAddress: await app.addressOf(h.owner),
    role: c.record.joinedByMe || role === "owner" ? role : h.members.includes(app.userId) ? "invited" : "former",
    joined: c.record.joinedByMe,
    members: h.members.length,
    standing: h.members.filter((m) => standsInCircle(m, c.chain, c.book, ctx)).length,
    ...(c.chain.frozen ? { frozen: c.chain.frozen.reason } : {}),
    isDefault: app.self?.defaultCircle === c.record.cid,
  };
}

export async function createCircleCmd(app: App, name: string, opts: { open?: boolean }): Promise<CircleSummary & { link?: string }> {
  const ik = app.requireKeyholder("Founding a circle");
  if (name.trim() === "" || [...name].length > 128) throw new CliError("usage", "a circle name is 1–128 characters");
  const v1 = createCircle(ik, { name, ...(opts.open ? { policy: "open" as const } : {}) });
  const chain = await storeOfferedCircle(app.store, [v1]);
  await signOwnJoin(app, chain.cid, chain.head.hash);
  await app.connect({ allowNone: true });
  const exp = await exportCircle(app, chain.cid);
  if (exp) await sendSync(app, { circles: [exp] });
  const c = (await loadCircle(app.store, chain.cid))!;
  const s = await summary(app, c);
  return opts.open ? { ...s, link: (await circleLink(app, chain.cid)).link } : s;
}

export async function listCircles(app: App): Promise<CircleSummary[]> {
  const out: CircleSummary[] = [];
  for (const r of await app.store.listCircles()) {
    const c = await loadCircle(app.store, r.cid);
    if (c) out.push(await summary(app, c));
  }
  return out;
}

export interface MemberRow {
  userId: string;
  address: string;
  owner: boolean;
  admin: boolean;
  stands: boolean;
  statement: "join" | "leave" | null;
  self: boolean;
}

export async function circleMembers(app: App, cidOrName: string): Promise<{ circle: CircleSummary; founder: string; members: MemberRow[] }> {
  const c = await resolveCircle(app, cidOrName);
  const h = c.chain.head;
  const blocks = new Set((await app.store.listBlocks()).map((b) => b.userId));
  const ctx = { viewer: app.userId, joinedByMe: c.record.joinedByMe, isBlocked: (u: string) => blocks.has(u) };
  const members: MemberRow[] = [];
  for (const m of h.members) {
    members.push({
      userId: m,
      address: await app.addressOf(m),
      owner: m === h.owner,
      admin: h.admins.includes(m),
      stands: standsInCircle(m, c.chain, c.book, ctx),
      statement: c.book[m]?.op ?? null,
      self: m === app.userId,
    });
  }
  return { circle: await summary(app, c), founder: h.founder, members };
}

/**
 * Sets (or with undefined unsets) the default circle. `byJoin`: a code join set it because there was
 * none, so sessions already running don't move into it (sessions.ts getSession); the user's own
 * `circle default` clears that, and sessions follow it again.
 */
export async function setDefaultCircle(app: App, cidOrName: string | undefined, opts: { byJoin?: boolean } = {}): Promise<{ defaultCircle: string | null }> {
  let cid: string | undefined;
  if (cidOrName !== undefined) {
    const c = await resolveCircle(app, cidOrName);
    if (!c.record.joinedByMe) throw new CliError("usage", "join the circle first");
    cid = c.record.cid;
  }
  await app.updateSelf((s) => {
    const { defaultFromJoin: _was, ...rest } = s;
    return { ...rest, defaultCircle: cid, ...(opts.byJoin && cid ? { defaultFromJoin: cid } : {}) };
  });
  await sendSync(app, { defaultCircle: cid ?? null, ...(opts.byJoin && cid ? { defaultFromJoin: cid } : {}) }).catch(() => 0);
  return { defaultCircle: cid ?? null };
}

// ---------------------------------------------------------------------------
// Owner: publishing and distribution

/** Signs the owner's next version, applies it here, and sends it out. */
export async function ownerPublish(app: App, cid: string, p: NextVersionParams, opts: { alsoTo?: string[] } = {}): Promise<VerifiedCircleVersion> {
  const ik = app.requireKeyholder("Signing a circle version");
  const c = await loadCircle(app.store, cid);
  if (!c) throw new CliError("not_found", `circle ${cid} is not held`);
  if (c.chain.head.owner !== app.userId) throw new CliError("not_owner", "only the circle's owner signs versions; admins propose");
  const v = createNextCircleVersion(ik, c.chain.head, p);
  const res = await applyCircleBundle(app.store, { circles: [v], joins: [], ops: [] }, await chainOpts(app));
  const r = res.versions[cid]?.[0];
  if (!r || (r.status !== "accepted" && r.status !== "replaced")) throw new CliError("internal", `own circle version not accepted (${r?.status} ${r?.reason ?? ""})`);
  const removed = c.chain.head.members.filter((m) => !(p.members ?? c.chain.head.members).includes(m));
  await distribute(app, cid, [...removed, ...(opts.alsoTo ?? [])]);
  // Members-only relays that follow this circle admit (and cut off) by its head: tell them now.
  await app.pushCircleToRelays(cid);
  return (await loadCircle(app.store, cid))!.chain.head;
}

/** Sends the chain and every statement held to every member (and `extra`), and to our own devices. */
export async function distribute(app: App, cid: string, extra: readonly string[] = []): Promise<{ delivered: string[]; failed: string[] }> {
  const c = await loadCircle(app.store, cid);
  if (!c) return { delivered: [], failed: [] };
  const out = await outgoingCircleBundle(app.store, cid);
  const bundle = { circles: out?.circles ?? [], joins: out?.joins ?? [], ops: [] as string[] };
  const recipients = [...new Set([...c.chain.head.members, ...extra])].filter((u) => u !== app.userId);
  const delivered: string[] = [];
  const failed: string[] = [];
  const parts = chunkBody(bundle);
  // R3-L1: our own join statement (and so our co-member cap) never goes to someone we blocked:
  // a block re-keys it. Other members can still pass it on; reach is relay-level only, and our
  // client drops whatever a blocked user sends.
  const mine = c.book[app.userId]?.jws;
  const blocked = new Set((await app.store.listBlocks()).map((b) => b.userId));
  for (const u of recipients) {
    let ok = false;
    for (const part of parts) {
      try {
        const joins = (part.joins ?? []).filter((j) => !(blocked.has(u) && j === mine));
        const d = await app.deliver(u, "circle", { own: app.userId, ...CIRCLE_SID }, { circles: part.circles ?? [], joins, ops: [] }, { extraCaps: memberCaps(c, u) });
        ok = ok || d.relays.length > 0;
      } catch {
        // no cap for them yet (an invitee who hasn't joined), or unreachable
      }
    }
    (ok ? delivered : failed).push(u);
  }
  // §3.3: the owner's own devices receive every version too.
  const view = await app.view(app.userId);
  if (view && view.devices.some((d) => d !== app.did)) {
    for (const part of parts) {
      await app.deliver(app.userId, "circle", { own: app.userId, ...CIRCLE_SID }, { circles: part.circles ?? [], joins: part.joins ?? [], ops: [] }).catch(() => undefined);
    }
  }
  return { delivered, failed };
}

export async function deliverCircle(app: App, to: string, body: { circles?: string[]; joins?: string[]; ops?: string[] }, extraCaps: string[] = []): Promise<Delivery> {
  return app.deliver(to, "circle", { own: app.userId, ...CIRCLE_SID }, { circles: body.circles ?? [], joins: body.joins ?? [], ops: body.ops ?? [] }, { extraCaps });
}

// ---------------------------------------------------------------------------
// Invites and links

export async function inviteToCircle(app: App, cidOrName: string, who: string): Promise<{ cid: string; invited: string; address: string; added: boolean; delivered: Delivery }> {
  await app.connectAndDrain();
  const c = await resolveCircle(app, cidOrName);
  const cid = c.record.cid;
  const u = await app.resolveUser(who);
  const h = c.chain.head;
  let added = false;
  if (h.owner === app.userId) {
    if (!h.members.includes(u)) {
      await ownerPublish(app, cid, { members: [...h.members, u] });
      added = true;
    }
  } else if (h.admins.includes(app.userId)) {
    const p = createProposal(app.signer(), { cid, base: h.ver, op: "add", target: u });
    await deliverCircle(app, h.owner, { ops: [p] }, ownerCaps(c));
  } else {
    throw new CliError("not_admin", "only the owner or an admin can invite to this circle; share `p2p circle invite <cid> --link` instead");
  }
  const cur = (await loadCircle(app.store, cid))!;
  const ob = await outgoingCircleBundle(app.store, cid);
  const versions = ob?.circles ?? cur.chain.versionsFrom(1);
  const statements = ob?.joins ?? [];
  const caps = await app.capsFor(u, "circle");
  let delivered: Delivery;
  if (caps.size > 0) {
    delivered = await deliverCircle(app, u, { circles: versions, joins: statements });
  } else {
    if (!(await app.viewFor(u))) throw new CliError("unknown_user", `can't find ${who}'s identity document on your relays; send them a link instead`);
    delivered = await app.deliver(u, "contact", { own: app.userId, sid: "~contact" }, { circle: cur.chain.head.jws, chain: versions.slice(0, -1) });
  }
  if (delivered.relays.length === 0) throw new CliError("undelivered", "the circle invite was delivered via 0 relays", { delivered });
  return { cid, invited: u, address: await app.addressOf(u), added, delivered };
}

/**
 * P4: adds `u`, who just redeemed one of our short codes for `cid`. The owner
 * (on a key-holding device) publishes the next version at once, which
 * distribution delivers to `u` too; an admin proposes the add to the owner
 * and sends `u` the circle as it stands. Never drains (it runs while
 * envelopes are being handled).
 */
export async function addMemberViaCode(app: App, cid: string, u: string): Promise<{ status: "added" | "already" | "proposed" | "failed"; name?: string; reason?: string }> {
  const c = await loadCircle(app.store, cid);
  if (!c) return { status: "failed", reason: "circle not held here" };
  const h = c.chain.head;
  const name = circleDisplayName(h);
  // Already a member: not the code's doing, so `p2p remove` leaves it.
  if (h.members.includes(u)) return { status: "already", name };
  if (h.owner === app.userId && app.isKeyholder) {
    await ownerPublish(app, cid, { members: [...h.members, u] });
    return { status: "added", name };
  }
  if (!h.admins.includes(app.userId)) {
    return { status: "failed", name, reason: h.owner === app.userId ? "this device doesn't hold your identity key: add them from one that does (p2p circle invite)" : "you are no longer an admin of the circle" };
  }
  const p = createProposal(app.signer(), { cid, base: h.ver, op: "add", target: u });
  await deliverCircle(app, h.owner, { ops: [p] }, ownerCaps(c));
  const ob = await outgoingCircleBundle(app.store, cid);
  await deliverCircle(app, u, { circles: ob?.circles ?? c.chain.versionsFrom(1), joins: ob?.joins ?? [] });
  return { status: "proposed", name };
}

/** P4 `p2p remove`: takes `u` out of a circle we own (or proposes it as an admin). */
export async function removeMember(app: App, cid: string, u: string): Promise<"removed" | "proposed" | "not-member" | "not-allowed"> {
  const c = await loadCircle(app.store, cid);
  if (!c) return "not-member";
  const h = c.chain.head;
  if (!h.members.includes(u)) return "not-member";
  if (u === h.owner) return "not-allowed";
  if (h.owner === app.userId && app.isKeyholder) {
    await ownerPublish(app, cid, { members: h.members.filter((m) => m !== u), admins: h.admins.filter((m) => m !== u) });
    return "removed";
  }
  if (!h.admins.includes(app.userId)) return "not-allowed";
  const p = createProposal(app.signer(), { cid, base: h.ver, op: "remove", target: u });
  await deliverCircle(app, h.owner, { ops: [p] }, ownerCaps(c));
  return "proposed";
}

function ownerCaps(c: LoadedCircle): string[] {
  return memberCaps(c, c.chain.head.owner);
}

/** The co-member cap from `u`'s current join statement, for paths where we may no longer stand (leave, removal). */
export function memberCaps(c: LoadedCircle, u: string): string[] {
  const s = c.book[u];
  const cap = s?.op === "join" ? joinCapOf(s.jws) : undefined;
  return cap ? [cap] : [];
}

// ---------------------------------------------------------------------------
// Joining (§3.3 bootstrap + confirm before joining; P2 open circles)

export interface JoinResult {
  status: "joined" | "waiting" | "unconfirmed" | "already" | "refused";
  /** status "refused": why (JoinInput.accept). */
  refused?: string;
  cid: string;
  name: string;
  owner: string;
  ownerAddress: string;
  founder: string;
  inviter?: string;
  ownershipChanged: boolean;
  policy: CirclePolicy;
  confirmation?: "confirmed" | "owner-only" | "unconfirmed";
  asked: string[];
  answered: string[];
  delivered?: Delivery[];
  openWarning?: boolean;
}

export interface JoinInput {
  head: string;
  chain?: string[];
  joins?: string[];
  inviter?: string;
  hint?: CircleHint;
  /**
   * Checked on the head actually joined (the newest consistent chain, which may be newer than the
   * offered head) before anything is stored: a reason refuses the join (status "refused"). A code
   * join passes its own rules here (codes.ts), so a circle that turned open, or changed hands or
   * name, since the code was made is never joined from it.
   */
  accept?: (head: VerifiedCircleVersion) => string | undefined;
}

/**
 * Stores a confirmer's answer for a pending join; true when it matched one. An answer can span
 * several envelopes (a chunked bundle, each marked `part` i of n): versions accumulate, the parts
 * received are recorded so the join knows when the answer is whole, and a part carrying only
 * statements names its circle with `cid`.
 */
export async function recordJoinAnswer(
  app: App,
  from: string,
  versions: readonly string[],
  joins: readonly string[],
  opts: { cid?: string; part?: AnswerPart } = {},
): Promise<boolean> {
  let cid: string | undefined = opts.cid;
  for (const v of cid ? [] : versions) {
    try {
      cid = parseCircleVersion(v).cid;
      break;
    } catch {
      // skip
    }
  }
  if (!cid) return false;
  // A read, not an update: the joins index is rewritten only the first time a confirmer answers.
  const p = (await app.state.get("joins"))?.[cid];
  if (!p) return false;
  // review L1: only the members we asked (and the inviter) answer; anyone else's chain is ignored.
  if (!p.asked.includes(from) && p.inviter !== from) return false;
  let offered: { ver: number; members: string[] };
  try {
    offered = parseCircleVersion(p.head);
  } catch {
    return false;
  }
  if (!(p.answerFrom ?? []).includes(from)) {
    await app.state.update("joins", (cur = {}) => {
      const q = cur[cid!];
      if (!q || (q.answerFrom ?? []).includes(from)) return { result: undefined };
      return { next: { ...cur, [cid!]: { ...q, answerFrom: [...(q.answerFrom ?? []), from] } }, result: undefined };
    });
  }
  await addToAnswer(app, cid, from, { offeredVer: offered.ver, members: offered.members.length }, versions, joins, opts.part);
  return true;
}

/** Each confirmer's answer so far for a pending join (older state's `answers` included). */
async function pendingAnswers(app: App, p: PendingJoin | undefined): Promise<Record<string, { versions: string[]; joins: string[]; parts?: Record<string, AnswerPartsRec> }>> {
  const out: Record<string, { versions: string[]; joins: string[]; parts?: Record<string, AnswerPartsRec> }> = {};
  if (!p) return out;
  for (const [from, vs] of Object.entries(p.answers ?? {})) out[from] = { versions: vs, joins: [] };
  for (const from of p.answerFrom ?? []) {
    const d = await readAnswer(app, p.cid, from);
    if (!d) continue;
    const prev = out[from];
    out[from] = { versions: prev ? [...new Set([...prev.versions, ...d.versions])] : d.versions, joins: d.joins, parts: d.parts };
  }
  return out;
}

async function knownUsers(app: App): Promise<Set<string>> {
  const s = new Set<string>();
  for (const f of await liveFriendshipsV3(app.store, app.signerCtx())) s.add(f.inviter === app.userId ? f.invitee : f.inviter);
  for (const r of await app.store.listCircles()) {
    if (!r.joinedByMe) continue;
    for (const m of CircleChain.fromStored(r.chain).head.members) s.add(m);
  }
  s.delete(app.userId);
  return s;
}

/** The highest version `n` such that `versions` hold every version of their circle from 1 to `n` (0: none). */
export function contiguousTop(versions: readonly string[] | undefined): number {
  const vers = new Set<number>();
  let cid: string | undefined;
  for (const v of versions ?? []) {
    try {
      const p = parseCircleVersion(v);
      if (cid !== undefined && p.cid !== cid) continue;
      cid = p.cid;
      vers.add(p.ver);
    } catch {
      // skip
    }
  }
  let n = 0;
  while (vers.has(n + 1)) n++;
  return n;
}

/**
 * Whether a confirmer's answer is whole (§3.3): it holds every version from 1 up to the offered
 * head's `ver` (a prefix of the chain confirms nothing), and, when it came in marked parts, every
 * part of one answer that reached that far arrived, statements included. An unmarked answer (one
 * envelope, or an older member) counts once its versions reach the offered head.
 */
export function answerComplete(versions: readonly string[] | undefined, parts: Record<string, AnswerPartsRec> | undefined, offeredVer: number): boolean {
  if (contiguousTop(versions) < offeredVer) return false;
  const recs = Object.values(parts ?? {});
  if (recs.length === 0) return true;
  // A whole answer that reached the offered head, or a whole one carrying no versions: the
  // member's answer to a want from past its head (the joiner held every version already and asked
  // for the rest, which is the statements).
  return recs.some((r) => r.got.length >= r.n && (r.top >= offeredVer || r.top === 0));
}

/**
 * The `want` asking `u` for a circle's history. Unless `u` is a friend (who holds our friend
 * cap), it carries an answer cap for `u` (§3.3, draft 3 amendment: sub `u`, kinds ["*"], a day at
 * most), so the answer can come as ordinary `circle` bundles in as many envelopes as it needs.
 * Recorded as issued, so a block revokes it.
 */
async function wantFor(app: App, cid: string, u: string, fromVer: number): Promise<{ want: { cid: string; fromVer: number }; cap?: string; pow?: WantPow }> {
  const friend = (await liveFriendshipsV3(app.store, app.signerCtx(), (f) => [f.inviter, f.invitee].includes(u))).some((f) => f.inviter === u || f.invitee === u);
  if (friend) return { want: { cid, fromVer } };
  const cap = createCap(app.device!, app.keys!.cert, { purpose: "answer", sub: u, relays: app.relays, ttlSec: ANSWER_CAP_MAX_TTL_SEC });
  const issued = await app.recordIssued(cap);
  // L1: our other devices know of it too (so a block there revokes it), and the join revokes it when done.
  await app.state.update("joins", (cur = {}) => {
    const p = cur[cid];
    return p ? { next: { ...cur, [cid]: { ...p, answerCaps: [...(p.answerCaps ?? []), issued.capid] } }, result: undefined } : { result: undefined };
  });
  await sendSync(app, { capsIssued: [issued] }).catch(() => undefined);
  // Re-review N3: work, so the member's reserved budget for non-members can't be drained by throwaway identities.
  return { want: { cid, fromVer }, cap, pow: solveWantPow(app.userId, u, cid, fromVer, nowSec()) };
}

/** Lists `u` as asked for a pending join, asked at `at` (ms; 0: due to be asked again). */
async function markAsked(app: App, cid: string, u: string, at: number): Promise<void> {
  await app.state.update("joins", (cur = {}) => {
    const p = cur[cid];
    return p ? { next: { ...cur, [cid]: { ...p, asked: [...new Set([...p.asked, u])], askedAtBy: { ...p.askedAtBy, [u]: at } } }, result: undefined } : { result: undefined };
  });
}

/** How old an unanswered request for a circle's history is before a join asks again. */
export const JOIN_REASK_MS = 60_000;

export async function joinCircle(app: App, input: JoinInput, opts: { waitSec?: number; yes?: boolean; confirm?: (q: string) => Promise<boolean> } = {}): Promise<JoinResult> {
  const offeredHead = parseCircleVersion(input.head);
  // Re-review N1: no chain longer than a bundle may carry is ever bootstrapped.
  if (offeredHead.ver > MAX_CHAIN_IN_BUNDLE) throw new CliError("join_conflict", `the offered circle claims ${offeredHead.ver} versions, more than ${MAX_CHAIN_IN_BUNDLE} can be bootstrapped`);
  const cid = offeredHead.cid;
  const base = {
    cid,
    name: circleDisplayName(offeredHead),
    owner: offeredHead.owner,
    ownerAddress: await app.addressOf(offeredHead.owner),
    founder: offeredHead.founder,
    ...(input.inviter ? { inviter: input.inviter } : {}),
    ownershipChanged: offeredHead.owner !== offeredHead.founder,
    policy: circlePolicy(offeredHead),
  };
  const held = await app.store.getCircle(cid);
  if (held?.joinedByMe) return { ...base, status: "already", asked: [], answered: [] };
  await app.connect();
  // The owner hint (CLI circle links): its document and join cap let us reach the owner.
  const extraOwnerCaps: string[] = [];
  if (input.hint?.join) {
    const cap = joinCapOf(input.hint.join);
    if (cap) extraOwnerCaps.push(cap);
  }
  if (input.hint?.doc) await app.refreshIdentity(offeredHead.owner, App.relaysOf(input.hint.doc), { force: true });
  await app.state.update("joins", (cur = {}) => {
    const p: PendingJoin = cur[cid] ?? { cid, head: input.head, joins: [], asked: [], askedAt: Date.now() };
    if (input.inviter) p.inviter = input.inviter;
    if (input.hint) p.hint = input.hint;
    if (input.joins) p.joins = [...new Set([...p.joins, ...input.joins])];
    return { next: { ...cur, [cid]: p }, result: undefined };
  });
  // The inviter's chain is its answer, stored like any other (bounded the same way).
  if (input.chain && input.inviter) await recordJoinAnswer(app, input.inviter, [...input.chain, input.head], []);
  await app.pool!.drain(app.tun.drainQuietMs, app.tun.drainMaxMs);
  const pickFrom = { ...offeredHead, jws: input.head, hash: jwsHash(input.head), signer: offeredHead.owner, isTransfer: false } as VerifiedCircleVersion;
  const conf = pickConfirmers(pickFrom, { inviter: input.inviter ?? "", self: app.userId, known: await knownUsers(app) });
  const confirmers = [conf.owner, ...(conf.other ? [conf.other] : [])].filter((u) => u !== app.userId);
  let pending = (await app.state.get("joins"))?.[cid];
  const asked: string[] = [];
  // Someone asked before who never answered is asked again once the last ask is a while old: the
  // request (or its answer) can be lost, and an unanswered join otherwise waits for good.
  const reask = (u: string) => pending !== undefined && Date.now() - (pending.askedAtBy?.[u] ?? pending.askedAt) >= JOIN_REASK_MS;
  let got = await pendingAnswers(app, pending);
  const whole = (u: string) => answerComplete(got[u]?.versions, got[u]?.parts, offeredHead.ver);
  for (const u of confirmers) {
    if (whole(u) || (pending?.asked.includes(u) && !reask(u))) continue;
    // A part answer (parts lost, or the member's hourly budget ran out) is resumed from what is missing.
    const fromVer = contiguousTop(got[u]?.versions) + 1;
    try {
      const want = await wantFor(app, cid, u, fromVer);
      // pre-release soak: recorded as asked BEFORE the want goes out. A member can answer within a second,
      // and another process of ours (the watch) may take the answer before this one gets here: an
      // answer from someone not yet listed as asked is dropped (review L1), and the member's limits
      // then refuse to send it again.
      await markAsked(app, cid, u, Date.now());
      const d = await app.deliver(u, "circle", { own: app.userId, ...CIRCLE_SID }, want, { extraCaps: u === offeredHead.owner ? extraOwnerCaps : [] });
      if (d.relays.length > 0) asked.push(u);
      // Not delivered: listed, but due to be asked again on the next try.
      else await markAsked(app, cid, u, 0);
    } catch (e) {
      await markAsked(app, cid, u, 0).catch(() => undefined);
      app.io.err(`couldn't ask ${await app.addressOf(u)} for the circle's history: ${(e as Error).message}`);
    }
  }
  const deadline = Date.now() + (opts.waitSec ?? 0) * 1000;
  // An answer counts once it is whole: a long chain comes in several envelopes (chunked bundles).
  // Keep listening, up to the overall deadline, while parts are still arriving.
  for (;;) {
    pending = (await app.state.get("joins"))?.[cid];
    got = await pendingAnswers(app, pending);
    if (confirmers.every((u) => whole(u)) || Date.now() >= deadline) break;
    await app.pool!.drain(Math.min(500, app.tun.drainQuietMs), Math.max(0, Math.min(2000, deadline - Date.now())));
  }
  pending = (await app.state.get("joins"))?.[cid];
  got = await pendingAnswers(app, pending);
  // Parts of an answer still on their way wait for the next try (they stay stored); a prefix of
  // the chain counts for nobody, the second confirmer included.
  const answers = Object.fromEntries(Object.entries(got).filter(([u]) => whole(u)).map(([u, a]) => [u, a.versions]));
  const statements = [...new Set([...(pending?.joins ?? []), ...Object.values(got).flatMap((a) => a.joins)])];
  const answered = Object.keys(answers);
  const offeredVersions = answers[offeredHead.owner] ?? (input.inviter ? answers[input.inviter] : undefined);
  if (!offeredVersions) {
    return { ...base, status: "waiting", asked: pending?.asked ?? asked, answered };
  }
  // §3.3 bootstrap: the full chain from version 1, with the offered head on it.
  // A gap (a version or the offered head still missing) means waiting, never a conflict: the join
  // stays pending and the next try asks for what is missing.
  const isGap = (e: unknown) => e instanceof P2PError && e.reason === "circle-gap";
  let offered: CircleChain;
  try {
    offered = CircleChain.bootstrap(offeredVersions, { head: input.head, ...(await chainOpts(app)) });
  } catch (e) {
    // Re-review N4: a gap with every version up to the offered head's `ver` present means the
    // offered head isn't on the chain at all (a fork): that is a conflict, not something to wait for.
    if (isGap(e) && contiguousTop(offeredVersions) < offeredHead.ver) return { ...base, status: "waiting", asked: pending?.asked ?? asked, answered };
    await dropPending(app, cid);
    throw new CliError("join_conflict", `the circle's history doesn't check out: ${(e as Error).message}`);
  }
  const chains: { from: string; chain: CircleChain }[] = [];
  for (const [from, vs] of Object.entries(answers)) {
    try {
      chains.push({ from, chain: CircleChain.bootstrap(vs) });
    } catch (e) {
      if (isGap(e)) continue;
      await dropPending(app, cid);
      throw new CliError("join_conflict", `${await app.addressOf(from)} answered with a chain that doesn't verify; not joining`);
    }
  }
  // Every answer must agree with the offered chain (§3.3: refuse on any conflict).
  if (confirmJoin(offered, chains, { inviter: input.inviter ?? "", self: app.userId }) === "conflict") {
    await dropPending(app, cid);
    throw new CliError("join_conflict", "the answers about this circle conflict with the offered chain: refusing to join (§3.3)");
  }
  // We join the longest consistent chain (an answer may be newer than the link), so the
  // confirmation is judged on THAT head (review M3): its owner, and another member it lists.
  const best = chains.reduce((a, b) => (b.chain.head.ver > a.head.ver ? b.chain : a), offered);
  if (!best.hasAncestor(jwsHash(input.head))) {
    await dropPending(app, cid);
    throw new CliError("join_conflict", "the newest chain the members sent doesn't contain the offered head: refusing to join");
  }
  // What the join is about to commit to is `best`, not the offered head: the caller's rules apply to it.
  const refused = input.accept?.(best.head);
  if (refused) {
    await dropPending(app, cid);
    return { ...base, ...headFacts(best.head), status: "refused", refused, asked: pending?.asked ?? asked, answered };
  }
  const conf2 = pickConfirmers(best.head, { inviter: input.inviter ?? "", self: app.userId, known: await knownUsers(app) });
  // review N-C: like the first confirmers, asked again once its last ask is old (or failed: due 0).
  if (conf2.other && !answers[conf2.other] && (!(pending?.asked ?? []).includes(conf2.other) || reask(conf2.other))) {
    try {
      const want = await wantFor(app, cid, conf2.other, contiguousTop(got[conf2.other]?.versions) + 1);
      // Listed before it goes out (see above); its own ask time, so it is asked again on its own clock.
      await markAsked(app, cid, conf2.other, Date.now());
      const d = await app.deliver(conf2.other, "circle", { own: app.userId, ...CIRCLE_SID }, want);
      if (d.relays.length === 0) await markAsked(app, cid, conf2.other, 0);
    } catch {
      // not reachable yet
      await markAsked(app, cid, conf2.other, 0).catch(() => undefined);
    }
  }
  const verdict = confirmJoin(best, chains, { inviter: input.inviter ?? "", self: app.userId });
  if (verdict === "conflict") {
    await dropPending(app, cid);
    throw new CliError("join_conflict", "the answers about this circle conflict with each other: refusing to join (§3.3)");
  }
  let confirmation: JoinResult["confirmation"] = verdict === "confirmed" ? "confirmed" : "unconfirmed";
  // Owner-only only when the head we join lists nobody but the owner (and us).
  const onlyOwner = best.head.members.every((m) => m === best.head.owner || m === app.userId);
  if (verdict === "unconfirmed" && onlyOwner && answers[best.head.owner]) confirmation = "owner-only";
  if (confirmation === "unconfirmed") {
    const ok = opts.yes || (opts.confirm ? await opts.confirm("Couldn't confirm this circle with a second member. Join anyway?") : false);
    if (!ok) return { ...base, status: "unconfirmed", confirmation, asked: (await app.state.get("joins"))?.[cid]?.asked ?? pending?.asked ?? [], answered };
  }
  const versions = best.versionsFrom(1);
  if (!(await app.store.getCircle(cid))) await storeOfferedCircle(app.store, versions, await chainOpts(app));
  await applyCircleBundle(app.store, { circles: versions, joins: statements, ops: [] }, await chainOpts(app));
  const c = (await loadCircle(app.store, cid))!;
  // A circle already stored here may be ahead of `best` after the merge: the join signs onto the stored
  // head, so the caller's rules see that one too, before anything is signed.
  const late = c.chain.head.hash === best.head.hash ? undefined : input.accept?.(c.chain.head);
  if (late) {
    await dropPending(app, cid);
    return { ...base, ...headFacts(c.chain.head), status: "refused", refused: late, asked: pending?.asked ?? [], answered };
  }
  await signOwnJoin(app, cid, c.chain.head.hash);
  const mine = (await loadCircle(app.store, cid))!.book[app.userId].jws;
  const delivered: Delivery[] = [];
  const targets = [...new Set([c.chain.head.owner, ...c.chain.head.admins])].filter((u) => u !== app.userId);
  for (const u of targets) {
    try {
      delivered.push(await deliverCircle(app, u, { joins: [mine] }, u === c.chain.head.owner ? extraOwnerCaps : []));
    } catch (e) {
      app.io.err(`couldn't send your join to ${await app.addressOf(u)}: ${(e as Error).message}`);
    }
  }
  await dropPending(app, cid);
  await dropHeld(app, (h) => h.cid === cid && h.type === "circle-invite");
  const exp = await exportCircle(app, cid);
  if (exp) await sendSync(app, { circles: [exp] });
  if (!delivered.some((d) => d.relays.length > 0) && targets.length > 0) {
    throw new CliError("undelivered", "joined locally, but the join was delivered via 0 relays: the owner doesn't know yet", { cid });
  }
  return {
    ...base,
    // As joined: the stored chain's head, which may be newer than the offered one.
    ...headFacts(c.chain.head),
    status: "joined",
    confirmation,
    asked: pending?.asked ?? [],
    answered,
    delivered,
    ...(circlePolicy(c.chain.head) === "open" ? { openWarning: true } : {}),
  };
}

function headFacts(h: VerifiedCircleVersion): { name: string; owner: string; policy: CirclePolicy; ownershipChanged: boolean } {
  return { name: circleDisplayName(h), owner: h.owner, policy: circlePolicy(h), ownershipChanged: h.owner !== h.founder };
}

async function dropPending(app: App, cid: string): Promise<void> {
  const gone = await app.state.update("joins", (cur = {}) => {
    if (!cur[cid]) return { result: undefined };
    const { [cid]: was, ...rest } = cur;
    return { next: rest, result: was };
  });
  if (!gone) return;
  await dropAnswers(app, cid, gone.answerFrom ?? []);
  // L1: the answer caps this join handed out have done their job (joined, or refused).
  const ids = new Set(gone.answerCaps ?? []);
  if (ids.size > 0) {
    const caps = await app.store.takeCapsIssued((c) => ids.has(c.capid));
    await app.revokeCaps(caps).catch(() => 0);
  }
}

export async function joinFromLink(
  app: App,
  link: string,
  opts: { waitSec?: number; yes?: boolean; confirm?: (q: string) => Promise<boolean>; allowPrivateRelay?: boolean },
): Promise<JoinResult> {
  let parsed: { head: string; hint?: CircleHint };
  try {
    parsed = parseCircleLink(link);
  } catch (e) {
    if (e instanceof CliError) throw e;
    throw new CliError("usage", "that is not a circle link (p2p://circle/… or https://ix-infra.com/p2p/c#…)");
  }
  // The relays the link names (its owner's document, its join cap) are dialed before anyone confirms anything.
  const hinted = [...App.relaysOf(parsed.hint?.doc), ...(capPeek(joinCapOf(parsed.hint?.join ?? "") ?? "")?.relays ?? [])];
  await guardForeignRelays(app, hinted, "circle link", opts.allowPrivateRelay || app.env.P2P_ALLOW_PRIVATE_RELAY === "1");
  return joinCircle(app, parsed, opts);
}

export async function joinFromHeld(app: App, item: HeldItem, opts: { waitSec?: number; yes?: boolean; confirm?: (q: string) => Promise<boolean> }): Promise<JoinResult> {
  return joinCircle(app, { head: item.head!, chain: item.chain, joins: item.joins, inviter: item.from }, opts);
}


/**
 * Open circles (P2, pre-release review M4): re-sign our join (n+1, a fresh cap of at
 * most 14 days) when the owner removed anyone since our cap was issued, when
 * the cap outlives 14 days, or when it lapses within 3 days; revoke the old
 * cap at its relays, and tell the members. Returns how many were renewed.
 */
export async function renewOpenJoinCaps(app: App): Promise<number> {
  const actions = await openCircleCapActions(app.store, app.userId);
  let n = 0;
  for (const a of actions) {
    const c = await loadCircle(app.store, a.cid);
    if (!c) continue;
    const cap = createCap(app.device!, app.keys!.cert, { purpose: "join", relays: app.relays, ttlSec: a.capTtlSec });
    const jws = createMembershipStatement(app.signer(), { cid: a.cid, n: a.nextN, op: "join", at: a.at, cap });
    const v = await verifyMembershipStatement(jws, app.signerCtx());
    await recordJoin(app, v);
    await app.recordIssued(cap);
    if (a.revoke) {
      const old = await app.store.takeCapsIssued((x) => x.capid === a.revoke!.capid);
      await app.revokeCaps(old.length > 0 ? old : [{ capid: a.revoke.capid, iss: app.userId, sub: "*", relays: a.revoke.relays, kinds: ["*"], exp: 0, jws: "" }]);
    }
    for (const m of c.chain.head.members) {
      if (m === app.userId) continue;
      await deliverCircle(app, m, { joins: [jws] }, memberCaps(c, m)).catch(() => undefined);
    }
    n++;
  }
  return n;
}

/**
 * §3.2 block, for circles: the blocked user holds our join cap (sub "*"), so
 * revoking friend caps alone doesn't stop it reaching our mailbox. In every
 * joined circle that lists them, re-sign our join with a fresh cap, revoke the
 * old one at its relays, and send the new statement to the other members
 * (never to the blocked user). Returns the circles re-keyed.
 */
export async function rekeyJoinsExcluding(app: App, blocked: string): Promise<string[]> {
  const out: string[] = [];
  for (const rec of await app.store.listCircles()) {
    if (!rec.joinedByMe) continue;
    const c = await loadCircle(app.store, rec.cid);
    if (!c || !c.chain.head.members.includes(blocked)) continue;
    const mine = c.book[app.userId];
    if (!mine || mine.op !== "join") continue;
    const oldCap = joinCapOf(mine.jws);
    const cap = createCap(app.device!, app.keys!.cert, { purpose: "join", relays: app.relays, ttlSec: joinCapTtlFor(circlePolicy(c.chain.head)) });
    const jws = createMembershipStatement(app.signer(), { cid: rec.cid, n: nextMembershipN(rec.myN), op: "join", at: c.chain.head.hash, cap });
    const v = await verifyMembershipStatement(jws, app.signerCtx());
    await recordJoin(app, v);
    await app.recordIssued(cap);
    if (oldCap) {
      const p = decodeTyped(oldCap, TYP3.cap).payload;
      const taken = await app.store.takeCapsIssued((x) => x.capid === p.capid);
      const relays = Array.isArray(p.relays) ? (p.relays as string[]) : app.relays;
      await app.revokeCaps(taken.length > 0 ? taken : [{ capid: String(p.capid), iss: app.userId, sub: "*", relays, kinds: ["*"], exp: 0, jws: oldCap }]);
    }
    for (const m of c.chain.head.members) {
      if (m === app.userId || m === blocked) continue;
      await deliverCircle(app, m, { joins: [jws] }, memberCaps(c, m)).catch(() => undefined);
    }
    out.push(rec.cid);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Leaving, proposals, transfer, policy

export async function leaveCircle(app: App, cidOrName: string): Promise<{ cid: string; left: boolean; told: number }> {
  // Handle what's queued first: the circle bundles waiting here carry the members' join statements,
  // whose caps are how a member we aren't friends with is reached. Without them a fresh member's
  // leave reached nobody (told 0), the owner kept listing it, and its later re-join diverged.
  await app.connectAndDrain();
  const c = await resolveCircle(app, cidOrName);
  const cid = c.record.cid;
  if (c.chain.head.owner === app.userId) throw new CliError("owner_cannot_leave", "you own this circle: hand it over first (`p2p circle transfer`)");
  const jws = createMembershipStatement(app.signer(), { cid, n: nextMembershipN(c.record.myN), op: "leave" });
  const v = await verifyMembershipStatement(jws, app.signerCtx());
  let told = 0;
  // §3.3: a leave goes to every member, who honour it at once.
  for (const m of c.chain.head.members) {
    if (m === app.userId) continue;
    try {
      const d = await deliverCircle(app, m, { joins: [jws] }, memberCaps(c, m));
      if (d.relays.length > 0) told++;
    } catch {
      // unreachable member
    }
  }
  await recordOwnLeave(app.store, app.userId, v);
  const exp = await exportCircle(app, cid);
  if (exp) await sendSync(app, { circles: [exp] });
  if (app.self?.defaultCircle === cid) await app.updateSelf((s) => ({ ...s, defaultCircle: undefined }));
  return { cid, left: true, told };
}

const OPS: readonly ProposalOp[] = ["add", "remove", "promote", "demote", "rename"];

export async function propose(app: App, cidOrName: string, op: string, arg: string): Promise<{ cid: string; op: string; applied: boolean; ver?: number; sentTo?: string }> {
  if (!OPS.includes(op as ProposalOp)) throw new CliError("usage", `op must be one of ${OPS.join(", ")}`);
  await app.connectAndDrain();
  const c = await resolveCircle(app, cidOrName);
  const cid = c.record.cid;
  const h = c.chain.head;
  const target = op === "rename" ? undefined : await app.resolveUser(arg);
  if (h.owner === app.userId) {
    let members = [...h.members];
    let admins = [...h.admins];
    let name = h.name;
    switch (op as ProposalOp) {
      case "add":
        if (!members.includes(target!)) members.push(target!);
        break;
      case "remove":
        if (target === h.owner) throw new CliError("usage", "the owner can't be removed");
        admins = admins.filter((a) => a !== target);
        members = members.filter((m) => m !== target);
        break;
      case "promote":
        if (!members.includes(target!)) throw new CliError("usage", "only members can be admins");
        if (!admins.includes(target!)) admins.push(target!);
        break;
      case "demote":
        admins = admins.filter((a) => a !== target);
        break;
      case "rename":
        if (arg.trim() === "" || [...arg].length > 128) throw new CliError("usage", "a circle name is 1–128 characters");
        name = arg;
        break;
    }
    if (name === h.name && admins.join() === h.admins.join() && members.join() === h.members.join()) return { cid, op, applied: false, ver: h.ver };
    const v = await ownerPublish(app, cid, { members, admins, name });
    return { cid, op, applied: true, ver: v.ver };
  }
  if (!h.admins.includes(app.userId)) throw new CliError("not_admin", "only admins propose changes (the owner applies them)");
  const p = createProposal(app.signer(), { cid, base: h.ver, op: op as ProposalOp, ...(target ? { target } : { name: arg }) });
  const d = await deliverCircle(app, h.owner, { ops: [p] }, ownerCaps(c));
  if (d.relays.length === 0) throw new CliError("undelivered", "the proposal was delivered via 0 relays");
  return { cid, op, applied: false, sentTo: h.owner };
}

export async function transfer(app: App, cidOrName: string, who: string | undefined, opts: { accept?: boolean; consent?: string }): Promise<Record<string, unknown>> {
  await app.connectAndDrain();
  const c = await resolveCircle(app, cidOrName);
  const cid = c.record.cid;
  const h = c.chain.head;
  if (opts.accept) {
    // The successor consents to exactly {cid, ver, prev} (§3.3 rule 3).
    const ik = app.requireKeyholder("Consenting to take over a circle");
    if (!h.members.includes(app.userId)) throw new CliError("usage", "only a member can take over a circle");
    const consent = createCircleTransferAccept(ik, { cid, ver: h.ver + 1, prev: h.hash });
    const d = await deliverCircle(app, h.owner, { ops: [consent] }, ownerCaps(c));
    return { cid, consent, sentTo: h.owner, delivered: d.relays.length };
  }
  if (h.owner !== app.userId) throw new CliError("not_owner", "only the owner can hand the circle over");
  if (!who) throw new CliError("usage", "name the new owner");
  const u = await app.resolveUser(who);
  if (!h.members.includes(u)) throw new CliError("usage", "the new owner must be a member");
  const consent = opts.consent ?? (await app.state.get("transfers"))?.[cid]?.[u];
  if (!consent) {
    throw new CliError("needs_consent", `${await app.addressOf(u)} must consent first: ask them to run \`p2p circle transfer ${cid} --accept\`, then run this again`);
  }
  const t = decodeTyped(consent, TYP3.circleAccept).payload;
  if (t.iss !== u || t.cid !== cid || t.ver !== h.ver + 1 || t.prev !== h.hash || typeof t.ik !== "string") {
    throw new CliError("stale_consent", "that consent is for another state of the circle: ask for a fresh `--accept`");
  }
  const v = await ownerPublish(app, cid, { newOwner: { userId: u, ik: t.ik, transfer: consent } });
  return { cid, owner: u, address: await app.addressOf(u), ver: v.ver };
}

export async function setPolicy(app: App, cidOrName: string, policy: string): Promise<{ cid: string; policy: CirclePolicy; ver: number }> {
  if (policy !== "invite" && policy !== "open") throw new CliError("usage", "policy is invite or open");
  await app.connectAndDrain();
  const c = await resolveCircle(app, cidOrName);
  if (circlePolicy(c.chain.head) === policy) return { cid: c.record.cid, policy, ver: c.chain.head.ver };
  const v = await ownerPublish(app, c.record.cid, { policy });
  return { cid: c.record.cid, policy, ver: v.ver };
}

/**
 * §3.3 "the owner may also set a policy to hold proposals for approval":
 * a local, per-circle setting on the owner's devices. While on, admins'
 * proposals and rotated members (§2.8) wait in `p2p held` for the owner.
 */
export async function setCircleHold(app: App, cidOrName: string, on: boolean | undefined): Promise<{ cid: string; hold: boolean }> {
  const c = await resolveCircle(app, cidOrName);
  const cid = c.record.cid;
  if (on !== undefined) {
    if (c.chain.head.owner !== app.userId) throw new CliError("not_owner", "only the owner holds changes to a circle for approval");
    await app.state.update("circleHold", (cur = {}) => {
      const next = { ...cur };
      if (on) next[cid] = true;
      else delete next[cid];
      return { next, result: undefined };
    });
  }
  return { cid, hold: await circleHeld(app, cid) };
}

/** Owner: approves a held join request. */
export async function approveJoinRequest(app: App, item: HeldItem): Promise<{ cid: string; added: string; ver: number }> {
  const c = await loadCircle(app.store, item.cid!);
  if (!c) throw new CliError("not_found", "circle not held");
  await app.connect();
  const h = c.chain.head;
  if (h.members.includes(item.from)) return { cid: c.record.cid, added: item.from, ver: h.ver };
  const v = await ownerPublish(app, c.record.cid, { members: [...h.members, item.from] });
  return { cid: c.record.cid, added: item.from, ver: v.ver };
}

// ---------------------------------------------------------------------------
// Inbound `circle` envelopes

export async function onCircleEnvelope(app: App, env: string, r: AcceptedMessageV3, relay: string): Promise<NewEvent[]> {
  const pt = r.plaintext as { kind: "circle"; want?: { cid: string; fromVer: number }; cap?: string; pow?: WantPow; circles?: string[]; joins?: string[]; ops?: string[]; rotation?: RotationStatement; part?: AnswerPart };
  const info = r.circle!;
  const from = await fromOf(app, r);
  const at = r.envelope.ts;
  if (pt.want) {
    await answerWant(app, r.envelope.from, r.envelope.fdid, pt.want, info.authorizedBy, relay, pt.cap, pt.pow, { ts: r.envelope.ts });
    return [];
  }
  const circles = pt.circles ?? [];
  const joins = pt.joins ?? [];
  const ops = pt.ops ?? [];
  const events: NewEvent[] = [];
  // Versions of circles we don't hold: an answer to a pending join, or an invite to hold.
  const byCid = new Map<string, string[]>();
  for (const j of circles) {
    try {
      const cid = parseCircleVersion(j).cid;
      byCid.set(cid, [...(byCid.get(cid) ?? []), j]);
    } catch {
      // ignore malformed
    }
  }
  const known: string[] = [];
  for (const [cid, vs] of byCid) {
    const cidJoins = joins.filter((j) => {
      try {
        return decodeTyped(j, TYP3.join).payload.cid === cid;
      } catch {
        return false;
      }
    });
    if (await app.store.getCircle(cid)) {
      known.push(...vs);
      // A circle we still hold but are joining again (we left it): the members we asked answer
      // here too. Without this a former member's join waited for an answer that never counted.
      if (await recordJoinAnswer(app, r.envelope.from, vs, cidJoins, { part: pt.part })) events.push(makeEvent(env, "p2p.circle", at, { from, event: "join-answer", cid }, {}, cid));
      continue;
    }
    if (await recordJoinAnswer(app, r.envelope.from, vs, cidJoins, { part: pt.part })) {
      events.push(makeEvent(env, "p2p.circle", at, { from, event: "join-answer", cid }, {}, cid));
      continue;
    }
    const head = vs.map((v) => parseCircleVersion(v)).sort((a, b) => b.ver - a.ver)[0];
    const headJws = vs.find((v) => parseCircleVersion(v).ver === head.ver && parseCircleVersion(v).cid === cid)!;
    const item = withHeldId({ type: "circle-invite", from: r.envelope.from, at, head: headJws, chain: vs, joins: cidJoins, cid });
    await hold(app, item);
    events.push(makeEvent(env, "p2p.held", at, { from, held: { id: item.id, type: item.type, cid } }, {}, cid));
  }
  // The statements-only part of a chunked answer to a pending join (its versions came before).
  const loose = new Map<string, string[]>();
  for (const j of joins) {
    try {
      const cid = decodeTyped(j, TYP3.join).payload.cid;
      if (typeof cid === "string" && !byCid.has(cid)) loose.set(cid, [...(loose.get(cid) ?? []), j]);
    } catch {
      // ignore malformed
    }
  }
  // Also for a circle we still hold but are joining again (L5): recordJoinAnswer matches only a pending join.
  for (const [cid, js] of loose) await recordJoinAnswer(app, r.envelope.from, [], js, { cid, part: pt.part });
  const before = new Map<string, { ver: number; member: boolean }>();
  for (const cid of info.cids) {
    const c = await loadCircle(app.store, cid);
    if (c) before.set(cid, { ver: c.chain.head.ver, member: c.chain.head.members.includes(app.userId) });
  }
  const res = await applyCircleBundle(app.store, { circles: known, joins, ops }, await chainOpts(app));
  for (const [cid, results] of Object.entries(res.versions)) {
    const c = await loadCircle(app.store, cid);
    if (!c) continue;
    const b = before.get(cid);
    for (const x of results) if (x.alert) events.push(makeEvent(env, "p2p.circle", at, { from, event: "alert", cid, alert: x.alert }, {}, `${cid}${x.hash}`));
    if (b && c.chain.head.ver !== b.ver) {
      const removed = b.member && !c.chain.head.members.includes(app.userId);
      events.push(
        makeEvent(env, "p2p.circle", at, { from, event: removed ? "removed" : "version", cid, name: circleDisplayName(c.chain.head), ver: c.chain.head.ver, policy: circlePolicy(c.chain.head) }, {}, cid),
      );
      if (removed) {
        await app.store.updateCircle(cid, (cur) => (cur ? { next: { ...cur, joinedByMe: false }, result: undefined } : { result: undefined }));
      }
    }
  }
  const applied = res.joins.filter((j) => j.status === "applied" && j.statement).map((j) => j.statement!);
  for (const s of applied) {
    if (s.iss === app.userId) continue;
    events.push(makeEvent(env, "p2p.circle", at, { from, event: s.op === "join" ? "member-joined" : "member-left", cid: s.cid, member: s.iss, address: await app.addressOf(s.iss) }, {}, s.hash));
  }
  // Transfer consents (CLI reading: carried in `ops`).
  for (const j of ops) {
    try {
      const t = decodeTyped(j, TYP3.circleAccept).payload;
      if (typeof t.cid === "string" && t.iss === r.envelope.from) {
        await app.state.update("transfers", (cur = {}) => ({ next: { ...cur, [t.cid as string]: { ...(cur[t.cid as string] ?? {}), [t.iss as string]: j } }, result: undefined }));
        events.push(makeEvent(env, "p2p.circle", at, { from, event: "transfer-consent", cid: t.cid }, {}, j));
      }
    } catch {
      // a proposal, handled by core
    }
  }
  if (Object.keys(res.versions).length > 0) await renewOpenJoinCaps(app).catch(() => 0);
  const statements = res.joins.map((j) => j.statement).filter((s): s is VerifiedMembership => !!s);
  // §2.8 (P3): a rotated member's join with the statement. The owner swaps old for new (or holds it);
  // its statements are then no ordinary join request.
  let rotated: { iss: string; old?: string; handled: Set<string> } | undefined;
  if (pt.rotation) {
    const o = await onRotationJoin(app, env, at, from, pt.rotation, r.envelope.from, statements);
    events.push(...o.events);
    rotated = { iss: r.envelope.from, ...(o.old ? { old: o.old } : {}), handled: o.handled };
  }
  // The old identity's leave that came with it waits too: the swap replaces old with new in one
  // version, so a held swap leaves the old member listed (with no standing) until it is decided.
  const ordinary = (s: VerifiedMembership) => !(rotated && rotated.handled.has(s.cid) && (s.iss === rotated.iss || s.iss === rotated.old));
  // Owner duties for circles we own.
  const owned = new Set<string>();
  for (const s of statements) owned.add(s.cid);
  for (const o of res.ops) if (o.status === "queued" && o.proposal) owned.add(o.proposal.cid);
  for (const cid of owned) {
    const c = await loadCircle(app.store, cid);
    if (!c || c.chain.head.owner !== app.userId || !app.isKeyholder) continue;
    events.push(...(await ownerDuties(app, env, at, from, c, statements.filter((s) => s.cid === cid && ordinary(s)), applied.some((s) => s.cid === cid), res.ops.some((o) => o.status === "queued" && o.proposal?.cid === cid))));
  }
  return events;
}

async function ownerDuties(
  app: App,
  env: string,
  at: number,
  from: Awaited<ReturnType<typeof fromOf>>,
  c: LoadedCircle,
  statements: VerifiedMembership[],
  anyApplied: boolean,
  proposals: boolean,
): Promise<NewEvent[]> {
  const cid = c.record.cid;
  const events: NewEvent[] = [];
  const blocks = new Set((await app.store.listBlocks()).map((b) => b.userId));
  const h = c.chain.head;
  let members = [...h.members];
  let admins = [...h.admins];
  let name = h.name;
  if (proposals) {
    // §3.3: the owner may hold proposals for approval (`p2p circle hold`).
    const r = await applyOwnerProposals(app.store, cid, { ...app.signerCtx(), hold: await circleHeld(app, cid) });
    if (r?.draft) {
      members = r.draft.members;
      admins = r.draft.admins;
      name = r.draft.name;
    }
    for (const x of r?.results ?? []) events.push(makeEvent(env, "p2p.circle", at, { from, event: "proposal", cid, status: x.status, proposer: x.iss }, {}, x.nonce));
  }
  for (const s of statements) {
    if (s.op === "leave") {
      if (members.includes(s.iss) && s.iss !== h.owner && c.book[s.iss]?.hash === s.hash) {
        members = members.filter((m) => m !== s.iss);
        admins = admins.filter((m) => m !== s.iss);
      }
      continue;
    }
    if (members.includes(s.iss)) continue;
    if (blocks.has(s.iss)) continue;
    const d = await decideOpenJoinFor(app.store, s);
    if (d.decision === "accept") members.push(s.iss);
    else if (d.decision === "hold") {
      const item = withHeldId({ type: "circle-join", from: s.iss, at, cid, head: h.jws, join: s.jws, reason: d.reason });
      await hold(app, item);
      events.push(makeEvent(env, "p2p.held", at, { from, held: { id: item.id, type: item.type, cid, reason: d.reason } }, {}, s.hash));
    }
  }
  const changed = name !== h.name || admins.join() !== h.admins.join() || members.join() !== h.members.join();
  if (changed) {
    const v = await ownerPublish(app, cid, { members, admins, name });
    events.push(makeEvent(env, "p2p.circle", at, { from, event: "published", cid, ver: v.ver, name: circleDisplayName(v) }, {}, `${cid}${v.ver}`));
  } else if (anyApplied) {
    // A statement changed standing without a new version: tell the members.
    await distribute(app, cid);
  }
  return events;
}

/**
 * Answers to one asker's `want`s per rolling hour (all circles; members too, review M1). The byte
 * budgets (per asker, per circle, the non-member pools) are what bound the cost; this only caps
 * how often. 3 was too few: a member who leaves and joins again a few times in an hour (each join
 * needs an answer) was refused, and could not join until the hour passed (pre-release soak, seed 21).
 */
export const ANSWERS_PER_ASKER_PER_HOUR = ANSWERS_PER_HOUR;
const HOUR_MS = 3_600_000;

export interface WantAnswersDoc {
  /** When each asker was answered. */
  by: Record<string, number[]>;
  /** Bytes sent to each asker. */
  bytes: Record<string, { at: number; bytes: number }[]>;
  /** Bytes sent to non-members, all together, by pool (`reserve`: their want carried a valid proof of work; `open`: it didn't). */
  sent: { at: number; bytes: number; pool?: "reserve" | "open" | "link" }[];
  /** Proofs of work already used this hour (each counts once). */
  pows?: { id: string; at: number }[];
  /** The highest version sent to `asker|cid`, when, and whether it was already sent again once. */
  last: Record<string, { ver: number; at: number; resent?: boolean }>;
  /** Bytes sent to members of each circle, all together (re-review N2), by cid. */
  members?: Record<string, { at: number; bytes: number }[]>;
  /** When a device of ours last refused `asker|cid` (ms; review F2): the others don't answer it either. */
  refused?: Record<string, number>;
}

function prunedAnswers(cur: Partial<WantAnswersDoc> | undefined, now: number): WantAnswersDoc {
  const fresh = <T extends { at: number }>(xs: readonly T[] | undefined) => (xs ?? []).filter((x) => now - x.at < HOUR_MS);
  const by: Record<string, number[]> = {};
  for (const [u, ts] of Object.entries(cur?.by ?? {})) {
    const keep = ts.filter((t) => now - t < HOUR_MS);
    if (keep.length > 0) by[u] = keep;
  }
  const bytes: WantAnswersDoc["bytes"] = {};
  for (const [u, xs] of Object.entries(cur?.bytes ?? {})) {
    const keep = fresh(xs);
    if (keep.length > 0) bytes[u] = keep;
  }
  const last: WantAnswersDoc["last"] = {};
  for (const [k, v] of Object.entries(cur?.last ?? {})) if (now - v.at < HOUR_MS) last[k] = v;
  const members: NonNullable<WantAnswersDoc["members"]> = {};
  for (const [c, xs] of Object.entries(cur?.members ?? {})) {
    const keep = fresh(xs);
    if (keep.length > 0) members[c] = keep;
  }
  const refused: Record<string, number> = {};
  for (const [k, t] of Object.entries(cur?.refused ?? {})) if (now - t < HOUR_MS) refused[k] = t;
  // review N-B: bounded however many askers and circles there are. Maps keep their most recent keys;
  // the pool lists fold their oldest entries into one (dated by the newest folded), so evicting
  // never frees budget a pool already spent.
  const latest = (xs: readonly number[]) => xs.reduce((a, b) => (b > a ? b : a), 0);
  const capMap = <V>(m: Record<string, V>, max: number, at: (v: V) => number): Record<string, V> => {
    const keys = Object.keys(m);
    if (keys.length <= max) return m;
    return Object.fromEntries(keys.map((k) => [k, m[k]] as const).sort((a, b) => at(b[1]) - at(a[1])).slice(0, max));
  };
  const fold = <T extends { at: number; bytes: number }>(xs: T[], max: number): T[] => {
    if (xs.length <= max) return xs;
    const sorted = [...xs].sort((a, b) => a.at - b.at);
    const old = sorted.slice(0, xs.length - max + 1);
    const merged = { ...old[old.length - 1], bytes: old.reduce((n, x) => n + x.bytes, 0) };
    return [merged, ...sorted.slice(xs.length - max + 1)];
  };
  const foldedMembers: NonNullable<WantAnswersDoc["members"]> = {};
  for (const [c, xs] of Object.entries(capMap(members, MAX_ANSWER_CIRCLES, (v) => latest(v.map((x) => x.at))))) foldedMembers[c] = fold(xs, MAX_POOL_ENTRIES);
  const byKept = capMap(by, MAX_ANSWER_ASKERS, latest);
  const bytesKept: WantAnswersDoc["bytes"] = {};
  for (const [u, xs] of Object.entries(bytes)) if (byKept[u] || Object.keys(bytes).length <= MAX_ANSWER_ASKERS) bytesKept[u] = fold(xs, MAX_POOL_ENTRIES);
  return {
    by: byKept,
    bytes: capMap(bytesKept, MAX_ANSWER_ASKERS, (v) => latest(v.map((x) => x.at))),
    sent: fold(fresh(cur?.sent), MAX_POOL_ENTRIES),
    last: capMap(last, MAX_ANSWER_ASKERS, (v) => v.at),
    members: foldedMembers,
    pows: keepPows(fresh(cur?.pows), now),
    refused: capMap(refused, MAX_ANSWER_ASKERS, (t) => t),
  };
}

/**
 * Spent proofs of work, bounded (review N-B) without ever forgetting one that could still be
 * replayed (review P3): every proof spent within the window a proof is accepted in (±10 min, so 20
 * minutes back) is kept, and only older ones are dropped beyond MAX_POOL_ENTRIES.
 */
function keepPows(pows: { id: string; at: number }[], now: number): { id: string; at: number }[] {
  if (pows.length <= MAX_POOL_ENTRIES) return pows;
  const live = pows.filter((p) => now - p.at <= 2 * WANT_POW_WINDOW_SEC * 1000);
  const old = pows.filter((p) => now - p.at > 2 * WANT_POW_WINDOW_SEC * 1000);
  const room = MAX_POOL_ENTRIES - live.length;
  return [...(room > 0 ? old.slice(-room) : []), ...live];
}

/** Askers (or asker|circle pairs) whose answer records are kept, the most recent first (review N-B). */
export const MAX_ANSWER_ASKERS = 2048;
/** Circles whose member pools are kept. */
export const MAX_ANSWER_CIRCLES = 512;
/** Entries per pool list before the oldest are folded into one. */
export const MAX_POOL_ENTRIES = 4096;

export type AnswerAllowance = { ok: true; bytes: number } | { ok: false; why: string };

const sum = (xs: readonly { bytes: number }[] | undefined) => (xs ?? []).reduce((a, x) => a + x.bytes, 0);

/** Who an answer is for: a member of the head, or a non-member whose want carried a valid proof of work (`reserve`), or neither (`open`). */
export type AnswerPool = "member" | "reserve" | "open";

/**
 * How many bytes this client may still send `asker` this hour: every asker has a count and a
 * byte budget (review M1); non-members also share a pool, with a separate reserve for those whose
 * want named a version they were offered, so identities that only know a circle id can't spend
 * what link-holders need (review M2).
 */
function allowanceIn(doc: WantAnswersDoc, app: App, asker: string, pool: AnswerPool, cid: string): AnswerAllowance {
  if ((doc.by[asker]?.length ?? 0) >= ANSWERS_PER_ASKER_PER_HOUR) return { ok: false, why: `already answered them ${ANSWERS_PER_ASKER_PER_HOUR} times this hour` };
  const mine = app.tun.answerBytesPerAskerPerHour - sum(doc.bytes[asker]);
  if (mine <= 0) return { ok: false, why: `this hour's budget for answering them (${app.tun.answerBytesPerAskerPerHour} bytes) is spent` };
  if (pool === "member") {
    // Re-review N2: an open circle admits up to 20 a rolling hour, each with its own per-asker
    // budget; all of a circle's members together share one pool too.
    const cap = app.tun.memberAnswerBytesPerCirclePerHour;
    const left = cap - sum(doc.members?.[cid]);
    if (left <= 0) return { ok: false, why: `this hour's budget for answering this circle's members (${cap} bytes) is spent` };
    return { ok: true, bytes: Math.min(mine, left) };
  }
  const cap = pool === "reserve" ? app.tun.strangerAnswerBytesPerHour : app.tun.unlinkedAnswerBytesPerHour;
  const left = cap - sum(doc.sent.filter((x) => (x.pool === "open" ? "open" : "reserve") === pool));
  if (left <= 0) return { ok: false, why: `this hour's budget for answering non-members${pool === "open" ? " whose want carries no proof of work" : ""} (${cap} bytes) is spent` };
  return { ok: true, bytes: Math.min(mine, left) };
}

/** What `asker` may still be sent this hour, checked before anything is built or fetched (review L4). Charges nothing. */
export async function answerAllowance(app: App, asker: string, pool: AnswerPool, cid: string): Promise<AnswerAllowance & { last: WantAnswersDoc["last"]; pows: Set<string> }> {
  const doc = prunedAnswers(await app.state.get("wantAnswers"), Date.now());
  return { ...allowanceIn(doc, app, asker, pool, cid), last: doc.last, pows: new Set((doc.pows ?? []).map((x) => x.id)) };
}

/**
 * Charges one answer of `bytes` to `asker` (and to the non-member pool), re-checking the limits
 * under the lock, and records the highest version sent (`ver`) for `cid`. Refused when another
 * answer spent the budget meanwhile.
 */
/** What one charge recorded, so an answer that didn't go out can be refunded (refundAnswer). */
export interface AnswerReceipt {
  asker: string;
  pool: AnswerPool;
  cid: string;
  at: number;
  bytes: number;
  pow?: string;
  /** `last` for asker|cid before the charge (undefined: none). */
  prevLast?: { ver: number; at: number; resent?: boolean };
}

export async function chargeAnswer(
  app: App,
  asker: string,
  pool: AnswerPool,
  bytes: number,
  mark?: { cid: string; ver: number; resent: boolean; pow?: string },
): Promise<AnswerAllowance & { receipt?: AnswerReceipt }> {
  return app.state.update<"wantAnswers", AnswerAllowance & { receipt?: AnswerReceipt }>("wantAnswers", (cur) => {
    const now = Date.now();
    const doc = prunedAnswers(cur, now);
    const cid = mark?.cid ?? "";
    if (pool === "reserve" && mark?.pow !== undefined && (doc.pows ?? []).some((x) => x.id === mark.pow)) {
      return { next: doc, result: { ok: false, why: "that proof of work was already used" } };
    }
    const a = allowanceIn(doc, app, asker, pool, cid);
    if (!a.ok) return { next: doc, result: a };
    if (pool === "reserve" && mark?.pow !== undefined) doc.pows = [...(doc.pows ?? []), { id: mark.pow, at: now }];
    if (bytes > a.bytes) return { next: doc, result: { ok: false, why: `the answer (${bytes} bytes) is over what is left of this hour's budget (${a.bytes})` } };
    doc.by[asker] = [...(doc.by[asker] ?? []), now];
    doc.bytes[asker] = [...(doc.bytes[asker] ?? []), { at: now, bytes }];
    if (pool !== "member") doc.sent.push({ at: now, bytes, pool });
    else doc.members = { ...doc.members, [cid]: [...(doc.members?.[cid] ?? []), { at: now, bytes }] };
    let prevLast: AnswerReceipt["prevLast"];
    if (mark) {
      const k = `${asker}|${mark.cid}`;
      const prev = doc.last[k];
      prevLast = prev;
      const sameHead = prev !== undefined && mark.ver <= prev.ver;
      doc.last[k] = { ver: Math.max(mark.ver, prev?.ver ?? 0), at: now, ...(mark.resent || (sameHead && prev?.resent) ? { resent: true } : {}) };
    }
    const receipt: AnswerReceipt = { asker, pool, cid, at: now, bytes, ...(pool === "reserve" && mark?.pow ? { pow: mark.pow } : {}), ...(prevLast ? { prevLast } : {}) };
    // Bounded again with the new entries in (N-B).
    return { next: prunedAnswers(doc, now), result: { ok: true, bytes: a.bytes - bytes, receipt } };
  });
}

/**
 * Settles a charge with what actually went out (pre-release review N-A, review P1): the bytes this member
 * wrote to the wire (each part's sealed size times the relays it was written to, whatever they
 * replied: a relay can store a part and answer an error), never less than ANSWER_ATTEMPT_MIN_BYTES, stay charged
 * against the asker and the pools; only the undelivered remainder comes back. `last` goes back to
 * what it was when the answer didn't fully go out, so the asker may ask for the rest without
 * being refused as a resend; the proof of work comes back only when nothing went out at all. An
 * asker steering parts to a relay that drops one of them can't get the rest for free.
 */
export const ANSWER_ATTEMPT_MIN_BYTES = 4096;

export async function settleAnswer(app: App, r: AnswerReceipt, spent: number): Promise<void> {
  const keep = Math.min(r.bytes, Math.max(ANSWER_ATTEMPT_MIN_BYTES, spent));
  await app.state.update("wantAnswers", (cur) => {
    const doc = prunedAnswers(cur, Date.now());
    const adjust = (xs: readonly { at: number; bytes: number }[]) => xs.map((x) => (x.at === r.at && x.bytes === r.bytes ? { ...x, bytes: keep } : x));
    if (doc.bytes[r.asker]) doc.bytes[r.asker] = adjust(doc.bytes[r.asker]);
    if (r.pool === "member") {
      if (doc.members?.[r.cid]) doc.members = { ...doc.members, [r.cid]: adjust(doc.members[r.cid]) };
    } else doc.sent = adjust(doc.sent) as typeof doc.sent;
    if (r.pow && spent === 0) doc.pows = (doc.pows ?? []).filter((x) => x.id !== r.pow);
    const k = `${r.asker}|${r.cid}`;
    if (r.prevLast) doc.last[k] = r.prevLast;
    else delete doc.last[k];
    return { next: doc, result: undefined };
  });
}

/** Undoes a charge entirely (nothing went out). */
export async function refundAnswer(app: App, r: AnswerReceipt): Promise<void> {
  await app.state.update("wantAnswers", (cur) => {
    const doc = prunedAnswers(cur, Date.now());
    const not = (x: { at: number; bytes: number }) => !(x.at === r.at && x.bytes === r.bytes);
    if (doc.bytes[r.asker]) doc.bytes[r.asker] = doc.bytes[r.asker].filter(not);
    if (r.pool === "member") {
      if (doc.members?.[r.cid]) doc.members = { ...doc.members, [r.cid]: doc.members[r.cid].filter(not) };
    } else doc.sent = doc.sent.filter(not);
    if (r.pow) doc.pows = (doc.pows ?? []).filter((x) => x.id !== r.pow);
    const k = `${r.asker}|${r.cid}`;
    if (r.prevLast) doc.last[k] = r.prevLast;
    else delete doc.last[k];
    return { next: doc, result: undefined };
  });
}

/**
 * The parts of an answer from version `fromVer`, cut to `budget` bytes: whole versions in order,
 * then the statements if everything up to the head fits; a cut answer always stops short of the
 * head, so the answer that reaches it carries the statements. What doesn't fit is asked for again
 * later (`fromVer`), so a chain larger than one hour's budget still gets through over hours.
 */
export function answerParts(versions: readonly string[], statements: readonly string[], budget: number, cost: (plainBytes: number) => number): { parts: { circles: string[]; joins: string[] }[]; bytes: number; sentVersions: number } {
  const measure = (vs: readonly string[], js: readonly string[]) => {
    const parts = chunkBody({ circles: [...vs], joins: [...js], ops: [] as string[] }).map((p) => ({ circles: p.circles ?? [], joins: p.joins ?? [] }));
    return { parts, bytes: parts.reduce((a, p) => a + cost(bodyBytes(p)), 0) };
  };
  const all = measure(versions, statements);
  if (all.bytes <= budget) return { ...all, sentVersions: versions.length };
  // Versions only, the longest prefix that fits (binary search on the count). Re-review N7: never
  // all of them without the statements: an answer that reaches the head counts as whole, so the
  // head goes out only with the statements, in a later answer once they fit.
  let lo = 0;
  let hi = statements.length > 0 ? versions.length - 1 : versions.length;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (measure(versions.slice(0, mid), []).bytes <= budget) lo = mid;
    else hi = mid - 1;
  }
  if (lo === 0) return { parts: [], bytes: 0, sentVersions: 0 };
  return { ...measure(versions.slice(0, lo), []), sentVersions: lo };
}

/**
 * The one device of ours that answers `want`s (review M3), chosen the same way on every device
 * from our identity document: the lowest-sorting did among the key holders it lists (they hold
 * every circle we own and sign its versions), else the lowest-sorting listed device.
 */
export function answeringDevice(view: { devices: readonly string[]; keyholders: readonly string[] }): string | undefined {
  const kh = view.keyholders.filter((d) => view.devices.includes(d));
  const pool = kh.length > 0 ? kh : view.devices;
  return [...pool].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))[0];
}

/**
 * This device's place in the answering order (re-review N6): 0 answers at once, rank r answers a
 * want r fallback delays later if no device of ours has answered it by then (the order is the
 * election's: key holders first, then the other listed devices, each lowest-sorting first). A
 * device can't see what the others hold, so one that doesn't hold the circle just can't answer,
 * and the next in line does. `undefined`: not listed (answer, as before).
 */
export function answeringRank(view: { devices: readonly string[]; keyholders: readonly string[] }, did: string): number | undefined {
  const sorted = (xs: readonly string[]) => [...xs].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const kh = sorted(view.keyholders.filter((d) => view.devices.includes(d)));
  const order = [...kh, ...sorted(view.devices.filter((d) => !kh.includes(d)))];
  const i = order.indexOf(did);
  return i < 0 ? undefined : i;
}

async function myAnsweringRank(app: App): Promise<number> {
  try {
    return answeringRank(await app.ownView(), app.did!) ?? 0;
  } catch {
    return 0;
  }
}

export interface DeferredWant {
  from: string;
  fdid: string;
  want: { cid: string; fromVer: number };
  relay: string;
  cap?: string;
  pow?: WantPow;
  /** The want's envelope `ts` (ms; review F2), and when this device answers it if nobody has. */
  at: number;
  due: number;
}

/** At most this many wants wait for a fallback answer on one device (the oldest go first). */
export const MAX_DEFERRED_WANTS = 64;
/** At most this many from one asker (review F3). */
export const MAX_DEFERRED_PER_ASKER = 4;
/** A deferred want older than this (by its envelope's `ts`) is dropped unanswered (review F2). */
export const DEFERRED_WANT_MAX_AGE_MS = 30 * 60_000;

/** Whether a device of ours answered or refused `asker` about `cid` since `at` (minus the fallback slack). */
function handledSince(doc: Partial<WantAnswersDoc> | undefined, asker: string, cid: string, at: number, slackMs: number): boolean {
  const k = `${asker}|${cid}`;
  const last = doc?.last?.[k];
  const refused = doc?.refused?.[k];
  return (last !== undefined && last.at >= at - slackMs) || (refused !== undefined && refused >= at - slackMs);
}

/**
 * Answers the deferred wants that are due (re-review N6), unless a device of ours answered or
 * refused that asker about that circle since (the synced `wantAnswers`), and drops those too old
 * to answer (review F2). The answer re-checks everything, the proof of work's window included.
 */
export async function answerDeferredWants(app: App): Promise<number> {
  const now = Date.now();
  const due = await app.state.update("deferredWants", (cur = []) => {
    const keep = cur.filter((w) => now - w.at <= DEFERRED_WANT_MAX_AGE_MS);
    const ready = keep.filter((w) => w.due <= now);
    if (ready.length === 0 && keep.length === cur.length) return { result: [] as DeferredWant[] };
    return { next: keep.filter((w) => w.due > now), result: ready };
  });
  let n = 0;
  for (const w of due) {
    if (handledSince(await app.state.get("wantAnswers"), w.from, w.want.cid, w.at, app.tun.wantFallbackSec * 1000)) continue;
    await answerWant(app, w.from, w.fdid, w.want, "fallback", w.relay, w.cap, w.pow, { fallback: true, ts: w.at });
    n++;
  }
  return n;
}

interface WantRecord {
  asker: string;
  cid: string;
  at: number;
  /** An answer: the highest version, the bytes, the pool and the proof spent. */
  ver?: number;
  bytes?: number;
  pool?: AnswerPool;
  pow?: string;
  /** A refusal. */
  refused?: boolean;
}

/** Tells our other devices what this device answered (or refused), so their fallback stays quiet and the pools are shared (review F2). */
async function noteHandled(app: App, rec: WantRecord): Promise<void> {
  await sendSync(app, { wantAnswered: [rec] }).catch(() => undefined);
}

/** Merges our other devices' answer and refusal records into this device's (sync.ts): every budget and pool is shared. */
export async function importWantAnswered(app: App, recs: unknown): Promise<void> {
  if (!Array.isArray(recs)) return;
  const int = (x: unknown) => Number.isSafeInteger(x);
  const ok = recs.filter(
    (r): r is WantRecord =>
      typeof r === "object" &&
      r !== null &&
      typeof r.asker === "string" &&
      typeof r.cid === "string" &&
      int(r.at) &&
      (r.refused === true || (int(r.ver) && int(r.bytes) && (r.pool === undefined || ["member", "reserve", "open"].includes(r.pool)) && (r.pow === undefined || typeof r.pow === "string"))),
  );
  if (ok.length === 0) return;
  await app.state.update("wantAnswers", (cur) => {
    const doc = prunedAnswers(cur, Date.now());
    for (const r of ok.slice(0, 256)) {
      const k = `${r.asker}|${r.cid}`;
      if (r.refused) {
        doc.refused = { ...doc.refused, [k]: Math.max(r.at, doc.refused?.[k] ?? 0) };
        continue;
      }
      const prev = doc.last[k];
      doc.last[k] = { ver: Math.max(r.ver!, prev?.ver ?? 0), at: Math.max(r.at, prev?.at ?? 0), ...(prev?.resent ? { resent: true } : {}) };
      doc.by[r.asker] = [...(doc.by[r.asker] ?? []), r.at];
      doc.bytes[r.asker] = [...(doc.bytes[r.asker] ?? []), { at: r.at, bytes: r.bytes! }];
      if (r.pool === "member") doc.members = { ...doc.members, [r.cid]: [...(doc.members?.[r.cid] ?? []), { at: r.at, bytes: r.bytes! }] };
      else if (r.pool !== undefined) doc.sent.push({ at: r.at, bytes: r.bytes!, pool: r.pool });
      if (r.pow !== undefined) doc.pows = [...(doc.pows ?? []), { id: r.pow, at: r.at }];
    }
    return { next: prunedAnswers(doc, Date.now()), result: undefined };
  });
}

/** Records a refusal here and tells our other devices, at most once per asker and circle every 10 minutes. */
export async function noteRefused(app: App, asker: string, cid: string): Promise<void> {
  const k = `${asker}|${cid}`;
  const now = Date.now();
  const fresh = await app.state.update("wantAnswers", (cur) => {
    const doc = prunedAnswers(cur, now);
    const was = doc.refused?.[k];
    // review N-B: a refusal recorded in the last 10 minutes changes nothing worth a rewrite.
    if (was !== undefined && now - was <= 10 * 60_000) return { result: false };
    doc.refused = { ...doc.refused, [k]: now };
    return { next: prunedAnswers(doc, now), result: true };
  });
  if (fresh) await noteHandled(app, { asker, cid, at: now, refused: true });
}

/** The asker's answer cap for us, verified (§3.3): issued by the asker, for us, kinds ["*"], at most a day. */
async function answerCapOf(app: App, capJws: string | undefined, asker: string): Promise<string | undefined> {
  if (capJws === undefined) return undefined;
  try {
    const view = await app.view(asker);
    const cap = verifyCap(capJws, { purpose: "answer", ...(view ? { identityDoc: { iss: view.iss, ik: view.ik, devices: view.devices } } : {}) });
    return cap.iss === asker && cap.sub === app.userId ? capJws : undefined;
  } catch {
    return undefined;
  }
}

const bodyBytes = (v: unknown) => Buffer.byteLength(JSON.stringify(v), "utf8");

/**
 * What one answer envelope costs on the wire (review L2): sealing and two layers of base64 make it
 * about 16/9 of its plaintext, plus ~3 KiB of certificate and fields, sent once to each relay.
 */
export const sealedCost = (relays: number) => (plainBytes: number) => (Math.ceil((plainBytes * 16) / 9) + 3072) * Math.max(1, relays);

async function answerWant(
  app: App,
  from: string,
  fdid: string,
  want: { cid: string; fromVer: number },
  authorizedBy: string,
  relay: string,
  capJws?: string,
  pow?: WantPow,
  opts: { fallback?: boolean; ts?: number } = {},
): Promise<void> {
  const c = await loadCircle(app.store, want.cid);
  // A device that doesn't hold the circle can't answer: the next in line will (re-review N6).
  if (!c) return;
  const h = c.chain.head;
  // review L2: the roster only to members of the head, or to anyone for an open circle (friendship alone isn't enough).
  void authorizedBy;
  const member = h.members.includes(from);
  const mayKnow = member || circlePolicy(h) === "open";
  // review F3: the cheap checks come before a want is queued for a fallback answer.
  if (!mayKnow || (await app.store.isBlocked(from))) return;
  // Re-review N3: a non-member draws on the reserve only with a fresh proof of work for this want
  // (an ancestor hash is public: `prev`, join statements' `at`); without one, on a small pool.
  const powId = member ? undefined : checkWantPow(pow, from, app.userId, want.cid, want.fromVer, nowSec());
  // M3: every device of ours gets the want; the first in line answers, the others wait their
  // turn and answer only if nobody did (re-review N6).
  if (!opts.fallback) {
    const rank = await myAnsweringRank(app);
    if (rank > 0) {
      // review F2: dated by the want's envelope, not by when it reached this device.
      const at = opts.ts ?? Date.now();
      const w: DeferredWant = { from, fdid, want, relay, ...(capJws ? { cap: capJws } : {}), ...(pow ? { pow } : {}), at, due: at + rank * app.tun.wantFallbackSec * 1000 };
      await app.state.update("deferredWants", (cur = []) => {
        if (cur.filter((x) => x.from === from).length >= MAX_DEFERRED_PER_ASKER) return { result: undefined };
        return { next: [...cur, w].slice(-MAX_DEFERRED_WANTS), result: undefined };
      });
      return;
    }
  }
  const who = async () => app.addressOf(from);
  const refuse = async (why: string) => {
    app.io.err(`not answering ${await who()}'s request for circle ${want.cid}: ${why}`);
    // review F2: our other devices don't answer what this one refused.
    await noteRefused(app, from, want.cid);
  };
  // L4: the limits first, before any bundle is built or identity document fetched.
  let pool: AnswerPool = member ? "member" : powId !== undefined ? "reserve" : "open";
  let allow = await answerAllowance(app, from, pool, want.cid);
  if (pool === "reserve" && allow.pows.has(powId!)) {
    pool = "open";
    allow = await answerAllowance(app, from, pool, want.cid);
  }
  if (!allow.ok) return refuse(allow.why);
  // M1: what was already sent to this asker this hour isn't sent again, except once (a lost part).
  // Once the circle has moved on (a newer head), what they hold is stale anyway: that is new.
  const last = allow.last[`${from}|${want.cid}`];
  const resend = last !== undefined && want.fromVer <= last.ver && h.ver <= last.ver;
  if (resend && last.resent) return refuse(`already sent them this circle up to version ${last.ver} this hour`);
  const fromVer = Math.max(1, want.fromVer);
  // M2: only the device that asked gets the answer, so it is counted (and sent) once.
  const toAsker = { onlyDevices: [fdid], hint: [relay] };
  try {
    const held = (await app.capsFor(from, "circle")).size > 0;
    const answerCap = held ? undefined : await answerCapOf(app, capJws, from);
    if (held || answerCap) {
      const view = held ? await app.view(from) : await app.viewFor(from, { hint: [relay] });
      if (!view?.devices.includes(fdid)) return refuse("the asking device isn't on their identity document");
      const ob = await outgoingCircleBundle(app.store, want.cid, { fromVer });
      // A blocked asker was refused above; our own statement is never in an answer to one (R3-L1).
      const cut = answerParts(ob?.circles ?? [], ob?.joins ?? [], allow.bytes, sealedCost(Math.min(3, view.head.relays.length)));
      if (cut.parts.length === 0) return refuse("not even one version fits what is left of this hour's budget");
      const charged = await chargeAnswer(app, from, pool, cut.bytes, { cid: want.cid, ver: fromVer + cut.sentVersions - 1, resent: resend, ...(pool === "reserve" ? { pow: powId } : {}) });
      if (!charged.ok) return refuse(charged.why);
      // Ordinary `circle` bundles, chunked under the envelope cap, each saying which part of how
      // many it is, so the asker knows when the answer is whole (§3.3).
      const id = b64uEncode(randomBytes(9));
      let all = true;
      // What actually went out, at the price the charge used: each part's sealed size, per relay reached.
      const perRelay = sealedCost(1);
      let spent = 0;
      try {
        for (const [i, part] of cut.parts.entries()) {
          const d = await app.deliver(
            from,
            "circle",
            { own: app.userId, ...CIRCLE_SID },
            { circles: part.circles, joins: part.joins, ops: [], part: { id, i: i + 1, n: cut.parts.length } },
            { extraCaps: answerCap ? [answerCap] : [], ...toAsker },
          );
          // review P1: what this member wrote to the wire, whatever the relays replied: a relay the
          // asker controls could store each part and answer an error.
          const wrote = d.relays.length + (d.errors ?? []).filter((e) => e.written).length;
          spent += perRelay(bodyBytes({ circles: part.circles, joins: part.joins })) * wrote;
          // The rest still goes: the asker keeps what arrives and asks again for the gap.
          if (d.relays.length === 0) {
            if (all) app.io.err(`part ${i + 1} of the answer to ${await who()} about circle ${want.cid} reached no relay (${[...new Set((d.errors ?? []).map((x) => x.code))].join(", ") || "no relay"})`);
            all = false;
          }
        }
      } catch (e) {
        all = false;
        app.io.err(`couldn't finish answering ${await who()} about circle ${want.cid}: ${(e as Error).message}`);
      }
      // review F2 and the soak: an answer that didn't fully go out isn't one. It is refunded (the
      // asker's next want is answered, not refused as a resend), and our other devices aren't told.
      if (!all) {
        // N-A: charged for what went out, refunded only the rest.
        if (charged.receipt) await settleAnswer(app, charged.receipt, spent);
        return;
      }
      await noteHandled(app, { asker: from, cid: want.cid, at: Date.now(), ver: fromVer + cut.sentVersions - 1, bytes: cut.bytes, pool, ...(pool === "reserve" && powId ? { pow: powId } : {}) });
      return;
    }
    // An older client's want, with no cap: one cap-less `contact` envelope (§5.4: relay rate limits
    // and PoW apply), so only a chain that fits one envelope can go this way.
    const body = { circle: h.jws, chain: c.chain.versionsFrom(1).slice(0, -1) };
    if (bodyBytes(body) > SYNC_CHUNK_BYTES) return refuse("its history is too long for one first-contact envelope, and their client sent no answer cap (it needs updating)");
    const view = await app.discover(from, [relay]);
    if (!view?.devices.includes(fdid)) return refuse("the asking device isn't on their identity document");
    const charged = await chargeAnswer(app, from, pool, sealedCost(Math.min(3, view.head.relays.length))(bodyBytes(body)), { cid: want.cid, ver: h.ver, resent: resend, ...(pool === "reserve" ? { pow: powId } : {}) });
    if (!charged.ok) return refuse(charged.why);
    const d = await app.deliver(from, "contact", { own: app.userId, sid: "~contact" }, body, toAsker).catch(() => undefined);
    if (!d || d.relays.length === 0) {
      if (charged.receipt) await refundAnswer(app, charged.receipt);
      return;
    }
    await noteHandled(app, { asker: from, cid: want.cid, at: Date.now(), ver: h.ver, bytes: bodyBytes(body), pool, ...(pool === "reserve" && powId ? { pow: powId } : {}) });
  } catch (e) {
    app.io.err(`couldn't answer ${await who()}'s request for circle ${want.cid}: ${(e as Error).message}`);
  }
}
