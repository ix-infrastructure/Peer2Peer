// Copyright 2026 Ix Infrastructure Inc.
//
// Delivery receipts (docs/protocol.md §4.3 "Delivery receipts", cap receipts.v1).
//
//  - Sender: a message to a session whose live status advertises receipts.v1 carries `rcpt`, a
//    random id; this device remembers it (`receipts.wanted`, by id) with the user it went to and
//    the local session that sent it. A `receipt` envelope is taken only from that user, for an
//    id this device sent them, at most RECEIPTS_PER_ID times, and becomes a `p2p.receipt` event
//    for the sending session. Anything else is dropped without a trace.
//  - Receiver: an inbound message that asked is remembered (`receipts.asked`, by event id). The
//    front end that shows messages (the Claude mod) reports what became of it with `p2p receipt
//    <event> --outcome …`; the CLI decides whether one goes out: receipts on, the session not
//    private, the message delivered to that session (or an ended session's unclaimed copy, which
//    only ever says `ended`), each outcome once, nothing after a final one, within the rate
//    limits. A receipt goes only to the authenticated sender's sending device, carries the id and
//    the outcome and nothing else, and is never itself receipted.

import { randomBytes } from "node:crypto";
import { RECEIPT_ID_RE, RECEIPT_OUTCOMES, RECEIPT_SID, STATUS_CAP_RECEIPTS, type AcceptedMessageV3, type ReceiptOutcome } from "@peer2peer/core/v3";
import type { App } from "./app.js";
import { receiptsEnabled } from "./config.js";
import { peerSupports } from "./features.js";
import { CliError } from "./errors.js";
import { fromOf, makeEvent, type NewEvent } from "./inbound.js";

/** What a sender remembers about a message that asked for receipts. */
export interface ReceiptWanted {
  /** The user it went to: the only one whose receipts for it count. */
  to: string;
  /** The session it went to (own, ref), for the sender's display. */
  own: string;
  ref: string;
  /** The local session that sent it: its watcher gets the receipts. */
  fromSession: string;
  at: number;
  outcomes: { outcome: ReceiptOutcome; at: number }[];
}

/** What a receiver remembers about a message that asked, by its event id. */
export interface ReceiptAsked {
  id: string;
  /** The authenticated sender, and the device that sent it (the receipt goes there only). */
  from: string;
  did: string;
  at: number;
  /** The local session it was delivered into. */
  toSession?: string;
  /** An ended session's copy (inbound `unclaimedFor`): it only ever says `ended`. */
  unclaimedFor?: string;
}

export interface ReceiptsDoc {
  wanted: Record<string, ReceiptWanted>;
  asked: Record<string, ReceiptAsked>;
  /** Outcomes sent, by `<sender>|<id>`. */
  sent: Record<string, { at: number; outcomes: ReceiptOutcome[] }>;
  /** When receipts went out, for the rate limits: by recipient, and all of them. */
  rate: { by: Record<string, number[]>; all: number[] };
}

/** Kept for as long as a message can still arrive (relays keep it 7 days), then dropped. */
export const RECEIPT_TTL_MS = 7 * 24 * 3600 * 1000;
export const RECEIPTS_WANTED_MAX = 512;
export const RECEIPTS_ASKED_MAX = 1024;
/** A message has at most this many outcomes (held, then shown or declined or expired): more are dropped. */
export const RECEIPTS_PER_ID = 3;
/**
 * Receipts this device sends in a minute: at most RECEIPT_RATE_PER_USER to one user. Past
 * RECEIPT_RATE_ALL in all, a user gets only their fair share of it (RECEIPT_RATE_ALL divided among
 * the users receipted this minute, this one included), so a few busy peers can't use up everyone
 * else's receipts; RECEIPT_RATE_HARD is the ceiling either way (pre-release review R5).
 */
export const RECEIPT_RATE_PER_USER = 30;
export const RECEIPT_RATE_ALL = 120;
export const RECEIPT_RATE_HARD = 240;

/** Whether one more receipt to `user` fits the limits (rate windows of the last minute). */
export function receiptRateAllows(rate: { by: Record<string, number[]>; all: number[] }, user: string): boolean {
  const mine = rate.by[user]?.length ?? 0;
  if (mine >= RECEIPT_RATE_PER_USER || rate.all.length >= RECEIPT_RATE_HARD) return false;
  if (rate.all.length < RECEIPT_RATE_ALL) return true;
  const users = new Set([...Object.keys(rate.by).filter((u) => (rate.by[u]?.length ?? 0) > 0), user]).size;
  return mine < Math.floor(RECEIPT_RATE_ALL / users);
}
const MINUTE = 60_000;
/** Outcomes after which nothing more is said about a message. */
const FINAL: ReadonlySet<ReceiptOutcome> = new Set(["shown", "declined", "expired", "ended"]);

const empty = (): ReceiptsDoc => ({ wanted: {}, asked: {}, sent: {}, rate: { by: {}, all: [] } });

/** Drops what is older than the TTL, and the oldest past each cap. */
function prune(d: ReceiptsDoc, now: number): ReceiptsDoc {
  const fresh = <T extends { at: number }>(m: Record<string, T>, max: number): Record<string, T> =>
    Object.fromEntries(
      Object.entries(m)
        .filter(([, v]) => now - v.at <= RECEIPT_TTL_MS)
        .sort(([, a], [, b]) => b.at - a.at)
        .slice(0, max),
    );
  const by: Record<string, number[]> = {};
  for (const [u, ts] of Object.entries(d.rate.by)) {
    const keep = ts.filter((t) => now - t < MINUTE);
    if (keep.length > 0) by[u] = keep;
  }
  return {
    wanted: fresh(d.wanted, RECEIPTS_WANTED_MAX),
    asked: fresh(d.asked, RECEIPTS_ASKED_MAX),
    sent: fresh(d.sent, RECEIPTS_ASKED_MAX),
    rate: { by, all: d.rate.all.filter((t) => now - t < MINUTE) },
  };
}

/** How many entries a doc holds: pruning changed it iff this went down. */
const size = (d: ReceiptsDoc): number =>
  Object.keys(d.wanted).length + Object.keys(d.asked).length + Object.keys(d.sent).length + d.rate.all.length + Object.values(d.rate.by).reduce((n, ts) => n + ts.length + 1, 0);

/** Read-modify-write under the state lock; nothing is written when nothing changed (pre-release review R3). */
function withDoc<R>(app: App, fn: (d: ReceiptsDoc, now: number) => { next?: ReceiptsDoc; result: R }): Promise<R> {
  const now = Date.now();
  return app.state.update("receipts", (cur) => {
    const d = prune({ ...empty(), ...(cur ?? {}) }, now);
    const r = fn(d, now);
    if (r.next !== undefined) return { next: r.next, result: r.result };
    // Only pruning: written only when it dropped something from a stored doc (prune only drops).
    return { ...(cur !== undefined && size(d) !== size({ ...empty(), ...cur }) ? { next: d } : {}), result: r.result };
  });
}

export function newReceiptId(): string {
  return randomBytes(12).toString("base64url");
}

/**
 * Whether a message to `(own, sid)` may carry `rcpt`: only when the session is live now (a status
 * within STATUS_LIVE_MS) and that status advertises receipts.v1 (never by substring). A client from
 * before receipts rejects the whole message for an unknown field, so a stale status (the session
 * since restarted on an older client, or turned receipts off) must never decide it: the 24 h
 * offline path sends without one (pre-release review R2).
 */
export async function asksReceipts(app: App, own: string, sid: string): Promise<boolean> {
  return peerSupports(app, own, { sid }, STATUS_CAP_RECEIPTS);
}

/** Sender: remember a message that asked for receipts. */
export async function rememberWanted(app: App, id: string, w: Omit<ReceiptWanted, "at" | "outcomes">): Promise<void> {
  await withDoc(app, (d, now) => ({ next: { ...d, wanted: { ...d.wanted, [id]: { ...w, at: now, outcomes: [] } } }, result: undefined }));
}

/** Receiver: remember an inbound message that asked (only while receipts are on). */
export async function rememberAsked(app: App, eventId: string, a: Omit<ReceiptAsked, "at">): Promise<void> {
  if (!receiptsEnabled(app.env, app.home)) return;
  await withDoc(app, (d, now) => (d.asked[eventId] ? { result: undefined } : { next: { ...d, asked: { ...d.asked, [eventId]: { ...a, at: now } } }, result: undefined }));
}

export interface SendReceiptResult {
  sent: boolean;
  outcome?: ReceiptOutcome;
  /** Why none went out: off, not-asked, private, not-yours, done, rate-limited, undelivered. */
  reason?: string;
}

/**
 * `p2p receipt <event> --from-session <sid> --outcome <o>`: what became of a message, reported by
 * the session that has it. Never an error for "nothing to send": `{sent: false, reason}`.
 */
export async function sendReceipt(app: App, o: { eventId: string; fromSession: string; outcome: string }): Promise<SendReceiptResult> {
  if (!RECEIPT_OUTCOMES.includes(o.outcome as ReceiptOutcome)) throw new CliError("usage", `--outcome must be one of ${RECEIPT_OUTCOMES.join(", ")}`);
  if (!receiptsEnabled(app.env, app.home)) return { sent: false, reason: "off" };
  const asked = ((await app.state.get("receipts"))?.asked ?? {})[o.eventId];
  if (!asked) return { sent: false, reason: "not-asked" };
  // The copy of an ended session's message says only that the session ended, whatever this one did
  // with it: never which session has it now (nor that it was held, shown or declined there).
  const outcome: ReceiptOutcome = asked.unclaimedFor !== undefined ? "ended" : (o.outcome as ReceiptOutcome);
  // A message for no session of ours (`toSession` unknown) is held by whichever session the user picks.
  if (asked.unclaimedFor === undefined && asked.toSession !== undefined && asked.toSession !== o.fromSession) return { sent: false, reason: "not-yours" };
  // A private session (shared with nobody) sends none: one would tell the sender it exists. Nor does
  // the copy of a private ended session's message. A session with no roster here counts as private.
  // Except to this user's own sessions (another device, or this one): they list it anyway, and the
  // receipt is how one of them learns its message waits for Deliver.
  const sessions = (await app.state.get("sessions")) ?? {};
  const isPrivate = (sid: string) => {
    const doc = sessions[sid];
    return !doc || (doc.vis === "private" && doc.parts.length === 0);
  };
  if (asked.from !== app.userId && (isPrivate(o.fromSession) || (asked.unclaimedFor !== undefined && isPrivate(asked.unclaimedFor)))) return { sent: false, reason: "private" };
  const key = `${asked.from}|${asked.id}`;
  const verdict = await withDoc(app, (d, now) => {
    const done = d.sent[key]?.outcomes ?? [];
    if (done.includes(outcome) || done.some((x) => FINAL.has(x)) || done.length >= RECEIPTS_PER_ID) return { result: "done" as const };
    const mine = d.rate.by[asked.from] ?? [];
    if (!receiptRateAllows(d.rate, asked.from)) return { result: "rate-limited" as const };
    // Counted before it goes out: a failed send doesn't free its slot (no retry storms), and an
    // outcome is claimed once even when two processes report it at the same time.
    return {
      next: { ...d, sent: { ...d.sent, [key]: { at: now, outcomes: [...done, outcome] } }, rate: { by: { ...d.rate.by, [asked.from]: [...mine, now] }, all: [...d.rate.all, now] } },
      result: "go" as const,
    };
  });
  if (verdict !== "go") return { sent: false, reason: verdict };
  await app.connectAndDrain();
  const d = await app.deliver(asked.from, "receipt", { own: app.userId, sid: RECEIPT_SID }, { receipt: { id: asked.id, outcome } }, { onlyDevices: [asked.did] });
  return d.relays.length > 0 ? { sent: true, outcome } : { sent: false, outcome, reason: "undelivered" };
}

/** Sender: a `receipt` envelope. Only from the user the message went to, for an id this device sent them. */
export async function onReceipt(app: App, env: string, r: AcceptedMessageV3): Promise<NewEvent[]> {
  const pt = r.plaintext as { kind: "receipt"; receipt: { id: string; outcome: ReceiptOutcome } };
  const { id, outcome } = pt.receipt;
  if (!RECEIPT_ID_RE.test(id)) return [];
  const from = r.envelope.from;
  const hit = await withDoc(app, (d, now) => {
    const w = d.wanted[id];
    if (!w || w.to !== from) return { result: undefined };
    if (w.outcomes.some((x) => x.outcome === outcome) || w.outcomes.length >= RECEIPTS_PER_ID) return { result: undefined };
    const next = { ...w, outcomes: [...w.outcomes, { outcome, at: now }] };
    return { next: { ...d, wanted: { ...d.wanted, [id]: next } }, result: next };
  });
  if (!hit) return [];
  const sender = await fromOf(app, r);
  return [makeEvent(env, "p2p.receipt", r.envelope.ts, { from: sender, receiptId: id, outcome, own: hit.own, ref: hit.ref }, { toSession: hit.fromSession }, hit.fromSession)];
}

/** `p2p receipts [on|off]`: the setting, as config.json and the environment make it. */
export function receiptsSetting(app: App): { receipts: boolean; overridden: boolean } {
  return { receipts: receiptsEnabled(app.env, app.home), overridden: app.env.P2P_RECEIPTS !== undefined && app.env.P2P_RECEIPTS.trim() !== "" };
}
