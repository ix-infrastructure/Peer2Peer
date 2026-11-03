// Copyright 2026 Ix Infrastructure Inc.
//
// The sender's outbox: messages no relay accepted when they were sent (this device's network was
// down, or every relay of the recipient was unreachable). Relays store ciphertext for 7 days; this
// is the same promise on the sender's side, so a message written during a dropped connection is
// not simply lost.
//
//  - What is kept is the sealed envelope itself, never the intent: a retry sends the same bytes,
//    so if a relay did store an earlier copy (its answer was lost) the recipient's replay window
//    drops the second one. No retry can deliver a message twice.
//  - It lives in the p2p home's state (`<home>/cli/outbox.json`, 0600, under the state lock),
//    next to the caps it was sealed with, which are held in the trust store already.
//  - `p2p watch` retries due items with backoff (OUTBOX_RETRY_MS doubling, at most
//    OUTBOX_RETRY_MAX_MS); a send from this device sends due ones too.
//  - An item expires OUTBOX_TTL_MS after it was sealed: a recipient refuses an envelope whose ts
//    is more than 7 days old anyway. Expired, delivered and refused items leave a `p2p.outbox`
//    event for the session that wrote them (data only: state, recipient, when it was queued).
//  - Bounded: OUTBOX_PER_RECIPIENT items per recipient, OUTBOX_MAX in all, OUTBOX_MAX_BYTES of
//    envelopes (OUTBOX_RECIPIENT_BYTES per recipient); a send past a cap is refused
//    (outbox_full), never queued by dropping another.
//  - Re-checked before every retry (pre-release review O1): a recipient blocked or no longer a friend or
//    co-member (or, for one of our own sessions, no longer on its roster), a device no longer on
//    their current identity document (refreshed when older than the usual bound), or an identity
//    that rotated: dropped as `refused`, never sent. Caps are taken fresh, not as sealed.
//  - Inside the replay window (O2): a recipient drops an envelope more than REPLAY_WINDOW seqs
//    below the highest it has seen from this device in that session. One that this device's seq
//    for the session has passed by more than OUTBOX_WINDOW is refused at queue time
//    (outbox_window) and dropped as `expired` at flush time, never reported delivered.
//  - Fair (O5): one recipient can't hold the outbox. It has at most 1/10 of the items and 1/8 of
//    the bytes; a flush stops at a recipient's first retryable failure (one slow timeout per
//    recipient per round, not twenty); and items that have failed for OUTBOX_STUCK_MS straight
//    while this device's own relays answered are expired early: their relays answer but refuse.

import { createHash } from "node:crypto";
import { CircleChain, decodeEnvelopeV3, liveFriendshipsV3, REPLAY_WINDOW } from "@peer2peer/core/v3";
import { orderRelays, type App } from "./app.js";
import { CliError } from "./errors.js";
import { makeEvent } from "./inbound.js";
import { sessKey, type EventRec } from "./state.js";
import { getSession, rosterAudience } from "./sessions.js";

export const OUTBOX_TTL_MS = 7 * 24 * 3600 * 1000;
export const OUTBOX_PER_RECIPIENT = 10;
export const OUTBOX_MAX = 200;
export const OUTBOX_MAX_BYTES = 4 * 1024 * 1024;
export const OUTBOX_RETRY_MS = 15_000;
export const OUTBOX_RETRY_MAX_MS = 30 * 60_000;
export const OUTBOX_RECIPIENT_BYTES = OUTBOX_MAX_BYTES / 20;
/** Answered refusals: a relay that took the request and said no. Only these expire an item early (P3). */
export const OUTBOX_ANSWERED = new Set(["relay-error", "rate-limited"]);
/**
 * A recipient's share (pre-release re-review P4): 1/20 of the items and bytes, halved while the outbox is
 * more than half full, so twenty recipients can always queue and no one of them can fill it.
 */
export function recipientShare(items: number, bytes: number): { items: number; bytes: number } {
  const crowded = items > OUTBOX_MAX / 2 || bytes > OUTBOX_MAX_BYTES / 2;
  return crowded ? { items: OUTBOX_PER_RECIPIENT / 2, bytes: OUTBOX_RECIPIENT_BYTES / 2 } : { items: OUTBOX_PER_RECIPIENT, bytes: OUTBOX_RECIPIENT_BYTES };
}
/** Seqs the session may move past a queued envelope before it is given up: REPLAY_WINDOW less a margin. */
export const OUTBOX_WINDOW = REPLAY_WINDOW - 64;
/** Retryable failures in a row, while our own relays work, before an item is expired early. */
export const OUTBOX_STUCK_MS = 3600_000;

/** Relay and connection failures that a later attempt can get past; anything else is final. */
export const OUTBOX_RETRYABLE = new Set(["network", "timeout", "unreachable", "no_relay", "closing", "rate-limited", "relay-error"]);

export interface OutboxItem {
  /** SHA-256 of the envelope (one item per sealed copy). */
  id: string;
  to: string;
  tdid: string;
  kind: string;
  env: string;
  targets: { relay: string; cap?: string }[];
  /** Where it goes and who wrote it, for the events about it. */
  dest: { userId: string; address: string; own: string; sid: string; ref: string };
  fromSession: string;
  queuedAt: number;
  expiresAt: number;
  tries: number;
  nextAt: number;
  /** The seq it was sealed with, for the replay window check. */
  seq?: number;
  /** When its run of retryable failures (with this device online) started. */
  failingSince?: number;
}

export interface OutboxDoc {
  items: OutboxItem[];
}

/** Every copy failed only for reasons a retry can get past (and at least one copy was sealed). */
export function retryable(unsent: readonly { codes: readonly string[] }[]): boolean {
  return unsent.length > 0 && unsent.every((u) => u.codes.every((c) => OUTBOX_RETRYABLE.has(c)));
}

const backoff = (tries: number) => Math.min(OUTBOX_RETRY_MAX_MS, OUTBOX_RETRY_MS * 2 ** Math.max(0, tries - 1));

/** Queues sealed copies; refuses (outbox_full) when a cap would be passed. Returns when they expire. */
export async function enqueue(
  app: App,
  copies: readonly { did: string; env: string; targets: { relay: string; cap?: string }[] }[],
  meta: { kind: string; dest: OutboxItem["dest"]; fromSession: string },
  now = Date.now(),
): Promise<{ expiresAt: number; queued: number }> {
  const expiresAt = now + OUTBOX_TTL_MS;
  const seqOf = (env: string) => {
    try {
      return decodeEnvelopeV3(env).payload.seq;
    } catch {
      return undefined;
    }
  };
  const counter = (await app.state.get("seq"))?.[sessKey(meta.dest.own, meta.dest.sid)];
  for (const c of copies) {
    const q = seqOf(c.env);
    if (q !== undefined && counter !== undefined && counter - q > OUTBOX_WINDOW) {
      throw new CliError("outbox_window", `this session has sent ${counter - q} envelopes since this one was sealed; a recipient would drop it as too old (it keeps the last ${REPLAY_WINDOW}): not queued`, { delivered: false });
    }
  }
  const fresh: OutboxItem[] = copies.map((c) => ({
    id: createHash("sha256").update(c.env).digest("base64url"),
    to: meta.dest.userId,
    tdid: c.did,
    kind: meta.kind,
    env: c.env,
    targets: c.targets.map((t) => ({ relay: t.relay, ...(t.cap ? { cap: t.cap } : {}) })),
    dest: meta.dest,
    fromSession: meta.fromSession,
    queuedAt: now,
    expiresAt,
    tries: 0,
    nextAt: now + OUTBOX_RETRY_MS,
    ...(seqOf(c.env) !== undefined ? { seq: seqOf(c.env) } : {}),
  }));
  await app.state.update("outbox", (cur = { items: [] }) => {
    const items = cur.items.filter((i) => i.expiresAt > now);
    const ids = new Set(items.map((i) => i.id));
    const add = fresh.filter((i) => !ids.has(i.id));
    const theirs = items.filter((i) => i.to === meta.dest.userId);
    const addBytes = add.reduce((t, i) => t + i.env.length, 0);
    const bytes = items.reduce((t, i) => t + i.env.length, 0) + addBytes;
    const theirBytes = theirs.reduce((t, i) => t + i.env.length, 0) + addBytes;
    const share = recipientShare(items.length, bytes - addBytes);
    if (theirs.length + add.length > share.items || theirBytes > share.bytes || items.length + add.length > OUTBOX_MAX || bytes > OUTBOX_MAX_BYTES) {
      throw new CliError("outbox_full", `this device's outbox is full (at most ${share.items} messages per person while it is this full, ${OUTBOX_MAX} in all): the message was not sent; try again when you're back online`, {
        delivered: false,
      });
    }
    return { next: { items: [...items, ...add] }, result: undefined };
  });
  return { expiresAt, queued: fresh.length };
}

export async function outboxCount(app: App): Promise<number> {
  return ((await app.state.get("outbox"))?.items ?? []).length;
}

/**
 * Sends the due items (all of them with `force`) over the connected pool. Each is claimed under
 * the state lock first (its next attempt moved on), so two processes don't send it at once;
 * a second copy would be harmless anyway (the same envelope). Returns how many went out.
 */
export async function flushOutbox(app: App, opts: { force?: boolean; now?: number } = {}): Promise<{ sent: number; expired: number; failed: number }> {
  const out = { sent: 0, expired: 0, failed: 0 };
  const pool = app.pool;
  if (!pool || pool.connected.length === 0) return out;
  const now = opts.now ?? Date.now();
  const doc = await app.state.get("outbox");
  if (!doc || doc.items.length === 0) return out;
  // Expired ones first: gone, with a notice to the session that wrote them.
  const expired = await app.state.update("outbox", (cur = { items: [] }) => {
    const gone = cur.items.filter((i) => i.expiresAt <= now);
    return gone.length === 0 ? { result: gone } : { next: { items: cur.items.filter((i) => i.expiresAt > now) }, result: gone };
  });
  if (expired.length > 0) await note(app, expired, "expired", now);
  out.expired = expired.length;
  const claimed = await app.state.update("outbox", (cur = { items: [] }) => {
    const due = cur.items.filter((i) => opts.force || i.nextAt <= now);
    if (due.length === 0) return { result: due };
    const ids = new Set(due.map((i) => i.id));
    return { next: { items: cur.items.map((i) => (ids.has(i.id) ? { ...i, tries: i.tries + 1, nextAt: now + backoff(i.tries + 1) } : i)) }, result: due };
  });
  const done: { item: OutboxItem; state: "delivered" | "refused" | "expired" }[] = [];
  const failing: OutboxItem[] = [];
  const outage: OutboxItem[] = [];
  const seqs = (await app.state.get("seq")) ?? {};
  // One recipient at a time, oldest first; at its first retryable failure the rest of its items
  // wait for the next round (O5: a recipient whose relays time out costs one timeout a round).
  const stalled = new Set<string>();
  // P5: each recipient's document is refreshed once a round, whatever the number of their items.
  const views: RoundViews = new Map();
  for (const item of [...claimed].sort((x, y) => x.queuedAt - y.queuedAt)) {
    if (stalled.has(item.to)) continue;
    // O2: the session has moved on past the recipient's replay window: it would be dropped there.
    const counter = seqs[sessKey(item.dest.own, item.dest.sid)];
    if (item.seq !== undefined && counter !== undefined && counter - item.seq > OUTBOX_WINDOW) {
      done.push({ item, state: "expired" });
      continue;
    }
    // O5: failing for an hour straight while this device's own relays answer.
    if (item.failingSince !== undefined && now - item.failingSince >= OUTBOX_STUCK_MS) {
      done.push({ item, state: "expired" });
      continue;
    }
    // O1: everything that allowed this send still holds; caps taken fresh. P1: when that can't be
    // known this round (the document couldn't be refreshed and the one held is stale), it waits.
    const allowed = await stillAllowed(app, item, views).catch(() => "later" as const);
    if (allowed === "later") {
      stalled.add(item.to);
      continue;
    }
    if (allowed === "refused") {
      done.push({ item, state: "refused" });
      continue;
    }
    const targets = allowed.targets;
    let res: { sent: string[]; errors: { code: string }[] };
    try {
      res = await pool.sendEnvelope(item.env, item.to, item.tdid, item.kind, targets);
    } catch {
      stalled.add(item.to);
      continue; // closing: the next attempt
    }
    if (res.sent.length > 0) done.push({ item, state: "delivered" });
    else if (res.errors.length > 0 && res.errors.every((e) => !OUTBOX_RETRYABLE.has(e.code))) done.push({ item, state: "refused" });
    else {
      stalled.add(item.to);
      // P3: only relays that answered and refused (every one of them) start or continue the run
      // that expires an item early; a timeout or an unreachable relay is an outage, which keeps the
      // 7-day expiry, and breaks the run.
      if (res.errors.length > 0 && res.errors.every((e) => OUTBOX_ANSWERED.has(e.code))) {
        if (item.failingSince === undefined) failing.push(item);
      } else if (item.failingSince !== undefined) outage.push(item);
    }
  }
  if (failing.length > 0 || outage.length > 0) {
    const start = new Set(failing.map((i) => i.id));
    const clear = new Set(outage.map((i) => i.id));
    await app.state.update("outbox", (cur = { items: [] }) => ({
      next: {
        items: cur.items.map((i) => {
          if (start.has(i.id) && i.failingSince === undefined) return { ...i, failingSince: now };
          if (clear.has(i.id)) {
            const { failingSince: _gone, ...rest } = i;
            return rest;
          }
          return i;
        }),
      },
      result: undefined,
    }));
  }
  if (done.length > 0) {
    const ids = new Set(done.map((d) => d.item.id));
    await app.state.update("outbox", (cur = { items: [] }) => ({ next: { items: cur.items.filter((i) => !ids.has(i.id)) }, result: undefined }));
    const delivered = done.filter((d) => d.state === "delivered").map((d) => d.item);
    const refused = done.filter((d) => d.state === "refused").map((d) => d.item);
    const gone = done.filter((d) => d.state === "expired").map((d) => d.item);
    if (delivered.length > 0) await note(app, delivered, "delivered", now);
    if (refused.length > 0) await note(app, refused, "refused", now);
    if (gone.length > 0) await note(app, gone, "expired", now);
    out.sent = delivered.length;
    out.failed = refused.length;
    out.expired += gone.length;
  }
  return out;
}

/** One `p2p.outbox` event per message (its copies to several devices count once) for the session that wrote it. */
async function note(app: App, items: readonly OutboxItem[], state: "delivered" | "expired" | "refused", now: number): Promise<void> {
  const seen = new Set<string>();
  const events: Omit<EventRec, "n">[] = [];
  for (const i of items) {
    const key = `${i.dest.userId}|${i.dest.sid}|${i.queuedAt}`;
    if (seen.has(key)) continue;
    seen.add(key);
    events.push(makeEvent(i.env, "p2p.outbox", now, { state, to: i.dest, queuedAt: i.queuedAt }, { toSession: i.fromSession }, state));
  }
  await app.state.addEvents(events);
}

/** One round's identity views, by recipient (P5): refreshed once, shared by all their items. */
export type RoundViews = Map<string, Promise<{ view: Awaited<ReturnType<App["view"]>>; fresh: boolean }>>;

/**
 * The recipient's view for this round: refreshed (once per round), and whether it is fresh: the
 * refresh went through now, or the one held was refreshed within the usual bound
 * (P2P_DOC_REFRESH_SEC, at least FETCHED_SLACK_MS as `fetched` is recorded).
 */
function roundView(app: App, to: string, views: RoundViews) {
  let p = views.get(to);
  if (!p) {
    p = (async () => {
      let view = await app.view(to);
      try {
        view = (await app.refreshIdentity(to, view?.relays ?? [], { quiet: true })) ?? view;
      } catch {
        // not refreshed: judged by how old the held one is
      }
      const fetched = (await app.state.get("fetched"))?.[to];
      const bound = Math.max(app.tun.docRefreshSec * 1000, 10_000);
      return { view, fresh: fetched !== undefined && Date.now() - fetched <= bound };
    })();
    views.set(to, p);
  }
  return p;
}

/**
 * O1: may this queued copy still go out, and over which relays? "refused" when not: the
 * recipient blocked; for their session, no longer a friend or co-member; for one of ours, no
 * longer on its roster; the device no longer on their current document; or their identity rotated.
 * "later" (P1) when that can't be told this round: the document couldn't be refreshed and the one
 * held is past its freshness bound. The relays (P2) are those of their current document, then the
 * ones it was sealed for, each with a cap of this moment.
 */
export async function stillAllowed(app: App, item: OutboxItem, views: RoundViews = new Map()): Promise<{ targets: { relay: string; cap?: string }[] } | "refused" | "later"> {
  const to = item.to;
  let relays: string[];
  if (to !== app.userId) {
    if (await app.store.isBlocked(to)) return "refused";
    const { view, fresh } = await roundView(app, to, views);
    if (!fresh) return "later";
    if (!view || (view.rotations?.length ?? 0) > 0 || !view.devices.includes(item.tdid)) return "refused";
    relays = orderRelays(view.head.relays, view.relays).slice(0, 3);
    if (item.dest.own === app.userId) {
      const sess = await getSession(app, item.dest.sid).catch(() => undefined);
      if (!sess || !(await rosterAudience(app, sess)).includes(to)) return "refused";
    } else {
      const friend = (await liveFriendshipsV3(app.store, app.signerCtx(), (f) => [f.inviter, f.invitee].includes(to))).some((f) => f.inviter === to || f.invitee === to);
      let comember = false;
      if (!friend) {
        for (const rec of await app.store.listCircles()) {
          const members = CircleChain.fromStored(rec.chain).head.members;
          if (rec.joinedByMe && members.includes(to) && members.includes(app.userId)) comember = true;
        }
      }
      if (!friend && !comember) return "refused";
    }
  } else {
    const own = await app.ownView();
    if (!own.devices.includes(item.tdid)) return "refused";
    relays = orderRelays(own.head.relays, own.relays).slice(0, 3);
  }
  const caps = await app.capsFor(to, item.kind);
  const candidates = [...new Set([...relays, ...item.targets.map((t) => t.relay)])];
  const targets = candidates.filter((r) => caps.has(r)).slice(0, 3).map((r) => ({ relay: r, cap: caps.get(r) }));
  return targets.length > 0 ? { targets } : "refused";
}
