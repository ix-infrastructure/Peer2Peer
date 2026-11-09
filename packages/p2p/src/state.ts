// Copyright 2026 Ix Infrastructure Inc.
//
// The CLI's own documents in `<home>/cli` (0700, 0600 files, atomic writes,
// one cross-process lock), next to the core trust store in `<home>/v3`.
// Every read-modify-write runs under the lock, so `p2p watch` and short
// commands can run at the same time.
//
//   keys      this device's secrets (and the identity seed on key holders)
//   self      name, relays, did, the default circle
//   sessions  own session rosters, by sid
//   seq       envelope sequence counters, by (own, sid)
//   peers     the latest status of every session heard of, by (own, sid)
//   held      first contacts and circle invites waiting for the user
//   events    the accepted-event log `watch` prints from (bounded)
//   spoke     which local session last spoke to a peer session
//   subs      notify-when-idle subscriptions
//   joins     circle joins waiting for confirmation answers
//   transfers transfer consents received, by cid
//   fetched   when each contact's identity document was last refreshed
//   codes     short-code invites this user issued (P4), by lid
//   redeemed  bundles fetched with `p2p join`, by lid (a retry needs no relay: the code is single-use)
//   codeJoins circles a redeemed code joins, waiting for the inviter to add us, by cid
//   admits    members-only relays: a redeemed code's admission key, by relay, until used
//   rotations rotation statements seen from friends and co-members (§2.8), by old userId
//   follows   rotations of our own identity a key holder sent (with their one-time link codes), by held id
//   rotationAlerts  rotations of our own identity this device already alerted about
//   circleHold      owned circles whose changes (proposals, rotated members) wait for approval
//   xstate    extension state kinds (§4.3, xstate.v1): an index of senders; each sender's values (latest per
//             (sid, kind)) and per-session rate windows are in a document of their own, xstate-<hash>
//   xstateSent      when this device last published each (sid, kind), for the sender's rate limit
//   outbox    sealed messages no relay accepted yet (outbox.ts), retried by watch, 7 days at most
//   receipts  delivery receipts (receipts.ts): ids this device asked for, messages that asked it, what it sent
//   unknownKinds  when each (sender, kind) of an envelope this version doesn't know was last noticed
//   relayInfo the relays' /.well-known/p2p-relay.json (features and frames), as last fetched
//   projects  project policies (projects.ts): shared with circles and people, or private (the default)
//   sessionProjects  the projects each session worked in (projects.ts), by sid
//   ixNotice  when the one-time "Ix on by default" notice was shown (ix-local.ts)
//   history, history-<n>  message history (history.ts): sealed with the key in history.key, never plaintext

import type { OutboxDoc } from "./outbox.js";
import type { ReceiptsDoc } from "./receipts.js";
import type { RelayInfoRec } from "./relay-info.js";
import type { ProjectsDoc, SessionProjectsDoc } from "./projects.js";
import { join } from "node:path";
import { FileDocBackend, type LockOptions } from "@peer2peer/core/v3/node";
import type { DocBackend, RotationStatement, StatusBody } from "@peer2peer/core/v3";
import { debug, step, type Progress } from "./progress.js";

export interface KeysDoc {
  v: 1;
  userId: string;
  did: string;
  /** b64u Ed25519 seed of the device signing key. */
  spk: string;
  /** b64u X25519 secret of the device agreement key. */
  kpk: string;
  /** This device's current certificate. */
  cert: string;
  /** b64u identity seed, on key-holding devices only (§2.2). */
  ik?: string;
}

export interface SelfDoc {
  name: string;
  relays: string[];
  createdAt: number;
  defaultCircle?: string;
  /**
   * The default circle was set by a code join (there was none): sessions already running when it was set
   * don't move into it by themselves; new ones start in it. Cleared when the user sets a default.
   */
  defaultFromJoin?: string;
  /** Relays that have not yet confirmed the current document. */
  unpublished?: string[];
  /** Relays that refused a publish outright (not a transient failure), with when (ms): retried at most hourly. */
  refusedPublish?: Record<string, number>;
  backupShown?: boolean;
  /** When this device last published its identity document to bring its `dinfo` entry current (ms; app.ts refreshDeviceInfo). */
  deviceInfoAt?: number;
}

export interface SessionDoc {
  sid: string;
  ver: number;
  vis: "circle" | "private";
  circle?: string;
  parts: string[];
  jws: string;
  /**
   * The roster is the default one (§6: the default circle, else private),
   * never set explicitly: it follows the default circle as that changes.
   * Absent on docs written before this field; isAutoRoster() reads those.
   */
  auto?: boolean;
  /** The open circle this session was last warned about being shared with (warned once per circle). */
  openNoted?: string;
}

/** One stored extension state value (xstate.ts): never an event. */
export interface XStateRec {
  own: string;
  sid: string;
  /** The sending device. */
  did: string;
  kind: string;
  /** The envelope `ts` (ms): latest wins by it. */
  ts: number;
  /** When it arrived here (ms). */
  at: number;
  /** Seconds it stays valid. */
  ttl: number;
  /** `ext.v` as sent. */
  v: number;
  /** The sanitized fallback line (no address prefix). */
  fallback: string;
  /** Bytes of `{v, body}` as sent. */
  bytes: number;
  /** The body the extension validated and kept; absent without the extension. */
  body?: unknown;
  extError?: string;
  /** This user's own session (this device, or another of ours). */
  self?: true;
}

/** `xstate`: the small index of senders whose state is held, with their totals (xstate.ts). */
export interface XStateIndex {
  v: 2;
  users: Record<string, { doc: string; n: number; cost: number }>;
}

/** `xstate-<hash>`: one sender's values, by `<sid>|<kind>`, and their per-session rate windows. */
export interface XStateSenderDoc {
  own: string;
  recs: Record<string, XStateRec>;
  /** Per session id: the current one-minute window of accepted updates (at most 128, the newest). */
  rate: Record<string, { start: number; n: number }>;
  /** The sender's one-minute window across all their sessions. */
  all?: { start: number; n: number };
}

/** One same-device send (Docs.localSends). */
export interface LocalSend {
  /** The sending session. */
  from: string;
  /** `person`: the person's own terminal session (`tui`, or a send as them); `agent`: any other session. */
  via: "person" | "agent";
  at: number;
}

export interface PeerStatusRec {
  own: string;
  sid: string;
  /** The sending device. */
  did: string;
  /** The envelope `ts` (ms): liveness is judged by it (§4.3). */
  ts: number;
  status: StatusBody;
  rule?: string;
  viewerRule?: string;
  self?: boolean;
}

/**
 * `rotation`: a friend's new identity, "<friend> moved to a new key" (§2.8).
 * `rotation-join`: the owner side, a rotated member's join to swap in.
 */
/** `rotation-dispute`: an approved rotation is now contested by another one (keep one, or neither). */
export type HeldType = "invite" | "circle-invite" | "circle-join" | "rotation" | "rotation-join" | "rotation-follow" | "rotation-dispute";

export interface HeldItem {
  id: string;
  type: HeldType;
  from: string;
  at: number;
  /** invite: the invite JWS. */
  invite?: string;
  /** circle-invite: the offered head and the chain that came with it. */
  head?: string;
  chain?: string[];
  joins?: string[];
  cid?: string;
  /** circle-join, rotation-join: the joiner's statement (owner side). */
  join?: string;
  reason?: string;
  /** rotation, rotation-join: the two-part statement (`invite` is the new identity's invite). */
  rotation?: RotationStatement;
  /** rotation, rotation-join: the old userId. */
  old?: string;
  /** rotation-dispute: the new identities that claim `old` (one of them approved here before). */
  candidates?: string[];
  /** rotation-follow: the key-holding device that sent it, its label, and the new identity's fingerprint. */
  device?: string;
  deviceLabel?: string;
  newFingerprint?: string;
}

export interface RotationApproval {
  to: string;
  kind: "friend" | "circle";
  cid?: string;
  at: number;
}

export interface RotationDispute {
  candidates: string[];
  /** Identities this client suspended (blocked) for it; `wasBlocked` ones it leaves blocked. */
  suspended: { userId: string; wasBlocked: boolean }[];
  /** review M3: members this owner's key holder took out of its circles when the dispute began (re-added if kept). */
  removedFrom?: { cid: string; userId: string; admin: boolean }[];
  heldId: string;
  at: number;
}

/**
 * A rotation of our own identity a key holder sent (§2.8 step 4), held until
 * the user follows it (`p2p identity follow <id>`): never followed by itself.
 * The link code is a secret, so it is kept here, never in the held item.
 */
export interface FollowRec {
  statement: RotationStatement;
  /** The one-time link code the new identity minted for this device (a secret). */
  link: string;
  fromDid: string;
  at: number;
}

export interface EventRec {
  n: number;
  id: string;
  at: number;
  kind: string;
  /** Session events: the local session it is for, when known. */
  toSession?: string;
  /** Session events: the session it belongs to. */
  own?: string;
  sid?: string;
  data: Record<string, unknown>;
}

export interface EventsDoc {
  next: number;
  items: EventRec[];
}

export interface IdleSub {
  own: string;
  sid: string;
  toSession: string;
  at: number;
}

export interface AnswerPartsRec {
  n: number;
  got: number[];
  top: number;
  /** When the first part of this answer arrived (ms). */
  at?: number;
}

export interface PendingJoin {
  cid: string;
  head: string;
  inviter?: string;
  /** Owner hint from a CLI circle link: its identity document and join statement. */
  hint?: { doc?: string; join?: string };
  /** Older clients kept answers here; now each confirmer's answer is a document of its own (join-answers.ts). */
  answers?: Record<string, string[]>;
  /** Who has an answer document for this join (written once per confirmer, not per part). */
  answerFrom?: string[];
  /** The answer caps this join issued (capids), revoked when it completes or is refused. */
  answerCaps?: string[];
  /** Membership statements that came with the answers. */
  joins: string[];
  asked: string[];
  askedAt: number;
  /** When each confirmer was last asked (ms); askedAt for ones asked before this field. */
  askedAtBy?: Record<string, number>;
}

/** A short-code invite this user issued (P4). */
export interface CodeRecord {
  lid: string;
  /** The grouped code, `K7QM-3XPD-9TWA-HF2N-6RJC` (this user's own secret, kept like the keys). */
  code: string;
  /** `<relay part>/<code>`. */
  short: string;
  relay: string;
  /** The hash of the invite JWS inside (what the accept names). */
  inv: string;
  /** The contact cap inside, so a revoke can revoke it too. */
  capid?: string;
  capRelays?: string[];
  aud: string;
  /** Local only: shown on the join notice. */
  label?: string;
  /** The (first) circle the code joins: what clients before multi-circle codes read. */
  cid?: string;
  /** Every circle the code joins, `cid` first (multi-circle codes). */
  cids?: string[];
  /** The circles the redemption put the redeemer in (added, or proposed to the owner): what `p2p remove` undoes. */
  added?: string[];
  /** Seconds. */
  createdAt: number;
  exp: number;
  status: "open" | "redeemed" | "revoked";
  redeemedBy?: string;
  redeemedAt?: number;
  removedAt?: number;
}

export interface RedeemedCode {
  lid: string;
  relay: string;
  blob: string;
  at: number;
  /** The accept reached no relay: a retry resends it. */
  undelivered?: boolean;
}

export interface CodeJoin {
  cid: string;
  inviter: string;
  lid: string;
  head: string;
  at: number;
  /** Set once a join was tried and needs the user's say (held item id). */
  needsApproval?: string;
  /** The code's first circle (the only one that may become the default circle); false for the others. */
  first?: boolean;
  /** What the person saw in the preview and said yes to: the circle that arrives must match it to be joined. */
  confirmed?: { name: string; policy: "invite" | "open"; owner: string };
}

type Docs = {
  keys: KeysDoc;
  self: SelfDoc;
  sessions: Record<string, SessionDoc>;
  seq: Record<string, number>;
  peers: Record<string, PeerStatusRec>;
  held: HeldItem[];
  events: EventsDoc;
  spoke: Record<string, string>;
  subs: IdleSub[];
  joins: Record<string, PendingJoin>;
  transfers: Record<string, Record<string, string>>;
  fetched: Record<string, number>;
  codes: Record<string, CodeRecord>;
  redeemed: Record<string, RedeemedCode>;
  codeJoins: Record<string, CodeJoin>;
  /** Members-only relays: admission keys from redeemed codes, by relay, until a relay admits us with one. */
  admits: Record<string, { key: string; at: number }>;
  rotations: Record<string, RotationStatement[]>;
  follows: Record<string, FollowRec>;
  rotationAlerts: string[];
  /** What this client carried over through a rotation, by old userId (friendships, circle swaps). */
  rotationApprovals: Record<string, RotationApproval[]>;
  /** Contested carry-overs waiting for the user: who was suspended, by old userId. */
  disputes: Record<string, RotationDispute>;
  /** How the user settled a contest, by old userId: the identity kept (or none) and the rejected ones. */
  rotationResolved: Record<string, { keep: string | null; rejected: string[]; at: number }>;
  circleHold: Record<string, boolean>;
  /** Slices of a synced circle too large for one envelope, waiting for the rest (sync.ts importCircle), by cid. */
  syncCircles: Record<string, { versions: string[]; statements: string[]; at: number }>;
  /** Answers to `want`s in the last hour (circle-ops chargeAnswer): per asker, bytes per asker and to non-members, and what was sent. */
  wantAnswers: {
    by: Record<string, number[]>;
    bytes: Record<string, { at: number; bytes: number }[]>;
    sent: { at: number; bytes: number; pool?: "reserve" | "open" | "link" }[];
    last: Record<string, { ver: number; at: number; resent?: boolean }>;
    members?: Record<string, { at: number; bytes: number }[]>;
    pows?: { id: string; at: number }[];
    refused?: Record<string, number>;
  };
  /** Wants this device answers only if no device of ours has by `due` (circle-ops DeferredWant, re-review N6). */
  deferredWants: { from: string; fdid: string; want: { cid: string; fromVer: number }; relay: string; cap?: string; pow?: { at: number; nonce: string }; at: number; due: number }[];
  /** Envelopes dropped unapplied (failed for good, or given up after every attempt): a count only. */
  inbound: { gaveUp: number; at?: number; tooOld?: number };
  xstate: XStateIndex;
  xstateSent: Record<string, number>;
  /** Sealed messages no relay accepted yet, retried by `watch` (outbox.ts). */
  outbox: OutboxDoc;
  /**
   * Messages one session of this device sent to another session of this device, by `<target sid>|<seq>`:
   * which session sent it and whether the person did (sessions.ts). Local only, never on the wire: the
   * receiving side (this same device) reads it to frame the message and to apply the hold rule.
   */
  localSends: Record<string, LocalSend>;
  /** When a message from a bounded session of yours last reached the person's own session (`tui`): for a warning there. */
  tuiTaint: { at: number; bound: "private" | "shared" };
  /** Delivery receipts (receipts.ts, §4.3). */
  receipts: ReceiptsDoc;
  /** When each (sender, kind) of an envelope this version doesn't know was last noticed (unknown-kinds.ts). */
  unknownKinds: Record<string, number>;
  /** Relays' /.well-known/p2p-relay.json, as last fetched (relay-info.ts), by canonical URL. */
  relayInfo: Record<string, RelayInfoRec>;
  /** Project policies (projects.ts): this device's own, keyed by project id. Never synced, never read from a repository. */
  projects: ProjectsDoc;
  /** Which projects each session has worked in (projects.ts), by sid: sticky until the session ends. */
  sessionProjects: SessionProjectsDoc;
  /** When this device showed the one-time notice that new installs turn the Ix extension on (ix-local.ts). */
  ixNotice: { at: number };
};

export const sessKey = (own: string, sid: string) => `${own}|${sid}`;

/** Events older than this, or beyond the count cap, are pruned. */
export const EVENT_RETENTION_MS = 7 * 24 * 3600 * 1000;
export const EVENT_MAX = 2000;

/** What CliState needs from its backend: documents and a lock (the file backend's, or an in-memory one). */
export type CliBackend = DocBackend & { withLock<T>(fn: () => Promise<T>): Promise<T> };

/** Back-to-back state updates from one process before it leaves other processes a gap. */
export const STATE_BURST = 8;
/** The gap: longer than FileDocBackend's longest wait between lock attempts (50 ms). */
export const STATE_YIELD_MS = 60;

export class CliState {
  readonly backend: CliBackend;
  private readonly eventListeners = new Set<() => void>();
  /**
   * In-process queue in front of the cross-process lock: concurrent updates from this process
   * (a status going to several recipients at once) wait their turn here instead of polling the
   * lock file with backoff. The lock itself is still taken for every update.
   */
  private queue: Promise<unknown> = Promise.resolve();
  /** Updates queued here and not yet done. */
  private queued = 0;
  /** Updates run back to back with more waiting (the lock went straight from one to the next). */
  private streak = 0;

  private locked<R>(fn: () => Promise<R>): Promise<R> {
    this.queued++;
    const t0 = Date.now();
    const run = this.queue.then(async () => {
      const waited = Date.now() - t0;
      if (waited >= 10) debug(this.progress, `state queue: waited ${waited}ms behind ${this.queued - 1} update(s) of this process`);
      // Fair to other processes (pre-release review L3): the file lock is released after every update, but
      // a long burst from here would win it straight back each time, while a waiter in another
      // process sleeps up to 50 ms between tries. After a few in a row, leave it a gap.
      if (this.streak >= STATE_BURST) {
        this.streak = 0;
        await new Promise((r) => setTimeout(r, STATE_YIELD_MS));
      }
      try {
        return await this.backend.withLock(fn);
      } finally {
        this.queued--;
        this.streak = this.queued > 0 ? this.streak + 1 : 0;
      }
    });
    this.queue = run.catch(() => {});
    return run;
  }

  constructor(
    readonly dir: string,
    private readonly progress?: Progress,
    /** `p2p doctor`: an in-memory overlay (readonly.ts), so nothing is written to `dir`. */
    backend?: CliBackend,
    lockOpts: Partial<LockOptions> = {},
  ) {
    this.backend = backend ?? new FileDocBackend(join(dir, "cli"), lockOpts);
  }

  async get<K extends keyof Docs>(name: K): Promise<Docs[K] | undefined> {
    return (await this.backend.read(name)) as Docs[K] | undefined;
  }

  /** Read-modify-write under the cross-process lock. Return `undefined` as `next` to leave it. */
  /**
   * Runs `fn` under the state lock (the same one every update takes), for a read-modify-write of a
   * file outside the state documents: config.json (config.ts updateFileConfigField).
   */
  withLock<R>(fn: () => Promise<R>): Promise<R> {
    return step(this.progress, `waiting for p2p's state lock in ${this.dir} (is another p2p command running?)`, () => this.locked(fn), { noDebug: true });
  }

  update<K extends keyof Docs, R>(name: K, fn: (cur: Docs[K] | undefined) => { next?: Docs[K]; result: R }): Promise<R> {
    // The lock waits at most 10 s (then "is locked"); past 3 s it says why it is waiting.
    return step(this.progress, `waiting for p2p's state lock in ${this.dir} (is another p2p command running?)`, () =>
      this.locked(async () => {
        const { next, result } = fn((await this.backend.read(name)) as Docs[K] | undefined);
        if (next !== undefined) await this.backend.write(name, next);
        return result;
      }),
      { noDebug: true },
    );
  }

  /**
   * update() for a decision that must await something while holding the lock
   * (rosters: the trust store's putRoster, whose own lock is another file's
   * and never takes this one). `fn` must not call back into this state.
   */
  updateAsync<K extends keyof Docs, R>(name: K, fn: (cur: Docs[K] | undefined) => Promise<{ next?: Docs[K]; result: R }>): Promise<R> {
    return step(this.progress, `waiting for p2p's state lock in ${this.dir} (is another p2p command running?)`, () =>
      this.locked(async () => {
        const { next, result } = await fn((await this.backend.read(name)) as Docs[K] | undefined);
        if (next !== undefined) await this.backend.write(name, next);
        return result;
      }),
      { noDebug: true },
    );
  }

  /** A document outside the fixed set (one per key, e.g. a join answer per confirmer), read without the lock. */
  async getDoc<T>(name: string): Promise<T | undefined> {
    return (await this.backend.read(name)) as T | undefined;
  }

  /** update() for a document outside the fixed set: only that document is rewritten. */
  updateDoc<T, R>(name: string, fn: (cur: T | undefined) => { next?: T; result: R }): Promise<R> {
    return step(this.progress, `waiting for p2p's state lock in ${this.dir} (is another p2p command running?)`, () =>
      this.locked(async () => {
        const { next, result } = fn((await this.backend.read(name)) as T | undefined);
        if (next !== undefined) await this.backend.write(name, next);
        return result;
      }),
      { noDebug: true },
    );
  }

  async removeDoc(name: string): Promise<void> {
    await this.locked(async () => {
      if (this.backend.remove) await this.backend.remove(name);
      else await this.backend.write(name, null);
    });
  }

  async put<K extends keyof Docs>(name: K, value: Docs[K]): Promise<void> {
    await this.update(name, () => ({ next: value, result: undefined }));
  }

  /** The next envelope seq for (own, sid) on this device. */
  async nextSeq(own: string, sid: string): Promise<number> {
    return (await this.nextSeqs(own, sid, 1))[0];
  }

  /**
   * `count` consecutive envelope seqs for (own, sid) on this device, in one write.
   *
   * A missing counter starts at the clock in ms (as on main, so it lands above every window a
   * receiver already holds for the session, and a lost or never-written seq.json heals); after
   * that it counts up by one (review M1, third round). Jumping to the clock on every send put two
   * sends a second apart ~1000 seqs apart, so an earlier envelope applied after a later one (a
   * crash, a transient failure, another relay's late copy) was dropped as seq-too-old.
   *
   * Residual: a counter restored from a backup taken after the session's first send is behind
   * seqs it already spent. Until it passes them, receivers drop its envelopes: as replays while
   * within their 512-seq window, and as late envelopes (counted in `p2p doctor`) below it.
   *
   * One counter serves every recipient device of a send (a status fan-out takes one seq per
   * device), so a receiver sees gaps of up to the number of other copies: its 512-seq window
   * tolerates about 512 / (devices per send) sends of reordering, ~36 statuses at 14 copies.
   */
  nextSeqs(own: string, sid: string, count: number): Promise<number[]> {
    return this.update("seq", (cur = {}) => {
      const k = sessKey(own, sid);
      const last = cur[k];
      const first = last === undefined ? Date.now() : last + 1;
      const out = Array.from({ length: count }, (_, i) => first + i);
      return { next: { ...cur, [k]: first + count - 1 }, result: out };
    });
  }

  /**
   * Calls `fn` whenever this process has appended events, so `watch` prints them at once instead
   * of at its next poll. Returns the unsubscribe.
   */
  onEventsAdded(fn: () => void): () => void {
    this.eventListeners.add(fn);
    return () => this.eventListeners.delete(fn);
  }

  /** Appends events; returns them with their log positions. Duplicate ids are dropped. */
  async addEvents(events: Omit<EventRec, "n">[], now = Date.now()): Promise<EventRec[]> {
    if (events.length === 0) return [];
    const added = await this.appendEvents(events, now);
    if (added.length > 0) for (const fn of [...this.eventListeners]) fn();
    return added;
  }

  private appendEvents(events: Omit<EventRec, "n">[], now: number): Promise<EventRec[]> {
    return this.update("events", (cur = { next: 1, items: [] }) => {
      const seen = new Set(cur.items.map((e) => e.id));
      const added: EventRec[] = [];
      let next = cur.next;
      for (const e of events) {
        if (seen.has(e.id)) continue;
        seen.add(e.id);
        added.push({ ...e, n: next++ });
      }
      let items = [...cur.items, ...added].filter((e) => now - e.at <= EVENT_RETENTION_MS);
      if (items.length > EVENT_MAX) items = items.slice(items.length - EVENT_MAX);
      return { next: { next, items }, result: added };
    });
  }
}
