// Copyright 2026 Ix Infrastructure Inc.
//
// The v3 trust store (docs/protocol.md §6): identity documents per user (every
// branch), friendships, unfriends, blocks, circles (chains, membership
// statements, proposals, applied nonces, joined-by-me), rosters, caps issued
// and held, replay windows (kept at least 7d10m after their last admit),
// petnames, outgoing invites, the device-certificate cache and the owner's
// publish log. Everything stored was verified before it was written; the
// store does no cryptography.
//
// Built on the same DocBackend as the v2 store; FileTrustStoreV3 (./node.ts)
// adds v2's lock and atomic-write rules (C7, C14). This module is pure.

import { MemoryDocBackend, type DocBackend } from "../docbackend.js";
import { fail } from "../errors.js";
import {
  checkReplay,
  mergeReplay,
  recordReplay,
  REPLAY_MAX_AGE_MS_V3,
  sessionKey,
  type ReplayFields,
  type ReplayRecord,
  type ReplayVerdict,
} from "../replay.js";
import type { AppliedNonces, MembershipFact, OpenJoinLimiter, StoredCircleChain } from "./circles.js";
import type { PublishLog, StoredIdentityChain } from "./identitydoc.js";
import type { RosterPutResultV3 } from "./roster.js";

export interface StoredFriendshipV3 {
  inviter: string;
  invitee: string;
  inv: string;
  aud: string;
  /** The accept's iat. */
  iat: number;
  /** The invite's iat. */
  inviteIat: number;
  /** Signer devices, so a later revocation of either ends the friendship. */
  inviteDid: string;
  acceptDid: string;
  proof: { invite: string; accept: string };
}

export interface StoredUnfriendV3 {
  iss: string;
  peer: string;
  inv: string;
  iat: number;
  jws: string;
}

export interface StoredBlock {
  userId: string;
  /** When blocked (seconds). */
  at: number;
}

export interface StoredCircleV3 {
  cid: string;
  chain: StoredCircleChain;
  /** Current membership statement per member. */
  statements: Record<string, MembershipFact>;
  /** The viewer joined on this device: a local, explicit action (review C1). */
  joinedByMe: boolean;
  /** Highest `n` this user's devices have used for this circle (synced, §3.3). */
  myN?: number;
  /** Owner only: applied proposal nonces with their iat (pruned after 30 days). */
  applied?: AppliedNonces;
  /** Owner only: proposals waiting to be applied or approved. */
  proposals?: string[];
  /** Owner only: automatic accepts under `policy: "open"`. */
  openJoins?: OpenJoinLimiter;
  /**
   * Members the owner dropped from `members` while their current statement
   * was a join (not a voluntary leave). An open circle holds any later join
   * from them for the owner's approval, whatever they sign in between (pre-release review M3). Cleared when a version re-adds them.
   */
  removed?: string[];
  /** When this client last saw a member removed (seconds): open circles re-key join caps after it (review M4). */
  removalSeenAt?: number;
}

export interface StoredRosterV3 {
  iss: string;
  sid: string;
  ver: number;
  jws: string;
}

/** A cap this user issued (to revoke on unfriend, block or removal) or holds (to send with). */
export interface StoredCapV3 {
  capid: string;
  iss: string;
  sub: string;
  relays: string[];
  kinds: string[];
  exp: number;
  jws: string;
}

export interface StoredDeviceCertV3 {
  userId: string;
  did: string;
  exp: number;
  jws: string;
}

export interface StoredOutgoingInviteV3 {
  inv: string;
  aud: string;
  exp: number;
  jws: string;
}

/** Replay state per sender device, plus when each window last admitted (ms). */
export interface StoredReplayV3 {
  record: ReplayRecord;
  lastAt: Record<string, number>;
  /**
   * Envelopes being applied right now (claimReplay), by replayClaimKey: recorded in `record`
   * only once their effects are written (commitReplay), so a crash in between doesn't turn the
   * relay's redelivery into a "replayed" drop.
   */
  claims?: Record<string, ReplayClaim>;
  /**
   * Attempts at envelopes not yet recorded, by replayClaimKey (review M-A): every claim counts one.
   * Past REPLAY_MAX_ATTEMPTS the next claim records the envelope as given up instead.
   */
  tries?: Record<string, { n: number; at: number; a?: number }>;
}

/** Who is applying an envelope: a token unique to that one attempt, and the process holding it. */
export interface ReplayClaimant {
  token: string;
  host: string;
  pid: number;
  /** When the holder process started (ms), so a reused pid isn't taken for it (review L-C). */
  started?: number;
}

/** Attempts at one envelope before it is recorded as given up (a poison envelope: review M-A). */
export const REPLAY_MAX_ATTEMPTS = 3;
/**
 * Attempts given back uncounted because their process exited with them still running
 * (releaseReplay { uncount }) have a cap of their own: an envelope whose handling always outlives
 * a short command (a circle want aimed at tarpit relays) is given up after this many, instead of
 * coming back to every command forever (pre-release re-review F1).
 */
export const REPLAY_MAX_ABANDONS = 10;

export interface ReplayClaim extends ReplayClaimant {
  /** When it was claimed (ms). */
  at: number;
}

/**
 * A claim whose holder can't be checked (another host sharing the home) stands this long; past it,
 * a redelivery takes over. A holder that can be checked (this machine) is judged by liveness only,
 * never by age (pre-release re-review M-1): a live holder keeps its claim however long it takes.
 */
export const REPLAY_CLAIM_TTL_MS = 120_000;
/** Claims are forgotten after this long whatever their holder: the envelope is past the window by then. */
const CLAIM_GC_MS = REPLAY_MAX_AGE_MS_V3;

/**
 * Whether a claim's holder is still at work: true or false when the caller can tell (a process on
 * this machine), undefined when it can't (another host): then REPLAY_CLAIM_TTL_MS decides.
 */
export type ClaimLiveness = (c: ReplayClaim) => boolean | undefined;

/** One envelope's claim key: its session, seq and nonce. */
export const replayClaimKey = (p: ReplayFields) => `${sessionKey(p.own, p.sid)}|${p.seq}|${p.n}`;

const liveTries = (tries: StoredReplayV3["tries"], nowMs: number): NonNullable<StoredReplayV3["tries"]> =>
  Object.fromEntries(Object.entries(tries ?? {}).filter(([, t]) => Math.abs(nowMs - t.at) < CLAIM_GC_MS));

/** Claims still standing: by `isAlive` where it can tell, else by age (TTL), and never past CLAIM_GC_MS. */
const standingClaims = (claims: Record<string, ReplayClaim> | undefined, nowMs: number, isAlive?: ClaimLiveness): Record<string, ReplayClaim> =>
  Object.fromEntries(
    Object.entries(claims ?? {}).filter(([, c]) => {
      const age = Math.abs(nowMs - c.at);
      if (age >= CLAIM_GC_MS) return false;
      if (!isAlive) return true;
      return isAlive(c) ?? age < REPLAY_CLAIM_TTL_MS;
    }),
  );

/**
 * A stranger's bundled identity document (pre-release re-review N1). Kept apart from
 * the identity store: no resolver, view or authorisation path ever reads it.
 * It only tells refreshIdentity where to fetch the real head from, so only
 * the relays are kept, never the document itself (review N9).
 */
export interface StoredProvisionalDoc {
  userId: string;
  relays: string[];
  /** When it was cached (seconds); entries expire after PROVISIONAL_TTL_SEC. */
  at: number;
}

/** Bound on the provisional cache (oldest-used evicted first). */
export const PROVISIONAL_MAX = 256;
/** How long a provisional document is kept. */
export const PROVISIONAL_TTL_SEC = 24 * 3600;

type Docs = {
  identities: Record<string, StoredIdentityChain>;
  friendships: StoredFriendshipV3[];
  unfriends: StoredUnfriendV3[];
  blocks: Record<string, StoredBlock>;
  circles: Record<string, StoredCircleV3>;
  rosters: Record<string, StoredRosterV3>;
  capsIssued: Record<string, StoredCapV3>;
  capsHeld: Record<string, StoredCapV3>;
  replay: Record<string, StoredReplayV3>;
  petnames: Record<string, string>;
  outgoing: Record<string, StoredOutgoingInviteV3>;
  devices: Record<string, StoredDeviceCertV3>;
  publishLog: PublishLog;
  provisional: Record<string, StoredProvisionalDoc>;
  refreshed: Record<string, number>;
};

const rosterKey = (iss: string, sid: string) => JSON.stringify([iss, sid]);

/** markRefreshed: a mark this recent (seconds) is left as it is. */
export const REFRESH_MARK_SLACK_SEC = 10;

/** Store document names carry a `v3-` prefix so a v3 store can share a directory with a v2 one. */
const docName = (k: string) => `v3-${k}`;

export class TrustStoreV3 {
  private chain: Promise<unknown> = Promise.resolve();

  constructor(private readonly backend: DocBackend) {}

  private async get<K extends keyof Docs>(name: K): Promise<Docs[K] | undefined> {
    return (await this.backend.read(docName(name))) as Docs[K] | undefined;
  }

  /** Read-modify-write under the in-process queue and the backend's cross-process lock. */
  private mutate<K extends keyof Docs, R>(name: K, fn: (cur: Docs[K] | undefined) => { next?: Docs[K]; result: R }): Promise<R> {
    const rmw = async () => {
      const { next, result } = fn(await this.get(name));
      if (next !== undefined) await this.backend.write(docName(name), next);
      return result;
    };
    const run = this.chain.then(() => (this.backend.withLock ? this.backend.withLock(rmw) : rmw()));
    this.chain = run.catch(() => {});
    return run;
  }

  // --- identity documents ----------------------------------------------------

  async getIdentity(userId: string): Promise<StoredIdentityChain | undefined> {
    return (await this.get("identities"))?.[userId];
  }

  async putIdentity(c: StoredIdentityChain): Promise<void> {
    await this.updateIdentity(c.iss, () => ({ next: c, result: undefined }));
  }

  /**
   * Atomic read-modify-write of one identity's chain: the read, the change
   * and the write happen under one lock, so concurrent adds can't lose a
   * version (pre-release review M2). Return no `next` to leave it unchanged.
   */
  updateIdentity<R>(userId: string, fn: (cur: StoredIdentityChain | undefined) => { next?: StoredIdentityChain; result: R }): Promise<R> {
    return this.mutate("identities", (cur = {}) => {
      const { next, result } = fn(cur[userId]);
      return next === undefined ? { result } : { next: { ...cur, [userId]: next }, result };
    });
  }

  async listIdentities(): Promise<string[]> {
    return Object.keys((await this.get("identities")) ?? {});
  }

  // --- friendships and unfriends ---------------------------------------------

  async listFriendships(): Promise<StoredFriendshipV3[]> {
    return (await this.get("friendships")) ?? [];
  }

  /** Idempotent. Throws invite-already-bound if `inv` is bound to another pair. */
  async addFriendship(f: StoredFriendshipV3): Promise<void> {
    await this.mutate("friendships", (cur = []) => {
      const existing = cur.find((x) => x.inv === f.inv);
      if (existing) {
        if (existing.inviter !== f.inviter || existing.invitee !== f.invitee) {
          fail("invite-already-bound", `invite already accepted by ${existing.invitee}`);
        }
        return { result: undefined };
      }
      return { next: [...cur, f], result: undefined };
    });
  }

  async listUnfriends(): Promise<StoredUnfriendV3[]> {
    return (await this.get("unfriends")) ?? [];
  }

  async addUnfriend(u: StoredUnfriendV3): Promise<void> {
    await this.mutate("unfriends", (cur = []) => (cur.some((x) => x.jws === u.jws) ? { result: undefined } : { next: [...cur, u], result: undefined }));
  }

  // --- blocks (§3.2) ------------------------------------------------------------

  async isBlocked(userId: string): Promise<boolean> {
    return (await this.get("blocks"))?.[userId] !== undefined;
  }

  async listBlocks(): Promise<StoredBlock[]> {
    return Object.values((await this.get("blocks")) ?? {});
  }

  async addBlock(b: StoredBlock): Promise<void> {
    await this.mutate("blocks", (cur = {}) => ({ next: { ...cur, [b.userId]: b }, result: undefined }));
  }

  async removeBlock(userId: string): Promise<void> {
    await this.mutate("blocks", (cur = {}) => {
      if (!cur[userId]) return { result: undefined };
      const { [userId]: _gone, ...rest } = cur;
      return { next: rest, result: undefined };
    });
  }

  // --- circles ----------------------------------------------------------------------

  async getCircle(cid: string): Promise<StoredCircleV3 | undefined> {
    return (await this.get("circles"))?.[cid];
  }

  async listCircles(): Promise<StoredCircleV3[]> {
    return Object.values((await this.get("circles")) ?? {});
  }

  /** Atomic update of one circle's record (`fn` gets undefined for an unknown cid; return undefined to leave it). */
  updateCircle<R>(cid: string, fn: (cur: StoredCircleV3 | undefined) => { next?: StoredCircleV3; result: R }): Promise<R> {
    return this.mutate("circles", (cur = {}) => {
      const { next, result } = fn(cur[cid]);
      return next === undefined ? { result } : { next: { ...cur, [cid]: next }, result };
    });
  }

  async putCircle(c: StoredCircleV3): Promise<void> {
    await this.updateCircle(c.cid, () => ({ next: c, result: undefined }));
  }

  async deleteCircle(cid: string): Promise<void> {
    await this.mutate("circles", (cur = {}) => {
      if (!cur[cid]) return { result: undefined };
      const { [cid]: _gone, ...rest } = cur;
      return { next: rest, result: undefined };
    });
  }

  // --- rosters ------------------------------------------------------------------------

  async getRoster(iss: string, sid: string): Promise<StoredRosterV3 | undefined> {
    return (await this.get("rosters"))?.[rosterKey(iss, sid)];
  }

  /** Keeps the highest ver per (iss, sid); equal ver with other bytes is a conflict (v2 C10). */
  putRoster(r: StoredRosterV3): Promise<RosterPutResultV3> {
    return this.mutate("rosters", (cur = {}) => {
      const k = rosterKey(r.iss, r.sid);
      const old = cur[k];
      if (old) {
        if (r.ver < old.ver) return { result: "stale" as const };
        if (r.ver === old.ver) return { result: old.jws === r.jws ? ("same" as const) : ("conflict" as const) };
      }
      return { next: { ...cur, [k]: r }, result: "stored" as const };
    });
  }

  // --- capabilities (§5.3) ---------------------------------------------------------

  async listCapsIssued(): Promise<StoredCapV3[]> {
    return Object.values((await this.get("capsIssued")) ?? {});
  }

  async addCapIssued(c: StoredCapV3): Promise<void> {
    await this.mutate("capsIssued", (cur = {}) => ({ next: { ...cur, [c.capid]: c }, result: undefined }));
  }

  /** Removes and returns the issued caps matching `pred` (the caller sends `revoke` for each to every relay it names). */
  takeCapsIssued(pred: (c: StoredCapV3) => boolean): Promise<StoredCapV3[]> {
    return this.mutate("capsIssued", (cur = {}) => {
      const taken = Object.values(cur).filter(pred);
      if (taken.length === 0) return { result: [] };
      const next = { ...cur };
      for (const c of taken) delete next[c.capid];
      return { next, result: taken };
    });
  }

  async listCapsHeld(iss?: string): Promise<StoredCapV3[]> {
    const all = Object.values((await this.get("capsHeld")) ?? {});
    return iss === undefined ? all : all.filter((c) => c.iss === iss);
  }

  async addCapHeld(c: StoredCapV3): Promise<void> {
    await this.mutate("capsHeld", (cur = {}) => ({ next: { ...cur, [c.capid]: c }, result: undefined }));
  }

  async removeCapsHeld(pred: (c: StoredCapV3) => boolean): Promise<void> {
    await this.mutate("capsHeld", (cur = {}) => {
      const gone = Object.values(cur).filter(pred);
      if (gone.length === 0) return { result: undefined };
      const next = { ...cur };
      for (const c of gone) delete next[c.capid];
      return { next, result: undefined };
    });
  }

  // --- replay (§4.4) ------------------------------------------------------------------

  async getReplay(fdid: string): Promise<ReplayRecord | undefined> {
    return (await this.get("replay"))?.[fdid]?.record;
  }

  /** Atomic check-and-record with the v3 window (ts within [now - 7d10m, now + 10m]). */
  admitReplay(fdid: string, p: ReplayFields, nowMs: number): Promise<ReplayVerdict> {
    return this.mutate("replay", (cur = {}) => {
      const old = cur[fdid];
      const verdict = checkReplay(p, old?.record, nowMs, REPLAY_MAX_AGE_MS_V3);
      if (verdict) return { result: verdict };
      const k = sessionKey(p.own, p.sid);
      const entry: StoredReplayV3 = { record: recordReplay(p, old?.record), lastAt: { ...(old?.lastAt ?? {}), [k]: nowMs }, ...(old?.claims ? { claims: old.claims } : {}), ...(old?.tries ? { tries: old.tries } : {}) };
      return { next: { ...cur, [fdid]: entry }, result: undefined };
    });
  }

  /**
   * The first half of admitReplay, for a receiver that records an envelope only once it has
   * applied it: the replay check, then a claim on this one envelope, atomically. A replayed
   * envelope gets its verdict; one another attempt is still applying (its claim fresh, and its
   * holder alive by `isAlive`) is `busy`, and must not be acked. A stale or dead claim is taken
   * over: that attempt never finished, so this one applies the envelope.
   */
  claimReplay(
    fdid: string,
    p: ReplayFields,
    nowMs: number,
    me: ReplayClaimant,
    isAlive: ClaimLiveness = () => undefined,
    maxAttempts: number = REPLAY_MAX_ATTEMPTS,
    maxAbandons: number = REPLAY_MAX_ABANDONS,
  ): Promise<{ verdict?: NonNullable<ReplayVerdict>; busy?: true; attempt?: number }> {
    return this.mutate<"replay", { verdict?: NonNullable<ReplayVerdict>; busy?: true; attempt?: number }>("replay", (cur = {}) => {
      const old = cur[fdid];
      const verdict = checkReplay(p, old?.record, nowMs, REPLAY_MAX_AGE_MS_V3);
      if (verdict) return { result: { verdict } };
      const k = replayClaimKey(p);
      const claims = standingClaims(old?.claims, nowMs, isAlive);
      const held = claims[k];
      if (held && held.token !== me.token) return { result: { busy: true as const } };
      const tries = liveTries(old?.tries, nowMs);
      const attempt = (tries[k]?.n ?? 0) + 1;
      const abandons = tries[k]?.a ?? 0;
      if (attempt > maxAttempts || abandons >= maxAbandons) {
        // A poison envelope: every attempt failed or died. Recorded as handled (so it is acked and
        // stops coming back), never applied.
        delete tries[k];
        delete claims[k];
        const sk = sessionKey(p.own, p.sid);
        const entry: StoredReplayV3 = {
          record: recordReplay(p, old?.record),
          lastAt: { ...(old?.lastAt ?? {}), [sk]: nowMs },
          ...(Object.keys(claims).length > 0 ? { claims } : {}),
          ...(Object.keys(tries).length > 0 ? { tries } : {}),
        };
        const why = attempt > maxAttempts ? `${maxAttempts} attempts` : `${abandons} attempts cut off by their process exiting`;
        return { next: { ...cur, [fdid]: entry }, result: { verdict: { reason: "gave-up" as const, message: `gave up on seq ${p.seq} from ${fdid} after ${why}` } } };
      }
      claims[k] = { ...me, at: nowMs };
      tries[k] = { n: attempt, at: nowMs, ...(abandons > 0 ? { a: abandons } : {}) };
      const entry: StoredReplayV3 = { record: old?.record ?? { nonces: [], windows: {} }, lastAt: old?.lastAt ?? {}, claims, tries };
      return { next: { ...cur, [fdid]: entry }, result: { attempt } };
    });
  }

  /**
   * Whether another attempt still at work holds this envelope's claim, from a read of the stored
   * replay state without the lock. Only ever a reason to wait (`replay-in-progress`: not acked,
   * not applied): claimReplay alone takes claims, under the lock. A process racing a watch of the
   * same device for the same envelopes no longer queues for the store's cross-process lock just
   * to learn that the watch has it (a short command's tail latency under load).
   */
  async claimHeldElsewhere(fdid: string, p: ReplayFields, nowMs: number, token: string, isAlive: ClaimLiveness = () => undefined): Promise<boolean> {
    const k = replayClaimKey(p);
    const held = (await this.get("replay"))?.[fdid]?.claims?.[k];
    if (!held || held.token === token) return false;
    return standingClaims({ [k]: held }, nowMs, isAlive)[k] !== undefined;
  }

  /**
   * The second half: records the envelope (as admitReplay would have) and drops the claim.
   * Returns the verdict if someone else recorded it meanwhile (a claim taken over as stale).
   */
  commitReplay(fdid: string, p: ReplayFields, nowMs: number, token: string): Promise<ReplayVerdict> {
    return this.mutate("replay", (cur = {}) => {
      const old = cur[fdid];
      const k = replayClaimKey(p);
      const claims = standingClaims(old?.claims, nowMs);
      if (claims[k]?.token === token) delete claims[k];
      const tries = liveTries(old?.tries, nowMs);
      delete tries[k];
      const keepClaims = { ...(Object.keys(claims).length > 0 ? { claims } : {}), ...(Object.keys(tries).length > 0 ? { tries } : {}) };
      const verdict = checkReplay(p, old?.record, nowMs, REPLAY_MAX_AGE_MS_V3);
      if (verdict) {
        return old ? { next: { ...cur, [fdid]: { record: old.record, lastAt: old.lastAt, ...keepClaims } }, result: verdict } : { result: verdict };
      }
      const sk = sessionKey(p.own, p.sid);
      const entry: StoredReplayV3 = { record: recordReplay(p, old?.record), lastAt: { ...(old?.lastAt ?? {}), [sk]: nowMs }, ...keepClaims };
      return { next: { ...cur, [fdid]: entry }, result: undefined };
    });
  }

  /**
   * Gives a claim up without recording the envelope (the attempt failed for a reason that says
   * nothing about the envelope: a lock timeout, I/O, the network): its redelivery is applied.
   *
   * `uncount`: the attempt didn't fail at all, it was abandoned (the process exits with it still
   * running), so it doesn't count toward REPLAY_MAX_ATTEMPTS, only toward REPLAY_MAX_ABANDONS. Before, a short command cut
   * off three times gave a legitimate envelope up unapplied (pre-release review M-A).
   */
  releaseReplay(fdid: string, p: ReplayFields, token: string, opts: { uncount?: boolean } = {}): Promise<void> {
    return this.mutate("replay", (cur = {}) => {
      const old = cur[fdid];
      const k = replayClaimKey(p);
      if (!old?.claims || old.claims[k]?.token !== token) return { result: undefined };
      const { [k]: _gone, ...claims } = old.claims;
      let tries = old.tries;
      if (opts.uncount && tries?.[k]) {
        const { [k]: t, ...rest } = tries;
        // Not a failed attempt, but counted against REPLAY_MAX_ABANDONS.
        tries = { ...rest, [k]: { n: t.n - 1, at: t.at, a: (t.a ?? 0) + 1 } };
      }
      const entry: StoredReplayV3 = { record: old.record, lastAt: old.lastAt, ...(Object.keys(claims).length > 0 ? { claims } : {}), ...(tries && Object.keys(tries).length > 0 ? { tries } : {}) };
      return { next: { ...cur, [fdid]: entry }, result: undefined };
    });
  }

  /** Merges replay state synced from another process or device: never overwrites. */
  async mergeReplay(fdid: string, r: ReplayRecord, lastAt: Record<string, number>): Promise<void> {
    await this.mutate("replay", (cur = {}) => {
      const old = cur[fdid];
      const merged: Record<string, number> = { ...(old?.lastAt ?? {}) };
      for (const [k, t] of Object.entries(lastAt)) merged[k] = Math.max(merged[k] ?? 0, t);
      return { next: { ...cur, [fdid]: { record: mergeReplay(old?.record, r), lastAt: merged, ...(old?.claims ? { claims: old.claims } : {}), ...(old?.tries ? { tries: old.tries } : {}) } }, result: undefined };
    });
  }

  /**
   * Drops replay windows whose last admit is more than `retentionMs` ago
   * (never less than 7d10m, §4.4: windows are kept at least that long, even
   * after the session ends). Returns how many windows were dropped.
   */
  pruneReplay(nowMs: number, retentionMs: number = REPLAY_MAX_AGE_MS_V3): Promise<number> {
    const keep = Math.max(retentionMs, REPLAY_MAX_AGE_MS_V3);
    return this.mutate("replay", (cur = {}) => {
      let dropped = 0;
      const next: Record<string, StoredReplayV3> = {};
      for (const [fdid, e] of Object.entries(cur)) {
        const windows: ReplayRecord["windows"] = {};
        const lastAt: Record<string, number> = {};
        for (const [k, w] of Object.entries(e.record.windows)) {
          const t = e.lastAt[k] ?? nowMs; // unknown age: keep (and start the clock)
          if (nowMs - t > keep) dropped++;
          else {
            windows[k] = w;
            lastAt[k] = t;
          }
        }
        const claims = standingClaims(e.claims, nowMs);
        const hasClaims = Object.keys(claims).length > 0;
        const tries = liveTries(e.tries, nowMs);
        const hasTries = Object.keys(tries).length > 0;
        if (Object.keys(windows).length > 0 || hasClaims || hasTries) next[fdid] = { record: { nonces: e.record.nonces, windows }, lastAt, ...(hasClaims ? { claims } : {}), ...(hasTries ? { tries } : {}) };
      }
      return dropped === 0 ? { result: 0 } : { next, result: dropped };
    });
  }

  // --- petnames (§2.1) ----------------------------------------------------------------

  async getPetname(userId: string): Promise<string | undefined> {
    return (await this.get("petnames"))?.[userId];
  }

  async listPetnames(): Promise<Record<string, string>> {
    return (await this.get("petnames")) ?? {};
  }

  /** Sets (or, with undefined/empty, clears) the local petname for a userId. */
  async setPetname(userId: string, petname: string | undefined): Promise<void> {
    await this.mutate("petnames", (cur = {}) => {
      const next = { ...cur };
      const p = petname?.trim();
      if (p) {
        if ([...p].length > 64) fail("malformed", "petname is longer than 64 characters");
        next[userId] = p;
      } else delete next[userId];
      return { next, result: undefined };
    });
  }

  // --- outgoing invites, device certificates, publish log ------------------------------

  async addOutgoingInvite(i: StoredOutgoingInviteV3): Promise<void> {
    await this.mutate("outgoing", (cur = {}) => ({ next: { ...cur, [i.inv]: i }, result: undefined }));
  }

  async getOutgoingInvite(inv: string): Promise<StoredOutgoingInviteV3 | undefined> {
    return (await this.get("outgoing"))?.[inv];
  }

  async getDeviceCert(did: string): Promise<StoredDeviceCertV3 | undefined> {
    return (await this.get("devices"))?.[did];
  }

  /** Keeps the longer-lived certificate per did (renewals keep did, spk and kpk). */
  async putDeviceCert(c: StoredDeviceCertV3): Promise<void> {
    // The same certificate again (every envelope from that device): known without the lock.
    const held = (await this.get("devices"))?.[c.did];
    if (held && held.userId === c.userId && held.jws === c.jws && held.exp === c.exp) return;
    await this.mutate("devices", (cur = {}) => {
      const old = cur[c.did];
      if (old && (old.userId !== c.userId || (old.exp >= c.exp && old.jws !== c.jws))) return { result: undefined };
      // The same certificate again (every envelope from that device): nothing to write.
      if (old && old.jws === c.jws && old.exp === c.exp) return { result: undefined };
      return { next: { ...cur, [c.did]: c }, result: undefined };
    });
  }

  // --- refresh bookkeeping (review T1) ------------------------------------------------

  /** Records a COMPLETE refresh of `userId` at `at` (seconds). */
  async markRefreshed(userId: string, at: number): Promise<void> {
    // Already recorded at most REFRESH_MARK_SLACK_SEC earlier (another process of this home just
    // refreshed it): no write. Only ever leaves the mark a little older than it could be, so the
    // next refresh comes no later than it would have.
    const held = (await this.get("refreshed"))?.[userId];
    if (held !== undefined && held >= at - REFRESH_MARK_SLACK_SEC) return;
    await this.mutate("refreshed", (cur = {}) => ({ next: { ...cur, [userId]: Math.max(cur[userId] ?? 0, at) }, result: undefined }));
  }

  async getRefreshed(userId: string): Promise<number | undefined> {
    return (await this.get("refreshed"))?.[userId];
  }

  // --- provisional bundled documents (review N1) ----------------------------------

  /** Caches a stranger's bundled document (bounded LRU with a TTL). Never part of the identity store. */
  async putProvisional(d: StoredProvisionalDoc): Promise<void> {
    await this.mutate("provisional", (cur = {}) => {
      const next: Record<string, StoredProvisionalDoc> = {};
      // Re-insert to the end (most recent); drop expired entries on the way.
      for (const [k, v] of Object.entries(cur)) if (k !== d.userId && d.at - v.at < PROVISIONAL_TTL_SEC) next[k] = v;
      next[d.userId] = d;
      const keys = Object.keys(next);
      for (const k of keys.slice(0, Math.max(0, keys.length - PROVISIONAL_MAX))) delete next[k];
      return { next, result: undefined };
    });
  }

  /** The cached bundled document for `userId`, if not expired at `now`. */
  async getProvisional(userId: string, now: number): Promise<StoredProvisionalDoc | undefined> {
    const d = (await this.get("provisional"))?.[userId];
    return d && now - d.at < PROVISIONAL_TTL_SEC ? d : undefined;
  }

  async deleteProvisional(userId: string): Promise<void> {
    // Nothing to delete (the usual case): no lock. One added meanwhile is a race either way.
    if (!(await this.get("provisional"))?.[userId]) return;
    await this.mutate("provisional", (cur = {}) => {
      if (!cur[userId]) return { result: undefined };
      const { [userId]: _gone, ...rest } = cur;
      return { next: rest, result: undefined };
    });
  }

  async countProvisional(): Promise<number> {
    return Object.keys((await this.get("provisional")) ?? {}).length;
  }

  async getPublishLog(): Promise<PublishLog> {
    return (await this.get("publishLog")) ?? { published: [], addedDevices: [], addedRelays: [], addedProofs: [] };
  }

  /** Records a version this user's device published, and what it added (synced across the owner's devices). */
  async recordPublished(entry: { hash: string; devices?: string[]; relays?: string[]; proofs?: string[] }): Promise<void> {
    await this.mutate("publishLog", (cur = { published: [], addedDevices: [], addedRelays: [], addedProofs: [] }) => {
      const u = (a: readonly string[], b: readonly string[] = []) => [...new Set([...a, ...b])];
      return {
        next: {
          published: u(cur.published, [entry.hash]),
          addedDevices: u(cur.addedDevices, entry.devices),
          addedRelays: u(cur.addedRelays, entry.relays),
          addedProofs: u(cur.addedProofs, entry.proofs),
        },
        result: undefined,
      };
    });
  }
}

export class MemoryTrustStoreV3 extends TrustStoreV3 {
  constructor() {
    super(new MemoryDocBackend());
  }
}
