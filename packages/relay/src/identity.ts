// Copyright 2026 Ix Infrastructure Inc.
//
// Identity documents on the relay (docs/protocol.md §5.6, chain rules §2.5).
//
// - Scope: only documents whose `relays` list this relay are stored.
// - Leaving: a document that drops this relay and chains from the current
//   head (or merges all current tips) is the owner leaving. The relay deletes
//   the documents and stops serving them, but keeps a TOMBSTONE: the last
//   allowlist and head version. Rule 6 keeps applying to that userId, so
//   deleting documents never re-opens auth to revoked devices. Any other
//   document that doesn't list this relay is refused.
// - Publish: accepted when its `prev` (and, for a merge, its `merge`) is a
//   version the relay holds, or when the relay holds no version of that
//   userId. Every branch is kept, up to `maxTips` tips.
// - Roots the relay can't vouch for (L5, N4): with nothing held, any version
//   is accepted as the root, including an OLD version replayed by someone who
//   has a copy (for example a since-revoked device). Such a history is
//   "unanchored" (no ver-1 root held). A later document from the same
//   identity key with a higher `ver` than the head, which doesn't chain,
//   replaces an unanchored history; an anchored one is only ever extended,
//   and its owner back-fills gaps. Re-entry after a tombstone also needs a
//   higher `ver` than the tombstoned head. In both cases the new root's
//   allowlist is CAPPED by (intersected with) the previous allowlist until a
//   document chains onto the new root, so a replay can't re-admit a device.
// - Head: the highest `ver` held (a tie goes to the higher jwsHash, so every
//   relay picks the same one). Tips: versions no held version names as
//   `prev` or `merge`.
// - Retention: non-tip versions for 90 days and at most `maxVersions` per
//   userId (oldest non-tips go first). A userId whose head has been expired
//   for `expiredRetentionSec` is tombstoned; tombstones are deleted after
//   `tombstoneRetentionSec` (longer than any device certificate can outlive
//   its revocation).
// - State-based acceptance (review R3): a version is checked against what the
//   relay holds now: chain and merge shape, `by` a key holder, a merge's
//   devices within both parents', and, over a restricted connection, being on
//   top of the tips. No-return (a revoked did never re-listed) is NOT checked
//   here: only identity-key holders publish versions, so a revoked ordinary
//   device can't re-list itself, and clients enforce no-return from their own
//   chains (core revokedAlong). What the relay must know is which dids were
//   listed and aren't now, to refuse them even a restricted connection: the
//   dids of every held version, plus those of history it discarded
//   (tombstones, replaced roots) for 91 days, longer than any certificate.
// - Request paths (auth, send, GETs) read only the per-userId index and single
//   documents by hash, never a full scan. Every publish's prune, insert and
//   reindex is one store transaction.

import type { IdentityDoc, RelayCrypto } from "./crypto.js";
import { referencedHashes, type IdentityIndex, type Store, type StoredIdentityDoc } from "./store.js";

export type PublishResult =
  | { ok: true; duplicate: boolean; left?: boolean }
  | { ok: false; code: "bad-identity" | "identity-gap" | "forbidden" | "too-large" | "full" };

export interface IdentityLimits {
  maxTips: number;
  maxVersions: number;
  /** Seconds a head may be expired before the userId is tombstoned. */
  expiredRetentionSec: number;
  /** Seconds a tombstone is kept. */
  tombstoneRetentionSec: number;
}

const MAX_DOC_BYTES = 16 * 1024;
const SKEW_SEC = 300;

function higher(a: { ver: number; hash: string }, b: { ver: number; hash: string }): boolean {
  return a.ver > b.ver || (a.ver === b.ver && a.hash > b.hash);
}

/**
 * Builds the index of a userId from its full set of held documents. With a
 * `cap`, the allowlist is intersected with it.
 */
export function buildIndex(iss: string, docs: readonly StoredIdentityDoc[], cap: string[] | null = null): IdentityIndex | undefined {
  if (docs.length === 0) return undefined;
  const refs = referencedHashes(docs);
  const tips = docs.filter((d) => !refs.has(d.hash)).sort((a, b) => (higher(a, b) ? -1 : 1));
  let head = docs[0];
  for (const d of docs) if (higher(d, head)) head = d;
  let allowed = new Set(tips[0].devices);
  for (const t of tips.slice(1)) allowed = new Set(t.devices.filter((x) => allowed.has(x)));
  if (cap) allowed = new Set([...allowed].filter((x) => cap.includes(x)));
  return {
    iss,
    head: head.hash,
    headVer: head.ver,
    headExp: head.exp,
    tips: tips.map((t) => t.hash),
    allowed: [...allowed],
    cap,
    leftAt: null,
  };
}

export class IdentityService {
  constructor(
    private readonly store: Store,
    private readonly crypto: RelayCrypto,
    private readonly relayUrl: string,
    private readonly now: () => number,
    private readonly limits: IdentityLimits,
  ) {}

  /** How long dids of discarded history are remembered (the tombstone window, > 90-day certificates). */
  private get seenWindowMs(): number {
    return this.limits.tombstoneRetentionSec * 1000;
  }

  /** Every did any held version of `iss` lists. */
  private heldDids(iss: string): Set<string> {
    const out = new Set<string>();
    for (const d of this.store.identityDocs(iss)) for (const x of d.devices) out.add(x);
    return out;
  }

  /**
   * Dids that were listed and aren't in the current allowlist: refused even a
   * restricted connection (H1). A restore always brings a brand-new did, which
   * isn't here. Bounded by the held versions (≤ maxVersions × 10) and the seen
   * rows (91 days, capped).
   */
  revoked(iss: string): Set<string> {
    const allowed = new Set(this.store.identityIndex(iss)?.allowed ?? []);
    const out = new Set<string>();
    for (const d of this.heldDids(iss)) if (!allowed.has(d)) out.add(d);
    for (const d of this.store.seenDevices(iss, this.now() - this.seenWindowMs)) if (!allowed.has(d)) out.add(d);
    return out;
  }

  private reindex(iss: string, cap: string[] | null): void {
    const before = this.store.identityIndex(iss)?.allowed ?? [];
    const idx = buildIndex(iss, this.store.identityDocs(iss), cap);
    if (idx) {
      this.store.putIdentityIndex(idx);
      // R4-M1: a did leaving the allowlist is remembered for the window from now, so pruning the
      // versions that listed it can't re-open even a restricted connection while its cert lives.
      const dropped = before.filter((d) => !idx.allowed.includes(d));
      if (dropped.length > 0) this.store.addSeen(iss, dropped, this.now());
    } else this.store.deleteIdentity(iss);
  }

  /** Deletes the documents of `iss` but keeps its allowlist and head version. */
  private tombstone(idx: IdentityIndex): void {
    this.store.transaction(() => {
      // Remember which dids this history listed, for the tombstone window.
      this.store.addSeen(idx.iss, [...this.heldDids(idx.iss), ...idx.allowed], this.now());
      this.store.deleteIdentityDocsOf(idx.iss);
      this.store.putIdentityIndex({ ...idx, head: "", tips: [], cap: null, leftAt: this.now() });
    });
  }

  private chainsFrom(doc: IdentityDoc): "ok" | "gap" | "bad" {
    if (doc.prev === null) return "gap";
    const prev = this.store.identityDoc(doc.prev);
    if (!prev || prev.iss !== doc.iss) return "gap";
    let merge: StoredIdentityDoc | undefined;
    if (doc.merge !== undefined) {
      merge = this.store.identityDoc(doc.merge);
      if (!merge || merge.iss !== doc.iss) return "gap";
    }
    try {
      // Stored versions were verified on the way in; re-parse to hand the seam
      // full documents (publishes are rate-limited and rare).
      this.crypto.verifyIdentityDocLink(
        this.crypto.parseIdentityDoc(prev.jws),
        doc,
        merge ? this.crypto.parseIdentityDoc(merge.jws) : undefined,
      );
      return "ok";
    } catch {
      return "bad";
    }
  }

  /**
   * N4/L-c: "owner left" only from the top of the held history: a document
   * extending the ONLY tip, or a merge of every tip. During a fork, extending
   * one branch says nothing about the others, which still list this relay.
   */
  private chainsFromTop(doc: IdentityDoc, idx: IdentityIndex): boolean {
    const extendsOnlyTip = idx.tips.length === 1 && doc.prev === idx.tips[0] && doc.merge === undefined;
    const mergesAllTips = doc.merge !== undefined && idx.tips.every((t) => t === doc.prev || t === doc.merge);
    return (extendsOnlyTip || mergesAllTips) && this.chainsFrom(doc) === "ok";
  }

  private mergesTwoTips(doc: IdentityDoc, idx: IdentityIndex): boolean {
    return doc.merge !== undefined && doc.prev !== null && idx.tips.includes(doc.prev) && idx.tips.includes(doc.merge) && this.chainsFrom(doc) === "ok";
  }

  publish(jws: unknown, publisherIss: string, opts: { topOnly?: boolean } = {}): PublishResult {
    if (typeof jws !== "string") return { ok: false, code: "bad-identity" };
    if (jws.length > MAX_DOC_BYTES) return { ok: false, code: "too-large" };
    let doc: IdentityDoc;
    try {
      doc = this.crypto.parseIdentityDoc(jws);
    } catch {
      return { ok: false, code: "bad-identity" };
    }
    if (doc.iss !== publisherIss) return { ok: false, code: "forbidden" };
    if (doc.iat > Math.floor(this.now() / 1000) + SKEW_SEC) return { ok: false, code: "bad-identity" };
    if (this.store.identityDoc(doc.hash)) return { ok: true, duplicate: true };

    const idx = this.store.identityIndex(doc.iss);
    const live = idx !== undefined && idx.leftAt === null;

    // Restricted publishers (§2.7 restore): only on top of the held history, never a fork or a new
    // root: extend the only tip, or merge two current tips (a merge never adds a device, so three
    // or more tips are merged pairwise).
    // A version whose parent isn't held is a gap (R3-M2): the publisher back-fills the missing
    // versions, each of which then extends the only tip. Genuine forks stay forbidden.
    if (opts.topOnly && !(live && (this.chainsFromTop(doc, idx) || this.mergesTwoTips(doc, idx)))) {
      return { ok: false, code: live && this.chainsFrom(doc) === "gap" ? "identity-gap" : "forbidden" };
    }

    if (!doc.relays.includes(this.relayUrl)) {
      if (live && this.chainsFromTop(doc, idx)) {
        this.tombstone(idx);
        return { ok: true, duplicate: false, left: true };
      }
      return { ok: false, code: "forbidden" };
    }

    // Decide the new history: extend, or start a (capped) new root.
    let newTips: string[];
    let cap: string[] | null;
    let replace = false;
    if (!idx) {
      newTips = [doc.hash];
      cap = null;
    } else if (!live) {
      // Re-entry after a tombstone: newer than what was known, and capped.
      if (doc.ver <= idx.headVer) return { ok: false, code: "identity-gap" };
      newTips = [doc.hash];
      cap = idx.allowed;
    } else {
      const link = this.chainsFrom(doc);
      if (link === "bad") return { ok: false, code: "bad-identity" };
      if (link === "gap") {
        // Anchored = a ver-1 root is still held. Computed from the documents
        // at publish time (never cached), so sweeping old versions can't leave
        // it stale (N7). An anchored history is only ever extended; its owner
        // back-fills gaps (§2.5).
        const anchored = this.store.identityDocs(doc.iss).some((d) => d.ver === 1);
        if (anchored || doc.ver <= idx.headVer) return { ok: false, code: "identity-gap" };
        // A newer version replaces history it doesn't chain to; the allowlist
        // can't grow past the previous one until a document chains.
        replace = true;
        newTips = [doc.hash];
        cap = idx.allowed;
      } else {
        newTips = [doc.hash, ...idx.tips.filter((t) => t !== doc.prev && t !== doc.merge)];
        if (newTips.length > this.limits.maxTips) return { ok: false, code: "full" };
        // A document that chains onto the held history lifts any cap.
        cap = null;
      }
    }

    let inserted = false;
    const prunedDids = new Set<string>();
    this.store.transaction(() => {
      // History about to be replaced: remember which dids it listed, for the tombstone window.
      if (replace && idx) this.store.addSeen(doc.iss, [...this.heldDids(doc.iss), ...idx.allowed], this.now());
      if (replace || (idx && !live)) this.store.deleteIdentityDocsOf(doc.iss);
      // Make room under maxVersions by dropping the oldest non-tip versions.
      const held = this.store.identityDocs(doc.iss);
      const over = held.length + 1 - this.limits.maxVersions;
      if (over > 0) {
        const keep = new Set(newTips);
        const victimDocs = held
          .filter((d) => !keep.has(d.hash))
          .sort((a, b) => a.ver - b.ver || a.receivedAt - b.receivedAt)
          .slice(0, over);
        for (const v of victimDocs) for (const d of v.devices) prunedDids.add(d);
        this.store.deleteIdentityDocs(victimDocs.map((d) => d.hash));
      }
      inserted = this.store.putIdentityDoc({
        hash: doc.hash,
        iss: doc.iss,
        ver: doc.ver,
        prev: doc.prev,
        merge: doc.merge ?? null,
        jws: doc.jws,
        devices: doc.devices,
        iat: doc.iat,
        exp: doc.exp,
        receivedAt: this.now(),
      });
      this.reindex(doc.iss, cap);
      // R4-M1: dids of versions pruned by the cap that the allowlist doesn't hold are remembered.
      const allowed = new Set(this.store.identityIndex(doc.iss)?.allowed ?? []);
      const gone = [...prunedDids].filter((d) => !allowed.has(d));
      if (gone.length > 0) this.store.addSeen(doc.iss, gone, this.now());
    });
    return { ok: true, duplicate: !inserted };
  }

  /**
   * §2.3 rule 6 as the relay applies it: undefined when the relay knows
   * nothing of `iss`; otherwise the devices listed in EVERY tip (during a fork
   * the intersection applies, §2.5), capped as above, or a tombstone's last
   * allowlist.
   */
  allowedDevices(iss: string): Set<string> | undefined {
    const idx = this.store.identityIndex(iss);
    return idx ? new Set(idx.allowed) : undefined;
  }

  /** The allowlist of `iss` and whether it is a tombstone; undefined when nothing is known. */
  status(iss: string): { allowed: Set<string>; left: boolean } | undefined {
    const idx = this.store.identityIndex(iss);
    return idx ? { allowed: new Set(idx.allowed), left: idx.leftAt !== null } : undefined;
  }

  head(iss: string): StoredIdentityDoc | undefined {
    const idx = this.store.identityIndex(iss);
    return idx && idx.leftAt === null ? this.store.identityDoc(idx.head) : undefined;
  }

  /** Every tip, highest first. */
  tips(iss: string): StoredIdentityDoc[] {
    const idx = this.store.identityIndex(iss);
    if (!idx || idx.leftAt !== null) return [];
    return idx.tips.map((h) => this.store.identityDoc(h)).filter((d): d is StoredIdentityDoc => d !== undefined);
  }

  /**
   * Walks back from `to` along `prev`, and along `merge` for merge versions,
   * returning at most `n` versions, highest first.
   */
  chain(iss: string, to: string, n: number): StoredIdentityDoc[] | undefined {
    const start = this.store.identityDoc(to);
    if (!start || start.iss !== iss) return undefined;
    const out: StoredIdentityDoc[] = [];
    const seen = new Set<string>([start.hash]);
    const frontier: StoredIdentityDoc[] = [start];
    while (frontier.length > 0 && out.length < n) {
      // Always expand the highest version next, so the result is highest-first.
      frontier.sort((a, b) => (higher(a, b) ? -1 : 1));
      const d = frontier.shift()!;
      out.push(d);
      for (const parent of [d.prev, d.merge]) {
        if (!parent || seen.has(parent)) continue;
        seen.add(parent);
        const p = this.store.identityDoc(parent);
        if (p && p.iss === iss) frontier.push(p);
      }
    }
    return out;
  }

  /**
   * Tombstones userIds whose head expired more than `expiredRetentionSec`
   * ago, and deletes tombstones older than `tombstoneRetentionSec`.
   */
  sweep(limit = Infinity): { tombstoned: number; deleted: number } {
    // F-4: at most `limit` of each per call, so the caller can yield between calls.
    const nowMs = this.now();
    const cutoff = Math.floor(nowMs / 1000) - this.limits.expiredRetentionSec;
    const page = Math.min(500, limit);
    let tombstoned = 0;
    while (tombstoned < limit) {
      const batch = this.store.expiredIdentities(cutoff, Math.min(page, limit - tombstoned));
      for (const iss of batch) {
        const idx = this.store.identityIndex(iss);
        if (idx) this.tombstone(idx);
      }
      tombstoned += batch.length;
      if (batch.length < page) break;
    }
    let deleted = 0;
    const tombCutoff = nowMs - this.limits.tombstoneRetentionSec * 1000;
    while (deleted < limit) {
      const batch = this.store.staleTombstones(tombCutoff, Math.min(page, limit - deleted));
      for (const iss of batch) this.store.deleteIdentity(iss);
      deleted += batch.length;
      if (batch.length < page) break;
    }
    return { tombstoned, deleted };
  }
}
