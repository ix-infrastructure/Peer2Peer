// Copyright 2026 Ix Infrastructure Inc.
//
// Relay storage. Two implementations: SqliteStore (node:sqlite, production)
// and MemoryStore (tests, ephemeral relays). Both keep only:
//   - device bindings: did -> iss (§5.2: one iss per did), with last-seen time;
//   - envelopes: the opaque JWS plus its mailbox (to, tdid), size, arrival
//     time, and `src`: a keyed hash of the sender's IP bucket under a key held
//     ONLY in the relay's memory (for source-first eviction). Nothing on disk
//     links an envelope to a network: once the process that made a tag is
//     gone, so is its key, and the tag is an anonymous group (R-M1);
//   - capability state: revoked / uses, keyed by a hash of (iss, capid), so the
//     store never holds a capability or the friend graph in readable form;
//   - identity documents, which are public by design (§5.6), plus a small
//     per-userId index (head, tips, allowed devices; or a tombstone) so request
//     paths never rescan documents.
// Times are milliseconds since the epoch unless named `...Sec`.

export interface StoredEnvelope {
  /** Monotonic, never reused: arrival order within the relay. Sent on the wire only encrypted. */
  rid: number;
  to: string;
  tdid: string;
  env: string;
  size: number;
  receivedAt: number;
}

export interface NewEnvelope {
  to: string;
  tdid: string;
  env: string;
  size: number;
  receivedAt: number;
  /** Keyed hash of the sender's IP bucket. */
  src: string;
}

export interface MailboxCaps {
  maxEnvelopes: number;
  maxBytes: number;
}

export interface StoredIdentityDoc {
  hash: string;
  iss: string;
  ver: number;
  prev: string | null;
  merge: string | null;
  jws: string;
  devices: string[];
  /** Seconds. */
  iat: number;
  exp: number;
  receivedAt: number;
}

/**
 * Derived per-userId state, rewritten on every accepted publish. A tombstone
 * (`leftAt` set) has no documents, but keeps the last allowlist and head
 * version, so rule 6 and the version floor survive the documents.
 */
export interface IdentityIndex {
  iss: string;
  /** Hash of the head (highest ver; tie: higher hash). Empty for a tombstone. */
  head: string;
  headVer: number;
  /** The head's `exp`, in seconds. */
  headExp: number;
  /** Hashes of every branch tip, highest first. Empty for a tombstone. */
  tips: string[];
  /** §2.3 rule 6: devices listed in every tip, intersected with `cap` when set. */
  allowed: string[];
  /**
   * Set while the held history doesn't chain to what the relay knew before
   * (a replaced unanchored root, or a re-entry after a tombstone): the
   * allowlist can't grow past it until a document chains onto that history.
   */
  cap: string[] | null;
  /** When the identity was tombstoned (owner left, or head long expired). */
  leftAt: number | null;
}

/** Seen-device rows kept per userId (128 versions × 10 devices, with headroom). */
export const MAX_SEEN_PER_ISS = 2048;

/**
 * A short-code invite mailbox entry (P4): an opaque sealed blob the relay
 * can't read, keyed by `lid` (a hash of the code secret it never sees).
 */
export interface StoredInvite {
  lid: string;
  /** The userId that put it (per-iss caps; only it may list or delete it). */
  iss: string;
  blob: string;
  size: number;
  createdAt: number;
  expiresAt: number;
  /** Keyed hash of the putter's IP bucket (/48 for IPv6), under a key held only in memory, as for envelopes. */
  src: string;
}

export interface CapState {
  revoked: boolean;
  uses: number;
}

export interface SweepCutoffs {
  /** Capability state untouched since this is deleted (caps live ≤ 90 days). */
  capsBefore: number;
  /** Identity versions received before this are deleted unless they are a branch tip. */
  identityVersionsBefore: number;
  /** Seen-device rows older than this (ms) are deleted. */
  seenBefore?: number;
  /** Now (ms): when swept versions' dids outside the allowlist are remembered (R4-M1). */
  nowMs?: number;
  /** Device bindings not seen since this are deleted. */
  devicesBefore: number;
}

export interface SweepResult {
  caps: number;
  identityDocs: number;
  devices: number;
  /** Seen-device rows deleted (past the tombstone window). */
  seen?: number;
}

export interface StoreCounts {
  envelopes: number;
  envelopeBytes: number;
  devices: number;
  identityDocs: number;
}

export interface Store {
  /**
   * Prepares the store before the relay accepts sends: rebuilds the running
   * totals (and derived device state) in chunks that yield to the event loop.
   */
  init(): Promise<void>;
  /** Runs `fn` atomically (re-entrant: nested calls join the outer transaction). */
  transaction<T>(fn: () => T): T;

  getMeta(key: string): string | undefined;
  setMeta(key: string, value: string): void;

  deviceIssuer(did: string): string | undefined;
  /** Binds did -> iss if unbound (returns true), and refreshes last-seen when it is bound to iss. */
  touchDevice(did: string, iss: string, now: number): boolean;
  /**
   * Bindings that could be evicted, least recently seen first (ties by did):
   * no stored envelopes and not in any held identity allowlist. Keyset paging:
   * pass the last row of the previous page as `after`. The caller still skips
   * live connections.
   */
  evictableDevices(limit: number, after?: { lastSeen: number; did: string }): { did: string; iss: string; lastSeen: number }[];
  deleteDevice(did: string): void;

  /** Appends an envelope, then drops the mailbox's oldest until it fits `caps`. */
  putEnvelope(e: NewEnvelope, caps: MailboxCaps): { rid: number; dropped: number; droppedBytes: number };
  /** Envelopes of mailbox (to, tdid) with rid > afterRid received at or after notBefore, oldest first. */
  envelopesAfter(to: string, tdid: string, afterRid: number, notBefore: number, limit: number): StoredEnvelope[];
  /** Deletes the given rids, but only those in mailbox (to, tdid). */
  ackEnvelopes(to: string, tdid: string, rids: readonly number[]): { count: number; bytes: number };
  /** Stored bytes addressed to `to` (every mailbox of that userId). A counter read, never an aggregate. */
  bytesForRecipient(to: string): number;
  /** Stored bytes in mailbox (to, tdid). A counter read. */
  mailboxBytes(to: string, tdid: string): number;
  /**
   * Frees at least `bytes` from recipient `to`: the source holding the most
   * bytes for `to` loses its oldest envelopes to `to` first. Returns the bytes freed.
   */
  evictRecipient(to: string, bytes: number, policy?: EvictPolicy): number;
  /**
   * Frees at least `bytes` store-wide: the source holding the most bytes loses
   * the oldest envelopes of its largest mailbox first. Returns the bytes freed.
   */
  evictGlobal(bytes: number, policy?: EvictPolicy): number;
  /** Stored bytes tagged with source `src`. A counter read. */
  sourceBytes(src: string): number;
  /** Frees at least `bytes` of source `src`'s own envelopes, oldest of its largest mailbox first. */
  evictSource(src: string, bytes: number): number;
  /** Deletes up to `limit` envelopes received before `before`, oldest first, keeping totals exact. */
  expireBatch(before: number, limit: number): { count: number; bytes: number };

  capState(key: string): CapState;
  revokeCap(key: string, now: number): void;
  useCap(key: string, now: number): void;

  identityDoc(hash: string): StoredIdentityDoc | undefined;
  identityDocs(iss: string): StoredIdentityDoc[];
  /** False when the hash is already stored. */
  putIdentityDoc(d: StoredIdentityDoc): boolean;
  deleteIdentityDocs(hashes: readonly string[]): void;
  /** Deletes every document of `iss`, keeping its index row. */
  deleteIdentityDocsOf(iss: string): void;
  identityIndex(iss: string): IdentityIndex | undefined;
  putIdentityIndex(idx: IdentityIndex): void;
  /** Deletes every document and the index of `iss`. */
  deleteIdentity(iss: string): void;
  /**
   * Device ids of history this relay discarded for `iss` (a tombstone, or a
   * replaced unanchored root), with when (ms). Restricted auth refuses them
   * (they were listed once and aren't now); kept for the tombstone window
   * (91 days, longer than any certificate lives), capped per userId, and
   * deleted with the identity. Nothing else about revocations is stored:
   * clients enforce no-return from their own chains.
   */
  seenDevices(iss: string, sinceMs: number): string[];
  addSeen(iss: string, dids: readonly string[], at: number): void;
  /** Live (non-tombstone) userIds whose head `exp` (seconds) is before `headExpBeforeSec`. */
  expiredIdentities(headExpBeforeSec: number, limit: number): string[];
  /** Tombstoned userIds whose `leftAt` is before `leftBefore`. */
  staleTombstones(leftBefore: number, limit: number): string[];

  /** P4 invite mailboxes. False when `lid` is already held (never overwritten). */
  putInvite(i: StoredInvite): boolean;
  /** Deletes and returns the live entry for `lid` (single use); expired entries are deleted and not returned. */
  takeInvite(lid: string, now: number): StoredInvite | undefined;
  /** Deletes `lid` only if `iss` put it; true when something was deleted. */
  deleteInvite(lid: string, iss: string): boolean;
  /** The live lids `iss` holds, oldest first. */
  invitesOf(iss: string, now: number): string[];
  /** Lids of `iss` the relay evicted (full store) that would not have expired yet. */
  evictedInvitesOf(iss: string, now: number): string[];
  /** Invite bytes `iss` holds. A counter read (kept per userId). */
  inviteBytesOfIss(iss: string): number;
  /** Bytes held across every invite (live or not yet swept). A counter read. */
  inviteBytes(): number;
  /** Bytes held by invites tagged with source `src`. */
  inviteBytesOfSrc(src: string): number;
  /**
   * Frees at least `bytes` (P4, full store). With `now`, invites already
   * expired at `now` go first (oldest expiry first, no tombstone), so a sweep
   * that hasn't caught up never costs a live invite. Then the userId holding
   * the most invite bytes (a per-userId counter, not an aggregate) loses its
   * newest invite, repeatedly, each leaving an `evicted` tombstone until it
   * would have expired. Returns the bytes freed.
   */
  evictInvites(bytes: number, now?: number): number;
  /**
   * Deletes at most `limit` expired invites (oldest expiry first, keeping the
   * per-userId totals row by row) and at most `limit` expired `evicted`
   * tombstones. Callers loop and yield (F-4).
   */
  sweepInvites(now: number, limit: number): { invites: number; evicted: number };

  /** Deletes at most `limit` expired rows from each of caps, identity versions and devices (F-4: callers loop and yield). */
  sweep(cutoffs: SweepCutoffs, limit: number): SweepResult;
  /** Stored envelope count and bytes: a counter read. */
  envelopeTotals(): { envelopes: number; bytes: number };
  counts(): StoreCounts;
  /** A cheap liveness probe for /healthz. */
  ping(): boolean;
  close(): void;
}

// ---------------------------------------------------------------------------

const mbox = (to: string, tdid: string) => `${to}\n${tdid}`;

/** Every identity version referenced as `prev` or `merge` by another held version. */
export function referencedHashes(docs: readonly StoredIdentityDoc[]): Set<string> {
  const refs = new Set<string>();
  for (const d of docs) {
    if (d.prev) refs.add(d.prev);
    if (d.merge) refs.add(d.merge);
  }
  return refs;
}

type MemEnvelope = StoredEnvelope & { src: string };

/**
 * How eviction ranks source groups (F-6, revised after the pre-release review). No
 * group is preferred for its age or the process that tagged it:
 *   1. the sending source pays first, but only when its group is over its
 *      fair share: more than both `floor` and `fairShare` (the quota divided
 *      by the number of groups). An honest sender to a full mailbox is under
 *      its share, so it never evicts its own older mail;
 *   2. otherwise the largest group among all groups above `floor`;
 *   3. and only when none is above it, the largest group overall.
 * So a flood (before or after a restart, from one source or spread across
 * many under the floor) pays for itself before it touches anyone else's
 * parked mail, and a restart doesn't make older groups preferred victims.
 */
export interface EvictPolicy {
  floor?: number;
  sender?: string;
  /** The quota the eviction is for: the fair share is quota / number of groups. */
  quota?: number;
}

/** Picks the group to evict from, per EvictPolicy. `groups` defaults to the candidates' count. */
export function pickSource(cands: readonly { src: string; bytes: number }[], policy: EvictPolicy = {}, groups = cands.length): string | undefined {
  const floor = policy.floor ?? 0;
  if (policy.sender !== undefined) {
    const own = cands.find((c) => c.src === policy.sender);
    const fairShare = policy.quota !== undefined && groups > 0 ? policy.quota / groups : 0;
    if (own && own.bytes > Math.max(floor, fairShare)) return own.src;
  }
  const largest = (xs: readonly { src: string; bytes: number }[]) =>
    xs.reduce<{ src: string; bytes: number } | undefined>((b, x) => (!b || x.bytes > b.bytes ? x : b), undefined)?.src;
  const above = cands.filter((c) => c.bytes > floor);
  return largest(above.length > 0 ? above : cands);
}

/** The running totals an envelope counts toward: (kind, key). */
export function totalKeys(to: string, tdid: string, src: string): [string, string][] {
  return [
    ["all", ""],
    ["mbox", `${to}\n${tdid}`],
    ["rcpt", to],
    ["src", src],
    ["rsrc", `${to}\n${src}`],
    ["smbox", `${src}\n${to}\n${tdid}`],
  ];
}

const copyIndex = (i: IdentityIndex): IdentityIndex => ({
  ...i,
  tips: [...i.tips],
  allowed: [...i.allowed],
  cap: i.cap ? [...i.cap] : null,
});

export class MemoryStore implements Store {
  private readonly devices = new Map<string, { iss: string; lastSeen: number }>();
  private readonly mailboxes = new Map<string, MemEnvelope[]>();
  private readonly caps = new Map<string, CapState & { updatedAt: number }>();
  private readonly docs = new Map<string, StoredIdentityDoc>();
  private readonly index = new Map<string, IdentityIndex>();
  private readonly seen = new Map<string, Map<string, number>>();
  private readonly revoked = new Map<string, { iss: string; dids: string[] }>();
  private readonly meta = new Map<string, string>();
  private readonly invites = new Map<string, StoredInvite>();
  /** Invite bytes per userId (eviction picks the biggest holder without a scan). */
  private readonly inviteIss = new Map<string, number>();
  /** Evicted lids, until their invite would have expired (so the inviter can tell evicted from taken). */
  private readonly evicted = new Map<string, { iss: string; expiresAt: number }>();
  private inviteTotal = 0;
  private nextRid = 1;

  async init(): Promise<void> {}

  transaction<T>(fn: () => T): T {
    return fn();
  }

  getMeta(key: string): string | undefined {
    return this.meta.get(key);
  }

  setMeta(key: string, value: string): void {
    this.meta.set(key, value);
  }

  evictableDevices(limit: number, after?: { lastSeen: number; did: string }): { did: string; iss: string; lastSeen: number }[] {
    // Only the device's OWN issuer's allowlist pins it: another identity's
    // document listing this did means nothing (matched on (iss, did)).
    const listed = (iss: string, did: string) => this.index.get(iss)?.allowed.includes(did) ?? false;
    return [...this.devices.entries()]
      .filter(([did, d]) => !listed(d.iss, did) && this.mailboxBytes(d.iss, did) === 0)
      .filter(([did, d]) => !after || d.lastSeen > after.lastSeen || (d.lastSeen === after.lastSeen && did > after.did))
      .sort((a, b) => a[1].lastSeen - b[1].lastSeen || (a[0] < b[0] ? -1 : 1))
      .slice(0, limit)
      .map(([did, d]) => ({ did, iss: d.iss, lastSeen: d.lastSeen }));
  }

  deleteDevice(did: string): void {
    this.devices.delete(did);
  }

  deviceIssuer(did: string): string | undefined {
    return this.devices.get(did)?.iss;
  }

  touchDevice(did: string, iss: string, now: number): boolean {
    const d = this.devices.get(did);
    if (!d) {
      this.devices.set(did, { iss, lastSeen: now });
      return true;
    }
    if (d.iss === iss) d.lastSeen = now;
    return false;
  }

  putEnvelope(e: NewEnvelope, caps: MailboxCaps): { rid: number; dropped: number; droppedBytes: number } {
    const key = mbox(e.to, e.tdid);
    let box = this.mailboxes.get(key);
    if (!box) this.mailboxes.set(key, (box = []));
    const rid = this.nextRid++;
    box.push({ rid, ...e });
    let bytes = box.reduce((n, x) => n + x.size, 0);
    let dropped = 0;
    let droppedBytes = 0;
    while (box.length > 0 && (box.length > caps.maxEnvelopes || bytes > caps.maxBytes)) {
      const size = box.shift()!.size;
      bytes -= size;
      droppedBytes += size;
      dropped++;
    }
    return { rid, dropped, droppedBytes };
  }

  envelopesAfter(to: string, tdid: string, afterRid: number, notBefore: number, limit: number): StoredEnvelope[] {
    const box = this.mailboxes.get(mbox(to, tdid)) ?? [];
    return box
      .filter((x) => x.rid > afterRid && x.receivedAt >= notBefore)
      .slice(0, limit)
      .map(({ src: _src, ...e }) => e);
  }

  ackEnvelopes(to: string, tdid: string, rids: readonly number[]): { count: number; bytes: number } {
    const key = mbox(to, tdid);
    const box = this.mailboxes.get(key);
    if (!box) return { count: 0, bytes: 0 };
    const drop = new Set(rids);
    const keep: MemEnvelope[] = [];
    let bytes = 0;
    for (const x of box) {
      if (drop.has(x.rid)) bytes += x.size;
      else keep.push(x);
    }
    const count = box.length - keep.length;
    if (keep.length === 0) this.mailboxes.delete(key);
    else this.mailboxes.set(key, keep);
    return { count, bytes };
  }

  bytesForRecipient(to: string): number {
    let n = 0;
    for (const box of this.mailboxes.values()) for (const x of box) if (x.to === to) n += x.size;
    return n;
  }

  mailboxBytes(to: string, tdid: string): number {
    return (this.mailboxes.get(mbox(to, tdid)) ?? []).reduce((n, x) => n + x.size, 0);
  }

  private all(): MemEnvelope[] {
    return [...this.mailboxes.values()].flat();
  }

  private remove(e: MemEnvelope): number {
    const key = mbox(e.to, e.tdid);
    const box = this.mailboxes.get(key)!;
    box.splice(box.indexOf(e), 1);
    if (box.length === 0) this.mailboxes.delete(key);
    return e.size;
  }

  /** The key with the most bytes, grouping `items` by `keyOf`. */
  private static largest<T extends { size: number }>(items: T[], keyOf: (x: T) => string): string | undefined {
    const sums = new Map<string, number>();
    for (const x of items) sums.set(keyOf(x), (sums.get(keyOf(x)) ?? 0) + x.size);
    let best: string | undefined;
    let max = -1;
    for (const [k, v] of sums) if (v > max) [best, max] = [k, v];
    return best;
  }

  /** Bytes per source among `items`. */
  private static sums<T extends { size: number; src: string }>(items: T[]): { src: string; bytes: number }[] {
    const m = new Map<string, number>();
    for (const x of items) m.set(x.src, (m.get(x.src) ?? 0) + x.size);
    return [...m].map(([src, bytes]) => ({ src, bytes }));
  }

  evictRecipient(to: string, bytes: number, policy: EvictPolicy = {}): number {
    let freed = 0;
    while (freed < bytes) {
      const mine = this.all().filter((x) => x.to === to);
      const src = pickSource(MemoryStore.sums(mine), policy);
      if (src === undefined) break;
      const oldest = mine.filter((x) => x.src === src).sort((a, b) => a.rid - b.rid)[0];
      freed += this.remove(oldest);
    }
    return freed;
  }

  evictGlobal(bytes: number, policy: EvictPolicy = {}): number {
    let freed = 0;
    while (freed < bytes) {
      const all = this.all();
      const src = pickSource(MemoryStore.sums(all), policy);
      if (src === undefined) break;
      const fromSrc = all.filter((x) => x.src === src);
      const box = MemoryStore.largest(fromSrc, (x) => mbox(x.to, x.tdid))!;
      const oldest = fromSrc.filter((x) => mbox(x.to, x.tdid) === box).sort((a, b) => a.rid - b.rid)[0];
      freed += this.remove(oldest);
    }
    return freed;
  }

  sourceBytes(src: string): number {
    return this.all()
      .filter((x) => x.src === src)
      .reduce((n, x) => n + x.size, 0);
  }

  evictSource(src: string, bytes: number): number {
    let freed = 0;
    while (freed < bytes) {
      const fromSrc = this.all().filter((x) => x.src === src);
      const box = MemoryStore.largest(fromSrc, (x) => mbox(x.to, x.tdid));
      if (box === undefined) break;
      const oldest = fromSrc.filter((x) => mbox(x.to, x.tdid) === box).sort((a, b) => a.rid - b.rid)[0];
      freed += this.remove(oldest);
    }
    return freed;
  }

  expireBatch(before: number, limit: number): { count: number; bytes: number } {
    const victims = this.all()
      .filter((x) => x.receivedAt < before)
      .sort((a, b) => a.receivedAt - b.receivedAt || a.rid - b.rid)
      .slice(0, limit);
    let bytes = 0;
    for (const v of victims) bytes += this.remove(v);
    return { count: victims.length, bytes };
  }

  capState(key: string): CapState {
    const c = this.caps.get(key);
    return { revoked: c?.revoked ?? false, uses: c?.uses ?? 0 };
  }

  revokeCap(key: string, now: number): void {
    const c = this.caps.get(key) ?? { revoked: false, uses: 0, updatedAt: now };
    this.caps.set(key, { ...c, revoked: true, updatedAt: now });
  }

  useCap(key: string, now: number): void {
    const c = this.caps.get(key) ?? { revoked: false, uses: 0, updatedAt: now };
    this.caps.set(key, { ...c, uses: c.uses + 1, updatedAt: now });
  }

  identityDoc(hash: string): StoredIdentityDoc | undefined {
    return this.docs.get(hash);
  }

  identityDocs(iss: string): StoredIdentityDoc[] {
    return [...this.docs.values()].filter((d) => d.iss === iss).sort((a, b) => a.ver - b.ver);
  }

  putIdentityDoc(d: StoredIdentityDoc): boolean {
    if (this.docs.has(d.hash)) return false;
    this.docs.set(d.hash, { ...d, devices: [...d.devices] });
    return true;
  }

  deleteIdentityDocs(hashes: readonly string[]): void {
    for (const h of hashes) this.docs.delete(h);
  }

  deleteIdentityDocsOf(iss: string): void {
    for (const [h, d] of this.docs) if (d.iss === iss) this.docs.delete(h);
  }

  identityIndex(iss: string): IdentityIndex | undefined {
    const i = this.index.get(iss);
    return i && copyIndex(i);
  }

  putIdentityIndex(idx: IdentityIndex): void {
    this.index.set(idx.iss, copyIndex(idx));
  }

  deleteIdentity(iss: string): void {
    this.deleteIdentityDocsOf(iss);
    this.index.delete(iss);
    this.seen.delete(iss);
  }

  seenDevices(iss: string, sinceMs: number): string[] {
    return [...(this.seen.get(iss) ?? new Map<string, number>())].filter(([, at]) => at >= sinceMs).map(([d]) => d);
  }

  addSeen(iss: string, dids: readonly string[], at: number): void {
    if (dids.length === 0) return;
    let m = this.seen.get(iss);
    if (!m) this.seen.set(iss, (m = new Map()));
    for (const d of dids) {
      m.delete(d);
      m.set(d, at);
    }
    // Oldest first: keep the newest MAX_SEEN_PER_ISS.
    while (m.size > MAX_SEEN_PER_ISS) m.delete(m.keys().next().value!);
  }

  expiredIdentities(headExpBeforeSec: number, limit: number): string[] {
    return [...this.index.values()]
      .filter((i) => i.leftAt === null && i.headExp < headExpBeforeSec)
      .slice(0, limit)
      .map((i) => i.iss);
  }

  staleTombstones(leftBefore: number, limit: number): string[] {
    return [...this.index.values()]
      .filter((i) => i.leftAt !== null && i.leftAt < leftBefore)
      .slice(0, limit)
      .map((i) => i.iss);
  }

  envelopeTotals(): { envelopes: number; bytes: number } {
    const c = this.counts();
    return { envelopes: c.envelopes, bytes: c.envelopeBytes };
  }

  sweep(c: SweepCutoffs, limit: number): SweepResult {
    let caps = 0;
    for (const [k, v] of this.caps) {
      if (caps >= limit) break;
      if (v.updatedAt < c.capsBefore) {
        this.caps.delete(k);
        caps++;
      }
    }
    const refs = referencedHashes([...this.docs.values()]);
    let identityDocs = 0;
    for (const [h, d] of this.docs) {
      if (identityDocs >= limit) break;
      if (d.receivedAt < c.identityVersionsBefore && refs.has(h)) {
        const allowed = new Set(this.index.get(d.iss)?.allowed ?? []);
        const gone = d.devices.filter((x) => !allowed.has(x));
        if (gone.length > 0 && c.nowMs !== undefined) this.addSeen(d.iss, gone, c.nowMs);
        this.docs.delete(h);
        identityDocs++;
      }
    }
    if (c.seenBefore !== undefined) {
      for (const [iss, m] of this.seen) {
        for (const [d, at] of m) if (at < c.seenBefore) m.delete(d);
        if (m.size === 0) this.seen.delete(iss);
      }
    }
    let devices = 0;
    for (const [did, d] of this.devices) {
      if (devices >= limit) break;
      if (d.lastSeen < c.devicesBefore) {
        this.devices.delete(did);
        devices++;
      }
    }
    return { caps, identityDocs, devices };
  }

  private issAdd(iss: string, d: number): void {
    const n = (this.inviteIss.get(iss) ?? 0) + d;
    if (n <= 0) this.inviteIss.delete(iss);
    else this.inviteIss.set(iss, n);
  }

  private dropInvite(i: StoredInvite): void {
    this.invites.delete(i.lid);
    this.inviteTotal -= i.size;
    this.issAdd(i.iss, -i.size);
  }

  putInvite(i: StoredInvite): boolean {
    if (this.invites.has(i.lid)) return false;
    this.invites.set(i.lid, { ...i });
    this.inviteTotal += i.size;
    this.issAdd(i.iss, i.size);
    return true;
  }

  takeInvite(lid: string, now: number): StoredInvite | undefined {
    const i = this.invites.get(lid);
    if (!i) return undefined;
    this.dropInvite(i);
    return i.expiresAt > now ? i : undefined;
  }

  deleteInvite(lid: string, iss: string): boolean {
    const i = this.invites.get(lid);
    if (!i || i.iss !== iss) return false;
    this.dropInvite(i);
    return true;
  }

  invitesOf(iss: string, now: number): string[] {
    return [...this.invites.values()]
      .filter((i) => i.iss === iss && i.expiresAt > now)
      .sort((a, b) => a.createdAt - b.createdAt || (a.lid < b.lid ? -1 : 1))
      .map((i) => i.lid);
  }

  evictedInvitesOf(iss: string, now: number): string[] {
    return [...this.evicted.entries()].filter(([, e]) => e.iss === iss && e.expiresAt > now).map(([lid]) => lid);
  }

  inviteBytes(): number {
    return this.inviteTotal;
  }

  inviteBytesOfIss(iss: string): number {
    return this.inviteIss.get(iss) ?? 0;
  }

  inviteBytesOfSrc(src: string): number {
    let n = 0;
    for (const i of this.invites.values()) if (i.src === src) n += i.size;
    return n;
  }

  evictInvites(bytes: number, now?: number): number {
    let freed = 0;
    if (now !== undefined) {
      const expired = [...this.invites.values()].filter((i) => i.expiresAt <= now).sort((a, b) => a.expiresAt - b.expiresAt || (a.lid < b.lid ? -1 : 1));
      for (const i of expired) {
        if (freed >= bytes) break;
        this.dropInvite(i);
        freed += i.size;
      }
    }
    while (freed < bytes && this.inviteIss.size > 0) {
      let top = "";
      let most = -1;
      for (const [iss, b] of this.inviteIss) if (b > most || (b === most && iss < top)) [top, most] = [iss, b];
      let newest: StoredInvite | undefined;
      for (const i of this.invites.values()) {
        if (i.iss === top && (!newest || i.createdAt > newest.createdAt || (i.createdAt === newest.createdAt && i.lid > newest.lid))) newest = i;
      }
      if (!newest) break;
      this.dropInvite(newest);
      this.evicted.set(newest.lid, { iss: newest.iss, expiresAt: newest.expiresAt });
      freed += newest.size;
    }
    return freed;
  }

  sweepInvites(now: number, limit: number): { invites: number; evicted: number } {
    const expired = [...this.invites.values()].filter((i) => i.expiresAt <= now).sort((a, b) => a.expiresAt - b.expiresAt || (a.lid < b.lid ? -1 : 1));
    for (const i of expired.slice(0, limit)) this.dropInvite(i);
    let evicted = 0;
    for (const [lid, e] of this.evicted) {
      if (evicted >= limit) break;
      if (e.expiresAt <= now) {
        this.evicted.delete(lid);
        evicted++;
      }
    }
    return { invites: Math.min(limit, expired.length), evicted };
  }

  counts(): StoreCounts {
    let envelopes = 0;
    let envelopeBytes = 0;
    for (const box of this.mailboxes.values()) {
      envelopes += box.length;
      for (const x of box) envelopeBytes += x.size;
    }
    return { envelopes, envelopeBytes, devices: this.devices.size, identityDocs: this.docs.size };
  }

  ping(): boolean {
    return true;
  }

  close(): void {}
}
