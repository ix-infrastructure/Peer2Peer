// Copyright 2026 Ix Infrastructure Inc.
//
// The production Store, on node:sqlite (built into Node >= 22.13; no native
// dependency). WAL mode, and secure_delete so acked or expired envelopes are
// overwritten on disk rather than left in free pages.
//
// Nothing ever aggregates over `envelopes` while the relay serves (H-1,
// N-M1). Byte and count totals per mailbox, recipient, source, (recipient,
// source) and (source, mailbox), plus the grand total, live in the small
// `totals` table, updated in the same transaction as every insert and delete
// (including expiry, which deletes in small batches). They are rebuilt only in
// `init`, at startup, in chunks that yield. In `envelopes`, the 64 KiB `env`
// column is last, so reading routing columns and `size` never touches overflow
// pages, and every hot query is an index SEARCH.
//
// Source tags (N-M3, R-M1): the tag key lives only in the relay's memory. A
// row stored by an earlier process keeps its tag; with that process's key
// gone, the tag is an anonymous group that can't be linked to any network,
// but it still groups one sender's rows, so source-first eviction stays fair
// across restarts (a flooder's old rows remain the largest source).
//
// Device eviction (R-L2): `devices.evictable` is 1 when the binding has no
// stored envelopes and is in no held allowlist. It is kept current wherever a
// mailbox gains its first or loses its last envelope and wherever an allowlist
// changes, so the cap path reads the oldest evictable rows straight from a
// partial index with a keyset cursor.

import { DatabaseSync, type StatementSync } from "node:sqlite";
import { readFileSync, statSync } from "node:fs";
import { Worker } from "node:worker_threads";
import {
  MAX_SEEN_PER_ISS,
  pickSource,
  totalKeys,
  type EvictPolicy,
  type CapState,
  type IdentityIndex,
  type MailboxCaps,
  type NewEnvelope,
  type Store,
  type StoreCounts,
  type StoredEnvelope,
  type StoredInvite,
  type StoredIdentityDoc,
  type SweepCutoffs,
  type SweepResult,
} from "./store.js";

const SCHEMA_VERSION = 1;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS devices (
  did TEXT PRIMARY KEY,
  iss TEXT NOT NULL,
  last_seen INTEGER NOT NULL,
  evictable INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS devices_seen ON devices (last_seen);
CREATE INDEX IF NOT EXISTS devices_evictable ON devices (last_seen, did) WHERE evictable = 1;
CREATE TABLE IF NOT EXISTS envelopes (
  rid INTEGER PRIMARY KEY AUTOINCREMENT,
  mbox_to TEXT NOT NULL,
  mbox_did TEXT NOT NULL,
  src TEXT NOT NULL,
  size INTEGER NOT NULL,
  received_at INTEGER NOT NULL,
  env TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS envelopes_mbox ON envelopes (mbox_to, mbox_did, rid);
CREATE INDEX IF NOT EXISTS envelopes_time ON envelopes (received_at);
CREATE INDEX IF NOT EXISTS envelopes_src_mbox ON envelopes (src, mbox_to, mbox_did, rid);
CREATE INDEX IF NOT EXISTS envelopes_to_src ON envelopes (mbox_to, src, rid);
CREATE TABLE IF NOT EXISTS totals (
  kind TEXT NOT NULL,
  key TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  n INTEGER NOT NULL,
  PRIMARY KEY (kind, key)
);
CREATE INDEX IF NOT EXISTS totals_bytes ON totals (kind, bytes);
CREATE TABLE IF NOT EXISTS caps (
  key TEXT PRIMARY KEY,
  revoked INTEGER NOT NULL DEFAULT 0,
  uses INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS caps_time ON caps (updated_at);
CREATE TABLE IF NOT EXISTS identity_docs (
  hash TEXT PRIMARY KEY,
  iss TEXT NOT NULL,
  ver INTEGER NOT NULL,
  prev TEXT,
  merge TEXT,
  devices TEXT NOT NULL,
  iat INTEGER NOT NULL,
  exp INTEGER NOT NULL,
  received_at INTEGER NOT NULL,
  jws TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS identity_iss ON identity_docs (iss, ver);
CREATE INDEX IF NOT EXISTS identity_prev ON identity_docs (prev);
CREATE INDEX IF NOT EXISTS identity_merge ON identity_docs (merge);
CREATE INDEX IF NOT EXISTS identity_received ON identity_docs (received_at);
CREATE TABLE IF NOT EXISTS identity_index (
  iss TEXT PRIMARY KEY,
  head TEXT NOT NULL,
  head_ver INTEGER NOT NULL,
  head_exp INTEGER NOT NULL,
  tips TEXT NOT NULL,
  allowed TEXT NOT NULL,
  cap TEXT,
  left_at INTEGER
);
CREATE INDEX IF NOT EXISTS identity_index_exp ON identity_index (head_exp);
CREATE INDEX IF NOT EXISTS identity_index_left ON identity_index (left_at);
CREATE TABLE IF NOT EXISTS allowed_devices (
  did TEXT NOT NULL,
  iss TEXT NOT NULL,
  PRIMARY KEY (did, iss)
);
CREATE INDEX IF NOT EXISTS allowed_devices_iss ON allowed_devices (iss);
CREATE TABLE IF NOT EXISTS identity_seen (
  iss TEXT NOT NULL,
  did TEXT NOT NULL,
  at INTEGER NOT NULL,
  PRIMARY KEY (iss, did)
);
CREATE INDEX IF NOT EXISTS identity_seen_at ON identity_seen (at);
CREATE TABLE IF NOT EXISTS invites (
  lid TEXT PRIMARY KEY,
  iss TEXT NOT NULL,
  blob TEXT NOT NULL,
  size INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  src TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS invites_iss ON invites (iss, created_at);
CREATE INDEX IF NOT EXISTS invites_src ON invites (src);
-- Covers inviteBytesOfSrc (sum(size) per src) without reading the blobs' overflow pages.
CREATE INDEX IF NOT EXISTS invites_src_size ON invites (src, size);
CREATE TABLE IF NOT EXISTS invite_iss (iss TEXT PRIMARY KEY, bytes INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS invite_iss_bytes ON invite_iss (bytes);
CREATE TABLE IF NOT EXISTS invite_evicted (lid TEXT PRIMARY KEY, iss TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS invite_evicted_iss ON invite_evicted (iss);
CREATE INDEX IF NOT EXISTS invites_exp ON invites (expires_at);
CREATE INDEX IF NOT EXISTS invite_evicted_exp ON invite_evicted (expires_at);
DROP TABLE IF EXISTS identity_revoked;
DROP TABLE IF EXISTS retired_devices;
`;

interface DocRow {
  hash: string;
  iss: string;
  ver: number;
  prev: string | null;
  merge: string | null;
  jws: string;
  devices: string;
  iat: number;
  exp: number;
  received_at: number;
}

function docFromRow(r: DocRow): StoredIdentityDoc {
  return {
    hash: r.hash,
    iss: r.iss,
    ver: Number(r.ver),
    prev: r.prev,
    merge: r.merge,
    jws: r.jws,
    devices: JSON.parse(r.devices) as string[],
    iat: Number(r.iat),
    exp: Number(r.exp),
    receivedAt: Number(r.received_at),
  };
}

interface IndexRow {
  iss: string;
  head: string;
  head_ver: number;
  head_exp: number;
  tips: string;
  allowed: string;
  cap: string | null;
  left_at: number | null;
}

/** The routing part of an envelope row: everything before `env`. */
interface EnvMeta {
  rid: number;
  mbox_to: string;
  mbox_did: string;
  src: string;
  size: number;
}

export interface SqliteStoreOptions {
  /** Called with the SQL of every statement run (tests use it to prove hot paths are aggregate-free). */
  trace?: (sql: string) => void;
  /**
   * Run WAL checkpoints on a worker thread (default for file databases). When
   * false, SQLite's automatic checkpoint runs inside commits on the main thread.
   */
  backgroundCheckpoint?: boolean;
  /** How often the worker checkpoints (default 100 ms). */
  checkpointIntervalMs?: number;
  /** No completed checkpoint for this long means the worker is stalled (default 30 s). */
  checkpointWatchdogMs?: number;
  /** A WAL larger than this means checkpoints aren't keeping up (default 256 MiB). */
  walLimitBytes?: number;
  /** After a checkpoint, SQLite truncates the WAL file back to this size (default 64 MiB). */
  journalSizeLimitBytes?: number;
  /**
   * The watchdog's clock (default Date.now). Tests pass a virtual one, so the
   * stall rule is judged by the time they advance, not by how fast a loaded
   * machine schedules the worker thread.
   */
  now?: () => number;
  /** Receives warnings (the relay passes its logger). */
  warn?: (msg: string, fields?: Record<string, string | number | boolean>) => void;
}

const CHECKPOINT_INTERVAL_MS = 100;
const CHECKPOINT_WATCHDOG_MS = 30_000;

/**
 * A running backup (deploy/relay/backup.mjs) writes `<db>-backup`, JSON with
 * `until` (ms since the epoch: its own deadline), and removes it when done.
 * Its read snapshot holds checkpoints back by design, so while it runs the
 * watchdog doesn't count that as a stall: re-enabling in-commit checkpoints
 * then only made the first commit after the backup copy the whole grown WAL
 * on the main thread (1-3.6 s on a 3 GiB database). A marker is honoured at
 * most BACKUP_MARKER_MAX_MS after its file was written, whatever it claims,
 * so a backup killed before cleaning up can't switch the watchdog off.
 */
export const BACKUP_MARKER_MAX_MS = 60 * 60 * 1000;
const WAL_LIMIT_BYTES = 256 * 1024 * 1024;
/** After a checkpoint, SQLite truncates the WAL file back to this size. */
const JOURNAL_SIZE_LIMIT = 64 * 1024 * 1024;

/**
 * F-4: the WAL checkpointer, on its own thread and connection. SQLite's
 * automatic checkpoint runs inside whichever commit crosses the threshold, on
 * the main thread, copying WAL pages and syncing the database file: on slow
 * disks that is a 20-30 ms stall every few hundred deletes. A PASSIVE
 * checkpoint from another connection never blocks writers, so the main thread
 * only ever appends to the WAL.
 */
const CHECKPOINT_WORKER = `
const { parentPort, workerData } = require("node:worker_threads");
const { DatabaseSync } = require("node:sqlite");
const flags = new Int32Array(workerData.flags);
let db;
try {
  db = new DatabaseSync(workerData.path);
} catch {
  // The database is gone or unreadable (a store closed, and its directory removed, before this
  // thread got to start): end quietly. The main thread sees the exit and, if the store is still
  // open, turns SQLite's own checkpoints back on.
  Atomics.store(flags, 0, 1);
  Atomics.notify(flags, 0);
  process.exit(0);
}
db.exec("PRAGMA busy_timeout = 1000");
db.exec("PRAGMA journal_size_limit = " + workerData.journalSizeLimit);
const checkpoint = db.prepare("PRAGMA wal_checkpoint(PASSIVE)");
// Every attempt is reported, so the main thread's watchdog sees a stall.
// A PASSIVE checkpoint copies the frames committed when it starts. Under a
// steady write load it rarely sees the WAL fully copied, and SQLite only
// rewinds the WAL to its start when a writer finds it fully copied, so the
// WAL would grow for as long as writes continue. While a pass leaves frames
// behind, the worker runs again right away (bounded), keeping the copy close
// behind the writer so the WAL keeps rewinding.
function pass(id) {
  try {
    let r;
    for (let i = 0; i < 32; i++) {
      r = checkpoint.all()[0];
      if (Number(r.log) <= Number(r.checkpointed)) break;
    }
    parentPort.postMessage({ t: "ckpt", ok: true, busy: Number(r.busy), log: Number(r.log), checkpointed: Number(r.checkpointed), ...(id !== undefined ? { id } : {}) });
  } catch (e) {
    parentPort.postMessage({ t: "ckpt", ok: false, error: String(e && e.message), ...(id !== undefined ? { id } : {}) });
  }
}
let timer = setInterval(pass, workerData.intervalMs);
parentPort.on("message", (m) => {
  // Test hook: one pass now, its report tagged with the id (it sees every commit made before).
  if (m && m.t === "pass") pass(m.id);
  if (m === "stall") {
    // Test hook: stop checkpointing, as a wedged worker would. The reply comes
    // after every report already sent (the port keeps order).
    clearInterval(timer);
    timer = undefined;
    parentPort.postMessage({ t: "stalled" });
  }
  if (m === "stop") {
    clearInterval(timer);
    try { db.close(); } catch {}
    // Tell the (blocked) main thread this connection is gone.
    Atomics.store(flags, 0, 1);
    Atomics.notify(flags, 0);
  }
});
`;

export class SqliteStore implements Store {
  private readonly db: DatabaseSync;
  private readonly q: Record<string, StatementSync>;
  private closed = false;
  private txDepth = 0;
  private checkpointer?: Worker;
  /** Shared with the checkpoint worker: [0] becomes 1 once its connection is closed. */
  private checkpointerFlags?: Int32Array;
  private readonly path: string;
  private readonly opts: SqliteStoreOptions;
  private watchdog?: NodeJS.Timeout;
  /** When the worker last reported a completed checkpoint (wall-clock ms). */
  private lastCheckpointAt: number;
  /** True while SQLite's in-commit autocheckpoint is back on (no healthy worker). */
  private autocheckpointOn = true;
  /** Bytes across every invite: the sum of `invite_iss`, kept by issAdd (a counter read, not a scan of the blobs). */
  private inviteTotal = 0;
  /** issAdd deltas of the open transaction, applied to inviteTotal on commit. */
  private inviteDelta = 0;

  constructor(path: string, opts: SqliteStoreOptions = {}) {
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA secure_delete = ON; PRAGMA busy_timeout = 5000;");
    this.db.exec(SCHEMA);
    this.db.exec(`PRAGMA journal_size_limit = ${Math.trunc(opts.journalSizeLimitBytes ?? JOURNAL_SIZE_LIMIT)}`);
    this.path = path;
    this.opts = opts;
    this.lastCheckpointAt = this.now();
    if (path !== ":memory:" && opts.backgroundCheckpoint !== false) {
      this.startCheckpointer();
      const every = Math.max(50, Math.min(1000, Math.floor((opts.checkpointWatchdogMs ?? CHECKPOINT_WATCHDOG_MS) / 3)));
      this.watchdog = setInterval(() => this.checkWatchdog(), every);
      this.watchdog.unref();
    }
    // One row per userId holding invites, not per invite; init() rebuilds it exactly.
    this.inviteTotal = Number((this.db.prepare("SELECT coalesce(sum(bytes), 0) AS b FROM invite_iss").get() as { b: number }).b);
    const row = this.db.prepare("SELECT v FROM meta WHERE k = 'schema'").get() as { v: string } | undefined;
    if (!row) this.db.prepare("INSERT INTO meta (k, v) VALUES ('schema', ?)").run(String(SCHEMA_VERSION));
    else if (Number(row.v) !== SCHEMA_VERSION) throw new Error(`relay db schema ${row.v}, this relay understands ${SCHEMA_VERSION}`);

    const trace = opts.trace;
    const p = (sql: string): StatementSync => {
      const st = this.db.prepare(sql);
      if (!trace) return st;
      return {
        run: (...a: never[]) => (trace(sql), st.run(...a)),
        get: (...a: never[]) => (trace(sql), st.get(...a)),
        all: (...a: never[]) => (trace(sql), st.all(...a)),
      } as unknown as StatementSync;
    };
    this.q = {
      getMeta: p("SELECT v FROM meta WHERE k = ?"),
      setMeta: p("INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)"),
      deviceIssuer: p("SELECT iss FROM devices WHERE did = ?"),
      touchDevice: p(
        "INSERT INTO devices (did, iss, last_seen) VALUES (?, ?, ?) ON CONFLICT (did) DO UPDATE SET last_seen = excluded.last_seen WHERE devices.iss = excluded.iss",
      ),
      evictableDevices: p(
        `SELECT did, iss, last_seen FROM devices WHERE evictable = 1 AND (last_seen > ? OR (last_seen = ? AND did > ?))
         ORDER BY last_seen ASC, did ASC LIMIT ?`,
      ),
      refreshEvictable: p(
        `UPDATE devices SET evictable = (
           NOT EXISTS (SELECT 1 FROM totals t WHERE t.kind = 'mbox' AND t.key = devices.iss || char(10) || devices.did)
           AND NOT EXISTS (SELECT 1 FROM allowed_devices a WHERE a.did = devices.did AND a.iss = devices.iss))
         WHERE did = ?`,
      ),
      refreshEvictableRange: p(
        `UPDATE devices SET evictable = (
           NOT EXISTS (SELECT 1 FROM totals t WHERE t.kind = 'mbox' AND t.key = devices.iss || char(10) || devices.did)
           AND NOT EXISTS (SELECT 1 FROM allowed_devices a WHERE a.did = devices.did AND a.iss = devices.iss))
         WHERE rowid > ? AND rowid <= ?`,
      ),
      maxDeviceRowid: p("SELECT coalesce(max(rowid), 0) AS m FROM devices"),
      allowedOf: p("SELECT did FROM allowed_devices WHERE iss = ?"),
      clearAllowed: p("DELETE FROM allowed_devices WHERE iss = ?"),
      addAllowed: p("INSERT OR IGNORE INTO allowed_devices (did, iss) VALUES (?, ?)"),
      chunk: p("SELECT rid, mbox_to, mbox_did, src, size FROM envelopes WHERE rid > ? ORDER BY rid ASC LIMIT ?"),
      expired: p("SELECT rid, mbox_to, mbox_did, src, size FROM envelopes WHERE received_at < ? ORDER BY received_at ASC LIMIT ?"),

      deleteDevice: p("DELETE FROM devices WHERE did = ?"),
      insertEnv: p("INSERT INTO envelopes (mbox_to, mbox_did, src, size, received_at, env) VALUES (?, ?, ?, ?, ?, ?)"),
      envMeta: p("SELECT rid, mbox_to, mbox_did, src, size FROM envelopes WHERE rid = ?"),
      deleteRid: p("DELETE FROM envelopes WHERE rid = ?"),
      total: p("SELECT bytes, n FROM totals WHERE kind = ? AND key = ?"),
      bump: p(
        "INSERT INTO totals (kind, key, bytes, n) VALUES (?, ?, ?, ?) ON CONFLICT (kind, key) DO UPDATE SET bytes = bytes + excluded.bytes, n = n + excluded.n",
      ),
      dropEmpty: p("DELETE FROM totals WHERE kind = ? AND key = ? AND n <= 0"),
      topSrc: p("SELECT key, bytes FROM totals WHERE kind = 'src' ORDER BY bytes DESC LIMIT 32"),
      countSrc: p("SELECT count(*) AS n FROM totals WHERE kind = 'src'"),
      rsrcOf: p("SELECT key, bytes FROM totals WHERE kind = 'rsrc' AND key > ? AND key < ?"),
      largestUnder: p("SELECT key FROM totals WHERE kind = ? AND key > ? AND key < ? ORDER BY bytes DESC LIMIT 1"),
      mboxOldest: p("SELECT rid, mbox_to, mbox_did, src, size FROM envelopes WHERE mbox_to = ? AND mbox_did = ? ORDER BY rid ASC LIMIT ?"),
      srcMboxOldest: p(
        "SELECT rid, mbox_to, mbox_did, src, size FROM envelopes WHERE src = ? AND mbox_to = ? AND mbox_did = ? ORDER BY rid ASC LIMIT 64",
      ),
      toSrcOldest: p("SELECT rid, mbox_to, mbox_did, src, size FROM envelopes WHERE mbox_to = ? AND src = ? ORDER BY rid ASC LIMIT 64"),
      envAfter: p(
        "SELECT rid, mbox_to, mbox_did, env, size, received_at FROM envelopes WHERE mbox_to = ? AND mbox_did = ? AND rid > ? AND received_at >= ? ORDER BY rid ASC LIMIT ?",
      ),
      capState: p("SELECT revoked, uses FROM caps WHERE key = ?"),
      revokeCap: p(
        "INSERT INTO caps (key, revoked, uses, updated_at) VALUES (?, 1, 0, ?) ON CONFLICT (key) DO UPDATE SET revoked = 1, updated_at = excluded.updated_at",
      ),
      useCap: p(
        "INSERT INTO caps (key, revoked, uses, updated_at) VALUES (?, 0, 1, ?) ON CONFLICT (key) DO UPDATE SET uses = uses + 1, updated_at = excluded.updated_at",
      ),
      doc: p("SELECT * FROM identity_docs WHERE hash = ?"),
      docs: p("SELECT * FROM identity_docs WHERE iss = ? ORDER BY ver ASC"),
      putDoc: p(
        "INSERT OR IGNORE INTO identity_docs (hash, iss, ver, prev, merge, devices, iat, exp, received_at, jws) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      ),
      deleteDoc: p("DELETE FROM identity_docs WHERE hash = ?"),
      index: p("SELECT * FROM identity_index WHERE iss = ?"),
      putIndex: p(
        "INSERT OR REPLACE INTO identity_index (iss, head, head_ver, head_exp, tips, allowed, cap, left_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      ),
      deleteIdentityDocs: p("DELETE FROM identity_docs WHERE iss = ?"),
      deleteIndex: p("DELETE FROM identity_index WHERE iss = ?"),
      seenOf: p("SELECT did FROM identity_seen WHERE iss = ? AND at >= ?"),
      addSeen: p("INSERT OR REPLACE INTO identity_seen (iss, did, at) VALUES (?, ?, ?)"),
      trimSeen: p(
        "DELETE FROM identity_seen WHERE iss = ? AND did NOT IN (SELECT did FROM identity_seen WHERE iss = ? ORDER BY at DESC, did LIMIT ?)",
      ),
      clearSeen: p("DELETE FROM identity_seen WHERE iss = ?"),
      sweepSeen: p("DELETE FROM identity_seen WHERE rowid IN (SELECT rowid FROM identity_seen WHERE at < ? LIMIT ?)"),
      expiredIdentities: p("SELECT iss FROM identity_index WHERE left_at IS NULL AND head_exp < ? LIMIT ?"),
      staleTombstones: p("SELECT iss FROM identity_index WHERE left_at IS NOT NULL AND left_at < ? LIMIT ?"),
      sweepCaps: p("DELETE FROM caps WHERE rowid IN (SELECT rowid FROM caps WHERE updated_at < ? LIMIT ?)"),
      sweepDocCandidates: p(
        `SELECT d.hash, d.iss, d.devices FROM identity_docs d WHERE d.received_at < ? AND (
           EXISTS (SELECT 1 FROM identity_docs c WHERE c.prev = d.hash)
           OR EXISTS (SELECT 1 FROM identity_docs c WHERE c.merge = d.hash))
         LIMIT ?`,
      ),
      sweepDocs: p(
        `DELETE FROM identity_docs WHERE rowid IN (
           SELECT d.rowid FROM identity_docs d WHERE d.received_at < ? AND (
             EXISTS (SELECT 1 FROM identity_docs c WHERE c.prev = d.hash)
             OR EXISTS (SELECT 1 FROM identity_docs c WHERE c.merge = d.hash))
           LIMIT ?)`,
      ),
      sweepDevices: p("DELETE FROM devices WHERE rowid IN (SELECT rowid FROM devices WHERE last_seen < ? LIMIT ?)"),
      countDevices: p("SELECT count(*) AS n FROM devices"),
      countDocs: p("SELECT count(*) AS n FROM identity_docs"),
      ping: p("SELECT 1 AS ok"),
      putInvite: p("INSERT OR IGNORE INTO invites (lid, iss, blob, size, created_at, expires_at, src) VALUES (?, ?, ?, ?, ?, ?, ?)"),
      getInvite: p("SELECT lid, iss, blob, size, created_at, expires_at, src FROM invites WHERE lid = ?"),
      inviteBytesOfSrc: p("SELECT coalesce(sum(size), 0) AS b FROM invites WHERE src = ?"),
      inviteTopIss: p("SELECT iss FROM invite_iss ORDER BY bytes DESC, iss LIMIT 1"),
      issAdd: p("INSERT INTO invite_iss (iss, bytes) VALUES (?, ?) ON CONFLICT (iss) DO UPDATE SET bytes = bytes + excluded.bytes"),
      issClean: p("DELETE FROM invite_iss WHERE iss = ? AND bytes <= 0"),
      issBytes: p("SELECT bytes FROM invite_iss WHERE iss = ?"),
      inviteChunk: p("SELECT rowid AS rid, iss, size FROM invites WHERE rowid > ? ORDER BY rowid LIMIT ?"),
      expiredInvites: p("SELECT lid, iss, size FROM invites WHERE expires_at <= ? ORDER BY expires_at, lid LIMIT ?"),
      addEvicted: p("INSERT OR REPLACE INTO invite_evicted (lid, iss, expires_at) VALUES (?, ?, ?)"),
      evictedOf: p("SELECT lid FROM invite_evicted WHERE iss = ? AND expires_at > ?"),
      sweepEvicted: p("DELETE FROM invite_evicted WHERE rowid IN (SELECT rowid FROM invite_evicted WHERE expires_at <= ? ORDER BY expires_at LIMIT ?)"),
      inviteNewestOf: p("SELECT lid, size, expires_at FROM invites WHERE iss = ? ORDER BY created_at DESC, lid DESC LIMIT 1"),
      getInviteOwner: p("SELECT iss, size FROM invites WHERE lid = ? AND iss = ?"),
      delInvite: p("DELETE FROM invites WHERE lid = ?"),
      delInviteOf: p("DELETE FROM invites WHERE lid = ? AND iss = ?"),
      invitesOf: p("SELECT lid FROM invites WHERE iss = ? AND expires_at > ? ORDER BY created_at, lid"),
    };
  }

  /**
   * Startup (N-M1): rebuilds `totals`, `allowed_devices` and the devices'
   * `evictable` flags, reading in chunks and yielding between them, so no
   * single step blocks for long. Old rows keep their (now anonymous) source
   * tags (R-M1). The relay calls this before it accepts connections.
   */
  async init(): Promise<void> {
    const CHUNK = 2000;
    // Earlier versions kept a persisted source key; never keep one (N-M3).
    this.db.exec("DELETE FROM meta WHERE k IN ('src_key', 'src_key_at')");
    const acc = new Map<string, { kind: string; key: string; bytes: number; n: number }>();
    let after = 0;
    for (;;) {
      const rows = this.q.chunk.all(after, CHUNK) as unknown as EnvMeta[];
      if (rows.length === 0) break;
      for (const r of rows) {
        for (const [kind, key] of totalKeys(r.mbox_to, r.mbox_did, r.src)) {
          const k = `${kind}\u0000${key}`;
          const t = acc.get(k) ?? { kind, key, bytes: 0, n: 0 };
          t.bytes += Number(r.size);
          t.n += 1;
          acc.set(k, t);
        }
      }
      after = Number(rows[rows.length - 1].rid);
      await new Promise((res) => setImmediate(res));
    }
    const entries = [...acc.values()];
    this.tx(() => this.db.exec("DELETE FROM totals"));
    for (let i = 0; i < entries.length; i += CHUNK) {
      this.tx(() => {
        for (const t of entries.slice(i, i + CHUNK)) this.q.bump.run(t.kind, t.key, t.bytes, t.n);
      });
      await new Promise((res) => setImmediate(res));
    }
    this.tx(() => {
      this.db.exec("DELETE FROM allowed_devices");
      const rows = this.db.prepare("SELECT iss, allowed FROM identity_index").all() as { iss: string; allowed: string }[];
      for (const r of rows) for (const did of JSON.parse(r.allowed) as string[]) this.q.addAllowed.run(did, r.iss);
    });
    const maxRowid = Number((this.q.maxDeviceRowid.get() as { m: number }).m);
    for (let lo = 0; lo < maxRowid; lo += CHUNK) {
      this.tx(() => this.q.refreshEvictableRange.run(lo, lo + CHUNK));
      await new Promise((res) => setImmediate(res));
    }
    // Per-userId invite totals, rebuilt from the invites in chunks (every
    // write keeps them after; this repairs anything a crash could leave).
    const issAcc = new Map<string, number>();
    let inv = 0;
    for (;;) {
      const rows = this.q.inviteChunk.all(inv, CHUNK) as { rid: number; iss: string; size: number }[];
      if (rows.length === 0) break;
      for (const r of rows) issAcc.set(r.iss, (issAcc.get(r.iss) ?? 0) + Number(r.size));
      inv = Number(rows[rows.length - 1].rid);
      await new Promise((res) => setImmediate(res));
    }
    const issRows = [...issAcc];
    this.tx(() => {
      this.db.exec("DELETE FROM invite_iss");
      for (const [iss, bytes] of issRows) this.q.issAdd.run(iss, bytes);
    });
    this.inviteTotal = issRows.reduce((a, [, b]) => a + b, 0);
  }

  /** Re-entrant: an inner call joins the outer transaction. */
  private tx<T>(fn: () => T): T {
    if (this.txDepth > 0) {
      this.txDepth++;
      try {
        return fn();
      } finally {
        this.txDepth--;
      }
    }
    this.db.exec("BEGIN IMMEDIATE");
    this.txDepth = 1;
    this.inviteDelta = 0;
    try {
      const out = fn();
      this.db.exec("COMMIT");
      this.inviteTotal += this.inviteDelta;
      return out;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    } finally {
      this.txDepth = 0;
      this.inviteDelta = 0;
    }
  }

  transaction<T>(fn: () => T): T {
    return this.tx(fn);
  }

  getMeta(key: string): string | undefined {
    return (this.q.getMeta.get(key) as { v: string } | undefined)?.v;
  }

  setMeta(key: string, value: string): void {
    this.q.setMeta.run(key, value);
  }

  deviceIssuer(did: string): string | undefined {
    const r = this.q.deviceIssuer.get(did) as { iss: string } | undefined;
    return r?.iss;
  }

  touchDevice(did: string, iss: string, now: number): boolean {
    const existed = this.q.deviceIssuer.get(did) !== undefined;
    this.q.touchDevice.run(did, iss, now);
    if (!existed) this.q.refreshEvictable.run(did);
    return !existed;
  }

  evictableDevices(limit: number, after?: { lastSeen: number; did: string }): { did: string; iss: string; lastSeen: number }[] {
    const ls = after?.lastSeen ?? -1;
    const rows = this.q.evictableDevices.all(ls, ls, after?.did ?? "", limit) as { did: string; iss: string; last_seen: number }[];
    return rows.map((r) => ({ did: r.did, iss: r.iss, lastSeen: Number(r.last_seen) }));
  }

  deleteDevice(did: string): void {
    this.q.deleteDevice.run(did);
  }

  // -------------------------------------------------------------------------
  // Envelopes and their totals

  private bumpTotals(to: string, tdid: string, src: string, size: number, sign: 1 | -1): void {
    for (const [kind, key] of totalKeys(to, tdid, src)) {
      this.q.bump.run(kind, key, sign * size, sign);
      if (sign < 0) this.q.dropEmpty.run(kind, key);
    }
    // R-L2: a mailbox gaining its first or losing its last envelope flips
    // whether its device binding may be evicted.
    const n = this.total("mbox", `${to}\n${tdid}`).n;
    if ((sign > 0 && n === 1) || (sign < 0 && n === 0)) this.q.refreshEvictable.run(tdid);
  }

  private total(kind: string, key: string): { bytes: number; n: number } {
    const r = this.q.total.get(kind, key) as { bytes: number; n: number } | undefined;
    return { bytes: Number(r?.bytes ?? 0), n: Number(r?.n ?? 0) };
  }

  private deleteEnv(m: EnvMeta): number {
    this.q.deleteRid.run(m.rid);
    const size = Number(m.size);
    this.bumpTotals(m.mbox_to, m.mbox_did, m.src, size, -1);
    return size;
  }

  /** The oldest envelopes of source `src` in mailbox (to, tdid). */
  private srcMailboxOldest(src: string, to: string, tdid: string): EnvMeta[] {
    return this.q.srcMboxOldest.all(src, to, tdid) as unknown as EnvMeta[];
  }

  /** Frees bytes from source `src`'s largest mailbox; 0 when the source holds nothing. */
  private evictFromSource(src: string, bytes: number): number {
    const mbox = this.largestUnder("smbox", src);
    if (mbox === undefined) return 0;
    const [to, tdid] = mbox.split("\n");
    let freed = 0;
    for (const r of this.srcMailboxOldest(src, to, tdid)) {
      if (freed >= bytes) break;
      freed += this.deleteEnv(r);
    }
    return freed;
  }

  /** Largest key of `kind` starting with `prefix + "\n"`, by bytes. */
  private largestUnder(kind: string, prefix: string): string | undefined {
    const r = this.q.largestUnder.get(kind, `${prefix}\n`, `${prefix}\u000b`) as { key: string } | undefined;
    return r?.key.slice(prefix.length + 1);
  }

  putEnvelope(e: NewEnvelope, caps: MailboxCaps): { rid: number; dropped: number; droppedBytes: number } {
    return this.tx(() => {
      const res = this.q.insertEnv.run(e.to, e.tdid, e.src, e.size, e.receivedAt, e.env);
      const rid = Number(res.lastInsertRowid);
      this.bumpTotals(e.to, e.tdid, e.src, e.size, 1);
      let { n, bytes } = this.total("mbox", `${e.to}\n${e.tdid}`);
      let dropped = 0;
      let droppedBytes = 0;
      while (n > caps.maxEnvelopes || bytes > caps.maxBytes) {
        const rows = this.q.mboxOldest.all(e.to, e.tdid, 64) as unknown as EnvMeta[];
        if (rows.length === 0) break;
        for (const r of rows) {
          if (n <= caps.maxEnvelopes && bytes <= caps.maxBytes) break;
          const size = this.deleteEnv(r);
          n--;
          bytes -= size;
          droppedBytes += size;
          dropped++;
        }
      }
      return { rid, dropped, droppedBytes };
    });
  }

  envelopesAfter(to: string, tdid: string, afterRid: number, notBefore: number, limit: number): StoredEnvelope[] {
    const rows = this.q.envAfter.all(to, tdid, afterRid, notBefore, limit) as {
      rid: number;
      mbox_to: string;
      mbox_did: string;
      env: string;
      size: number;
      received_at: number;
    }[];
    return rows.map((r) => ({
      rid: Number(r.rid),
      to: r.mbox_to,
      tdid: r.mbox_did,
      env: r.env,
      size: Number(r.size),
      receivedAt: Number(r.received_at),
    }));
  }

  ackEnvelopes(to: string, tdid: string, rids: readonly number[]): { count: number; bytes: number } {
    if (rids.length === 0) return { count: 0, bytes: 0 };
    return this.tx(() => {
      let count = 0;
      let bytes = 0;
      for (const rid of rids) {
        const m = this.q.envMeta.get(rid) as EnvMeta | undefined;
        if (!m || m.mbox_to !== to || m.mbox_did !== tdid) continue;
        bytes += this.deleteEnv(m);
        count++;
      }
      return { count, bytes };
    });
  }

  bytesForRecipient(to: string): number {
    return this.total("rcpt", to).bytes;
  }

  mailboxBytes(to: string, tdid: string): number {
    return this.total("mbox", `${to}\n${tdid}`).bytes;
  }

  evictRecipient(to: string, bytes: number, policy: EvictPolicy = {}): number {
    return this.tx(() => {
      let freed = 0;
      while (freed < bytes) {
        // Per EvictPolicy (F-6): the sender if over its fair share, else the largest group above the floor, else the largest.
        const rows = this.q.rsrcOf.all(`${to}\n`, `${to}\u000b`) as { key: string; bytes: number }[];
        const src = pickSource(
          rows.map((r) => ({ src: r.key.slice(to.length + 1), bytes: Number(r.bytes) })),
          policy,
        );
        if (src === undefined) break;
        const victims = this.q.toSrcOldest.all(to, src) as unknown as EnvMeta[];
        if (victims.length === 0) break;
        for (const r of victims) {
          if (freed >= bytes) break;
          freed += this.deleteEnv(r);
        }
      }
      return freed;
    });
  }

  /**
   * The source group to evict from, per EvictPolicy, from counters only: the
   * largest groups by the bytes index, plus the sender's own total.
   */
  private pickGlobalSource(policy: EvictPolicy): string | undefined {
    const cands = (this.q.topSrc.all() as { key: string; bytes: number }[]).map((r) => ({ src: r.key, bytes: Number(r.bytes) }));
    if (policy.sender !== undefined && !cands.some((c) => c.src === policy.sender)) {
      cands.push({ src: policy.sender, bytes: this.total("src", policy.sender).bytes });
    }
    const groups = Number((this.q.countSrc.get() as { n: number }).n);
    return pickSource(cands, policy, groups);
  }

  evictGlobal(bytes: number, policy: EvictPolicy = {}): number {
    return this.tx(() => {
      let freed = 0;
      while (freed < bytes) {
        // Per EvictPolicy (sender first, then the largest above the floor);
        // within the chosen source, the oldest of its largest mailbox.
        const src = this.pickGlobalSource(policy);
        if (src === undefined) break;
        const got = this.evictFromSource(src, bytes - freed);
        if (got === 0) break;
        freed += got;
      }
      return freed;
    });
  }

  sourceBytes(src: string): number {
    return this.total("src", src).bytes;
  }

  evictSource(src: string, bytes: number): number {
    return this.tx(() => {
      let freed = 0;
      while (freed < bytes) {
        const got = this.evictFromSource(src, bytes - freed);
        if (got === 0) break;
        freed += got;
      }
      return freed;
    });
  }

  expireBatch(before: number, limit: number): { count: number; bytes: number } {
    return this.tx(() => {
      const rows = this.q.expired.all(before, limit) as unknown as EnvMeta[];
      let bytes = 0;
      for (const r of rows) bytes += this.deleteEnv(r);
      return { count: rows.length, bytes };
    });
  }

  // -------------------------------------------------------------------------

  capState(key: string): CapState {
    const r = this.q.capState.get(key) as { revoked: number; uses: number } | undefined;
    return { revoked: Number(r?.revoked ?? 0) === 1, uses: Number(r?.uses ?? 0) };
  }

  revokeCap(key: string, now: number): void {
    this.q.revokeCap.run(key, now);
  }

  useCap(key: string, now: number): void {
    this.q.useCap.run(key, now);
  }

  identityDoc(hash: string): StoredIdentityDoc | undefined {
    const r = this.q.doc.get(hash) as DocRow | undefined;
    return r ? docFromRow(r) : undefined;
  }

  identityDocs(iss: string): StoredIdentityDoc[] {
    return (this.q.docs.all(iss) as unknown as DocRow[]).map(docFromRow);
  }

  putIdentityDoc(d: StoredIdentityDoc): boolean {
    const res = this.q.putDoc.run(d.hash, d.iss, d.ver, d.prev, d.merge, JSON.stringify(d.devices), d.iat, d.exp, d.receivedAt, d.jws);
    return Number(res.changes) === 1;
  }

  deleteIdentityDocs(hashes: readonly string[]): void {
    if (hashes.length === 0) return;
    this.tx(() => {
      for (const h of hashes) this.q.deleteDoc.run(h);
    });
  }

  identityIndex(iss: string): IdentityIndex | undefined {
    const r = this.q.index.get(iss) as IndexRow | undefined;
    if (!r) return undefined;
    return {
      iss: r.iss,
      head: r.head,
      headVer: Number(r.head_ver),
      headExp: Number(r.head_exp),
      tips: JSON.parse(r.tips) as string[],
      allowed: JSON.parse(r.allowed) as string[],
      cap: r.cap === null ? null : (JSON.parse(r.cap) as string[]),
      leftAt: r.left_at === null ? null : Number(r.left_at),
    };
  }

  putIdentityIndex(i: IdentityIndex): void {
    this.tx(() => {
      const before = (this.q.allowedOf.all(i.iss) as { did: string }[]).map((r) => r.did);
      this.q.clearAllowed.run(i.iss);
      for (const did of i.allowed) this.q.addAllowed.run(did, i.iss);
      this.putIndexRow(i);
      for (const did of new Set([...before, ...i.allowed])) this.q.refreshEvictable.run(did);
    });
  }

  private putIndexRow(i: IdentityIndex): void {
    this.q.putIndex.run(
      i.iss,
      i.head,
      i.headVer,
      i.headExp,
      JSON.stringify(i.tips),
      JSON.stringify(i.allowed),
      i.cap === null ? null : JSON.stringify(i.cap),
      i.leftAt,
    );
  }

  deleteIdentityDocsOf(iss: string): void {
    this.q.deleteIdentityDocs.run(iss);
  }

  deleteIdentity(iss: string): void {
    this.tx(() => {
      const before = (this.q.allowedOf.all(iss) as { did: string }[]).map((r) => r.did);
      this.q.deleteIdentityDocs.run(iss);
      this.q.deleteIndex.run(iss);
      this.q.clearAllowed.run(iss);
      this.q.clearSeen.run(iss);
      for (const did of before) this.q.refreshEvictable.run(did);
    });
  }

  /**
   * Sweeps at most `limit` old non-tip versions (F-4: bounded steps); their
   * dids outside the allowlist are remembered first (R4-M1).
   */
  private sweepIdentityDocs(c: SweepCutoffs, limit: number): number {
    const rows = this.q.sweepDocCandidates.all(c.identityVersionsBefore, limit) as { hash: string; iss: string; devices: string }[];
    if (c.nowMs !== undefined) {
      const byIss = new Map<string, Set<string>>();
      for (const r of rows) {
        let set = byIss.get(r.iss);
        if (!set) byIss.set(r.iss, (set = new Set()));
        for (const d of JSON.parse(r.devices) as string[]) set.add(d);
      }
      for (const [iss, dids] of byIss) {
        const allowed = new Set((this.q.allowedOf.all(iss) as { did: string }[]).map((r) => r.did));
        const gone = [...dids].filter((d) => !allowed.has(d));
        if (gone.length > 0) this.addSeen(iss, gone, c.nowMs);
      }
    }
    for (const r of rows) this.q.deleteDoc.run(r.hash);
    return rows.length;
  }

  seenDevices(iss: string, sinceMs: number): string[] {
    return (this.q.seenOf.all(iss, sinceMs) as { did: string }[]).map((r) => r.did);
  }

  addSeen(iss: string, dids: readonly string[], at: number): void {
    if (dids.length === 0) return;
    this.tx(() => {
      for (const d of dids) this.q.addSeen.run(iss, d, at);
      this.q.trimSeen.run(iss, iss, MAX_SEEN_PER_ISS);
    });
  }

  expiredIdentities(headExpBeforeSec: number, limit: number): string[] {
    return (this.q.expiredIdentities.all(headExpBeforeSec, limit) as { iss: string }[]).map((r) => r.iss);
  }

  staleTombstones(leftBefore: number, limit: number): string[] {
    return (this.q.staleTombstones.all(leftBefore, limit) as { iss: string }[]).map((r) => r.iss);
  }

  private issAdd(iss: string, d: number): void {
    this.q.issAdd.run(iss, d);
    // Applied to inviteTotal only when the outermost transaction commits, so
    // a rollback leaves the counter matching the table.
    if (this.txDepth > 0) this.inviteDelta += d;
    else this.inviteTotal += d;
    if (d < 0) this.q.issClean.run(iss);
  }

  putInvite(i: StoredInvite): boolean {
    return this.tx(() => {
      const ok = Number(this.q.putInvite.run(i.lid, i.iss, i.blob, i.size, i.createdAt, i.expiresAt, i.src).changes) === 1;
      if (ok) this.issAdd(i.iss, i.size);
      return ok;
    });
  }

  takeInvite(lid: string, now: number): StoredInvite | undefined {
    return this.tx(() => {
      const r = this.q.getInvite.get(lid) as { lid: string; iss: string; blob: string; size: number; created_at: number; expires_at: number; src: string } | undefined;
      if (!r) return undefined;
      this.q.delInvite.run(lid);
      this.issAdd(r.iss, -Number(r.size));
      const i: StoredInvite = { lid: r.lid, iss: r.iss, blob: r.blob, size: Number(r.size), createdAt: Number(r.created_at), expiresAt: Number(r.expires_at), src: r.src };
      return i.expiresAt > now ? i : undefined;
    });
  }

  deleteInvite(lid: string, iss: string): boolean {
    return this.tx(() => {
      const r = this.q.getInviteOwner.get(lid, iss) as { iss: string; size: number } | undefined;
      if (!r) return false;
      this.q.delInviteOf.run(lid, iss);
      this.issAdd(iss, -Number(r.size));
      return true;
    });
  }

  invitesOf(iss: string, now: number): string[] {
    return (this.q.invitesOf.all(iss, now) as { lid: string }[]).map((r) => r.lid);
  }

  evictedInvitesOf(iss: string, now: number): string[] {
    return (this.q.evictedOf.all(iss, now) as { lid: string }[]).map((r) => r.lid);
  }

  inviteBytes(): number {
    return this.inviteTotal;
  }

  inviteBytesOfIss(iss: string): number {
    const r = this.q.issBytes.get(iss) as { bytes: number } | undefined;
    return r ? Number(r.bytes) : 0;
  }

  sweepInvites(now: number, limit: number): { invites: number; evicted: number } {
    return this.tx(() => {
      const rows = this.q.expiredInvites.all(now, limit) as { lid: string; iss: string; size: number }[];
      for (const r of rows) {
        this.q.delInvite.run(r.lid);
        this.issAdd(r.iss, -Number(r.size));
      }
      return { invites: rows.length, evicted: Number(this.q.sweepEvicted.run(now, limit).changes) };
    });
  }

  inviteBytesOfSrc(src: string): number {
    return Number((this.q.inviteBytesOfSrc.get(src) as { b: number }).b);
  }

  evictInvites(bytes: number, now?: number): number {
    return this.tx(() => {
      let freed = 0;
      // Already-expired invites first: one row per step, only as many as `bytes` needs.
      while (now !== undefined && freed < bytes) {
        const r = this.q.expiredInvites.get(now, 1) as { lid: string; iss: string; size: number } | undefined;
        if (!r) break;
        this.q.delInvite.run(r.lid);
        this.issAdd(r.iss, -Number(r.size));
        freed += Number(r.size);
      }
      while (freed < bytes) {
        const top = this.q.inviteTopIss.get() as { iss: string } | undefined;
        if (!top) break;
        const n = this.q.inviteNewestOf.get(top.iss) as { lid: string; size: number; expires_at: number } | undefined;
        if (!n) {
          // A stale counter (can't happen while every write keeps it): drop it and go on.
          this.issAdd(top.iss, -this.inviteBytesOfIss(top.iss));
          continue;
        }
        this.q.delInvite.run(n.lid);
        this.issAdd(top.iss, -Number(n.size));
        this.q.addEvicted.run(n.lid, top.iss, Number(n.expires_at));
        freed += Number(n.size);
      }
      return freed;
    });
  }

  envelopeTotals(): { envelopes: number; bytes: number } {
    const t = this.total("all", "");
    return { envelopes: t.n, bytes: t.bytes };
  }

  sweep(c: SweepCutoffs, limit: number): SweepResult {
    // Envelopes expire separately, in batches (expireBatch).
    return this.tx(() => ({
      caps: Number(this.q.sweepCaps.run(c.capsBefore, limit).changes),
      identityDocs: this.sweepIdentityDocs(c, limit),
      ...(c.seenBefore !== undefined ? { seen: Number(this.q.sweepSeen.run(c.seenBefore, limit).changes) } : {}),
      devices: Number(this.q.sweepDevices.run(c.devicesBefore, limit).changes),
    }));
  }

  counts(): StoreCounts {
    const e = this.total("all", "");
    const d = this.q.countDevices.get() as { n: number };
    const i = this.q.countDocs.get() as { n: number };
    return { envelopes: e.n, envelopeBytes: e.bytes, devices: Number(d.n), identityDocs: Number(i.n) };
  }

  ping(): boolean {
    const r = this.q.ping.get() as { ok: number } | undefined;
    return Number(r?.ok) === 1;
  }

  private setAutocheckpoint(on: boolean): void {
    if (this.closed || this.autocheckpointOn === on) return;
    this.db.exec(`PRAGMA wal_autocheckpoint = ${on ? 1000 : 0}`);
    this.autocheckpointOn = on;
  }

  /**
   * Starts the checkpoint worker. SQLite's in-commit autocheckpoint stays on
   * until the worker reports its first completed checkpoint, and comes back
   * whenever the worker dies or stalls, so the WAL is never left unchecked.
   */
  private startCheckpointer(): void {
    const flags = new Int32Array(new SharedArrayBuffer(4));
    this.checkpointerFlags = flags;
    const w = new Worker(CHECKPOINT_WORKER, {
      eval: true,
      workerData: {
        path: this.path,
        intervalMs: this.opts.checkpointIntervalMs ?? CHECKPOINT_INTERVAL_MS,
        journalSizeLimit: Math.trunc(this.opts.journalSizeLimitBytes ?? JOURNAL_SIZE_LIMIT),
        flags: flags.buffer,
      },
    });
    w.unref();
    this.lastCheckpointAt = this.now();
    let prev: { log: number; checkpointed: number } | undefined;
    w.on("message", (m: { t?: string; ok?: boolean; busy?: number; log?: number; checkpointed?: number }) => {
      if (m?.t !== "ckpt" || this.checkpointer !== w) return;
      if (!m.ok) return;
      // A pass shows progress when it copied every frame, when it copied more
      // than the pass before, or when the WAL rewound (everything before was
      // copied). Under sustained writes a pass rarely ends fully caught up,
      // but it keeps advancing; a reader pinning an old snapshot stops it at
      // the same frame every time (L-3), which is a real stall. (A PASSIVE
      // pass reports busy = 0 even when a reader stops it short.)
      const log = Number(m.log);
      const checkpointed = Number(m.checkpointed);
      const progress = checkpointed === log || (prev !== undefined && (checkpointed > prev.checkpointed || log < prev.log));
      prev = { log, checkpointed };
      if (progress) {
        this.lastCheckpointAt = this.now();
        // Hand checkpoints back to the worker only while the WAL is in bounds.
        if (this.walBytes() <= (this.opts.walLimitBytes ?? WAL_LIMIT_BYTES)) this.setAutocheckpoint(false);
      }
    });
    const died = () => {
      if (this.checkpointer !== w) return;
      // Never let the WAL grow unchecked: back to SQLite's own checkpoints.
      this.checkpointer = undefined;
      this.setAutocheckpoint(true);
      this.opts.warn?.("relay checkpoint worker exited; SQLite autocheckpoint re-enabled");
    };
    w.on("error", died);
    w.on("exit", died);
    this.checkpointer = w;
  }

  private walBytes(): number {
    try {
      return statSync(`${this.path}-wal`).size;
    } catch {
      return 0;
    }
  }

  /**
   * pre-release review: if no checkpoint completed within the watchdog window, or the
   * WAL grew past its limit, turn SQLite's autocheckpoint back on, warn, and
   * restart the worker (it switches autocheckpoint off again once healthy).
   */
  private lastWarnAt = 0;

  private now(): number {
    return this.opts.now ? this.opts.now() : Date.now();
  }

  private warnOnce(msg: string, fields: Record<string, string | number | boolean>): void {
    const now = this.now();
    if (now - this.lastWarnAt < (this.opts.checkpointWatchdogMs ?? CHECKPOINT_WATCHDOG_MS)) return;
    this.lastWarnAt = now;
    this.opts.warn?.(msg, fields);
  }

  /** A backup's marker that is still in force (see BACKUP_MARKER_MAX_MS), or undefined. */
  private backupRunning(): { until: number } | undefined {
    const marker = `${this.path}-backup`;
    try {
      const st = statSync(marker);
      if (!st.isFile() || st.size > 1024) return undefined;
      const until = Number((JSON.parse(readFileSync(marker, "utf8")) as { until?: unknown }).until);
      const now = this.now();
      if (!Number.isFinite(until) || now >= until || now - st.mtimeMs > BACKUP_MARKER_MAX_MS) return undefined;
      return { until };
    } catch {
      return undefined;
    }
  }

  /** One watchdog check, as its timer runs it (tests call it after advancing their clock). */
  checkWatchdog(): void {
    if (this.closed) return;
    const limit = this.opts.walLimitBytes ?? WAL_LIMIT_BYTES;
    const stalledMs = this.now() - this.lastCheckpointAt;
    const wal = this.walBytes();
    const stalled = !this.checkpointer || stalledMs > (this.opts.checkpointWatchdogMs ?? CHECKPOINT_WATCHDOG_MS);
    if (this.checkpointer && (stalled || wal > limit) && this.backupRunning()) {
      // Held back by a backup's snapshot, not stalled: the worker keeps running and copies the
      // grown WAL off the main thread once the backup lets go. The time the backup held it is
      // excused, so the worker gets a full window after that.
      this.lastCheckpointAt = this.now();
      this.warnOnce("relay checkpoints held back by a running backup; the checkpoint worker catches up when it ends", { stalledMs, walBytes: wal });
      return;
    }
    if (stalled) {
      this.setAutocheckpoint(true);
      this.warnOnce("relay checkpoint worker stalled; autocheckpoint re-enabled, restarting the worker", { stalledMs, walBytes: wal });
      const old = this.checkpointer;
      this.checkpointer = undefined;
      if (old) {
        old.removeAllListeners();
        void old.terminate();
      }
      this.startCheckpointer();
    } else if (wal > limit) {
      // Checkpoints run but can't keep up (or a reader pins the WAL): let
      // commits checkpoint too until it is back under the limit.
      this.setAutocheckpoint(true);
      this.warnOnce("relay WAL over its limit; autocheckpoint re-enabled", { walBytes: wal, walLimitBytes: limit });
    }
  }

  /** For tests: the worker's identity and whether autocheckpoint is on. */
  checkpointState(): { worker: Worker | undefined; autocheckpoint: boolean } {
    return { worker: this.checkpointer, autocheckpoint: this.autocheckpointOn };
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    if (this.watchdog) clearInterval(this.watchdog);
    const w = this.checkpointer;
    this.checkpointer = undefined;
    if (w) {
      w.removeAllListeners("exit");
      w.removeAllListeners("error");
      // Close the worker's connection first, synchronously, so this
      // connection is the last one: its close then checkpoints and removes
      // the WAL itself, and nothing touches the files after close() returns.
      w.postMessage("stop");
      if (this.checkpointerFlags) Atomics.wait(this.checkpointerFlags, 0, 0, 2000);
      void w.terminate();
    }
    this.db.close();
  }
}
