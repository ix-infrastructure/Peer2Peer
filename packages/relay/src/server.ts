// Copyright 2026 Ix Infrastructure Inc.
//
// The Peer2Peer v3 relay (docs/protocol.md §5): a WebSocket endpoint at the
// configured path (default /v3) plus a few public HTTP GETs.
//
// The relay is dumb store-and-forward. It sees outer envelope fields,
// capabilities, identity documents and connection metadata, and enforces only
// device-signature auth, mailbox capabilities and rate limits. It never
// stores or logs envelope contents, capabilities, link data or invite blobs.
//
// Resource rule: every write path (envelopes, cap state, identity documents,
// device bindings, link mailboxes, invite mailboxes) has a rate limit and a
// size or count cap,
// and per-IP limits key IPv6 clients by /64.

import { createCipheriv, createDecipheriv, createHmac, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIPv4 } from "node:net";
import type { Duplex } from "node:stream";
import { readFileSync } from "node:fs";
import { monitorEventLoopDelay, type IntervalHistogram } from "node:perf_hooks";
import { b64uDecode, b64uEncode, randomBytes, sha256 } from "@peer2peer/core";
import { WebSocketServer, WebSocket, type RawData } from "ws";
import type { RelayConfig } from "./config.js";
import { createRelayCrypto, type RelayCrypto, type VerifiedCap, type VerifiedDeviceCert, type OuterEnvelope } from "./crypto.js";
import { IdentityService } from "./identity.js";
import { LID_RE, LinkMailboxes, type LinkSlot } from "./links.js";
import { ADMIT_RE, Membership } from "./members.js";
import { createLogger, redact, type Logger } from "./log.js";
import { Metrics } from "./metrics.js";
import { clientAddress, ipBucket, ipBucket48 } from "./net.js";
import { RateLimiter } from "./ratelimit.js";
import { MemoryStore, type EvictPolicy, type Store, type StoreCounts } from "./store.js";

export const RELAY_SOFTWARE = "@peer2peer/relay";

function readVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version?: string };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}
export const RELAY_VERSION = readVersion();

/** docs/compatibility.md: this relay's protocol minor (3.1: the crit rule on what it parses). */
export const RELAY_PROTOCOL_MINOR = 1;
/** The frames this relay answers (handleFrame's cases), listed in /.well-known/p2p-relay.json. */
export const RELAY_FRAMES: readonly string[] = ["auth", "link-put", "link-get", "invite-get", "send", "ack", "revoke", "identity", "link-open", "invite-put", "invite-del", "invite-list", "circle-put"];
/**
 * What it supports beyond the frames:
 *  - `identity.lenient`: identity documents, device certs and caps with fields it doesn't know are
 *    stored and served (refused only for a field listed in `crit`);
 *  - `envelope.lenient`: envelopes of kinds it doesn't know, and with unknown outer fields, are
 *    relayed (refused only for an unknown field listed in `crit`);
 *  - `invite-mailbox`: short-code invite mailboxes (P4);
 *  - `link-mailbox`: pre-auth device-link mailboxes (§5.7);
 *  - `members`: this software can run members-only: it honours `admit` on `auth` and
 *    `invite-put`, and answers `circle-put`. Whether this relay does run so is `access`
 *    ("members" or "open") in the same document; `attention` asks its operator to look at the logs.
 * Frames ignore fields the relay doesn't know (they are requests, not signed objects); a client that
 * needs a frame field honoured checks the relay's features first.
 */
export const RELAY_FEATURES: readonly string[] = ["identity.lenient", "envelope.lenient", "invite-mailbox", "link-mailbox", "members"];

/**
 * Parses a request target against a dummy base. Node's HTTP parser lets
 * through targets that WHATWG URL rejects (`http://[::1`), and an exception in
 * an `upgrade` handler would take the process down, so callers get undefined.
 */
function parseTarget(target: string | undefined): URL | undefined {
  try {
    return new URL(target ?? "/", "http://relay.invalid");
  } catch {
    return undefined;
  }
}

/** Wire error codes. `send` uses only the four from §5.4; the rest are for the other frames. */
export type ErrorCode =
  | "undeliverable"
  | "rate-limited"
  | "too-large"
  | "bad-envelope"
  | "bad-request"
  | "auth-required"
  | "auth-failed"
  | "bad-identity"
  | "identity-gap"
  | "forbidden"
  | "not-found"
  | "full"
  | "exists"
  /** Members-only relay: this userId isn't admitted (an auth refusal, closed with 4001). */
  | "not-member";

/** Close codes the relay uses. */
export const CLOSE = {
  shutdown: 1001,
  tooBig: 1009,
  authFailed: 4001,
  /** The device certificate expired: reconnect with a renewed one (not a revocation, R4-L1). */
  certExpired: 4003,
  unauthTimeout: 4008,
  tooManyConnections: 4029,
} as const;

const DAY_MS = 24 * 3600 * 1000;
/** Capability state outlives any cap it could apply to (exp ≤ iat + 90 d). */
const CAP_STATE_RETENTION_MS = 91 * DAY_MS;
/** Stop queueing deliveries above this much unsent data per connection. */
const HIGH_WATER_BYTES = 1024 * 1024;
const DELIVERY_PAGE = 64;
const HEARTBEAT_MS = 30_000;
const MAX_ID_LEN = 128;
const MAX_ACK_RIDS = 1024;
/** Gauges read store counts at most this often, so scrapes never scan tables. */
const COUNTS_TTL_MS = 60_000;
const WIRE_RID_RE = /^[A-Za-z0-9_-]{22}$/;
/**
 * F-4: each expiry step aims at EXPIRE_STEP_MS of work; the row count adapts
 * between these bounds. Sweep prelude steps delete at most SWEEP_STEP rows per
 * table before yielding.
 */
const EXPIRE_STEP_MS = 10;
/** Above this share of a global cap (connections, device rows), per-address limits fall back to the strict IPv6 values. */
const POOL_PRESSURE = 0.8;
/** Pool evictions one newcomer address may cause per minute (pre-release re-review M-1). */
const POOL_EVICTIONS_PER_IP_PER_MINUTE = 10;
const EXPIRE_ROWS_MIN = 20;
const EXPIRE_ROWS_MAX = 2000;
const SWEEP_STEP = 200;
/** Members-only: `circle-put` frames per userId per hour. */
const CIRCLE_PUTS_PER_ISS_PER_HOUR = 120;
/** At most one "X-Forwarded-For has fewer hops than TRUST_PROXY" warning per this long. */
const SHORT_XFF_WARN_MS = 60_000;

interface ConnAuth {
  iss: string;
  did: string;
  /** The exact cert JWS the connection authenticated with, and its expiry (seconds). */
  cert: string;
  certExp: number;
  verified: VerifiedDeviceCert;
  /**
   * A valid certificate (rules 1–5) for a device the held identity document
   * doesn't list (rule 6). Such a connection may only publish identity
   * documents, so a key holder restoring from a backup (§2.7) can publish the
   * version that lists its new device. It has no mailbox until it is listed.
   */
  restricted?: boolean;
  /** The restricted identity limiter was charged for this connection (once per restore, review N-L1). */
  charged?: boolean;
}

interface Conn {
  /** Closes a restricted connection at its deadline (upgrade timeout or cert expiry). */
  restrictedTimer?: NodeJS.Timeout;
  /** Closes the connection when its device certificate expires (every authenticated connection). */
  certTimer?: NodeJS.Timeout;
  id: number;
  ws: WebSocket;
  /** The per-IP limit key: the IPv4 address or the IPv6 /64. */
  ip: string;
  nonce: string;
  pow: number;
  auth?: ConnAuth;
  lastSentRid: number;
  pumping: boolean;
  /** Set when the relay de-authorised the connection; it is closing and ignores every frame. */
  kicked: boolean;
  pumpTimer?: NodeJS.Timeout;
  /** Set once everything stored when the connection authenticated was sent (§5.4 `caught-up`). */
  caughtUp?: boolean;
  unauthTimer?: NodeJS.Timeout;
  alive: boolean;
  /** When the client last sent a frame (ms): eviction picks the oldest idle. */
  lastActive: number;
}

export interface RelayOptions {
  config: RelayConfig;
  store?: Store;
  crypto?: RelayCrypto;
  logger?: Logger;
  /** Milliseconds since the epoch. Injectable for tests. */
  now?: () => number;
}

const mboxKey = (iss: string, did: string) => `${iss}\n${did}`;

type LimiterName =
  | "sends"
  | "contactSender"
  | "contactPair"
  | "contactIp"
  | "link"
  | "http"
  | "frames"
  | "sendBytesConn"
  | "sendBytesIp"
  | "revokeConn"
  | "revokeIss"
  | "identityIss"
  | "identityIp"
  | "identityRestricted"
  | "linkOpenIss"
  | "linkOpenIp"
  | "invitePutIss"
  | "invitePutIp"
  | "inviteGet"
  | "inviteMiss"
  | "connectsIp"
  | "poolEvictIp"
  | "authsIp"
  | "authsIp4"
  | "newDevicesIp"
  | "newDevicesIp4"
  | "sourceAccepted"
  | "circlePut";

export class Relay {
  readonly config: RelayConfig;
  readonly store: Store;
  readonly crypto: RelayCrypto;
  readonly log: Logger;
  readonly metrics = new Metrics();
  readonly identity: IdentityService;
  private readonly now: () => number;
  private readonly links: LinkMailboxes;
  /** Members-only mode; admits everyone when neither an allowlist nor a circle is configured. */
  readonly members: Membership;
  private readonly http: Server;
  private metricsHttp?: Server;
  private readonly wss: WebSocketServer;
  private readonly conns = new Set<Conn>();
  private readonly byMailbox = new Map<string, Set<Conn>>();
  private readonly byIss = new Map<string, Set<Conn>>();
  /** Restricted connections per userId (never in byIss or a mailbox map). */
  private readonly restrictedByIss = new Map<string, Set<Conn>>();
  private readonly perIp = new Map<string, number>();
  /** Unauthenticated connections, oldest first, and their count per IP bucket. */
  private readonly unauthConns = new Set<Conn>();
  private readonly unauthPerIp = new Map<string, number>();
  private readonly limiters: Record<LimiterName, RateLimiter>;
  private readonly path: string;
  /** Per-process AES-128 key: the wire rid is the internal rid encrypted as one block (L3, N2). */
  private readonly ridKey = randomBytes(16);
  /**
   * Key for `src`, the stored keyed hash of a sender's IP bucket (N1). Held
   * ONLY in memory (N-M3): nothing on disk can link an envelope to a network.
   * After a restart, older rows keep their tags as anonymous groups (R-M1).
   */
  private readonly srcKey = Buffer.from(randomBytes(32));
  /** Device bindings held, for the maxDevices cap (N3). Re-synced on sweep. */
  private deviceCount: number;
  private lastShortXffWarn = -Infinity;
  private nextConnId = 1;
  private timers: NodeJS.Timeout[] = [];
  private closing = false;
  /** Running total of stored envelope bytes, for the global quota. Re-synced on sweep. */
  private storedBytes: number;
  private cachedCounts: { at: number; counts: StoreCounts };
  /** Event-loop delay, sampled only when `debugStats` is on. */
  private lagHist?: IntervalHistogram;

  constructor(opts: RelayOptions) {
    this.config = opts.config;
    this.crypto = opts.crypto ?? createRelayCrypto();
    this.store = opts.store ?? new MemoryStore();
    this.now = opts.now ?? Date.now;
    this.log = opts.logger ?? createLogger({ level: opts.config.logLevel, now: this.now });
    const L = this.config.limits;
    this.identity = new IdentityService(this.store, this.crypto, this.config.relayUrl, this.now, {
      maxTips: L.identityMaxTips,
      maxVersions: L.identityMaxVersions,
      expiredRetentionSec: L.identityExpiredRetentionSec,
      tombstoneRetentionSec: L.identityTombstoneRetentionSec,
    });
    this.links = new LinkMailboxes(
      {
        ttlMs: L.linkTtlSec * 1000,
        reqEntries: L.linkReqEntries,
        entryBytes: L.linkEntryBytes,
        openPerDevice: L.linkOpenPerDevice,
        openPerIp: L.linkOpenPerIp,
        // L-d: never more mailboxes than the byte budget can reserve.
        maxOpen: Math.min(10_000, Math.floor(L.linkTotalBytes / ((L.linkReqEntries + 1) * L.linkEntryBytes))),
        totalBytes: L.linkTotalBytes,
      },
      this.now,
    );
    const MIN = 60_000;
    const HOUR = 3_600_000;
    const rl = (limit: number, period: number) => new RateLimiter(limit, period, this.now);
    this.limiters = {
      sends: rl(L.sendsPerMinute, MIN),
      contactSender: rl(L.contactPerSenderPerHour, HOUR),
      contactPair: rl(L.contactPerPairPerHour, HOUR),
      contactIp: rl(L.contactPerIpPerHour, HOUR),
      link: rl(L.linkOpsPerIpPerMinute, MIN),
      http: rl(L.httpPerIpPerMinute, MIN),
      frames: rl(L.framesPerConnPerMinute, MIN),
      sendBytesConn: rl(L.sendBytesPerConnPerMinute, MIN),
      sendBytesIp: rl(L.sendBytesPerIpPerMinute, MIN),
      revokeConn: rl(L.revokesPerConnPerMinute, MIN),
      revokeIss: rl(L.revokesPerIssPerHour, HOUR),
      identityIss: rl(L.identityPublishPerIssPerHour, HOUR),
      identityIp: rl(L.identityPublishPerIpPerHour, HOUR),
      identityRestricted: rl(L.restrictedIdentityPerIssPerHour, HOUR),
      linkOpenIss: rl(L.linkOpenPerIssPerHour, HOUR),
      linkOpenIp: rl(L.linkOpenPerIpPerHour, HOUR),
      invitePutIss: rl(L.invitePutPerIssPerHour, HOUR),
      invitePutIp: rl(L.invitePutPerIpPerHour, HOUR),
      inviteGet: rl(L.inviteGetsPerIpPerMinute, MIN),
      inviteMiss: rl(L.inviteMissesPerIpPerHour, HOUR),
      connectsIp: rl(L.connectsPerIpPerMinute, MIN),
      poolEvictIp: rl(POOL_EVICTIONS_PER_IP_PER_MINUTE, MIN),
      authsIp: rl(L.authsPerIpPerMinute, MIN),
      authsIp4: rl(L.authsPerIpv4PerMinute, MIN),
      newDevicesIp: rl(L.newDevicesPerIpPerDay, DAY_MS),
      newDevicesIp4: rl(L.newDevicesPerIpv4PerDay, DAY_MS),
      // M-3/N-M2: bytes ACCEPTED from a source, refilling continuously over an
      // hour. Silently dropped contacts count too, and acks or evictions never
      // give bytes back, so the budget says nothing about mailboxes or receivers.
      sourceAccepted: rl(L.sourceAcceptedBytesPerHour, HOUR),
      circlePut: rl(CIRCLE_PUTS_PER_ISS_PER_HOUR, HOUR),
    };
    this.members = new Membership({
      allow: this.config.allow,
      deny: this.config.deny,
      circle: this.config.allowCircle,
      inviteAdmitSec: this.config.inviteAdmitSec,
      store: this.store,
      now: this.now,
      log: this.log,
    });
    this.path = new URL(this.config.relayUrl).pathname;
    const counts = this.store.counts();
    this.storedBytes = counts.envelopeBytes;
    this.deviceCount = counts.devices;
    this.cachedCounts = { at: this.now(), counts };
    this.registerMetrics();

    // F-2: allowSynchronousEvents=false makes ws emit at most one message per
    // connection per macrotask (setImmediate between frames). A pipelined burst
    // on one socket therefore yields to everything else between frames, and
    // ws's receiver stops reading the socket meanwhile (TCP backpressure), so
    // nothing queues up in relay memory.
    this.wss = new WebSocketServer({ noServer: true, maxPayload: L.frameBytes, perMessageDeflate: false, allowSynchronousEvents: false });
    this.http = createServer((req, res) => this.onHttp(req, res));
    this.http.on("upgrade", (req, socket, head) => this.onUpgrade(req, socket, head));
  }

  // -------------------------------------------------------------------------
  // Lifecycle

  /** Starts listening; resolves with the bound port. */
  async listen(): Promise<number> {
    // Startup work (re-attributing old rows, rebuilding totals) finishes,
    // in yielding chunks, before the relay accepts any connection.
    await this.store.init();
    this.members.load();
    const counts = this.store.counts();
    this.storedBytes = counts.envelopeBytes;
    this.deviceCount = counts.devices;
    this.cachedCounts = { at: this.now(), counts };
    const port = await new Promise<number>((resolve, reject) => {
      this.http.once("error", reject);
      this.http.listen(this.config.port, this.config.host, () => {
        this.http.off("error", reject);
        const addr = this.http.address();
        resolve(typeof addr === "object" && addr ? addr.port : this.config.port);
      });
    });
    if (this.config.metricsPort !== null) {
      const m = createServer((req, res) => this.onMetricsHttp(req, res));
      this.metricsHttp = m;
      await new Promise<void>((resolve, reject) => {
        m.once("error", reject);
        m.listen(this.config.metricsPort ?? 0, this.config.metricsHost, () => {
          m.off("error", reject);
          resolve();
        });
      });
    }
    if (this.config.debugStats) {
      this.lagHist = monitorEventLoopDelay({ resolution: 10 });
      this.lagHist.enable();
    }
    this.timers.push(setInterval(() => void this.sweep(), this.config.sweepIntervalSec * 1000));
    this.timers.push(setInterval(() => this.heartbeat(), HEARTBEAT_MS));
    for (const t of this.timers) t.unref();
    this.log.info("relay listening", {
      port,
      relay: this.config.relayUrl,
      version: RELAY_VERSION,
      pow: this.config.powBits,
      metricsPort: this.metricsPort ?? undefined,
    });
    return port;
  }

  /** The bound port of the separate /metrics listener, if it is running. */
  get metricsPort(): number | undefined {
    const a = this.metricsHttp?.address();
    return typeof a === "object" && a ? a.port : undefined;
  }

  /** Graceful shutdown: refuse new work, close every connection with 1001, flush the store. */
  async close(): Promise<void> {
    if (this.closing) return;
    this.closing = true;
    for (const t of this.timers) clearInterval(t);
    this.timers = [];
    this.lagHist?.disable();
    for (const c of this.conns) {
      if (c.pumpTimer) clearTimeout(c.pumpTimer);
      c.ws.close(CLOSE.shutdown, "relay shutting down");
    }
    await new Promise<void>((resolve) => {
      const force = setTimeout(() => {
        for (const c of this.conns) c.ws.terminate();
      }, 2000);
      force.unref();
      const done = () => {
        clearTimeout(force);
        resolve();
      };
      if (this.conns.size === 0) done();
      else {
        const check = setInterval(() => {
          if (this.conns.size === 0) {
            clearInterval(check);
            done();
          }
        }, 10);
        check.unref();
      }
    });
    this.wss.close();
    for (const srv of [this.http, this.metricsHttp]) {
      if (!srv) continue;
      await new Promise<void>((resolve) => {
        if (!srv.listening) return resolve();
        srv.close(() => resolve());
        srv.closeAllConnections();
      });
    }
    this.store.close();
    this.log.info("relay stopped");
  }

  /**
   * Deletes expired envelopes (in batches that yield, N-M1), cap state,
   * identity versions and userIds, stale device bindings and link mailboxes.
   * Resolves when the envelope expiry has caught up.
   */
  async sweep(): Promise<void> {
    const now = this.now();
    const L = this.config.limits;
    const yieldNow = () => new Promise((res) => setImmediate(res));
    try {
      // F-4: every step is bounded and followed by a yield.
      const r = { caps: 0, identityDocs: 0, devices: 0 };
      const cutoffs = {
        capsBefore: now - CAP_STATE_RETENTION_MS,
        identityVersionsBefore: now - L.identityVersionRetentionSec * 1000,
        devicesBefore: now - L.deviceRetentionSec * 1000,
        seenBefore: now - L.identityTombstoneRetentionSec * 1000,
        nowMs: now,
      };
      for (;;) {
        const step = this.store.sweep(cutoffs, SWEEP_STEP);
        r.caps += step.caps;
        r.identityDocs += step.identityDocs;
        r.devices += step.devices;
        this.deviceCount = Math.max(0, this.deviceCount - step.devices);
        const seen = step.seen ?? 0;
        if (step.caps < SWEEP_STEP && step.identityDocs < SWEEP_STEP && step.devices < SWEEP_STEP && seen < SWEEP_STEP) break;
        await yieldNow();
      }
      await yieldNow();
      const ids = { tombstoned: 0, deleted: 0 };
      for (;;) {
        const step = this.identity.sweep(SWEEP_STEP / 2);
        ids.tombstoned += step.tombstoned;
        ids.deleted += step.deleted;
        if (step.tombstoned < SWEEP_STEP / 2 && step.deleted < SWEEP_STEP / 2) break;
        await yieldNow();
      }
      const links = this.links.sweep();
      await yieldNow();
      const invites = await this.sweepInvites(now);
      if (this.members.enabled && this.members.expire()) this.enforceMembers();
      for (const l of Object.values(this.limiters)) l.prune();
      // A counter read, not a table scan; device rows are counted as they go.
      this.storedBytes = this.store.envelopeTotals().bytes;
      if (r.caps + r.identityDocs + r.devices + ids.tombstoned + ids.deleted + links + invites > 0) {
        this.log.info("sweep", {
          caps: r.caps,
          identityDocs: r.identityDocs,
          devices: r.devices,
          identitiesTombstoned: ids.tombstoned,
          tombstonesDeleted: ids.deleted,
          links,
          invites,
        });
      }
    } catch (e) {
      this.log.error("sweep failed", { error: (e as Error).message });
    }
    await this.expire();
  }

  /** Rows per invite-sweep step, adapted like expireRows (F-4). */
  private inviteSweepRows = 200;

  /**
   * F-4: deletes expired invites (and their `evicted` tombstones) in batches,
   * yielding between them; each batch adapts to about EXPIRE_STEP_MS. Returns
   * how many invites went.
   */
  private async sweepInvites(now: number): Promise<number> {
    let total = 0;
    for (;;) {
      if (this.closing) break;
      const rows = this.inviteSweepRows;
      const t0 = performance.now();
      const step = this.store.sweepInvites(now, rows);
      const ms = performance.now() - t0;
      if (ms > EXPIRE_STEP_MS) this.inviteSweepRows = Math.max(EXPIRE_ROWS_MIN, Math.floor(rows / 2));
      else if (ms < EXPIRE_STEP_MS / 2 && (step.invites === rows || step.evicted === rows)) this.inviteSweepRows = Math.min(EXPIRE_ROWS_MAX, Math.ceil(rows * 1.5));
      total += step.invites;
      if (step.invites < rows && step.evicted < rows) break;
      await new Promise((res) => setImmediate(res));
    }
    return total;
  }

  private expiring?: Promise<void>;

  /** Rows per expiry step, adapted to keep each step near EXPIRE_STEP_MS (F-4). */
  private expireRows = 200;

  /**
   * N-M1/F-4: deletes expired envelopes in batches through the received_at
   * index, yielding to the event loop between batches. The batch size adapts
   * so each one takes about EXPIRE_STEP_MS, so a large expiry never holds the
   * loop (or the write lock) for long.
   */
  expire(): Promise<void> {
    this.expiring ??= (async () => {
      let total = 0;
      try {
        for (;;) {
          if (this.closing) break;
          const before = this.now() - this.config.limits.retentionSec * 1000;
          const rows = this.expireRows;
          const t0 = performance.now();
          const { count, bytes } = this.store.expireBatch(before, rows);
          const ms = performance.now() - t0;
          if (ms > EXPIRE_STEP_MS) this.expireRows = Math.max(EXPIRE_ROWS_MIN, Math.floor(rows / 2));
          else if (ms < EXPIRE_STEP_MS / 2 && count === rows) this.expireRows = Math.min(EXPIRE_ROWS_MAX, Math.ceil(rows * 1.5));
          total += count;
          this.storedBytes = Math.max(0, this.storedBytes - bytes);
          if (count < rows) break;
          await new Promise((res) => setImmediate(res));
        }
      } catch (e) {
        this.log.error("expiry failed", { error: (e as Error).message });
      } finally {
        this.expiring = undefined;
      }
      if (total > 0) {
        this.metrics.inc("envelopes_expired", undefined, total);
        this.log.info("expired", { envelopes: total });
      }
    })();
    return this.expiring;
  }

  private heartbeat(): void {
    if (this.members.enabled && this.members.expire()) this.enforceMembers();
    for (const c of this.conns) {
      if (!c.alive) {
        c.ws.terminate();
        continue;
      }
      c.alive = false;
      c.ws.ping();
    }
  }

  private counts(): StoreCounts {
    const now = this.now();
    if (now - this.cachedCounts.at >= COUNTS_TTL_MS) this.cachedCounts = { at: now, counts: this.store.counts() };
    return this.cachedCounts.counts;
  }

  private registerMetrics(): void {
    // Only aggregate counts. Nothing here may tell apart outcomes a sender
    // can't distinguish on the wire (stored vs silently dropped, delivered or
    // not), or it becomes a mailbox-existence / presence oracle.
    const m = this.metrics;
    m.counter("connections", "WebSocket connections accepted");
    m.counter("connections_rejected", "WebSocket upgrades refused (limits, wrong path)");
    m.counter("auth", "Authentication attempts by result");
    m.counter("sends", "send frames by wire result");
    m.counter("envelopes_expired", "Envelopes deleted after the retention period");
    m.counter("envelopes_evicted", "Envelopes evicted to stay under the store or per-recipient quota");
    m.counter("revokes", "Capability revocations recorded");
    m.counter("identity_publish", "Identity document publishes by result");
    m.counter("link", "Link mailbox operations by op and result");
    m.counter("invite", "Short-code invite mailbox operations by op and result");
    m.counter("http_requests", "HTTP requests by route");
    m.counter("frames_rejected", "Frames rejected as malformed, unknown or over the frame rate");
    m.counter("circle_put", "Members-only circle-put frames by result");
    m.gauge("connections_open", "Open WebSocket connections", () => this.conns.size);
    m.gauge("connections_authenticated", "Authenticated WebSocket connections", () => this.conns.size - this.unauthConns.size);
    m.gauge("envelopes_stored_now", "Envelopes stored (refreshed at most once a minute)", () => this.counts().envelopes);
    m.gauge("envelope_bytes_stored_now", "Envelope bytes stored (refreshed at most once a minute)", () => this.counts().envelopeBytes);
    m.gauge("link_mailboxes_open", "Link mailboxes currently open", () => this.links.size);
    m.gauge("invite_bytes_stored_now", "Bytes held in short-code invite mailboxes", () => this.store.inviteBytes());
  }

  // -------------------------------------------------------------------------
  // Discovery

  /** The `hello.limits` object and the limits block of the relay-info document. */
  advertisedLimits(): Record<string, number> {
    const L = this.config.limits;
    return {
      frameBytes: L.frameBytes,
      envelopeBytes: L.envelopeBytes,
      mailboxEnvelopes: L.mailboxEnvelopes,
      mailboxBytes: L.mailboxBytes,
      retentionSec: L.retentionSec,
      sendsPerMinute: L.sendsPerMinute,
      contactPerSenderPerHour: L.contactPerSenderPerHour,
      contactPerPairPerHour: L.contactPerPairPerHour,
      contactPerIpPerHour: L.contactPerIpPerHour,
      linkOpsPerIpPerMinute: L.linkOpsPerIpPerMinute,
      // R-L1: link pollers (unauthenticated) must reconnect within this.
      unauthTimeoutSec: L.unauthTimeoutSec,
      framesPerConnPerMinute: L.framesPerConnPerMinute,
      sendBytesPerConnPerMinute: L.sendBytesPerConnPerMinute,
      inviteTtlMaxSec: L.inviteTtlMaxSec,
      inviteBlobBytes: L.inviteBlobBytes,
      inviteGetsPerIpPerMinute: L.inviteGetsPerIpPerMinute,
    };
  }

  /** GET /.well-known/p2p-relay.json: how communities discover and compare relays, and what this one supports. */
  relayInfo(): Record<string, unknown> {
    return {
      protocol: "p2p/v3",
      // docs/compatibility.md: what this relay answers, so a client can degrade against an older one.
      // A relay from before these fields lists neither, and counts as protocol 3.0, baseline frames.
      protocolMinor: RELAY_PROTOCOL_MINOR,
      frames: [...RELAY_FRAMES],
      features: [...RELAY_FEATURES],
      relay: this.config.relayUrl,
      name: this.config.name ?? null,
      software: { name: RELAY_SOFTWARE, version: RELAY_VERSION },
      limits: this.advertisedLimits(),
      pow: this.config.powBits,
      operator: { contact: this.config.operatorContact ?? null },
      policy: this.config.policy ?? null,
      // Members-only relays say so (not who the members are), so a refused client can explain why.
      access: this.members.enabled ? "members" : "open",
      // The operator should look at the logs (e.g. the followed circle turned open); no details here.
      ...(this.members.attention ? { attention: true } : {}),
    };
  }

  // -------------------------------------------------------------------------
  // HTTP

  private clientIp(req: IncomingMessage): string {
    // A local health check (e.g. Docker's HEALTHCHECK on 127.0.0.1) has no proxy in front: not a misconfiguration.
    const remote = req.socket.remoteAddress ?? "";
    const localHealth = /^(127\.|::1$|::ffff:127\.)/.test(remote) && (req.url ?? "").split("?")[0] === "/healthz";
    const addr = clientAddress(remote, req.headers["x-forwarded-for"], this.config.trustProxy, (hops) => {
      if (localHealth) return;
      // N8: the proxy chain isn't what TRUST_PROXY says; every client may be
      // sharing the proxy's limits. Warn, but not on every request.
      const now = this.now();
      if (now - this.lastShortXffWarn < SHORT_XFF_WARN_MS) return;
      this.lastShortXffWarn = now;
      this.log.warn("X-Forwarded-For has fewer hops than TRUST_PROXY; using the socket address", {
        hops,
        trustProxy: this.config.trustProxy,
      });
    });
    return ipBucket(addr);
  }

  private sendMetrics(res: ServerResponse): void {
    res.writeHead(200, { "content-type": "text/plain; version=0.0.4; charset=utf-8", "cache-control": "no-store" });
    res.end(this.metrics.render());
  }

  /**
   * GET /debug/stats on the metrics listener, only when `debugStats` is on:
   * event-loop delay, process memory and the sizes of every in-memory map, for
   * the resilience suite (packages/relay/resilience). Aggregates only, like /metrics.
   * `?reset=1` restarts the delay histogram after reading it; `?store=1` adds
   * live store counts (a table scan, so the harness asks only at checkpoints).
   */
  debugStats(opts: { reset?: boolean; store?: boolean } = {}): Record<string, unknown> {
    const h = this.lagHist;
    const ms = (ns: number) => (Number.isFinite(ns) ? ns / 1e6 : 0);
    const lag = h
      ? { p50: ms(h.percentile(50)), p99: ms(h.percentile(99)), max: ms(h.max), mean: ms(h.mean), count: h.count }
      : null;
    if (opts.reset) h?.reset();
    const mem = process.memoryUsage();
    const limiterKeys: Record<string, number> = {};
    for (const [name, l] of Object.entries(this.limiters)) limiterKeys[name] = l.size;
    const out: Record<string, unknown> = {
      lagMs: lag,
      rssBytes: mem.rss,
      heapUsedBytes: mem.heapUsed,
      heapTotalBytes: mem.heapTotal,
      externalBytes: mem.external,
      arrayBuffersBytes: mem.arrayBuffers,
      connections: this.conns.size,
      unauthConnections: this.unauthConns.size,
      maps: {
        byMailbox: this.byMailbox.size,
        byIss: this.byIss.size,
        perIp: this.perIp.size,
        unauthPerIp: this.unauthPerIp.size,
        limiterKeys,
      },
      links: { open: this.links.size, reservedBytes: this.links.reservedBytes },
      storedBytes: this.storedBytes,
    };
    if (opts.store) out.store = this.store.counts();
    return out;
  }

  /** The separate (by default localhost-only) metrics listener. */
  private onMetricsHttp(req: IncomingMessage, res: ServerResponse): void {
    try {
      const url = parseTarget(req.url);
      if (!url) return void res.writeHead(400).end();
      if (req.method === "GET" && url.pathname === "/metrics") return this.sendMetrics(res);
      if (req.method === "GET" && url.pathname === "/debug/stats" && this.config.debugStats) {
        const body = this.debugStats({ reset: url.searchParams.get("reset") === "1", store: url.searchParams.get("store") === "1" });
        res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
        res.end(JSON.stringify(body));
        return;
      }
      res.writeHead(404).end();
    } catch (e) {
      this.log.error("metrics handler failed", { error: (e as Error).message });
      if (!res.headersSent) res.writeHead(500);
      res.end();
    }
  }

  private metricsTokenOk(req: IncomingMessage): boolean {
    const token = this.config.metricsToken;
    const header = req.headers.authorization;
    if (!token || typeof header !== "string" || !header.startsWith("Bearer ")) return false;
    const a = Buffer.from(header.slice(7));
    const b = Buffer.from(token);
    return a.length === b.length && timingSafeEqual(a, b);
  }

  private onHttp(req: IncomingMessage, res: ServerResponse): void {
    const send = (status: number, body: unknown) => {
      res.writeHead(status, {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
        "access-control-allow-origin": "*",
        "x-content-type-options": "nosniff",
      });
      res.end(req.method === "HEAD" ? undefined : JSON.stringify(body));
    };
    let route = "other";
    try {
      if (req.method !== "GET" && req.method !== "HEAD") {
        route = "method";
        return send(405, { error: "method-not-allowed" });
      }
      if (!this.limiters.http.take(this.clientIp(req))) {
        route = "rate-limited";
        return send(429, { error: "rate-limited" });
      }
      const url = parseTarget(req.url);
      if (!url) {
        route = "bad-target";
        return send(400, { error: "bad-request" });
      }
      const p = url.pathname;
      if (p === "/healthz") {
        route = "healthz";
        let ok = false;
        try {
          ok = !this.closing && this.store.ping();
        } catch {
          ok = false;
        }
        return send(ok ? 200 : 503, { ok });
      }
      if (p === "/metrics") {
        // Public only with the operator's token; otherwise it lives on the metrics listener.
        route = "metrics";
        if (this.metricsTokenOk(req)) return this.sendMetrics(res);
        return send(404, { error: "not-found" });
      }
      if (p === "/.well-known/p2p-relay.json") {
        route = "relay-info";
        return send(200, this.relayInfo());
      }
      if (p === this.path) {
        route = "ws-path";
        return send(426, { error: "upgrade-required" });
      }
      const prefix = `${this.path === "/" ? "" : this.path}/identity/`;
      if (p.startsWith(prefix)) {
        route = "identity";
        return this.identityRoute(p.slice(prefix.length), url, send);
      }
      return send(404, { error: "not-found" });
    } catch (e) {
      this.log.error("http handler failed", { error: (e as Error).message });
      if (!res.headersSent) send(500, { error: "internal" });
      else res.end();
    } finally {
      this.metrics.inc("http_requests", { route });
    }
  }

  private identityRoute(rest: string, url: URL, send: (status: number, body: unknown) => void): void {
    const parts = rest.split("/");
    let userId: string;
    try {
      userId = decodeURIComponent(parts[0]);
    } catch {
      return send(400, { error: "bad-request" });
    }
    if (!this.crypto.isUserId(userId) || parts.length > 2) return send(404, { error: "not-found" });
    // Members-only: documents of members only, so the relay is no public directory; a
    // non-member's userId looks exactly like an unknown one.
    if (!this.members.admitted(userId)) return send(404, { error: "not-found" });
    const sub = parts[1];
    if (sub === undefined || sub === "") {
      const head = this.identity.head(userId);
      return head ? send(200, { doc: head.jws }) : send(404, { error: "not-found" });
    }
    if (sub === "tips") {
      const tips = this.identity.tips(userId);
      return tips.length > 0 ? send(200, { tips: tips.map((t) => t.jws) }) : send(404, { error: "not-found" });
    }
    if (sub === "chain") {
      const to = url.searchParams.get("to");
      const nRaw = url.searchParams.get("n");
      const max = this.config.limits.chainMaxN;
      const n = nRaw === null ? max : Number(nRaw);
      if (!to || !/^[A-Za-z0-9_-]{43}$/.test(to) || !Number.isSafeInteger(n) || n < 1 || n > max) {
        return send(400, { error: "bad-request" });
      }
      const docs = this.identity.chain(userId, to, n);
      return docs ? send(200, { docs: docs.map((d) => d.jws) }) : send(404, { error: "not-found" });
    }
    return send(404, { error: "not-found" });
  }

  // -------------------------------------------------------------------------
  // WebSocket

  private onUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void {
    const reject = (status: number, why: string) => {
      this.metrics.inc("connections_rejected", { reason: why });
      socket.write(`HTTP/1.1 ${status} ${why}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
      socket.destroy();
    };
    try {
      const url = parseTarget(req.url);
      if (!url) return reject(400, "bad-request");
      if (this.closing) return reject(503, "shutting-down");
      if (url.pathname !== this.path) return reject(404, "not-found");
      const ip = this.clientIp(req);
      const L = this.config.limits;
      // F-5 / pre-release review: the higher IPv4 per-address cap is for shared NAT.
      // Past POOL_PRESSURE of the global cap, every address gets the strict
      // per-IP cap, so a few addresses can't take the whole pool.
      const pressured = this.conns.size >= Math.floor(L.maxConnections * POOL_PRESSURE);
      const perIpCap = isIPv4(ip) && !pressured ? L.maxConnectionsPerIpv4 : L.maxConnectionsPerIp;
      if ((this.perIp.get(ip) ?? 0) >= perIpCap) return reject(429, "too-many-connections");
      // Full (pre-release re-review M-1): room comes only from an address holding
      // more than the strict per-IP cap, so every address keeps up to that
      // many connections whatever others do. When none is over it, the
      // newcomer is refused as before. One newcomer address may cause only
      // POOL_EVICTIONS_PER_IP_PER_MINUTE evictions.
      const full = this.conns.size >= L.maxConnections;
      if (full && !this.poolVictim()) return reject(503, "too-many-connections");
      // Unauthenticated sockets: a small per-IP cap, and a global cap that,
      // when full, drops the OLDEST unauthenticated socket instead of refusing
      // the newcomer, so stale sockets can't lock honest clients out.
      if ((this.unauthPerIp.get(ip) ?? 0) >= L.maxUnauthPerIp) return reject(429, "too-many-connections");
      // N3: new connections per IP bucket per minute.
      if (!this.limiters.connectsIp.take(ip)) return reject(429, "rate-limited");
      while (this.unauthConns.size >= L.maxUnauthConnections) {
        const oldest = this.unauthConns.values().next().value as Conn;
        this.leaveUnauth(oldest);
        oldest.ws.close(CLOSE.unauthTimeout, "make room");
        setTimeout(() => oldest.ws.terminate(), 1000).unref();
      }
      if (full && !this.limiters.poolEvictIp.take(ip)) return reject(503, "too-many-connections");
      this.wss.handleUpgrade(req, socket, head, (ws) => {
        // L-4: evict only once the upgrade has succeeded, so a failed
        // upgrade costs nobody a connection. If the room went meanwhile and
        // no address is over the strict cap any more, the newcomer leaves.
        if (this.conns.size >= L.maxConnections) {
          const victim = this.poolVictim();
          if (!victim) {
            this.metrics.inc("connections_rejected", { reason: "too-many-connections" });
            ws.close(CLOSE.tooManyConnections, "relay full");
            return;
          }
          this.evict(victim);
        }
        this.onConnection(ws, ip);
      });
    } catch (e) {
      this.log.error("upgrade failed", { error: (e as Error).message });
      socket.destroy();
    }
  }

  /**
   * The global cap is full: the connection to close for a newcomer, or
   * undefined when none may go (pre-release re-review M-1).
   * - Only an address bucket holding MORE than the strict per-IP cap gives
   *   one up (the biggest such bucket), so no address is pushed below it.
   * - In that bucket, the userId with the most connections there gives one
   *   up (ties: all of the tied userIds), its least recently active one, so
   *   one user's churn can't cycle through the others' idle receivers.
   * - A bucket with no authenticated connection gives up its least recently
   *   active unauthenticated one.
   */
  private poolVictim(): Conn | undefined {
    const strict = this.config.limits.maxConnectionsPerIp;
    let bucket: string | undefined;
    let most = strict;
    for (const [ip, n] of this.perIp) {
      if (n > most) [bucket, most] = [ip, n];
    }
    if (bucket === undefined) return undefined;
    const perIss = new Map<string, Conn[]>();
    let unauth: Conn | undefined;
    for (const c of this.conns) {
      if (c.ip !== bucket || c.kicked) continue;
      if (!c.auth) {
        if (!unauth || c.lastActive < unauth.lastActive) unauth = c;
        continue;
      }
      const list = perIss.get(c.auth.iss);
      if (list) list.push(c);
      else perIss.set(c.auth.iss, [c]);
    }
    let top = 0;
    for (const l of perIss.values()) top = Math.max(top, l.length);
    let victim: Conn | undefined;
    for (const l of perIss.values()) {
      if (l.length !== top) continue;
      for (const c of l) if (!victim || c.lastActive < victim.lastActive) victim = c;
    }
    return victim ?? unauth;
  }

  private evict(victim: Conn): void {
    this.metrics.inc("connections_rejected", { reason: "evicted-pool-full" });
    if (this.log.debugEnabled) this.log.debug("connection evicted for a newcomer", { conn: victim.id });
    victim.ws.close(CLOSE.tooManyConnections, "relay full");
    victim.ws.terminate();
    this.onClose(victim);
  }

  /** Removes `conn` from the unauthenticated set (on auth, close or eviction). */
  private leaveUnauth(conn: Conn): void {
    if (!this.unauthConns.delete(conn)) return;
    if (conn.unauthTimer) clearTimeout(conn.unauthTimer);
    const n = (this.unauthPerIp.get(conn.ip) ?? 1) - 1;
    if (n <= 0) this.unauthPerIp.delete(conn.ip);
    else this.unauthPerIp.set(conn.ip, n);
  }

  private onConnection(ws: WebSocket, ip: string): void {
    const conn: Conn = {
      id: this.nextConnId++,
      ws,
      ip,
      nonce: b64uEncode(randomBytes(32)),
      pow: this.config.powBits,
      lastSentRid: 0,
      pumping: false,
      kicked: false,
      alive: true,
      lastActive: this.now(),
    };
    this.conns.add(conn);
    this.unauthConns.add(conn);
    this.unauthPerIp.set(ip, (this.unauthPerIp.get(ip) ?? 0) + 1);
    conn.unauthTimer = setTimeout(() => {
      if (!conn.auth) ws.close(CLOSE.unauthTimeout, "authenticate or leave");
    }, this.config.limits.unauthTimeoutSec * 1000);
    conn.unauthTimer.unref();
    this.perIp.set(ip, (this.perIp.get(ip) ?? 0) + 1);
    this.metrics.inc("connections");
    if (this.log.debugEnabled) this.log.debug("connection open", { conn: conn.id, ip: redact(ip) });

    ws.on("pong", () => (conn.alive = true));
    ws.on("message", (data, isBinary) => this.onFrame(conn, data, isBinary));
    ws.on("error", (e) => {
      // ws closes with 1009 by itself when a frame exceeds maxPayload.
      if (this.log.debugEnabled) this.log.debug("connection error", { conn: conn.id, error: e.message });
    });
    ws.on("close", () => this.onClose(conn));

    this.reply(conn, {
      t: "hello",
      relay: this.config.relayUrl,
      nonce: conn.nonce,
      pow: conn.pow,
      limits: this.advertisedLimits(),
    });
  }

  private onClose(conn: Conn): void {
    if (!this.conns.delete(conn)) return;
    if (conn.pumpTimer) clearTimeout(conn.pumpTimer);
    if (conn.unauthTimer) clearTimeout(conn.unauthTimer);
    const n = (this.perIp.get(conn.ip) ?? 1) - 1;
    if (n <= 0) this.perIp.delete(conn.ip);
    else this.perIp.set(conn.ip, n);
    if (conn.auth) this.unregister(conn, conn.auth);
    this.leaveUnauth(conn);
    if (this.log.debugEnabled) this.log.debug("connection closed", { conn: conn.id });
  }

  /** Removes an authenticated connection from the mailbox and userId maps. */
  private unregister(conn: Conn, auth: ConnAuth): void {
    const key = mboxKey(auth.iss, auth.did);
    const set = this.byMailbox.get(key);
    set?.delete(conn);
    if (set && set.size === 0) this.byMailbox.delete(key);
    const mine = this.byIss.get(auth.iss);
    mine?.delete(conn);
    if (mine && mine.size === 0) this.byIss.delete(auth.iss);
    const r = this.restrictedByIss.get(auth.iss);
    r?.delete(conn);
    if (r && r.size === 0) this.restrictedByIss.delete(auth.iss);
    if (conn.restrictedTimer) clearTimeout(conn.restrictedTimer);
    conn.restrictedTimer = undefined;
    if (conn.certTimer) clearTimeout(conn.certTimer);
    conn.certTimer = undefined;
  }

  private reply(conn: Conn, msg: Record<string, unknown>): void {
    if (conn.ws.readyState === WebSocket.OPEN) conn.ws.send(JSON.stringify(msg));
  }

  private ok(conn: Conn, id: string | undefined): void {
    this.reply(conn, id === undefined ? { t: "ok" } : { t: "ok", id });
  }

  private error(conn: Conn, id: string | undefined, code: ErrorCode): void {
    this.reply(conn, id === undefined ? { t: "error", code } : { t: "error", id, code });
  }

  private onFrame(conn: Conn, data: RawData, isBinary: boolean): void {
    if (conn.kicked) return;
    conn.alive = true;
    conn.lastActive = this.now();
    // Every frame type costs a token before any parsing (M3).
    if (!this.limiters.frames.take(String(conn.id))) {
      this.metrics.inc("frames_rejected", { reason: "rate-limited" });
      return this.error(conn, undefined, "rate-limited");
    }
    let msg: Record<string, unknown>;
    try {
      if (isBinary) throw new Error("binary");
      const text = Array.isArray(data) ? Buffer.concat(data).toString("utf8") : Buffer.from(data as ArrayBuffer).toString("utf8");
      const v: unknown = JSON.parse(text);
      if (typeof v !== "object" || v === null || Array.isArray(v) || typeof (v as { t?: unknown }).t !== "string") {
        throw new Error("shape");
      }
      msg = v as Record<string, unknown>;
    } catch {
      this.metrics.inc("frames_rejected", { reason: "malformed" });
      return this.error(conn, undefined, "bad-request");
    }
    const rawId = msg.id;
    if (rawId !== undefined && (typeof rawId !== "string" || rawId.length > MAX_ID_LEN)) {
      this.metrics.inc("frames_rejected", { reason: "bad-id" });
      return this.error(conn, undefined, "bad-request");
    }
    const id = rawId as string | undefined;
    try {
      switch (msg.t) {
        case "auth":
          return this.onAuth(conn, msg, id);
        case "link-put":
          return this.onLinkPut(conn, msg, id);
        case "link-get":
          return this.onLinkGet(conn, msg, id);
        case "invite-get":
          return this.onInviteGet(conn, msg, id);
      }
      if (!conn.auth) return this.error(conn, id, "auth-required");
      const auth = conn.auth;
      // An unlisted device may only publish the identity document that lists it.
      if (auth.restricted && msg.t !== "identity") return this.error(conn, id, "forbidden");
      switch (msg.t) {
        case "send":
          return this.onSend(conn, auth, msg, id);
        case "ack":
          return this.onAck(conn, auth, msg, id);
        case "revoke":
          return this.onRevoke(conn, auth, msg, id);
        case "identity":
          return this.onIdentity(conn, auth, msg, id);
        case "link-open":
          return this.onLinkOpen(conn, auth, msg, id);
        case "invite-put":
          return this.onInvitePut(conn, auth, msg, id);
        case "invite-del":
          return this.onInviteDel(conn, auth, msg, id);
        case "invite-list":
          return this.onInviteList(conn, auth, id);
        case "circle-put":
          return this.onCirclePut(conn, auth, msg, id);
        default:
          this.metrics.inc("frames_rejected", { reason: "unknown-type" });
          return this.error(conn, id, "bad-request");
      }
    } catch (e) {
      // A bug, not a client error; never echo details to the client.
      this.log.error("frame handler failed", { t: String(msg.t).slice(0, 32), error: (e as Error).message });
      this.error(conn, id, "bad-request");
    }
  }

  // -------------------------------------------------------------------------
  // §5.2 auth, and keeping rule 6 true for live sessions

  /**
   * Closes `conn` as no longer authorised (N5): its auth is cleared and it
   * leaves the mailbox and userId maps at once, so nothing more is delivered
   * to it and none of its frames are processed during the close handshake.
   * The socket is terminated if the peer doesn't finish the handshake.
   */
  private kick(conn: Conn, id: string | undefined, why: string, code: number = CLOSE.authFailed): void {
    if (this.log.debugEnabled) this.log.debug("connection deauthorised", { conn: conn.id, why });
    const notMember = why === "not-member";
    this.error(conn, id, notMember ? "not-member" : "auth-failed");
    if (conn.auth) this.unregister(conn, conn.auth);
    conn.auth = undefined;
    conn.kicked = true;
    if (conn.pumpTimer) clearTimeout(conn.pumpTimer);
    conn.ws.close(code, code === CLOSE.certExpired ? "certificate expired" : notMember ? "not a member" : "device not allowed");
    setTimeout(() => conn.ws.terminate(), 1000).unref();
  }

  /** M1: after the allowlist of `iss` changes, close every live connection of a device it no longer lists. */
  private enforceAllowlist(iss: string): void {
    const allowed = this.identity.allowedDevices(iss);
    if (!allowed) return;
    for (const c of this.byIss.get(iss) ?? []) {
      if (c.auth && !c.auth.restricted && !allowed.has(c.auth.did)) this.kick(c, undefined, "revoked");
    }
    const restricted = this.restrictedByIss.get(iss);
    if (restricted && restricted.size > 0) {
      const revoked = this.identity.revoked(iss);
      for (const c of [...restricted]) if (c.auth && revoked.has(c.auth.did)) this.kick(c, undefined, "revoked");
      this.promoteRestricted(iss);
    }
  }

  /**
   * Members-only: after the allowlist, the circle or a provisional admission
   * changed, every live connection of a userId no longer admitted is closed.
   */
  enforceMembers(): void {
    const gone = new Set<string>();
    for (const iss of [...this.byIss.keys(), ...this.restrictedByIss.keys()]) {
      if (!this.members.admitted(iss)) gone.add(iss);
    }
    for (const iss of gone) {
      for (const c of [...(this.byIss.get(iss) ?? []), ...(this.restrictedByIss.get(iss) ?? [])]) this.kick(c, undefined, "not-member");
    }
    if (gone.size > 0) this.log.info("members-only: closed the connections of removed members", { userIds: gone.size });
  }

  /** Replaces the members-only allowlist (and deny list) at runtime (SIGHUP), closing the connections of anyone removed. */
  setAllow(list: readonly string[] | undefined, deny?: readonly string[]): void {
    this.members.setAllow(list, deny);
    this.enforceMembers();
  }

  private onAuth(conn: Conn, msg: Record<string, unknown>, id: string | undefined): void {
    const fail = (why: string, code: ErrorCode = "auth-failed", close: number = CLOSE.authFailed) => {
      this.metrics.inc("auth", { result: "fail" });
      if (this.log.debugEnabled) this.log.debug("auth failed", { conn: conn.id, why });
      this.error(conn, id, code);
      conn.ws.close(close, "auth failed");
    };
    if (conn.auth) return this.error(conn, id, "bad-request");
    // N3: auth attempts per IP bucket (each can create a device row).
    const v4 = isIPv4(conn.ip);
    if (!(v4 ? this.limiters.authsIp4 : this.limiters.authsIp).take(conn.ip)) return fail("rate-limited", "rate-limited", CLOSE.tooManyConnections);
    if (typeof msg.cert !== "string" || typeof msg.sig !== "string") return fail("shape");
    const nowSec = Math.floor(this.now() / 1000);
    let cert: VerifiedDeviceCert;
    try {
      cert = this.crypto.verifyDeviceCert(msg.cert, { now: nowSec });
    } catch {
      return fail("cert");
    }
    // The signature binds this relay's canonical URL and this connection's nonce.
    if (!this.crypto.verifyRelayAuth(cert, this.config.relayUrl, conn.nonce, msg.sig)) return fail("sig");
    // Members-only: refused before anything is stored for this device. A redeemed
    // invite admission (`admit`, the key the inviter's grant hashes) admits it provisionally.
    let admittedBy: "invite" | undefined;
    if (!this.members.admitted(cert.iss)) {
      // Re-checked after redeeming: a redemption admits only someone the relay would admit (not a denied userId).
      if (!(typeof msg.admit === "string" && this.members.redeem(msg.admit, cert.iss) && this.members.admitted(cert.iss))) {
        this.metrics.inc("auth", { result: "not-member" });
        if (this.log.debugEnabled) this.log.debug("auth refused: not a member", { conn: conn.id, iss: redact(cert.iss) });
        this.error(conn, id, "not-member");
        conn.ws.close(CLOSE.authFailed, "not a member");
        return;
      }
      admittedBy = "invite";
      this.log.info("members-only: admitted a userId through a member's invite", { until: Math.floor(this.now() / 1000) + this.config.inviteAdmitSec });
    }
    // §2.3 rule 6, when the relay holds the issuer's identity document.
    const allowed = this.identity.allowedDevices(cert.iss);
    const restricted = allowed !== undefined && !allowed.has(cert.did);
    // §5.2: one iss per did.
    const bound = this.store.deviceIssuer(cert.did);
    if (bound !== undefined && bound !== cert.iss) return fail("did-bound");
    if (restricted) {
      // A did a held (or recently discarded) version listed, and the allowlist doesn't: revoked.
      // Not even a restricted connection; a restore always brings a new did.
      if (this.identity.revoked(cert.iss).has(cert.did)) return fail("revoked");
      // Restricted connections have their own small cap, so they can't crowd out listed devices.
      if ((this.restrictedByIss.get(cert.iss)?.size ?? 0) >= this.config.limits.restrictedPerIss) {
        return fail("too-many-restricted", "full", CLOSE.tooManyConnections);
      }
    } else if ((this.byIss.get(cert.iss)?.size ?? 0) >= this.config.limits.maxConnectionsPerIss) {
      return fail("too-many-for-iss", "full", CLOSE.tooManyConnections);
    }
    if (bound === undefined) {
      // N3/M-4: new device rows are bounded per IP per day and globally. A did
      // listed in its issuer's held identity document is always admitted.
      const listed = allowed?.has(cert.did) ?? false;
      // The IPv4 allowance applies only while the device table has room (pre-release review).
      const devicesPressured = this.deviceCount >= Math.floor(this.config.limits.maxDevices * POOL_PRESSURE);
      const newDevices = v4 && !devicesPressured ? this.limiters.newDevicesIp4 : this.limiters.newDevicesIp;
      if (!listed && !newDevices.has(conn.ip)) return fail("new-device-rate", "rate-limited", CLOSE.tooManyConnections);
      if (this.deviceCount >= this.config.limits.maxDevices && !this.evictDevice() && !listed) {
        return fail("device-cap", "full", CLOSE.tooManyConnections);
      }
      if (!listed) newDevices.take(conn.ip);
    }
    if (this.store.touchDevice(cert.did, cert.iss, this.now())) this.deviceCount++;

    conn.auth = { iss: cert.iss, did: cert.did, cert: msg.cert, certExp: cert.exp, verified: cert, ...(restricted ? { restricted } : {}) };
    this.leaveUnauth(conn);
    this.metrics.inc("auth", { result: restricted ? "restricted" : "ok" });
    if (this.log.debugEnabled) this.log.debug("auth ok", { conn: conn.id, iss: redact(cert.iss), did: redact(cert.did), restricted });
    if (restricted) {
      let rs = this.restrictedByIss.get(cert.iss);
      if (!rs) this.restrictedByIss.set(cert.iss, (rs = new Set()));
      rs.add(conn);
      // Closed if not upgraded in time, and in any case when its certificate expires.
      const untilExp = cert.exp * 1000 - this.now();
      conn.restrictedTimer = setTimeout(() => this.kick(conn, undefined, "restricted-expired"), Math.max(0, Math.min(this.config.limits.restrictedTimeoutSec * 1000, untilExp)));
      conn.restrictedTimer.unref();
      const out: Record<string, unknown> = { t: "ok", restricted: true };
      if (id !== undefined) out.id = id;
      if (admittedBy) out.admitted = admittedBy;
      this.reply(conn, out);
      return;
    }
    let mine = this.byIss.get(cert.iss);
    if (!mine) this.byIss.set(cert.iss, (mine = new Set()));
    mine.add(conn);
    this.bindMailbox(conn, conn.auth);
    this.armCertExpiry(conn);
    const circle = this.members.circleInfo();
    if (circle || admittedBy) {
      // Members-only: the circle this relay follows (so members push its new versions), and
      // whether this auth used an invite admission (so the client can forget the key).
      const out: Record<string, unknown> = { t: "ok" };
      if (id !== undefined) out.id = id;
      if (circle) out.circle = circle;
      if (admittedBy) out.admitted = admittedBy;
      this.reply(conn, out);
    } else this.ok(conn, id);
    // Everything un-acked, in arrival order (§5.4 redelivery).
    this.pump(conn);
  }

  /**
   * A connection lives no longer than its device certificate (review R3: what
   * makes the 91-day memory of discarded dids enough). Timers longer than
   * Node's ~24.8-day maximum re-arm in steps.
   */
  private armCertExpiry(conn: Conn): void {
    if (conn.certTimer) clearTimeout(conn.certTimer);
    conn.certTimer = undefined;
    if (!conn.auth || conn.ws.readyState !== WebSocket.OPEN) return;
    const ms = conn.auth.certExp * 1000 - this.now();
    if (ms <= 0) return this.kick(conn, undefined, "cert-expired", CLOSE.certExpired);
    const max = 2 ** 31 - 1;
    conn.certTimer = setTimeout(() => (ms <= max ? this.kick(conn, undefined, "cert-expired", CLOSE.certExpired) : this.armCertExpiry(conn)), Math.min(ms, max));
    conn.certTimer.unref();
  }

  /** Binds an authenticated, listed connection to its mailbox (iss, did). */
  private bindMailbox(conn: Conn, auth: ConnAuth): void {
    const key = mboxKey(auth.iss, auth.did);
    let set = this.byMailbox.get(key);
    if (!set) this.byMailbox.set(key, (set = new Set()));
    set.add(conn);
  }

  // -------------------------------------------------------------------------
  // §5.4 send

  /**
   * M-4: frees one device row: the least recently seen binding with no stored
   * envelopes, no live connection, and not in its issuer's held allowlist.
   */
  private evictDevice(): boolean {
    // N-L2: the store selects candidates (no envelopes, not in any allowlist)
    // with an indexed query; only live connections are skipped here, and
    // those are bounded by the connection caps.
    let after: { lastSeen: number; did: string } | undefined;
    for (;;) {
      const page = this.store.evictableDevices(64, after);
      if (page.length === 0) return false;
      for (const { did, iss } of page) {
        if (this.byMailbox.has(mboxKey(iss, did))) continue;
        this.store.deleteDevice(did);
        this.deviceCount--;
        return true;
      }
      const last = page[page.length - 1];
      after = { lastSeen: last.lastSeen, did: last.did };
    }
  }

  /**
   * A mailbox exists when the relay holds the recipient's identity document
   * and it lists `tdid` (rule 6 for receivers), or, with no document held,
   * when `tdid` has authenticated here bound to `to`.
   */
  private mailboxKnown(to: string, tdid: string): boolean {
    const bound = this.store.deviceIssuer(tdid);
    if (bound !== undefined && bound !== to) return false;
    const st = this.identity.status(to);
    // L-b: a tombstoned identity has no mailboxes here (its allowlist still gates auth).
    if (st?.left) return false;
    if (st) return st.allowed.has(tdid);
    return bound === to;
  }

  private capKey(iss: string, capid: string): string {
    return b64uEncode(sha256(new TextEncoder().encode(`p2p/relay/cap|${iss}|${capid}`)));
  }

  /**
   * L3/N2: what receivers see as `rid`: the internal rid (8 bytes, big-endian,
   * then 8 zero bytes) encrypted as one AES-128 block under a per-process key.
   * Opaque, deterministic (redelivery keeps the rid), and reversible without
   * any per-connection state.
   */
  private wireRid(rid: number): string {
    const block = Buffer.alloc(16);
    block.writeBigUInt64BE(BigInt(rid), 0);
    const c = createCipheriv("aes-128-ecb", this.ridKey, null).setAutoPadding(false);
    return Buffer.concat([c.update(block), c.final()]).toString("base64url");
  }

  /** The internal rid of a wire rid, or undefined when it isn't one this process issued. */
  private ridFromWire(wire: string): number | undefined {
    const bytes = Buffer.from(wire, "base64url");
    if (bytes.length !== 16) return undefined;
    const d = createDecipheriv("aes-128-ecb", this.ridKey, null).setAutoPadding(false);
    const block = Buffer.concat([d.update(bytes), d.final()]);
    if (!block.subarray(8).equals(Buffer.alloc(8))) return undefined;
    const rid = block.readBigUInt64BE(0);
    return rid <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(rid) : undefined;
  }

  /** N1: the stored tag of a sender's IP bucket, keyed per process. */
  private srcTag(ip: string): string {
    return createHmac("sha256", this.srcKey).update(ip).digest().subarray(0, 12).toString("base64url");
  }

  /** F-6: eviction ranking for an envelope from `src` (the sender pays first, then the largest group). */
  private evictPolicy(quota: number, src: string): EvictPolicy {
    return { floor: Math.max(4096, Math.floor(quota / 16)), sender: src, quota };
  }

  private onSend(conn: Conn, auth: ConnAuth, msg: Record<string, unknown>, id: string | undefined): void {
    const result = (code: ErrorCode | "sent") => {
      this.metrics.inc("sends", { result: code });
      if (code === "sent") this.reply(conn, id === undefined ? { t: "sent" } : { t: "sent", id });
      else this.error(conn, id, code);
    };
    const { to, tdid, env: envJws, cap: capJws, pow } = msg;
    if (typeof to !== "string" || typeof tdid !== "string" || typeof envJws !== "string") return result("bad-envelope");
    if (capJws !== undefined && typeof capJws !== "string") return result("bad-envelope");
    if (pow !== undefined && typeof pow !== "string") return result("bad-envelope");

    // 1. Parses, ≤ 64 KiB, and env.to/tdid match the routing fields.
    const size = Buffer.byteLength(envJws, "utf8");
    if (size > this.config.limits.envelopeBytes) return result("too-large");
    let env: OuterEnvelope;
    try {
      env = this.crypto.parseOuterEnvelope(envJws);
    } catch {
      return result("bad-envelope");
    }
    if (env.to !== to || env.tdid !== tdid) return result("bad-envelope");

    // Cheap checks before any signature work (M3). Relay policy: a connection
    // sends only its own device's envelopes, so a captured envelope can't be
    // replayed into this relay by someone else.
    if (env.from !== auth.iss || env.fdid !== auth.did) return result("bad-envelope");
    // Members-only: nothing is stored for someone who can't come and get it.
    if (!this.members.admitted(env.to)) return result("undeliverable");
    // Rule 6 for the sender, from the cached allowlist (M1).
    const senderAllowed = this.identity.allowedDevices(auth.iss);
    if (senderAllowed && !senderAllowed.has(auth.did)) return this.kick(conn, id, "sender-revoked");
    // 120 sends/min per env.from, and byte budgets per connection and per IP
    // (H2), all before signatures and before a cap's `uses` can be spent.
    const L = this.limiters;
    const connKey = String(conn.id);
    if (!L.sends.has(env.from) || !L.sendBytesConn.has(connKey, size) || !L.sendBytesIp.has(conn.ip, size)) {
      return result("rate-limited");
    }
    L.sends.take(env.from);
    L.sendBytesConn.take(connKey, size);
    L.sendBytesIp.take(conn.ip, size);

    // 2. fcert (§2.3 rules 1–5) and the envelope signature under fcert.spk.
    // An fcert byte-identical to the authenticated cert was verified at auth.
    const nowMs = this.now();
    const nowSec = Math.floor(nowMs / 1000);
    try {
      let fcert: VerifiedDeviceCert;
      if (env.fcert === auth.cert) {
        if (nowSec >= auth.certExp) return result("bad-envelope");
        fcert = auth.verified;
      } else {
        fcert = this.crypto.verifyDeviceCert(env.fcert, { now: nowSec });
      }
      this.crypto.verifyEnvelope(env, fcert);
    } catch {
      return result("bad-envelope");
    }

    // N1: quotas checked before the mailbox lookup, so known and unknown
    // mailboxes always get the same answer. The store-wide hard ceiling is a
    // last resort: normally eviction keeps the store under storeMaxBytes.
    const src = this.srcTag(conn.ip);
    const quota = (): ErrorCode | undefined => {
      if (this.storedBytes + size > this.config.limits.storeHardMaxBytes) return "undeliverable";
      if (!this.limiters.sourceAccepted.has(conn.ip, size)) return "rate-limited";
      return undefined;
    };

    if (capJws !== undefined) {
      // 3. With a cap: every failure is the one `undeliverable` code.
      let cap: VerifiedCap;
      try {
        cap = this.crypto.verifyCapForSend(capJws, {
          relayUrl: this.config.relayUrl,
          to,
          envFrom: env.from,
          kind: env.kind,
          now: nowSec,
        });
      } catch {
        return result("undeliverable");
      }
      // L1: a cap signed by a device the issuer's document no longer lists.
      const issuerAllowed = this.identity.allowedDevices(cap.iss);
      if (issuerAllowed && !issuerAllowed.has(cap.signerDid)) return result("undeliverable");
      const key = this.capKey(cap.iss, cap.capid);
      const state = this.store.capState(key);
      if (state.revoked) return result("undeliverable");
      if (cap.uses !== undefined && state.uses >= cap.uses) return result("undeliverable");
      const over = quota();
      if (over) return result(over);
      if (!this.mailboxKnown(to, tdid)) return result("undeliverable");
      if (cap.uses !== undefined) this.store.useCap(key, nowMs);
      this.limiters.sourceAccepted.take(conn.ip, size);
      result("sent");
      return this.storeAndDeliver(to, tdid, envJws, size, nowMs, src);
    }

    // 4. Without a cap: contact only, rate-limited three ways, PoW when asked.
    if (env.kind !== "contact") return result("undeliverable");
    const pairKey = `${env.from}\n${to}`;
    if (!L.contactSender.has(env.from) || !L.contactPair.has(pairKey) || !L.contactIp.has(conn.ip)) {
      return result("rate-limited");
    }
    if (conn.pow > 0) {
      let nonce: Uint8Array;
      try {
        if (pow === undefined || pow.length > 128) throw new Error("pow");
        nonce = b64uDecode(pow);
      } catch {
        return result("undeliverable");
      }
      if (!this.crypto.powOk(env.bytes, nonce, conn.pow)) return result("undeliverable");
    }
    L.contactSender.take(env.from);
    L.contactPair.take(pairKey);
    L.contactIp.take(conn.ip);
    // The quota is checked before the mailbox lookup, so a full relay answers
    // known and unknown mailboxes alike.
    const over = quota();
    if (over) return result(over);
    // Charged whether or not the mailbox exists (M-3).
    this.limiters.sourceAccepted.take(conn.ip, size);
    const known = this.mailboxKnown(to, tdid);
    // L2: answer before any store work, so timing doesn't tell a stored
    // contact from a silently dropped one (unknown mailbox, §5.4).
    result("sent");
    if (known) this.storeAndDeliver(to, tdid, envJws, size, nowMs, src);
  }

  /**
   * Stores an envelope, first evicting to stay under the quotas (N1): the
   * recipient's own oldest envelopes past recipientMaxBytes, then the oldest
   * envelopes of the largest mailboxes past storeMaxBytes. Filling the relay
   * therefore churns the biggest (usually the attacker's) mailboxes instead of
   * refusing everyone.
   */
  private storeAndDeliver(to: string, tdid: string, env: string, size: number, now: number, src: string): void {
    const L = this.config.limits;
    try {
      this.store.transaction(() => {
        let evicted = 0;
        // N-M2: a source over its stored-bytes share loses its own oldest first.
        const forSource = this.store.sourceBytes(src) + size - L.sourceMaxBytes;
        if (forSource > 0) evicted += this.store.evictSource(src, forSource);
        const forRecipient = this.store.bytesForRecipient(to) + size - L.recipientMaxBytes;
        if (forRecipient > 0) evicted += this.store.evictRecipient(to, forRecipient, this.evictPolicy(L.recipientMaxBytes, src));
        const global = this.storedBytes - evicted + size - L.storeMaxBytes;
        if (global > 0) evicted += this.store.evictGlobal(global, this.evictPolicy(L.storeMaxBytes, src));
        const { droppedBytes } = this.store.putEnvelope(
          { to, tdid, env, size, receivedAt: now, src },
          { maxEnvelopes: L.mailboxEnvelopes, maxBytes: L.mailboxBytes },
        );
        this.storedBytes = Math.max(0, this.storedBytes - evicted + size - droppedBytes);
        if (evicted > 0) this.metrics.inc("envelopes_evicted");
      });
    } catch (e) {
      this.log.error("store failed", { error: (e as Error).message });
      return;
    }
    for (const c of this.byMailbox.get(mboxKey(to, tdid)) ?? []) this.pump(c);
  }

  /** Sends the connection every stored envelope after the last one it was sent, in rid order, with backpressure. */
  private pump(conn: Conn): void {
    if (!conn.auth || conn.pumping) return;
    conn.pumping = true;
    try {
      const { iss, did } = conn.auth;
      const notBefore = this.now() - this.config.limits.retentionSec * 1000;
      while (conn.ws.readyState === WebSocket.OPEN) {
        if (conn.ws.bufferedAmount > HIGH_WATER_BYTES) {
          if (!conn.pumpTimer) {
            conn.pumpTimer = setTimeout(() => {
              conn.pumpTimer = undefined;
              this.pump(conn);
            }, 25);
          }
          break;
        }
        const rows = this.store.envelopesAfter(iss, did, conn.lastSentRid, notBefore, DELIVERY_PAGE);
        if (rows.length === 0) {
          // §5.4: the backlog is out. Once per connection, so a short command can stop listening
          // for queued envelopes at once instead of waiting out a quiet period.
          if (!conn.caughtUp) {
            conn.caughtUp = true;
            conn.ws.send('{"t":"caught-up"}');
          }
          break;
        }
        for (const r of rows) {
          conn.ws.send(JSON.stringify({ t: "env", rid: this.wireRid(r.rid), env: r.env }));
          conn.lastSentRid = r.rid;
        }
      }
    } finally {
      conn.pumping = false;
    }
  }

  private onAck(conn: Conn, auth: ConnAuth, msg: Record<string, unknown>, id: string | undefined): void {
    const rids = msg.rids;
    if (!Array.isArray(rids) || rids.length > MAX_ACK_RIDS) return this.error(conn, id, "bad-request");
    if (!rids.every((r) => typeof r === "string" && WIRE_RID_RE.test(r))) return this.error(conn, id, "bad-request");
    const internal: number[] = [];
    for (const r of rids as string[]) {
      const rid = this.ridFromWire(r);
      if (rid !== undefined) internal.push(rid);
    }
    // Scoped to this connection's mailbox by the store.
    const { bytes } = this.store.ackEnvelopes(auth.iss, auth.did, internal);
    this.storedBytes = Math.max(0, this.storedBytes - bytes);
  }

  // -------------------------------------------------------------------------
  // §5.3 revoke

  private onRevoke(conn: Conn, auth: ConnAuth, msg: Record<string, unknown>, id: string | undefined): void {
    const capid = msg.capid;
    let ok = typeof capid === "string";
    if (ok) {
      try {
        b64uDecode(capid as string, 16);
      } catch {
        ok = false;
      }
    }
    if (!ok) return this.error(conn, id, "bad-request");
    // H2: each revoke writes a row, so it's rate-limited per connection and per userId.
    if (!this.limiters.revokeConn.has(String(conn.id)) || !this.limiters.revokeIss.has(auth.iss)) {
      return this.error(conn, id, "rate-limited");
    }
    this.limiters.revokeConn.take(String(conn.id));
    this.limiters.revokeIss.take(auth.iss);
    // Keyed by (revoker's iss, capid): it can only ever affect caps whose
    // `iss` is the revoker, which is "only an authenticated device of cap.iss".
    this.store.revokeCap(this.capKey(auth.iss, capid as string), this.now());
    this.metrics.inc("revokes");
    this.ok(conn, id);
  }

  // -------------------------------------------------------------------------
  // §5.6 identity publish

  private onIdentity(conn: Conn, auth: ConnAuth, msg: Record<string, unknown>, id: string | undefined): void {
    if (auth.restricted) return this.onRestrictedIdentity(conn, auth, msg, id);
    if (!this.limiters.identityIss.has(auth.iss) || !this.limiters.identityIp.has(conn.ip)) {
      this.metrics.inc("identity_publish", { result: "rate-limited" });
      return this.error(conn, id, "rate-limited");
    }
    this.limiters.identityIss.take(auth.iss);
    this.limiters.identityIp.take(conn.ip);
    const r = this.identity.publish(msg.doc, auth.iss);
    this.metrics.inc("identity_publish", { result: r.ok ? (r.left ? "left" : r.duplicate ? "duplicate" : "ok") : r.code });
    if (!r.ok) return this.error(conn, id, r.code);
    this.ok(conn, id);
    // M1: a new version may have dropped devices with live sessions.
    if (!r.duplicate) this.enforceAllowlist(auth.iss);
  }

  /**
   * §2.7 restore over a restricted connection (H1/H2). The document is parsed
   * before anything is charged, and charged to its own limiter. Only a
   * version on top of the held history is accepted (one that extends every
   * tip, or merges them): never a fork, so a stale or stolen key holder can't
   * split the allowlist away from the restored device. When the version lists
   * this device (and its certificate is still valid), the connection becomes
   * a full one.
   */
  private onRestrictedIdentity(conn: Conn, auth: ConnAuth, msg: Record<string, unknown>, id: string | undefined): void {
    if (typeof msg.doc !== "string") return this.error(conn, id, "bad-identity");
    try {
      this.crypto.parseIdentityDoc(msg.doc);
    } catch {
      return this.error(conn, id, "bad-identity");
    }
    // Charged once per restricted connection: a restore that back-fills a lagging relay sends
    // several chaining versions in a row (review N-L1).
    if (!auth.charged) {
      if (!this.limiters.identityRestricted.take(auth.iss)) {
        this.metrics.inc("identity_publish", { result: "rate-limited" });
        return this.error(conn, id, "rate-limited");
      }
      auth.charged = true;
    }
    const r = this.identity.publish(msg.doc, auth.iss, { topOnly: true });
    this.metrics.inc("identity_publish", { result: r.ok ? (r.duplicate ? "duplicate" : "restricted") : r.code });
    if (!r.ok) return this.error(conn, id, r.code);
    this.ok(conn, id);
    if (!r.duplicate) this.enforceAllowlist(auth.iss);
  }

  /**
   * After the allowlist of `iss` changes: every restricted connection whose
   * device it now lists becomes a full one (not only the publishing one,
   * pre-release review), its certificate re-checked.
   */
  private promoteRestricted(iss: string): void {
    const allowed = this.identity.allowedDevices(iss);
    const set = this.restrictedByIss.get(iss);
    if (!allowed || !set) return;
    const nowSec = Math.floor(this.now() / 1000);
    for (const conn of [...set]) {
      const auth = conn.auth;
      if (!auth || !allowed.has(auth.did) || conn.ws.readyState !== WebSocket.OPEN) continue;
      if (nowSec >= auth.certExp) {
        this.kick(conn, undefined, "cert-expired", CLOSE.certExpired);
        continue;
      }
      if ((this.byIss.get(iss)?.size ?? 0) >= this.config.limits.maxConnectionsPerIss) {
        this.kick(conn, undefined, "too-many-for-iss");
        continue;
      }
      this.unregister(conn, auth);
      auth.restricted = undefined;
      let mine = this.byIss.get(iss);
      if (!mine) this.byIss.set(iss, (mine = new Set()));
      mine.add(conn);
      this.bindMailbox(conn, auth);
      this.armCertExpiry(conn);
      this.pump(conn);
    }
  }

  // -------------------------------------------------------------------------
  // §5.7 link mailboxes

  private onLinkOpen(conn: Conn, auth: ConnAuth, msg: Record<string, unknown>, id: string | undefined): void {
    if (typeof msg.lid !== "string" || !LID_RE.test(msg.lid)) return this.error(conn, id, "bad-request");
    if (!this.limiters.linkOpenIss.has(auth.iss) || !this.limiters.linkOpenIp.has(conn.ip)) {
      this.metrics.inc("link", { op: "open", result: "rate-limited" });
      return this.error(conn, id, "rate-limited");
    }
    this.limiters.linkOpenIss.take(auth.iss);
    this.limiters.linkOpenIp.take(conn.ip);
    const r = this.links.open(msg.lid, conn.id, auth.did, conn.ip);
    this.metrics.inc("link", { op: "open", result: r });
    if (r !== "ok") return this.error(conn, id, r === "exists" ? "exists" : "full");
    this.ok(conn, id);
  }

  private linkArgs(msg: Record<string, unknown>): { lid: string; slot: LinkSlot } | undefined {
    const { lid, slot } = msg;
    if (typeof lid !== "string" || !LID_RE.test(lid)) return undefined;
    if (slot !== "req" && slot !== "resp") return undefined;
    return { lid, slot };
  }

  private onLinkPut(conn: Conn, msg: Record<string, unknown>, id: string | undefined): void {
    if (!this.limiters.link.take(conn.ip)) {
      this.metrics.inc("link", { op: "put", result: "rate-limited" });
      return this.error(conn, id, "rate-limited");
    }
    const a = this.linkArgs(msg);
    if (!a || typeof msg.data !== "string") return this.error(conn, id, "bad-request");
    const r = this.links.put(a.lid, a.slot, msg.data, conn.id);
    this.metrics.inc("link", { op: "put", result: r });
    if (r !== "ok") return this.error(conn, id, r === "too-large" ? "too-large" : r === "forbidden" ? "forbidden" : r === "full" ? "full" : "not-found");
    this.ok(conn, id);
  }

  private onLinkGet(conn: Conn, msg: Record<string, unknown>, id: string | undefined): void {
    if (!this.limiters.link.take(conn.ip)) {
      this.metrics.inc("link", { op: "get", result: "rate-limited" });
      return this.error(conn, id, "rate-limited");
    }
    const a = this.linkArgs(msg);
    if (!a) return this.error(conn, id, "bad-request");
    const entries = this.links.get(a.lid, a.slot);
    this.metrics.inc("link", { op: "get", result: entries ? "ok" : "not-found" });
    if (!entries) return this.error(conn, id, "not-found");
    const out: Record<string, unknown> = { t: "link", lid: a.lid, slot: a.slot, entries };
    if (id !== undefined) out.id = id;
    this.reply(conn, out);
  }

  // -------------------------------------------------------------------------
  // P4 short-code invite mailboxes
  //
  // An authenticated device puts a sealed blob under `lid`, a hash of a code
  // secret the relay never sees; anyone may take it once (unauthenticated,
  // per-IP limited, misses limited harder). There is deliberately no
  // non-consuming read: a take is what lets the inviter notice an intercepted
  // code (docs/protocol.md P4).

  private onInvitePut(conn: Conn, auth: ConnAuth, msg: Record<string, unknown>, id: string | undefined): void {
    const L = this.config.limits;
    const { lid, blob, ttl, admit } = msg;
    if (typeof lid !== "string" || !LID_RE.test(lid) || typeof blob !== "string" || blob.length === 0) return this.error(conn, id, "bad-request");
    if (typeof ttl !== "number" || !Number.isSafeInteger(ttl) || ttl < 1) return this.error(conn, id, "bad-request");
    if (admit !== undefined && (typeof admit !== "string" || !ADMIT_RE.test(admit))) return this.error(conn, id, "bad-request");
    // Members-only: only a full member's code may admit its redeemer (a provisional member's can't).
    const admits = this.members.enabled && this.config.inviteAdmitSec > 0 && typeof admit === "string";
    if (admits && !this.members.isFull(auth.iss)) {
      this.metrics.inc("invite", { op: "put", result: "forbidden" });
      return this.error(conn, id, "forbidden");
    }
    const size = Buffer.byteLength(blob, "utf8");
    if (size > L.inviteBlobBytes) {
      this.metrics.inc("invite", { op: "put", result: "too-large" });
      return this.error(conn, id, "too-large");
    }
    if (!this.limiters.invitePutIss.has(auth.iss) || !this.limiters.invitePutIp.has(conn.ip)) {
      this.metrics.inc("invite", { op: "put", result: "rate-limited" });
      return this.error(conn, id, "rate-limited");
    }
    this.limiters.invitePutIss.take(auth.iss);
    this.limiters.invitePutIp.take(conn.ip);
    const now = this.now();
    if (this.store.invitesOf(auth.iss, now).length >= L.inviteOpenPerIss) {
      this.metrics.inc("invite", { op: "put", result: "full" });
      return this.error(conn, id, "full");
    }
    const full = (why: string) => {
      this.metrics.inc("invite", { op: "put", result: why });
      return this.error(conn, id, "full");
    };
    // M2: one network can hold only so many bytes (IPv6 counted per /48), so a handful of
    // addresses can't fill the store.
    const src = this.srcTag(ipBucket48(conn.ip));
    if (this.store.inviteBytesOfSrc(src) + size > L.inviteBytesPerIp) return full("full-ip");
    if (this.store.inviteBytes() + size > L.inviteTotalBytes * 0.9) {
      // One bounded step here (F-4); the periodic sweep does the rest, and
      // eviction below takes expired invites before any live one.
      this.store.sweepInvites(now, this.inviteSweepRows);
      // The last tenth is reserved for identities the relay has known for a while.
      if (this.store.inviteBytes() + size > L.inviteTotalBytes * 0.9 && this.identityYoung(auth.iss, now)) return full("full-young");
      // Completely full: the userIds holding the most bytes lose their newest invites, rather
      // than everyone being refused.
      const over = this.store.inviteBytes() + size - L.inviteTotalBytes;
      if (over > 0 && this.store.evictInvites(over, now) < over) return full("full");
    }
    const expiresAt = now + Math.min(ttl, L.inviteTtlMaxSec) * 1000;
    if (!this.store.putInvite({ lid, iss: auth.iss, blob, size, createdAt: now, expiresAt, src })) {
      this.metrics.inc("invite", { op: "put", result: "exists" });
      return this.error(conn, id, "exists");
    }
    this.metrics.inc("invite", { op: "put", result: "ok" });
    const out: Record<string, unknown> = { t: "ok", exp: Math.floor(expiresAt / 1000) };
    // The grant outlives the take (the redeemer authenticates after taking the blob) but not the code.
    if (admits && this.members.grant(lid, admit, auth.iss, expiresAt)) out.admits = true;
    if (id !== undefined) out.id = id;
    this.reply(conn, out);
  }

  /** Whether the relay first saw `iss` (its oldest held document) less than inviteYoungIdentitySec ago. */
  private identityYoung(iss: string, now: number): boolean {
    const docs = this.store.identityDocs(iss);
    if (docs.length === 0) return true;
    const first = Math.min(...docs.map((d) => d.receivedAt));
    return now - first < this.config.limits.inviteYoungIdentitySec * 1000;
  }

  private onInviteGet(conn: Conn, msg: Record<string, unknown>, id: string | undefined): void {
    // Every get costs a token; a miss costs one more from a much smaller hourly budget, which
    // gates every further get from that IP bucket: guessing 100-bit codes stays hopeless.
    if (!this.limiters.inviteMiss.has(conn.ip) || !this.limiters.inviteGet.take(conn.ip)) {
      this.metrics.inc("invite", { op: "get", result: "rate-limited" });
      return this.error(conn, id, "rate-limited");
    }
    if (typeof msg.lid !== "string" || !LID_RE.test(msg.lid)) return this.error(conn, id, "bad-request");
    const inv = this.store.takeInvite(msg.lid, this.now());
    if (!inv) {
      this.limiters.inviteMiss.take(conn.ip);
      this.metrics.inc("invite", { op: "get", result: "not-found" });
      return this.error(conn, id, "not-found");
    }
    this.metrics.inc("invite", { op: "get", result: "ok" });
    const out: Record<string, unknown> = { t: "invite", lid: inv.lid, blob: inv.blob };
    if (id !== undefined) out.id = id;
    this.reply(conn, out);
  }

  private onInviteDel(conn: Conn, auth: ConnAuth, msg: Record<string, unknown>, id: string | undefined): void {
    if (typeof msg.lid !== "string" || !LID_RE.test(msg.lid)) return this.error(conn, id, "bad-request");
    // A revoked code admits nobody, even when its blob was already taken (the reply still says
    // whether the invite itself was there, so the inviter can tell a taken code).
    // Whoever the code already admitted provisionally loses that too.
    if (this.members.revokeInvite(msg.lid, auth.iss)) this.enforceMembers();
    const ok = this.store.deleteInvite(msg.lid, auth.iss);
    this.metrics.inc("invite", { op: "del", result: ok ? "ok" : "not-found" });
    if (!ok) return this.error(conn, id, "not-found");
    this.ok(conn, id);
  }

  private onInviteList(conn: Conn, auth: ConnAuth, id: string | undefined): void {
    const now = this.now();
    // `evicted`: lids the relay dropped to make room (full store), until they would have expired,
    // so the inviter can tell an evicted code from one somebody took.
    const out: Record<string, unknown> = { t: "invites", lids: this.store.invitesOf(auth.iss, now), evicted: this.store.evictedInvitesOf(auth.iss, now) };
    if (id !== undefined) out.id = id;
    this.reply(conn, out);
  }

  // -------------------------------------------------------------------------
  // Members-only circle admission

  /**
   * `{t: "circle-put", versions: [jws…]}`: versions of the circle named by
   * RELAY_ALLOW_CIRCLE. The relay verifies them itself (owner-signed, chained
   * from version 1); a new head re-decides who is admitted at once.
   */
  private onCirclePut(conn: Conn, auth: ConnAuth, msg: Record<string, unknown>, id: string | undefined): void {
    if (!this.members.circleId) return this.error(conn, id, "not-found");
    if (!this.limiters.circlePut.take(auth.iss)) {
      this.metrics.inc("circle_put", { result: "rate-limited" });
      return this.error(conn, id, "rate-limited");
    }
    const r = this.members.putCircle(auth.iss, msg.versions);
    this.metrics.inc("circle_put", { result: r.ok ? r.status : r.code });
    if (!r.ok) {
      if (this.log.debugEnabled) this.log.debug("circle-put refused", { conn: conn.id, why: r.reason.slice(0, 120) });
      return this.error(conn, id, r.code);
    }
    const out: Record<string, unknown> = { t: "ok", ver: r.ver, status: r.status };
    if (id !== undefined) out.id = id;
    this.reply(conn, out);
    if (r.changed) {
      this.log.info("members-only: circle head", r.status === "seeded" ? { ver: r.ver, seeded: true } : { ver: r.ver });
      this.enforceMembers();
    }
  }
}
