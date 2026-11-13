// Copyright 2026 Ix Infrastructure Inc.
//
// Relay configuration: defaults (docs/protocol.md §5.4, §5.7), then an
// optional preset (RELAY_PRESET), then an optional JSON file (RELAY_CONFIG),
// then environment variables.

import { readFileSync } from "node:fs";
import type { RelayCrypto } from "./crypto.js";

export interface RelayLimits {
  /** Largest WebSocket frame accepted (§5.2: 96 KiB). */
  frameBytes: number;
  /** Largest envelope JWS (§1: 64 KiB). */
  envelopeBytes: number;
  /** Envelopes per mailbox before the oldest is dropped (§5.4). */
  mailboxEnvelopes: number;
  /** Bytes per mailbox before the oldest is dropped (§5.4: 64 MiB). */
  mailboxBytes: number;
  /** How long an un-acked envelope is kept (§5.4: 7 days). */
  retentionSec: number;
  /** Sends per minute per `env.from` (§5.4). */
  sendsPerMinute: number;
  /** Cap-less `contact` limits (§5.4 step 4). */
  contactPerSenderPerHour: number;
  contactPerPairPerHour: number;
  contactPerIpPerHour: number;
  /** Unauthenticated link-put/link-get per source IP (§5.7). */
  linkOpsPerIpPerMinute: number;
  /** Link mailbox lifetime (§5.7: 10 minutes). */
  linkTtlSec: number;
  /** Entries in a link mailbox's `req` slot (§5.7: 4). */
  linkReqEntries: number;
  /** Bytes per link entry (§5.7: 16 KiB). */
  linkEntryBytes: number;
  /** Link mailboxes one device may hold open at once. */
  linkOpenPerDevice: number;
  /** How long non-head identity versions are kept (§5.6: 90 days). */
  identityVersionRetentionSec: number;
  /** Largest `n` for the chain walk (§5.6: 64). */
  chainMaxN: number;
  /**
   * Concurrent WebSocket connections, in total and per source IP. The per-IP
   * value applies to IPv6 /64 buckets; IPv4 addresses, which are routinely
   * shared (carrier NAT, campuses, offices), use `maxConnectionsPerIpv4` (F-5).
   */
  maxConnections: number;
  maxConnectionsPerIp: number;
  maxConnectionsPerIpv4: number;
  /** HTTP requests per source IP per minute. */
  httpPerIpPerMinute: number;
  /**
   * How long a connection may stay unauthenticated. hello/auth is one round
   * trip; link-put/link-get clients reconnect to keep polling.
   */
  unauthTimeoutSec: number;
  /** Unauthenticated connections at once (the rest of maxConnections stays free for authenticated ones). */
  maxUnauthConnections: number;
  /** Concurrent connections per userId. */
  maxConnectionsPerIss: number;
  /**
   * Restricted connections (a valid certificate for a device the held document
   * doesn't list; publish-only, §2.7 restore) per userId, kept apart from
   * maxConnectionsPerIss so they can't crowd out listed devices.
   */
  restrictedPerIss: number;
  /** A restricted connection that hasn't been upgraded (its device listed) is closed after this long. */
  restrictedTimeoutSec: number;
  /** Identity publishes per userId per hour over restricted connections (charged only for a parsable document). */
  restrictedIdentityPerIssPerHour: number;
  /** Frames of any type per connection per minute. */
  framesPerConnPerMinute: number;
  /** Envelope bytes sent per connection, and per source IP (/64 for IPv6), per minute. */
  sendBytesPerConnPerMinute: number;
  sendBytesPerIpPerMinute: number;
  /**
   * Total envelope bytes the relay aims to store. Past it, the oldest
   * envelopes of the largest mailboxes are evicted to make room.
   */
  storeMaxBytes: number;
  /** Hard ceiling: past it (eviction can't keep up), sends get `undeliverable`. */
  storeHardMaxBytes: number;
  /** Stored bytes per recipient userId; past it, that recipient's oldest are evicted. */
  recipientMaxBytes: number;
  /**
   * Stored bytes per sending IP (/64 for IPv6): the long-horizon disk-fairness
   * share. Past it, that source's OWN oldest envelopes are evicted; nothing is
   * refused, so it isn't visible to a prober.
   */
  sourceMaxBytes: number;
  /**
   * Bytes accepted from one sending IP per hour, refilling continuously. Past
   * it, sends are rate-limited. Counts silently dropped contacts too and never
   * refunds, so it reveals nothing about recipients.
   */
  sourceAcceptedBytesPerHour: number;
  /** Unauthenticated connections per source IP. */
  maxUnauthPerIp: number;
  /**
   * New device bindings per source IP per day (dids listed in a held identity
   * document are exempt): IPv6 /64, and IPv4.
   */
  newDevicesPerIpPerDay: number;
  newDevicesPerIpv4PerDay: number;
  /** New WebSocket connections, and auth attempts, per source IP per minute (auths: IPv6 /64; IPv4 below). */
  connectsPerIpPerMinute: number;
  authsPerIpPerMinute: number;
  authsPerIpv4PerMinute: number;
  /** Device bindings (did -> iss rows) the relay keeps; new devices past it are refused. */
  maxDevices: number;
  /** `revoke` frames per connection per minute, and per userId per hour. */
  revokesPerConnPerMinute: number;
  revokesPerIssPerHour: number;
  /** How long a did -> iss binding is kept after the device was last seen. */
  deviceRetentionSec: number;
  /** Identity publishes per userId, and per source IP, per hour. */
  identityPublishPerIssPerHour: number;
  identityPublishPerIpPerHour: number;
  /** Branch tips (§2.5 forks) and versions kept per userId. */
  identityMaxTips: number;
  identityMaxVersions: number;
  /** A userId whose head expired longer ago than this is tombstoned (documents deleted, allowlist kept). */
  identityExpiredRetentionSec: number;
  /** How long a tombstone keeps the last allowlist (longer than a revoked device's cert can live). */
  identityTombstoneRetentionSec: number;
  /** link-open per userId and per source IP per hour, and open link mailboxes per source IP. */
  linkOpenPerIssPerHour: number;
  linkOpenPerIpPerHour: number;
  linkOpenPerIp: number;
  /** Bytes held across all link mailboxes. */
  linkTotalBytes: number;
  /** P4 short-code invites: the longest TTL a put may ask for (7 days). */
  inviteTtlMaxSec: number;
  /** Bytes per sealed invite blob (32 KiB). */
  inviteBlobBytes: number;
  /** invite-put per userId and per source IP per hour. */
  invitePutPerIssPerHour: number;
  invitePutPerIpPerHour: number;
  /** Invites one userId may hold open at once. */
  inviteOpenPerIss: number;
  /** Bytes held across every invite. */
  inviteTotalBytes: number;
  /** Bytes of open invites per source network (an IPv4 address, or an IPv6 /48). */
  inviteBytesPerIp: number;
  /**
   * The last tenth of inviteTotalBytes is reserved: once past 90%, identities
   * the relay first saw less than this long ago can't put.
   */
  inviteYoungIdentitySec: number;
  /** Unauthenticated invite-get per source IP per minute, and misses (not-found) per source IP per hour. */
  inviteGetsPerIpPerMinute: number;
  inviteMissesPerIpPerHour: number;
}

export const DEFAULT_LIMITS: Readonly<RelayLimits> = Object.freeze({
  frameBytes: 96 * 1024,
  envelopeBytes: 64 * 1024,
  mailboxEnvelopes: 10_000,
  mailboxBytes: 64 * 1024 * 1024,
  retentionSec: 7 * 24 * 3600,
  sendsPerMinute: 120,
  contactPerSenderPerHour: 60,
  contactPerPairPerHour: 3,
  contactPerIpPerHour: 120,
  linkOpsPerIpPerMinute: 60,
  linkTtlSec: 600,
  linkReqEntries: 4,
  linkEntryBytes: 16 * 1024,
  linkOpenPerDevice: 4,
  identityVersionRetentionSec: 90 * 24 * 3600,
  chainMaxN: 64,
  maxConnections: 10_000,
  maxConnectionsPerIp: 64,
  maxConnectionsPerIpv4: 512,
  httpPerIpPerMinute: 600,
  unauthTimeoutSec: 15,
  maxUnauthConnections: 2_000,
  maxConnectionsPerIss: 16,
  restrictedPerIss: 2,
  restrictedTimeoutSec: 60,
  restrictedIdentityPerIssPerHour: 6,
  framesPerConnPerMinute: 600,
  sendBytesPerConnPerMinute: 8 * 1024 * 1024,
  sendBytesPerIpPerMinute: 32 * 1024 * 1024,
  storeMaxBytes: 4 * 1024 * 1024 * 1024,
  storeHardMaxBytes: 5 * 1024 * 1024 * 1024,
  recipientMaxBytes: 256 * 1024 * 1024,
  sourceMaxBytes: 512 * 1024 * 1024,
  sourceAcceptedBytesPerHour: 256 * 1024 * 1024,
  maxUnauthPerIp: 8,
  newDevicesPerIpPerDay: 50,
  newDevicesPerIpv4PerDay: 1000,
  connectsPerIpPerMinute: 120,
  authsPerIpPerMinute: 60,
  authsPerIpv4PerMinute: 600,
  maxDevices: 1_000_000,
  revokesPerConnPerMinute: 30,
  revokesPerIssPerHour: 600,
  deviceRetentionSec: 90 * 24 * 3600,
  identityPublishPerIssPerHour: 30,
  identityPublishPerIpPerHour: 120,
  identityMaxTips: 4,
  identityMaxVersions: 128,
  identityExpiredRetentionSec: 90 * 24 * 3600,
  identityTombstoneRetentionSec: 91 * 24 * 3600,
  linkOpenPerIssPerHour: 20,
  linkOpenPerIpPerHour: 60,
  linkOpenPerIp: 8,
  linkTotalBytes: 64 * 1024 * 1024,
  inviteTtlMaxSec: 7 * 24 * 3600,
  inviteBlobBytes: 32 * 1024,
  invitePutPerIssPerHour: 20,
  invitePutPerIpPerHour: 60,
  inviteOpenPerIss: 20,
  inviteTotalBytes: 256 * 1024 * 1024,
  inviteBytesPerIp: 2 * 1024 * 1024,
  inviteYoungIdentitySec: 24 * 3600,
  inviteGetsPerIpPerMinute: 10,
  inviteMissesPerIpPerHour: 30,
});

const MiB = 1024 * 1024;

/**
 * SQLite tuning passed to the store. Unset fields keep the store's defaults
 * (sqlite-store.ts: WAL watchdog limit 256 MiB, journal_size_limit 64 MiB,
 * checkpoint every 100 ms).
 */
export interface StorageTuning {
  /** A WAL larger than this means checkpoints aren't keeping up (the watchdog then intervenes). */
  walLimitBytes?: number;
  /** After a checkpoint, the WAL file is truncated back to this size. */
  journalSizeLimitBytes?: number;
  /** How often the background thread checkpoints the WAL (10 ms to 10 s). */
  checkpointIntervalMs?: number;
}

export type RelayPresetName = "small";

export interface RelayPreset {
  limits: Partial<RelayLimits>;
  storage: StorageTuning;
}

/**
 * Named presets that sit between DEFAULT_LIMITS and the JSON file / env vars.
 * They only lower capacity limits; the protocol sizes (frames, envelopes,
 * retention, link and invite formats) stay the protocol's.
 *
 * `small`: a private team relay (up to about 50 people) on a 2 GB single-board
 * computer such as a Jetson Nano or a Raspberry Pi, with its database on a USB
 * SSD. About 512 MiB of envelopes at most, a few hundred connections, and a
 * smaller write-ahead log. Pair it with NODE_OPTIONS=--max-old-space-size=384
 * and a container memory limit of 768 MiB (docs/run-a-relay-on-any-machine.md).
 * Per-address limits are moderate: still far above what a 50-person team
 * needs, but low enough that one outside address can't take every connection
 * or fill the device table when the relay sits behind a public tunnel. An
 * office behind one NAT address can raise them (docs/run-a-relay-on-any-machine.md).
 */
export const RELAY_PRESETS: Readonly<Record<RelayPresetName, Readonly<RelayPreset>>> = Object.freeze({
  small: Object.freeze({
    limits: Object.freeze({
      mailboxEnvelopes: 2_000,
      mailboxBytes: 16 * MiB,
      maxConnections: 400,
      maxConnectionsPerIp: 64,
      maxConnectionsPerIpv4: 64,
      maxUnauthConnections: 100,
      maxUnauthPerIp: 8,
      sendBytesPerConnPerMinute: 4 * MiB,
      sendBytesPerIpPerMinute: 16 * MiB,
      storeMaxBytes: 448 * MiB,
      storeHardMaxBytes: 512 * MiB,
      recipientMaxBytes: 32 * MiB,
      sourceMaxBytes: 256 * MiB,
      sourceAcceptedBytesPerHour: 128 * MiB,
      newDevicesPerIpPerDay: 100,
      newDevicesPerIpv4PerDay: 100,
      authsPerIpPerMinute: 60,
      authsPerIpv4PerMinute: 60,
      maxDevices: 10_000,
      linkTotalBytes: 8 * MiB,
      inviteTotalBytes: 16 * MiB,
    }),
    storage: Object.freeze({
      walLimitBytes: 64 * MiB,
      journalSizeLimitBytes: 16 * MiB,
      checkpointIntervalMs: 500,
    }),
  }),
});
/** Members-only: a redeemed invite admits its redeemer for 7 days unless the list or circle does first. */
export const DEFAULT_INVITE_ADMIT_SEC = 7 * 24 * 3600;

export type LogLevel = "debug" | "info" | "warn" | "error";

export interface RelayConfig {
  /** This relay's canonical URL (§5.1), e.g. `wss://relay.example.org/v3`. */
  relayUrl: string;
  host: string;
  port: number;
  /** SQLite file, or `:memory:`. */
  dbPath: string;
  /** `hello.pow`: leading zero bits required on cap-less contacts (0..24). */
  powBits: number;
  limits: RelayLimits;
  /** Shown in /.well-known/p2p-relay.json. */
  name?: string;
  operatorContact?: string;
  policy?: string;
  /**
   * How many reverse proxies you run in front of the relay. 0 ignores
   * X-Forwarded-For; n takes the client IP from the n-th entry from the right.
   */
  trustProxy: number;
  /** Separate /metrics listener (default 127.0.0.1:9464); null disables it. */
  metricsPort: number | null;
  metricsHost: string;
  /** When set, /metrics is also served on the main port to `Authorization: Bearer <token>`. */
  metricsToken?: string;
  logLevel: LogLevel;
  /** How often expired data is swept. */
  sweepIntervalSec: number;
  /**
   * Serve `/debug/stats` (event-loop lag, memory, internal map sizes) on the
   * metrics listener. Off by default; for the resilience suite and local profiling.
   */
  debugStats: boolean;
  /** The preset applied under the file and env vars, if any. */
  preset?: RelayPresetName;
  /** SQLite tuning for the store; empty keeps the store's defaults. */
  storage?: StorageTuning;
  /**
   * Members-only mode (docs/run-a-relay.md): only these userIds (and, with
   * `allowCircle`, the circle's current members) may authenticate. Unset with
   * no `allowCircle`: an open relay. RELAY_ALLOW, the `allow` list in the
   * JSON file, and the lines of `allowFile` (RELAY_ALLOW_FILE) together.
   */
  allow?: string[];
  /** A text file of userIds, one per line (`#` comments); re-read on SIGHUP. */
  allowFile?: string;
  /**
   * Members-only: userIds never admitted, whatever the list, the circle or an
   * invite says (RELAY_DENY, `deny` in the file, `!<userId>` lines of the allow
   * file). How an operator removes one provisional member early.
   */
  deny?: string[];
  /** RELAY_ALLOW_CIRCLE: also admit the current members of this circle (its chain verified by the relay). */
  allowCircle?: string;
  /**
   * Members-only: how long a userId that redeemed a member's invite code here
   * stays admitted before it is on the list or in the circle (0: invites
   * don't admit anyone).
   */
  inviteAdmitSec: number;
}

const LEVELS: readonly LogLevel[] = ["debug", "info", "warn", "error"];

/** `contactPerPairPerHour` → `LIMIT_CONTACT_PER_PAIR_PER_HOUR`. */
export function limitEnvName(key: keyof RelayLimits): string {
  return `LIMIT_${key.replace(/([A-Z])/g, "_$1").toUpperCase()}`;
}

function intIn(name: string, raw: unknown, min: number, max: number): number {
  const n = typeof raw === "string" ? Number(raw.trim()) : raw;
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < min || n > max) {
    throw new Error(`config: ${name} must be an integer in [${min}, ${max}]`);
  }
  return n;
}

/** TRUST_PROXY: a hop count; true/yes/on mean 1, false/no/off/empty mean 0. */
function proxyHops(raw: unknown): number {
  if (typeof raw === "boolean") return raw ? 1 : 0;
  if (typeof raw === "string") {
    const v = raw.trim().toLowerCase();
    if (/^(true|yes|on)$/.test(v)) return 1;
    if (v === "" || /^(false|no|off)$/.test(v)) return 0;
  }
  return intIn("TRUST_PROXY", raw, 0, 16);
}

/** DEBUG_STATS: 1/true/yes/on enable it; anything else (or unset) leaves it off. */
function flag(raw: unknown): boolean {
  if (typeof raw === "boolean") return raw;
  return typeof raw === "string" && /^(1|true|yes|on)$/i.test(raw.trim());
}

/** METRICS_PORT: a port, or off/none/false to disable the metrics listener. */
function metricsPort(raw: unknown): number | null {
  if (raw === null || (typeof raw === "string" && /^(off|none|false|)$/i.test(raw.trim()))) return null;
  return intIn("METRICS_PORT", raw, 0, 65535);
}

const ALLOW_SPLIT = /[\s,]+/;
const CIRCLE_ID_RE = /^c_[a-z2-7]{26}$/;

/**
 * The text of an allow file: one userId per line, blank lines and `#`
 * comments ignored. A line `!<userId>` denies that userId (never admitted,
 * whatever the list, the circle or an invite says).
 */
export function parseAllowFile(text: string): { allow: string[]; deny: string[] } {
  const ids = text
    .split("\n")
    .map((l) => {
      const hash = l.indexOf("#");
      return (hash >= 0 ? l.slice(0, hash) : l).trim();
    })
    .filter((l) => l !== "")
    .flatMap((l) => l.split(ALLOW_SPLIT));
  return { allow: ids.filter((x) => !x.startsWith("!")), deny: ids.filter((x) => x.startsWith("!")).map((x) => x.slice(1)) };
}

function allowList(crypto: RelayCrypto, sources: { name: string; ids: unknown }[]): string[] | undefined {
  let out: Set<string> | undefined;
  for (const { name, ids } of sources) {
    if (ids === undefined) continue;
    const list = typeof ids === "string" ? ids.split(ALLOW_SPLIT).filter((x) => x !== "") : ids;
    if (!Array.isArray(list)) throw new Error(`config: ${name} must be a list of userIds`);
    out ??= new Set();
    for (const u of list) {
      if (!crypto.isUserId(u)) throw new Error(`config: ${name}: ${String(u).slice(0, 80)} is not a full userId`);
      out.add(u);
    }
  }
  return out ? [...out] : undefined;
}

/** The JSON file uses the RelayConfig field names (limits nested under `limits`). */
type FileConfig = Partial<Omit<RelayConfig, "limits" | "storage">> & { limits?: Partial<RelayLimits>; storage?: Partial<Record<keyof StorageTuning, unknown>> };

/** StorageTuning field → env var. */
const STORAGE_ENV: Readonly<Record<keyof StorageTuning, { env: string; min: number; max: number }>> = {
  walLimitBytes: { env: "SQLITE_WAL_LIMIT_BYTES", min: 1 * MiB, max: Number.MAX_SAFE_INTEGER },
  journalSizeLimitBytes: { env: "SQLITE_JOURNAL_SIZE_LIMIT_BYTES", min: 0, max: Number.MAX_SAFE_INTEGER },
  // Capped at 10 s: a longer interval lets the WAL grow unchecked between passes on a busy relay.
  checkpointIntervalMs: { env: "SQLITE_CHECKPOINT_INTERVAL_MS", min: 10, max: 10_000 },
};

function presetName(raw: unknown): RelayPresetName | undefined {
  if (raw === undefined || raw === null) return undefined;
  const v = typeof raw === "string" ? raw.trim().toLowerCase() : raw;
  if (v === "" || v === "default" || v === "none") return undefined;
  if (typeof v === "string" && Object.hasOwn(RELAY_PRESETS, v)) return v as RelayPresetName;
  throw new Error(`config: RELAY_PRESET must be one of default, ${Object.keys(RELAY_PRESETS).join(", ")}`);
}

export interface LoadConfigOptions {
  env?: NodeJS.ProcessEnv;
  readFile?: (path: string) => string;
}

/**
 * Builds the config from defaults, the RELAY_CONFIG JSON file and env vars
 * (env wins). Throws with a readable message on any bad value.
 */
export function loadConfig(crypto: RelayCrypto, opts: LoadConfigOptions = {}): RelayConfig {
  const env = opts.env ?? process.env;
  const readFile = opts.readFile ?? ((p: string) => readFileSync(p, "utf8"));
  let file: FileConfig = {};
  if (env.RELAY_CONFIG) {
    const parsed: unknown = JSON.parse(readFile(env.RELAY_CONFIG));
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("config: RELAY_CONFIG must hold a JSON object");
    }
    file = parsed as FileConfig;
  }

  const port = intIn("PORT", env.PORT ?? file.port ?? 8080, 0, 65535);
  const rawUrl = env.RELAY_URL ?? file.relayUrl ?? `wss://localhost:${port === 0 ? 8080 : port}/v3`;
  const relayUrl = crypto.canonicalRelayUrl(rawUrl);

  const preset = presetName(env.RELAY_PRESET ?? file.preset);
  const limits: RelayLimits = { ...DEFAULT_LIMITS, ...(preset ? RELAY_PRESETS[preset].limits : {}) };
  for (const key of Object.keys(DEFAULT_LIMITS) as (keyof RelayLimits)[]) {
    const raw = env[limitEnvName(key)] ?? file.limits?.[key];
    if (raw !== undefined) limits[key] = intIn(key, raw, 0, Number.MAX_SAFE_INTEGER);
  }
  if (limits.storeHardMaxBytes < limits.storeMaxBytes) {
    throw new Error("config: storeHardMaxBytes must be at least storeMaxBytes");
  }
  if (limits.frameBytes < limits.envelopeBytes + 1024) {
    throw new Error("config: frameBytes must leave room for an envelope plus its send frame");
  }
  if (limits.frameBytes < limits.inviteBlobBytes + 1024) {
    throw new Error("config: frameBytes must leave room for an invite blob plus its put frame");
  }

  const storage: StorageTuning = { ...(preset ? RELAY_PRESETS[preset].storage : {}) };
  for (const key of Object.keys(STORAGE_ENV) as (keyof StorageTuning)[]) {
    const { env: name, min, max } = STORAGE_ENV[key];
    const raw = env[name] ?? file.storage?.[key];
    if (raw !== undefined) storage[key] = intIn(name, raw, min, max);
  }

  const logLevel = (env.LOG_LEVEL ?? file.logLevel ?? "info") as LogLevel;
  if (!LEVELS.includes(logLevel)) throw new Error(`config: LOG_LEVEL must be one of ${LEVELS.join(", ")}`);

  const cfg: RelayConfig = {
    relayUrl,
    host: env.HOST ?? file.host ?? "0.0.0.0",
    port,
    dbPath: env.DB_PATH ?? file.dbPath ?? "./relay.db",
    powBits: intIn("POW_BITS", env.POW_BITS ?? file.powBits ?? 0, 0, 24),
    limits,
    trustProxy: proxyHops(env.TRUST_PROXY ?? file.trustProxy ?? 0),
    metricsPort: metricsPort(env.METRICS_PORT ?? (file.metricsPort === undefined ? 9464 : file.metricsPort)),
    metricsHost: env.METRICS_HOST ?? file.metricsHost ?? "127.0.0.1",
    logLevel,
    sweepIntervalSec: intIn("SWEEP_INTERVAL_SEC", env.SWEEP_INTERVAL_SEC ?? file.sweepIntervalSec ?? 300, 1, 86400),
    debugStats: flag(env.DEBUG_STATS ?? file.debugStats ?? false),
    storage,
    inviteAdmitSec: intIn("RELAY_INVITE_ADMIT_SEC", env.RELAY_INVITE_ADMIT_SEC ?? file.inviteAdmitSec ?? DEFAULT_INVITE_ADMIT_SEC, 0, 90 * 86400),
  };
  if (preset) cfg.preset = preset;
  const name = env.RELAY_NAME ?? file.name;
  if (name) cfg.name = name;
  const contact = env.OPERATOR_CONTACT ?? file.operatorContact;
  if (contact) cfg.operatorContact = contact;
  const policy = env.RELAY_POLICY ?? file.policy;
  if (policy) cfg.policy = policy;
  const token = env.METRICS_TOKEN ?? file.metricsToken;
  if (token) cfg.metricsToken = token;
  const allowFile = env.RELAY_ALLOW_FILE ?? file.allowFile;
  if (allowFile) cfg.allowFile = allowFile;
  const fromFile = allowFile ? parseAllowFile(readFile(allowFile)) : undefined;
  const allow = allowList(crypto, [
    { name: "RELAY_ALLOW", ids: env.RELAY_ALLOW ?? file.allow },
    { name: allowFile ?? "RELAY_ALLOW_FILE", ids: fromFile?.allow },
  ]);
  if (allow) cfg.allow = allow;
  const deny = allowList(crypto, [
    { name: "RELAY_DENY", ids: env.RELAY_DENY ?? file.deny },
    { name: allowFile ?? "RELAY_ALLOW_FILE", ids: fromFile?.deny },
  ]);
  if (deny && deny.length > 0) cfg.deny = deny;
  const circle = env.RELAY_ALLOW_CIRCLE ?? file.allowCircle;
  if (circle) {
    if (!CIRCLE_ID_RE.test(circle)) throw new Error("config: RELAY_ALLOW_CIRCLE must be a circle id (c_…)");
    cfg.allowCircle = circle;
  }
  return cfg;
}

/** A config for tests and embedding: defaults plus overrides, no env or file. */
export function makeConfig(crypto: RelayCrypto, over: Partial<Omit<RelayConfig, "limits">> & { limits?: Partial<RelayLimits> } = {}): RelayConfig {
  const { limits, ...rest } = over;
  return {
    host: "127.0.0.1",
    port: 0,
    dbPath: ":memory:",
    powBits: 0,
    trustProxy: 0,
    metricsPort: null,
    metricsHost: "127.0.0.1",
    logLevel: "info",
    sweepIntervalSec: 300,
    debugStats: false,
    inviteAdmitSec: DEFAULT_INVITE_ADMIT_SEC,
    ...rest,
    relayUrl: crypto.canonicalRelayUrl(rest.relayUrl ?? "wss://relay.test/v3"),
    limits: { ...DEFAULT_LIMITS, ...limits },
  };
}
