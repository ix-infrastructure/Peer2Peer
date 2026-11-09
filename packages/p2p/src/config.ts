// Copyright 2026 Ix Infrastructure Inc.
//
// Where the CLI keeps its state, which relays a new identity uses, and how a
// canonical relay URL is actually reached.
//
//  - Home: `P2P_HOME`, else `~/.p2p`. The v3 trust store lives in
//    `<home>/v3` (FileTrustStoreV3), the CLI's own documents in `<home>/cli`,
//    both 0700 with 0600 files written atomically under a cross-process lock.
//  - Default relays: none are hardcoded. `P2P_DEFAULT_RELAYS` (comma or
//    space separated) wins over `defaultRelays` in `<home>/config.json`,
//    which wins over `defaultRelays` in a `defaults.json` shipped next to the
//    CLI (the bundled single-file build; `P2P_DEFAULTS_FILE` names another).
//  - Transport overrides: a canonical relay URL (always `wss://…`, §5.1) is
//    dialled at itself, and its document API at `https://<host>/<path>`.
//    `P2P_RELAY_TRANSPORT` (JSON) or `transport` in config.json can map a
//    canonical URL to another dial URL, e.g. a local relay without TLS:
//    `{"wss://relay.test/v3": "ws://127.0.0.1:8080/v3"}`. It is a hosts file
//    for relays: the hello check still compares against the canonical URL.

import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalRelayUrl, MAX_RELAYS, relayHttpsBase } from "@peer2peer/core/v3";
import { CliError } from "./errors.js";

export type Env = Record<string, string | undefined>;

export interface FileConfig {
  defaultRelays?: string[];
  /** Enabled extension namespaces (`p2p extensions enable ix`); see extensions.ts. */
  extensions?: string[];
  transport?: Record<string, string>;
  /** Send `caps` in statuses (§4.3 "Status caps"); on by default since P1, `false` opts out. P2P_STATUS_CAPS wins. */
  statusCaps?: boolean;
  /** Send delivery receipts (§4.3 "Delivery receipts"); on by default, `false` turns them off. P2P_RECEIPTS wins. */
  receipts?: boolean;
  /** Who this user trusts to drive a session that approves its own tool calls (trust.ts): full userIds and circle ids. */
  trust?: { users?: string[]; circles?: string[] };
  /** Publish this device's caps and version in the identity document (`dinfo`); off until step 2 (docs/compatibility.md). P2P_DEVICE_INFO wins. */
  deviceInfo?: boolean;
  /** The local Ix backend (projects.ts localGraphEndpoint): honoured only as a loopback URL. Default http://localhost:8090. */
  ixEndpoint?: string;
  /**
   * Trust a root-owned listener on the local Ix endpoint's port (ext-ix listener.ts): Docker's port
   * proxy on Linux runs as root whoever started the container, so on a machine whose Docker others
   * use too it may be a teammate's backend. Off by default; only this file turns it on (hand-edited:
   * no command writes it, and no environment variable overrides it).
   */
  ixTrustRootListener?: boolean;
  /** Message history (history.ts): on by default, kept `retentionDays` (30) and at most `maxBytes` (8 MiB). P2P_HISTORY=0 turns recording off. */
  history?: { enabled?: boolean; retentionDays?: number; maxBytes?: number };
  /** Graph memory (graph-memory.ts): this device's sessions' context into the local Ix graph; on by default with the Ix extension, `false` turns it off. P2P_IX_MEMORY=0 turns it off too. */
  ixMemory?: boolean;
  /**
   * Messages from your own agent sessions skip the hold in a session that approves its own tool calls
   * (`p2p own-agents deliver`, person only). Off by default: they are held like a peer's. No variable
   * overrides it, so nothing an agent sets in its environment turns it on.
   */
  ownAgentsDeliver?: boolean;
  /**
   * Narrower (`p2p own-agents deliver --devices <did…|all-other>`, person only): messages from your own
   * sessions on these other devices skip the hold, while this device's agent sessions stay held. Another
   * device can't say whether you typed a message (that needs the wire field of RFC #48), so this trusts
   * every session there.
   */
  ownDevicesDeliver?: string[] | "all-other";
}

/**
 * Whether `p2p watch` writes this device's sessions' context into the local Ix graph (graph-memory.ts):
 * on by default (it needs the Ix extension and an Ix with the OSS `ix note`). `"ixMemory": false` in
 * config.json turns it off, and so does P2P_IX_MEMORY=0 (or `false`). The environment can only turn it
 * off: it never overrides the person's `false`.
 */
export function graphMemoryEnabled(env: Env, home: string): boolean {
  const v = env.P2P_IX_MEMORY?.trim().toLowerCase();
  if (v === "0" || v === "false") return false;
  try {
    return readFileConfig(home).ixMemory !== false;
  } catch {
    return true;
  }
}

/** Whether your own agent sessions' messages skip the hold (FileConfig.ownAgentsDeliver). */
export function ownAgentsDeliver(home: string): boolean {
  try {
    return readFileConfig(home).ownAgentsDeliver === true;
  } catch {
    return false;
  }
}

/** The other devices whose sessions skip the hold (FileConfig.ownDevicesDeliver): none, a list, or every other one. */
export function ownDevicesDeliver(home: string): string[] | "all-other" {
  try {
    const v = readFileConfig(home).ownDevicesDeliver;
    if (v === "all-other") return v;
    return Array.isArray(v) ? v.filter((d): d is string => typeof d === "string") : [];
  } catch {
    return [];
  }
}

/**
 * Whether a message from one of your own agent sessions on device `did` skips the hold now (read at
 * delivery time, never stamped on an event): `own-agents deliver`, or `--devices` naming that device
 * (another device than this one).
 */
export function ownAgentsDeliverFrom(home: string, did: string, thisDevice: string): boolean {
  if (ownAgentsDeliver(home)) return true;
  if (did === thisDevice) return false;
  const devices = ownDevicesDeliver(home);
  return devices === "all-other" || devices.includes(did);
}

/**
 * Whether this device puts its caps and client version in the identity document (`dinfo`).
 * Off by default in this release: pre-release clients from before protocol 3.1 refuse
 * an identity document with a field they don't know, so the user would become unreachable to them.
 * Step 2 (once the two previous releases are 3.1) turns it on. `P2P_DEVICE_INFO` (`1`/`true`,
 * `0`/`false`) wins over `"deviceInfo": true` in config.json. Even on, it is published only to
 * relays that list `identity.lenient` (relay-info.ts).
 */
export function deviceInfoEnabled(env: Env, home: string): boolean {
  const v = env.P2P_DEVICE_INFO?.trim().toLowerCase();
  if (v === "1" || v === "true") return true;
  if (v === "0" || v === "false") return false;
  try {
    return readFileConfig(home).deviceInfo === true;
  } catch {
    return false;
  }
}

/**
 * Whether this user sends delivery receipts, and advertises `receipts.v1` (§4.3): on by default.
 * `P2P_RECEIPTS` (`1`/`true` on, `0`/`false` off) wins over `"receipts": false` in config.json.
 * Off, no receipt goes out and no status advertises the cap, so senders see what an older client
 * looks like ("no receipt yet"): turning them off is not itself revealed.
 */
export function receiptsEnabled(env: Env, home: string): boolean {
  const v = env.P2P_RECEIPTS?.trim().toLowerCase();
  if (v === "1" || v === "true") return true;
  if (v === "0" || v === "false") return false;
  try {
    return readFileConfig(home).receipts !== false;
  } catch {
    return true;
  }
}

/**
 * Whether statuses carry `caps` (two-step rollout, §4.3, step 2): on by
 * default. `P2P_STATUS_CAPS` (`1`/`true` on, `0`/`false` off) wins over
 * `"statusCaps": false` in config.json, the opt-out for a user whose peers
 * still run a client older than the amendment (it rejects a status carrying
 * `caps`). A broken config.json counts as the default (the command reports
 * it elsewhere).
 */
export function statusCapsEnabled(env: Env, home: string): boolean {
  const v = env.P2P_STATUS_CAPS?.trim().toLowerCase();
  if (v === "1" || v === "true") return true;
  if (v === "0" || v === "false") return false;
  try {
    return readFileConfig(home).statusCaps !== false;
  } catch {
    return true;
  }
}

export function resolveHome(env: Env): string {
  const h = env.P2P_HOME?.trim();
  return h ? h : join(homedir(), ".p2p");
}

export function readFileConfig(home: string): FileConfig {
  let raw: string;
  try {
    raw = readFileSync(join(home, "config.json"), "utf8");
  } catch {
    return {};
  }
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    throw new CliError("config", `${join(home, "config.json")} is not valid JSON`);
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new CliError("config", "config.json must hold a JSON object");
  return v as FileConfig;
}

/** `p2p receipts on|off`: sets `receipts` in <home>/config.json (atomically, 0600). */
export function setReceiptsEnabled(home: string, on: boolean): void {
  setFileConfigField(home, "receipts", on);
}

/**
 * Read-modify-write of one top-level field of <home>/config.json under the state lock, so two
 * commands changing it at once (`p2p receipts`, `p2p trust`) never lose an update (pre-release review N3).
 * `fn` gets the field as stored and returns its next value and a result.
 */
export async function updateFileConfigField<R>(
  app: { home: string; state: { withLock<T>(fn: () => Promise<T>): Promise<T> } },
  key: string,
  fn: (cur: unknown) => { next: unknown; result: R },
): Promise<R> {
  return app.state.withLock(async () => {
    const r = fn((readFileConfig(app.home) as Record<string, unknown>)[key]);
    setFileConfigField(app.home, key, r.next);
    return r.result;
  });
}

/** Sets one top-level field of <home>/config.json, keeping the rest (atomically, 0600). Callers hold the state lock. */
export function setFileConfigField(home: string, key: string, value: unknown): void {
  const p = join(home, "config.json");
  const cfg = readFileConfig(home) as Record<string, unknown>;
  mkdirSync(home, { recursive: true, mode: 0o700 });
  const tmp = `${p}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify({ ...cfg, [key]: value }, null, 2) + "\n", { mode: 0o600 });
  renameSync(tmp, p);
}

/** Canonicalises, de-duplicates and bounds a relay list (1–5, §5.8). */
export function normalizeRelays(list: readonly string[]): string[] {
  const out: string[] = [];
  for (const r of list) {
    let c: string;
    try {
      c = canonicalRelayUrl(r.trim());
    } catch (e) {
      throw new CliError("bad_relay", `${r} is not a relay URL: ${(e as Error).message}`);
    }
    if (!out.includes(c)) out.push(c);
  }
  if (out.length > MAX_RELAYS) throw new CliError("bad_relay", `at most ${MAX_RELAYS} relays (got ${out.length})`);
  return out;
}

/** `defaultRelays` from the `defaults.json` beside the CLI (or `P2P_DEFAULTS_FILE`); [] when there is none. */
export function shippedDefaultRelays(env: Env): string[] {
  let path: string;
  try {
    path = env.P2P_DEFAULTS_FILE?.trim() || fileURLToPath(new URL("./defaults.json", import.meta.url));
  } catch {
    return [];
  }
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return [];
  }
  try {
    const v = JSON.parse(raw) as { defaultRelays?: unknown };
    if (v.defaultRelays === undefined) return [];
    if (!Array.isArray(v.defaultRelays) || v.defaultRelays.some((x) => typeof x !== "string")) throw new Error("defaultRelays must be a list of relay URLs");
    return v.defaultRelays as string[];
  } catch (e) {
    throw new CliError("config", `${path}: ${(e as Error).message}`);
  }
}

/** The relays a new identity uses when `--relay` is not given. */
export function defaultRelays(env: Env, file: FileConfig): string[] {
  const fromEnv = env.P2P_DEFAULT_RELAYS?.split(/[\s,]+/).filter((s) => s !== "");
  const list = fromEnv && fromEnv.length > 0 ? fromEnv : file.defaultRelays && file.defaultRelays.length > 0 ? file.defaultRelays : shippedDefaultRelays(env);
  return normalizeRelays(list);
}

export interface Transport {
  /** What the WebSocket dials. */
  ws: string;
  /** The document API base (§5.6): `<http>/identity/<userId>`. */
  http: string;
}

export type TransportResolver = (canonical: string) => Transport;

function httpFor(ws: string): string {
  return ws.replace(/^wss:/, "https:").replace(/^ws:/, "http:");
}

export function transportResolver(env: Env, file: FileConfig): TransportResolver {
  let map: Record<string, string> = { ...(file.transport ?? {}) };
  if (env.P2P_RELAY_TRANSPORT) {
    try {
      const v = JSON.parse(env.P2P_RELAY_TRANSPORT) as unknown;
      if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error("not an object");
      map = { ...map, ...(v as Record<string, string>) };
    } catch (e) {
      throw new CliError("config", `P2P_RELAY_TRANSPORT must be a JSON object: ${(e as Error).message}`);
    }
  }
  const canon: Record<string, string> = {};
  for (const [k, v] of Object.entries(map)) {
    if (typeof v !== "string" || !/^wss?:\/\//.test(v)) throw new CliError("config", `transport for ${k} must be a ws:// or wss:// URL`);
    canon[canonicalRelayUrl(k)] = v.replace(/\/+$/, "");
  }
  return (relay) => {
    const c = canonicalRelayUrl(relay);
    const over = canon[c];
    if (over) return { ws: over, http: httpFor(over) };
    return { ws: c, http: relayHttpsBase(c) };
  };
}

/** Tunables, mostly so tests run fast. */
export interface Tunables {
  /** How long a short command listens for queued envelopes after connecting. */
  drainQuietMs: number;
  drainMaxMs: number;
  /** Re-fetch a contact's identity document when the copy is older than this. */
  docRefreshSec: number;
  /** Link mailbox polling. */
  linkPollMs: number;
  /** Per-relay connect timeout: each of dial, hello and auth (and an HTTP document fetch). */
  connectTimeoutMs: number;
  /** Per relay request (send, identity, invite-*, …). */
  requestTimeoutMs: number;
  /** A whole short command (not `watch`; `--wait` adds to it; 0 = none). */
  commandTimeoutSec: number;
  /** How long a failed identity lookup is remembered before trying again. */
  discoverRetrySec: number;
  /** A relay refusing this device triggers at most one own-document refresh per this long. */
  refusedRefreshSec: number;
  /** A relay that refused a publish outright is retried automatically at most this often. */
  refusedPublishRetrySec: number;
  /** Bytes of circle history this client sends, per rolling hour, in answer to non-members' `want`s. */
  strangerAnswerBytesPerHour: number;
  /** Bytes of circle history sent per rolling hour to non-members whose want names no version they were offered. */
  unlinkedAnswerBytesPerHour: number;
  /** How long each device after the first in answering order waits before answering a want nobody answered. */
  wantFallbackSec: number;
  /** Bytes of one circle's history sent per rolling hour to all its members together. */
  memberAnswerBytesPerCirclePerHour: number;
  /** Bytes of circle history this client sends one asker (member or not) per rolling hour. */
  answerBytesPerAskerPerHour: number;
  /** Tests only: a smaller cap on a code's sealed bundle than the relay's (never a larger one). */
  inviteBlobMax?: number;
}

export function tunables(env: Env): Tunables {
  const n = (k: string, d: number) => {
    const v = env[k];
    if (v === undefined || v.trim() === "") return d;
    const x = Number(v);
    return Number.isFinite(x) && x >= 0 ? x : d;
  };
  return {
    drainQuietMs: n("P2P_DRAIN_QUIET_MS", 400),
    drainMaxMs: n("P2P_DRAIN_MAX_MS", 5000),
    docRefreshSec: n("P2P_DOC_REFRESH_SEC", 60),
    linkPollMs: n("P2P_LINK_POLL_MS", 2000),
    connectTimeoutMs: n("P2P_CONNECT_TIMEOUT_MS", 10_000),
    requestTimeoutMs: n("P2P_REQUEST_TIMEOUT_MS", 15_000),
    commandTimeoutSec: n("P2P_COMMAND_TIMEOUT_SEC", 60),
    discoverRetrySec: n("P2P_DISCOVER_RETRY_SEC", 60),
    refusedRefreshSec: n("P2P_REFUSED_REFRESH_SEC", 60),
    refusedPublishRetrySec: n("P2P_REFUSED_PUBLISH_RETRY_SEC", 3600),
    strangerAnswerBytesPerHour: n("P2P_STRANGER_ANSWER_BYTES_PER_HOUR", 8 * 1024 * 1024),
    unlinkedAnswerBytesPerHour: n("P2P_UNLINKED_ANSWER_BYTES_PER_HOUR", 1024 * 1024),
    wantFallbackSec: n("P2P_WANT_FALLBACK_SEC", 120),
    memberAnswerBytesPerCirclePerHour: n("P2P_MEMBER_ANSWER_BYTES_PER_CIRCLE_PER_HOUR", 16 * 1024 * 1024),
    answerBytesPerAskerPerHour: n("P2P_ANSWER_BYTES_PER_ASKER_PER_HOUR", 4 * 1024 * 1024),
    // Tests only (the "bundle too big" case): it can only lower the cap (codes.ts takes the smaller of the two).
    ...(env.P2P_INVITE_BLOB_MAX ? { inviteBlobMax: n("P2P_INVITE_BLOB_MAX", 32 * 1024) } : {}),
  };
}
