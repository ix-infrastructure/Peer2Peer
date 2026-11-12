// Copyright 2026 Ix Infrastructure Inc.
//
// `p2p doctor [<user>]`: why sessions are or aren't visible, in plain words.
//
// Without a user it checks this device: the identity and its document's
// freshness, each relay (reachable, latency, this device's mailbox and auth,
// our document published there, the clock vs the relay), the default circle
// and our standing in it, which sessions are shared and with whom, when a
// status last went out, and the CLI version vs the mod's bundled one.
//
// With a user (an address, a petname, a name or a userId) it explains
// whether we can see them: friendship or shared circles, their identity
// document, their relays and whether we share a reachable one, the caps each
// side holds (as far as this side can tell), when anything last arrived from
// them, blocks, suspensions and held items, and whether the sessions they
// shared include us.
//
// Each check is ✓ (fine), ✗ (a problem, with a one-line fix) or ? (unknown or a warning,
// with what would tell). Read-only: the relay probes authenticate but never
// ack what is queued, publish nothing and send nothing. Every network step is
// bounded (P2P_DOCTOR_TIMEOUT_MS, default 5 s, never more than the connect
// timeout), and so is every local step, so the command can't hang. Nothing
// secret is ever in the output: no keys, caps, invite or link codes, envelopes.

import { readdirSync, statSync } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  capAllowsKind,
  daysPastExp,
  decodeTyped,
  DEFAULT_SKEW_SEC,
  displayAddress,
  identityFreshness,
  isLive,
  isUserId,
  liveFriendshipsV3,
  nowSec,
  peekIdentityDoc,
  sanitizePeerText,
  TYP3,
  unfriendApplies,
  refreshIdentity as coreRefreshIdentity,
  type ChainFetcher,
  type IdentityView,
  type TipsFetcher,
} from "@peer2peer/core/v3";
import { App, capPeek, joinCapOf, orderRelays, REPUBLISH_DOC_WITHIN_SEC } from "./app.js";
import { CAP_PROJECTS, CLI_CAPS, KNOWN_FEATURES, peerDevices, unavailableBetween, type PeerDevice } from "./features.js";
import { circleMembers, listCircles, type CircleSummary } from "./circle-ops.js";
import { defaultRelays } from "./config.js";
import { CliError } from "./errors.js";
import { readCapped, RelayConnection } from "./relay-client.js";
import { rosterAudience, sessionRef } from "./sessions.js";
import type { PeerStatusRec } from "./state.js";
import { enabledNamespaces } from "./extensions.js";
import { extIxInstalled, ixBinary, ixDeclined, IX_INSTALL_URL, ixInstallLine, ixMemorySupport, ixVersion, runIx } from "./ix-local.js";
import { personHere } from "./projects.js";
import { graphMemoryReport } from "./graph-memory.js";
import { graphMemoryEnabled } from "./config.js";
import { describeGraphTarget, listProjects, localGraphEndpoint, projectOf, projectsDoc, projectGraphTarget, sessionWorkdir } from "./projects.js";

export type CheckStatus = "ok" | "fail" | "unknown";

export interface Check {
  id: string;
  status: CheckStatus;
  title: string;
  detail: string;
  /** One line: what to do (✗), or what would tell (?). */
  fix?: string;
}

export interface DoctorResult {
  scope: "device" | "user";
  version: string;
  user?: { input: string; userId?: string; address?: string };
  checks: Check[];
  summary: { ok: number; fail: number; unknown: number };
  /** About a user: each of their devices with its client version and caps (docs/compatibility.md). */
  devices?: PeerDevice[];
  /** About a user: the known features one of you has and the other lacks. */
  unavailable?: { theyLack: string[]; weLack: string[] };
}

export interface DoctorOptions {
  /** The CLI's own version (cli.ts VERSION). */
  version: string;
  user?: string;
  /** Overrides P2P_DOCTOR_TIMEOUT_MS (tests). */
  timeoutMs?: number;
  /** The mod's folder, when known (P2P_MOD_ROOT; else the folder around a bundled p2p.mjs). */
  modRoot?: string;
}

/**
 * Clock skew. Signed objects (device certificates, documents, caps, invites, statements) are
 * refused when their `iat` is more than DEFAULT_SKEW_SEC (300 s) ahead of the verifier's clock,
 * in core and at relays (relay auth too). Envelope `ts` alone tolerates 10 minutes
 * (REPLAY_FUTURE_SKEW_MS), so 300 s is the real limit. Under SKEW_OK_SEC is fine (the Date
 * header has 1 s resolution, plus half a round trip); up to the limit still works, so it is a
 * warning; only past it does anything break.
 */
export const SKEW_OK_SEC = 30;
export const SKEW_FAIL_SEC = DEFAULT_SKEW_SEC;
const DAY = 86_400;

const MARK: Record<CheckStatus, string> = { ok: "✓", fail: "✗", unknown: "?" };

/** A promise bounded by `ms`: `undefined` with `timedOut` when it doesn't settle in time. */
async function bounded<T>(p: Promise<T>, ms: number): Promise<{ value?: T; error?: unknown; timedOut?: boolean }> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      p.then(
        (value) => ({ value }),
        (error: unknown) => ({ error }),
      ),
      new Promise<{ timedOut: true }>((r) => {
        timer = setTimeout(() => r({ timedOut: true }), ms);
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

const ago = (ms: number): string => {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 90) return `${s}s ago`;
  if (s < 90 * 60) return `${Math.round(s / 60)}m ago`;
  if (s < 36 * 3600) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / DAY)} days ago`;
};

const days = (sec: number): string => {
  const d = Math.floor(Math.abs(sec) / DAY);
  if (d >= 1) return `${d} day${d === 1 ? "" : "s"}`;
  const h = Math.max(1, Math.round(Math.abs(sec) / 3600));
  return `${h} hour${h === 1 ? "" : "s"}`;
};

const errText = (e: unknown): string => sanitizePeerText((e as Error)?.message ?? String(e), 200);

/** A peer-written string, inert and short. */
const peer = (s: unknown, max = 64): string => sanitizePeerText(s, max).replace(/["`]/g, "'") || "?";

/** A relay URL a peer chose (their document, a cap they gave us): quoted peer data, at most 200 characters. */
const peerUrl = (s: unknown): string => `"${peer(s, 200)}"`;

/** A session id from a peer, safe as part of a check id: [A-Za-z0-9._-], at most 128. */
const safeSid = (s: unknown): string => String(s).replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 128) || "_";

/** At most this many of a peer's relays are ever probed (§5.8: a document lists 1-5). */
const MAX_PEER_RELAYS = 5;

// ---------------------------------------------------------------------------
// Probes

export interface HttpProbe {
  ok: boolean;
  status?: number;
  ms: number;
  /** The server's clock (ms) from its Date header, and our midpoint of the request. */
  serverMs?: number;
  localMs?: number;
  body?: Record<string, unknown>;
  error?: string;
  code?: "unreachable" | "timeout" | "network";
}

/** One bounded GET (the relay's document API), with its latency and the server's Date header. */
export async function httpProbe(url: string, timeoutMs: number, opts: { maxBody?: number; noRedirect?: boolean } = {}): Promise<HttpProbe> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  t.unref?.();
  const t0 = Date.now();
  try {
    const res = await fetch(url, { signal: ctl.signal, headers: { accept: "application/json" }, ...(opts.noRedirect ? { redirect: "error" as const } : {}) });
    const t1 = Date.now();
    const date = res.headers.get("date");
    const serverMs = date ? Date.parse(date) : NaN;
    // A body only when asked for (our own document), capped; a peer's relay's answer is never kept.
    let body: Record<string, unknown> | undefined;
    if (opts.maxBody) {
      try {
        const text = await readCapped(res, opts.maxBody);
        body = text ? (JSON.parse(text) as Record<string, unknown>) : undefined;
      } catch {
        body = undefined;
      }
    } else await res.body?.cancel().catch(() => {});
    return {
      ok: true,
      status: res.status,
      ms: t1 - t0,
      ...(Number.isFinite(serverMs) ? { serverMs: serverMs + 500, localMs: Math.round((t0 + t1) / 2) } : {}),
      ...(body && typeof body === "object" ? { body } : {}),
    };
  } catch (e) {
    const ms = Date.now() - t0;
    if (ctl.signal.aborted) return { ok: false, ms, code: "timeout", error: `no answer after ${Math.round(timeoutMs / 1000)}s` };
    const code = (e as { cause?: { code?: string } }).cause?.code ?? "";
    if (["ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN", "EHOSTUNREACH", "ENETUNREACH", "ETIMEDOUT"].includes(code)) {
      return { ok: false, ms, code: "unreachable", error: code === "ECONNREFUSED" ? "connection refused" : code === "ENOTFOUND" || code === "EAI_AGAIN" ? "can't resolve the host" : "no route to it" };
    }
    return { ok: false, ms, code: "network", error: errText(e) };
  } finally {
    clearTimeout(t);
  }
}

export interface WsProbe {
  /** Dial + hello (+ auth) took this long. */
  connectMs?: number;
  /** An authenticated round trip. */
  rttMs?: number;
  authed: boolean;
  restricted: boolean;
  /** Envelopes the relay pushed while we were connected (queued for this device; not acked). */
  queued: number;
  error?: string;
  code?: string;
}

/** Dials one relay as this device (or anonymously), checks hello and auth, and makes one authenticated round trip. */
export async function wsProbe(app: App, relay: string, timeoutMs: number, auth: boolean): Promise<WsProbe> {
  let queued = 0;
  const conn = new RelayConnection(relay, app.transport(relay), {
    ...(auth ? { auth: { cert: app.keys!.cert, signingSecretKey: app.device!.signingSecretKey } } : {}),
    // Accepted, so a relay that doesn't list this device yet is reported as such.
    allowRestricted: true,
    timeoutMs,
    requestTimeoutMs: timeoutMs,
    rememberUnreachable: false,
    // Counted, never acked: they stay queued for the next real command.
    onEnv: () => {
      queued++;
    },
  });
  const t0 = Date.now();
  try {
    // The whole open (dial, hello, auth) within the doctor's bound, not one bound per stage.
    const opened = await bounded(conn.open(), timeoutMs);
    if (opened.timedOut) return { authed: false, restricted: false, queued, code: "timeout", error: `no answer after ${Math.round(timeoutMs / 1000)}s` };
    if (opened.error !== undefined) {
      const e = opened.error as CliError;
      return { authed: false, restricted: false, queued, code: e.code ?? "network", error: errText(e) };
    }
    const connectMs = Date.now() - t0;
    if (!auth) return { connectMs, authed: false, restricted: false, queued };
    let rttMs: number | undefined;
    if (!conn.restricted) {
      const t1 = Date.now();
      const r = await bounded(conn.request({ t: "invite-list" }, timeoutMs), timeoutMs + 500);
      if (r.value) rttMs = Date.now() - t1;
    }
    return { connectMs, ...(rttMs !== undefined ? { rttMs } : {}), authed: conn.authed, restricted: conn.restricted, queued };
  } finally {
    conn.close();
  }
}

// ---------------------------------------------------------------------------
// Local state

/** The newest status this device posted (the mod's status publisher, or `p2p status`). */
function ownStatuses(app: App, peers: Record<string, PeerStatusRec>): PeerStatusRec[] {
  return Object.values(peers)
    .filter((p) => p.own === app.userId && p.did === app.did)
    .sort((a, b) => b.ts - a.ts);
}

/** The newest `p2p watch` cursor write: when a watcher last handed an event on (or started). */
function watchCursor(home: string): { sid: string; at: number } | undefined {
  let best: { sid: string; at: number } | undefined;
  try {
    for (const name of readdirSync(join(home, "cursors"))) {
      if (!name.endsWith(".cursor")) continue;
      const at = statSync(join(home, "cursors", name)).mtimeMs;
      if (!best || at > best.at) best = { sid: name.slice(0, -".cursor".length), at };
    }
  } catch {
    return undefined;
  }
  return best;
}

/** The mod's folder: P2P_MOD_ROOT, or the plugin around a bundled `bin/p2p.mjs`. */
function findModRoot(app: App, given?: string): string | undefined {
  const fromEnv = given ?? app.env.P2P_MOD_ROOT?.trim();
  if (fromEnv) return fromEnv;
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const root = dirname(here);
    statSync(join(root, ".claude-plugin", "plugin.json"));
    return root;
  } catch {
    return undefined;
  }
}

/** The plugin's version and the version of the `p2p` it bundles (read from the file, not run). */
/** Files bigger than this aren't read (the bundled CLI is ~1.2 MB). */
const MAX_MOD_FILE_BYTES = 16 * 1024 * 1024;

async function readSmall(path: string): Promise<string> {
  if ((await stat(path)).size > MAX_MOD_FILE_BYTES) throw new Error("too large");
  return readFile(path, "utf8");
}

export async function modVersions(root: string): Promise<{ plugin?: string; bundled?: string }> {
  const out: { plugin?: string; bundled?: string } = {};
  try {
    const v = (JSON.parse(await readSmall(join(root, ".claude-plugin", "plugin.json"))) as { version?: unknown }).version;
    if (typeof v === "string") out.plugin = peer(v, 32);
  } catch {
    // no plugin.json
  }
  try {
    const m = /^var VERSION = "([^"]{1,32})";$/m.exec(await readSmall(join(root, "bin", "p2p.mjs")));
    if (m) out.bundled = peer(m[1], 32);
  } catch {
    // no bundled CLI
  }
  return out;
}

// ---------------------------------------------------------------------------
// The checks

class Checks {
  readonly list: Check[] = [];
  add(id: string, status: CheckStatus, title: string, detail: string, fix?: string): Check {
    const c: Check = { id, status, title, detail, ...(fix && status !== "ok" ? { fix } : {}) };
    this.list.push(c);
    return c;
  }
}

interface RelayReport {
  relay: string;
  ws: WsProbe;
  http: HttpProbe;
  reachable: boolean;
}

/** Probes each relay over WebSocket (as this device) and the document API, in parallel. */
async function probeRelays(app: App, relays: readonly string[], timeoutMs: number, auth: boolean, docUser?: string): Promise<RelayReport[]> {
  return Promise.all(
    relays.map(async (relay) => {
      const http = docUser ? `${app.transport(relay).http}/identity/${encodeURIComponent(docUser)}` : `${new URL(app.transport(relay).http).origin}/healthz`;
      const [ws, hp] = await Promise.all([
        wsProbe(app, relay, timeoutMs, auth).catch((e: unknown) => ({ authed: false, restricted: false, queued: 0, code: "network", error: errText(e) }) as WsProbe),
        // Our own head document (≤ 16 KiB per protocol §2.5; room to spare).
        httpProbe(http, timeoutMs, docUser ? { maxBody: 64 * 1024 } : {}),
      ]);
      return { relay, ws, http: hp, reachable: ws.connectMs !== undefined || hp.ok };
    }),
  );
}

function relayChecks(c: Checks, app: App, reports: readonly RelayReport[], head: { hash: string; ver: number } | undefined): void {
  for (const r of reports) {
    const id = `relay:${r.relay}`;
    if (r.ws.connectMs === undefined) {
      const why = r.ws.error ?? r.http.error ?? "no answer";
      const refused = r.ws.code === "auth_failed";
      c.add(
        id,
        "fail",
        `relay ${r.relay}`,
        refused ? `reachable, but it refused this device (${why})` : r.ws.code === "relay_mismatch" ? "it introduced itself as another relay" : `unreachable: ${why}`,
        refused
          ? "this device may have been revoked: run `p2p whoami` on another of your devices, or re-link this one (`p2p link start` there, `p2p link join <code>` here)"
          : r.ws.code === "relay_mismatch"
            ? "check the URL and any transport override (P2P_RELAY_TRANSPORT, config.json `transport`)"
            : "check your network, VPN or firewall (WebSocket over port 443); if it stays down, add another relay: `p2p relays add <wss://…>` (or `/peers relays add <wss://…>`)",
      );
    } else if (app.keys && r.ws.restricted) {
      c.add(id, "fail", `relay ${r.relay}`, `reachable (${r.ws.connectMs} ms), but it doesn't list this device yet, so its mailbox is closed to it`, "publish your current document there: `p2p identity republish`");
    } else if (app.keys && !r.ws.authed) {
      c.add(id, "fail", `relay ${r.relay}`, `reachable (${r.ws.connectMs} ms), but this device couldn't sign in`, "run `p2p identity republish`, then `p2p doctor` again");
    } else {
      const lat = `${r.ws.connectMs} ms to connect${r.ws.rttMs !== undefined ? `, ${r.ws.rttMs} ms round trip` : ""}`;
      const queued = r.ws.queued > 0 ? `; ${r.ws.queued} envelope${r.ws.queued === 1 ? "" : "s"} queued for this device` : "";
      c.add(id, "ok", `relay ${r.relay}`, app.keys ? `reachable (${lat}); this device's mailbox works${queued}` : `reachable (${lat})`);
    }
    if (!app.keys) continue;
    // Our document there.
    const did = `published:${r.relay}`;
    if (!r.http.ok) c.add(did, "unknown", `identity document on ${r.relay}`, `couldn't ask (${r.http.error ?? "no answer"})`, "run `p2p doctor` again once the relay answers");
    else if (r.http.status === 404) c.add(did, "fail", `identity document on ${r.relay}`, "not published there: nobody can find your devices or relays through it", "run `p2p identity republish`");
    else if (r.http.status !== 200 || typeof r.http.body?.doc !== "string") c.add(did, "unknown", `identity document on ${r.relay}`, `unexpected answer (HTTP ${r.http.status})`, "run `p2p doctor` again later");
    else {
      let theirs: { hash: string; ver: number } | undefined;
      try {
        const p = peekIdentityDoc(r.http.body.doc);
        theirs = { hash: p.hash, ver: p.ver };
      } catch {
        theirs = undefined;
      }
      if (!theirs) c.add(did, "unknown", `identity document on ${r.relay}`, "the relay's copy doesn't parse", "run `p2p identity republish`");
      else if (!head) c.add(did, "unknown", `identity document on ${r.relay}`, `version ${theirs.ver} is there; this device holds none to compare`, "run `p2p whoami`");
      else if (theirs.hash === head.hash) c.add(did, "ok", `identity document on ${r.relay}`, `published (version ${theirs.ver}, the current one)`);
      else if (theirs.ver < head.ver) c.add(did, "fail", `identity document on ${r.relay}`, `the relay has version ${theirs.ver}; yours is ${head.ver}`, "run `p2p identity republish`");
      else c.add(did, "unknown", `identity document on ${r.relay}`, `the relay has version ${theirs.ver}; this device holds ${head.ver} (another device published since?)`, "run `p2p whoami` to refresh, then `p2p doctor` again");
    }
  }
}

function clockCheck(c: Checks, reports: readonly RelayReport[]): void {
  const skews = reports
    .filter((r) => r.http.serverMs !== undefined && r.http.localMs !== undefined)
    .map((r) => ({ relay: r.relay, sec: Math.round(((r.http.localMs as number) - (r.http.serverMs as number)) / 1000) }));
  const k = clockVerdict(skews);
  c.add("clock", k.status, k.title, k.detail, k.fix);
}

const CLOCK_FIX = "turn on automatic time in your system settings (Windows: Settings > Time & language > Sync now)";

/**
 * The clock check from each relay's skew (seconds, + when this device is ahead): ✓ under
 * SKEW_OK_SEC, ? (a warning) up to the protocol's limit (SKEW_FAIL_SEC, 300 s), ✗ only past it.
 */
export function clockVerdict(skews: readonly { relay: string; sec: number }[]): Check {
  if (skews.length === 0) return { id: "clock", status: "unknown", title: "clock", detail: "no relay answered with its time", fix: "check your system clock is set automatically" };
  const worst = skews.reduce((a, b) => (Math.abs(b.sec) > Math.abs(a.sec) ? b : a));
  const abs = Math.abs(worst.sec);
  const dir = worst.sec > 0 ? "ahead of" : "behind";
  const limit = `the protocol's ${SKEW_FAIL_SEC}s (5-minute) limit`;
  if (abs < SKEW_OK_SEC) {
    return { id: "clock", status: "ok", title: "clock", detail: `within ${Math.max(1, abs)}s of ${skews.length === 1 ? worst.relay : `your relays (worst: ${worst.relay})`}` };
  }
  if (abs <= SKEW_FAIL_SEC) {
    return {
      id: "clock",
      status: "unknown",
      title: "clock",
      detail: `${abs}s ${dir} ${worst.relay}: still within ${limit}, but ${SKEW_FAIL_SEC - abs}s more drift and relays and peers will reject what this device signs (sooner with a peer whose clock is off the other way: the two add up)`,
      fix: CLOCK_FIX,
    };
  }
  return {
    id: "clock",
    status: "fail",
    title: "clock",
    detail: `${abs}s ${dir} ${worst.relay}: past ${limit}, so relays and peers reject what this device signs`,
    fix: CLOCK_FIX,
  };
}

async function versionCheck(c: Checks, app: App, o: DoctorOptions, ms: number): Promise<void> {
  const root = findModRoot(app, o.modRoot);
  if (!root) {
    c.add("version", "unknown", "versions", `p2p ${o.version}; no Claude mod found next to it`, "run `/peers doctor` in Claude Code to compare with the mod's bundled p2p");
    return;
  }
  const read = await bounded(modVersions(root), ms);
  if (read.value === undefined) {
    c.add("version", "unknown", "versions", `p2p ${o.version}; couldn't read the mod's files in ${Math.round(ms / 1000)}s`, "run `p2p doctor` again");
    return;
  }
  const v = read.value;
  if (!v.bundled) {
    c.add("version", "unknown", "versions", `p2p ${o.version}; the mod${v.plugin ? ` (${v.plugin})` : ""} bundles no p2p version this can read`, "reinstall the mod: `/plugin install peer2peer@peer2peer`");
    return;
  }
  if (v.bundled !== o.version) {
    c.add(
      "version",
      "fail",
      "versions",
      `this p2p is ${o.version} but the mod${v.plugin ? ` (${v.plugin})` : ""} bundles ${v.bundled}`,
      "the mod is running another p2p: check P2P_BIN and `which p2p` (`where p2p` on Windows); update that one to match, or unset P2P_BIN and remove it from your PATH so the bundled p2p is used",
    );
    return;
  }
  c.add("version", "ok", "versions", `p2p ${o.version}, the same as the mod${v.plugin ? ` (${v.plugin})` : ""} bundles`);
}

/** The circle summaries this device knows, bounded. */
async function circlesOf(app: App, ms: number): Promise<CircleSummary[]> {
  return (await bounded(listCircles(app), ms)).value ?? [];
}

async function deviceChecks(c: Checks, app: App, o: DoctorOptions, ms: number, reports: readonly RelayReport[]): Promise<void> {
  const view = (await bounded(app.view(app.userId), ms)).value;
  const name = view?.head.name ?? app.self?.name ?? "?";
  c.add("identity", "ok", "identity", `${displayAddress(app.userId, name)} on device ${app.did}${app.isKeyholder ? " (key holder)" : ""}`);
  if (!view) {
    c.add("document", "fail", "identity document", "this device holds no identity document for itself", "run `p2p identity republish` on a key-holding device, then `p2p whoami` here");
  } else {
    const now = nowSec();
    const f = identityFreshness(view.head.exp, now);
    const left = view.head.exp - now;
    const keyholderFix = app.isKeyholder ? "run any `p2p` command here (or keep Claude Code with the mod open) and it re-publishes; `p2p identity republish` forces it" : "run any `p2p` command on a key-holding device: only key holders re-publish";
    if (f === "fail-closed") c.add("document", "fail", "identity document", `version ${view.head.ver} expired ${daysPastExp(view.head.exp, now)} days ago (hard expiry): peers now refuse everything from you`, keyholderFix);
    else if (f === "expired") c.add("document", "fail", "identity document", `version ${view.head.ver} expired ${days(left)} ago (soft expiry): peers warn, and refuse it after the grace period`, keyholderFix);
    else if (left <= REPUBLISH_DOC_WITHIN_SEC) c.add("document", "ok", "identity document", `version ${view.head.ver}, expires in ${days(left)}: due for renewal (a key holder renews it on its next run)`);
    else c.add("document", "ok", "identity document", `version ${view.head.ver}, fresh (expires in ${days(left)})`);
    if (view.forked) c.add("document-fork", "fail", "identity document history", "forked (two versions claim the same place)", "run `p2p identity republish` on a key holder: it merges the branches");
    if (view.rotations.length > 0) c.add("document-rotated", "fail", "identity", "this identity moved to a new key", "follow it: `p2p held` shows the move (approve it there), or re-link with `p2p link join <code> --rotated`");
  }
  relayChecks(c, app, reports, view ? { hash: view.head.hash, ver: view.head.ver } : undefined);
  clockCheck(c, reports);

  // The default circle and our standing in it.
  const def = app.self?.defaultCircle;
  if (!def) {
    c.add("default-circle", "fail", "default circle", "none: invites join no circle by default (sessions follow their project either way: private until you share it)", "pick one: `/peers circle default <cid>` or `p2p circle default <cid>` (`p2p circle ls` lists them); share a project with `p2p project share <cid>` in it (or /peers project share)");
  } else {
    const m = await bounded(circleMembers(app, def), ms);
    if (!m.value) {
      c.add("default-circle", "fail", "default circle", `${def} isn't known on this device`, "pick one you're in: `p2p circle ls`, then `p2p circle default <cid>`");
    } else {
      const self = m.value.members.find((x) => x.self);
      const nm = peer(m.value.circle.name);
      const others = m.value.members.filter((x) => !x.self && x.stands).length;
      if (!self) c.add("default-circle", "fail", "default circle", `"${nm}" (${def}): you're not a member of it any more`, "ask its owner to add you again, or pick another: `p2p circle default <cid>`");
      else if (!self.stands) c.add("default-circle", "fail", "default circle", `"${nm}" (${def}): you're listed but don't stand in it (your membership statement is missing or a leave)`, "join it again with a fresh link from its owner (`p2p circle join <link>`)");
      else c.add("default-circle", "ok", "default circle", `"${nm}" (${def}): you stand in it as ${m.value.circle.role}, with ${others} other standing member${others === 1 ? "" : "s"}`);
    }
  }

  // Shared sessions and the status publisher.
  const peers = (await bounded(app.state.get("peers"), ms)).value ?? {};
  const sessions = (await bounded(app.state.get("sessions"), ms)).value ?? {};
  const now = Date.now();
  const mine = ownStatuses(app, peers);
  const live = mine.filter((p) => isLive(p.ts, now));
  // Your other devices: one on a client from before project boundaries runs its own sessions by the
  // old rule (new sessions follow the default circle), and can't honour a bounded own-session message.
  const others = Object.values(peers).filter((p) => p.own === app.userId && p.did !== app.did && isLive(p.ts, now));
  const older = [...new Set(others.filter((p) => !(Array.isArray(p.status.caps) && p.status.caps.includes(CAP_PROJECTS))).map((p) => p.did))];
  if (older.length > 0) {
    c.add("other-devices", "fail", "your other devices", `${older.length} of your other devices run a client without project boundaries: their sessions follow your default circle, whatever the project`, "update Peer2Peer on those devices (docs/compatibility.md, \"Project boundaries\")");
  } else if (others.length > 0) c.add("other-devices", "ok", "your other devices", "every live session of your other devices keeps project boundaries");
  if (live.length === 0) {
    c.add(
      "shared",
      "unknown",
      "shared sessions",
      mine.length === 0 ? "no session on this device has posted a status yet" : "no session on this device is live right now (none posted a status in the last 150 s)",
      "start Claude Code with the mod (or run `p2p status --session <sid> --state idle`), then `p2p doctor` again",
    );
  } else {
    const circles = await circlesOf(app, ms);
    for (const p of live.slice(0, 5)) {
      const s = sessions[p.sid];
      const label = peer(p.status.label);
      const ref = sessionRef(app.userId, p.sid);
      if (!s) {
        c.add(`shared:${safeSid(p.sid)}`, "unknown", `session "${label}" [${ref}]`, "live, but its roster isn't on this device", `run \`p2p session roster ${safeSid(p.sid)}\``);
        continue;
      }
      const aud = (await bounded(rosterAudience(app, s), ms)).value;
      const where = s.vis === "circle" && s.circle ? `circle "${peer(circles.find((x) => x.cid === s.circle)?.name ?? s.circle)}"${s.parts.length ? ` plus ${s.parts.length} added` : ""}` : s.parts.length ? `${s.parts.length} added people (private)` : "nobody (private)";
      if (aud === undefined) c.add(`shared:${safeSid(p.sid)}`, "unknown", `session "${label}" [${ref}]`, `live, shared with ${where}; couldn't work out who stands in it in time`, "run `p2p doctor` again");
      else if (aud.length === 0)
        c.add(`shared:${safeSid(p.sid)}`, "fail", `session "${label}" [${ref}]`, `live, but shared with ${where}: nobody else can see it`, "its project is private until you share it: `p2p project share <cid>` in it (or /peers project share in that session); `p2p project show` says why");
      else {
        const names = await Promise.all(aud.slice(0, 5).map((u) => app.addressOf(u)));
        c.add(`shared:${safeSid(p.sid)}`, "ok", `session "${label}" [${ref}]`, `live, shared with ${where}: ${aud.length} can see it (${names.join(", ")}${aud.length > 5 ? ", …" : ""})`);
      }
    }
  }
  if (mine.length === 0) c.add("publisher", "unknown", "status publisher", "this device has never posted a status", "start Claude Code with the mod: it posts every 60 s while a session runs");
  else if (isLive(mine[0].ts, now)) c.add("publisher", "ok", "status publisher", `last status from this device ${ago(now - mine[0].ts)} ("${peer(mine[0].status.label)}", ${mine[0].status.state})`);
  else c.add("publisher", "fail", "status publisher", `last status from this device ${ago(now - mine[0].ts)}: peers see nothing live from you`, "is Claude Code with the mod running? It posts every 60 s; `p2p status --session <sid> --state idle` posts one by hand");
  const cur = watchCursor(app.home);
  if (!cur) c.add("watch", "unknown", "watch", "no `p2p watch` has run on this device (no cursor)", "the mod runs `p2p watch` for each session; start Claude Code with the mod");
  else c.add("watch", now - cur.at < 3600_000 ? "ok" : "unknown", "watch", `a watcher last moved its cursor ${ago(now - cur.at)} (it moves only when events arrive, so this doesn't prove it's running)`, "if nothing arrives, restart the Claude Code session (the mod restarts `p2p watch`)");
  // review M-A: envelopes this device dropped unapplied (a count only, never what they held).
  const inbound = await app.state.get("inbound").catch(() => undefined);
  const dropped = inbound?.gaveUp ?? 0;
  const tooOld = inbound?.tooOld ?? 0;
  if (tooOld > 0) {
    c.add(
      "inbound-old",
      "unknown",
      "late envelopes",
      `${tooOld} arrived behind the replay window (more than 512 later ones from the same session first, or a duplicate) and ${tooOld === 1 ? "was" : "were"} dropped`,
      "if a message from someone seems missing, ask them to send it again",
    );
  }
  if (dropped > 0) {
    c.add(
      "inbound",
      "unknown",
      "incoming envelopes",
      `${dropped} couldn't be applied and ${dropped === 1 ? "was" : "were"} dropped after failing for good (or every attempt)`,
      "if messages from someone seem missing, ask them to send again; P2P_DEBUG=1 on `p2p ls` shows why one fails",
    );
  }

  await ixChecks(c, app, ms);
  await versionCheck(c, app, o, ms);
}


// ---------------------------------------------------------------------------
// Ix (epic #41): the local CLI, its backend, this checkout's map, and each project's graph target

/** At most this many projects' graph targets are listed. */
const MAX_GRAPH_ROWS = 10;

/**
 * The Ix section: the binary and its version, the local backend (reachable at the local endpoint),
 * whether the project here is mapped, and the graph target of the project here and of each project
 * with a policy ("local only" today). Without Ix nothing is a failure: Peer2Peer works without it.
 * `ix` runs as ext-ix runs it (ix-local.ts): absolute path, allowlisted environment, the local
 * endpoint pinned, read-only commands, bounded.
 */
export async function ixChecks(c: Checks, app: App, ms: number): Promise<void> {
  const local = localGraphEndpoint(app.env, app.file);
  const target = { endpoint: local };
  const bin = ixBinary(app.env);
  const on = enabledNamespaces(app.env, app.file).enabled.includes("ix");
  if (!bin) {
    c.add(
      "ix",
      "unknown",
      "Ix",
      `the Ix CLI isn't installed: it is optional (Peer2Peer works without it; peers' Ix items show as plain text)${ixDeclined(app.file) ? ", and you said no to it at setup" : ""}`,
      personHere(app)
        ? `optional and recommended; Peer2Peer never installs it. To add it, run \`${ixInstallLine()}\` yourself (${IX_INSTALL_URL}), then \`p2p setup --ix\``
        : `optional and recommended; installing it is your user's decision, never yours: ask your user whether they want it; they run \`${ixInstallLine()}\` in their own terminal, then \`p2p setup --ix\``,
    );
  } else {
    const v = (await bounded(ixVersion(bin, app.env, target, ms), ms + 500)).value;
    if (v) c.add("ix", "ok", "Ix", `ix ${v} (${bin})`);
    else c.add("ix", "unknown", "Ix", `${bin} didn't answer \`ix --version\` in time`, "run `ix --version` in a terminal");
    if (on) c.add("ix-extension", "ok", "Ix extension", "enabled: sessions can share Ix context");
    else c.add("ix-extension", "unknown", "Ix extension", "not enabled", extIxInstalled(app.env) ? "`p2p extensions enable ix`" : "`npm i -g @peer2peer/ext-ix`, then `p2p extensions enable ix`");
    if (on) await graphMemoryChecks(c, app, bin, target, ms);
    // Never followed elsewhere: a loopback listener that redirects is not the local backend.
    const h = await httpProbe(`${local}/v1/health`, ms, { noRedirect: true });
    if (h.ok && h.status !== undefined && h.status < 500) c.add("ix-backend", "ok", "Ix backend", `reachable at ${local} (${h.ms} ms)`);
    else c.add("ix-backend", "fail", "Ix backend", `nothing answers at ${local}${h.error ? `: ${h.error}` : h.status ? ` (HTTP ${h.status})` : ""}`, "start it with `ix docker start` (or set `ixEndpoint` in config.json to your local backend)");
    const here = projectOf(sessionWorkdir(app.env));
    if (here.kind === "git" && h.ok) {
      const st = (await bounded(runIx(bin, ["status", "--format", "json", "--root", here.root], { env: app.env, target, cwd: here.root, timeoutMs: ms }), ms + 500)).value;
      let mapped: boolean | undefined;
      try {
        const j = st && st.code === 0 ? (JSON.parse(st.stdout) as { graphCompleted?: unknown }) : undefined;
        mapped = j ? j.graphCompleted === true : undefined;
      } catch {
        mapped = undefined;
      }
      if (mapped === true) c.add("ix-workspace", "ok", "Ix workspace", `${here.name} is mapped`);
      else if (mapped === false) c.add("ix-workspace", "unknown", "Ix workspace", `${here.name} isn't mapped yet`, `run \`ix map\` in ${here.root}`);
      else c.add("ix-workspace", "unknown", "Ix workspace", `couldn't tell whether ${here.name} is mapped`, "run `ix status` in it");
    }
  }
  // Graph targets: the project here first, then each project with a policy.
  const doc = (await bounded(projectsDoc(app), ms)).value ?? { v: 1 as const, projects: {} };
  const here = projectOf(sessionWorkdir(app.env));
  const rows: { id: string; name: string; repoPrivate?: true }[] = [{ id: here.id, name: here.name, ...(here.repoPrivate ? { repoPrivate: true as const } : {}) }];
  const all = (await bounded(listProjects(app), ms)).value ?? [];
  for (const p of all) if (!rows.some((r) => r.id === p.id)) rows.push({ id: p.id, name: p.name });
  for (const r of rows.slice(0, MAX_GRAPH_ROWS)) {
    const t = projectGraphTarget(app, r, doc);
    c.add(`graph:${r.id}`, "ok", `graph of project ${peer(r.name)}${r.id === here.id ? " (here)" : ""}`, `${describeGraphTarget(t)}${t.kind === "local" ? `: ${t.why}` : ""}`);
  }
  if (rows.length > MAX_GRAPH_ROWS) c.add("graph:more", "ok", "graphs of other projects", `${rows.length - MAX_GRAPH_ROWS} more not listed (run \`p2p project show\` in each)`);
}

/**
 * Graph memory (graph-memory.ts): whether this Ix has the OSS `ix note` (local) or Ix Pro's (cloud,
 * so memory stays off), and what `p2p watch` wrote, queued and dropped. Never a failure: Peer2Peer
 * works without it.
 */
async function graphMemoryChecks(c: Checks, app: App, bin: string, target: { endpoint: string }, ms: number): Promise<void> {
  if (!graphMemoryEnabled(app.env, app.home)) {
    c.add("ix-memory", "ok", "Ix graph memory", 'off ("ixMemory": false in config.json, or P2P_IX_MEMORY=0)');
    return;
  }
  const support = (await bounded(ixMemorySupport(bin, app.env, target, ms), ms + 500)).value;
  const doc = (await bounded(graphMemoryReport(app), ms)).value;
  const counts = doc ? `${doc.written} written, ${doc.queue.length} queued` : "nothing written yet";
  const dropped = doc ? Object.entries(doc.dropped).filter(([, n]) => n > 0) : [];
  if (support === "oss") c.add("ix-memory", "ok", "Ix graph memory", `on: sessions' records, statuses and edited files go to the local graph only (${target.endpoint}); ${counts}`);
  else if (support === "pro") c.add("ix-memory", "unknown", "Ix graph memory", "off: Ix Pro is installed, and its `ix note` writes to your cloud org; Peer2Peer keeps graph writes local", "use an Ix without Pro for local notes (or leave it off)");
  else if (support === "none") c.add("ix-memory", "unknown", "Ix graph memory", "off: this Ix has no local `ix note` (it came after Ix 0.13.0)", "upgrade Ix (`ix upgrade`)");
  else c.add("ix-memory", "unknown", "Ix graph memory", `couldn't tell whether this Ix has a local \`ix note\`; ${counts}`, "run `ix --help` in a terminal");
  if (dropped.length > 0) {
    const total = dropped.reduce((a, [, n]) => a + n, 0);
    c.add("ix-memory-dropped", "unknown", "Ix graph memory dropped", `${total} item${total === 1 ? "" : "s"} not written (${dropped.map(([r, n]) => `${peer(r)}: ${n}`).join(", ")})`, "best effort: each reason is counted; the queue holds 64 items");
  }
  if (doc?.unavailable && support === "oss") {
    // Who holds the local endpoint's port wasn't this user (ext-ix listener.ts): say what to do.
    const fix =
      doc.unavailable.reason === "ix_listener"
        ? `start your Ix backend (\`ix docker start\`); if another user's process holds the port, use a port of yours (\`ixEndpoint\` in config.json). On Linux, Docker's port proxy runs as root: if this machine's Docker is only yours, set "ixTrustRootListener": true in config.json (by hand)`
        : undefined;
    c.add("ix-memory-last", "unknown", "Ix graph memory", `last stopped: ${peer(doc.unavailable.message, 300)}`, fix);
  }
  if (app.file.ixTrustRootListener === true) c.add("ix-memory-root", "ok", "Ix graph memory", 'a root-owned listener on the local port counts as yours ("ixTrustRootListener": true in config.json)');
}

// ---------------------------------------------------------------------------
// About another user

/**
 * Refreshes `userId`'s document from at most 5 relays, whatever its held (possibly forked) view
 * lists: a peer's document chooses those hosts, so the doctor never contacts more of them than a
 * single document may list (§5.8). Writes land in the read-only overlay (readonly.ts).
 */
async function refreshCapped(app: App, userId: string, relays: readonly string[]): Promise<IdentityView | undefined> {
  const allowed = new Set(relays.slice(0, MAX_PEER_RELAYS));
  const only = (rs: readonly string[]) => rs.filter((r) => allowed.has(r));
  const f = app.fetcher() as { tips: TipsFetcher; chain: ChainFetcher };
  const v = await coreRefreshIdentity(app.store, userId, { tips: (u, rs) => f.tips(u, only(rs)), chain: (u, rs, to, n) => f.chain(u, only(rs), to, n) }, { relays: [...allowed] });
  return v.incomplete ? undefined : v;
}

async function userChecks(c: Checks, app: App, userId: string, ms: number, mine: readonly RelayReport[]): Promise<void> {
  const now = Date.now();
  const nowS = nowSec();
  const store = app.store;
  const me = app.userId;

  // Friendship, or circles we share.
  const friendship = await bounded(
    (async () => {
      const live = await liveFriendshipsV3(store, app.signerCtx(), (f) => f.inviter === userId || f.invitee === userId);
      const unfriends = await store.listUnfriends();
      return live.find((f) => !unfriends.some((u) => unfriendApplies(f, u)));
    })(),
    ms,
  );
  const circles = await circlesOf(app, ms);
  const shared: { cid: string; name: string; meStands: boolean; themStands: boolean }[] = [];
  for (const s of circles) {
    if (!s.joined) continue;
    const m = (await bounded(circleMembers(app, s.cid), ms)).value;
    const them = m?.members.find((x) => x.userId === userId);
    const self = m?.members.find((x) => x.self);
    if (them) shared.push({ cid: s.cid, name: peer(s.name), meStands: !!self?.stands, themStands: them.stands });
  }
  const standing = shared.filter((s) => s.meStands && s.themStands);
  const circleText = (list: typeof shared) => list.map((s) => `"${s.name}"`).join(", ");
  if (friendship.timedOut) c.add("friendship", "unknown", "friendship", "couldn't check in time", "run `p2p doctor` again");
  else if (friendship.value) {
    c.add("friendship", "ok", "friendship", `friends since ${new Date(friendship.value.iat * 1000).toISOString().slice(0, 10)}${standing.length ? `; you also share ${circleText(standing)}` : ""}`);
  } else if (standing.length > 0) c.add("friendship", "ok", "friendship", `not friends, but you both stand in ${circleText(standing)}`);
  else if (shared.length > 0)
    c.add("friendship", "fail", "friendship", `not friends; you share ${circleText(shared)} but ${shared.some((s) => !s.themStands) ? "they don't stand in it (no join statement)" : "you don't stand in it"}`, "re-join from a fresh circle link (`p2p circle join <link>`), or become friends: `p2p invite` and they run `p2p join <code>` (or `/peers join <code>`)");
  else c.add("friendship", "fail", "friendship", "you're not friends and share no circle", "make an invite: `p2p invite` (or `/peers invite`), and they run `p2p join <code>` (or `/peers join <code>`)");

  // Their identity document.
  const held = (await bounded(app.view(userId), ms)).value;
  const probeRelays = [...new Set([...(held?.relays ?? []), ...app.relays])].slice(0, 5);
  const refreshed = await bounded(refreshCapped(app, userId, probeRelays), ms * 2);
  const view: IdentityView | undefined = refreshed.value ?? held;
  if (!view) {
    c.add("their-document", "fail", "their identity document", `not found on ${probeRelays.length ? probeRelays.map(peerUrl).join(", ") : "any relay"}${refreshed.timedOut ? " (timed out)" : ""}`, "ask them to run `p2p doctor` (their document may not be published), or for a fresh invite that carries it");
  } else {
    const f = identityFreshness(view.head.exp, nowS);
    const how = refreshed.value ? "fetched just now" : "the copy held here (couldn't refresh it)";
    if (f === "fresh") c.add("their-document", refreshed.value ? "ok" : "unknown", "their identity document", `version ${view.head.ver}, fresh (expires in ${days(view.head.exp - nowS)}); ${how}`, "check your relays are reachable, then `p2p doctor <user>` again");
    else c.add("their-document", "fail", "their identity document", `version ${view.head.ver} expired ${days(nowS - view.head.exp)} ago (${f === "fail-closed" ? "hard expiry: everything from them is refused" : "soft expiry"}); ${how}`, "they need to run any `p2p` command (or open Claude Code with the mod) on a key-holding device");
    if (view.rotations.length > 0) c.add("their-rotation", "fail", "their identity", "they moved to a new key", "approve the move when it's held (`p2p held`), or ask them for a fresh invite");
  }

  // Their relays, and one we share and reach.
  if (view) {
    // A peer's document (every tip of it) chooses these hosts: probe at most 5, keep no answer body.
    const theirs = orderRelays(view.head.relays, view.relays).slice(0, MAX_PEER_RELAYS);
    const ours = new Set(app.relays);
    const mineByRelay = new Map(mine.map((r) => [r.relay, r]));
    const others = theirs.filter((r) => !mineByRelay.has(r));
    const probed = new Map(await Promise.all(others.map(async (r) => [r, (await httpProbe(`${app.transport(r).http}/identity/${encodeURIComponent(userId)}`, ms)).ok] as const)));
    const reach = (r: string) => (mineByRelay.get(r)?.reachable ?? probed.get(r)) === true;
    const common = theirs.filter((r) => ours.has(r));
    const reachableTheirs = theirs.filter(reach);
    const list = theirs.map((r) => `${peerUrl(r)}${reach(r) ? "" : " (unreachable from here)"}`).join(", ");
    if (common.some(reach)) c.add("relays", "ok", "relays", `they list ${list}; you share ${common.filter(reach).map(peerUrl).join(", ")}, reachable from here`);
    else if (common.length > 0) c.add("relays", "fail", "relays", `they list ${list}; the relay you share isn't reachable from here`, "check your network; or both add another relay you can reach: `p2p relays add <wss://…>`");
    else if (reachableTheirs.length > 0)
      c.add("relays", "unknown", "relays", `they list ${list}; you share none (you reach theirs, but can they reach ${app.relays.join(", ")}?)`, "use a common relay: one of you runs `p2p relays add <url>` (or `/peers relays add <url>`) with a relay the other lists");
    else c.add("relays", "fail", "relays", `they list ${list}; you share none and reach none of theirs`, "use a common relay you both reach: `p2p relays add <url>` (or `/peers relays add <url>`)");

    // Caps we hold for them (what `p2p send` and statuses would use).
    const caps = (await bounded(app.capsFor(userId, "status"), ms)).value;
    const targets = theirs.slice(0, 3);
    if (!caps) c.add("cap-ours", "unknown", "your capability for them", "couldn't check in time", "run `p2p doctor` again");
    else {
      const usable = targets.filter((r) => caps.has(r));
      if (usable.length > 0) c.add("cap-ours", "ok", "your capability for them", `you can reach their mailbox on ${usable.map(peerUrl).join(", ")}`);
      else if (caps.size > 0) c.add("cap-ours", "fail", "your capability for them", `the capabilities you hold name ${[...caps.keys()].slice(0, MAX_PEER_RELAYS).map(peerUrl).join(", ")}, none of their current relays`, "they changed relays: a fresh invite re-grants it (`p2p invite`, they run `p2p join <code>`)");
      else c.add("cap-ours", "fail", "your capability for them", "you hold none, so your statuses and messages can't reach them", "become friends (`p2p invite` → they `p2p join <code>`) or share a circle you both stand in");
    }
  }

  // Caps they hold for us, as far as we can tell: what we issued them, and our join cap in circles we share.
  const issued = ((await bounded(store.listCapsIssued(), ms)).value ?? []).filter((x) => x.sub === userId && x.exp > nowS + 60 && capAllowsKind(x.kinds, "status"));
  const ours = new Set(app.relays);
  const fromCircles: { relays: string[]; exp: number }[] = [];
  for (const s of standing) {
    const rec = (await bounded(store.getCircle(s.cid), ms)).value;
    const st = rec?.statements[me];
    const cap = st?.op === "join" ? joinCapOf(st.jws) : undefined;
    const p = cap ? capPeek(cap) : undefined;
    if (p && p.exp > nowS + 60) fromCircles.push({ relays: p.relays, exp: p.exp });
  }
  const all = [...issued.map((x) => ({ relays: x.relays, exp: x.exp })), ...fromCircles];
  const reaching = all.filter((x) => x.relays.some((r) => ours.has(r)));
  if (reaching.length > 0) {
    const exp = Math.max(...reaching.map((x) => x.exp));
    c.add("cap-theirs", "ok", "their capability for you", `you gave them one for ${[...new Set(reaching.flatMap((x) => x.relays.filter((r) => ours.has(r))))].join(", ")} (good for ${days(exp - nowS)})`);
  } else if (all.length > 0) c.add("cap-theirs", "fail", "their capability for you", `the capabilities you gave them name ${[...new Set(all.flatMap((x) => x.relays))].join(", ")}, none of your current relays`, "their statuses can't reach you: a fresh invite fixes it (`p2p invite`, they run `p2p join <code>`)");
  else c.add("cap-theirs", "fail", "their capability for you", "this device has no record of giving them one, so their statuses can't reach your relays", "become friends (`p2p invite` → they `p2p join <code>`), or both stand in one circle");

  // When anything last arrived from them.
  const peers = (await bounded(app.state.get("peers"), ms)).value ?? {};
  const events = (await bounded(app.state.get("events"), ms)).value;
  const recs = Object.values(peers)
    .filter((p) => p.own === userId)
    .sort((a, b) => b.ts - a.ts);
  const lastEvent = (events?.items ?? [])
    .filter((e) => (e.data as { from?: { userId?: unknown } }).from?.userId === userId)
    .reduce((m, e) => Math.max(m, e.at), 0);
  const lastStatus = recs[0]?.ts ?? 0;
  const queued = mine.reduce((n, r) => n + r.ws.queued, 0);
  const queuedNote = queued > 0 ? ` ${queued} envelope${queued === 1 ? " is" : "s are"} still waiting in this device's mailbox: \`p2p ls\` processes them` : "";
  if (lastStatus === 0 && lastEvent === 0) {
    c.add("received", "fail", "last heard from them", `nothing from them has reached this device yet.${queuedNote}`, queued > 0 ? "run `p2p ls`, then `p2p doctor <user>` again" : "ask them to run `p2p doctor <you>` (or `/peers doctor <you>`): their side shows what's missing");
  } else {
    const last = Math.max(lastStatus, lastEvent);
    c.add("received", "ok", "last heard from them", `${ago(now - last)}${lastStatus ? ` (last status ${ago(now - lastStatus)})` : ""}${queuedNote ? `.${queuedNote}` : ""}`);
  }

  // Blocked, suspended, held.
  const blocked = (await bounded(store.isBlocked(userId), ms)).value === true;
  const disputes = (await bounded(app.state.get("disputes"), ms)).value ?? {};
  const dispute = Object.values(disputes).find((d) => d.suspended.some((s) => s.userId === userId) || d.candidates.includes(userId));
  const heldItems = ((await bounded(app.state.get("held"), ms)).value ?? []).filter((h) => h.from === userId);
  if (blocked) c.add("blocked", "fail", "blocked", "you blocked them: everything from them is refused", `\`p2p unblock ${userId}\``);
  if (dispute) c.add("suspended", "fail", "suspended", "suspended: another key also claims to be them (a contested move to a new key)", `check with them another way, then \`p2p identity dispute ${dispute.heldId} --keep <userId>\` (or /peers approve)`);
  for (const h of heldItems.slice(0, 3)) {
    c.add(`held:${h.id}`, "fail", "held", `a ${h.type.replace(/-/g, " ")} from them waits for you`, `\`/peers approve ${h.id}\` or \`p2p held approve ${h.id}\` (decline: \`p2p held decline ${h.id}\`)`);
  }
  if (!blocked && !dispute && heldItems.length === 0) c.add("blocked", "ok", "blocks and holds", "not blocked, suspended or held");

  // Their sessions: shared with an audience we're in?
  const myCircle = app.self?.defaultCircle ? standing.find((s) => s.cid === app.self?.defaultCircle) ?? standing[0] : standing[0];
  const askShare = myCircle
    ? `they haven't shared any session with "${myCircle.name}": ask them to share their project with it, \`/peers project share ${myCircle.cid}\` in their session (or \`p2p project share ${myCircle.cid}\` in the repository)`
    : `ask them to share their project with you: \`/peers project share --person ${displayAddress(me, app.self?.name ?? "?")}\` in their session (or \`p2p project share --person <you>\` in the repository)`;
  if (recs.length === 0) {
    c.add("their-sessions", "fail", "their sessions", `no status from any of their sessions has reached you.${queuedNote}`, queued > 0 ? "run `p2p ls`, then `p2p doctor <user>` again" : askShare);
  } else {
    let reported = 0;
    for (const p of recs.slice(0, 3)) {
      const roster = (await bounded(store.getRoster(userId, p.sid), ms)).value;
      let r: { vis?: unknown; circle?: unknown; parts?: unknown } = {};
      try {
        r = roster ? (decodeTyped(roster.jws, TYP3.roster).payload as typeof r) : {};
      } catch {
        r = {};
      }
      const parts = Array.isArray(r.parts) ? r.parts : [];
      const circle = typeof r.circle === "string" ? r.circle : undefined;
      const inCircle = circle ? standing.some((s) => s.cid === circle) : false;
      const circleName = circle ? (shared.find((s) => s.cid === circle)?.name ?? peer(circle, 128)) : undefined;
      const via = parts.includes(me) ? "you directly" : r.vis === "circle" && circle ? `circle "${circleName}"` : "nobody else (private)";
      const label = `session "${peer(p.status.label)}" [${sessionRef(userId, p.sid)}]`;
      const isIn = parts.includes(me) || (r.vis === "circle" && inCircle) || p.viewerRule !== undefined;
      const liveNow = isLive(p.ts, now);
      if (!isIn) c.add(`their-session:${safeSid(p.sid)}`, "fail", label, `shared with ${via}, which doesn't include you`, circle && !inCircle ? `you don't stand in that circle: ask its owner to add you, or them to run \`/peers add <you>\` in that session` : askShare);
      else if (!liveNow) c.add(`their-session:${safeSid(p.sid)}`, "fail", label, `shared with ${via}, but its last status was ${ago(now - p.ts)}: not live`, "their session isn't running, or its status isn't going out: ask them to run `/peers doctor`");
      else c.add(`their-session:${safeSid(p.sid)}`, "ok", label, `live (${p.status.state}, ${ago(now - p.ts)}), shared with ${via}`);
      reported++;
    }
    if (recs.length > reported) c.add("their-sessions", "ok", "their sessions", `${recs.length - reported} more not shown`);
  }
}

// ---------------------------------------------------------------------------

export function summarize(checks: readonly Check[]): DoctorResult["summary"] {
  return {
    ok: checks.filter((x) => x.status === "ok").length,
    fail: checks.filter((x) => x.status === "fail").length,
    unknown: checks.filter((x) => x.status === "unknown").length,
  };
}

/** The doctor's per-step bound: P2P_DOCTOR_TIMEOUT_MS (default 5 s), never more than the connect timeout. */
export function doctorTimeoutMs(app: App, override?: number): number {
  if (override !== undefined) return override;
  const raw = Number(app.env.P2P_DOCTOR_TIMEOUT_MS);
  const base = Number.isFinite(raw) && raw > 0 ? raw : 5000;
  const cap = app.tun.connectTimeoutMs > 0 ? app.tun.connectTimeoutMs : base;
  return Math.max(200, Math.min(base, cap));
}

export async function doctor(app: App, o: DoctorOptions): Promise<DoctorResult> {
  // Read-only, whoever calls: on a writable context, diagnose through a read-only one (readonly.ts).
  if (!app.readOnly) app = new App({ env: app.env, io: app.io, readOnly: true });
  const ms = doctorTimeoutMs(app, o.timeoutMs);
  // Every network step the app itself takes (identity refreshes, discovery) is bounded the same way.
  app.tun.connectTimeoutMs = ms;
  app.tun.requestTimeoutMs = ms;
  const c = new Checks();
  const scope: DoctorResult["scope"] = o.user !== undefined ? "user" : "device";
  const hasIdentity = await app.load(false).catch(() => false);
  if (!hasIdentity) {
    c.add("identity", "fail", "identity", "this device has no Peer2Peer identity yet", "run `/peers setup` in Claude Code (or `p2p setup`), then `/peers join <code>` with a code from a friend");
    let relays: string[];
    try {
      relays = defaultRelays(app.env, app.file);
    } catch {
      relays = [];
    }
    if (relays.length === 0) c.add("relays", "unknown", "relays", "no relays configured yet", "`p2p setup --relay <wss://…>` picks one");
    else relayChecks(c, app, await probeRelays(app, relays, ms, false), undefined);
    await versionCheck(c, app, o, ms);
    return { scope, version: o.version, ...(o.user !== undefined ? { user: { input: o.user } } : {}), checks: c.list, summary: summarize(c.list) };
  }
  const reports = await probeRelays(app, app.relays, ms, true, app.userId);
  if (scope === "device") {
    await deviceChecks(c, app, o, ms, reports);
    return { scope, version: o.version, checks: c.list, summary: summarize(c.list) };
  }
  // About a user: who they are first (a userId needn't be known yet).
  const input = o.user!.trim();
  let userId: string | undefined;
  try {
    userId = isUserId(input) ? input : await app.resolveUser(input);
  } catch (e) {
    const amb = e instanceof CliError && e.code === "ambiguous";
    c.add(
      "user",
      "fail",
      "who",
      amb ? `more than one known identity matches "${peer(input)}"` : `no known identity matches "${peer(input)}"`,
      amb ? "use their name@fingerprint (as `p2p friends` shows it), or set a petname: `p2p petname <userId> <name>`" : "use their full name@fingerprint or userId (ask them for `p2p whoami`); if you've never connected, make an invite: `p2p invite`",
    );
    return { scope, version: o.version, user: { input }, checks: c.list, summary: summarize(c.list) };
  }
  if (userId === app.userId) {
    await deviceChecks(c, app, o, ms, reports);
    return { scope: "device", version: o.version, user: { input, userId, address: await app.addressOf(userId) }, checks: c.list, summary: summarize(c.list) };
  }
  // This device first, in one line (its details are `p2p doctor` with no user).
  const dev = new Checks();
  await deviceChecks(dev, app, o, ms, reports);
  // Only what decides whether this device can hear anyone: identity, document, relays, clock.
  const bad = dev.list.filter((x) => x.status === "fail" && /^(identity|document|relay:|published:|clock)/.test(x.id));
  if (bad.length === 0) c.add("device", "ok", "this device", "identity, relays and clock look fine");
  else c.add("device", "fail", "this device", `${bad.length} problem${bad.length === 1 ? "" : "s"}: ${bad.map((x) => x.title).join(", ")}`, "run `p2p doctor` (no user) for details and fixes");
  await userChecks(c, app, userId, ms, reports);
  const versions = await versionChecks(c, app, userId);
  return { scope, version: o.version, user: { input, userId, address: await app.addressOf(userId) }, checks: c.list, summary: summarize(c.list), ...versions };
}

/**
 * Each of the user's devices with its client version and what it understands (from its identity
 * document entry or its latest status), and the features unavailable between you. A difference is
 * never a failure: the feature is left out between you, and everything you share still works.
 */
async function versionChecks(c: Checks, app: App, userId: string): Promise<Pick<DoctorResult, "devices" | "unavailable">> {
  const devices = await peerDevices(app, userId).catch(() => [] as PeerDevice[]);
  for (const d of devices) {
    const name = d.label ? `device "${peer(d.label)}"` : `device ${d.did.slice(0, 12)}`;
    if (!d.source) {
      c.add(`version:${d.did}`, "unknown", name, "its client version isn't known yet (no status from it, and its identity document doesn't say)", "it shows once one of its sessions shares a status with you");
      continue;
    }
    const caps = d.caps.filter((x) => !x.startsWith("proto.")).join(", ") || "none listed";
    // The exact version only when the device publishes it (opt-in `dinfo`); else the protocol minor says enough.
    c.add(`version:${d.did}`, "ok", name, `protocol 3.${d.proto}${d.client ? `, client ${peer(d.client)}` : ""}; understands ${caps}${d.source === "status" ? " (from its latest status)" : ""}`);
  }
  const known = devices.filter((d) => d.source).map((d) => d.caps.concat(d.proto > 0 ? [`proto.3.${d.proto}`] : []));
  const unavailable = unavailableBetween(CLI_CAPS, known);
  const words = (caps: string[]) => caps.map((cap) => KNOWN_FEATURES.find((f) => f.cap === cap)?.what ?? cap).join("; ");
  if (known.length > 0) {
    if (unavailable.theyLack.length === 0 && unavailable.weLack.length === 0) c.add("features", "ok", "features", "everything this client knows works between you");
    else {
      const parts = [
        ...(unavailable.theyLack.length ? [`their client can't use: ${words(unavailable.theyLack)}`] : []),
        ...(unavailable.weLack.length ? [`yours can't use: ${words(unavailable.weLack)}`] : []),
      ];
      c.add("features", "ok", "features", `${parts.join("; ")}. Those are left out between you; the rest works`, unavailable.weLack.length ? "update p2p to use them" : "they can update to use them");
    }
  }
  return { devices, unavailable };
}

/** Human output: one line per check (✓ ✗ ?), with its fix indented below. */
export function formatDoctor(r: DoctorResult): string {
  const head = r.scope === "user" && r.user ? `p2p doctor: can you see ${r.user.address ?? r.user.input}?` : "p2p doctor: this device";
  const lines = [head, ""];
  for (const x of r.checks) {
    lines.push(`${MARK[x.status]} ${x.title}: ${x.detail}`);
    if (x.fix) lines.push(`    ${x.status === "unknown" ? "to tell" : "fix"}: ${x.fix}`);
  }
  lines.push("", `${r.summary.ok} ✓  ${r.summary.fail} ✗  ${r.summary.unknown} ?`);
  return lines.join("\n");
}
