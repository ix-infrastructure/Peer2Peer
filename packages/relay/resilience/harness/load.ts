// Copyright 2026 Ix Infrastructure Inc.
//
// Shared pieces of every resilience test: thresholds, clients that present a
// chosen client IP through X-Forwarded-For (the relay runs with TRUST_PROXY=1,
// so one loopback socket can stand for many source addresses), the canary
// pair, a stats sampler and the end-of-test health assertions.

import { expect } from "vitest";
import { WebSocket } from "ws";
import {
  authSig,
  makeCap,
  makeDevice,
  makeEnvelope,
  makeIdentity,
  TestClient,
  type Device,
  type Frame,
} from "../../src/__tests__/helpers.js";
import type { DebugStats, RelayProcess } from "./relay-process.js";

// ---------------------------------------------------------------------------
// Thresholds (README.md explains each)

export const THRESHOLDS = {
  /** Event-loop delay p99 over a test's load phase. */
  lagP99Ms: 50,
  /** Event-loop delay max during the periodic sweep (#11 only). */
  sweepLagMaxMs: 100,
  /** RSS ceiling for any relay process in the suite. */
  rssMaxBytes: 256 * 1024 * 1024,
  /** RSS growth allowed from the start of the load phase to its end. */
  rssGrowthBytes: 64 * 1024 * 1024,
  /** Canary delivery latency (send frame written -> env frame received). */
  canaryP99Ms: 250,
  canaryMaxMs: 1000,
  /** On-disk database (db + WAL + SHM) above what the store limit allows. */
  dbOverheadBytes: 16 * 1024 * 1024,
} as const;

/** The canary's own source address; attackers never use it. */
export const CANARY_IP = "203.0.113.7";

// ---------------------------------------------------------------------------
// Clients

export const xff = (ip: string): Record<string, string> => ({ "x-forwarded-for": ip });

/**
 * TestClient.connect, except that a refused upgrade leaves no dangling
 * hello-waiter behind (TestClient.connect arms it before the socket opens, so
 * a 429 there turns into an unhandled timeout two seconds later).
 */
export async function connectFrom(relay: RelayProcess, ip: string): Promise<TestClient> {
  const ws = new WebSocket(relay.url, { headers: xff(ip) });
  const c = new (TestClient as unknown as new (ws: WebSocket) => TestClient)(ws);
  await new Promise<void>((resolve, reject) => {
    ws.once("open", () => resolve());
    ws.once("error", reject);
    ws.once("unexpected-response", (_req, res) => {
      reject(new Error(`HTTP ${res.statusCode}`));
      res.resume();
      ws.terminate();
    });
  });
  // Frames that arrive before a waiter is armed are queued, so this can't miss hello.
  c.hello = await c.next((f) => f.t === "hello");
  return c;
}

/** Connects from `ip` and authenticates `device`; throws with the relay's answer on failure. */
export async function authedFrom(relay: RelayProcess, device: Device, ip: string): Promise<TestClient> {
  const c = await connectFrom(relay, ip);
  const reply = await c.auth(device);
  if (reply.t !== "ok") {
    c.ws.terminate();
    throw new Error(`auth failed: ${JSON.stringify(reply)}`);
  }
  return c;
}

/** Connect + auth, returning the outcome instead of throwing. */
export async function tryAuthFrom(relay: RelayProcess, device: Device, ip: string): Promise<{ client?: TestClient; outcome: string }> {
  let c: TestClient;
  try {
    c = await connectFrom(relay, ip);
  } catch (e) {
    return { outcome: (e as Error).message };
  }
  try {
    const reply = await c.auth(device);
    if (reply.t === "ok") return { client: c, outcome: "ok" };
    c.ws.terminate();
    return { outcome: String(reply.code) };
  } catch (e) {
    c.ws.terminate();
    return { outcome: (e as Error).message };
  }
}

export const newDevice = (relay: RelayProcess): Device => makeDevice(makeIdentity(), relay.nowSec());
export const dest = (d: Device) => ({ userId: d.identity.userId, did: d.did });

/** A `send` frame from `from` to `to`, with a cap from `to` unless `cap` is null. */
export function sendFrame(from: Device, to: Device, o: { cap?: string | null; padTo?: number; kind?: string; plaintext?: string; id?: string } = {}): Frame {
  const env = makeEnvelope(from, dest(to), { padTo: o.padTo, kind: o.kind, plaintext: o.plaintext });
  const f: Frame = { t: "send", to: to.identity.userId, tdid: to.did, env };
  if (o.cap !== null) f.cap = o.cap;
  if (o.id) f.id = o.id;
  return f;
}

export { authSig };

export function percentile(xs: readonly number[], p: number): number {
  if (xs.length === 0) return 0;
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)];
}

export const tally = (xs: readonly string[]): Record<string, number> => {
  const out: Record<string, number> = {};
  for (const x of xs) out[x] = (out[x] ?? 0) + 1;
  return out;
};

// ---------------------------------------------------------------------------
// Canary: two honest users exchanging messages for the whole test

export interface CanaryReport {
  sent: number;
  accepted: number;
  delivered: number;
  lost: number;
  rejected: Record<string, number>;
  p50Ms: number;
  p99Ms: number;
  maxMs: number;
}

export class Canary {
  private readonly sentAt = new Map<string, number>();
  private readonly accepted = new Set<string>();
  private readonly delivered = new Set<string>();
  private readonly latencies: number[] = [];
  private readonly rejected: string[] = [];
  private timer?: NodeJS.Timeout;
  private ackTimer?: NodeJS.Timeout;
  private pendingAcks: string[] = [];
  private inflight = 0;
  private stopped = false;

  private constructor(
    readonly relay: RelayProcess,
    readonly a: Device,
    readonly b: Device,
    readonly ac: TestClient,
    readonly bc: TestClient,
    readonly cap: string,
  ) {
    bc.ws.on("message", (data) => {
      const f = JSON.parse(String(data)) as Frame;
      if (f.t !== "env") return;
      const t0 = this.sentAt.get(f.env as string);
      if (t0 !== undefined && !this.delivered.has(f.env as string)) {
        this.delivered.add(f.env as string);
        this.latencies.push(performance.now() - t0);
      }
      this.pendingAcks.push(f.rid as string);
    });
    // TestClient also queues every frame; the canary consumes them itself.
    this.ackTimer = setInterval(() => {
      bc.frames.length = 0;
      ac.frames.length = 0;
      if (this.pendingAcks.length > 0 && bc.ws.readyState === bc.ws.OPEN) {
        bc.send({ t: "ack", rids: this.pendingAcks.splice(0, 1024) });
      }
    }, 100);
  }

  /** Connects the pair from CANARY_IP (both users) and starts sending every `intervalMs`. */
  static async start(relay: RelayProcess, o: { intervalMs?: number; ip?: string } = {}): Promise<Canary> {
    const ip = o.ip ?? CANARY_IP;
    const a = newDevice(relay);
    const b = newDevice(relay);
    const bc = await authedFrom(relay, b, ip);
    const ac = await authedFrom(relay, a, ip);
    const cap = makeCap(b, relay.nowSec()).jws;
    const c = new Canary(relay, a, b, ac, bc, cap);
    void c.sendOne();
    c.timer = setInterval(() => void c.sendOne(), o.intervalMs ?? 200);
    return c;
  }

  private async sendOne(): Promise<void> {
    if (this.stopped) return;
    const f = sendFrame(this.a, this.b, { cap: this.cap });
    const env = f.env as string;
    this.inflight++;
    this.sentAt.set(env, performance.now());
    try {
      const reply = await this.ac.request(f);
      if (reply.t === "sent") this.accepted.add(env);
      else this.rejected.push(String(reply.code));
    } catch (e) {
      this.rejected.push(`no-reply: ${(e as Error).message}`);
    } finally {
      this.inflight--;
    }
  }

  /**
   * Keeps sending until at least `minSent` messages went out (so a fast test
   * still exercises the canary), then stops, waits (up to `waitMs`) for every
   * accepted message to arrive, and reports.
   */
  async stop(waitMs = 3000, minSent = 5): Promise<CanaryReport> {
    while (!this.stopped && this.sentAt.size < minSent) await new Promise((r) => setTimeout(r, 25));
    this.stopped = true;
    clearInterval(this.timer);
    const deadline = Date.now() + waitMs;
    while (Date.now() < deadline && (this.inflight > 0 || [...this.accepted].some((e) => !this.delivered.has(e)))) {
      await new Promise((r) => setTimeout(r, 25));
    }
    clearInterval(this.ackTimer);
    const lost = [...this.accepted].filter((e) => !this.delivered.has(e)).length;
    return {
      sent: this.sentAt.size,
      accepted: this.accepted.size,
      delivered: this.delivered.size,
      lost,
      rejected: tally(this.rejected),
      p50Ms: round(percentile(this.latencies, 50)),
      p99Ms: round(percentile(this.latencies, 99)),
      maxMs: round(Math.max(0, ...this.latencies)),
    };
  }

  close(): void {
    this.stopped = true;
    clearInterval(this.timer);
    clearInterval(this.ackTimer);
    this.ac.ws.terminate();
    this.bc.ws.terminate();
  }
}

export const round = (n: number, d = 1): number => Math.round(n * 10 ** d) / 10 ** d;
export const mib = (n: number): number => round(n / (1024 * 1024), 1);

// ---------------------------------------------------------------------------
// Sampler: RSS over the load phase, event-loop delay at the end

export class Sampler {
  maxRss = 0;
  startRss = 0;
  private timer?: NodeJS.Timeout;
  private busy = false;

  private constructor(readonly relay: RelayProcess) {}

  /** Resets the relay's delay histogram and starts polling RSS. */
  static async start(relay: RelayProcess): Promise<Sampler> {
    const s = new Sampler(relay);
    const first = await relay.stats({ reset: true });
    s.startRss = first.rssBytes;
    s.maxRss = first.rssBytes;
    s.timer = setInterval(() => {
      if (s.busy || !relay.alive()) return;
      s.busy = true;
      relay
        .stats()
        .then((st) => (s.maxRss = Math.max(s.maxRss, st.rssBytes)))
        .catch(() => {})
        .finally(() => (s.busy = false));
    }, 200);
    return s;
  }

  async stop(): Promise<DebugStats> {
    clearInterval(this.timer);
    const st = await this.relay.stats({ store: true });
    this.maxRss = Math.max(this.maxRss, st.rssBytes);
    return st;
  }
}

// ---------------------------------------------------------------------------
// Reporting and the shared assertions

export interface Measured {
  test: string;
  limits?: Record<string, number | string>;
  lagP99Ms?: number;
  lagMaxMs?: number;
  rssMiB?: number;
  rssGrowthMiB?: number;
  dbMiB?: number;
  canary?: CanaryReport;
  [k: string]: unknown;
}

/** One line per test on stdout, prefixed so the numbers can be grepped out of a run. */
export function report(m: Measured): void {
  console.log(`RESILIENCE ${JSON.stringify(m)}`);
}

export interface HealthInput {
  test: string;
  relay: RelayProcess;
  sampler: Sampler;
  canary?: Canary;
  limits?: Record<string, number | string>;
  /** Largest database the limits allow, before THRESHOLDS.dbOverheadBytes. */
  dbLimitBytes?: number;
  extra?: Record<string, unknown>;
  lagP99Ms?: number;
}

/**
 * Stops the sampler and canary, reports, then asserts: process up, healthz
 * 200, RSS and DB within bounds, event-loop delay p99 under the threshold,
 * and the canary lost nothing, was never refused and stayed fast.
 */
export async function assertHealthy(h: HealthInput): Promise<{ stats: DebugStats; canary?: CanaryReport }> {
  const canary = await h.canary?.stop();
  const alive = h.relay.alive();
  const stats = alive ? await h.sampler.stop() : undefined;
  const health = alive ? await h.relay.healthz() : 0;
  const db = h.relay.dbBytes();
  const m: Measured = {
    test: h.test,
    limits: h.limits,
    alive,
    healthz: health,
    lagP99Ms: stats?.lagMs ? round(stats.lagMs.p99) : undefined,
    lagMaxMs: stats?.lagMs ? round(stats.lagMs.max) : undefined,
    rssMiB: mib(h.sampler.maxRss),
    rssGrowthMiB: mib(h.sampler.maxRss - h.sampler.startRss),
    dbMiB: mib(db),
    storeBytes: stats?.store?.envelopeBytes,
    canary,
    ...h.extra,
  };
  report(m);
  expect(alive, `relay exited (${h.relay.exitCode ?? h.relay.exitSignal}):\n${h.relay.logs.slice(-20).join("\n")}`).toBe(true);
  expect(health).toBe(200);
  expect(h.sampler.maxRss).toBeLessThan(THRESHOLDS.rssMaxBytes);
  expect(h.sampler.maxRss - h.sampler.startRss).toBeLessThan(THRESHOLDS.rssGrowthBytes);
  if (h.dbLimitBytes !== undefined) expect(db).toBeLessThan(h.dbLimitBytes + THRESHOLDS.dbOverheadBytes);
  expect(stats?.lagMs?.p99 ?? Infinity).toBeLessThan(h.lagP99Ms ?? THRESHOLDS.lagP99Ms);
  if (canary) {
    expect(canary.rejected, "canary sends refused").toEqual({});
    expect(canary.accepted).toBeGreaterThan(0);
    expect(canary.lost, "canary messages lost").toBe(0);
    expect(canary.p99Ms).toBeLessThan(THRESHOLDS.canaryP99Ms);
    expect(canary.maxMs).toBeLessThan(THRESHOLDS.canaryMaxMs);
  }
  return { stats: stats!, canary };
}

/** Sends frames one at a time (each `request` waits for its reply) and tallies reply codes. */
export async function sendAll(c: TestClient, frames: Frame[]): Promise<Record<string, number>> {
  const codes: string[] = [];
  for (const f of frames) {
    const r = await c.request(f);
    codes.push(r.t === "error" ? String(r.code) : String(r.t));
  }
  return tally(codes);
}

/** Like sendAll, but pipelined: everything is written first, then the replies are collected. */
export async function sendPipelined(c: TestClient, frames: Frame[], timeoutMs = 10_000): Promise<Record<string, number>> {
  // ws drops sends on a closed socket silently; don't wait for replies that can't come.
  if (c.ws.readyState !== c.ws.OPEN) return { closed: frames.length };
  const replies = frames.map((f, i) => {
    const id = f.id ?? `p${i}-${Math.random().toString(36).slice(2)}`;
    const p = c.next((x) => x.id === id, timeoutMs);
    c.send({ ...f, id });
    return p.then(
      (r) => (r.t === "error" ? String(r.code) : String(r.t)),
      (e: Error) => `no-reply: ${e.message}`,
    );
  });
  return tally(await Promise.all(replies));
}

/** Collects `env` frames on `c` until none arrive for `quietMs`; acks them when `ack` is set. */
export async function collectEnvs(c: TestClient, o: { quietMs?: number; ack?: boolean } = {}): Promise<Frame[]> {
  const out: Frame[] = [];
  const quiet = o.quietMs ?? 300;
  let last = Date.now();
  for (;;) {
    await new Promise((r) => setTimeout(r, 25));
    const envs = c.frames.filter((f) => f.t === "env");
    if (envs.length > 0) {
      for (const e of envs) c.frames.splice(c.frames.indexOf(e), 1);
      out.push(...envs);
      last = Date.now();
      if (o.ack) c.send({ t: "ack", rids: envs.map((e) => e.rid as string) });
    } else if (Date.now() - last >= quiet) {
      return out;
    }
  }
}

/** Authenticates `device` from `ip` and returns everything in its mailbox. */
export async function drainMailbox(relay: RelayProcess, device: Device, ip: string, o: { ack?: boolean } = {}): Promise<string[]> {
  const c = await authedFrom(relay, device, ip);
  const envs = await collectEnvs(c, { ack: o.ack });
  if (o.ack) await new Promise((r) => setTimeout(r, 100));
  c.ws.terminate();
  return envs.map((e) => e.env as string);
}

/** Authenticates `device` once from `ip` and leaves, so the relay knows its mailbox. */
export async function register(relay: RelayProcess, device: Device, ip: string): Promise<void> {
  const c = await authedFrom(relay, device, ip);
  await c.close();
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Sends `frames` pipelined `batch` at a time. A capped send costs the relay
 * about 2 ms of CPU (FINDINGS.md F-2), so a deep pipeline from one socket is a
 * stall by itself; the limit tests keep batches small so they measure the
 * limit, not that.
 */
export async function sendBatched(c: TestClient, frames: Frame[], batch = 4): Promise<Record<string, number>> {
  const out: Record<string, number> = {};
  for (let i = 0; i < frames.length; i += batch) {
    for (const [k, v] of Object.entries(await sendPipelined(c, frames.slice(i, i + batch)))) out[k] = (out[k] ?? 0) + v;
  }
  return out;
}
