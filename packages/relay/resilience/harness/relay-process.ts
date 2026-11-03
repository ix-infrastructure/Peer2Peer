// Copyright 2026 Ix Infrastructure Inc.
//
// A relay child process on 127.0.0.1 with a random port and a temp SQLite
// file. There is no way to point this at anything else: the URL is always
// built from the port the child reports over IPC.

import { fork, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BUILD_DIR } from "../global-setup.js";
import type { RelayLimits } from "../../src/config.js";
import { limitEnvName } from "../../src/config.js";
import { RELAY_URL } from "../../src/__tests__/helpers.js";

export interface DebugStats {
  lagMs: { p50: number; p99: number; max: number; mean: number; count: number } | null;
  rssBytes: number;
  heapUsedBytes: number;
  heapTotalBytes: number;
  externalBytes: number;
  arrayBuffersBytes: number;
  connections: number;
  unauthConnections: number;
  maps: { byMailbox: number; byIss: number; perIp: number; limiterKeys: Record<string, number> };
  links: { open: number; reservedBytes: number };
  storedBytes: number;
  store?: { envelopes: number; envelopeBytes: number; devices: number; identityDocs: number };
}

export interface RelayProcessOptions {
  limits?: Partial<RelayLimits>;
  /** Extra env (TRUST_PROXY, SWEEP_INTERVAL_SEC, POW_BITS, LOG_LEVEL...). Host/port vars are not overridable. */
  env?: Record<string, string>;
  /** Reuse an existing temp dir (restart tests). */
  dir?: string;
  /** Start the relay clock this far ahead of the wall clock. */
  clockOffsetMs?: number;
}

const CHILD = join(BUILD_DIR, "resilience", "child", "relay-child.js");
const FORCED = ["HOST", "PORT", "METRICS_HOST", "METRICS_PORT", "DEBUG_STATS", "DB_PATH", "RELAY_URL", "RELAY_CONFIG"];

export class RelayProcess {
  readonly exited: Promise<void>;
  private nextId = 1;
  private pending = new Map<number, (m: Record<string, unknown>) => void>();
  private ownsDir: boolean;

  private constructor(
    readonly child: ChildProcess,
    /** Every stdout/stderr line of the process, from its start. */
    readonly logs: string[],
    readonly port: number,
    readonly metricsPort: number,
    readonly dir: string,
    readonly opts: RelayProcessOptions,
    public clockOffsetMs: number,
    ownsDir: boolean,
    exited: Promise<void>,
  ) {
    this.ownsDir = ownsDir;
    this.exited = exited;
    child.on("message", (raw) => {
      const m = raw as Record<string, unknown>;
      if (m.t === "ack" && typeof m.id === "number") {
        this.pending.get(m.id)?.(m);
        this.pending.delete(m.id);
      }
    });
  }

  static async start(opts: RelayProcessOptions = {}): Promise<RelayProcess> {
    const ownsDir = opts.dir === undefined;
    const dir = opts.dir ?? mkdtempSync(join(tmpdir(), "relay-resilience-"));
    const env: Record<string, string> = {
      PATH: process.env.PATH ?? "",
      LOG_LEVEL: "warn",
      SWEEP_INTERVAL_SEC: "300",
    };
    for (const [k, v] of Object.entries(opts.limits ?? {})) env[limitEnvName(k as keyof RelayLimits)] = String(v);
    for (const [k, v] of Object.entries(opts.env ?? {})) {
      if (FORCED.includes(k)) throw new Error(`resilience harness: ${k} is fixed by the harness`);
      env[k] = v;
    }
    Object.assign(env, {
      HOST: "127.0.0.1",
      PORT: "0",
      METRICS_HOST: "127.0.0.1",
      METRICS_PORT: "0",
      DEBUG_STATS: "1",
      DB_PATH: join(dir, "relay.db"),
      RELAY_URL,
      RESILIENCE_CLOCK_OFFSET_MS: String(opts.clockOffsetMs ?? 0),
    });
    const child = fork(CHILD, [], { env, execArgv: [], stdio: ["ignore", "pipe", "pipe", "ipc"] });
    const logs: string[] = [];
    const collect = (buf: Buffer) => {
      for (const line of String(buf).split("\n")) if (line.trim()) logs.push(line);
    };
    child.stdout?.on("data", collect);
    child.stderr?.on("data", collect);
    const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
    const ready = await new Promise<{ port: number; metricsPort: number }>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`relay child did not start:\n${logs.join("\n")}`)), 15_000);
      child.on("message", (raw) => {
        const m = raw as Record<string, unknown>;
        if (m.t === "ready") {
          clearTimeout(timer);
          resolve({ port: Number(m.port), metricsPort: Number(m.metricsPort) });
        }
      });
      void exited.then(() => {
        clearTimeout(timer);
        reject(new Error(`relay child exited during start (${child.exitCode ?? child.signalCode}):\n${logs.join("\n")}`));
      });
    });
    return new RelayProcess(child, logs, ready.port, ready.metricsPort, dir, opts, opts.clockOffsetMs ?? 0, ownsDir, exited);
  }

  get exitCode(): number | null {
    return this.child.exitCode;
  }

  get exitSignal(): NodeJS.Signals | null {
    return this.child.signalCode;
  }

  get url(): string {
    return `ws://127.0.0.1:${this.port}/v3`;
  }

  get http(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  get dbPath(): string {
    return join(this.dir, "relay.db");
  }

  /** The relay's clock in seconds, for minting certs and docs it will accept. */
  nowSec(): number {
    return Math.floor((Date.now() + this.clockOffsetMs) / 1000);
  }

  alive(): boolean {
    return this.child.exitCode === null && this.child.signalCode === null;
  }

  private call(msg: Record<string, unknown>): Promise<Record<string, unknown>> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("relay child did not answer")), 30_000);
      this.pending.set(id, (m) => {
        clearTimeout(timer);
        resolve(m);
      });
      this.child.send({ ...msg, id });
    });
  }

  /** Moves the relay clock forward (rate-limit windows, link TTLs). */
  async advance(ms: number): Promise<void> {
    await this.call({ t: "advance", ms });
    this.clockOffsetMs += ms;
  }

  /** Runs one sweep now; resolves with its duration in ms as the child measured it. */
  async sweep(): Promise<number> {
    return Number((await this.call({ t: "sweep" })).ms);
  }

  async stats(o: { reset?: boolean; store?: boolean } = {}): Promise<DebugStats> {
    const q = new URLSearchParams();
    if (o.reset) q.set("reset", "1");
    if (o.store) q.set("store", "1");
    const res = await fetch(`http://127.0.0.1:${this.metricsPort}/debug/stats?${q}`);
    if (res.status !== 200) throw new Error(`/debug/stats ${res.status}`);
    return (await res.json()) as DebugStats;
  }

  /** GET /healthz from a given client IP (TRUST_PROXY must be on for `ip` to matter). */
  async healthz(ip = "203.0.113.250"): Promise<number> {
    try {
      const res = await fetch(`${this.http}/healthz`, { headers: { "x-forwarded-for": ip } });
      await res.arrayBuffer();
      return res.status;
    } catch {
      return 0;
    }
  }

  /** SQLite file + WAL + SHM on disk. */
  dbBytes(): number {
    let n = 0;
    for (const f of [this.dbPath, `${this.dbPath}-wal`, `${this.dbPath}-shm`]) if (existsSync(f)) n += statSync(f).size;
    return n;
  }

  errorLogs(): string[] {
    return this.logs.filter((l) => l.includes('"level":"error"') || (!l.startsWith("{") && /Error|error/.test(l)));
  }

  /** SIGTERM (graceful) or SIGKILL (crash); resolves once the process is gone. */
  async stop(signal: NodeJS.Signals = "SIGTERM"): Promise<void> {
    if (this.alive()) {
      this.child.kill(signal);
      const t = setTimeout(() => this.child.kill("SIGKILL"), 5000);
      await this.exited;
      clearTimeout(t);
    }
  }

  /** A new process on the same database and limits; the old one must be stopped. */
  async restart(): Promise<RelayProcess> {
    if (this.alive()) throw new Error("stop the relay before restarting it");
    const next = await RelayProcess.start({ ...this.opts, dir: this.dir, clockOffsetMs: this.clockOffsetMs });
    // The new process owns the temp dir now.
    next.ownsDir = this.ownsDir;
    this.ownsDir = false;
    return next;
  }

  async dispose(): Promise<void> {
    await this.stop("SIGKILL");
    if (this.ownsDir) rmSync(this.dir, { recursive: true, force: true });
  }
}
