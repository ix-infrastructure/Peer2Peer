// Copyright 2026 Ix Infrastructure Inc.
//
// Integration harness: real in-process relays from packages/relay (real
// clock), and users as separate temp `P2P_HOME`s driven through the real CLI
// entry point (`main`), so argument parsing, JSON output and exit codes are
// exercised too.

import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createLogger, createRelayCrypto, makeConfig, MemoryStore, Relay } from "@peer2peer/relay";
import { App, type Io } from "../app.js";
import { main } from "../cli.js";
import type { Env } from "../config.js";

/** Writes a person token into `home` (as the CLI makes one) and returns it. */
export function personTokenFor(home: string): string {
  const t = randomBytes(32).toString("base64url");
  mkdirSync(join(home, "cli"), { recursive: true, mode: 0o700 });
  writeFileSync(join(home, "cli", "person.key"), t, { mode: 0o600 });
  return t;
}

export interface TestRelay {
  url: string;
  relay: Relay;
  port: number;
  close(): Promise<void>;
}

export async function startRelay(
  url: string,
  opts: { powBits?: number; limits?: Record<string, number>; now?: () => number; config?: { allow?: string[]; allowCircle?: string; inviteAdmitSec?: number } } = {},
): Promise<TestRelay> {
  const crypto = createRelayCrypto();
  const relay = new Relay({
    ...(opts.now ? { now: opts.now } : {}),
    config: makeConfig(crypto, { relayUrl: url, logLevel: "error", powBits: opts.powBits ?? 0, ...opts.config, ...(opts.limits ? { limits: opts.limits } : {}) }),
    store: new MemoryStore(),
    crypto,
    logger: createLogger({ level: "error", sink: () => {} }),
  });
  const port = await relay.listen();
  return { url, relay, port, close: () => relay.close() };
}

export interface RunResult {
  code: number;
  out: string;
  err: string;
  json: any;
}

export class User {
  readonly home: string;
  /** What this user's watches printed on stderr (diagnostics for failure messages). */
  readonly watchErr: string[] = [];
  constructor(
    readonly name: string,
    private readonly transport: Record<string, string>,
    readonly extraEnv: Env = {},
  ) {
    this.home = mkdtempSync(join(tmpdir(), `p2p-${name}-`));
    this.personToken = personTokenFor(this.home);
  }

  /**
   * The person token (projects.ts) the person's front end passes: these users act as the person. A
   * test about agents builds an env without it (and sets an agent's variables).
   */
  readonly personToken: string;

  get env(): Env {
    return {
      P2P_HOME: this.home,
      P2P_PERSON_TOKEN: this.personToken,
      P2P_RELAY_TRANSPORT: JSON.stringify(this.transport),
      P2P_DRAIN_QUIET_MS: "250",
      P2P_DRAIN_MAX_MS: "4000",
      P2P_DOC_REFRESH_SEC: "0",
      P2P_LINK_POLL_MS: "100",
      P2P_CONNECT_TIMEOUT_MS: "3000",
      ...this.extraEnv,
    };
  }

  io(lines: { out: string[]; err: string[] }, stdin?: string): Io {
    return {
      out: (s) => lines.out.push(s),
      err: (s) => lines.err.push(s),
      ...(stdin !== undefined ? { readStdin: async () => stdin } : {}),
    };
  }

  /**
   * Project boundaries (projects.ts): a session is private until the person shares its project.
   * Tests about something else share a session with `session roster <sid> --add|--circle`, or by
   * setting a default circle (which shared new sessions before project boundaries); with this on
   * (the default), the harness first shares the test's project (this process's folder) with the
   * same people or circle, as the person would with `p2p project share`. The project boundary
   * tests turn it off.
   */
  autoShareProject = true;

  /** Runs `p2p <args> --json` and parses the single JSON object. */
  async run(args: string[], opts: { stdin?: string; json?: boolean } = {}): Promise<RunResult> {
    if (this.autoShareProject && args[0] === "session" && args[1] === "roster") {
      const share: string[] = [];
      for (let i = 2; i < args.length; i++) {
        if (args[i] === "--add" && args[i + 1]) share.push("--person", args[++i]);
        else if (args[i].startsWith("--add=")) share.push("--person", args[i].slice("--add=".length));
        else if (args[i] === "--circle" && args[i + 1]) share.push(args[++i]);
      }
      if (share.length > 0) await this.run(["project", "share", "--add", ...share]);
    }
    if (this.autoShareProject && args[0] === "circle" && args[1] === "default" && args[2] && !args[2].startsWith("-")) {
      await this.run(["project", "share", "--add", args[2]]);
    }
    const lines = { out: [] as string[], err: [] as string[] };
    const argv = opts.json === false ? args : [...args, "--json"];
    const code = await main(argv, { env: this.env, io: this.io(lines, opts.stdin) });
    process.exitCode = 0;
    const out = lines.out.join("\n");
    let json: any;
    if (opts.json !== false) {
      try {
        json = JSON.parse(lines.out.at(-1) ?? "null");
      } catch {
        json = undefined;
      }
    }
    return { code, out, err: lines.err.join("\n"), json };
  }

  /** Shares this test's project (this process's folder) with circles (`c_…`) and friends, as the person would. */
  async share(...targets: string[]): Promise<void> {
    await this.ok(["project", "share", "--add", ...targets.flatMap((t) => (t.startsWith("c_") ? [t] : ["--person", t]))]);
  }

  /** Runs and expects success. */
  async ok(args: string[], opts: { stdin?: string } = {}): Promise<any> {
    const r = await this.run(args, opts);
    if (r.code !== 0) throw new Error(`${this.name}: p2p ${args.join(" ")} failed (${r.code}): ${r.out}\n${r.err}`);
    return r.json;
  }

  /** Runs `p2p watch --session <sid> --jsonl` for `ms`, and returns the parsed lines. */
  async watch(sid: string, ms: number): Promise<any[]> {
    const lines: string[] = [];
    const ctl = new AbortController();
    const out = { out: [] as string[], err: [] as string[] };
    const t = setTimeout(() => ctl.abort(), ms);
    const code = await main(["watch", "--session", sid, "--jsonl"], {
      env: this.env,
      io: this.io(out),
      signal: ctl.signal,
      writeLine: async (l) => {
        lines.push(l);
        return true;
      },
    });
    clearTimeout(t);
    process.exitCode = 0;
    this.watchErr.push(...out.err);
    if (code !== 0) throw new Error(`${this.name}: watch exited ${code}: ${out.err.join("\n")}`);
    return lines.map((l) => JSON.parse(l));
  }

  /**
   * Runs `p2p watch` in the background until `stop()`: this user as a running client, handling
   * what arrives (answering wants, …) for as long as that takes.
   */
  serve(sid: string): { stop: () => Promise<void> } {
    const ctl = new AbortController();
    const io: Io = { out: () => {}, err: (s) => this.watchErr.push(s) };
    const done = main(["watch", "--session", sid, "--jsonl"], { env: this.env, io, signal: ctl.signal, writeLine: async () => true }).then((code) => {
      process.exitCode = 0;
      if (code !== 0) this.watchErr.push(`(watch exited ${code})`);
    });
    return {
      stop: async () => {
        ctl.abort();
        await done;
      },
    };
  }

  /** An App on this home (for flows driven programmatically, e.g. linking). */
  async app(): Promise<App> {
    const lines = { out: [] as string[], err: [] as string[] };
    const app = new App({ env: this.env, io: this.io(lines) });
    // These users are their own front end (their token): an App made here speaks for their sessions.
    app.front = true;
    return app;
  }

  cleanup(): void {
    rmSync(this.home, { recursive: true, force: true });
  }
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Runs `side` over and over while `work` is pending, as a running client (the mod's `watch`) would
 * keep handling deliveries. Use it instead of "sleep, then run the other side once": that races
 * with how long `work` takes to get its envelope out (under load, longer than the sleep).
 * Whether `work` succeeds or fails, the `side` run in flight is waited for (bounded by
 * `sideTimeoutMs` each) before this settles, so no command of the other user outlives the test step.
 */
export async function alongside<T>(work: Promise<T>, side: () => Promise<unknown>, everyMs = 300, sideTimeoutMs = 20_000): Promise<T> {
  let done = false;
  const settled = work.then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error }),
  );
  void settled.then(() => {
    done = true;
  });
  const loop = (async () => {
    while (!done) {
      let t: NodeJS.Timeout | undefined;
      await Promise.race([side().catch(() => undefined), new Promise((r) => (t = setTimeout(r, sideTimeoutMs)))]);
      clearTimeout(t);
      if (!done) await sleep(everyMs);
    }
  })();
  const [r] = await Promise.all([settled, loop]);
  if (!r.ok) throw r.error;
  return r.value;
}
