// Copyright 2026 Ix Infrastructure Inc.
//
// Shared by the integration and Codex smoke tests: an in-process relay, people
// as temporary P2P homes running the real `p2p` CLI, and a stdio MCP client.

import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { tempRoots, unsafeLocation } from "../knobs.js";
import { createLogger, createRelayCrypto, makeConfig, MemoryStore, Relay } from "@peer2peer/relay";

export const REPO = fileURLToPath(new URL("../../../../", import.meta.url));
export const P2P_JS = join(REPO, "packages/p2p/dist/bin.js");
export const RELAY = "wss://relay-codex.test/v3";
export const hasCli = existsSync(P2P_JS);

export type Json = Record<string, any>;

/**
 * A fresh folder outside every temp folder: the bridge never trusts a
 * CODEX_HOME or P2P_HOME in one (knobs.ts), so the homes the tests hand it
 * live under this package (or, when the checkout itself is in a temp
 * folder, under ~/.cache).
 */
export function safeTmp(prefix: string): string {
  const bases = [join(REPO, "packages/codex-bridge/.test-homes"), join(homedir(), ".cache", "p2p-codex-tests")];
  const base = bases.find((b) => unsafeLocation(b, { temp: tempRoots(), projectDirs: [] }) === undefined);
  if (!base) throw new Error("no folder outside the temp folders for the test homes");
  mkdirSync(base, { recursive: true, mode: 0o700 });
  return mkdtempSync(join(base, prefix));
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
export async function until<T>(what: string, fn: () => Promise<T | undefined> | T | undefined, ms = 30_000): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v !== undefined) return v;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await sleep(250);
  }
}

export class Person {
  private madeHome: string | undefined;
  userId = "";
  address = "";
  constructor(
    readonly name: string,
    private readonly port: () => number,
  ) {}
  /** Made on first use, so a skipped suite leaves no folder behind. */
  get home(): string {
    this.madeHome ??= safeTmp(`p2p-codex-${this.name}-`);
    return this.madeHome;
  }
  get env(): NodeJS.ProcessEnv {
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      P2P_HOME: this.home,
      P2P_DEFAULT_RELAYS: RELAY,
      P2P_RELAY_TRANSPORT: JSON.stringify({ [RELAY]: `ws://127.0.0.1:${this.port()}/v3` }),
      P2P_DRAIN_QUIET_MS: "250",
      P2P_DRAIN_MAX_MS: "4000",
      P2P_DOC_REFRESH_SEC: "0",
      P2P_CONNECT_TIMEOUT_MS: "3000",
    };
    for (const k of ["CODEX_THREAD_ID", "CODEX_SESSION_ID", "CODEX_HOME", "P2P_AUTO_DELIVER", "P2P_SHARE_STATUS", "P2P_BIN"]) delete env[k];
    return { ...env, ...this.extra };
  }
  /** Extra environment (e.g. this person's CODEX_HOME). */
  extra: NodeJS.ProcessEnv = {};
  /**
   * A user-level Codex config for this person: the bridge takes P2P_HOME, the
   * relay transport and the other guarded settings only from its
   * [mcp_servers.peer2peer.env] table.
   */
  codexConfig(extra: Record<string, string> = {}): string {
    const env = this.env;
    const table: Record<string, string> = { P2P_HOME: this.home, P2P_DEFAULT_RELAYS: env.P2P_DEFAULT_RELAYS as string, P2P_RELAY_TRANSPORT: env.P2P_RELAY_TRANSPORT as string, ...extra };
    return ["[mcp_servers.peer2peer.env]", ...Object.entries(table).map(([k, v]) => `${k} = ${JSON.stringify(v)}`)].join("\n") + "\n";
  }
  /**
   * `p2p <args> --json` as the person types it. Asynchronous: the relay runs
   * in this process, so a blocking child would starve it.
   */
  p2p(args: string[], stdin?: string): Promise<Json> {
    const dash = args.indexOf("--");
    const argv = dash < 0 ? [...args, "--json"] : [...args.slice(0, dash), "--json", ...args.slice(dash)];
    return run([P2P_JS, ...argv], this.env, stdin).then((r) => {
      try {
        return JSON.parse(r.stdout.trim().split("\n").pop() as string);
      } catch {
        throw new Error(`p2p ${args[0]} printed no JSON (exit ${r.code}): ${r.stderr}`);
      }
    });
  }
  /** `p2p codex hook <event>` as Codex runs it: the payload on stdin, JSON (or nothing) on stdout. */
  hook(event: string, payload: Json): Promise<string> {
    return run([P2P_JS, "codex", "hook", event], this.env, JSON.stringify(payload)).then((r) => r.stdout);
  }
}

export function run(args: string[], env: NodeJS.ProcessEnv, stdin?: string): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, { env, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), 60_000);
    child.stdout.on("data", (d) => (stdout += String(d)));
    child.stderr.on("data", (d) => (stderr += String(d)));
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
    child.stdin.end(stdin ?? "");
  });
}

/** A JSON-RPC client over the MCP server's stdio. */
export class McpClient {
  private buf = "";
  private id = 0;
  private waiting = new Map<number, (m: Json) => void>();
  stderr = "";
  constructor(readonly child: ChildProcess) {
    child.stdout!.setEncoding("utf8");
    child.stdout!.on("data", (chunk: string) => {
      this.buf += chunk;
      const lines = this.buf.split("\n");
      this.buf = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.trim()) continue;
        const m = JSON.parse(line);
        if (typeof m.id === "number" && this.waiting.has(m.id)) {
          this.waiting.get(m.id)!(m);
          this.waiting.delete(m.id);
        }
      }
    });
    child.stderr!.on("data", (d) => (this.stderr += String(d)));
  }
  request(method: string, params: Json = {}): Promise<Json> {
    const id = ++this.id;
    return new Promise((resolve) => {
      this.waiting.set(id, resolve);
      this.child.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }
  notify(method: string, params: Json = {}): void {
    this.child.stdin!.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
  }
  async tool(name: string, args: Json = {}, meta?: Json): Promise<{ text: string; isError: boolean }> {
    const r = await this.request("tools/call", { name, arguments: args, ...(meta ? { _meta: meta } : {}) });
    return { text: (r.result?.content ?? []).map((c: Json) => c.text).join("\n"), isError: r.result?.isError === true };
  }
}


/** An in-process relay from packages/relay. */
export async function startRelay(url = RELAY): Promise<{ relay: Relay; port: number }> {
  const crypto = createRelayCrypto();
  const relay = new Relay({ config: makeConfig(crypto, { relayUrl: url, logLevel: "error", powBits: 0 }), store: new MemoryStore(), crypto, logger: createLogger({ level: "error", sink: () => {} }) });
  return { relay, port: await relay.listen() };
}

/** Init both and make them friends with a short code, as people do. */
export async function befriend(a: Person, b: Person): Promise<void> {
  for (const p of [a, b]) {
    const r = await p.p2p(["init", `--name=${p.name}`, "--yes"]);
    if (typeof r.userId !== "string") throw new Error(`init failed: ${JSON.stringify(r)}`);
    Object.assign(p, { userId: r.userId, address: r.address });
  }
  const inv = await b.p2p(["invite"]);
  const joined = await a.p2p(["join", "--confirmed", "--", inv.code]);
  if (joined.error) throw new Error(`join failed: ${JSON.stringify(joined)}`);
  await until("both are friends", async () => {
    const x = (await a.p2p(["friends"])).friends?.some((f: Json) => f.userId === b.userId && f.canMessage);
    const y = (await b.p2p(["friends"])).friends?.some((f: Json) => f.userId === a.userId && f.canMessage);
    return x && y ? true : undefined;
  });
}

/** Collects `p2p watch --jsonl` lines. */
export function watchLines(child: ChildProcess, into: Json[]): void {
  let buf = "";
  child.stdout!.on("data", (d) => {
    buf += String(d);
    const lines = buf.split("\n");
    buf = lines.pop() ?? "";
    for (const l of lines) if (l.trim()) into.push(JSON.parse(l));
  });
}
