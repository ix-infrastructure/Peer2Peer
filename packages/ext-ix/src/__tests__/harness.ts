// Copyright 2026 Ix Infrastructure Inc.
//
// Integration harness for ext-ix: real in-process relays (packages/relay),
// users as separate temp P2P_HOMEs driven through the real `p2p` entry point
// (`main` of @peer2peer/cli), a fake `ix` on PATH, and a way to install
// ext-ix for one user only: a P2P_EXTENSION_PATH directory whose
// node_modules/@peer2peer/ext-ix links to this package, so `p2p` finds it
// with its ordinary dynamic loader.

import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createLogger, createRelayCrypto, makeConfig, MemoryStore, Relay } from "@peer2peer/relay";
import { main } from "@peer2peer/cli";

export const PKG = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
export const REPO = resolve(PKG, "../..");

const dirs: string[] = [];
export function tmp(prefix: string): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}
export function cleanupTmp(): void {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
}

/** Writes a person token into `home` (as the CLI makes one) and returns it. Pre-seeded on purpose: it stands in for the person's terminal "yes" (tests have no terminal); a fresh install's own creation is tested apart (mods/claude/peer2peer/integration/first-run.e2e.ts, the bridge's personTokenOf, the CLI's personToken). */
export function personTokenFor(home: string): string {
  const t = randomBytes(32).toString("base64url");
  mkdirSync(join(home, "cli"), { recursive: true, mode: 0o700 });
  writeFileSync(join(home, "cli", "person.key"), t, { mode: 0o600 });
  return t;
}

export interface TestRelay {
  url: string;
  port: number;
  close(): Promise<void>;
}

export async function startRelay(url: string): Promise<TestRelay> {
  const crypto = createRelayCrypto();
  const relay = new Relay({
    config: makeConfig(crypto, { relayUrl: url, logLevel: "error", powBits: 0 }),
    store: new MemoryStore(),
    crypto,
    logger: createLogger({ level: "error", sink: () => {} }),
  });
  const port = await relay.listen();
  return { url, port, close: () => relay.close() };
}

/** A directory that makes `p2p` find this package (P2P_EXTENSION_PATH). */
export function extensionDir(): string {
  // Installing is not enough: a user also enables it (P2P_EXTENSIONS=ix or `p2p extensions enable ix`).
  const d = tmp("p2p-ext-");
  mkdirSync(join(d, "node_modules", "@peer2peer"), { recursive: true });
  symlinkSync(PKG, join(d, "node_modules", "@peer2peer", "ext-ix"), "dir");
  return d;
}

// The fake `ix` (scripts/fake-ix.cjs, shared with the soak harness): logs every call; answers from files in FAKE_IX_DIR.
const FAKE_IX = readFileSync(join(PKG, "scripts", "fake-ix.cjs"), "utf8");

export interface FakeIx {
  bin: string;
  dir: string;
  set(name: string, content: unknown): void;
  calls(): { argv: string[]; stdin: string; cwd: string }[];
  written(): { argv: string[]; text: string }[];
  env(): Record<string, string>;
}

export function fakeIx(): FakeIx {
  const bin = tmp("fake-ix-bin-");
  const dir = tmp("fake-ix-data-");
  writeFileSync(join(bin, "ix"), FAKE_IX);
  chmodSync(join(bin, "ix"), 0o755);
  const lines = (n: string) => (existsSync(join(dir, n)) ? readFileSync(join(dir, n), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
  return {
    bin,
    dir,
    set: (name, content) => writeFileSync(join(dir, name), typeof content === "string" ? content : JSON.stringify(content)),
    calls: () => lines("calls.jsonl"),
    written: () => lines("notes-written.jsonl"),
    env: () => ({ PATH: `${bin}:${process.env.PATH ?? ""}`, FAKE_IX_DIR: dir, IX_HOME: dir }),
  };
}

/** A git checkout with an origin remote and one commit. */
export function gitRepo(remote: string): { root: string; rev: string } {
  const root = realpathSync(tmp("repo-"));
  const g = (...a: string[]) => execFileSync("git", a, { cwd: root, env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" } }).toString().trim();
  g("init", "-q", "-b", "main");
  g("remote", "add", "origin", remote);
  mkdirSync(join(root, "src", "auth"), { recursive: true });
  writeFileSync(join(root, "src", "auth", "token.ts"), "export const t = 1;\n");
  g("add", ".");
  g("-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "-m", "init");
  return { root, rev: g("rev-parse", "HEAD") };
}

export interface RunResult {
  code: number;
  out: string;
  err: string;
  json: any;
}

export class User {
  readonly home: string;
  constructor(
    readonly name: string,
    private readonly transport: Record<string, string>,
    readonly extraEnv: Record<string, string> = {},
  ) {
    this.home = tmp(`p2p-${name}-`);
    this.personToken = personTokenFor(this.home);
  }

  /** The person token (packages/p2p/src/projects.ts): these users act as the person. */
  readonly personToken: string;

  get env(): Record<string, string> {
    return {
      P2P_HOME: this.home,
      P2P_PERSON_TOKEN: this.personToken,
      P2P_RELAY_TRANSPORT: JSON.stringify(this.transport),
      P2P_DRAIN_QUIET_MS: "250",
      P2P_DRAIN_MAX_MS: "4000",
      P2P_DOC_REFRESH_SEC: "0",
      P2P_CONNECT_TIMEOUT_MS: "3000",
      ...this.extraEnv,
    };
  }

  /** Runs `p2p <args> --json` (in `cwd` when given) and parses the last JSON line. */
  /** Questions asked through the (simulated) terminal, for tests that answer prompts. */
  readonly asked: string[] = [];

  /**
   * Project boundaries (packages/p2p/src/projects.ts): a session is private until the person shares
   * its project, and these tests run commands in several folders (a repository, the process's own).
   * With this on (the default), sharing a session with `session roster <sid> --add|--circle` also
   * shares, as the person would with `p2p project share --add`, every folder this user runs p2p in.
   */
  autoShareProject = true;
  private shareTargets: string[] = [];
  private sharedDirs = new Set<string>();
  private usedDirs = new Set<string>();

  async run(args: string[], opts: { stdin?: string; json?: boolean; cwd?: string; answer?: string } = {}): Promise<RunResult> {
    if (this.autoShareProject && args[0] !== "project") {
      const dir = opts.cwd ?? process.cwd();
      this.usedDirs.add(dir);
      if (args[0] === "session" && args[1] === "roster") {
        for (let i = 2; i < args.length; i++) {
          if (args[i] === "--add" && args[i + 1]) this.shareTargets.push("--person", args[++i]);
          else if (args[i] === "--circle" && args[i + 1]) this.shareTargets.push(args[++i]);
        }
        this.sharedDirs.clear();
      }
      for (const d of this.shareTargets.length > 0 ? this.usedDirs : []) {
        if (this.sharedDirs.has(d)) continue;
        this.sharedDirs.add(d);
        await this.run(["project", "share", "--add", ...this.shareTargets], { cwd: d });
      }
    }
    const lines = { out: [] as string[], err: [] as string[] };
    const argv = opts.json === false ? args : [...args, "--json"];
    const before = process.cwd();
    if (opts.cwd) process.chdir(opts.cwd);
    let code: number;
    try {
      code = await main(argv, {
        env: this.env,
        io: {
          out: (s) => lines.out.push(s),
          err: (s) => lines.err.push(s),
          ...(opts.stdin !== undefined ? { readStdin: async () => opts.stdin! } : {}),
          // A person at a terminal: `answer` is typed at every prompt.
          ...(opts.answer !== undefined
            ? {
                prompt: async (q: string) => {
                  this.asked.push(q);
                  return opts.answer!;
                },
              }
            : {}),
        },
      });
    } finally {
      if (opts.cwd) process.chdir(before);
    }
    process.exitCode = 0;
    let json: any;
    try {
      json = JSON.parse(lines.out.at(-1) ?? "null");
    } catch {
      json = undefined;
    }
    return { code, out: lines.out.join("\n"), err: lines.err.join("\n"), json };
  }

  async ok(args: string[], opts: { stdin?: string; cwd?: string } = {}): Promise<any> {
    const r = await this.run(args, opts);
    if (r.code !== 0) throw new Error(`${this.name}: p2p ${args.join(" ")} failed (${r.code}): ${r.out}\n${r.err}`);
    return r.json;
  }

  /** `p2p watch --session <sid> --jsonl` for `ms`; the parsed lines (and the raw ones). */
  async watch(sid: string, ms: number): Promise<{ events: any[]; raw: string[] }> {
    const raw: string[] = [];
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), ms);
    const errs: string[] = [];
    const code = await main(["watch", "--session", sid, "--jsonl"], {
      env: this.env,
      io: { out: () => {}, err: (s) => errs.push(s) },
      signal: ctl.signal,
      writeLine: async (l) => {
        raw.push(l);
        return true;
      },
    });
    clearTimeout(t);
    process.exitCode = 0;
    if (code !== 0) throw new Error(`${this.name}: watch exited ${code}: ${errs.join("\n")}`);
    return { events: raw.map((l) => JSON.parse(l)), raw };
  }
}
