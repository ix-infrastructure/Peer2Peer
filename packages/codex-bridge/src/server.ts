// Copyright 2026 Ix Infrastructure Inc.
//
// `p2p codex mcp`: the stdio MCP server Codex starts with each session. It
// hosts the session's Bridge (watcher, inbox, status), the local socket the
// hooks and the person's `p2p codex …` commands reach it on, and the MCP
// tools. stdout carries MCP only; diagnostics go to stderr (Codex logs it).

import { execFile, spawn } from "node:child_process";
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { childEnv, codexBinDirs, cwdPolicy, effectiveEnv, gitBinary, isHomeFolder, parentCwd, projectConfigDirsOf, safeBinary, safeExecEnv, userHome } from "./knobs.js";
import type { Readable, Writable } from "node:stream";
import { Bridge, type HookReport, type WatchRunner } from "./bridge.js";
import { consumeNonce, PersonGate, ttyWriter, type Nonce } from "./confirm.js";
import { descendsFromCodex, peerPid, removeEntry, readEntries, serve, socketPath, writeEntry, type Entry } from "./ipc.js";
import { firstLine, inert, type CodexMode } from "./lib.js";
import { RolloutReader } from "./trusted.js";
import { lineFeeder, McpServer } from "./mcp.js";
import { nodeExec, P2P } from "./p2p.js";
import { makeTools, refuseMutating, serverInstructions } from "./tools.js";

export const BRIDGE_VERSION = "0.1.0";

export type Env = Record<string, string | undefined>;

export function resolveHome(env: Env): string {
  const h = env.P2P_HOME?.trim();
  return h ? h : join(userHome(), ".p2p");
}

/** `p2p watch` as a child: stdout lines as they come; killed when `signal` aborts. */
export function childWatch(env: Env, extra: Env = {}): WatchRunner {
  return (argv, onLine, signal) =>
    new Promise((resolve, reject) => {
      const child = spawn(argv[0] as string, argv.slice(1), { env: childEnv(env, extra), stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
      let buf = "";
      let stderr = "";
      const kill = () => child.kill("SIGTERM");
      signal.addEventListener("abort", kill, { once: true });
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (chunk: string) => {
        buf += chunk;
        const parts = buf.split("\n");
        buf = parts.pop() ?? "";
        for (const line of parts) if (line.trim()) onLine(line);
      });
      child.stderr.on("data", (d) => (stderr = `${stderr}${String(d)}`.slice(-4_000)));
      child.on("error", (e) => {
        signal.removeEventListener("abort", kill);
        reject(e);
      });
      child.on("close", (code) => {
        signal.removeEventListener("abort", kill);
        resolve({ code, stderr });
      });
    });
}

/**
 * `git <args>` in `cwd`: git by absolute path, with a scrubbed environment
 * (no GIT_*, a fixed system PATH) and no fsmonitor, so neither the
 * server's env (which a project config can set) nor the repo picks what
 * runs. Its trimmed stdout, or undefined.
 */
export function gitIn(git: string | undefined = gitBinary()) {
  return (cwd: string, args: readonly string[]): Promise<string | undefined> =>
    new Promise((resolve) => {
      if (!git) return resolve(undefined);
      execFile(git, ["-c", "core.fsmonitor=false", ...args], { cwd, env: safeExecEnv(), timeout: 5_000 }, (err, stdout) => resolve(err ? undefined : String(stdout).trim() || undefined));
    });
}

/**
 * `codex queue --thread <id> --message <text>` (opt-in, P2P_CODEX_QUEUE=1):
 * P2P_CODEX_BIN when it is an absolute path, else `codex` from the usual
 * install folders, never through the env's PATH. Its PATH is the node
 * running this server plus the system folders (an npm-installed `codex` is
 * a node script). Undefined (no queueing) when there is no such binary.
 */
export function codexQueue(env: Env, log?: (line: string) => void) {
  const given = env.P2P_CODEX_BIN?.trim();
  const bin = given && isAbsolute(given) ? given : safeBinary("codex", codexBinDirs());
  if (!bin) {
    if (env.P2P_CODEX_QUEUE === "1") log?.("P2P_CODEX_QUEUE is on but no codex binary was found by absolute path: set P2P_CODEX_BIN to its full path in [mcp_servers.peer2peer.env]");
    return undefined;
  }
  // codex queue also needs the Codex home the bridge settled on.
  const queueEnv = childEnv(env, { CODEX_HOME: env.CODEX_HOME });
  return (threadId: string, text: string): Promise<boolean> =>
    new Promise((resolve) => {
      execFile(bin, ["queue", "--thread", threadId, "--message", text], { env: queueEnv, timeout: 30_000 }, (err) => resolve(!err));
    });
}

/** A hook report off the socket, reduced to the fields and types the bridge reads. */
/**
 * The person token in `<P2P_HOME>/cli/person.key` (made here if the CLI hasn't yet): what lets the
 * CLI tell this bridge's runs from the model's own shell (packages/p2p/src/projects.ts). Codex's
 * sandbox may let a model's command read P2P_HOME: the token is then defence in depth only.
 */
export function personTokenOf(home: string | undefined): string | undefined {
  if (!home) return undefined;
  const f = join(home, "cli", "person.key");
  try {
    const t = readFileSync(f, "utf8").trim();
    if (/^[A-Za-z0-9_-]{43}$/.test(t)) return t;
  } catch {
    // none yet
  }
  try {
    mkdirSync(join(home, "cli"), { recursive: true, mode: 0o700 });
    const t = randomBytes(32).toString("base64url");
    writeFileSync(f, t, { mode: 0o600, flag: "wx" });
    return t;
  } catch {
    try {
      const t = readFileSync(f, "utf8").trim();
      return /^[A-Za-z0-9_-]{43}$/.test(t) ? t : undefined;
    } catch {
      return undefined;
    }
  }
}

export function sanitizeReport(raw: unknown): HookReport {
  const r = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
  const m = (typeof r.mode === "object" && r.mode !== null ? r.mode : {}) as Record<string, unknown>;
  const mode: CodexMode = {};
  if (typeof m.permissionMode === "string") mode.permissionMode = m.permissionMode;
  return {
    event: typeof r.event === "string" ? r.event : "",
    ...(typeof r.cwd === "string" && isAbsolute(r.cwd) ? { cwd: r.cwd } : {}),
    mode,
    ...(Array.isArray(r.files) ? { files: r.files.filter((f): f is string => typeof f === "string").slice(0, 50) } : {}),
    ...(Array.isArray(r.dirs) ? { dirs: r.dirs.filter((f): f is string => typeof f === "string" && isAbsolute(f) && f.length <= 4096).slice(0, 256) } : {}),
    // Only narrows: a report can make the session private, never the reverse.
    ...(r.over === true || (Array.isArray(r.dirs) && r.dirs.length > 256) ? { over: true } : {}),
    // Why (the CLI's OverWhy words), only alongside `over`: a word the CLI doesn't know counts as `front` there.
    ...(r.over === true || (Array.isArray(r.dirs) && r.dirs.length > 256)
      ? { overWhy: [...new Set([...(Array.isArray(r.overWhy) ? r.overWhy.filter((w): w is string => typeof w === "string" && /^[a-z]{1,16}$/.test(w)).slice(0, 8) : []), ...(Array.isArray(r.dirs) && r.dirs.length > 256 ? ["folders"] : [])])] }
      : {}),
  };
}

export interface McpOptions {
  /** The argv that runs this very `p2p` script (P2P_BIN from the user-level config replaces it). */
  bin: readonly string[];
  env: Env;
  stdin: Readable;
  stdout: Writable;
  stderr?: Writable;
  cwd?: string;
}

/** Serves MCP on stdin/stdout until stdin closes; then the final idle status and cleanup. */
export async function runMcpServer(o: McpOptions): Promise<void> {
  const log = (line: string) => o.stderr?.write(`[peer2peer] ${line}\n`);
  // Guarded settings from the user-level config only (a trusted repo's .codex/config.toml can add env here too).
  // The project: this server's cwd (which a project config can move) and Codex's own, each with its repo root.
  const cwd = o.cwd ?? process.cwd();
  const git = gitIn();
  const top = await git(cwd, ["rev-parse", "--show-toplevel"]);
  const codexCwd = await parentCwd();
  const codexTop = codexCwd ? await git(codexCwd, ["rev-parse", "--show-toplevel"]) : undefined;
  // A home folder that is itself a git repo (dotfiles) isn't a project root: the cwd subtree still is.
  const asRoot = (t: string | undefined) => (t && !isHomeFolder(t) ? t : undefined);
  const projectDirs = [...new Set([cwd, asRoot(top), codexCwd, asRoot(codexTop)].filter((d): d is string => !!d))];
  const projectConfigDirs = [...new Set([...projectConfigDirsOf(cwd, top), ...(codexCwd ? projectConfigDirsOf(codexCwd, codexTop) : [])])];
  const eff = await effectiveEnv({ env: o.env, projectDirs, projectConfigDirs });
  for (const w of eff.warnings) log(w);
  // Codex's own cwd confirms the project; a server cwd it didn't launch with must come from the user-level config.
  const cwdCheck = cwdPolicy({ serverCwd: cwd, codexCwd, configuredCwd: eff.serverCwd });
  if (cwdCheck.warning) log(cwdCheck.warning);
  const refusal = eff.refusal ?? cwdCheck.refusal;
  const env = eff.env;
  const home = eff.p2pHome;
  const p2pBin = env.P2P_BIN?.trim();
  if (p2pBin && !isAbsolute(p2pBin)) log(`ignored P2P_BIN=${p2pBin}: it must be an absolute path (never looked up through PATH)`);
  const bin = p2pBin && isAbsolute(p2pBin) ? [p2pBin] : o.bin;
  // The person token (projects.ts): this bridge speaks for the person's session, so its p2p runs pass it
  // (the session is registered, its sends are its own). The model's shell never has it.
  // Only `p2p` and `p2p watch` get it (`extra`); childEnv never passes one through (CHILD_P2P_DENY), so
  // `codex queue` and anything else this bridge runs can't.
  const token = personTokenOf(home);
  const front = token ? { P2P_PERSON_TOKEN: token } : {};
  // Every `p2p` child runs without project-settable node/loader variables (NODE_OPTIONS, DYLD_*, ...).
  const p2p = new P2P(nodeExec(childEnv(env, front)), bin);
  let entry: Entry | null = null;
  const bridge: Bridge = new Bridge({
    p2p,
    bin,
    // The long-lived watch never gets it: it needs none, and its environment is readable by others
    // running as this user (/proc/<pid>/environ on Linux).
    watch: childWatch(env),
    env,
    transcript: (threadId) => new RolloutReader(eff.codexHome, threadId),
    codexHome: eff.codexHome,
    settingsWarnings: eff.warnings,
    tmpdir: env.TMPDIR?.trim() || tmpdir(),
    p2pHome: home,
    projectDirs,
    ...(refusal ? { refusal } : {}),
    ...(cwdCheck.releaseRefusal ? { releaseRefusal: cwdCheck.releaseRefusal } : {}),
    git,
    cwd,
    board: async () => readEntries(home).filter((e) => e.pid !== process.pid).map((e) => ({ sid: e.sid, activeAt: e.activeAt })),
    ...((q) => (q ? { queue: q } : {}))(codexQueue(env, log)),
    log,
    onChange: () => {
      if (!entry) return;
      entry = { ...entry, sid: bridge.sid, ref: bridge.ref, cwd: bridge.cwd, label: bridge.label, activeAt: bridge.activeAt, ...(bridge.threadId ? { threadId: bridge.threadId } : {}) };
      try {
        writeEntry(home, entry);
      } catch {}
    },
  });

  // Releases and declines: the person only (see confirm.ts).
  const gate = new PersonGate({
    tty: ttyWriter(env.P2P_CODEX_CONFIRM_TTY),
    descends: (pid) => descendsFromCodex(pid, [process.ppid, process.pid]),
    reach: () => bridge.releaseReach(home),
    // Set only in Codex's config for this server (the model can't change it); tests raise it.
    ...(Number(env.P2P_CODEX_CONFIRM_RATE) > 0 ? { ratePerMinute: Number(env.P2P_CODEX_CONFIRM_RATE) } : {}),
    nonce: (op, id, n) => consumeNonce(home, op, id, n, Date.now()),
    now: () => Date.now(),
  });

  // The local socket: hooks, and the person's `p2p codex held|release|decline|sessions`.
  let ipc: Awaited<ReturnType<typeof serve>> | null = null;
  try {
    const sock = socketPath(home, process.pid);
    ipc = await serve(sock, async (req, conn) => {
      switch (req.op) {
        case "hook":
          // Untrusted (anything running as the user can send one): stricter only, see Bridge.onHook.
          return { ok: true, output: await bridge.onHook(sanitizeReport(req.report)) };
        case "held":
          // Metadata only: no message text over the socket.
          return { ok: true, session: bridge.describe(), held: bridge.heldList() };
        case "release":
        case "decline": {
          const op = req.op;
          const id = String(req.id ?? "");
          const item = bridge.heldItem(id);
          if (!item) return { ok: false, reason: "no held message with that id here" };
          // The sandbox's writable roots as Codex last recorded them.
          await bridge.refreshTrusted();
          const what = `the message from ${inert(item.from.address)} ("${firstLine(item.text, 100)}")`;
          const nonce = typeof req.nonce === "object" && req.nonce !== null ? (req.nonce as Nonce) : undefined;
          const gateAnswer = await gate.check(op, id, typeof req.code === "string" ? req.code : undefined, what, () => peerPid(conn), nonce);
          if (!gateAnswer.ok) return gateAnswer;
          return op === "release" ? bridge.release(id) : await bridge.decline(id);
        }
        case "info":
          return { ok: true, session: bridge.describe() };
        default:
          return { ok: false, reason: "unknown op" };
      }
    });
    entry = { v: 1, pid: process.pid, codexPid: process.ppid, sock, sid: bridge.sid, cwd: bridge.cwd, startedAt: Date.now(), activeAt: 0 };
    writeEntry(home, entry);
  } catch (e) {
    log(`no local socket (hooks and \`p2p codex held\` won't reach this session): ${String((e as Error)?.message ?? e)}`);
  }

  // Diagnostics only (the Codex smoke test): what Codex puts in each tool call's _meta.
  const metaLog = env.P2P_CODEX_META_LOG?.trim();
  const onMeta = metaLog ? (meta: unknown) => appendFileSync(metaLog, `${JSON.stringify(meta ?? null)}\n`, { mode: 0o600 }) : undefined;
  const server = new McpServer({ name: "peer2peer", version: BRIDGE_VERSION, instructions: serverInstructions() }, makeTools(bridge, onMeta), (line) => o.stdout.write(`${line}\n`), refuseMutating);
  void bridge.start().catch((e) => log(`start failed: ${String((e as Error)?.message ?? e)}`));

  const feeder = lineFeeder((line) => server.onLine(line));
  await new Promise<void>((resolve) => {
    o.stdin.setEncoding?.("utf8");
    o.stdin.on("data", (chunk) => feeder.push(String(chunk)));
    o.stdin.on("end", resolve);
    o.stdin.on("close", resolve);
    o.stdin.on("error", () => resolve());
  });
  await feeder.end();
  server.close();
  await bridge.close();
  if (entry) removeEntry(home, process.pid);
  ipc?.close();
}
