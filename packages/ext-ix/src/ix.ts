// Copyright 2026 Ix Infrastructure Inc.
//
// Running the local Ix CLI (`ix`, or IX_BIN). Always by argv with no shell,
// with a timeout and an output cap; every argument that came from a peer has
// been validated against a strict pattern first (subgraph.ts), and never
// starts with "-", so it can't be read as an option.
//
// Commands this extension uses (Ix CLI 0.12; output shapes in SPEC.md §6):
//   ix --version                                   is Ix installed
//   ix impact <target> --format json [--kind k] [--path p] [--depth n] [--limit n]
//   ix around <path> --format json [--limit n]     callers / users / tests / importers of a file
//   ix --help                                      which `ix note` / `ix session` answer: OSS (local) or Ix Pro (cloud)
//   ix note --json show <id>                       read a note (OSS: the local backend; refused when Ix Pro answers)
//   ix note --tag=t [--session=s] [--actor=a] --json   < text   write a note (likewise)
//   ix session --json create <p2p-name> --purpose=p --actor=a --ttl=h   a session's record in the local graph (likewise)
//   ix overview <file> --format llm                resolve a subgraph: one file
//   ix inventory --kind file --path <prefix> --format llm --limit n    a directory
//   ix context <symbol> --format llm [--kind k] [--path p]             a symbol
//   ix subsystems --target <region> --format llm   an architecture region
//   ix status --format json [--root <dir>]          is a checkout mapped (footprint)
//   ix around <path>:<start>-<end> --format json    the definitions an edit touched, and their dependents (footprint)
//   ix overview <file> --format json               a file's key items (footprint, coarse fallback)

import { execFile } from "node:child_process";
import { IxExtError } from "./text.js";
import { delimiter, isAbsolute, resolve as resolvePath } from "node:path";
import { whichAbsolute } from "./which.js";

export interface IxResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface IxRunner {
  run(argv: readonly string[], opts?: { stdin?: string; timeoutMs?: number; cwd?: string }): Promise<IxResult>;
}

export const IX_TIMEOUT_MS = 30_000;
const MAX_OUTPUT = 8 * 1024 * 1024;

/** Lines the CLI prints about its own plugins, not about the request. */
const NOISE = /^ix: failed to load [^\n]*$/gm;

/**
 * Where an `ix` call may go: the graph target p2p's chokepoint gave (ExtContext.graphTarget,
 * packages/p2p/src/projects.ts graphTarget). Never taken from the environment.
 */
export type IxTarget = { kind: "local"; endpoint: string; why?: string } | { kind: "shared"; circle: string; endpoint: string; token?: string };

/** `s` without trailing slashes (a loop, not a regex: linear on any input). */
function trimSlashes(s: string): string {
  let n = s.length;
  while (n > 0 && s.charCodeAt(n - 1) === 47) n--;
  return s.slice(0, n);
}

/** Ix's own default backend (ix-cli DEFAULT_ENDPOINT). */
export const DEFAULT_IX_ENDPOINT = "http://localhost:8090";

/** http(s) to localhost, 127.0.0.0/8 or ::1, no credentials, query or fragment (as p2p's isLoopbackEndpoint). */
export function isLoopbackEndpoint(url: unknown): url is string {
  if (typeof url !== "string" || url.length > 512 || /[\s\0]/.test(url)) return false;
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if ((u.protocol !== "http:" && u.protocol !== "https:") || u.username || u.password || u.search || u.hash) return false;
  const h = u.hostname.toLowerCase();
  return h === "localhost" || h === "[::1]" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}

/** A loopback endpoint as `origin + pathname`, trailing slashes dropped; undefined when it isn't one. */
export function normalizeLoopbackEndpoint(url: unknown): string | undefined {
  if (!isLoopbackEndpoint(url)) return undefined;
  const u = new URL(url);
  return trimSlashes(u.origin + u.pathname);
}

/** A shared graph's endpoint as `origin + pathname`: https, off this machine, no credentials, query or fragment. */
export function normalizeSharedEndpoint(url: unknown): string | undefined {
  if (typeof url !== "string" || url.length > 512 || /[\s\0]/.test(url) || isLoopbackEndpoint(url)) return undefined;
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return undefined;
  }
  if (u.protocol !== "https:" || u.username || u.password || u.search || u.hash) return undefined;
  return trimSlashes(u.origin + u.pathname);
}

/**
 * The local target a library caller (or a p2p from before graph targets) gets: Ix's default
 * backend. Never from the environment (IX_ENDPOINT is exactly what an agent or a Pro login sets):
 * a person's other local port comes from p2p's config.json, through the host's target.
 */
export function localTarget(_env?: Record<string, string | undefined>): IxTarget {
  return { kind: "local", endpoint: DEFAULT_IX_ENDPOINT };
}

/**
 * A target as given, checked again here (a buggy or older host is not trusted with it): a local
 * one must name a loopback endpoint, a shared one an https endpoint off this machine. Anything else
 * is the default local target.
 */
export function checkedTarget(t: unknown): IxTarget {
  const x = t as Partial<{ kind: string; endpoint: unknown; circle: unknown; token: unknown; why: unknown }> | null;
  const lo = x && x.kind === "local" ? normalizeLoopbackEndpoint(x.endpoint) : undefined;
  if (lo) return { kind: "local", endpoint: lo, ...(typeof x!.why === "string" ? { why: x!.why } : {}) };
  const sh = x && x.kind === "shared" && typeof x.circle === "string" ? normalizeSharedEndpoint(x.endpoint) : undefined;
  if (sh) return { kind: "shared", circle: x!.circle as string, endpoint: sh, ...(typeof x!.token === "string" && /^[\x21-\x7e]{1,4096}$/.test(x!.token) ? { token: x!.token } : {}) };
  return { kind: "local", endpoint: DEFAULT_IX_ENDPOINT };
}

/**
 * What an `ix` child sees of the environment: these names only (case-insensitively, as on
 * Windows). No IX_ENDPOINT, IX_PAT, IX_ORG or any other IX_* cloud or login setting of the caller's
 * (Ix Pro's PAT mode is driven by the environment alone), no P2P_* (the person token), no
 * NODE_OPTIONS, proxies, LD_* or DYLD_*. IX_HOME (where Ix keeps its local state, the workspace
 * registry) and IX_TOKEN (the local backend's token, which Ix sends to a loopback endpoint only)
 * stay.
 */
export const IX_ENV_ALLOW: readonly string[] = ["PATH", "PATHEXT", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA", "SYSTEMROOT", "WINDIR", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "TZ", "TERM", "NO_COLOR", "IX_HOME", "IX_TOKEN"];

/**
 * The environment an `ix` call runs with: IX_ENV_ALLOW from `env`, then the target pinned:
 * IX_ENDPOINT is the target's endpoint (Ix reads it before config.yaml's `endpoint`, which Ix Pro
 * rewrites to the cloud cluster on `ix login`); a shared target's token, when it has one, goes as
 * IX_PAT; readers never start a background `ix map` (Ix Pro routes a map to the cloud whenever an
 * org session is active in config.yaml, whatever IX_ENDPOINT says); no update check.
 */
export function ixEnv(env: Record<string, string | undefined>, target: IxTarget): NodeJS.ProcessEnv {
  const allow = new Set(IX_ENV_ALLOW);
  const out: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(env)) if (typeof v === "string" && allow.has(k.toUpperCase())) out[k] = k.toUpperCase() === "PATH" ? absolutePath(v) : v;
  out.IX_ENDPOINT = target.endpoint;
  if (target.kind === "shared" && target.token) out.IX_PAT = target.token;
  out.IX_MAP_BACKGROUND_REFRESH = "0";
  out.IX_NO_UPDATE_CHECK = "1";
  return out;
}

/** PATH with its relative and empty entries dropped (they mean the current directory: a repository's own `node`). */
export function absolutePath(v: string, platform: NodeJS.Platform = process.platform): string {
  const sep = platform === "win32" ? ";" : delimiter;
  return v
    .split(sep)
    .filter((d) => {
      const x = d.trim().replace(/^"|"$/g, "");
      return x !== "" && (platform === "win32" ? /^(?:[A-Za-z]:[\\/]|\\\\)/.test(x) : isAbsolute(x));
    })
    .join(sep);
}

/** What one `ix` call is for its graph target: its argv and the folder it runs in. */
export interface IxCall {
  argv: readonly string[];
  cwd: string;
}

/** Resolves the target of one call. */
export type TargetFn = (call: IxCall) => Promise<IxTarget>;

/** At most this many paths one call names for its target (p2p refuses more: local). */
const MAX_CALL_PATHS = 32;

/**
 * The paths an `ix` call names, absolute: the folder it runs in, its positional target (a file, a
 * `file:start-end` range, a directory or a symbol, resolved against the cwd: a symbol only names
 * the cwd's project again), and the values of `--path` and `--root`. Every one's project is
 * intersected into the call's graph target, so a call can't reach past a private project it names.
 */
export function callPaths(call: IxCall): string[] {
  const out = [call.cwd];
  const add = (v: string | undefined) => {
    if (typeof v !== "string" || v === "" || v.startsWith("-")) return;
    const p = v.replace(/:\d{1,9}(?:-\d{1,9})?$/, "");
    out.push(isAbsolute(p) ? p : resolvePath(call.cwd, p));
  };
  const a = call.argv;
  if (a[0] && !a[0].startsWith("-")) add(a[1]);
  for (let i = 1; i < a.length; i++) {
    const m = /^--(path|root)(?:=(.*))?$/.exec(a[i]);
    if (!m) continue;
    add(m[2] !== undefined ? m[2] : a[++i]);
  }
  return [...new Set(out)].slice(0, MAX_CALL_PATHS);
}

/**
 * The `ix` subcommands ext-ix may run against a local target: reads of the local graph only. Ix
 * Pro's own commands (`ix note` writes and reads Ix-memory in the cloud, whatever IX_ENDPOINT says)
 * and `ix map` (routed to the cloud when an org session is active) are refused, so a private
 * project's content never reaches the cloud through ext-ix. The exceptions are the memory calls
 * (memoryCall): exact forms of `ix note` and `ix session`, allowed against a local target only and
 * only when the `ix` that answers is the OSS one (guardRunner, memorySupport).
 */
export const LOCAL_IX_COMMANDS: readonly string[] = ["--version", "impact", "around", "overview", "inventory", "context", "subsystems", "status"];

// ---------------------------------------------------------------------------
// Memory calls (epic #41 piece 2): OSS `ix note` and `ix session` against the local backend

/** Tags `ix note --tag` takes (the OSS CLI and Ix Pro accept the same four). */
const MEMORY_TAGS: readonly string[] = ["note", "finding", "decision", "reminder"];
/** An Ix note id (`ix note show <id>`): what --ix-note accepts. */
export const IX_NOTE_ID_RE = /^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$/;
/** An Ix session reference (`--session=`): a name or an id. */
export const IX_SESSION_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
/** The sessions ext-ix creates: `p2p-` and a session id (or its hash). */
export const IX_SESSION_NAME_RE = /^p2p-[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
/** `--actor=`: `p2p`, or `p2p:` and a Peer2Peer address. A label on the OSS backend, never an identity. */
export const IX_ACTOR_RE = /^p2p(?::[A-Za-z0-9._@-]{1,80})?$/;
/** Longest `--purpose=` ext-ix sends. */
export const MAX_PURPOSE = 200;
/** Longest session TTL ext-ix asks for, in hours (a year). */
export const MAX_TTL_HOURS = 8760;

export type MemoryCall = "help" | "note-create" | "note-show" | "session-create";

/** One line of printable text: no control or format characters, no line or paragraph separators. */
const isOneLine = (s: string) => !/[\p{Cc}\p{Cf}\u2028\u2029]/u.test(s);

/**
 * Which memory call `argv` is, when it is exactly one of the forms ext-ix runs; undefined for
 * anything else (another subcommand, an extra or repeated flag, a positional note text: the text
 * only ever goes on stdin, never into argv where `ps` shows it):
 *   ix --help                                                         which commands answer (memorySupport)
 *   ix note --json show <id>                                          read a note (--ix-note)
 *   ix note --tag=<t> [--session=<ref>] [--actor=<a>] --json          write a note, text on stdin
 *   ix session --json create <p2p-name> --purpose=<p> --actor=<a> --ttl=<h>   a session record
 */
export function memoryCall(argv: readonly string[]): MemoryCall | undefined {
  const a = argv;
  if (a.length === 1 && a[0] === "--help") return "help";
  if (a[0] === "note") {
    if (a.length === 4 && a[1] === "--json" && a[2] === "show" && IX_NOTE_ID_RE.test(a[3])) return "note-show";
    const seen = new Set<string>();
    for (const x of a.slice(1)) {
      const m = /^--(tag|session|actor)=(.*)$/s.exec(x);
      const key = x === "--json" ? "json" : m?.[1];
      if (key === undefined || seen.has(key)) return undefined;
      seen.add(key);
      if (key === "tag" && !MEMORY_TAGS.includes(m![2])) return undefined;
      if (key === "session" && !IX_SESSION_REF_RE.test(m![2])) return undefined;
      if (key === "actor" && !IX_ACTOR_RE.test(m![2])) return undefined;
    }
    return seen.has("json") && seen.has("tag") ? "note-create" : undefined;
  }
  if (a[0] === "session" && a.length === 7 && a[1] === "--json" && a[2] === "create" && IX_SESSION_NAME_RE.test(a[3])) {
    const purpose = /^--purpose=(.+)$/s.exec(a[4])?.[1];
    const actor = /^--actor=(.+)$/s.exec(a[5])?.[1];
    const ttl = /^--ttl=([1-9]\d{0,3})$/.exec(a[6])?.[1];
    if (purpose === undefined || [...purpose].length > MAX_PURPOSE || !isOneLine(purpose) || purpose.trim() !== purpose) return undefined;
    if (actor === undefined || !IX_ACTOR_RE.test(actor)) return undefined;
    if (ttl === undefined || Number(ttl) > MAX_TTL_HOURS) return undefined;
    return "session-create";
  }
  return undefined;
}

/** Calls that write to the backend: each must say on stderr that it went to the local backend. */
const WRITES: ReadonlySet<MemoryCall> = new Set(["note-create", "session-create"]);

/**
 * Which `ix note` / `ix session` this Ix has, from `ix --help` (the capability, never a trial write):
 *   - "oss": the OSS commands against the local backend (Ix after 0.13.0, ix-infrastructure/Ix#916).
 *     Ix registers them only when Ix Pro did not load, and lists them in a "Memory:" section of the
 *     help only then.
 *   - "pro": Ix Pro loaded (its "Pro:" section). Its `ix note` and `ix session` always go to the
 *     active cloud org, whatever IX_ENDPOINT says.
 *   - "none": neither (an Ix from before #916 without Pro, or not Ix at all).
 * Anything that isn't plainly the first is not it.
 */
export type MemorySupport = "oss" | "pro" | "none";

export function parseMemorySupport(help: string): MemorySupport {
  const lines = help.replace(/\u001b\[[0-9;]*m/g, "").split(/\r?\n/);
  if (lines.some((l) => /^Pro:\s*$/.test(l))) return "pro";
  const at = lines.findIndex((l) => /^Memory:\s*$/.test(l));
  if (at < 0) return "none";
  const section: string[] = [];
  for (const l of lines.slice(at + 1)) {
    if (!/^\s+\S/.test(l)) break;
    section.push(l);
  }
  const has = (name: string) => section.some((l) => new RegExp(`^\\s+${name}\\s`).test(l));
  return has("note") && has("session") ? "oss" : "none";
}

/** Why a memory call can't run with this Ix, for a person: what to do about it. */
export function memoryRefusal(support: Exclude<MemorySupport, "oss">, target: IxTarget): IxExtError {
  const where = target.kind === "local" && target.why ? ` (${target.why})` : "";
  if (support === "pro") {
    return new IxExtError("graph_target", `Ix Pro is installed, and its \`ix note\` and \`ix session\` write to your Ix cloud org whatever the endpoint; this graph is local only${where}, so Peer2Peer doesn't run them (\`p2p project show\` shows the graph)`, { ix: "pro" });
  }
  return new IxExtError("graph_target", `this Ix has no local \`ix note\` (it came after Ix 0.13.0, ix-infrastructure/Ix#916): upgrade Ix (\`ix upgrade\`), and Peer2Peer writes notes into your local graph${where}`, { ix: "upgrade" });
}

/** `ix --help` through `ix`, read as a MemorySupport; "none" when it fails. */
export async function memorySupport(ix: IxRunner): Promise<MemorySupport> {
  try {
    const r = await ix.run(["--help"], { timeoutMs: 15_000 });
    return r.code === 0 ? parseMemorySupport(r.stdout) : "none";
  } catch {
    return "none";
  }
}

/** Whether a write's stderr says it went to `endpoint`, the local backend (OSS `ix note`/`ix session` print `→ local backend <origin+path>`). */
export function confirmsLocalWrite(stderr: string, endpoint: string): boolean {
  const want = `→ local backend ${endpoint}`;
  return stderr
    .replace(/\u001b\[[0-9;]*m/g, "")
    .split(/\r?\n/)
    .some((l) => l.trim() === want);
}

/** The refusal for a command a target doesn't allow. */
export function refuseForTarget(argv: readonly string[], target: IxTarget): IxExtError | undefined {
  const cmd = argv[0] ?? "";
  if (LOCAL_IX_COMMANDS.includes(cmd)) return undefined;
  const memory = memoryCall(argv);
  if (memory === "help") return undefined;
  if (target.kind === "local") {
    if (memory !== undefined) return undefined;
    if (cmd === "note" || cmd === "session") {
      return new IxExtError("graph_target", `ext-ix runs only its own forms of \`ix ${cmd}\` (to the local graph${target.why ? `: ${target.why}` : ""}), not this one`);
    }
    return new IxExtError("graph_target", `\`ix ${cmd.slice(0, 40)}\` can reach Ix Pro's cloud, and this project's graph is local only${target.why ? ` (${target.why})` : ""}: Peer2Peer doesn't run it (\`p2p project show\` shows the graph)`);
  }
  if (cmd === "note" || cmd === "session") {
    // Graph memory (notes, sessions) goes to the local graph only: no shared graph takes it yet.
    return new IxExtError("graph_target", `ext-ix writes Ix notes and sessions to the local graph only, never to a shared graph (circle ${target.circle.slice(0, 64)})`);
  }
  return new IxExtError("graph_target", `ext-ix doesn't run \`ix ${cmd.slice(0, 40)}\` against a shared graph yet`);
}

/**
 * Wraps a runner so every call is checked against its target first (refuseForTarget). `cwd`: the
 * folder a call runs in when it names none. A memory call (`ix note`, `ix session`) also needs the
 * OSS commands (memorySupport, asked once per guard: a guard lives for one command or one batch),
 * and a write must then say on stderr that it went to the target's local endpoint, or it fails
 * with `ix_unconfirmed` (whatever answered was not the OSS command against that backend).
 */
export function guardRunner(inner: IxRunner, target: TargetFn | (() => Promise<IxTarget>), cwd: string = process.cwd()): IxRunner {
  let support: Promise<MemorySupport> | undefined;
  return {
    run: async (argv, o) => {
      const t = await (target as TargetFn)({ argv, cwd: o?.cwd ?? cwd });
      const refused = refuseForTarget(argv, t);
      if (refused) throw refused;
      const memory = memoryCall(argv);
      if (memory === undefined || memory === "help") return inner.run(argv, o);
      support ??= memorySupport(inner);
      const s = await support;
      if (s !== "oss") throw memoryRefusal(s, t);
      const r = await inner.run(argv, o);
      if (r.code === 0 && WRITES.has(memory) && !confirmsLocalWrite(r.stderr, t.endpoint)) {
        throw new IxExtError("ix_unconfirmed", `\`ix ${argv[0]}\` didn't say it wrote to the local backend (${t.endpoint}): Peer2Peer stops writing to Ix until it does (is Ix Pro installed now?)`);
      }
      return r;
    },
  };
}

export function ixRunner(opts: { env?: Record<string, string | undefined>; cwd?: string; target?: IxTarget | TargetFn } = {}): IxRunner {
  // The merged view is read for IX_BIN and PATH only; the child gets ixEnv's allowlist.
  const view = { ...process.env, ...opts.env } as Record<string, string | undefined>;
  const name = view.IX_BIN?.trim() || "ix";
  // Absolute, from PATH's absolute entries: never a program planted in the repo (cwd).
  const bin = whichAbsolute(name, view);
  const target = async (call: IxCall): Promise<IxTarget> => {
    const t = opts.target;
    if (t === undefined) return localTarget();
    try {
      return checkedTarget(typeof t === "function" ? await t(call) : t);
    } catch {
      return localTarget();
    }
  };
  return {
    run: (argv, o = {}) =>
      target({ argv, cwd: o.cwd ?? opts.cwd ?? process.cwd() }).then(
        (t) =>
          new Promise((resolve, reject) => {
            if (!bin) return reject(new IxExtError("ix_missing", `Ix isn't installed (no \`${name}\` on PATH): https://github.com/ix-infrastructure/Ix`));
            const child = execFile(
              bin,
              [...argv],
              { cwd: o.cwd ?? opts.cwd, env: ixEnv(view, t), timeout: o.timeoutMs ?? IX_TIMEOUT_MS, killSignal: "SIGKILL", maxBuffer: MAX_OUTPUT, windowsHide: true },
              (err, stdout, stderr) => {
                const e = err as (NodeJS.ErrnoException & { code?: unknown; killed?: boolean }) | null;
                if (e && e.code === "ENOENT") return reject(new IxExtError("ix_missing", `Ix isn't installed (no \`${bin}\` on PATH): https://github.com/ix-infrastructure/Ix`));
                if (e && e.killed) return reject(new IxExtError("ix_timeout", `ix ${argv[0] ?? ""} took longer than ${Math.round((o.timeoutMs ?? IX_TIMEOUT_MS) / 1000)} s`));
                const code = e ? (typeof e.code === "number" ? e.code : 1) : 0;
                resolve({ code, stdout: String(stdout), stderr: String(stderr).replace(NOISE, "").trim() });
              },
            );
            if (o.stdin !== undefined) child.stdin?.end(o.stdin);
            else child.stdin?.end();
          }),
      ),
  };
}

/** Whether `ix` runs at all (cached per runner). */
const availability = new WeakMap<IxRunner, Promise<boolean>>();
export function ixAvailable(ix: IxRunner): Promise<boolean> {
  let p = availability.get(ix);
  if (!p) {
    p = ix.run(["--version"], { timeoutMs: 10_000 }).then(
      (r) => r.code === 0,
      () => false,
    );
    availability.set(ix, p);
  }
  return p;
}

/** Runs and parses JSON output; a failure is an IxExtError naming the command. */
export async function ixJson(ix: IxRunner, argv: readonly string[]): Promise<unknown> {
  const r = await ix.run(argv);
  if (r.code !== 0) throw new IxExtError("ix_failed", `ix ${argv[0]} failed (exit ${r.code})${r.stderr ? `: ${r.stderr.slice(0, 300)}` : ""}`);
  try {
    return JSON.parse(r.stdout);
  } catch {
    throw new IxExtError("ix_failed", `ix ${argv[0]} didn't print JSON`);
  }
}
