// Copyright 2026 Ix Infrastructure Inc.
//
// Sandbox by default: the agents' own sandboxes deny their commands read and write access to
// P2P_HOME (`~/.p2p`: the identity key, the person token, config.json's trust, the CLI's state).
// The CLI's gates (the widening and person-only ones, projects.ts) and the front ends' shell guards
// stop an agent that runs `p2p`; they can't stop one that reads the key files directly. The OS
// sandbox can.
//
//   - `p2p sandbox`: whether Claude Code's and Codex's sandboxes deny P2P_HOME (read-only).
//   - `p2p sandbox enable [--claude] [--codex] [--yes]`: adds the deny to the person's own config
//     (Claude Code's user settings.json, Codex's config.toml), asking about each agent on its own
//     after saying what changes, how to undo it and exactly what it writes (default Yes). Writes
//     only a file that still holds what was shown; backs it up beside itself (0600) first, writes
//     atomically, keeps everything else. `--yes` is refused on Windows (no process-tree check).
//   - `p2p setup` (at a terminal) and `p2p codex install --write` offer the same once; a "no" is
//     remembered per agent (config.json `sandboxDeclined`) and `p2p sandbox enable` asks again.
//   - `p2p doctor` reports both (doctor.ts), and the Claude Code mod tells the person once.
//
// Only the person changes these files, and only outside every agent's session: the front ends'
// token doesn't count here (an agent's front end changing its own sandbox is what this is
// about), and an unreadable process tree refuses (fail closed). An agent can still read this
// command's output; it never contains a settings file's contents, only what this edit adds.
//
// What each sandbox enforces (docs/security/threat-model.md has the sources):
//   - Claude Code: `sandbox.filesystem.denyRead|denyWrite` are enforced by the OS (Seatbelt on
//     macOS, bubblewrap on Linux and WSL2) on Bash commands and every process they start; native
//     Windows has no sandbox. The built-in file tools (Read, Edit, Grep, Glob) follow permission
//     rules instead, hence `Read(…)`/`Edit(…)` deny rules too. Hooks, MCP servers and processes a
//     mod starts run outside the sandbox, so the mod's own `p2p` runs keep working.
//   - Codex: a permissions profile's `"deny"` entry, enforced by the OS on the commands Codex runs
//     (codex-bridge sandbox.ts). MCP servers and hooks aren't sandboxed by it, so the bridge keeps
//     working.

import { randomBytes } from "node:crypto";
import { closeSync, constants, existsSync, fstatSync, mkdirSync, openSync, readSync, realpathSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, normalize, resolve, sep } from "node:path";
import * as codex from "@peer2peer/codex-bridge";
import { ancestryUnknown, ancestryWhy } from "./ancestry.js";
import { readFileConfig, resolveHome, setFileConfigField, type Env, type FileConfig } from "./config.js";
import { CliError } from "./errors.js";
import type { App } from "./app.js";
import { agentContext, sessionWorkdir } from "./projects.js";

/** The person's home folder, as the agents expand `~` (HOME, USERPROFILE on Windows). */
export function userHomeOf(env: Env): string {
  return env.HOME?.trim() || env.USERPROFILE?.trim() || homedir();
}

/** P2P_HOME, absolute, and its real path when that differs (a symbolic link on the way). */
export function p2pHomePaths(env: Env): { home: string; real?: string } {
  const home = normalize(resolve(resolveHome(env)));
  try {
    const real = realpathSync(home);
    return real !== home ? { home, real } : { home };
  } catch {
    return { home };
  }
}

/** Whether `path` is `root` or inside it (normalized; case-insensitive on macOS and Windows). */
function within(path: string, root: string): boolean {
  const caseless = process.platform === "darwin" || process.platform === "win32";
  const a = caseless ? path.toLowerCase() : path;
  const b = caseless ? root.toLowerCase() : root;
  const r = b.endsWith(sep) ? b : b + sep;
  return a === b || a.startsWith(r);
}

/** `~/…` for a path under the home folder, else the path itself. */
function tildeForm(abs: string, userHome: string): string {
  const h = normalize(resolve(userHome));
  return abs.startsWith(h + sep) ? `~/${abs.slice(h.length + 1).split(sep).join("/")}` : abs;
}

// ── Claude Code ─────────────────────────────────────────────────────────────

/** Claude Code's user settings file: `$CLAUDE_CONFIG_DIR/settings.json`, else `~/.claude/settings.json`. */
export function claudeSettingsPath(env: Env): string {
  const dir = env.CLAUDE_CONFIG_DIR?.trim();
  return join(dir ? resolve(dir) : join(userHomeOf(env), ".claude"), "settings.json");
}

/** Managed settings (what an organization deploys): read for the status only, never written. */
export function claudeManagedPath(platform: NodeJS.Platform = process.platform): string | undefined {
  if (platform === "darwin") return "/Library/Application Support/ClaudeCode/managed-settings.json";
  if (platform === "linux") return "/etc/claude-code/managed-settings.json";
  return undefined;
}

/** What Claude Code's settings should hold for P2P_HOME: the sandbox paths, and the file tools' rules. */
export function claudeWanted(paths: { home: string; real?: string }, userHome: string): { sandbox: string[]; read: string[]; edit: string[] } {
  const homes = [paths.home, ...(paths.real ? [paths.real] : [])];
  const sandbox = homes.map((h) => tildeForm(h, userHome));
  // Permission rules: `~/x` from the home folder, `//abs` for an absolute path.
  const rule = (h: string) => {
    const t = tildeForm(h, userHome);
    return t.startsWith("~/") ? `${t}/**` : `/${h.split(sep).join("/")}/**`;
  };
  return { sandbox, read: homes.map((h) => `Read(${rule(h)})`), edit: homes.map((h) => `Edit(${rule(h)})`) };
}

/** `s` without its trailing slashes and backslashes (a loop: no regular expression on settings text). */
function trimSlashes(s: string): string {
  let end = s.length;
  while (end > 1 && (s[end - 1] === "/" || s[end - 1] === "\\")) end--;
  return s.slice(0, end);
}

/**
 * A sandbox path entry as an absolute path (`~/x`, `/x`, `//x`), or undefined for a relative one.
 * `base` resolves a relative entry (a project's settings resolve it against the project root).
 */
function sandboxPath(entry: string, userHome: string, base?: string): string | undefined {
  const e = trimSlashes(entry.trim());
  if (e === "~") return normalize(userHome);
  if (e.startsWith("~/")) return normalize(join(userHome, e.slice(2)));
  if (e.startsWith("//")) return normalize(e.slice(1));
  if (isAbsolute(e)) return normalize(e);
  return base && e !== "" ? normalize(resolve(base, e)) : undefined;
}

/** A `Read(…)`/`Edit(…)` rule's folder when it covers everything under it (`P` or `P/**`, no other glob), else undefined. */
function ruleFolder(rule: string, tool: "Read" | "Edit", userHome: string): string | undefined {
  if (!rule.startsWith(`${tool}(`) || !rule.endsWith(")")) return undefined;
  let p = rule.slice(tool.length + 1, -1).trim();
  if (p.endsWith("/**")) p = p.slice(0, -3);
  if (p === "" || /[*?[\]{}]/.test(p)) return undefined;
  if (p === "~") return normalize(userHome);
  if (p.startsWith("~/")) return normalize(join(userHome, p.slice(2)));
  if (p.startsWith("//")) return normalize(p.slice(1));
  return undefined;
}

type Json = Record<string, unknown>;
const obj = (v: unknown): Json | undefined => (typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Json) : undefined);
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

export interface ClaudeSandboxStatus {
  /** on: every piece is in place; off: something is missing; unknown: settings couldn't be read; unavailable: no sandbox on this platform. */
  state: "on" | "off" | "unknown" | "unavailable";
  detail: string;
  /** What is missing (each a settings key or rule). */
  missing: string[];
  /** Things that weaken it. */
  notes: string[];
  settings: string;
}

/** The most a config file read here may hold: anything bigger is treated as unreadable. */
export const MAX_CONFIG_BYTES = 1024 * 1024;

/**
 * Reads a config file safely, whoever put it there (a cloned repository's `.claude` or `.codex`):
 * opened non-blocking (a FIFO can't hang the read), it must be a regular file once a symbolic link
 * is followed (not a FIFO, a device such as /dev/zero, or a folder), and at most MAX_CONFIG_BYTES.
 * null when it doesn't exist; throws a CliError when it can't be read that way.
 */
export function readConfigFile(path: string): string | null {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new CliError("config", `${path} couldn't be read: ${(e as Error).message}`);
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new CliError("config", `${path} isn't a regular file, so it wasn't read`);
    if (st.size > MAX_CONFIG_BYTES) throw new CliError("config", `${path} is larger than ${MAX_CONFIG_BYTES} bytes, so it wasn't read`);
    const buf = Buffer.alloc(MAX_CONFIG_BYTES + 1);
    let n = 0;
    for (;;) {
      const r = readSync(fd, buf, n, buf.length - n, null);
      if (r === 0) break;
      n += r;
      if (n > MAX_CONFIG_BYTES) throw new CliError("config", `${path} is larger than ${MAX_CONFIG_BYTES} bytes, so it wasn't read`);
    }
    return buf.subarray(0, n).toString("utf8");
  } finally {
    closeSync(fd);
  }
}

/** Reads a JSON settings file: undefined when it doesn't exist, "bad" when it isn't a readable JSON object. */
function readJson(path: string | undefined): Json | undefined | "bad" {
  if (!path) return undefined;
  let text: string;
  try {
    const t = readConfigFile(path);
    if (t === null) return undefined;
    text = t;
  } catch {
    return "bad";
  }
  if (text.trim() === "") return {};
  try {
    return obj(JSON.parse(text)) ?? "bad";
  } catch {
    return "bad";
  }
}

/** The folders whose `.claude` settings a session here loads: its working directory and, in a git repository, the repository root. */
export function projectRoots(workdir: string): string[] {
  const out = [normalize(workdir)];
  let d = normalize(workdir);
  for (let i = 0; i < 64; i++) {
    if (existsSync(join(d, ".git"))) {
      if (!out.includes(d)) out.push(d);
      break;
    }
    const up = dirname(d);
    if (up === d) break;
    d = up;
  }
  return out;
}

/** Whether `name` is an executable file in one of PATH's absolute folders. */
function onPath(name: string, env: Env): boolean {
  for (const dir of (env.PATH ?? "").split(":")) {
    if (!dir || !isAbsolute(dir)) continue;
    try {
      if (statSync(join(dir, name)).isFile()) return true;
    } catch {
      // not here
    }
  }
  return false;
}

/**
 * Whether Claude Code's sandbox denies its commands (and its file tools) P2P_HOME: from the user,
 * managed and this folder's project settings (`.claude/settings.json` and `.claude/settings.local.json`
 * in the session's folder and its repository root), and, on Linux, whether bubblewrap is there.
 */
export function claudeSandboxStatus(env: Env, o: { platform?: NodeJS.Platform; managedPath?: string | null; workdir?: string } = {}): ClaudeSandboxStatus {
  const settings = claudeSettingsPath(env);
  const platform = o.platform ?? process.platform;
  const base = { settings, missing: [] as string[], notes: [] as string[] };
  if (platform === "win32") return { ...base, state: "unavailable", detail: "Claude Code has no sandbox on native Windows (it runs commands unsandboxed); use WSL2" };
  const problem = p2pHomeProblem(env);
  if (problem) return { ...base, state: "unknown", detail: problem };
  const user = readJson(settings);
  if (user === "bad") return { ...base, state: "unknown", detail: `${settings} isn't a JSON object, so it couldn't be read` };
  const managedFile = o.managedPath === null ? undefined : (o.managedPath ?? claudeManagedPath(platform));
  const managed = readJson(managedFile);
  // Project settings, highest first (local over shared, the session's folder over the repository root).
  const project: { file: string; root: string; doc: Json }[] = [];
  const unreadable: string[] = [];
  for (const root of projectRoots(o.workdir ?? sessionWorkdir(env))) {
    for (const name of ["settings.local.json", "settings.json"]) {
      const file = join(root, ".claude", name);
      if (file === settings) continue;
      const doc = readJson(file);
      if (doc === "bad") unreadable.push(file);
      else if (doc) project.push({ file, root, doc });
    }
  }
  const managedDoc = managed && managed !== "bad" ? managed : undefined;
  const userHome = userHomeOf(env);
  const want = claudeWanted(p2pHomePaths(env), userHome);
  const homes = want.sandbox.map((s) => sandboxPath(s, userHome) as string);
  const sb = (s: Json) => obj(s.sandbox) ?? {};
  const fs = (s: Json) => obj(sb(s).filesystem) ?? {};
  // Every source with the folder its relative paths resolve against.
  const sources: { doc: Json; base?: string; file?: string }[] = [
    ...(managedDoc ? [{ doc: managedDoc }] : []),
    ...project.map((p) => ({ doc: p.doc, base: p.root, file: p.file })),
    ...(user ? [{ doc: user, base: dirname(settings) }] : []),
  ];
  // Booleans: the highest source that sets one decides (managed, project local, project, user).
  const flag = (k: string): { value: unknown; file?: string } => {
    for (const src of sources) if (typeof sb(src.doc)[k] === "boolean") return { value: sb(src.doc)[k], ...(src.file ? { file: src.file } : {}) };
    return { value: undefined };
  };
  const deny = sources.flatMap((src) => strs(obj(src.doc.permissions)?.deny));
  const ruleCovers = (tool: "Read" | "Edit") => (h: string) =>
    deny.some((r) => {
      const p = ruleFolder(r, tool, userHome);
      return p !== undefined && within(h, p);
    });
  const covered = (key: "denyRead" | "denyWrite", tool: "Read" | "Edit") => (h: string) =>
    sources.some((src) =>
      strs(fs(src.doc)[key]).some((e) => {
        const p = sandboxPath(e, userHome, src.base);
        return p !== undefined && within(h, p);
      }),
    ) || ruleCovers(tool)(h);
  const missing: string[] = [];
  const enabled = flag("enabled");
  if (enabled.value !== true) missing.push(enabled.file ? `sandbox.enabled (${enabled.file} turns it off in this project)` : "sandbox.enabled");
  const retry = flag("allowUnsandboxedCommands");
  if (retry.value !== false) missing.push(retry.file ? `sandbox.allowUnsandboxedCommands = false (${retry.file} allows the retry in this project)` : "sandbox.allowUnsandboxedCommands = false");
  if (!homes.every(covered("denyRead", "Read"))) missing.push(`sandbox.filesystem.denyRead ${want.sandbox.join(", ")}`);
  if (!homes.every(covered("denyWrite", "Edit"))) missing.push(`sandbox.filesystem.denyWrite ${want.sandbox.join(", ")}`);
  if (!homes.every(ruleCovers("Read"))) missing.push(`permissions.deny ${want.read.join(", ")}`);
  if (!homes.every(ruleCovers("Edit"))) missing.push(`permissions.deny ${want.edit.join(", ")}`);
  const notes: string[] = [];
  // A narrower allow inside the denied folder opens it again ("the rule with the narrower path applies").
  for (const k of ["allowRead", "allowWrite"] as const) {
    for (const src of sources) {
      for (const e of strs(fs(src.doc)[k])) {
        const p = sandboxPath(e, userHome, src.base);
        if (p && homes.some((h) => within(p, h))) missing.push(`no sandbox.filesystem.${k} inside P2P_HOME (${e}${src.file ? ` in ${src.file}` : ""})`);
      }
    }
  }
  if (platform === "linux" && (!onPath("bwrap", env) || !onPath("socat", env))) {
    missing.push("bubblewrap and socat (Claude Code's sandbox needs both on Linux; without them it runs commands unsandboxed unless sandbox.failIfUnavailable is set)");
  }
  const excluded = sources.flatMap((src) => strs(sb(src.doc).excludedCommands));
  if (excluded.length > 0) notes.push(`sandbox.excludedCommands lists ${excluded.length} command pattern${excluded.length === 1 ? "" : "s"}: those run outside the sandbox, P2P_HOME included`);
  if (managed === "bad") notes.push(`${managedFile} couldn't be read`);
  for (const f of unreadable) notes.push(`${f} couldn't be read, so what it sets isn't known`);
  if (missing.length === 0 && unreadable.length > 0) {
    return { settings, missing, notes, state: "unknown", detail: `the user settings deny ${want.sandbox.join(" and ")}, but a project settings file here couldn't be read` };
  }
  if (missing.length === 0) return { settings, missing, notes, state: "on", detail: `Claude Code's sandbox denies its commands ${want.sandbox.join(" and ")}, and its file tools have deny rules for it` };
  return { settings, missing, notes, state: "off", detail: `Claude Code's sandbox doesn't keep its commands out of ${want.sandbox.join(" and ")}: missing ${missing.join("; ")}` };
}

/** The indentation a JSON text uses (its first indented line), else two spaces. */
function indentOf(text: string): string {
  // A loop, not a regular expression, over the person's file.
  for (const line of text.split("\n")) {
    let i = 0;
    while (i < line.length && (line[i] === " " || line[i] === "\t")) i++;
    if (i > 0 && (line[i] === '"' || line[i] === "}" || line[i] === "]")) return line.slice(0, i);
  }
  return "  ";
}

/** One change to settings.json, for the preview. */
export type JsonEdit = { key: string; value: unknown; was?: unknown; append?: boolean };

export type ClaudeSandboxPlan = { kind: "already" } | { kind: "edit"; after: string; edits: JsonEdit[] } | { kind: "manual"; reason: string };

/**
 * The edit to Claude Code's user settings (`text`, null when the file doesn't exist) that denies
 * P2P_HOME to its sandboxed commands and file tools, keeping every other key and the file's
 * indentation. Idempotent: entries already there (or a folder above P2P_HOME) aren't added again.
 */
export function planClaudeSandbox(text: string | null, env: Env): ClaudeSandboxPlan {
  let doc: Json = {};
  if (text !== null && text.trim() !== "") {
    let v: unknown;
    try {
      v = JSON.parse(text);
    } catch {
      return { kind: "manual", reason: "settings.json isn't valid JSON (Claude Code reads it as strict JSON): fix it first" };
    }
    const o = obj(v);
    if (!o) return { kind: "manual", reason: "settings.json doesn't hold a JSON object" };
    doc = o;
  }
  for (const [k, parent] of [["sandbox", doc], ["permissions", doc]] as const) {
    if (parent[k] !== undefined && !obj(parent[k])) return { kind: "manual", reason: `"${k}" in settings.json isn't an object` };
  }
  const sandbox = (doc.sandbox as Json | undefined) ?? {};
  if (sandbox.filesystem !== undefined && !obj(sandbox.filesystem)) return { kind: "manual", reason: `"sandbox.filesystem" in settings.json isn't an object` };
  const fs = (sandbox.filesystem as Json | undefined) ?? {};
  const permissions = (doc.permissions as Json | undefined) ?? {};
  for (const [k, v] of [["sandbox.filesystem.denyRead", fs.denyRead], ["sandbox.filesystem.denyWrite", fs.denyWrite], ["permissions.deny", permissions.deny]] as const) {
    if (v !== undefined && !Array.isArray(v)) return { kind: "manual", reason: `"${k}" in settings.json isn't a list` };
  }
  const userHome = userHomeOf(env);
  const want = claudeWanted(p2pHomePaths(env), userHome);
  const edits: JsonEdit[] = [];
  if (sandbox.enabled !== true) {
    edits.push({ key: "sandbox.enabled", value: true, ...(sandbox.enabled !== undefined ? { was: sandbox.enabled } : {}) });
    sandbox.enabled = true;
  }
  // Older Claude Code releases ran sandboxed commands without a prompt by default (before v2.1.324):
  // the person's own approvals stay, unless they set this themselves.
  if (sandbox.autoAllowBashIfSandboxed === undefined) {
    edits.push({ key: "sandbox.autoAllowBashIfSandboxed", value: false });
    sandbox.autoAllowBashIfSandboxed = false;
  }
  if (sandbox.allowUnsandboxedCommands !== false) {
    edits.push({ key: "sandbox.allowUnsandboxedCommands", value: false, ...(sandbox.allowUnsandboxedCommands !== undefined ? { was: sandbox.allowUnsandboxedCommands } : {}) });
    sandbox.allowUnsandboxedCommands = false;
  }
  const addPaths = (key: "denyRead" | "denyWrite") => {
    const list = strs(fs[key]);
    const cur = Array.isArray(fs[key]) ? (fs[key] as unknown[]) : [];
    for (const p of want.sandbox) {
      const abs = sandboxPath(p, userHome) as string;
      if (list.some((e) => {
        const q = sandboxPath(e, userHome);
        return q !== undefined && within(abs, q);
      })) continue;
      cur.push(p);
      edits.push({ key: `sandbox.filesystem.${key}`, value: p, append: true });
    }
    if (cur.length > 0) fs[key] = cur;
  };
  addPaths("denyRead");
  addPaths("denyWrite");
  const deny = Array.isArray(permissions.deny) ? (permissions.deny as unknown[]) : [];
  for (const [tool, rules] of [["Read", want.read], ["Edit", want.edit]] as const) {
    rules.forEach((r, i) => {
      const abs = sandboxPath(want.sandbox[i] as string, userHome) as string;
      if (strs(deny).some((e) => {
        const q = ruleFolder(e, tool, userHome);
        return q !== undefined && within(abs, q);
      })) return;
      deny.push(r);
      edits.push({ key: "permissions.deny", value: r, append: true });
    });
  }
  if (edits.length === 0) return { kind: "already" };
  if (Object.keys(fs).length > 0) sandbox.filesystem = fs;
  doc.sandbox = sandbox;
  if (deny.length > 0) doc.permissions = { ...permissions, deny };
  const after = `${JSON.stringify(doc, null, text ? indentOf(text) : 2)}\n`;
  return { kind: "edit", after, edits };
}

// ── both ────────────────────────────────────────────────────────────────────

export interface FrontPlan {
  front: "claude" | "codex";
  /** The file the edit writes. */
  path: string;
  /** Whether the agent looks installed (its config folder exists). */
  present: boolean;
  status: { state: string; detail: string; notes: string[] };
  plan:
    | { kind: "already" }
    | { kind: "edit"; before: string | null; after: string; preview: string[]; /** Codex: what the new profile extends. */ base?: string; /** Codex: the config set no sandbox, so the base was chosen. */ assumed?: true }
    | { kind: "manual"; reason: string; snippet?: string }
    | { kind: "unavailable" };
}

function readText(path: string): string | null {
  return readConfigFile(path);
}

const isDir = (p: string) => {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
};

/** The Codex home (CODEX_HOME, else ~/.codex) and its config.toml. */
export function codexConfigPath(env: Env): string {
  const h = env.CODEX_HOME?.trim();
  return join(h ? resolve(h) : join(userHomeOf(env), ".codex"), "config.toml");
}

/** The deny paths for Codex's config (`~/…` under the home folder). */
export function codexDenyPathsOf(env: Env): string[] {
  const p = p2pHomePaths(env);
  return codex.codexDenyPaths(p.home, userHomeOf(env), p.real);
}

/** Characters that mean something in a permission rule or a glob: a P2P_HOME holding one isn't written into a rule. */
const RULE_CHARS = new Set(["[", "]", "{", "}", "*", "?", "(", ")"]);

/**
 * Why P2P_HOME can't be denied safely, or undefined: a path with rule or glob characters (it would
 * match something else, or break the rule), or the home folder itself, `/` or a folder above the home
 * folder (denying it would lock the agents out of everything).
 */
export function p2pHomeProblem(env: Env): string | undefined {
  const paths = p2pHomePaths(env);
  const userHome = normalize(resolve(userHomeOf(env)));
  for (const h of [paths.home, ...(paths.real ? [paths.real] : [])]) {
    if ([...h].some((c) => RULE_CHARS.has(c))) return `P2P_HOME (${h}) has a character that means something in a sandbox rule ([ ] { } * ? ( )): move it to a plain path, then run this again`;
    if (h === sep || within(userHome, h)) return `P2P_HOME (${h}) is your home folder or a folder above it: denying it would shut your agents out of everything. Point P2P_HOME at its own folder`;
  }
  return undefined;
}

/** The project `.codex/config.toml` files Codex loads here when the project is trusted (repository root down to the folder). */
function codexProjectConfigs(workdir: string): string[] {
  const roots = projectRoots(workdir);
  const top = roots[roots.length - 1] as string;
  const out: string[] = [];
  let d = normalize(workdir);
  for (let i = 0; i < 64; i++) {
    const f = join(d, ".codex", "config.toml");
    if (existsSync(f)) out.push(f);
    if (d === top) break;
    const up = dirname(d);
    if (up === d) break;
    d = up;
  }
  return out;
}

export function codexStatus(env: Env, o: { workdir?: string } = {}): codex.CodexSandboxStatus & { settings: string } {
  const path = codexConfigPath(env);
  const problem = p2pHomeProblem(env);
  if (problem) return { state: "unknown", detail: problem, notes: [], settings: path };
  let text: string | null;
  try {
    text = readText(path);
  } catch {
    return { state: "unknown", detail: `${path} couldn't be read`, notes: [], settings: path };
  }
  const st = { ...codex.codexSandboxStatus(text, codexDenyPathsOf(env), userHomeOf(env)), settings: path };
  // A trusted project's own config.toml can choose another sandbox here; whether Codex trusts the
  // project isn't known from outside, so "on" becomes "?" when one does.
  const overriding: string[] = [];
  for (const f of codexProjectConfigs(o.workdir ?? sessionWorkdir(env))) {
    if (f === path) continue;
    let t: string | null;
    try {
      t = readText(f);
    } catch {
      overriding.push(`${f} (unreadable)`);
      continue;
    }
    const lines = t === null ? [] : codex.scanTomlLines(t);
    if (lines === null) {
      overriding.push(`${f} (unreadable)`);
      continue;
    }
    if (lines.some((l) => l.kind === "kv" && (["sandbox_mode", "default_permissions", "permissions"].includes([...l.table, ...l.key][0] as string)))) overriding.push(f);
    else if (lines.some((l) => l.kind === "header" && l.table[0] === "permissions")) overriding.push(f);
  }
  if (overriding.length === 0) return st;
  const note = `${overriding.join(", ")} sets its own sandbox or permissions: when Codex trusts this project, that applies here instead`;
  return st.state === "on" ? { ...st, state: "unknown", detail: `${st.detail}, but a project config may override it here`, notes: [...st.notes, note] } : { ...st, notes: [...st.notes, note] };
}

const show = (v: unknown) => JSON.stringify(v);

export interface PlanOptions {
  platform?: NodeJS.Platform;
  managedPath?: string | null;
  workdir?: string;
  /** For a Codex config that sets no sandbox at all: what the new profile extends (default :read-only). */
  codexBase?: ":read-only" | ":workspace";
}

/** What `enable` would do for one front end (computed, nothing written). */
export function planFront(front: "claude" | "codex", env: Env, o: PlanOptions = {}): FrontPlan {
  const path = front === "claude" ? claudeSettingsPath(env) : codexConfigPath(env);
  const present = isDir(dirname(path));
  const problem = p2pHomeProblem(env);
  if (front === "claude") {
    const status = claudeSandboxStatus(env, o);
    if (status.state === "unavailable") return { front, path, present, status, plan: { kind: "unavailable" } };
    if (problem) return { front, path, present, status, plan: { kind: "manual", reason: problem } };
    let before: string | null;
    try {
      before = readText(path);
    } catch (e) {
      return { front, path, present, status, plan: { kind: "manual", reason: (e as Error).message } };
    }
    const p = planClaudeSandbox(before, env);
    if (p.kind !== "edit") return { front, path, present, status, plan: p };
    const preview = p.edits.map((e) => (e.append ? `  ${e.key} += ${show(e.value)}` : `  ${e.key} = ${show(e.value)}${e.was !== undefined ? `   (was ${show(e.was)})` : ""}`));
    return { front, path, present, status, plan: { kind: "edit", before, after: p.after, preview } };
  }
  const status = codexStatus(env, o);
  if (problem) return { front, path, present, status, plan: { kind: "manual", reason: problem } };
  let before: string | null;
  try {
    before = readText(path);
  } catch (e) {
    return { front, path, present, status, plan: { kind: "manual", reason: (e as Error).message } };
  }
  const p = codex.planCodexSandbox(before, codexDenyPathsOf(env), userHomeOf(env), o.codexBase ? { baseWhenUnset: o.codexBase } : {});
  if (p.kind === "already") return { front, path, present, status, plan: { kind: "already" } };
  if (p.kind === "manual") return { front, path, present, status, plan: { kind: "manual", reason: p.reason, snippet: p.snippet } };
  const preview = p.edits.map((e) => ("add" in e ? `  + ${e.add}` : `  - ${e.before}\n  + ${e.after}`));
  return { front, path, present, status, plan: { kind: "edit", before, after: p.after, preview, ...(p.base ? { base: p.base } : {}), ...(p.assumed ? { assumed: true as const } : {}) } };
}

/** The name the person knows each front end's agent by. */
export const AGENT_NAME: Record<"claude" | "codex", string> = { claude: "Claude Code", codex: "Codex" };

/** What one agent's edit does, in full, then the exact lines: asked about on its own. */
export function frontPreview(f: FrontPlan, p2pHome: string, userHome: string): string {
  if (f.plan.kind !== "edit") return "";
  const home = tildeForm(p2pHome, userHome);
  const why =
    f.front === "claude"
      ? [
          `Your agents run as you, so Claude Code can read ${home} (your identity key and person token) unless its`,
          "sandbox denies it. This adds that deny to your Claude Code user settings, and changes, in every project:",
          "  - Claude's shell commands run in Claude Code's sandbox: they write only inside the project (and folders",
          "    you add to sandbox.filesystem.allowWrite) and reach only network hosts you allow (Claude Code asks for",
          "    a new host). A build or tool that writes elsewhere (a global cache, say) may fail or ask.",
          "  - No retry outside the sandbox (allowUnsandboxedCommands: false): a command the sandbox blocks just fails.",
          "  - Your permission prompts stay as they are (autoAllowBashIfSandboxed: false, unless you set it already).",
          `  - Claude's shell and its Read/Edit tools can't open ${home}, so they can't run p2p any more either; Claude`,
          "    uses ListAgents, SendMessage and /peers. The Peer2Peer mod isn't affected (what a mod starts runs outside",
          "    the sandbox).",
          `  - To undo: put the backup back (${f.path}.p2p-backup-<time>), or remove the keys below.`,
        ]
      : [
          `Your agents run as you, so Codex can read ${home} (your identity key and person token) unless its sandbox`,
          "denies it. This has Codex's commands run under a permissions profile that denies it:",
          ...(f.plan.assumed
            ? [
                "  - Your config sets no sandbox, and Codex then picks one per folder (workspace-write in a version-controlled",
                `    folder, read-only elsewhere), which a profile can't. This one extends ${f.plan.base}${f.plan.base === ":read-only" ? ": Codex's commands can't write (it asks first under an on-request approval policy; under \"never\", a write just fails)" : ": Codex's commands write in the workspace, in every folder, including ones Codex hasn't trusted"}.`,
                `    ${f.plan.base === ":read-only" ? "`p2p sandbox enable --codex --codex-base workspace` lets them write in the workspace instead (in folders Codex hasn't trusted too)." : "`--codex-base read-only` keeps them read-only instead."}`,
              ]
            : ["  - It extends the sandbox you use now, so writes and network stay as they were."]),
          "  - Codex's shell can't open it, so it can't run p2p any more either; Codex uses the bridge's p2p_* tools.",
          "    The bridge isn't affected (Codex doesn't sandbox MCP servers or hooks). Restart open Codex sessions.",
          `  - To undo: put the backup back (${f.path}.p2p-backup-<time>), or remove the lines marked p2p sandbox.`,
        ];
  return [`${AGENT_NAME[f.front]}: ${f.path}`, ...why, "", "Exactly what is written (the file is backed up first; everything else in it stays):", ...f.plan.preview].join("\n");
}

/** The question for one agent. */
export function frontQuestion(f: FrontPlan): string {
  return f.front === "claude" ? "Turn on Claude Code's sandbox with this deny?" : "Add this to Codex's config?";
}

/**
 * Writes the planned edits. Each file must still hold what the preview was made from (else nothing
 * is written). The backup sits next to the path as named (a symbolic link's own folder, not its
 * target's), 0600, created exclusively; the new content is written atomically to the link's target,
 * keeping its mode.
 */
export function applyPlans(plans: readonly FrontPlan[], now: Date = new Date()): { path: string; backup?: string }[] {
  const changes = plans.flatMap((f) => (f.plan.kind === "edit" ? [{ path: f.path, before: f.plan.before, after: f.plan.after }] : []));
  for (const c of changes) {
    if (readText(c.path) !== c.before) throw new CliError("changed", `${c.path} changed after it was shown: nothing was written. Run the command again to see the changes`);
  }
  const stamp = now.toISOString().replace(/[:.]/g, "-");
  const done: { path: string; backup?: string }[] = [];
  for (const c of changes) {
    const target = codex.resolveLink(c.path);
    mkdirSync(dirname(target), { recursive: true });
    let backup: string | undefined;
    if (c.before !== null) {
      backup = `${c.path}.p2p-backup-${stamp}`;
      writeFileSync(backup, c.before, { mode: 0o600, flag: "wx" });
    }
    let mode = 0o600;
    try {
      mode = statSync(target).mode & 0o777;
    } catch {
      // a new file: 0600
    }
    const tmp = `${target}.p2p-tmp-${randomBytes(8).toString("hex")}`;
    rmSync(tmp, { force: true });
    writeFileSync(tmp, c.after, { mode, flag: "wx" });
    renameSync(tmp, target);
    done.push({ path: c.path, ...(backup ? { backup } : {}) });
  }
  return done;
}

/**
 * Only the person changes an agent's sandbox, at their own terminal, outside every agent's session:
 * never with a front end's token (that would be an agent's front end changing its own sandbox), and
 * never when the process tree can't be read (fail closed).
 */
export function assertPersonOutsideAgents(app: { env: Env; front?: boolean }, what: string): void {
  const why = `\`p2p ${what}\` changes your agents' sandbox, so only you run it, in your own terminal (not inside Claude Code or Codex)`;
  if (app.front === true) throw new CliError("refused", `${why}. A front end (the Claude Code mod, the Codex bridge) never changes its own agent's sandbox`);
  if (agentContext(app.env)) throw new CliError("refused", `${why}. It was refused here because it runs inside an agent's session`);
  if (ancestryUnknown()) throw new CliError("refused", `${why}. It was refused here because p2p couldn't read its process tree to tell whether it runs inside an agent's session${ancestryWhy() ? ` (${ancestryWhy()})` : ""}`);
}

type Front = "claude" | "codex";

/** Which agents the person said no for (FileConfig.sandboxDeclined: `true` for both, as an older answer, or a list). */
export function sandboxDeclined(file: Pick<FileConfig, "sandboxDeclined">, front?: Front): boolean {
  const v = file.sandboxDeclined;
  if (v === true) return true;
  if (!Array.isArray(v)) return false;
  return front ? v.includes(front) : v.length > 0;
}

/** Records the person's answer for one agent. */
export function setSandboxDeclined(home: string, front: Front, declined: boolean): void {
  let cur: Front[] = [];
  try {
    const v = readFileConfig(home).sandboxDeclined;
    cur = v === true ? ["claude", "codex"] : Array.isArray(v) ? v.filter((x): x is Front => x === "claude" || x === "codex") : [];
  } catch {
    // unreadable: start over
  }
  const next = declined ? [...new Set([...cur, front])] : cur.filter((f) => f !== front);
  setFileConfigField(home, "sandboxDeclined", next);
}

/** The front ends worth offering: installed here (their config folder exists), with an edit to make. */
export function offerablePlans(env: Env, only?: readonly Front[], o: PlanOptions = {}): FrontPlan[] {
  const fronts = only ?? (["claude", "codex"] as const);
  return fronts.map((f) => planFront(f, env, o)).filter((f) => (only ? true : f.present) && f.plan.kind === "edit");
}

/** Whether the person said no before, for `front` (any, without one); config.json unreadable counts as no answer. */
export function declinedHere(env: Env, front?: Front): boolean {
  try {
    return sandboxDeclined(readFileConfig(resolveHome(env)), front);
  } catch {
    return false;
  }
}

/** Whether a front end's config folder is here at all. */
export function frontPresent(front: "claude" | "codex", env: Env): boolean {
  return existsSync(dirname(front === "claude" ? claudeSettingsPath(env) : codexConfigPath(env)));
}

/**
 * The one-time notice a front end shows its person (never its model) when its agent's sandbox
 * doesn't deny P2P_HOME: the command to run in their own terminal. Undefined when the sandbox
 * already does, the person said no before, it was shown already (once per device and front end),
 * or the caller is neither the person's front end nor the person. An agent's shell without the token
 * can't use it up; one that already reads P2P_HOME (no sandbox yet) can take the token and can.
 */
export async function sandboxNotice(app: App, front: "claude" | "codex"): Promise<string | undefined> {
  if (app.front !== true && agentContext(app.env)) return undefined;
  if (declinedHere(app.env, front)) return undefined;
  const st = front === "claude" ? claudeSandboxStatus(app.env) : codexStatus(app.env);
  if (st.state !== "off") return undefined;
  const shown = await app.state.update("sandboxNotice", (cur) => (cur?.[front] !== undefined ? { result: false } : { next: { ...(cur ?? {}), [front]: Date.now() }, result: true }));
  if (!shown) return undefined;
  const agent = front === "claude" ? "Claude Code" : "Codex";
  return `${agent}'s sandbox doesn't keep its commands out of ${tildeForm(p2pHomePaths(app.env).home, userHomeOf(app.env))}, where your identity key and person token live. In your own terminal (not inside ${agent}), run \`p2p sandbox enable\`: it shows what it adds to your ${agent} config and asks first. \`p2p doctor\` shows the details.`;
}

export interface SandboxReport {
  p2pHome: string;
  /** The person said no to the offer before. */
  declined: boolean;
  claude: ClaudeSandboxStatus & { present: boolean };
  codex: codex.CodexSandboxStatus & { settings: string; present: boolean };
}

/** Both front ends' sandbox status (read-only; whoever asks). */
export function sandboxReport(env: Env, o: { platform?: NodeJS.Platform; managedPath?: string | null; workdir?: string } = {}): SandboxReport {
  return {
    p2pHome: p2pHomePaths(env).home,
    declined: declinedHere(env),
    claude: { ...claudeSandboxStatus(env, o), present: frontPresent("claude", env) },
    codex: { ...codexStatus(env, o), present: frontPresent("codex", env) },
  };
}

/** The fix, said to the person, or to an agent (which never runs it). */
export function sandboxFix(person: boolean): string {
  return person
    ? "run `p2p sandbox enable` in your own terminal (not inside Claude Code or Codex): it shows what it adds and asks first"
    : "`p2p sandbox enable`, run by the person in their own terminal (outside Claude Code and Codex): an agent never changes its own sandbox, so ask your user";
}

export function sandboxHuman(r: SandboxReport, person: boolean): string {
  const row = (name: string, s: { state: string; detail: string; notes: string[] }, present: boolean, path: string) => {
    if (!present && s.state !== "on") return [`${name}: not set up here (${path})`];
    const mark = s.state === "on" ? "✓" : s.state === "off" ? "✗" : "?";
    return [`${mark} ${name}: ${s.detail}`, ...s.notes.map((n) => `    note: ${n}`)];
  };
  const lines = [`P2P_HOME is ${r.p2pHome}.`, ...row("Claude Code", r.claude, r.claude.present, r.claude.settings), ...row("Codex", r.codex, r.codex.present, r.codex.settings)];
  const off = (r.claude.present && r.claude.state === "off") || (r.codex.present && r.codex.state === "off");
  if (off) lines.push("", `Fix: ${sandboxFix(person)}.${r.declined ? " (You said no when `p2p setup` offered it.)" : ""}`);
  return lines.join("\n");
}
