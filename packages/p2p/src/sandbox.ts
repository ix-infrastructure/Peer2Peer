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
//     (Claude Code's user settings.json, Codex's config.toml), after showing exactly what it writes
//     and asking (default Yes). Backs each file up first, writes atomically, keeps everything else.
//   - `p2p setup` (at a terminal) and `p2p codex install --write` offer the same once; a "no" is
//     remembered (config.json `sandboxDeclined`) and `p2p sandbox enable` asks again.
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

import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, normalize, resolve, sep } from "node:path";
import * as codex from "@peer2peer/codex-bridge";
import { ancestryUnknown, ancestryWhy } from "./ancestry.js";
import { readFileConfig, resolveHome, setFileConfigField, type Env, type FileConfig } from "./config.js";
import { CliError } from "./errors.js";
import type { App } from "./app.js";
import { agentContext } from "./projects.js";

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

/** A sandbox path entry as an absolute path (`~/x`, `/x`, `//x`), or undefined for a relative one. */
function sandboxPath(entry: string, userHome: string): string | undefined {
  const e = entry.trim().replace(/[\\/]+$/, "");
  if (e === "~") return normalize(userHome);
  if (e.startsWith("~/")) return normalize(join(userHome, e.slice(2)));
  if (e.startsWith("//")) return normalize(e.slice(1));
  if (isAbsolute(e)) return normalize(e);
  return undefined;
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

/** Reads a JSON settings file: undefined when it doesn't exist, "bad" when it isn't a JSON object. */
function readJson(path: string | undefined): Json | undefined | "bad" {
  if (!path) return undefined;
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "ENOENT" ? undefined : "bad";
  }
  if (text.trim() === "") return {};
  try {
    return obj(JSON.parse(text)) ?? "bad";
  } catch {
    return "bad";
  }
}

/** Whether Claude Code's sandbox denies its commands (and its file tools) P2P_HOME, from the user and managed settings. */
export function claudeSandboxStatus(env: Env, o: { platform?: NodeJS.Platform; managedPath?: string | null } = {}): ClaudeSandboxStatus {
  const settings = claudeSettingsPath(env);
  const platform = o.platform ?? process.platform;
  const base = { settings, missing: [] as string[], notes: [] as string[] };
  if (platform === "win32") return { ...base, state: "unavailable", detail: "Claude Code has no sandbox on native Windows (it runs commands unsandboxed); use WSL2" };
  const user = readJson(settings);
  if (user === "bad") return { ...base, state: "unknown", detail: `${settings} isn't a JSON object, so it couldn't be read` };
  const managedFile = o.managedPath === null ? undefined : (o.managedPath ?? claudeManagedPath(platform));
  const managed = readJson(managedFile);
  const sources = [user, managed === "bad" ? undefined : managed].filter((s): s is Json => s !== undefined);
  const userHome = userHomeOf(env);
  const want = claudeWanted(p2pHomePaths(env), userHome);
  const homes = want.sandbox.map((s) => sandboxPath(s, userHome) as string);
  const sb = (s: Json) => obj(s.sandbox) ?? {};
  const fs = (s: Json) => obj(sb(s).filesystem) ?? {};
  const managedSb = managed && managed !== "bad" ? sb(managed) : {};
  const flag = (k: string) => (typeof managedSb[k] === "boolean" ? managedSb[k] : user ? sb(user)[k] : undefined);
  const deny = sources.flatMap((s) => strs(obj(s.permissions)?.deny));
  const covered = (entries: string[], tool: "Read" | "Edit") => (h: string) =>
    entries.some((e) => {
      const p = sandboxPath(e, userHome);
      return p !== undefined && within(h, p);
    }) || deny.some((r) => {
      const p = ruleFolder(r, tool, userHome);
      return p !== undefined && within(h, p);
    });
  const missing: string[] = [];
  if (flag("enabled") !== true) missing.push("sandbox.enabled");
  if (flag("allowUnsandboxedCommands") !== false) missing.push("sandbox.allowUnsandboxedCommands = false");
  const denyRead = sources.flatMap((s) => strs(fs(s).denyRead));
  const denyWrite = sources.flatMap((s) => strs(fs(s).denyWrite));
  if (!homes.every(covered(denyRead, "Read"))) missing.push(`sandbox.filesystem.denyRead ${want.sandbox.join(", ")}`);
  if (!homes.every(covered(denyWrite, "Edit"))) missing.push(`sandbox.filesystem.denyWrite ${want.sandbox.join(", ")}`);
  const ruleCovers = (tool: "Read" | "Edit") => (h: string) => deny.some((r) => {
    const p = ruleFolder(r, tool, userHome);
    return p !== undefined && within(h, p);
  });
  if (!homes.every(ruleCovers("Read"))) missing.push(`permissions.deny ${want.read.join(", ")}`);
  if (!homes.every(ruleCovers("Edit"))) missing.push(`permissions.deny ${want.edit.join(", ")}`);
  const notes: string[] = [];
  // A narrower allow inside the denied folder opens it again ("the rule with the narrower path applies").
  for (const k of ["allowRead", "allowWrite"] as const) {
    for (const e of sources.flatMap((s) => strs(fs(s)[k]))) {
      const p = sandboxPath(e, userHome);
      if (p && homes.some((h) => within(p, h))) missing.push(`no sandbox.filesystem.${k} inside P2P_HOME (${e})`);
    }
  }
  const excluded = sources.flatMap((s) => strs(sb(s).excludedCommands));
  if (excluded.length > 0) notes.push(`sandbox.excludedCommands lists ${excluded.length} command pattern${excluded.length === 1 ? "" : "s"}: those run outside the sandbox, P2P_HOME included`);
  if (managed === "bad") notes.push(`${managedFile} couldn't be read`);
  if (missing.length === 0) return { settings, missing, notes, state: "on", detail: `Claude Code's sandbox denies its commands ${want.sandbox.join(" and ")}, and its file tools have deny rules for it` };
  return { settings, missing, notes, state: "off", detail: `Claude Code's sandbox doesn't keep its commands out of ${want.sandbox.join(" and ")}: missing ${missing.join("; ")}` };
}

/** The indentation a JSON text uses (its first indented line), else two spaces. */
function indentOf(text: string): string {
  const m = /\n([ \t]+)["}\]]/.exec(text);
  return m ? (m[1] as string) : "  ";
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
  plan: { kind: "already" } | { kind: "edit"; before: string | null; after: string; preview: string[] } | { kind: "manual"; reason: string; snippet?: string } | { kind: "unavailable" };
}

function readText(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new CliError("config", `${path} couldn't be read: ${(e as Error).message}`);
  }
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

export function codexStatus(env: Env): codex.CodexSandboxStatus & { settings: string } {
  const path = codexConfigPath(env);
  let text: string | null;
  try {
    text = readText(path);
  } catch {
    return { state: "unknown", detail: `${path} couldn't be read`, notes: [], settings: path };
  }
  return { ...codex.codexSandboxStatus(text, codexDenyPathsOf(env), userHomeOf(env)), settings: path };
}

const show = (v: unknown) => JSON.stringify(v);

/** What `enable` would do for one front end (computed, nothing written). */
export function planFront(front: "claude" | "codex", env: Env, o: { platform?: NodeJS.Platform; managedPath?: string | null } = {}): FrontPlan {
  if (front === "claude") {
    const path = claudeSettingsPath(env);
    const status = claudeSandboxStatus(env, o);
    const present = isDir(dirname(path));
    if (status.state === "unavailable") return { front, path, present, status, plan: { kind: "unavailable" } };
    const before = readText(path);
    const p = planClaudeSandbox(before, env);
    if (p.kind !== "edit") return { front, path, present, status, plan: p };
    const preview = p.edits.map((e) => (e.append ? `  ${e.key} += ${show(e.value)}` : `  ${e.key} = ${show(e.value)}${e.was !== undefined ? `   (was ${show(e.was)})` : ""}`));
    return { front, path, present, status, plan: { kind: "edit", before, after: p.after, preview } };
  }
  const path = codexConfigPath(env);
  const status = codexStatus(env);
  const present = isDir(dirname(path));
  const before = readText(path);
  const p = codex.planCodexSandbox(before, codexDenyPathsOf(env), userHomeOf(env));
  if (p.kind === "already") return { front, path, present, status, plan: { kind: "already" } };
  if (p.kind === "manual") return { front, path, present, status, plan: { kind: "manual", reason: p.reason, snippet: p.snippet } };
  const preview = p.edits.map((e) => ("add" in e ? `  + ${e.add}` : `  - ${e.before}\n  + ${e.after}`));
  return { front, path, present, status, plan: { kind: "edit", before, after: p.after, preview } };
}

/** What each front end's edit does, said once above the preview. */
const WHY: Record<"claude" | "codex", string[]> = {
  claude: [
    "Turns on Claude Code's sandbox for its shell commands in every project (they then write only in the",
    "project and reach only network hosts you allow), with no retry outside it, and denies them and Claude's",
    "file tools P2P_HOME. Peer2Peer's mod isn't affected: what a mod starts runs outside the sandbox.",
  ],
  codex: [
    "Has Codex's commands run under a permissions profile that denies them P2P_HOME (keeping your current",
    "sandbox otherwise). The Peer2Peer bridge isn't affected: Codex doesn't sandbox MCP servers or hooks.",
  ],
};

/** The question: every change, file by file, and what it does. */
export function previewText(plans: readonly FrontPlan[], p2pHome: string): string {
  const lines = [
    `Your agents run as you, so they can read ${p2pHome} (your identity key and person token) unless their`,
    "sandbox denies it. Peer2Peer can add that deny to your agents' own config:",
  ];
  for (const f of plans) {
    if (f.plan.kind !== "edit") continue;
    lines.push("", `${f.front === "claude" ? "Claude Code" : "Codex"}: ${f.path}`, ...WHY[f.front].map((l) => `  ${l}`), "", ...f.plan.preview);
  }
  lines.push("", "Each file is backed up first (<file>.p2p-backup-<time>); everything else in it stays as it is.");
  return lines.join("\n");
}

/** Writes the planned edits (backup, atomic, a symbolic link written through), returning each file and its backup. */
export function applyPlans(plans: readonly FrontPlan[], now: Date = new Date()): { path: string; backup?: string }[] {
  const changes = plans.flatMap((f) => (f.plan.kind === "edit" ? [{ path: f.path, before: f.plan.before, after: f.plan.after }] : []));
  const stamp = now.toISOString().replace(/[:.]/g, "-");
  return codex.applyChanges(changes, stamp).map((c) => ({ path: c.path, ...(c.backup ? { backup: c.backup } : {}) }));
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

/** The person said no to the sandbox offer (FileConfig.sandboxDeclined): not offered again until `p2p sandbox enable`. */
export function sandboxDeclined(file: Pick<FileConfig, "sandboxDeclined">): boolean {
  return file.sandboxDeclined === true;
}

export function setSandboxDeclined(home: string, declined: boolean): void {
  setFileConfigField(home, "sandboxDeclined", declined);
}

/** The front ends worth offering: installed here (their config folder exists), with an edit to make. */
export function offerablePlans(env: Env, only?: readonly ("claude" | "codex")[]): FrontPlan[] {
  const fronts = only ?? (["claude", "codex"] as const);
  return fronts.map((f) => planFront(f, env)).filter((f) => (only ? true : f.present) && f.plan.kind === "edit");
}

/** Whether the person said no before (config.json unreadable counts as no answer). */
export function declinedHere(env: Env): boolean {
  try {
    return sandboxDeclined(readFileConfig(resolveHome(env)));
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
 * or the caller is neither the person's front end nor the person (an agent's own shell can't use it up).
 */
export async function sandboxNotice(app: App, front: "claude" | "codex"): Promise<string | undefined> {
  if (app.front !== true && agentContext(app.env)) return undefined;
  if (declinedHere(app.env)) return undefined;
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
export function sandboxReport(env: Env, o: { platform?: NodeJS.Platform; managedPath?: string | null } = {}): SandboxReport {
  return {
    p2pHome: p2pHomePaths(env).home,
    declined: declinedHere(env),
    claude: { ...claudeSandboxStatus(env, o), present: frontPresent("claude", env) },
    codex: { ...codexStatus(env), present: frontPresent("codex", env) },
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
