// Copyright 2026 Ix Infrastructure Inc.
//
// Codex's sandbox and P2P_HOME: whether the commands a Codex session runs are denied read and
// write access to P2P_HOME (`p2p doctor`, `p2p sandbox`), and the smallest edit to config.toml
// that makes them so (`p2p sandbox enable`, offered by `p2p setup` and `p2p codex install`).
//
// What Codex enforces (learn.chatgpt.com/docs/permissions): a permissions profile
// (`default_permissions = "<name>"`, `[permissions.<name>.filesystem]`) can map a path to
// `"deny"`, which "denies both reads and writes under the path", enforced by the OS sandbox
// (Seatbelt on macOS, bubblewrap on Linux and WSL) on the commands Codex runs. The older
// `sandbox_mode` / `[sandbox_workspace_write]` settings can't deny a read, and they don't compose
// with profiles: "If `sandbox_mode` appears in any loaded config file … Codex uses those older
// sandbox settings instead of `default_permissions`." MCP servers and hooks aren't sandboxed by a
// profile, so the bridge (`p2p codex mcp`, `p2p codex hook`) keeps reading P2P_HOME.
//
// The edit is minimal and line-based: other lines, comments and their order stay as they were. A
// top-level line it changes carries a `# p2p sandbox` comment, and the profile it adds sits in a
// marked block. Anything it can't edit with confidence (a profile written as an inline table or
// dotted keys, a multi-line `writable_roots`, the `exclude_*` switches) is left alone: the person
// gets the lines to add by hand. The profile it adds is never broader than what Codex enforced
// before (writes and network): `sandbox_mode` alone decides what it extends when set, else a
// built-in `default_permissions`, else `:read-only` (or what the person chose).

import { isAbsolute, join, normalize, resolve, sep } from "node:path";
import { readTomlTable, scanTomlLines, type TomlLine } from "./knobs.js";

/** The profile `p2p sandbox enable` adds when the person has none of their own. */
export const SANDBOX_PROFILE = "peer2peer";
export const SANDBOX_BEGIN = "# >>> peer2peer sandbox (added by `p2p sandbox enable`: Codex's sandbox denies P2P_HOME) >>>";
export const SANDBOX_END = "# <<< peer2peer sandbox <<<";
/** The comment on a top-level line the edit changed. */
export const SANDBOX_MARK = "# p2p sandbox";

const BUILT_INS = new Set([":workspace", ":read-only", ":danger-full-access"]);
const toml = (s: string) => JSON.stringify(s);

export interface CodexSandboxStatus {
  /** on: the active profile denies every P2P_HOME path; off: it doesn't (or no profile is active); unknown: config.toml couldn't be read. */
  state: "on" | "off" | "unknown";
  /** The active permissions profile, when one is. */
  profile?: string;
  /** One line, for the person. */
  detail: string;
  /** Things that weaken it, said beside an "on". */
  notes: string[];
}

/** One line of the edit, for the preview: an added line, or a changed one (before → after). */
export type TomlEdit = { add: string } | { before: string; after: string };

export type CodexSandboxPlan =
  | { kind: "already"; profile: string }
  | { kind: "edit"; after: string; edits: TomlEdit[]; profile: string; base?: string; assumed?: true }
  | { kind: "manual"; reason: string; snippet: string };

/** P2P_HOME as config.toml paths: `~/…` under the home folder, else absolute; its real path too when that differs. */
export function codexDenyPaths(p2pHome: string, userHome: string, realHome?: string): string[] {
  const out: string[] = [];
  for (const p of [p2pHome, realHome]) {
    if (!p) continue;
    const abs = normalize(resolve(p));
    const home = normalize(resolve(userHome));
    const form = abs.startsWith(home + sep) ? `~/${abs.slice(home.length + 1).split(sep).join("/")}` : abs;
    if (!out.includes(form)) out.push(form);
  }
  return out;
}

/** A config.toml path key expanded to an absolute path (`~/x`, `~`, absolute), or undefined for a special (`:root`, …) or a relative key. */
function expand(key: string, userHome: string): string | undefined {
  if (key === "~") return normalize(userHome);
  if (key.startsWith("~/") || key.startsWith("~\\")) return normalize(join(userHome, key.slice(2)));
  if (isAbsolute(key)) return normalize(key);
  return undefined;
}

/** Whether `path` is `root` or inside it (normalized; case-insensitive on macOS and Windows). */
function within(path: string, root: string): boolean {
  const caseless = process.platform === "darwin" || process.platform === "win32";
  const a = caseless ? path.toLowerCase() : path;
  const b = caseless ? root.toLowerCase() : root;
  const r = b.endsWith(sep) ? b : b + sep;
  return a === b || a.startsWith(r);
}

/** The top-level scalar keys (and the line each sits on). */
function topLevel(lines: readonly TomlLine[]): Map<string, { value: string | null; at: number }> {
  const out = new Map<string, { value: string | null; at: number }>();
  lines.forEach((l, at) => {
    if (l.kind === "kv" && l.table.length === 0 && l.key.length === 1) out.set(l.key[0] as string, { value: l.value, at });
  });
  return out;
}

const startsWith = (a: readonly string[], b: readonly string[]) => a.length >= b.length && b.every((x, i) => a[i] === x);
const same = (a: readonly string[], b: readonly string[]) => a.length === b.length && startsWith(a, b);

/**
 * A named profile's filesystem entries, its `extends` chain followed (the child's entries over its
 * parents'), or null when the text can't be read with confidence. `base` is the built-in the chain
 * ends on, if any.
 */
function profileEntries(text: string, name: string): { entries: Record<string, string>; base?: string } | null {
  const entries: Record<string, string> = {};
  const chain: string[] = [];
  let cur: string | undefined = name;
  let base: string | undefined;
  while (cur !== undefined) {
    if (BUILT_INS.has(cur)) {
      base = cur;
      break;
    }
    if (chain.includes(cur) || chain.length > 8) return null;
    chain.push(cur);
    const t = readTomlTable(text, ["permissions", cur]);
    if (t === null) return null;
    cur = t.extends;
  }
  for (const p of chain.reverse()) {
    const fs = readTomlTable(text, ["permissions", p, "filesystem"]);
    if (fs === null) return null;
    Object.assign(entries, fs);
  }
  return { entries, ...(base ? { base } : {}) };
}

/** Why a profile's entries leave P2P_HOME reachable, or undefined when every path is denied. */
function denyGap(entries: Record<string, string>, denyPaths: readonly string[], userHome: string): string | undefined {
  for (const want of denyPaths) {
    const target = expand(want, userHome);
    if (!target) return `${want} isn't a path Codex reads`;
    // The most specific entry at or above the path decides (a deny wins a tie).
    let best: { len: number; access: string } | undefined;
    for (const [k, v] of Object.entries(entries)) {
      if (v !== "deny" && v !== "read" && v !== "write") continue;
      const p = expand(k, userHome);
      if (!p || !within(target, p)) continue;
      if (!best || p.length > best.len || (p.length === best.len && v === "deny")) best = { len: p.length, access: v };
    }
    if (best?.access !== "deny") return `it doesn't deny ${want}`;
    // An entry below it that grants access opens part of it again.
    for (const [k, v] of Object.entries(entries)) {
      const p = expand(k, userHome);
      if (p && (v === "read" || v === "write") && within(p, target) && p.length > target.length) return `"${k}" = "${v}" opens part of ${want} again`;
    }
  }
  return undefined;
}

/** `[profiles.<name>]` config profiles that set `sandbox_mode` (each turns the permissions profile off when selected). */
function sandboxModeProfiles(lines: readonly TomlLine[]): string[] {
  const out = new Set<string>();
  for (const l of lines) {
    if (l.kind !== "kv") continue;
    const full = [...l.table, ...l.key];
    if (full.length === 3 && full[0] === "profiles" && full[2] === "sandbox_mode") out.add(full[1] as string);
  }
  return [...out];
}

/** Whether the commands Codex runs are denied P2P_HOME by this config.toml (`text`, null when there is none). */
export function codexSandboxStatus(text: string | null, denyPaths: readonly string[], userHome: string): CodexSandboxStatus {
  if (text === null) return { state: "off", detail: "config.toml has no permissions profile: Codex's sandbox lets its commands read everywhere, P2P_HOME included", notes: [] };
  const lines = scanTomlLines(text);
  if (lines === null) return { state: "unknown", detail: "config.toml couldn't be read with confidence", notes: [] };
  const top = topLevel(lines);
  const notes = sandboxModeProfiles(lines).map((p) => `the config profile "${p}" sets sandbox_mode: \`codex --profile ${p}\` runs without this deny`);
  const mode = top.get("sandbox_mode")?.value;
  if (mode) {
    return {
      state: "off",
      detail: mode === "danger-full-access" ? `sandbox_mode = "danger-full-access": Codex runs its commands without a sandbox` : `sandbox_mode = "${mode}" is set: Codex uses it instead of a permissions profile, and it can't deny reads`,
      notes,
    };
  }
  const dp = top.get("default_permissions")?.value;
  if (!dp) return { state: "off", detail: "no permissions profile (default_permissions): Codex's sandbox lets its commands read everywhere, P2P_HOME included", notes };
  if (dp === ":danger-full-access") return { state: "off", profile: dp, detail: `default_permissions = ":danger-full-access": Codex runs its commands without a sandbox`, notes };
  if (BUILT_INS.has(dp)) return { state: "off", profile: dp, detail: `the built-in profile ${dp} lets Codex's commands read P2P_HOME`, notes };
  const p = profileEntries(text, dp);
  if (p === null) return { state: "unknown", profile: dp, detail: `the permissions profile "${dp}" couldn't be read with confidence`, notes };
  if (p.base === ":danger-full-access") return { state: "off", profile: dp, detail: `the permissions profile "${dp}" extends :danger-full-access`, notes };
  const gap = denyGap(p.entries, denyPaths, userHome);
  if (gap) return { state: "off", profile: dp, detail: `the permissions profile "${dp}" is active, but ${gap}`, notes };
  return { state: "on", profile: dp, detail: `the permissions profile "${dp}" denies Codex's commands ${denyPaths.join(" and ")} (read and write)`, notes };
}

/** The lines a person adds by hand (when the edit can't be made safely). */
export function codexManualSnippet(denyPaths: readonly string[], base?: string): string {
  return [
    `default_permissions = ${toml(SANDBOX_PROFILE)}   # at the top, before any [table]; remove any sandbox_mode line`,
    "",
    `[permissions.${SANDBOX_PROFILE}]`,
    base ? `extends = ${toml(base)}` : `extends = ":read-only"   # or ":workspace", if Codex may write in your workspace without asking`,
    "",
    `[permissions.${SANDBOX_PROFILE}.filesystem]`,
    ...denyPaths.map((p) => `${toml(p)} = "deny"`),
  ].join("\n");
}

/** The kv lines that define something under `prefix` other than from the `[prefix]` table (or a table below it). */
function definedOutside(lines: readonly TomlLine[], prefix: readonly string[]): boolean {
  return lines.some((l) => l.kind === "kv" && startsWith([...l.table, ...l.key], prefix) && !startsWith(l.table, prefix));
}

/**
 * The edit that makes Codex's sandbox deny `denyPaths` (to config.toml's text, null when there is
 * none), or why it must be done by hand. Idempotent: on its own output it answers "already".
 */
export function planCodexSandbox(
  text: string | null,
  denyPaths: readonly string[],
  userHome: string,
  o: { baseWhenUnset?: ":read-only" | ":workspace" } = {},
): CodexSandboxPlan {
  const src = text ?? "";
  const status = codexSandboxStatus(text, denyPaths, userHome);
  if (status.state === "on" && status.profile) return { kind: "already", profile: status.profile };
  const lines = scanTomlLines(src);
  const manual = (reason: string, base?: string): CodexSandboxPlan => ({ kind: "manual", reason, snippet: codexManualSnippet(denyPaths, base) });
  if (lines === null) return manual("config.toml couldn't be read with confidence, so it wasn't edited");
  const eol = src.includes("\r\n") ? "\r\n" : "\n";
  const raw = src === "" ? [] : src.split(/\r?\n/);
  // A trailing newline leaves one empty last element: kept as is, and the appended block goes before it.
  const hadFinalEol = raw.length > 0 && raw[raw.length - 1] === "";
  if (hadFinalEol) raw.pop();
  const scanned = lines.slice(0, raw.length);
  const edits: TomlEdit[] = [];
  const top = topLevel(scanned);
  const mode = top.get("sandbox_mode");
  const dp = top.get("default_permissions");
  if (mode?.value === "danger-full-access" || dp?.value === ":danger-full-access") {
    return manual("Codex runs its commands without a sandbox here (danger-full-access): choose a sandbox first (a permissions profile that extends :workspace), then deny P2P_HOME in it");
  }
  if (mode && mode.value === null) return manual("sandbox_mode isn't a plain value");

  // The profile that gets the deny: the person's own named profile, or ours.
  const own = dp?.value && !BUILT_INS.has(dp.value) && !mode ? dp.value : undefined;
  const target = own ?? SANDBOX_PROFILE;
  const fsTable = ["permissions", target, "filesystem"];
  if (definedOutside(scanned, fsTable)) return manual(`[permissions.${target}.filesystem] is written as an inline table or dotted keys, so it wasn't edited`);
  const ours = target === SANDBOX_PROFILE;
  const oursDefined = ours && scanned.some((l) => (l.kind === "header" && startsWith(l.table, ["permissions", SANDBOX_PROFILE])) || (l.kind === "kv" && startsWith([...l.table, ...l.key], ["permissions", SANDBOX_PROFILE])));

  // What the profile we add extends: never broader than what Codex enforces now. Codex uses
  // sandbox_mode whenever it is set (default_permissions is ignored then), so it alone decides; else
  // a built-in default_permissions; else nothing is set, and Codex picks per folder (workspace-write
  // in a version-controlled folder, read-only elsewhere and until a folder is trusted), which a
  // profile can't express: :read-only unless the person chose :workspace.
  let base = ":read-only";
  let assumed = false;
  const carried: string[] = [];
  let network = false;
  if (ours && oursDefined && mode) return manual("sandbox_mode is set and a [permissions.peer2peer] profile exists already: remove one of them first");
  if (ours && !oursDefined) {
    if (mode) {
      if (mode.value === "read-only") base = ":read-only";
      else if (mode.value === "workspace-write") base = ":workspace";
      else return manual(`sandbox_mode = "${mode.value}" isn't one this edit knows`);
    } else if (dp?.value === ":read-only" || dp?.value === ":workspace") base = dp.value;
    else {
      base = o.baseWhenUnset ?? ":read-only";
      assumed = true;
    }
    // [sandbox_workspace_write] applies only under sandbox_mode = "workspace-write": carried over only then.
    if (mode?.value === "workspace-write") {
      const sww = scanned.filter((l): l is Extract<TomlLine, { kind: "kv" }> => l.kind === "kv" && startsWith([...l.table, ...l.key], ["sandbox_workspace_write"]));
      for (const l of sww) {
        const k = [...l.table, ...l.key].slice(1).join(".");
        if (k === "writable_roots") {
          if (!l.list) return manual("[sandbox_workspace_write] writable_roots isn't a one-line list of strings, so its folders couldn't be carried over", base);
          carried.push(...l.list);
        } else if (k === "network_access") network = l.value === "true";
        else if ((k === "exclude_tmpdir_env_var" || k === "exclude_slash_tmp") && l.value === "true") {
          return manual(`[sandbox_workspace_write] sets ${k}, which a profile extending :workspace can't express`, base);
        }
      }
    }
  }

  // Top-level lines first (their indexes don't move until we insert).
  const setLine = `default_permissions = ${toml(target)} ${SANDBOX_MARK}`;
  let insertTopAt: number | undefined;
  if (dp && dp.value !== target) {
    const before = raw[dp.at] as string;
    const after = `default_permissions = ${toml(target)} ${SANDBOX_MARK} (was ${toml(dp.value ?? "")})`;
    raw[dp.at] = after;
    edits.push({ before, after });
  } else if (!dp) {
    // After the last top-level key (and the lines its value spans), else before the first table.
    const firstHeader = scanned.findIndex((l) => l.kind === "header");
    const end = firstHeader < 0 ? raw.length : firstHeader;
    let lastTop = -1;
    for (let i = 0; i < end; i++) if (scanned[i]?.kind === "kv" || (scanned[i]?.kind === "cont" && lastTop === i - 1)) lastTop = i;
    insertTopAt = lastTop >= 0 ? lastTop + 1 : end;
  }
  if (mode) {
    const before = raw[mode.at] as string;
    const after = `# ${before.trim()} ${SANDBOX_MARK}: replaced by default_permissions = ${toml(target)} (profiles don't combine with sandbox_mode)`;
    raw[mode.at] = after;
    edits.push({ before, after });
  }

  // Then the deny entries: into the existing filesystem table, or a new one.
  const status2 = profileEntries(src, target);
  const have = status2?.entries ?? {};
  const missing = denyPaths.filter((p) => denyGap(have, [p], userHome) !== undefined);
  const denyLines = missing.map((p) => `${toml(p)} = "deny"`);
  const header = scanned.findIndex((l) => l.kind === "header" && same(l.table, fsTable));
  const appended: string[] = [];
  if (header >= 0) {
    raw.splice(header + 1, 0, ...denyLines);
    for (const a of denyLines) edits.push({ add: a });
    if (insertTopAt !== undefined && insertTopAt > header) insertTopAt += denyLines.length;
  } else if (ours && !oursDefined) {
    appended.push(
      SANDBOX_BEGIN,
      `[permissions.${SANDBOX_PROFILE}]`,
      `description = "Codex's sandbox, with Peer2Peer's keys (P2P_HOME) denied to its commands"`,
      `extends = ${toml(base)}`,
      "",
      `[permissions.${SANDBOX_PROFILE}.filesystem]`,
      ...denyLines,
      ...carried.map((p) => `${toml(p)} = "write"`),
      ...(network ? ["", `[permissions.${SANDBOX_PROFILE}.network]`, "enabled = true"] : []),
      SANDBOX_END,
    );
  } else {
    appended.push(`[permissions.${target}.filesystem] ${SANDBOX_MARK}`, ...denyLines);
  }
  if (insertTopAt !== undefined) {
    const nextIsHeader = insertTopAt < raw.length && raw[insertTopAt]?.trim().startsWith("[") === true;
    const add = nextIsHeader ? [setLine, ""] : [setLine];
    raw.splice(insertTopAt, 0, ...add);
    edits.unshift({ add: setLine });
  }
  if (appended.length > 0) {
    while (raw.length > 0 && raw[raw.length - 1]?.trim() === "") raw.pop();
    if (raw.length > 0) raw.push("");
    raw.push(...appended);
    for (const a of appended) edits.push({ add: a });
  }
  const after = raw.join(eol) + eol;
  // The edit must read back as "on"; anything else is left to the person.
  const check = codexSandboxStatus(after, denyPaths, userHome);
  if (check.state !== "on") return manual(`the edit wouldn't make the sandbox deny P2P_HOME (${check.detail}), so nothing was changed`, base);
  return { kind: "edit", after, edits, profile: target, ...(ours && !oursDefined ? { base } : {}), ...(assumed ? { assumed: true as const } : {}) };
}
