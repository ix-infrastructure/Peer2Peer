// Copyright 2026 Ix Infrastructure Inc.
//
// Ix: optional and recommended, never installed for the person (epic #41 piece 1): finding the
// local Ix CLI, asking it about this machine (version, backend, whether a checkout is mapped),
// recommending it when it isn't there (the person installs it, or says no and isn't asked again),
// and turning the `ix` extension on for a new install, with the person's yes, when Ix is there. The CLI never imports an extension (scripts/check-boundaries.mjs), so
// it runs `ix` itself here, the same way ext-ix does: by absolute path from PATH's absolute
// entries (never a binary planted in the repository), by argv with no shell, bounded, with an
// allowlisted environment pinned to the graph target (projects.ts), never the caller's IX_*
// cloud settings. Nothing is ever installed: the person is told how.

import { execFile } from "node:child_process";
import { accessSync, constants, statSync } from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";
import { sanitizePeerText } from "@peer2peer/core/v3";
import type { App } from "./app.js";
import { setFileConfigField, type Env, type FileConfig } from "./config.js";
import { enabledNamespaces, extensionDirs, extensionPackageName, resolveIn, setExtensionEnabled } from "./extensions.js";
import { personHere, type GraphTarget } from "./projects.js";

/** Where to get Ix (and how p2p says it): never installed for the person. */
export const IX_INSTALL_URL = "https://github.com/ix-infrastructure/Ix";

/**
 * The command(s) that install Ix on this platform, from the Ix README, for the person to run in their
 * own terminal: Peer2Peer prints them and never runs them (it doesn't run a downloaded script). Intel
 * Macs have no pre-built Ix package, so Homebrew builds it.
 */
export function ixInstallCommands(platform: NodeJS.Platform = process.platform, arch: string = process.arch): string[] {
  if (platform === "win32") return ["irm https://ix-infra.com/install.ps1 | iex"];
  if (platform === "darwin" && arch === "x64") return ["brew tap ix-infrastructure/ix https://github.com/ix-infrastructure/Ix", "brew install ix"];
  return ["curl -fsSL https://ix-infra.com/install.sh | sh"];
}

/** The install command(s) as one line (`&&` between steps; Windows has one). */
export function ixInstallLine(platform: NodeJS.Platform = process.platform, arch: string = process.arch): string {
  return ixInstallCommands(platform, arch).join(" && ");
}

/** What Ix adds, in a few lines, said when `p2p setup` recommends it. */
export const IX_PITCH = [
  "Ix (optional, recommended) maps your code into a local graph. With it, Peer2Peer can flag when a peer's",
  "session works on code that overlaps yours, show a change's blast radius, and keep your sessions' context",
  "as local graph memory. Everything stays on this machine. Peer2Peer works without it and never installs it for you.",
];

/** The person said no to Ix at `p2p setup` (FileConfig.ixDeclined): not asked again until `p2p setup --ix`. */
export function ixDeclined(file: Pick<FileConfig, "ixDeclined">): boolean {
  return file.ixDeclined === true;
}

/** Records the person's answer to the Ix offer (config.json `ixDeclined`); only `p2p setup`, at a terminal, writes it. */
export function setIxDeclined(home: string, declined: boolean): void {
  setFileConfigField(home, "ixDeclined", declined);
}

/** CI set (anything but empty, 0 or false): never a prompt. */
export function ciEnv(env: Env): boolean {
  const v = env.CI?.trim().toLowerCase();
  return Boolean(v) && v !== "0" && v !== "false";
}

/**
 * Whether p2p recommends Ix here (`p2p setup --json`, `p2p extensions --json`, and the hint the front
 * ends give their agent): the Ix CLI isn't found and the person hasn't said no. `install` is the
 * command for the person to run; nothing is ever installed for them.
 */
export interface IxAdvice {
  /** The Ix CLI was found. */
  installed: boolean;
  /** The person said no at `p2p setup` (`p2p setup --ix` asks again). */
  declined: boolean;
  /** Ix isn't installed and the person hasn't said no. */
  recommended: boolean;
  /** The command that installs Ix on this platform, for the person to run themselves. */
  install: string;
}

export function ixAdvice(env: Env, file: Pick<FileConfig, "ixDeclined">, o: { reoffer?: boolean } = {}): IxAdvice {
  const installed = ixBinary(env) !== undefined;
  const declined = ixDeclined(file) && o.reoffer !== true;
  return { installed, declined, recommended: !installed && !declined, install: ixInstallLine() };
}

/**
 * `name` resolved to an absolute path through PATH's absolute entries (the same rule as ext-ix's
 * which.ts: on Windows the current directory is searched before PATH, so a cloned repository's
 * `ix.exe` would otherwise run). An absolute name is used as given when it runs.
 */
export function whichAbsolute(name: string, env: Record<string, string | undefined> = process.env, platform: NodeJS.Platform = process.platform): string | undefined {
  const runnable = (p: string) => {
    try {
      if (!statSync(p).isFile()) return false;
      if (platform !== "win32") accessSync(p, constants.X_OK);
      return true;
    } catch {
      return false;
    }
  };
  if (isAbsolute(name)) return runnable(name) ? name : undefined;
  if (/[\\/]/.test(name)) return undefined;
  const win = platform === "win32";
  const sep = win ? ";" : delimiter;
  const path = env.PATH ?? env.Path ?? "";
  const exts = win ? (env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean) : [""];
  const hasExt = win && exts.some((e) => name.toLowerCase().endsWith(e.toLowerCase()));
  for (const dir of path.split(sep)) {
    const d = dir.trim().replace(/^"|"$/g, "");
    if (d === "" || !isAbsolute(d)) continue;
    for (const ext of hasExt ? [""] : exts) {
      const p = join(d, name + ext);
      if (runnable(p)) return p;
    }
  }
  return undefined;
}

/** The Ix CLI: IX_BIN when it is an absolute path that runs (or a bare name found on PATH), else `ix` on PATH. */
export function ixBinary(env: Env): string | undefined {
  const name = env.IX_BIN?.trim() || "ix";
  return whichAbsolute(name, env);
}

/** What an `ix` child may see of the environment (besides the pinned IX_ENDPOINT): no IX_* cloud setting, no P2P_*, no loader or proxy variables. */
const IX_CHILD_ALLOW = ["PATH", "PATHEXT", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA", "SYSTEMROOT", "WINDIR", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "TZ", "TERM", "NO_COLOR", "IX_HOME", "IX_TOKEN"];

/**
 * The environment `ix` runs with: IX_CHILD_ALLOW from `env`, then IX_ENDPOINT from the target
 * (never the caller's), no background `ix map` from a reader (Ix Pro routes a map to the cloud
 * whenever an org session is active), no update check. Names compare case-insensitively, as on
 * Windows. The same rule as ext-ix's ixEnv (ix.ts).
 */
export function ixChildEnv(env: Record<string, string | undefined>, target: Pick<GraphTarget, "endpoint">): NodeJS.ProcessEnv {
  const allow = new Set(IX_CHILD_ALLOW);
  const out: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(env)) if (typeof v === "string" && allow.has(k.toUpperCase())) out[k] = k.toUpperCase() === "PATH" ? absolutePath(v) : v;
  out.IX_ENDPOINT = target.endpoint;
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

export interface IxRun {
  code: number;
  stdout: string;
  stderr: string;
  timedOut?: true;
}

/** One bounded `ix` call (argv, no shell, SIGKILL on timeout, output capped). Read-only commands only. */
export function runIx(bin: string, argv: readonly string[], o: { env: Record<string, string | undefined>; target: Pick<GraphTarget, "endpoint">; cwd?: string; timeoutMs: number }): Promise<IxRun> {
  return new Promise((resolve) => {
    execFile(bin, [...argv], { cwd: o.cwd, env: ixChildEnv(o.env, o.target), timeout: o.timeoutMs, killSignal: "SIGKILL", maxBuffer: 1 << 20, windowsHide: true }, (err, stdout, stderr) => {
      const e = err as (NodeJS.ErrnoException & { killed?: boolean; code?: unknown }) | null;
      resolve({ code: e ? (typeof e.code === "number" ? e.code : 1) : 0, stdout: String(stdout ?? ""), stderr: String(stderr ?? ""), ...(e?.killed ? { timedOut: true as const } : {}) });
    });
  });
}

/** `ix --version`'s first line, sanitized; undefined when it fails. */
export async function ixVersion(bin: string, env: Env, target: Pick<GraphTarget, "endpoint">, timeoutMs: number): Promise<string | undefined> {
  const r = await runIx(bin, ["--version"], { env, target, timeoutMs });
  if (r.code !== 0) return undefined;
  const v = sanitizePeerText(r.stdout.split("\n")[0]?.trim() ?? "", 64);
  return v || undefined;
}

/** Whether @peer2peer/ext-ix is where this p2p loads extensions from (resolved, never imported). */
export function extIxInstalled(env: Env): boolean {
  for (const dir of extensionDirs(env, import.meta.url)) {
    try {
      if (resolveIn(dir, extensionPackageName("ix"))) return true;
    } catch {
      // a malformed copy is not an installed one
    }
  }
  return false;
}

/** P2P_EXTENSIONS decides which extensions load (anything but unset or `config`, which defers to config.json). */
const envDecides = (env: Env) => env.P2P_EXTENSIONS !== undefined && env.P2P_EXTENSIONS.trim() !== "config";

/** What `p2p setup` did about Ix (SetupResult.ix). */
export interface SetupIx {
  /** The Ix CLI was found (its absolute path is local only, never sent anywhere). */
  found: boolean;
  /** The same as `found` (IxAdvice's name). */
  installed: boolean;
  /** Ix isn't installed and the person hasn't said no: p2p recommends it (it never installs it). */
  recommended: boolean;
  /** The person said no to Ix at an earlier `p2p setup` (`--ix` asks again). */
  declined?: true;
  /** The command that installs Ix on this platform, for the person to run themselves (when it isn't installed). */
  install?: string;
  /** The `ix` extension is enabled now (by this setup, or already). */
  enabled: boolean;
  /** This setup turned it on (a new install, Ix present, ext-ix installed, the person running it). */
  enabledNow?: true;
  /** What the person can do, when it isn't on. */
  hint?: string;
}

/**
 * What to do about Ix when it isn't installed: the person runs the command themselves; read by an
 * agent (not the person), it says to ask the user instead, since installing is theirs alone.
 */
export function ixInstallHint(line: string, person: boolean): string {
  const what = "Ix (optional, recommended: a local code graph for overlap, blast radius and graph memory) isn't installed";
  return person
    ? `${what}. Peer2Peer never installs it for you: to add it, run \`${line}\` yourself (or see ${IX_INSTALL_URL}), then \`p2p setup --ix\``
    : `${what}. Installing it is your user's decision: don't install it yourself; you may ask your user whether they want it, and they run \`${line}\` in their own terminal, then \`p2p setup --ix\``;
}
const DECLINED_IX = "Ix isn't installed (you said no; `p2p setup --ix` offers it again). Peer2Peer works without it";
const INSTALL_EXT = "Ix is installed, but the Ix extension isn't: `npm i -g @peer2peer/ext-ix`, then `p2p extensions enable ix` (the Claude Code mod ships it: `/peers setup` there turns it on)";

/**
 * Ix for `p2p setup`: optional and recommended, never installed. Without the Ix CLI it says what to
 * run (`recommended`, `install`), unless the person said no before (`--ix`, `reoffer`, asks again).
 * With it, a new install (`created`; or any install, with `reoffer`) gets the `ix` extension enabled
 * when ext-ix is there too and the person agrees: their front end's token (the Claude mod's typed
 * `/peers setup`), or, outside any agent's session (its environment or a Claude Code or Codex
 * ancestor), their "yes" typed on the controlling terminal, as for every other person-only action
 * (projects.ts). Otherwise nothing changes: an existing install is never switched silently (it gets
 * the one-time notice, ixNotice), an agent never enables an extension, and P2P_EXTENSIONS, when
 * set, decides alone.
 */
export async function setupIx(app: App, created: boolean, o: { reoffer?: boolean } = {}): Promise<SetupIx> {
  const adv = ixAdvice(app.env, app.file, o);
  const found = adv.installed;
  const base = { found, installed: found, recommended: adv.recommended, ...(adv.declined ? { declined: true as const } : {}) };
  const { enabled } = enabledNamespaces(app.env, app.file);
  if (enabled.includes("ix")) return { ...base, enabled: true };
  if (!found) return { ...base, enabled: false, install: adv.install, hint: adv.declined ? DECLINED_IX : ixInstallHint(adv.install, personHere(app)) };
  if (!extIxInstalled(app.env)) return { ...base, enabled: false, hint: INSTALL_EXT };
  const chose = Array.isArray(app.file.extensions);
  if ((!created && o.reoffer !== true) || chose || envDecides(app.env) || !personHere(app)) {
    return { ...base, enabled: false, hint: "Ix is installed: `p2p extensions enable ix` lets your sessions share Ix context (notes, subgraph references, blast radius, footprints)" };
  }
  if (app.front !== true) {
    const yes = app.confirmTty ? await app.confirmTty("Ix is installed. Turn on the Ix extension, so your sessions can share Ix context with the people you share a project with? (Ix calls stay on this machine.)").catch(() => false) : false;
    if (!yes) return { ...base, enabled: false, hint: "Ix is installed: `p2p extensions enable ix` lets your sessions share Ix context (notes, subgraph references, blast radius, footprints)" };
  }
  setExtensionEnabled(app.home, "ix", true);
  return { ...base, enabled: true, enabledNow: true };
}

/**
 * The one-time notice for an existing install (shown once per device, to the person at a terminal):
 * new installs offer to turn the Ix extension on when Ix is present; this one wasn't changed.
 * Undefined when it was shown already, Ix isn't installed, the person said no to Ix, or the
 * extension is on (or P2P_EXTENSIONS decides).
 */
export async function ixNotice(app: App): Promise<string | undefined> {
  if (envDecides(app.env) || ixDeclined(app.file)) return undefined;
  if (enabledNamespaces(app.env, app.file).enabled.includes("ix")) return undefined;
  if ((await app.state.get("ixNotice"))?.at !== undefined) return undefined;
  if (!ixBinary(app.env)) return undefined;
  const shown = await app.state.update("ixNotice", (cur) => (cur?.at !== undefined ? { result: false } : { next: { at: Date.now() }, result: true }));
  if (!shown) return undefined;
  const how = extIxInstalled(app.env) ? "`p2p extensions enable ix`" : "`npm i -g @peer2peer/ext-ix`, then `p2p extensions enable ix`";
  return `Ix: \`p2p setup\` now offers to turn the Ix extension on when Ix is installed, so sessions can share Ix context. Yours wasn't changed; to turn it on, run ${how}. Ix calls stay on this machine (\`p2p doctor\` shows each project's graph: local only)`;
}

/**
 * Which `ix note` / `ix session` this Ix has, from `ix --help` (graph memory, graph-memory.ts):
 * "oss" (the local backend: Ix after 0.13.0, ix-infrastructure/Ix#916, with Ix Pro not loaded: its
 * help then lists them under "Memory:"), "pro" (Ix Pro loaded: its "Pro:" section; its note and
 * session go to the cloud org), "none" (neither). The same reading as ext-ix's parseMemorySupport
 * (ix.ts), which decides; this one only reports (`p2p doctor`).
 */
export function parseIxMemorySupport(help: string): "oss" | "pro" | "none" {
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

/** `ix --help` read as parseIxMemorySupport; undefined when it doesn't answer. */
export async function ixMemorySupport(bin: string, env: Env, target: Pick<GraphTarget, "endpoint">, timeoutMs: number): Promise<"oss" | "pro" | "none" | undefined> {
  const r = await runIx(bin, ["--help"], { env, target, timeoutMs });
  return r.code === 0 ? parseIxMemorySupport(r.stdout) : undefined;
}
