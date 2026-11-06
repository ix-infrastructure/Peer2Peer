// Copyright 2026 Ix Infrastructure Inc.
//
// Ix on by default (epic #41 piece 1): finding the local Ix CLI, asking it about this machine
// (version, backend, whether a checkout is mapped), and turning the `ix` extension on for a new
// install when Ix is there. The CLI never imports an extension (scripts/check-boundaries.mjs), so
// it runs `ix` itself here, the same way ext-ix does: by absolute path from PATH's absolute
// entries (never a binary planted in the repository), by argv with no shell, bounded, with an
// allowlisted environment pinned to the graph target (projects.ts), never the caller's IX_*
// cloud settings. Nothing is ever installed: the person is told how.

import { execFile } from "node:child_process";
import { accessSync, constants, statSync } from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";
import { sanitizePeerText } from "@peer2peer/core/v3";
import type { App } from "./app.js";
import type { Env } from "./config.js";
import { enabledNamespaces, extensionDirs, extensionPackageName, resolveIn, setExtensionEnabled } from "./extensions.js";
import { personHere, type GraphTarget } from "./projects.js";

/** Where to get Ix (and how p2p says it): never installed for the person. */
export const IX_INSTALL_URL = "https://github.com/ix-infrastructure/Ix";

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
  for (const [k, v] of Object.entries(env)) if (typeof v === "string" && allow.has(k.toUpperCase())) out[k] = v;
  out.IX_ENDPOINT = target.endpoint;
  out.IX_MAP_BACKGROUND_REFRESH = "0";
  out.IX_NO_UPDATE_CHECK = "1";
  return out;
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
  /** The `ix` extension is enabled now (by this setup, or already). */
  enabled: boolean;
  /** This setup turned it on (a new install, Ix present, ext-ix installed, the person running it). */
  enabledNow?: true;
  /** What the person can do, when it isn't on. */
  hint?: string;
}

const INSTALL_IX = `Ix (the local code graph peers' agents point into) isn't installed: get it from ${IX_INSTALL_URL}, then run \`p2p extensions enable ix\` (Peer2Peer works without it)`;
const INSTALL_EXT = "Ix is installed, but the Ix extension isn't: `npm i -g @peer2peer/ext-ix`, then `p2p extensions enable ix` (the Claude Code mod ships it: `/peers setup` there turns it on)";

/**
 * Ix on by default, for `p2p setup`. A new install (`created`) run by the person (their front end's
 * token, or a terminal outside any agent's session) gets the `ix` extension enabled when the Ix CLI
 * and ext-ix are both there. Otherwise nothing changes: an existing install is never switched
 * silently (it gets the one-time notice, ixNotice), an agent's shell never enables an extension,
 * and P2P_EXTENSIONS, when set, decides alone.
 */
export function setupIx(app: App, created: boolean): SetupIx {
  const found = ixBinary(app.env) !== undefined;
  const { enabled } = enabledNamespaces(app.env, app.file);
  if (enabled.includes("ix")) return { found, enabled: true };
  if (!found) return { found, enabled: false, hint: INSTALL_IX };
  if (!extIxInstalled(app.env)) return { found, enabled: false, hint: INSTALL_EXT };
  const chose = Array.isArray(app.file.extensions);
  if (!created || chose || envDecides(app.env) || !personHere(app)) {
    return { found, enabled: false, hint: "Ix is installed: `p2p extensions enable ix` lets your sessions share Ix context (notes, subgraph references, blast radius, footprints)" };
  }
  setExtensionEnabled(app.home, "ix", true);
  return { found, enabled: true, enabledNow: true };
}

/**
 * The one-time notice for an existing install (shown once per device, to the person at a terminal):
 * new installs turn the Ix extension on when Ix is present; this one wasn't changed. Undefined when
 * it was shown already, Ix isn't installed, or the extension is on (or P2P_EXTENSIONS decides).
 */
export async function ixNotice(app: App): Promise<string | undefined> {
  if (envDecides(app.env)) return undefined;
  if (enabledNamespaces(app.env, app.file).enabled.includes("ix")) return undefined;
  if ((await app.state.get("ixNotice"))?.at !== undefined) return undefined;
  if (!ixBinary(app.env)) return undefined;
  const shown = await app.state.update("ixNotice", (cur) => (cur?.at !== undefined ? { result: false } : { next: { at: Date.now() }, result: true }));
  if (!shown) return undefined;
  const how = extIxInstalled(app.env) ? "`p2p extensions enable ix`" : "`npm i -g @peer2peer/ext-ix`, then `p2p extensions enable ix`";
  return `Ix: new installs now turn the Ix extension on when Ix is installed, so sessions can share Ix context. Yours wasn't changed; to turn it on, run ${how}. Ix calls stay on this machine (\`p2p doctor\` shows each project's graph: local only)`;
}
