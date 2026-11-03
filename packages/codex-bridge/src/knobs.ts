// Copyright 2026 Ix Infrastructure Inc.
//
// Where the bridge's security-relevant settings may come from.
//
// Codex merges config layers: user (`CODEX_HOME/config.toml`), profile,
// then project layers (`.codex/config.toml` in the cwd, its parents and the
// repo root) for projects the person marked trusted, then `-c` flags.
// `mcp_servers` is not on Codex's project-local denylist
// (`codex-rs/config/src/loader/mod.rs`, PROJECT_LOCAL_CONFIG_DENYLIST), so a
// trusted repo's `.codex/config.toml` can add to `mcp_servers.peer2peer.env`,
// for example `P2P_AUTO_DELIVER = "p2p:<attacker>"`. A repo is content, not
// the person, so the bridge takes every knob that loosens a rule, redirects
// a confirmation, or picks which identity, binary or Codex home it uses
// ONLY from the user-level config's `[mcp_servers.peer2peer.env]` table. An
// environment value that differs is ignored, with a warning. A knob that
// only tightens (P2P_SHARE_STATUS=0) is honoured from either place.
//
// CODEX_HOME locates that user config, so it is bootstrapped separately.
// A value in a temp folder (/tmp, TMPDIR, ...), in the project (cwd and
// repo), not owned by the person or world-writable is always refused. Else
// it counts only when Codex itself (this server's parent process) runs with
// the same CODEX_HOME, where the OS lets the bridge read the parent's
// environment; where it can't (Windows, a non-dumpable Codex on Linux), only
// when the person's `p2p codex install --write` pinned it (pinFile). Else
// ~/.codex.
//
// The same merge lets a trusted repo replace `mcp_servers.peer2peer`'s
// command, args, cwd or env (HOME, TMPDIR, PATH) outright, so all of this
// is defence in depth. ~ comes from the user database, never $HOME; the
// EFFECTIVE Codex home and P2P_HOME are checked every time; and a HOME
// that isn't the person's, or a project config touching
// `mcp_servers.peer2peer` at all, makes the bridge hold everything and
// refuse every release (locationPolicy).

import { execFile, execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, closeSync, constants as fsConstants, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, statSync, writeFileSync } from "node:fs";
import { readFile, readlink } from "node:fs/promises";
import { homedir, tmpdir, userInfo } from "node:os";
import { basename, delimiter, dirname, isAbsolute, join } from "node:path";
import { isInside } from "./lib.js";

/** Knobs taken only from the user-level config. */
export const GUARDED_KNOBS = [
  "P2P_AUTO_DELIVER",
  "P2P_CODEX_CONFIRM_TTY",
  "P2P_CODEX_CONFIRM_RATE",
  "P2P_CODEX_QUEUE",
  "P2P_CODEX_BIN",
  "P2P_CODEX_META_LOG",
  "P2P_BIN",
  "P2P_HOME",
  "P2P_RELAY_TRANSPORT",
  "P2P_DEFAULT_RELAYS",
  // The Ix CLI ext-ix runs (`$IX_BIN impact …`): a project-set /bin/sh would run the repo's scripts.
  "IX_BIN",
] as const;

/** Knobs that only tighten: honoured from the environment too. */
export const TIGHTEN_ONLY = ["P2P_SHARE_STATUS", "IX_PEERS_SHARE_STATUS"] as const;

export type Env = Record<string, string | undefined>;

/** Where nothing trusted may live: temp folders, Codex-granted folders, the project. */
export type Where = {
  projectDirs: readonly string[];
  temp: readonly string[];
  granted?: readonly string[];
  /** The person's home folder (default userHome): a project dir that is exactly it doesn't cover ~/.codex or ~/.p2p. */
  home?: string;
};

/** The default P2P home's folder name under the person's home. */
export const DEFAULT_P2P_DIR = ".p2p";

// ── a small TOML reader, for one table ──────────────────────────────────────

type Scanner = { s: string; i: number };

function skipWs(sc: Scanner): void {
  while (sc.i < sc.s.length && (sc.s[sc.i] === " " || sc.s[sc.i] === "\t")) sc.i++;
}

function readKey(sc: Scanner): string[] | null {
  const parts: string[] = [];
  for (;;) {
    skipWs(sc);
    const c = sc.s[sc.i];
    if (c === '"' || c === "'") {
      const v = readString(sc);
      if (v === null) return null;
      parts.push(v);
    } else {
      const m = /^[A-Za-z0-9_-]+/.exec(sc.s.slice(sc.i));
      if (!m) return null;
      parts.push(m[0]);
      sc.i += m[0].length;
    }
    skipWs(sc);
    if (sc.s[sc.i] === ".") {
      sc.i++;
      continue;
    }
    return parts;
  }
}

function readString(sc: Scanner): string | null {
  const q = sc.s[sc.i];
  if (q === "'") {
    const end = sc.s.indexOf("'", sc.i + 1);
    if (end < 0) return null;
    const v = sc.s.slice(sc.i + 1, end);
    sc.i = end + 1;
    return v;
  }
  if (q !== '"') return null;
  let out = "";
  for (let j = sc.i + 1; j < sc.s.length; j++) {
    const c = sc.s[j] as string;
    if (c === '"') {
      sc.i = j + 1;
      return out;
    }
    if (c === "\n") return null;
    if (c !== "\\") {
      out += c;
      continue;
    }
    const e = sc.s[++j];
    const simple: Record<string, string> = { '"': '"', "\\": "\\", n: "\n", t: "\t", r: "\r", b: "\b", f: "\f" };
    if (e !== undefined && simple[e] !== undefined) out += simple[e];
    else if (e === "u" || e === "U") {
      const len = e === "u" ? 4 : 8;
      const hex = sc.s.slice(j + 1, j + 1 + len);
      if (!/^[0-9A-Fa-f]+$/.test(hex) || hex.length !== len) return null;
      out += String.fromCodePoint(parseInt(hex, 16));
      j += len;
    } else return null;
  }
  return null;
}

/** A scalar value as a string (strings, numbers, booleans); null for anything else. */
function readScalar(sc: Scanner): string | null {
  skipWs(sc);
  const c = sc.s[sc.i];
  if (c === '"' || c === "'") {
    if (sc.s.startsWith('"""', sc.i) || sc.s.startsWith("'''", sc.i)) return null;
    return readString(sc);
  }
  const m = /^[A-Za-z0-9_.+:-]+/.exec(sc.s.slice(sc.i));
  if (!m) return null;
  sc.i += m[0].length;
  return m[0];
}

function readInlineTable(sc: Scanner, into: (key: string[], value: string) => void): boolean {
  if (sc.s[sc.i] !== "{") return false;
  sc.i++;
  for (;;) {
    skipWs(sc);
    if (sc.s[sc.i] === "}") {
      sc.i++;
      return true;
    }
    const key = readKey(sc);
    if (!key) return false;
    skipWs(sc);
    if (sc.s[sc.i] !== "=") return false;
    sc.i++;
    skipWs(sc);
    if (sc.s[sc.i] === "{") {
      if (!readInlineTable(sc, (k, v) => into([...key, ...k], v))) return false;
    } else {
      const v = readScalar(sc);
      if (v === null) return false;
      into(key, v);
    }
    skipWs(sc);
    if (sc.s[sc.i] === ",") sc.i++;
  }
}

/** Where a scan stands across lines: open brackets/braces, and an open string (multi-line ones span lines). */
type Tail = { depth: number; quote: '"' | "'" | '"""' | "'''" | null; bad: boolean };

/**
 * Scans `s` (the rest of a value, or a whole line inside one) from `state`:
 * strings of all four kinds (so a `"""` or `'''` string's contents are
 * never read as TOML), comments, and `[`/`{` nesting. A single-line string
 * left open at the end of a line marks the text malformed.
 */
function scanTail(s: string, state: Tail): Tail {
  const st = { ...state };
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (st.quote === '"""' || st.quote === "'''") {
      if (st.quote === '"""' && c === "\\") i++;
      else if (s.startsWith(st.quote, i)) {
        // A closing delimiter may carry up to two more quote characters (part of the string).
        let j = i + 3;
        while (j < s.length && j < i + 5 && s[j] === st.quote[0]) j++;
        i = j - 1;
        st.quote = null;
      }
      continue;
    }
    if (st.quote) {
      if (c === "\\" && st.quote === '"') i++;
      else if (c === st.quote) st.quote = null;
      continue;
    }
    if (s.startsWith('"""', i) || s.startsWith("'''", i)) {
      st.quote = s.slice(i, i + 3) as Tail["quote"];
      i += 2;
    } else if (c === '"' || c === "'") st.quote = c;
    else if (c === "#") break;
    else if (c === "[" || c === "{") st.depth++;
    else if (c === "]" || c === "}") st.depth--;
  }
  if (st.quote === '"' || st.quote === "'") {
    st.bad = true;
    st.quote = null;
  }
  return st;
}

const isOpen = (t: Tail) => t.depth > 0 || t.quote !== null;

/**
 * The string values under `table` (a dotted path such as
 * `mcp_servers.peer2peer.env`) in a TOML document: from `[table]`, from an
 * inline `env = { … }` in the parent table, and from dotted keys. Only what
 * Codex's config can hold there (string values) is read; null when the text
 * can't be read with confidence (the caller then trusts nothing from it).
 * Values that span lines (multi-line strings, arrays, inline tables) are
 * skipped whole, so their contents are never read as keys; one under our
 * table means null.
 */
export function readTomlTable(text: string, table: string[], touched?: () => void): Record<string, string> | null {
  const out: Record<string, string> = {};
  const isPrefix = (a: readonly string[], b: readonly string[]) => a.length <= b.length && a.every((x, i) => x === b[i]);
  const take = (full: string[], value: string) => {
    if (isPrefix(table, full)) touched?.();
    if (full.length === table.length + 1 && isPrefix(table, full)) out[full[table.length] as string] = value;
  };
  let current: string[] = [];
  // Inside a value of some other key that spans lines.
  let tail: Tail = { depth: 0, quote: null, bad: false };
  for (const raw of text.split(/\r?\n/)) {
    if (isOpen(tail)) {
      tail = scanTail(raw, tail);
      if (tail.bad || tail.depth < 0) return null;
      continue;
    }
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    if (line.startsWith("[")) {
      const isArray = line.startsWith("[[");
      const hsc: Scanner = { s: line, i: isArray ? 2 : 1 };
      const key = readKey(hsc);
      if (!key || !line.slice(hsc.i).startsWith(isArray ? "]]" : "]")) return null;
      const after = scanTail(line.slice(hsc.i + (isArray ? 2 : 1)), tail);
      if (after.bad || after.depth !== 0 || after.quote !== null) return null;
      if (isPrefix(table, key)) touched?.();
      // An array of tables never holds our table.
      current = isArray ? ["\u0000"] : key;
      continue;
    }
    const sc: Scanner = { s: raw, i: 0 };
    const key = readKey(sc);
    if (!key) return null;
    skipWs(sc);
    if (sc.s[sc.i] !== "=") return null;
    sc.i++;
    skipWs(sc);
    const full = [...current, ...key];
    const relevant = isPrefix(full, table) || isPrefix(table, full);
    const valueAt = sc.i;
    const rest = scanTail(sc.s.slice(valueAt), tail);
    if (rest.bad || rest.depth < 0) return null;
    if (isOpen(rest)) {
      // A value spanning lines: never ours to read; skipped whole when it isn't under our table.
      if (relevant) return null;
      tail = rest;
      continue;
    }
    const c = sc.s[valueAt];
    if (sc.s.startsWith('"""', valueAt) || sc.s.startsWith("'''", valueAt)) {
      if (relevant) return null;
      continue;
    }
    if (c === "{") {
      if (!readInlineTable(sc, (k, v) => take([...full, ...k], v)) && relevant) return null;
      continue;
    }
    if (c === "[") {
      if (relevant && full.length >= table.length + 1) return null;
      continue;
    }
    const v = readScalar(sc);
    if (v === null) {
      if (relevant) return null;
      continue;
    }
    if (relevant) take(full, v);
  }
  if (isOpen(tail)) return null;
  return out;
}

/**
 * Whether a TOML document sets anything under `table` (a header, a key, an
 * inline table, a value spanning lines), matched on decoded keys (quoted,
 * literal and \u-escaped spellings alike). Fails closed: true whenever the
 * text can't be read with confidence, for any reason (a value the reader
 * doesn't take, such as a `"""` string or an array under the table, or text
 * it can't parse at all).
 */
export function touchesTable(text: string, table: string[]): boolean {
  let hit = false;
  const r = readTomlTable(text, table, () => (hit = true));
  return hit || r === null;
}

// ── the policy ──────────────────────────────────────────────────────────────

/** The parent process's value of `name`, where the OS shows it (Linux /proc, macOS ps -E); undefined when it can't be told. */
export async function parentEnvValue(name: string, ppid: number = process.ppid): Promise<string | undefined | null> {
  try {
    if (process.platform === "linux") {
      const raw = await readFile(`/proc/${ppid}/environ`, "utf8");
      for (const entry of raw.split("\0")) if (entry.startsWith(`${name}=`)) return entry.slice(name.length + 1);
      return null; // readable, and not set
    }
    if (process.platform === "darwin") {
      const ps = (args: string[]) =>
        new Promise<string>((resolve, reject) =>
          execFile("/bin/ps", [...args, "-ww", "-o", "command=", "-p", String(ppid)], { timeout: 3_000, maxBuffer: 4_000_000, env: safeExecEnv() }, (e, so) => (e ? reject(e) : resolve(String(so)))),
        );
      const [withEnv, command] = await Promise.all([ps(["-E"]), ps([])]);
      return envFromPs(withEnv, command, name);
    }
  } catch {}
  return undefined;
}

/**
 * The working folder of Codex itself (this server's parent), where the OS
 * shows it (Linux /proc, macOS lsof): a project config can move the
 * server's own cwd (`mcp_servers.peer2peer.cwd`), not Codex's.
 */
export async function parentCwd(ppid: number = process.ppid): Promise<string | undefined> {
  try {
    if (process.platform === "linux") return await readlink(`/proc/${ppid}/cwd`);
    if (process.platform === "darwin") {
      const out = await new Promise<string>((resolve, reject) =>
        execFile("/usr/sbin/lsof", ["-a", "-p", String(ppid), "-d", "cwd", "-Fn"], { timeout: 3_000, maxBuffer: 1_000_000, env: safeExecEnv() }, (e, so) => (e ? reject(e) : resolve(String(so)))),
      );
      const line = out.split("\n").find((l) => l.startsWith("n/"));
      return line ? line.slice(1) : undefined;
    }
  } catch {}
  return undefined;
}

/**
 * One variable from macOS `ps -E -o command=` output, given the plain
 * `ps -o command=` output of the same process: ps appends the environment
 * after the command and its arguments, so only what follows that prefix is
 * read (a ` CODEX_HOME=` in an argument never counts). A value runs to the
 * next ` NAME=` or the end, so paths with spaces survive. undefined ("can't
 * tell") when the prefix doesn't match, the environment is hidden (no HOME=;
 * macOS hides it for platform binaries such as /bin/sh), or the variable
 * appears more than once; null when it is plainly not set.
 */
export function envFromPs(withEnv: string, command: string, name: string): string | undefined | null {
  const full = withEnv.replace(/\r?\n$/, "");
  const cmd = command.replace(/\r?\n$/, "");
  if (cmd === "" || !full.startsWith(cmd)) return undefined;
  const envPart = full.slice(cmd.length);
  if (envPart !== "" && !envPart.startsWith(" ")) return undefined;
  // Each ` NAME=` starts a variable; the text up to the next one is its value.
  const starts = [...envPart.matchAll(/ ([A-Za-z_][A-Za-z0-9_]*)=/g)];
  if (!starts.some((m) => m[1] === "HOME")) return undefined;
  const hits = starts.map((m, i) => ({ m, i })).filter(({ m }) => m[1] === name);
  if (hits.length === 0) return null;
  // Another value holding ` NAME=` can't be told from the variable itself: can't tell.
  if (hits.length > 1 || envPart.split(` ${name}=`).length - 1 !== 1) return undefined;
  const { m, i } = hits[0] as { m: RegExpExecArray; i: number };
  const from = m.index + m[0].length;
  const next = starts[i + 1];
  return envPart.slice(from, next ? next.index : envPart.length);
}

// ── running other programs ──────────────────────────────────────────────────

/**
 * P2P_* variables a child never gets: they load code (extensions), point
 * the CLI at other files, or change what this session tells peers
 * (P2P_STATUS_CAPS, review L2: which status fields go on the wire), and a
 * project config can set them in the server's env. (The guarded knobs come
 * from the user-level config; status caps from `"statusCaps"` in the p2p
 * home's config.json.)
 */
export const CHILD_P2P_DENY = ["P2P_EXTENSION_PATH", "P2P_EXTENSIONS", "P2P_EXTENSION_EXCLUDE", "P2P_DEFAULTS_FILE", "P2P_WRITE_VECTORS", "P2P_GO_VECTORS", "P2P_STATUS_CAPS"] as const;

/** Exact names (besides P2P_* and LC_*) a child may get from the bridge's env. */
const CHILD_ALLOW = ["LANG", "TZ", "TERM"];

function isRegularFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}
const CHILD_ALLOW_WIN = ["SYSTEMROOT", "APPDATA", "LOCALAPPDATA"];

/**
 * The environment for the programs the bridge runs (`p2p`, `p2p watch`,
 * `codex queue`), built from an allowlist: a fixed PATH (the node running
 * this server, then the system folders), HOME (USERPROFILE on Windows)
 * from the user database, P2P_* (minus CHILD_P2P_DENY), LANG, LC_*, TZ,
 * TERM, and SYSTEMROOT/APPDATA/LOCALAPPDATA on Windows, plus `extra`.
 * Nothing else: no NODE_OPTIONS, NODE_TLS_REJECT_UNAUTHORIZED, proxies,
 * NODE_ICU_DATA, GCONV_PATH, LD_* or DYLD_*. Names compare
 * case-insensitively, as on Windows.
 */
export function childEnv(env: Env, extra: Env = {}): NodeJS.ProcessEnv {
  const win = process.platform === "win32";
  const deny = new Set<string>(CHILD_P2P_DENY);
  const exact = new Set<string>([...CHILD_ALLOW, ...(win ? CHILD_ALLOW_WIN : [])]);
  const out: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(env)) {
    if (v === undefined) continue;
    const K = k.toUpperCase();
    if ((K.startsWith("P2P_") && !deny.has(K)) || K.startsWith("LC_") || exact.has(K)) out[k] = v;
    // ext-ix runs the Ix CLI from IX_BIN (validated by effectiveEnv): passed on only as an absolute path to a regular file.
    else if (K === "IX_BIN" && isAbsolute(v) && isRegularFile(v)) out[k] = v;
  }
  out.PATH = [dirname(process.execPath), ...SAFE_PATH_DIRS].join(delimiter);
  if (win) out.USERPROFILE = userHome();
  else out.HOME = userHome();
  for (const [k, v] of Object.entries(extra)) if (v !== undefined) out[k] = v;
  return out;
}

/** System folders only: never the PATH a project config may have put in the server's env. */
export const SAFE_PATH_DIRS = process.platform === "win32" ? [] : ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

/**
 * A scrubbed environment for helper programs (git, ps, lsof, ss, getconf):
 * a fixed system PATH, the person's home from the user database, and
 * nothing else (no GIT_*, no project-set PATH, no LD_* or DYLD_*).
 */
export function safeExecEnv(): NodeJS.ProcessEnv {
  if (process.platform === "win32") {
    const sys = process.env.SystemRoot ?? "C:\\Windows";
    return { SystemRoot: sys, PATH: join(sys, "System32"), USERPROFILE: userHome() };
  }
  return { PATH: SAFE_PATH_DIRS.join(":"), HOME: userHome(), LC_ALL: "C" };
}

/**
 * A program by absolute path, looked up in fixed folders (the system ones,
 * then `extra`), never through the environment's PATH; undefined when none
 * has it.
 */
export function safeBinary(name: string, extra: readonly string[] = []): string | undefined {
  const dirs = process.platform === "win32" ? extra : [...SAFE_PATH_DIRS, ...extra];
  const names = process.platform === "win32" ? [`${name}.exe`, `${name}.cmd`] : [name];
  for (const d of dirs) {
    for (const n of names) {
      const p = join(d, n);
      try {
        if (statSync(p).isFile()) return p;
      } catch {}
    }
  }
  return undefined;
}

/** git by absolute path: the system's, else Homebrew's or /usr/local's, else Git for Windows'. */
export function gitBinary(): string | undefined {
  return safeBinary("git", process.platform === "win32" ? ["C:\\Program Files\\Git\\cmd", "C:\\Program Files\\Git\\bin"] : ["/opt/homebrew/bin", "/usr/local/bin"]);
}

/**
 * Folders an installed `codex` usually lives in (npm, Homebrew, cargo, a
 * user bin), for a bare `codex` when P2P_CODEX_BIN isn't an absolute path.
 */
export function codexBinDirs(home: string = userHome()): string[] {
  return ["/opt/homebrew/bin", "/usr/local/bin", join(home, ".local", "bin"), join(home, ".cargo", "bin"), join(home, ".npm-global", "bin"), join(home, ".bun", "bin"), join(home, ".volta", "bin")];
}

// ── where settings and trusted files may live ───────────────────────────────

/**
 * The person's home folder from the user database, never $HOME (a project
 * config can set HOME in the server's env, which would move ~/.codex,
 * the P2P home and the pin file).
 */
export function userHome(): string {
  try {
    const h = userInfo().homedir;
    if (h) return h;
  } catch {}
  return homedir();
}

/** Why the environment's HOME (USERPROFILE on Windows) isn't the person's home folder; undefined when it is or isn't set. */
export function homeRefusal(env: Env, home: string = userHome()): string | undefined {
  const name = process.platform === "win32" ? "USERPROFILE" : "HOME";
  const v = env[name]?.trim();
  if (!v || samePath(v, home) || samePath(realish(v), realish(home))) return undefined;
  return `${name}=${v} isn't your home folder (${home}); a project config may have set it`;
}

let darwinTemp: string | null | undefined;

/** macOS's per-user temp folder (/var/folders/…/T) from confstr, never from TMPDIR; undefined elsewhere. */
export function darwinUserTempDir(): string | undefined {
  if (process.platform !== "darwin") return undefined;
  if (darwinTemp === undefined) {
    try {
      darwinTemp = execFileSync("/usr/bin/getconf", ["DARWIN_USER_TEMP_DIR"], { encoding: "utf8", timeout: 3_000, env: {}, stdio: ["ignore", "pipe", "ignore"] }).trim() || null;
    } catch {
      darwinTemp = null;
    }
  }
  return darwinTemp ?? undefined;
}

/**
 * Folders anyone, or a sandboxed command, can write: the system temp
 * folders and the person's own (macOS confstr, Windows' AppData\Local\Temp),
 * which TMPDIR can't take away. TMPDIR values given (and os.tmpdir()) are
 * added too: they only ever add folders.
 */
export function tempRoots(tmp?: readonly (string | undefined)[]): string[] {
  const out = ["/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/dev/shm", darwinUserTempDir(), ...(process.platform === "win32" ? [join(userHome(), "AppData", "Local", "Temp")] : []), tmpdir(), ...(tmp ?? [])];
  return [...new Set(out.map((d) => d?.trim()).filter((d): d is string => !!d))];
}

/** Folders Codex itself lets the sandbox write under a Codex home (its memories), for each Codex home given and ~/.codex. */
export function codexGranted(codexHomes: readonly string[], home: string = userHome()): string[] {
  return [...new Set([...codexHomes, join(home, ".codex")].flatMap((h) => [join(h, "memories"), join(h, "memories_v2")]))];
}

/**
 * An absolute path with symlinks resolved (macOS's /var is /private/var, and
 * git reports the resolved toplevel). A file not written yet resolves by its
 * folder.
 */
export function realish(path: string): string {
  try {
    return realpathSync.native(path);
  } catch {
    try {
      return join(realpathSync.native(dirname(path)), basename(path));
    } catch {
      return path;
    }
  }
}

/**
 * Why `path` lies where a project config or a sandboxed command could put
 * files (a temp folder, the project), symlinks resolved on both sides; else
 * undefined.
 */
export function unsafeLocation(path: string, o: Where): string | undefined {
  const paths = [path, realish(path)];
  const home = o.home ?? userHome();
  // The person's own config folders aren't project files when the project is the home folder itself (cwd = ~).
  const own = [join(home, ".codex"), join(home, DEFAULT_P2P_DIR)].flatMap((d) => [d, realish(d)]);
  const isOwn = paths.some((p) => own.some((d) => isInside(p, d)));
  const check = (roots: readonly string[], what: string, skipHome = false) => {
    for (const r of roots) {
      if (skipHome && isOwn && isHomeFolder(r, home)) continue;
      for (const root of [r, realish(r)]) for (const p of paths) if (isInside(p, root)) return `${p} is inside ${what} ${root}`;
    }
    return undefined;
  };
  return check(o.temp, "the temp folder") ?? check(o.granted ?? [], "a folder Codex lets the sandbox write,") ?? check(o.projectDirs, "the project", true);
}

/**
 * Why a folder (and its config.toml, when there) may hold someone else's
 * files: not a folder, not this user's, or world-writable; else undefined.
 * A symlinked config.toml (stow, chezmoi, Nix) is judged by its target: a
 * regular file outside temp folders, Codex-granted folders and the project
 * (`where`), owned by the person (or by root, as in /nix/store), and
 * writable by no group or others. A missing folder counts only without
 * `allowMissing`.
 */
export function notPrivate(dir: string, o: { allowMissing?: boolean; where?: Where } = {}): string | undefined {
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  let st;
  try {
    st = statSync(dir);
  } catch {
    return o.allowMissing ? undefined : `${dir} doesn't exist`;
  }
  const bad = (p: string, s: { uid: number; mode: number }) => {
    if (uid !== undefined && s.uid !== uid) return `${p} isn't owned by you`;
    if (process.platform !== "win32" && (s.mode & 0o002) !== 0) return `${p} is world-writable`;
    return undefined;
  };
  if (!st.isDirectory()) return `${dir} isn't a folder`;
  const d = bad(dir, st);
  if (d) return d;
  const config = join(dir, "config.toml");
  let cst;
  try {
    cst = lstatSync(config);
  } catch {
    return undefined;
  }
  if (!cst.isSymbolicLink()) return bad(config, cst);
  let target: string;
  let tst;
  try {
    target = realpathSync.native(config);
    tst = statSync(target);
  } catch {
    return `${config} is a symbolic link to nothing readable`;
  }
  if (!tst.isFile()) return `${config} links to ${target}, which isn't a regular file`;
  const where = o.where ? unsafeLocation(target, o.where) : undefined;
  if (where) return `${config} links to ${target}: ${where}`;
  if (uid !== undefined && tst.uid !== uid && tst.uid !== 0) return `${config} links to ${target}, which isn't owned by you (or root)`;
  if (process.platform !== "win32" && (tst.mode & 0o022) !== 0) return `${config} links to ${target}, which a group or others can write`;
  // Every folder above the target: someone else could swap the file otherwise.
  const above = foldersAboveProblem(target);
  return above ? `${config} links to ${target}, and ${above}` : undefined;
}

/**
 * Why someone other than the person (or root) could replace `file`: a
 * folder above it isn't owned by the person or root, or is group- or
 * world-writable without the sticky bit; else undefined. `file` is taken as
 * resolved (no symlinks on its path). Not checked on Windows.
 */
export function foldersAboveProblem(file: string): string | undefined {
  if (process.platform === "win32") return undefined;
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  for (let d = dirname(file); ; d = dirname(d)) {
    let ds;
    try {
      ds = lstatSync(d);
    } catch {
      return `${d} can't be checked`;
    }
    if (uid !== undefined && ds.uid !== uid && ds.uid !== 0) return `${d} isn't owned by you (or root)`;
    if ((ds.mode & 0o022) !== 0 && (ds.mode & 0o1000) === 0) return `${d} is group- or world-writable without the sticky bit`;
    if (dirname(d) === d) break;
  }
  return undefined;
}

/**
 * The CODEX_HOMEs `p2p codex install --write` pinned, one per line, in a
 * file at a fixed place outside any project (codex/codex-homes in the
 * default P2P home, with ~ from the user database): not under the
 * environment's P2P_HOME or HOME, which a project config can set too.
 */
export function pinFile(home: string = userHome()): string {
  return join(home, DEFAULT_P2P_DIR, "codex", "codex-homes");
}

/** Why a folder on the pin file's path may be someone else's: a symlink, not a folder, not this user's, or group/world-writable. */
function pinDirProblem(dir: string): string | undefined {
  let st;
  try {
    st = lstatSync(dir);
  } catch {
    return `${dir} doesn't exist`;
  }
  if (st.isSymbolicLink() || !st.isDirectory()) return `${dir} isn't a real folder`;
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  if (uid !== undefined && st.uid !== uid) return `${dir} isn't owned by you`;
  if (process.platform !== "win32" && (st.mode & 0o022) !== 0) return `${dir} is group- or world-writable`;
  return undefined;
}

const NOFOLLOW = fsConstants.O_NOFOLLOW ?? 0;

/**
 * The pinned CODEX_HOMEs: only from a regular file of this user that nobody
 * else can write, opened without following a symlink and checked on the
 * open descriptor, in folders (the P2P home and its codex/) of this user
 * that nobody else can write; [] otherwise.
 */
export function readPins(file: string = pinFile()): string[] {
  if (pinDirProblem(dirname(file)) || pinDirProblem(dirname(dirname(file)))) return [];
  let fd: number | undefined;
  try {
    fd = openSync(file, fsConstants.O_RDONLY | NOFOLLOW);
    const st = fstatSync(fd);
    if (!st.isFile()) return [];
    const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
    if (uid !== undefined && st.uid !== uid) return [];
    if (process.platform !== "win32" && (st.mode & 0o022) !== 0) return [];
    return readFileSync(fd, "utf8")
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l !== "" && !l.startsWith("#"));
  } catch {
    return [];
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

const samePath = (a: string, b: string) => isInside(a, b) && isInside(b, a);

/**
 * Records (or with `remove`, drops) a CODEX_HOME in the pin file; the
 * person's `p2p codex install --write` only. Its folders are made (or
 * tightened to) 0700; the new file is written through a fresh temp file
 * (O_EXCL, no symlink followed) and renamed into place.
 */
export function writePin(codexHome: string, o: { file?: string; remove?: boolean } = {}): boolean {
  const file = o.file ?? pinFile();
  for (const dir of [dirname(dirname(file)), dirname(file)]) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    if (lstatSync(dir).isSymbolicLink()) throw new Error(`${dir} is a symbolic link: not writing the CODEX_HOME pin there`);
    if (process.platform !== "win32") chmodSync(dir, 0o700);
  }
  const pins = readPins(file);
  const has = pins.some((p) => samePath(p, codexHome));
  if (o.remove ? !has : has) return false;
  const next = o.remove ? pins.filter((p) => !samePath(p, codexHome)) : [...pins, codexHome];
  const tmp = `${file}.tmp-${process.pid}-${randomBytes(6).toString("hex")}`;
  const fd = openSync(tmp, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | NOFOLLOW, 0o600);
  try {
    writeFileSync(fd, ["# CODEX_HOMEs `p2p codex install --write` set up; the Codex bridge trusts no other when it can't read Codex's own environment.", ...next, ""].join("\n"));
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, file);
  return true;
}

// ── the policy ──────────────────────────────────────────────────────────────

export type EffectiveEnv = {
  env: Env;
  codexHome: string;
  /** `cwd` in the user-level `[mcp_servers.peer2peer]` table, when set (the person moved the server on purpose). */
  serverCwd?: string;
  /** The P2P_HOME the bridge uses (also set in `env`, so every `p2p` it runs uses it, whatever HOME says). */
  p2pHome: string;
  warnings: string[];
  /** Why the bridge must hold everything and refuse every release (see locationPolicy), or undefined. */
  refusal?: string;
};

/**
 * The environment the bridge (and every `p2p` it runs) uses: guarded knobs
 * from the user-level config only, tighten-only knobs from either place,
 * everything else as given.
 */
export async function effectiveEnv(o: {
  env: Env;
  /** The project a project config lives in (cwd, and the repo root when known). */
  projectDirs: readonly string[];
  readConfig?: (path: string) => Promise<string | null>;
  parentValue?: (name: string) => Promise<string | undefined | null>;
  home?: string;
  /** Temp folders (default: tempRoots with the environment's TMPDIR). */
  temp?: readonly string[];
  /** Why a CODEX_HOME folder isn't private to this user (default notPrivate). */
  privacy?: (dir: string, where?: Where) => string | undefined;
  /** The installer's pinned CODEX_HOMEs (default readPins). */
  pins?: () => string[];
  /** Folders whose `.codex/config.toml` is a project config Codex may merge (cwd up to the repo root). */
  projectConfigDirs?: readonly string[];
}): Promise<EffectiveEnv> {
  const warnings: string[] = [];
  const home = o.home ?? userHome();
  const defaultCodexHome = join(home, ".codex");
  const given = o.env.CODEX_HOME?.trim();
  let codexHome = defaultCodexHome;
  if (given && given !== defaultCodexHome) {
    const ignore = (why: string) => warnings.push(`ignored CODEX_HOME=${given}: ${why}; using ${defaultCodexHome}`);
    // Never a folder a project config or a sandboxed command could fill, whatever else says so.
    const refused = !isAbsolute(given)
      ? "not an absolute path"
      : (() => {
          const where: Where = { projectDirs: o.projectDirs, temp: o.temp ?? tempRoots([o.env.TMPDIR]), granted: codexGranted([given], home), home };
          return unsafeLocation(given, where) ?? (o.privacy ?? ((d: string, w?: Where) => notPrivate(d, w ? { where: w } : {})))(given, where);
        })();
    if (refused) ignore(refused);
    else {
      const parent = await (o.parentValue ?? parentEnvValue)("CODEX_HOME");
      if (parent !== undefined) {
        // The OS shows Codex's own environment: only its value counts.
        if (parent === given) codexHome = given;
        else ignore(`Codex itself runs with ${parent === null ? "the default" : parent}`);
      } else if ((o.pins ?? (() => readPins(pinFile(home))))().some((p) => samePath(p, given) || samePath(realish(p), realish(given)))) {
        // Codex's environment can't be read here (Windows, a non-dumpable Codex): only a CODEX_HOME the person's installer pinned.
        codexHome = given;
      } else {
        ignore(`Codex's own environment can't be read here, so only a CODEX_HOME that \`p2p codex install --write\` set up (pinned in ${pinFile(home)}) counts; run it with this CODEX_HOME in your own terminal`);
      }
    }
  }
  const readConfig = o.readConfig ?? ((p: string) => readFile(p, "utf8").catch(() => null));
  const text = await readConfig(join(codexHome, "config.toml"));
  let user: Record<string, string> = {};
  if (text !== null) {
    const parsed = readTomlTable(text, ["mcp_servers", "peer2peer", "env"]);
    if (parsed === null) warnings.push("couldn't read [mcp_servers.peer2peer.env] in the user-level config.toml with confidence: using defaults for the guarded settings");
    else user = parsed;
  }
  const env: Env = { ...o.env, CODEX_HOME: codexHome };
  for (const k of GUARDED_KNOBS) {
    const from = o.env[k];
    const want = user[k];
    if (from !== want && from !== undefined) warnings.push(`ignored ${k} from the environment: set it in [mcp_servers.peer2peer.env] in ${join(codexHome, "config.toml")} (a project config can't override it there)`);
    if (want === undefined) delete env[k];
    else env[k] = want;
  }
  for (const k of TIGHTEN_ONLY) if (o.env[k] === "0" || user[k] === "0") env[k] = "0";
  // IX_BIN (the Ix CLI ext-ix runs): a guarded knob, so only the user-level config's value (the loop
  // above already dropped an env value); and only a file nobody else can replace, outside the project.
  const ixBin = ixBinOf(user.IX_BIN, { projectDirs: o.projectDirs, temp: o.temp ?? tempRoots([o.env.TMPDIR]), granted: codexGranted([codexHome], home), home });
  if (ixBin.value) env.IX_BIN = ixBin.value;
  else delete env.IX_BIN;
  if (ixBin.warning) warnings.push(ixBin.warning);
  const p2pHome = env.P2P_HOME?.trim() || join(home, DEFAULT_P2P_DIR);
  env.P2P_HOME = p2pHome;
  const refusal = await locationPolicy({
    env: o.env,
    home,
    codexHome,
    p2pHome,
    projectDirs: o.projectDirs,
    temp: o.temp ?? tempRoots([o.env.TMPDIR]),
    privacy: o.privacy ?? ((d, where) => notPrivate(d, { allowMissing: true, ...(where ? { where } : {}) })),
    projectConfigDirs: o.projectConfigDirs ?? [],
    readConfig,
  });
  if (refusal) warnings.push(`holding every message and refusing every release: ${refusal}`);
  const serverCwd = text !== null ? readTomlTable(text, ["mcp_servers", "peer2peer"])?.cwd : undefined;
  return { env, codexHome, p2pHome, warnings, ...(refusal ? { refusal } : {}), ...(serverCwd ? { serverCwd } : {}) };
}

/**
 * IX_BIN, resolved (the real path is what is checked and forwarded), when
 * it is an absolute path to an existing regular file outside temp folders, Codex-granted folders and the project,
 * owned by the person or root, writable by no group or others, in folders
 * nobody else can write (foldersAboveProblem); else why not.
 */
export function ixBinOf(raw: string | undefined, where: Where): { value?: string; warning?: string } {
  const v = raw?.trim();
  if (!v) return {};
  if (!isAbsolute(v)) return { warning: `ignored IX_BIN=${v}: it must be an absolute path` };
  try {
    if (!statSync(v).isFile()) return { warning: `ignored IX_BIN=${v}: not a regular file` };
  } catch {
    return { warning: `ignored IX_BIN=${v}: no such file` };
  }
  const unsafe = unsafeLocation(v, where);
  if (unsafe) return { warning: `ignored IX_BIN=${v}: ${unsafe}` };
  const real = realish(v);
  // The resolved file too: a symlink in a safe folder may point into /tmp (sticky, so the folder walk passes).
  const unsafeReal = unsafeLocation(real, where);
  if (unsafeReal) return { warning: `ignored IX_BIN=${v}: it resolves to ${real}, and ${unsafeReal}` };
  let st;
  try {
    st = statSync(real);
  } catch {
    return { warning: `ignored IX_BIN=${v}: ${real} can't be checked` };
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  if (uid !== undefined && st.uid !== uid && st.uid !== 0) return { warning: `ignored IX_BIN=${v}: ${real} isn't owned by you (or root)` };
  if (process.platform !== "win32" && (st.mode & 0o022) !== 0) return { warning: `ignored IX_BIN=${v}: ${real} is writable by a group or others` };
  const above = foldersAboveProblem(real);
  if (above) return { warning: `ignored IX_BIN=${v}: ${above}` };
  // The path checked is the one forwarded: a symlink can't be repointed after the check.
  return { value: real };
}

/** Whether `dir` is the person's home folder itself (symlinks resolved). */
export function isHomeFolder(dir: string, home: string = userHome()): boolean {
  return samePath(dir, home) || samePath(realish(dir), realish(home));
}

/**
 * What Codex's own working folder says about the server's. Unknown (the OS
 * doesn't show it: Windows, lsof missing): the project can't be confirmed,
 * so releases are refused, with a warning. Known but different from the
 * server's cwd: a cwd override moved the server; unless the user-level
 * config set that cwd, a project config did, and the bridge holds
 * everything.
 */
export function cwdPolicy(o: { serverCwd: string; codexCwd: string | undefined; configuredCwd?: string | undefined }): { refusal?: string; releaseRefusal?: string; warning?: string } {
  const same = (a: string, b: string) => samePath(a, b) || samePath(realish(a), realish(b));
  if (o.codexCwd === undefined) {
    const releaseRefusal = "Codex's own working folder can't be read here, so the project this session works in can't be confirmed";
    return { releaseRefusal, warning: `refusing releases: ${releaseRefusal}` };
  }
  if (same(o.serverCwd, o.codexCwd)) return {};
  if (o.configuredCwd && same(o.serverCwd, o.configuredCwd)) return {};
  const refusal = `this server runs in ${o.serverCwd}, not in Codex's working folder ${o.codexCwd}, and the user-level config doesn't set that cwd (a project config may have moved it)`;
  return { refusal, warning: `holding every message and refusing every release: ${refusal}` };
}

/**
 * Why the bridge must hold everything and refuse every release, checked on
 * the EFFECTIVE Codex home and P2P_HOME every time (whether or not
 * CODEX_HOME was given): HOME isn't the person's home folder; either lies
 * in a temp folder, a folder Codex lets the sandbox write, or the project;
 * either isn't private to the person; or a project config touches
 * `mcp_servers.peer2peer` at all (a trusted project can replace this
 * server's command, args, cwd and env outright: Codex merges
 * `mcp_servers` from project layers).
 */
export async function locationPolicy(o: {
  env: Env;
  home: string;
  codexHome: string;
  p2pHome: string;
  projectDirs: readonly string[];
  temp: readonly string[];
  privacy: (dir: string, where?: Where) => string | undefined;
  projectConfigDirs: readonly string[];
  readConfig: (path: string) => Promise<string | null>;
}): Promise<string | undefined> {
  const h = homeRefusal(o.env, o.home);
  if (h) return h;
  const where = { projectDirs: o.projectDirs, temp: o.temp, granted: codexGranted([o.codexHome], o.home), home: o.home };
  for (const [name, dir] of [
    ["the Codex home", o.codexHome],
    ["P2P_HOME", o.p2pHome],
  ] as const) {
    const why = unsafeLocation(dir, where) ?? o.privacy(dir, where);
    if (why) return `${name} isn't safe: ${why}`;
  }
  return projectOverride(o.projectConfigDirs, o.codexHome, o.readConfig);
}

/**
 * Why a project config among `dirs` (each one's `.codex/config.toml`)
 * replaces or changes this server: it touches `mcp_servers.peer2peer` at
 * all. The person's own Codex home (cwd = ~) is the user layer, skipped.
 */
export async function projectOverride(dirs: readonly string[], codexHome: string, readConfig: (path: string) => Promise<string | null>): Promise<string | undefined> {
  for (const dir of dirs) {
    const codexDir = join(dir, ".codex");
    if (samePath(codexDir, codexHome) || samePath(realish(codexDir), realish(codexHome))) continue;
    const file = join(codexDir, "config.toml");
    const text = await readConfig(file);
    if (text !== null && touchesTable(text, ["mcp_servers", "peer2peer"])) return `the project config ${file} sets mcp_servers.peer2peer (a trusted project can replace this server)`;
  }
  return undefined;
}

/** The folders whose `.codex/config.toml` Codex reads as project layers for `cwd`: it and each parent up to the repo root (just `cwd` outside a repo). */
export function projectConfigDirsOf(cwd: string, top: string | undefined): string[] {
  const out = [cwd];
  if (!top || !isInside(cwd, top)) return out;
  let d = cwd;
  while (!samePath(d, top)) {
    const up = dirname(d);
    if (up === d) break;
    d = up;
    out.push(d);
  }
  return out;
}

/**
 * The P2P_HOME the bridges use, for the person's `p2p codex …` commands and
 * the hooks: the user-level config's value when it sets one (that's what the
 * bridge takes), else the environment's, else ~/.p2p.
 */
export function bridgeHome(env: Env, home: string = userHome()): string {
  const codexHome = env.CODEX_HOME?.trim() || join(home, ".codex");
  let fromConfig: string | undefined;
  try {
    fromConfig = readTomlTable(readFileSync(join(codexHome, "config.toml"), "utf8"), ["mcp_servers", "peer2peer", "env"])?.P2P_HOME?.trim();
  } catch {}
  return fromConfig || env.P2P_HOME?.trim() || join(home, DEFAULT_P2P_DIR);
}
