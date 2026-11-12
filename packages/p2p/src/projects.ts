// Copyright 2026 Ix Infrastructure Inc.
//
// Project boundaries (docs/concepts.md "Projects", threat model "Project boundaries").
//
//  - A project is a git repository, keyed by its normalised remote URL (if any) and its git
//    common dir, so every worktree and subfolder of one clone is the same project. Outside git,
//    the real path of the folder, or of the nearest folder above it whose share covers its
//    subfolders (opt-in: `p2p project share --subfolders`), never past a repository, a
//    `.p2p-private`, a folder with its own policy or a folder that is gone.
//  - Its policy lives only in this user's state (`<home>/cli/projects`): shared with circles and
//    named people, or private. A project with no policy is private: only this user's own devices
//    see its sessions. Nothing in a repository can widen that; a committed `.p2p-private` file at
//    the repository's top level can only make it private.
//  - Each session is bound to every project it has worked in (its directories, the files it
//    touched): sticky until the session ends. Its ceiling is the intersection of those projects'
//    policies, the most restrictive, so a session that touched a private project stays private.
//  - The ceiling caps the session's signed roster (sessions.ts getSession), so who sees its status,
//    footprints and summary, and who may message it, follows it everywhere a roster is checked: on
//    this device, on the user's other devices and at every peer, old clients included. Sends from a
//    session (messages, extension kinds, offline copies) are refused to anyone outside it.
//  - `p2p tui` and `p2p send` typed at a terminal with no --from-session are the person's own
//    session: never bound, no ceiling.

import { agentAncestor, isAgentProcess } from "./ancestry.js";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { type Dirent, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, readlinkSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, delimiter, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { circlePolicy, liveFriendshipsV3, loadCircle, sanitizePeerText, standsLookup } from "@peer2peer/core/v3";
import type { App } from "./app.js";
import { CliError } from "./errors.js";

/** The person's own terminal session (`p2p tui`, `p2p send` with no --from-session). */
export const PERSON_SESSION = "tui";

/** The committed file a repository may carry to ask for privacy (it can never widen anything). */
export const PRIVATE_MARKER = ".p2p-private";

/**
 * The directory a session works in, as the CLI sees it: P2P_WORKDIR when it names an existing
 * absolute directory (the Claude mod and the Codex bridge run p2p from elsewhere and pass the
 * session's folder there), else the process's own.
 */
export function sessionWorkdir(env: Record<string, string | undefined>): string {
  const w = env.P2P_WORKDIR?.trim();
  if (w && isAbsolute(w)) {
    try {
      if (statSync(w).isDirectory()) return w;
    } catch {
      // not there: the process's own
    }
  }
  return process.cwd();
}

/**
 * Every folder a session works in, as its front end tells the CLI: its working directory
 * (sessionWorkdir) and P2P_PROJECT_DIRS (path-delimited: folders it moved to, files it touched
 * elsewhere). Anyone may add to these: a binding only ever narrows who the session reaches.
 */
export function sessionDirs(env: Record<string, string | undefined>): { dirs: string[]; over: boolean; why: OverWhy[] } {
  const extra = (env.P2P_PROJECT_DIRS ?? "").split(delimiter).filter((x) => x.trim() !== "" && isAbsolute(x.trim()));
  // Past the cap (or when the front end says it dropped some): private, never "the first N".
  const why: OverWhy[] = extra.length > MAX_SESSION_DIRS ? ["folders"] : [];
  const said = env.P2P_PROJECT_DIRS_OVER?.trim() ?? "";
  if (said !== "" && said !== "0") why.push(...overWhys(said));
  return { dirs: [sessionWorkdir(env), ...extra.slice(0, MAX_SESSION_DIRS)], over: why.length > 0, why: [...new Set(why)] };
}

/**
 * Why a session went private for good, past a cap or a gap in what its front end saw:
 *  - `projects`: more than MAX_SESSION_PROJECTS projects;
 *  - `folders`: more folders than a front end or the CLI keeps (MAX_SESSION_DIRS per call);
 *  - `unresolved`: a path its front end couldn't resolve (a variable or `$(…)` it doesn't know, in the path's first segment);
 *  - `front`: its front end lost track (a forked conversation, a record it couldn't read; an older front end's bare "over");
 *  - `constraints`: more than MAX_SESSION_CONSTRAINTS bounds from own-session messages.
 */
export type OverWhy = "projects" | "folders" | "unresolved" | "front" | "constraints";
const OVER_WHYS: ReadonlySet<string> = new Set<OverWhy>(["projects", "folders", "unresolved", "front", "constraints"]);

/** A front end's over reasons (`unresolved,folders`, an array, or `1`/`true` from an older one): an unknown word counts as `front`, never as nothing. */
export function overWhys(v: unknown): OverWhy[] {
  const words = Array.isArray(v) ? v.map(String) : typeof v === "string" ? v.split(/[\s,]+/) : v === true ? ["front"] : [];
  const out = new Set<OverWhy>();
  for (const w of words.map((x) => x.trim().toLowerCase()).filter((x) => x !== "")) out.add(OVER_WHYS.has(w) ? (w as OverWhy) : "front");
  return [...out];
}

/** At most this many folders a front end passes per call; past it the session is private. */
export const MAX_SESSION_DIRS = 512;

/**
 * At most this many projects per session; past it the session is private. A storage bound only:
 * a session's ceiling is the intersection of all its projects' policies, so a higher cap never
 * lets a session reach anyone a smaller one wouldn't.
 */
export const MAX_SESSION_PROJECTS = 64;
/** Bindings of sessions not seen for this long are dropped. */
export const SESSION_BINDING_TTL_MS = 30 * 24 * 3600 * 1000;
/** At most this many circles and people in one project's policy. */
export const MAX_PROJECT_SHARES = 32;

export interface ProjectRef {
  /** `pj_` + 24 hex: a hash, so state never holds a remote URL's credentials or a path as a key. */
  id: string;
  /** A short display name (the repository or folder name). */
  name: string;
  kind: "git" | "dir";
  /** The working tree's top level (git) or the folder (dir), real path. */
  root: string;
  /** The normalised remote URL (no credentials), when the repository has one. */
  remote?: string;
  /** The repository asks to stay private (a committed PRIVATE_MARKER at `root`). */
  repoPrivate?: true;
  /** A `.git` is there but can't be read as a repository (a folder project at that level). */
  brokenGit?: true;
}

export type ProjectShare = "private" | { circles: string[]; people: string[] };

export interface ProjectPolicyRec {
  name: string;
  root: string;
  remote?: string;
  share: ProjectShare;
  /**
   * A folder project's share covers its subfolders too (`p2p project share --subfolders`). Without
   * it (every policy from before it), the policy is for that folder alone.
   */
  covers?: true;
  at: number;
}

export interface ProjectsDoc {
  v: 1;
  projects: Record<string, ProjectPolicyRec>;
  /** When this device showed the one-time notice that sessions no longer follow the default circle. */
  noticeAt?: number;
}

export interface SessionBinding {
  projects: Record<string, BoundProject>;
  /** Past a cap, or a path its front end couldn't resolve: private (overWhy says which; absent in bindings from before it). */
  over?: true;
  overWhy?: OverWhy[];
  /**
   * What other sessions of this user that sent to this one could reach (own-device messages carry
   * their sender's ceiling): intersected in, sticky, so a private session can't launder through a
   * shared one of yours.
   */
  constraints?: ProjectShare[];
  /** First used by an agent (agentContext) with no front end vouching for it: private until registered. */
  unregistered?: true;
  /** A front end holding the person token (personTokenOk) has used it. */
  registered?: true;
  /** When this binding began (ms): a session id bound anew (its old binding expired) starts again here (history.ts). */
  since?: number;
  at: number;
}

/** At most this many constraints a session keeps; past it, private. */
export const MAX_SESSION_CONSTRAINTS = 16;

export type SessionProjectsDoc = Record<string, SessionBinding>;

export interface BoundProject {
  name: string;
  /** Its folder (git: the working tree it was first seen in), for `p2p session show`. */
  root?: string;
  repoPrivate?: true;
  /**
   * Folders below `root` that a shared folder covered (dir projects only, at most MAX_UNDER): a
   * policy given to one of them later still narrows this session. `underOver`: more than that,
   * so any policy below `root` does.
   */
  under?: string[];
  underOver?: true;
}

/** At most this many covered subfolders a bound folder project remembers; past it, every policy below it counts. */
export const MAX_UNDER = 64;

/** What a session may reach. `none`: the person's own session, or one not bound yet. */
export type Ceiling = { kind: "none" } | { kind: "private"; why: string; causes: PrivateCause[]; blocking?: string[] } | { kind: "shared"; circles: string[]; people: string[] };

/**
 * Why a session is private: an over reason (OverWhy), `unregistered` (an agent named it, no front
 * end registered it), `repo-private` (`.p2p-private`), `private` (a project made private),
 * `unshared` (a project never shared), `sent-private` (a private session of yours sent it a
 * message), `disjoint` (its projects share nobody in common, or nobody you can reach).
 */
export type PrivateCause = OverWhy | "legacy-over" | "unregistered" | "repo-private" | "private" | "unshared" | "sent-private" | "disjoint";

/** Causes no share can lift: the session stays private until it ends. */
const STICKY: ReadonlySet<PrivateCause> = new Set<PrivateCause>(["projects", "folders", "unresolved", "front", "constraints", "legacy-over", "repo-private", "sent-private"]);

// ---------------------------------------------------------------------------
// Project identity

const sha = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");

/** The real path, with the case the file system stores (realpathSync.native), else as given. */
function real(p: string): string {
  try {
    return realpathSync.native(p);
  } catch {
    try {
      return realpathSync(p);
    } catch {
      return p;
    }
  }
}

/** Whether a path, as written, has a `..` segment (`a/../b`, `..`, `a/..`). */
export function hasDotDot(p: string): boolean {
  return p.split(/[\\/]/).includes("..");
}

/**
 * `p` as the file system walks it (POSIX): each existing prefix is resolved through its symlinks
 * before the next segment applies, so `link/../x` is the link's target's parent's `x`, never the
 * `x` beside the link (path.resolve collapses `..` as text). Past the first segment that doesn't
 * exist, the rest is applied as text. Relative paths start at the process's cwd. On Windows,
 * path.resolve.
 */
export function physicalPath(p: string): string {
  const abs = isAbsolute(p) ? p : `${process.cwd()}${sep}${p}`;
  if (process.platform === "win32") return resolve(abs);
  let cur = "/";
  for (const c of abs.split("/")) {
    if (c === "" || c === ".") continue;
    if (c === "..") {
      cur = dirname(cur);
      continue;
    }
    const next = cur === "/" ? `/${c}` : `${cur}/${c}`;
    try {
      lstatSync(next);
      cur = real(next);
    } catch {
      cur = next;
    }
  }
  return cur;
}

/** The nearest existing directory at or above `p` (walked as the file system does: physicalPath), as a real path. */
function existingDir(p: string): string {
  let cur = physicalPath(p);
  for (let i = 0; i < 4096; i++) {
    try {
      const st = statSync(cur);
      return real(st.isDirectory() ? cur : dirname(cur));
    } catch {
      const up = dirname(cur);
      if (up === cur) return cur;
      cur = up;
    }
  }
  return cur;
}

/** Device and pseudo-file roots: what is under them is never a project (POSIX). */
const PSEUDO_ROOTS = ["/dev", "/proc", "/sys"];

/**
 * Whether `p` is a device or pseudo file (`/dev/null`, `/dev/tty`, `/proc/self/status`), never a
 * project: it exists, isn't a folder, and its real path stays under /dev (and isn't a regular
 * file there, like one in /dev/shm), /proc or /sys. A path through /proc to a real file
 * (`/proc/self/cwd/x`, `/proc/<pid>/root/…`) resolves out of it and binds as usual; one that
 * doesn't exist binds its nearest existing parent as every path does.
 */
export function pseudoPath(p: string): boolean {
  if (process.platform === "win32" || typeof p !== "string" || !isAbsolute(p)) return false;
  // Named there, too: a link elsewhere (a repository's file that points at /dev/null) binds as its folder.
  const at = resolve(p);
  if (!PSEUDO_ROOTS.some((root) => at === root || at.startsWith(`${root}/`))) return false;
  let st: ReturnType<typeof statSync>;
  try {
    st = statSync(p);
  } catch {
    return false;
  }
  if (st.isDirectory()) return false;
  const r = real(p);
  const under = (root: string) => r === root || r.startsWith(`${root}/`);
  if (under("/dev")) return !st.isFile();
  return PSEUDO_ROOTS.slice(1).some(under);
}

/**
 * Whether a path component holds a brace expansion with a choice: a `{`, then `,` or `..` with no
 * brace between, then `}` (`{.git,x}`, `{a..z}`). One pass, so it stays linear on any input.
 */
export function braceChoice(c: string): boolean {
  let open = false;
  let choice = false;
  for (let i = 0; i < c.length; i++) {
    const ch = c[i];
    if (ch === "{") {
      open = true;
      choice = false;
    } else if (ch === "}") {
      if (open && choice) return true;
      open = false;
    } else if (open && (ch === "," || (ch === "." && c[i + 1] === "."))) choice = true;
  }
  return false;
}

/**
 * The folder holding the first path component that names a repository's marker (`.git`,
 * PRIVATE_MARKER) or could match one (a glob or brace pattern a dotfile can match: `.g*`,
 * `[.]git`, `{.git,x}`): a command naming it may remove it, so a shared folder above never
 * covers that folder (projectOf). Lexical, on the path as given.
 */
function namedStop(p: string): string | undefined {
  const parts = p.split(/[\\/]/);
  for (let i = 1; i < parts.length; i++) {
    const c = parts[i];
    const glob = ((c.startsWith(".") || c.startsWith("[")) && /[*?[]/.test(c)) || braceChoice(c);
    if (c === ".git" || c === PRIVATE_MARKER || glob) return parts.slice(0, i).join(sep) || sep;
  }
  return undefined;
}

/** Whether `p` is `dir` or below it (real paths, this platform's separator). */
function within(p: string, dir: string): boolean {
  if (p === dir) return true;
  const d = dir.endsWith(sep) ? dir : `${dir}${sep}`;
  return p.startsWith(d);
}

/** A folder project's id: its real path, hashed. */
export function dirProjectId(root: string): string {
  return `pj_${sha(`dir\n${root}`).slice(0, 24)}`;
}

/**
 * A remote URL as one canonical string: scheme, credentials, port-less ssh form, trailing `.git`
 * and slashes dropped, host lower-cased. `https://u:t@GitHub.com/a/b.git` and `git@github.com:a/b`
 * are both `github.com/a/b`. A local path stays a path.
 */
export function normalizeRemote(url: string): string | undefined {
  let u = url.trim();
  if (u === "" || u.length > 2048 || /[\0\n\r]/.test(u)) return undefined;
  let host: string;
  let path: string;
  const scheme = /^([a-z][a-z0-9+.-]*):\/\/(.*)$/i.exec(u);
  if (scheme) {
    const rest = scheme[2];
    if (scheme[1].toLowerCase() === "file") return u.replace(/^file:\/\//i, "").replace(/\/+$/, "").replace(/\.git$/, "") || undefined;
    const slash = rest.indexOf("/");
    host = slash < 0 ? rest : rest.slice(0, slash);
    path = slash < 0 ? "" : rest.slice(slash + 1);
    host = host.replace(/^.*@/, "").replace(/:\d+$/, "");
  } else {
    const scp = /^(?:[^@/:]+@)?([^/:]+):(.*)$/.exec(u);
    if (scp && !/^[A-Za-z]:[\\/]/.test(u)) {
      host = scp[1];
      path = scp[2];
    } else {
      u = u.replace(/\\/g, "/").replace(/\/+$/, "").replace(/\.git$/, "");
      return u || undefined;
    }
  }
  path = path.replace(/^\/+|\/+$/g, "").replace(/\.git$/, "").replace(/\/+$/, "");
  host = host.toLowerCase();
  return host ? `${host}/${path}` : undefined;
}

/** The remote URLs in a git config file's text: `origin` first, then the others in order. */
function remotesOf(config: string): string[] {
  const out: { name: string; url: string }[] = [];
  let section: string | undefined;
  for (const raw of config.split(/\r?\n/)) {
    const line = raw.trim();
    const sec = /^\[\s*remote\s+"([^"]*)"\s*\]$/.exec(line);
    if (sec) {
      section = sec[1];
      continue;
    }
    if (line.startsWith("[")) {
      section = undefined;
      continue;
    }
    const kv = /^url\s*=\s*(.*)$/.exec(line);
    if (section !== undefined && kv) out.push({ name: section, url: kv[1].replace(/^"|"$/g, "") });
  }
  out.sort((a, b) => Number(b.name === "origin") - Number(a.name === "origin"));
  return out.map((r) => r.url);
}

function readSmall(file: string): string | undefined {
  try {
    const st = statSync(file);
    if (!st.isFile() || st.size > 256 * 1024) return undefined;
    return readFileSync(file, "utf8");
  } catch {
    return undefined;
  }
}

/**
 * Whether `d` is a bare git repository: `HEAD`, `objects/` and `refs/` in it, or a `config` that
 * says `bare = true` (a folder named `.git` is a working tree's, found from its parent instead).
 */
function isBareRepo(d: string): boolean {
  if (basename(d) === ".git") return false;
  const st = (p: string) => {
    try {
      return statSync(p);
    } catch {
      return undefined;
    }
  };
  if (st(join(d, "HEAD"))?.isFile() && st(join(d, "objects"))?.isDirectory() && st(join(d, "refs"))?.isDirectory()) return true;
  return /^\s*bare\s*=\s*true\s*$/im.test(readSmall(join(d, "config")) ?? "");
}

/** The git project whose git dir is `gitDir`, found at the folder `root`. */
function gitRef(gitDir: string, root: string): ProjectRef {
  let common = gitDir;
  const cd = readSmall(join(gitDir, "commondir"))?.trim();
  if (cd) common = resolve(gitDir, cd);
  common = real(common);
  const urls = remotesOf(readSmall(join(common, "config")) ?? "");
  const remote = urls.map(normalizeRemote).find((x): x is string => x !== undefined);
  const main = basename(common) === ".git" ? dirname(common) : common;
  const name = clean(remote ? (remote.split("/").pop() ?? "") : basename(main)) || clean(basename(root)) || "project";
  return {
    id: `pj_${sha(`git\n${remote ?? ""}\n${common}`).slice(0, 24)}`,
    name,
    kind: "git",
    root,
    ...(remote ? { remote } : {}),
    ...(existsSync(join(root, PRIVATE_MARKER)) ? { repoPrivate: true as const } : {}),
  };
}

/** Whether `p` names something that is there, its trailing pattern parts (`*.log`, `{a,b}`) left out. */
function present(p: string): boolean {
  let q = resolve(p);
  while (/[*?[\]{}]/.test(basename(q)) && dirname(q) !== q) q = dirname(q);
  try {
    statSync(q);
    return true;
  } catch {
    return false;
  }
}

/**
 * The project `dir` belongs to, read from the files alone (git is never run: no hook, fsmonitor
 * or config of the repository's can execute). A `.git` directory or `gitdir:` file up the tree
 * marks a working tree; its common dir (`commondir` for a linked worktree) identifies the clone.
 * A bare repository (isBareRepo) is a git project too, and a `.git` that can't be read as one is
 * a folder project of its own.
 *
 * Outside git, a folder project. With `doc` (the policies), the nearest folder at or above `dir`
 * that has a policy of its own is the project when that is `dir`'s own folder, or when its share
 * covers subfolders (`covers`, given with `p2p project share --subfolders`; a policy without it
 * is for that folder alone, as before). The walk stops at the first folder with a policy (the
 * nearest one wins, so a private subfolder stays private; one that doesn't cover leaves `dir`'s
 * own folder as the project), and it never crosses:
 *  - a git repository (found first: a nested repository is always its own project);
 *  - a `.p2p-private` (at or above `dir`: the folder project is private, whatever covers it);
 *  - a folder whose `.git` or `.p2p-private` the path itself names (namedStop: a command that may
 *    have just removed it);
 *  - the nearest existing folder, when `dir` itself isn't there (deleted or moved since the
 *    session named it, or not made yet): that folder is the project unless it has a policy, so a
 *    repository removed after a session read it is never covered from above.
 * Without `doc` (sharing, `project show`): the folder itself.
 */
export function projectOf(dir: string, doc?: ProjectsDoc): ProjectRef {
  // As the file system walks it: `link/../x` is beside the link's target, not beside the link.
  const given = physicalPath(dir);
  const start = existingDir(given);
  let cur = start;
  for (let i = 0; i < 4096; i++) {
    const dotgit = join(cur, ".git");
    // Anything named .git here (a folder, a file, a symlink, even a broken or unreadable one) ends
    // the walk: this folder is its own project, never the parent repository's.
    let isThere: boolean;
    try {
      lstatSync(dotgit);
      isThere = true;
    } catch {
      isThere = false;
    }
    if (isThere) {
      let st: ReturnType<typeof statSync> | undefined;
      try {
        st = statSync(dotgit);
      } catch {
        st = undefined;
      }
      let gitDir: string | undefined;
      if (st?.isDirectory()) gitDir = dotgit;
      else if (st?.isFile()) {
        const m = /^gitdir:\s*(.+?)\s*$/m.exec(readSmall(dotgit) ?? "");
        if (m) gitDir = resolve(cur, m[1]);
      }
      if (!gitDir || !existsSync(gitDir)) {
        // A .git that can't be read as one: a folder project at this level (private until shared).
        return { id: dirProjectId(cur), name: clean(basename(cur)) || "folder", kind: "dir", root: cur, brokenGit: true };
      }
      return gitRef(gitDir, cur);
    }
    // A bare repository (a clone with no working tree): a git project, never a shared folder's.
    if (isBareRepo(cur)) return gitRef(cur, cur);
    const up = dirname(cur);
    if (up === cur) break;
    cur = up;
  }
  const dirRef = (root: string, repoPrivate: boolean): ProjectRef => ({ id: dirProjectId(root), name: clean(basename(root)) || "folder", kind: "dir", root, ...(repoPrivate ? { repoPrivate: true as const } : {}) });
  // A .p2p-private at or above the folder (no repository in between, or the walk above found it):
  // the folder is private, whatever a policy above says.
  let marked = false;
  for (let c = start, i = 0; i < 4096; i++) {
    if (existsSync(join(c, PRIVATE_MARKER))) {
      marked = true;
      break;
    }
    const up = dirname(c);
    if (up === c) break;
    c = up;
  }
  if (!doc || marked) return dirRef(start, marked);
  // The walk stops at a folder the path names a marker in (it may be gone now: never covered from
  // above), and at `start` itself when the path isn't there (only its nearest parent is).
  const named = namedStop(given);
  const ns = named === undefined ? undefined : existingDir(named);
  const stop = !present(given) ? start : ns === undefined ? undefined : within(start, ns) ? ns : start;
  for (let c = start, i = 0; i < 4096; i++) {
    const rec = doc.projects[dirProjectId(c)];
    if (rec) return c === start || rec.covers === true ? dirRef(c, false) : dirRef(start, false);
    if (c === stop) break;
    const up = dirname(c);
    if (up === c) break;
    c = up;
  }
  return dirRef(start, false);
}

const clean = (s: string) => sanitizePeerText(s, 64).replace(/[^\w.@+-]/g, "").slice(0, 64);

// ---------------------------------------------------------------------------
// Policies

export async function projectsDoc(app: App): Promise<ProjectsDoc> {
  const d = (await app.state.get("projects")) as ProjectsDoc | undefined;
  return d && d.v === 1 && d.projects && typeof d.projects === "object" ? d : { v: 1, projects: {} };
}

/** A project's share as stored, or `private` (no policy: private by default). */
export function shareOf(doc: ProjectsDoc, id: string): ProjectShare {
  const r = doc.projects[id];
  if (!r || r.share === "private" || typeof r.share !== "object") return "private";
  const circles = Array.isArray(r.share.circles) ? r.share.circles.filter((x) => typeof x === "string") : [];
  const people = Array.isArray(r.share.people) ? r.share.people.filter((x) => typeof x === "string") : [];
  return circles.length + people.length > 0 ? { circles, people } : "private";
}

export interface ProjectView {
  id: string;
  name: string;
  kind: "git" | "dir";
  root: string;
  remote?: string;
  /** Who it is shared with (`private`: only your own devices). */
  policy: "private" | "shared";
  circles: { cid: string; name?: string; open?: true; joined: boolean }[];
  people: { userId: string; address: string }[];
  /** Why it is private although a policy shares it, or `unmapped` when none does. */
  why?: string;
  repoPrivate?: true;
  /** A folder whose share covers its subfolders (`p2p project share --subfolders`). */
  covers?: true;
  /** Which Ix graph its work may reach (graphTarget): `local` (only this machine's) today. */
  graph: GraphTarget;
}

export async function projectView(app: App, ref: Pick<ProjectRef, "id" | "name" | "kind" | "root" | "remote" | "repoPrivate">, doc?: ProjectsDoc): Promise<ProjectView> {
  const d = doc ?? (await projectsDoc(app));
  const share = shareOf(d, ref.id);
  const circles: ProjectView["circles"] = [];
  const people: ProjectView["people"] = [];
  if (share !== "private") {
    for (const cid of share.circles) {
      const rec = await app.store.getCircle(cid);
      const c = await loadCircle(app.store, cid).catch(() => undefined);
      circles.push({ cid, ...(c ? { name: sanitizePeerText(c.chain.head.name, 64) } : {}), ...(c && circlePolicy(c.chain.head) === "open" ? { open: true as const } : {}), joined: rec?.joinedByMe === true });
    }
    for (const u of share.people) people.push({ userId: u, address: await app.addressOf(u) });
  }
  const policy = share === "private" || ref.repoPrivate ? "private" : "shared";
  const why = ref.repoPrivate ? `the repository asks to stay private (${PRIVATE_MARKER} at its top level)` : !d.projects[ref.id] ? "unmapped" : undefined;
  return {
    id: ref.id,
    name: ref.name,
    kind: ref.kind,
    root: ref.root,
    ...(ref.remote ? { remote: ref.remote } : {}),
    policy,
    circles,
    people,
    ...(why ? { why } : {}),
    ...(ref.repoPrivate ? { repoPrivate: true as const } : {}),
    ...(d.projects[ref.id]?.covers === true && ref.kind === "dir" ? { covers: true as const } : {}),
    graph: projectGraphTarget(app, ref, d),
  };
}

/**
 * Why `root` may not cover its subfolders (a share for it alone is still allowed), or undefined:
 * the file system's root, a home folder or a folder above one (`$HOME`, `/Users`, `/home/<u>`),
 * the temporary folders (`/tmp`, `/private/tmp`, `/var/folders/…`, os.tmpdir() and above it), and
 * the system's top folders. Everything below them would be one project.
 */
export function broadRoot(root: string, env: Record<string, string | undefined> = {}): string | undefined {
  const norm = (p: string) => {
    const r = resolve(p);
    return process.platform === "win32" ? r.toLowerCase() : r;
  };
  const forms = (p: string) => [...new Set([norm(p), norm(real(p))])];
  const at = forms(root);
  const isOrAbove = (dir: string | undefined) => !!dir && isAbsolute(dir) && forms(dir).some((d) => at.some((r) => within(d, r)));
  if (at.some((r) => dirname(r) === r)) return "the file system's root";
  const homes = [homedir(), env.HOME, env.USERPROFILE].filter((x): x is string => typeof x === "string" && x !== "");
  if (homes.some(isOrAbove)) return "a home folder (or a folder that holds one)";
  if (isOrAbove(tmpdir()) || isOrAbove(env.TMPDIR)) return "the temporary folder (or a folder that holds it)";
  for (const r of at) {
    const parts = r.split(/[\\/]+/).filter(Boolean);
    const top = (parts[0] ?? "").toLowerCase();
    if (!/^[a-z]:$/i.test(top) && parts.length === 1) return "a top-level system folder";
    if (/^[a-z]:$/i.test(parts[0] ?? "") && parts.length <= 2 && (parts.length === 1 || (parts[1] ?? "").toLowerCase() === "users")) return "a drive's root or its Users folder";
    if (/^[a-z]:$/i.test(parts[0] ?? "") && parts.length === 3 && (parts[1] ?? "").toLowerCase() === "users") return "a home folder";
    if (["home", "users"].includes(top) && parts.length <= 2) return "a home folder (or the folder that holds them)";
    if (top === "tmp" && parts.length === 1) return "the temporary folder";
    if (top === "private" && parts.length <= 2) return "a system folder";
    if (top === "private" && (parts[1] === "tmp" || parts[1] === "var") && parts.length === 2) return "the temporary folder";
    const vf = top === "var" ? 1 : top === "private" && parts[1] === "var" ? 2 : -1;
    if (vf > 0 && parts[vf] === "folders" && parts.length <= vf + 4) return "the temporary folder (or a folder that holds it)";
    if (vf > 0 && parts.length <= vf + 1) return "a system folder";
    if (top === "run" && parts.length <= 3) return "a system folder";
    if (["volumes", "mnt", "media"].includes(top) && parts.length <= 2) return "a volume's root";
  }
  return undefined;
}

/** At most this deep and this many entries `nestedBoundaries` looks through below a covering share. */
export const NESTED_SCAN_DEPTH = 4;
export const NESTED_SCAN_ENTRIES = 2000;

/**
 * The nested git repositories (a `.git`, or a bare repository) and `.p2p-private` folders below
 * `root`, for the warning a covering share prints: each stays its own project, but only while its
 * marker is there. Bounded (NESTED_SCAN_DEPTH, NESTED_SCAN_ENTRIES: `capped` past it); symlinks
 * are never followed.
 */
export function nestedBoundaries(root: string): { repos: string[]; private: string[]; capped: boolean } {
  const repos: string[] = [];
  const priv: string[] = [];
  let seen = 0;
  let capped = false;
  let level: string[] = [root];
  for (let depth = 1; depth <= NESTED_SCAN_DEPTH && level.length > 0 && !capped; depth++) {
    const next: string[] = [];
    for (const d of level) {
      let entries: import("node:fs").Dirent[];
      try {
        entries = readdirSync(d, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const e of entries) {
        if (++seen > NESTED_SCAN_ENTRIES) {
          capped = true;
          break;
        }
        if (!e.isDirectory() || e.isSymbolicLink()) continue;
        const p = join(d, e.name);
        if (e.name === ".git") continue;
        if (existsSync(join(p, ".git")) || isBareRepo(p)) {
          repos.push(p);
          continue;
        }
        if (existsSync(join(p, PRIVATE_MARKER))) priv.push(p);
        next.push(p);
      }
      if (capped) break;
    }
    level = next;
  }
  return { repos, private: priv, capped };
}

/**
 * `p2p project share`: share the project at `dir` with circles you joined and friends. Replaces the
 * project's shares with exactly these (`add` keeps the ones it has). Only ever the person's
 * command: no session or file can run it for them (the mod and the Codex bridge refuse it from a
 * model).
 */
export async function shareProject(app: App, dir: string, targets: { circles?: string[]; people?: string[]; add?: boolean; subfolders?: boolean }): Promise<{ project: ProjectView; warnings: string[] }> {
  const ref = projectOf(dir);
  if (ref.repoPrivate) {
    throw new CliError("repo_private", `${ref.name} asks to stay private: its repository has ${PRIVATE_MARKER} at the top level. Peer2Peer never shares it; remove that file from your copy first if you mean to`);
  }
  const warnings: string[] = [];
  // Subfolders are covered only when asked, and never below a root that holds everything.
  let subfolders = targets.subfolders === true;
  if (subfolders && ref.kind === "git") {
    warnings.push(`${ref.name} is a git repository: its subfolders are part of it already (--subfolders is for folders outside git)`);
    subfolders = false;
  }
  if (subfolders) {
    const broad = broadRoot(ref.root, app.env);
    if (broad) throw new CliError("usage", `${ref.root} is ${broad}: a share there can't cover its subfolders (share it without --subfolders, or share the folders below it you mean)`);
    const n = nestedBoundaries(ref.root);
    const list = (xs: string[]) => `${xs.slice(0, 10).join(", ")}${xs.length > 10 ? ` and ${xs.length - 10} more` : ""}`;
    if (n.repos.length > 0) warnings.push(`git repositories below ${ref.root} stay their own projects (private until you share each one), only while their .git is there: ${list(n.repos)}`);
    if (n.private.length > 0) warnings.push(`folders below ${ref.root} with ${PRIVATE_MARKER} stay private: ${list(n.private)}`);
    if (n.capped) warnings.push(`stopped looking for repositories below ${ref.root} after ${NESTED_SCAN_ENTRIES} entries (${NESTED_SCAN_DEPTH} levels deep): there may be more than listed`);
  }
  const { resolveCircle } = await import("./circle-ops.js");
  const circles: string[] = [];
  for (const c of targets.circles ?? []) {
    const r = await resolveCircle(app, c);
    if (!r.record.joinedByMe) throw new CliError("usage", `you haven't joined circle ${c}`);
    if (!circles.includes(r.record.cid)) circles.push(r.record.cid);
    const lc = await loadCircle(app.store, r.record.cid).catch(() => undefined);
    if (lc && circlePolicy(lc.chain.head) === "open") warnings.push(`circle ${r.record.cid} is open: anyone its owner admits will see ${ref.name}'s sessions`);
  }
  const people: string[] = [];
  if ((targets.people ?? []).length > 0) {
    const friends = await liveFriendshipsV3(app.store, app.signerCtx());
    for (const p of targets.people ?? []) {
      const u = await app.resolveUser(p);
      if (u === app.userId) continue;
      if (await app.store.isBlocked(u)) throw new CliError("blocked", `you blocked ${p}`);
      if (!friends.some((f) => f.inviter === u || f.invitee === u)) throw new CliError("usage", `${await app.addressOf(u)} isn't your friend: share with a circle they're in, or befriend them first`);
      if (!people.includes(u)) people.push(u);
    }
  }
  if (circles.length + people.length === 0) throw new CliError("usage", "name a circle or a friend to share with (or `p2p project private`)");
  const doc = await app.state.update("projects", (cur) => {
    const d = (cur as ProjectsDoc | undefined)?.v === 1 ? (cur as ProjectsDoc) : { v: 1 as const, projects: {} };
    const old = shareOf(d, ref.id);
    const keep = targets.add && old !== "private" ? old : { circles: [], people: [] };
    const share = { circles: [...new Set([...keep.circles, ...circles])], people: [...new Set([...keep.people, ...people])] };
    if (share.circles.length + share.people.length > MAX_PROJECT_SHARES) throw new CliError("usage", `a project is shared with at most ${MAX_PROJECT_SHARES} circles and people`);
    // --add keeps whether it covers its subfolders; a share made afresh covers them only when asked.
    const covers = subfolders || (targets.add === true && targets.subfolders === undefined && d.projects[ref.id]?.covers === true);
    const next: ProjectsDoc = { ...d, projects: { ...d.projects, [ref.id]: { name: ref.name, root: ref.root, ...(ref.remote ? { remote: ref.remote } : {}), share, ...(covers ? { covers: true as const } : {}), at: Date.now() } } };
    return { next: next, result: next };
  });
  return { project: await projectView(app, ref, doc), warnings };
}

/** `p2p project private`: only your own devices see the project's sessions (the default). */
export async function makeProjectPrivate(app: App, dir: string): Promise<ProjectView> {
  const ref = projectOf(dir);
  const doc = await app.state.update("projects", (cur) => {
    const d = (cur as ProjectsDoc | undefined)?.v === 1 ? (cur as ProjectsDoc) : { v: 1 as const, projects: {} };
    const next: ProjectsDoc = { ...d, projects: { ...d.projects, [ref.id]: { name: ref.name, root: ref.root, ...(ref.remote ? { remote: ref.remote } : {}), share: "private", at: Date.now() } } };
    return { next: next, result: next };
  });
  return projectView(app, ref, doc);
}

/** `p2p project ls`: every project with a policy on this device. */
export async function listProjects(app: App): Promise<ProjectView[]> {
  const doc = await projectsDoc(app);
  const out: ProjectView[] = [];
  for (const [id, r] of Object.entries(doc.projects)) {
    out.push(await projectView(app, { id, name: r.name, kind: r.remote !== undefined || existsSync(join(r.root, ".git")) ? "git" : "dir", root: r.root, ...(r.remote ? { remote: r.remote } : {}) }, doc));
  }
  return out.sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
}

/** `p2p project show`: the project at `dir` (a shared folder above it covers it), its policy and why. */
export async function showProject(app: App, dir: string): Promise<ProjectView> {
  const doc = await projectsDoc(app);
  return projectView(app, projectOf(dir, doc), doc);
}

// ---------------------------------------------------------------------------
// A session's own scratch

/**
 * The folders an agent keeps for this one session (Claude Code: its background tasks' output, the
 * large tool results it saved, its subagents' transcripts, a background job's folder), which its
 * front end names in SCRATCH_ENV. What is in them came from the session's own tool calls, whose
 * real paths were bound already, so a path in them is the session, not a project of its own.
 * Each is matched by the session's exact id, on real paths:
 *  - `bases`: a folder whose `<one folder>/<sid>` subtree is this session's: `<tmp>/claude-<uid>`
 *    (`<tmp>/claude-<uid>/<project>/<sid>/tasks/…`) and `<config>/projects`
 *    (`<config>/projects/<project>/<sid>/tool-results/…`, `…/subagents/…`). Never what is shared
 *    across sessions there (`<config>/projects/<project>/memory`, other sessions' transcripts);
 *  - `jobs`: the session's background job folder (`<config>/jobs/<id>`, `<id>` the start of `sid`,
 *    so a job's next conversation after a /clear, which has a new id, has none).
 */
export interface SessionScratch {
  sid: string;
  bases: string[];
  jobs: string[];
}

/** The variable a front end names its session's scratch in (JSON: `{sid, tmp: [..], config, job}`). */
export const SCRATCH_ENV = "P2P_SESSION_SCRATCH";

/** At most this many entries a scratch folder is scanned for symlinks; past it nothing in it is skipped (fails closed: paths there bind). */
export const SCRATCH_SCAN_ENTRIES = 4096;

const SCRATCH_SID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/;
const JOB_ID_RE = /^[A-Za-z0-9][\w.-]{7,127}$/;

/** `p` as a real path, when it is a folder of this user's own and not a symlink itself. */
function ownDir(p: string): string | undefined {
  if (!isAbsolute(p)) return undefined;
  try {
    const st = lstatSync(p);
    if (!st.isDirectory() || st.isSymbolicLink()) return undefined;
    const uid = process.getuid?.();
    if (uid !== undefined && st.uid !== uid) return undefined;
    return real(p);
  } catch {
    return undefined;
  }
}

/**
 * The scratch a front end named (SCRATCH_ENV), checked: the id's shape; each folder there this
 * user's own and not a symlink; the temporary one named as Claude Code names it (`claude-<uid>`);
 * the job folder right in `<config>/jobs`, its name the start of the id. Anything else: none.
 */
export function sessionScratch(raw: string | undefined): SessionScratch | undefined {
  // Not on Windows until it is verified there (no owner check, no per-user folder name).
  if (process.platform === "win32") return undefined;
  if (typeof raw !== "string" || raw === "" || raw.length > 16 * 1024) return undefined;
  let o: Record<string, unknown>;
  try {
    const j = JSON.parse(raw) as unknown;
    if (!j || typeof j !== "object" || Array.isArray(j)) return undefined;
    o = j as Record<string, unknown>;
  } catch {
    return undefined;
  }
  const sid = o.sid;
  if (typeof sid !== "string" || !SCRATCH_SID_RE.test(sid)) return undefined;
  const path = (v: unknown) => (typeof v === "string" && v !== "" && v.length <= 4096 && !/[\0\n]/.test(v) && isAbsolute(v) ? resolve(v) : undefined);
  const bases = new Set<string>();
  const jobs = new Set<string>();
  // Claude Code's per-user temporary folder (`claude-<uid>`; 0 where there is no uid), in each temporary root it may use.
  const tmpName = `claude-${process.getuid?.() ?? 0}`;
  for (const t of Array.isArray(o.tmp) ? o.tmp.slice(0, 4) : []) {
    const at = path(t);
    const b = at === undefined ? undefined : ownDir(join(at, tmpName));
    if (b) bases.add(b);
  }
  const config = path(o.config);
  if (config !== undefined) {
    const projects = ownDir(join(config, "projects"));
    if (projects) bases.add(projects);
    const job = path(o.job);
    const jobsDir = ownDir(join(config, "jobs"));
    if (job !== undefined && jobsDir !== undefined && dirname(job) === join(config, "jobs")) {
      const id = basename(job);
      const r = JOB_ID_RE.test(id) && sid.startsWith(id) ? ownDir(job) : undefined;
      if (r && dirname(r) === jobsDir) jobs.add(r);
    }
  }
  return bases.size + jobs.size > 0 ? { sid, bases: [...bases], jobs: [...jobs] } : undefined;
}

/** The scratch folder (`<base>/<project>/<sid>`, or the job folder) the real folder `dir` is in, if any. */
export function scratchRoot(dir: string, s: SessionScratch): string | undefined {
  for (const j of s.jobs) if (within(dir, j)) return j;
  for (const b of s.bases) {
    if (dir === b || !within(dir, b)) continue;
    const parts = dir.slice(b.endsWith(sep) ? b.length : b.length + 1).split(sep);
    if (parts.length >= 2 && parts[0] !== "" && parts[1] === s.sid) return join(b, parts[0], parts[1]);
  }
  return undefined;
}

/**
 * What every symlink anywhere in a scratch folder points at: a link out of it, read through
 * `link/…`, `link/../…` or as a file in a folder, binds its target. Undefined when that can't be
 * told (a folder or link that can't be read, more than SCRATCH_SCAN_ENTRIES entries): then
 * nothing in that scratch folder is skipped.
 */
function scratchLinks(root: string): string[] | undefined {
  const out: string[] = [];
  const stack = [root];
  let seen = 0;
  while (stack.length > 0) {
    const d = stack.pop() as string;
    let ents: Dirent[];
    try {
      ents = readdirSync(d, { withFileTypes: true });
    } catch {
      return undefined;
    }
    for (const e of ents) {
      if (++seen > SCRATCH_SCAN_ENTRIES) return undefined;
      const p = join(d, e.name);
      if (e.isSymbolicLink()) {
        try {
          out.push(realpathSync(p));
        } catch {
          // Dangling, or a loop: where it points.
          try {
            out.push(resolve(d, readlinkSync(p)));
          } catch {
            return undefined;
          }
        }
      } else if (e.isDirectory()) stack.push(p);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Sessions

/**
 * Binds a session to the projects of `dirs` (sticky: a session's projects only ever grow until it
 * ends), plus a constraint an own-device message carried. The person's own session is never
 * bound; another caller naming it is refused. A session an agent names (agentContext) that no
 * front end of this user has registered (personTokenOk) starts private.
 */
export async function bindSession(
  app: App,
  sid: string,
  dirs: readonly string[],
  o: { person?: boolean; over?: boolean | readonly OverWhy[]; constraint?: ProjectShare; inbound?: boolean; scratch?: SessionScratch } = {},
): Promise<SessionBinding | undefined> {
  if (sid === PERSON_SESSION) {
    if (o.person) return undefined;
    throw new CliError("usage", `session ${PERSON_SESSION} is your own terminal's (p2p tui, or p2p send typed with no --from-session); an agent sends from its own session`);
  }
  // Folder projects follow the policies (a shared folder covers its subfolders): read once, before the lock.
  const doc = dirs.length > 0 ? await projectsDoc(app) : undefined;
  const refs = new Map<string, { ref: ProjectRef; under: Set<string> }>();
  const add = (d: string, r: ProjectRef) => {
    const one = refs.get(r.id) ?? { ref: r, under: new Set<string>() };
    // A folder a shared folder above covered: remembered, so a policy it gets later still narrows this session.
    if (r.kind === "dir") {
      const at = existingDir(d);
      if (at !== r.root && within(at, r.root)) one.under.add(at);
    }
    refs.set(r.id, one);
  };
  // The session's own scratch (SessionScratch) is the session, not a project: a path in it binds
  // nothing, unless it is a repository or `.p2p-private` (a clone made there keeps its identity),
  // a folder the person gave a policy of its own, or a path that names a `.git` or `.p2p-private`
  // (namedStop: a command that may remove one), or a `.git` that can't be read. A symlink in it
  // binds what it points at. A path written with a `..` segment never gets the exemption: it binds
  // where the file system takes it, as everywhere else.
  const scans = new Map<string, string[] | undefined>();
  const scratchOf = (d: string, r: ProjectRef): string | undefined => {
    const s = o.scratch;
    if (!s || r.kind !== "dir" || r.repoPrivate || r.brokenGit || hasDotDot(d) || doc?.projects[r.id] !== undefined || namedStop(physicalPath(d)) !== undefined) return undefined;
    return scratchRoot(r.root, s);
  };
  // Binds what a scratch folder's symlinks point at (once per folder; one into another scratch folder
  // of this session's has that one's bound too). False when they couldn't all be read: then a path
  // in it binds as any folder's.
  const scanned = (root: string): boolean => {
    if (!scans.has(root)) {
      const links = scratchLinks(root);
      scans.set(root, links);
      for (const t of links ?? []) {
        if (pseudoPath(t)) continue;
        const tr = projectOf(t, doc);
        const at = scratchOf(t, tr);
        if (at === undefined || !scanned(at)) add(t, tr);
      }
    }
    return scans.get(root) !== undefined;
  };
  for (const d of dirs) {
    if (typeof d !== "string" || d.trim() === "") continue;
    // A device or pseudo file (2>/dev/null) is no project; a path that isn't there yet still binds its parent's.
    if (pseudoPath(d)) continue;
    const r = projectOf(d, doc);
    const root = scratchOf(d, r);
    if (root !== undefined && scanned(root)) continue;
    add(d, r);
  }
  // Who may speak for a session (statuses, sends): its front end (the person token), or, for a session
  // no front end registered, a caller outside any agent's session. An agent's own shell never may.
  const front = app.front === true;
  if (!o.inbound && !front && agentContext(app.env)) {
    throw new CliError("refused", `session ${sid}: inside an agent's session only its front end speaks for a session (the Claude mod's SendMessage, the Codex bridge's p2p_send), never the shell`);
  }
  // A session nobody has used yet, without the front end's token: the person confirms it on their own
  // terminal (a status, a send, an extension send or state alike; a detached process can't).
  if (!o.inbound && !front && !(await sessionBinding(app, sid))) {
    if (!(await app.confirmTty(`p2p is about to speak for a new session ${sid}.`))) {
      throw new CliError("refused", `session ${sid} is new: without your front end's token, confirm it with "yes" on your own terminal (read from the terminal itself, never stdin or a flag)`);
    }
  }
  const now = Date.now();
  return app.state.update("sessionProjects", (cur) => {
    const all = { ...((cur as SessionProjectsDoc | undefined) ?? {}) };
    for (const [k, v] of Object.entries(all)) if (!v || typeof v.at !== "number" || now - v.at > SESSION_BINDING_TTL_MS) delete all[k];
    const have: SessionBinding | undefined = all[sid];
    // A session a front end registered is that front end's: nobody else acts on it, not even to narrow it.
    if (!o.inbound && !front && have?.registered) {
      throw new CliError("refused", `session ${sid} belongs to a front end of yours (the Claude mod or the Codex bridge): only it speaks for that session`);
    }
    const projects = { ...(have?.projects ?? {}) };
    const why = new Set<OverWhy>(have?.overWhy ?? []);
    if (o.over === true) why.add("front");
    else if (Array.isArray(o.over)) for (const w of overWhys(o.over)) why.add(w);
    // A binding from before overWhy kept only `over`: it stays over (said as such: legacy-over).
    let over = have?.over === true || why.size > 0;
    for (const { ref: r, under } of refs.values()) {
      const prev = projects[r.id];
      if (!prev && Object.keys(projects).length >= MAX_SESSION_PROJECTS) {
        over = true;
        why.add("projects");
        continue;
      }
      // Once a repository asked for privacy, it stays asked for this session; covered folders only add up.
      const all = new Set([...(prev?.under ?? []), ...under]);
      const underOver = prev?.underOver === true || all.size > MAX_UNDER;
      projects[r.id] = {
        name: r.name,
        root: prev?.root ?? r.root,
        ...(r.repoPrivate || prev?.repoPrivate ? { repoPrivate: true as const } : {}),
        ...(!underOver && all.size > 0 ? { under: [...all].sort() } : {}),
        ...(underOver ? { underOver: true as const } : {}),
      };
    }
    const constraints = [...(have?.constraints ?? [])];
    if (o.constraint !== undefined && !constraints.some((c) => JSON.stringify(c) === JSON.stringify(o.constraint))) {
      if (constraints.length >= MAX_SESSION_CONSTRAINTS) {
        over = true;
        why.add("constraints");
      } else constraints.push(o.constraint);
    }
    const registered = front || have?.registered === true;
    const unregistered = !registered && have?.unregistered === true;
    const next: SessionBinding = {
      projects,
      ...(over ? { over: true as const } : {}),
      ...(why.size > 0 ? { overWhy: [...why] } : {}),
      ...(constraints.length ? { constraints } : {}),
      ...(unregistered ? { unregistered: true as const } : {}),
      ...(registered ? { registered: true as const } : {}),
      since: typeof have?.since === "number" ? have.since : now,
      at: now,
    };
    return { next: { ...all, [sid]: next }, result: next };
  });
}

// ---------------------------------------------------------------------------
// Who is calling: the person's front end, or an agent

/**
 * The variables Claude Code and Codex set in the commands their agents run (an allow-list, from
 * their documentation and source: docs/security/threat-model.md "Project boundaries"). Variables a
 * person sets in their own shell (CODEX_HOME, CODEX_API_KEY, CODEX_PROFILE) never count.
 */
export const AGENT_ENV_VARS: readonly string[] = [
  // Claude Code (code.claude.com/docs/en/env-vars): its Bash, PowerShell and Monitor tools, hooks.
  "CLAUDECODE",
  "CLAUDE_CODE_CHILD_SESSION",
  // Codex (openai/codex codex-rs core/src/unified_exec/process_manager.rs, exec_env.rs, sandboxing/mod.rs):
  // every model tool call, the sandbox markers, and the thread (its user `!` shell sets the last two too).
  "CODEX_TOOL_CALL_ID",
  "CODEX_CI",
  "CODEX_SANDBOX",
  "CODEX_SANDBOX_NETWORK_DISABLED",
  "CODEX_THREAD_ID",
  "CODEX_SESSION_ID",
];

/** Whether the environment says this runs inside an agent's tool call. */
export function agentEnv(env: Record<string, string | undefined> | undefined): boolean {
  if (!env) return false;
  return AGENT_ENV_VARS.some((k) => (env[k] ?? "") !== "");
}

/** Whether this call runs on an agent's behalf: its environment, or a Claude Code or Codex ancestor (ancestry.ts). */
export function agentContext(env: Record<string, string | undefined> | undefined): boolean {
  return agentEnv(env) || agentAncestor();
}

export { isAgentProcess };

/** `<home>/cli/person.key`: a random secret the person's front ends (the Claude mod, the Codex bridge) pass back as P2P_PERSON_TOKEN. */
export function personTokenFile(home: string): string {
  return join(home, "cli", "person.key");
}

const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

/** The person token, made once (exclusively, 0600, in the CLI's own folder, which the mod's guards keep from the model). */
export function personToken(home: string): string {
  const f = personTokenFile(home);
  const read = () => {
    try {
      const t = readFileSync(f, "utf8").trim();
      return TOKEN_RE.test(t) ? t : undefined;
    } catch {
      return undefined;
    }
  };
  const have = read();
  if (have) return have;
  mkdirSync(join(home, "cli"), { recursive: true, mode: 0o700 });
  const t = randomBytes(32).toString("base64url");
  try {
    writeFileSync(f, t, { mode: 0o600, flag: "wx" });
    return t;
  } catch {
    // Made meanwhile by another process (or a file in the way): that one, if it is a token.
    const again = read();
    if (again) return again;
    throw new CliError("conflict", `${f} isn't a person token: remove it and run the command again`);
  }
}

/** Whether P2P_PERSON_TOKEN is this home's person token (read only: a missing file is no match). */
export function personTokenOk(env: Record<string, string | undefined> | undefined, home: string | undefined): boolean {
  const given = env?.P2P_PERSON_TOKEN?.trim();
  if (!given || typeof home !== "string" || home === "") return false;
  let t: string;
  try {
    t = readFileSync(personTokenFile(home), "utf8").trim();
  } catch {
    return false;
  }
  const a = Buffer.from(given);
  const b = Buffer.from(t);
  return a.length === b.length && b.length >= 32 && timingSafeEqual(a, b);
}

/**
 * Checks the person token once, at the start of a command, and takes it out of the environment
 * (this object and the process's), so no child (git, ix, an extension's tool) ever inherits it.
 */
export function takePersonToken(env: Record<string, string | undefined>, home: string | undefined): boolean {
  const ok = personTokenOk(env, home);
  delete env.P2P_PERSON_TOKEN;
  delete process.env.P2P_PERSON_TOKEN;
  return ok;
}

/** The person's confirmation on their own terminal (tty-confirm.ts), or a test's stand-in. */
export type ConfirmTty = (question: string) => Promise<boolean>;

/**
 * Lets a command that widens who reaches this user (sharing a project, a session, a default
 * circle, invites, joins, trust, friends) run only for the person: their front end's token; or,
 * outside any agent's session, their "yes" typed on the controlling terminal (never stdin, never a
 * flag: a process detached from every terminal can't give it). Reads are never asked, except for
 * the person's own messages (history.ts), which pass their own `why`.
 */
export async function assertPersonForWidening(app: Pick<App, "env"> & { front?: boolean }, what: string, confirm: ConfirmTty, why = "changes who reaches you"): Promise<void> {
  if (app.front === true) return;
  if (agentContext(app.env)) {
    throw new CliError(
      "refused",
      `\`p2p ${what}\` ${why}, so only you run it: in your own terminal (not inside Claude Code or Codex), or with /peers in Claude Code. It was refused here because it runs inside an agent's session`,
    );
  }
  if (!(await confirm(`p2p ${what} ${why}.`))) {
    throw new CliError("refused", `\`p2p ${what}\` ${why}: confirm it with "yes" on your own terminal (it is read from the terminal itself, so a script or a process without one can't)`);
  }
}

/**
 * For an act on a session that binds nothing (a delivery receipt): the session's front end (its
 * token); or, outside any agent's session, a caller acting for a session no front end registered.
 * An agent's own shell never may, as for statuses and sends (bindSession).
 */
export async function assertSpeaksFor(app: App, sid: string): Promise<void> {
  if (app.front === true) return;
  if (agentContext(app.env)) {
    throw new CliError("refused", `session ${sid}: inside an agent's session only its front end speaks for a session (the Claude mod, the Codex bridge), never the shell`);
  }
  if ((await sessionBinding(app, sid))?.registered) {
    throw new CliError("refused", `session ${sid} belongs to a front end of yours (the Claude mod or the Codex bridge): only it speaks for that session`);
  }
}

/** Whether a person-only path (session `tui`) may run here: the person's front end, or no agent in sight (then a terminal "yes" too). */
export function personHere(app: Pick<App, "env"> & { front?: boolean }): boolean {
  return app.front === true || !agentContext(app.env);
}

export async function sessionBinding(app: App, sid: string): Promise<SessionBinding | undefined> {
  return ((await app.state.get("sessionProjects")) as SessionProjectsDoc | undefined)?.[sid];
}

/** One reason a session is private, as said to the person (and to a model that reads a refusal). */
export interface PrivateReason {
  cause: PrivateCause;
  why: string;
  /** The project it is about, when it is one project's policy. */
  project?: string;
}

const OVER_TEXT: Record<OverWhy | "legacy-over", string> = {
  projects: `it worked in more than ${MAX_SESSION_PROJECTS} projects`,
  folders: "it worked in more folders than Peer2Peer keeps track of for one session",
  unresolved:
    "a command it ran named a path Peer2Peer couldn't resolve (one that starts with a variable or a command substitution its front end doesn't know the value of, like $X/… or $(…)/…), so which project that path is in can't be told",
  front: "its front end couldn't keep track of every folder it worked in (a forked conversation, or a record it couldn't read)",
  constraints: `more than ${MAX_SESSION_CONSTRAINTS} sessions of yours sent it messages`,
  "legacy-over": "it worked in more projects or folders than Peer2Peer keeps track of, or named a path Peer2Peer couldn't resolve",
};

/**
 * Every policy a bound project answers to: its own, and, for a folder project a shared folder
 * covered, each policy a covered subfolder (or a folder between it and the root) has since been
 * given. Past MAX_UNDER covered subfolders, every folder policy below the root.
 */
function boundShares(doc: ProjectsDoc, id: string, p: BoundProject): { share: ProjectShare; mapped: boolean; name: string }[] {
  const out = [{ share: shareOf(doc, id), mapped: doc.projects[id] !== undefined, name: p.name }];
  const root = p.root;
  if (typeof root !== "string" || root === "") return out;
  const seen = new Set<string>([id]);
  const add = (pid: string) => {
    const r = doc.projects[pid];
    if (seen.has(pid) || !r) return;
    seen.add(pid);
    out.push({ share: shareOf(doc, pid), mapped: true, name: clean(String(r.name ?? "")) || p.name });
  };
  // Subfolders it covered, and its share no longer covers them (shared again without --subfolders): private.
  if ((p.underOver || (p.under?.length ?? 0) > 0) && doc.projects[id]?.covers !== true) out.push({ share: "private", mapped: true, name: p.name });
  if (p.underOver) {
    for (const [pid, r] of Object.entries(doc.projects)) if (typeof r?.root === "string" && r.root !== root && within(r.root, root) && pid === dirProjectId(r.root)) add(pid);
    return out;
  }
  for (const f of p.under ?? []) {
    if (typeof f !== "string") continue;
    for (let c = f, i = 0; i < 4096 && c !== root && within(c, root); i++) {
      add(dirProjectId(c));
      const up = dirname(c);
      if (up === c) break;
      c = up;
    }
  }
  return out;
}

/** Why a binding is private, every cause (no network: `disjoint` needs the store, see sessionCeiling). */
export function privateReasons(doc: ProjectsDoc, b: SessionBinding): PrivateReason[] {
  const out: PrivateReason[] = [];
  if (b.over) for (const w of b.overWhy?.length ? overWhys(b.overWhy) : (["legacy-over"] as const)) out.push({ cause: w, why: OVER_TEXT[w] });
  if (b.unregistered) out.push({ cause: "unregistered", why: "an agent named it, and no front end of yours has registered it" });
  for (const [id, p] of Object.entries(b.projects)) {
    if (p.repoPrivate) {
      out.push({ cause: "repo-private", why: `${p.name} asks to stay private (${PRIVATE_MARKER})`, project: p.name });
      continue;
    }
    for (const s of boundShares(doc, id, p)) {
      if (s.share !== "private") continue;
      out.push(s.mapped ? { cause: "private", why: `${s.name} is private`, project: s.name } : { cause: "unshared", why: `${s.name} isn't shared (projects are private until you share them)`, project: s.name });
      break;
    }
  }
  if ((b.constraints ?? []).includes("private")) out.push({ cause: "sent-private", why: "a private session of yours sent it a message" });
  return out;
}

/**
 * What the person can do about a private session, for an error a model may read: a share only
 * when a share can lift it, never the "share each project" hint for a cause that lasts until the
 * session ends (a cap, an unresolved path, a dropped front end, `.p2p-private`, a private
 * session's message).
 */
export function privateRemedy(causes: readonly PrivateCause[], names: string[]): string {
  if (causes.some((c) => STICKY.has(c))) {
    return "sharing a project can't change that, and it lasts until the session ends: start a new session for the work you want to share (`p2p session show <session>` in your own terminal, or /peers session in Claude Code, lists what it is bound to and why)";
  }
  const parts: string[] = [];
  if (causes.includes("unregistered")) parts.push("send from the session's own front end (SendMessage in Claude Code, p2p_send in Codex), which registers it");
  if (causes.some((c) => c === "private" || c === "unshared" || c === "disjoint") || parts.length === 0) parts.push(shareHint(names));
  return parts.join("; and ");
}

/** Whether a ceiling's privacy can only end with the session (privateRemedy says to start a new one). */
export function stickyPrivate(c: Ceiling): boolean {
  return c.kind === "private" && c.causes.some((x) => STICKY.has(x));
}

/**
 * The most a session may reach: the intersection of every bound project's policy. Unmapped,
 * private and repository-private projects make it private, and so does an empty intersection.
 */
export async function sessionCeiling(app: App, sid: string, binding?: SessionBinding | null): Promise<Ceiling> {
  if (sid === PERSON_SESSION) return { kind: "none" };
  const b = binding === null ? undefined : (binding ?? (await sessionBinding(app, sid)));
  if (!b || (Object.keys(b.projects).length === 0 && !b.constraints?.length && !b.unregistered && !b.over)) return { kind: "none" };
  const doc = await projectsDoc(app);
  const reasons = privateReasons(doc, b);
  if (reasons.length > 0) return privateOf(reasons);
  let circles: Set<string> | undefined;
  let people: Set<string> | undefined;
  const shares: { name: string; share: ProjectShare }[] = [];
  for (const [id, p] of Object.entries(b.projects)) for (const s of boundShares(doc, id, p)) shares.push({ name: s.name, share: s.share });
  for (const c of b.constraints ?? []) shares.push({ name: "a session of yours that sent it a message", share: c });
  for (const { share } of shares) {
    if (share === "private") continue;
    circles = circles ? new Set(share.circles.filter((c) => circles!.has(c))) : new Set(share.circles);
    people = people ? new Set(share.people.filter((u) => people!.has(u))) : new Set(share.people);
  }
  const joined: string[] = [];
  for (const c of circles ?? []) if ((await app.store.getCircle(c))?.joinedByMe === true) joined.push(c);
  const blocks = new Set((await app.store.listBlocks()).map((x) => x.userId));
  // People only while they are still friends (an unfriend ends a share as it ends everything else).
  const friends = (people?.size ?? 0) > 0 ? await friendIds(app) : new Set<string>();
  const ppl = [...(people ?? [])].filter((u) => !blocks.has(u) && u !== app.userId && friends.has(u));
  if (joined.length + ppl.length === 0) {
    const names = [...new Set(shares.map((x) => x.name))];
    return privateOf([{ cause: "disjoint", why: names.length > 1 ? `its projects (${nameList(names)}) share nobody in common` : `${names[0]} shares nobody you can reach` }], names);
  }
  return { kind: "shared", circles: joined.sort(), people: ppl.sort() };
}

/** A private ceiling from its reasons: the first said in full, the count of the rest (`p2p session show` lists them all). */
function privateOf(reasons: PrivateReason[], names?: string[]): Ceiling & { kind: "private" } {
  const more = reasons.length - 1;
  const blocking = names ?? [...new Set(reasons.map((r) => r.project).filter((x): x is string => x !== undefined))];
  return {
    kind: "private",
    why: `${reasons[0].why}${more > 0 ? ` (and ${more} more reason${more === 1 ? "" : "s"})` : ""}`,
    causes: [...new Set(reasons.map((r) => r.cause))],
    ...(blocking.length ? { blocking } : {}),
  };
}

/** Everyone a ceiling lets in (besides this user): members of its circles who stand in them, and its people. */
export async function ceilingAudience(app: App, c: Ceiling): Promise<Set<string> | undefined> {
  if (c.kind === "none") return undefined;
  const out = new Set<string>();
  if (c.kind === "private") return out;
  const stands = await standsLookup(app.store, app.userId);
  for (const cid of c.circles) {
    const lc = await loadCircle(app.store, cid).catch(() => undefined);
    if (!lc || !stands(app.userId, cid)) continue;
    for (const m of lc.chain.head.members) if (m !== app.userId && stands(m, cid)) out.add(m);
  }
  for (const u of c.people) out.add(u);
  const blocks = new Set((await app.store.listBlocks()).map((x) => x.userId));
  for (const u of [...out]) if (blocks.has(u)) out.delete(u);
  return out;
}

/** Project names for a message: the first MESSAGE_NAMES, then how many more (`p2p session show` lists them all). */
const MESSAGE_NAMES = 16;
function nameList(names: readonly string[]): string {
  return `${names.slice(0, MESSAGE_NAMES).join(", ")}${names.length > MESSAGE_NAMES ? ` and ${names.length - MESSAGE_NAMES} more` : ""}`;
}

/** How to tell the person to share, for an error a model may read: the person's command, never a flag for the caller. */
export function shareHint(names: string[]): string {
  const what = names.length === 1 ? `the project ${names[0]}` : `each of ${nameList(names)}`;
  return `only the person can widen this, by sharing ${what} themselves: \`p2p project share <circle or friend>\` run in it (or /peers project share in Claude Code)`;
}

/**
 * The exfiltration barrier: may session `sid` send to `userId`? Your own devices always; the
 * person's own session always; anyone else only within the session's project ceiling.
 */
export async function assertMayReach(app: App, sid: string, userId: string, o: { person?: boolean; address?: string } = {}): Promise<void> {
  if (userId === app.userId || o.person || sid === PERSON_SESSION) return;
  const c = await sessionCeiling(app, sid);
  if (c.kind === "none") return;
  const aud = await ceilingAudience(app, c);
  if (aud?.has(userId)) return;
  const b = await sessionBinding(app, sid);
  const names = Object.values(b?.projects ?? {}).map((p) => p.name);
  const who = o.address ?? (await app.addressOf(userId));
  const why = c.kind === "private" ? c.why : `${who} isn't in the circles or people ${names.length > 1 ? "all its projects share" : "its project shares"}`;
  const remedy = c.kind === "private" ? privateRemedy(c.causes, c.blocking?.length ? c.blocking : names) : shareHint(names);
  throw new CliError("not_shared", `session ${sid} works in ${nameList(names) || "a project"}, and Peer2Peer won't carry anything from it to ${who}: ${why}. ${remedy.charAt(0).toUpperCase()}${remedy.slice(1)}`, {
    delivered: false,
    project: { names, policy: c.kind, ...(c.kind === "private" ? { causes: c.causes, ...(stickyPrivate(c) ? { sticky: true } : {}) } : {}) },
  });
}

/** Friends of this user (live friendships), for the roster's named parts. */
export async function friendIds(app: App): Promise<Set<string>> {
  const out = new Set<string>();
  for (const f of await liveFriendshipsV3(app.store, app.signerCtx())) out.add(f.inviter === app.userId ? f.invitee : f.inviter);
  return out;
}

/** What `p2p status`, `ls` and the mod show about a session's projects. */
export interface SessionProjectView {
  projects: { id: string; name: string; repoPrivate?: true }[];
  /** `private`: only your own devices see it; `shared`: the circles and people below (all its projects share them). */
  policy: "private" | "shared" | "none";
  why?: string;
  /** Why it is private, as codes (PrivateCause). */
  causes?: PrivateCause[];
  circles?: string[];
  people?: string[];
}

export async function sessionProjectView(app: App, sid: string): Promise<SessionProjectView> {
  const b = await sessionBinding(app, sid);
  const c = await sessionCeiling(app, sid, b ?? null);
  const projects = Object.entries(b?.projects ?? {}).map(([id, p]) => ({ id, name: p.name, ...(p.repoPrivate ? { repoPrivate: true as const } : {}) }));
  if (c.kind === "private") return { projects, policy: "private", why: c.why, causes: c.causes };
  if (c.kind === "shared") return { projects, policy: "shared", circles: c.circles, people: c.people };
  return { projects, policy: "none" };
}

/** `p2p session show`: one session's bound projects, each one's policy, and every reason it is private. */
export interface SessionShow {
  sid: string;
  policy: "private" | "shared" | "none";
  /** Every reason it is private (empty when it isn't). */
  reasons: PrivateReason[];
  /** What the person can do about it (privateRemedy). */
  remedy?: string;
  /** Who it reaches, when shared: circle ids and userIds. */
  circles?: string[];
  people?: string[];
  projects: (ProjectView & { under?: string[]; underOver?: true })[];
  /** Bounds own-session messages carried in (projects.v1). */
  constraints: number;
}

/**
 * `p2p session show <sid>`: read only, and the person's: their front end (the person token) or
 * their own terminal outside any agent's session. An agent's shell is refused, so no session reads
 * another's bindings (or its own: the model has the not_shared reason already).
 */
export async function showSession(app: App, sid: string): Promise<SessionShow> {
  if (app.front !== true && agentContext(app.env)) {
    throw new CliError(
      "refused",
      "`p2p session show` lists a session's projects and why it is private, which is for you to read: run it in your own terminal (not inside Claude Code or Codex), or type /peers session in Claude Code",
    );
  }
  if (sid === PERSON_SESSION) return { sid, policy: "none", reasons: [], projects: [], constraints: 0 };
  const b = await sessionBinding(app, sid);
  const c = await sessionCeiling(app, sid, b ?? null);
  const doc = await projectsDoc(app);
  const reasons = b ? privateReasons(doc, b) : [];
  if (c.kind === "private" && reasons.length === 0) reasons.push({ cause: c.causes[0] ?? "disjoint", why: c.why });
  const projects: SessionShow["projects"] = [];
  for (const [id, p] of Object.entries(b?.projects ?? {})) {
    const root = typeof p.root === "string" && p.root !== "" ? p.root : (doc.projects[id]?.root ?? "");
    const kind = root !== "" && dirProjectId(root) === id ? "dir" : "git";
    const v = await projectView(app, { id, name: p.name, kind, root, ...(doc.projects[id]?.remote ? { remote: doc.projects[id].remote } : {}), ...(p.repoPrivate ? { repoPrivate: true as const } : {}) }, doc);
    projects.push({ ...v, ...(p.under?.length ? { under: [...p.under] } : {}), ...(p.underOver ? { underOver: true as const } : {}) });
  }
  return {
    sid,
    policy: c.kind,
    reasons,
    ...(c.kind === "private" ? { remedy: privateRemedy(c.causes, c.blocking?.length ? c.blocking : projects.map((x) => x.name)) } : {}),
    ...(c.kind === "shared" ? { circles: c.circles, people: c.people } : {}),
    projects,
    constraints: b?.constraints?.length ?? 0,
  };
}

/**
 * The one-time notice for a user who relied on the default circle: shown once per device, the
 * first time a session of theirs is private only because its project was never shared.
 */
export async function defaultCircleNotice(app: App, sid: string): Promise<string | undefined> {
  const def = app.self?.defaultCircle;
  if (!def || (await app.store.getCircle(def))?.joinedByMe !== true) return undefined;
  const b = await sessionBinding(app, sid);
  if (!b) return undefined;
  const doc = await projectsDoc(app);
  if (doc.noticeAt !== undefined) return undefined;
  const unmapped = Object.entries(b.projects).filter(([id, p]) => !doc.projects[id] && !p.repoPrivate);
  if (unmapped.length === 0) return undefined;
  const shown = await app.state.update("projects", (cur) => {
    const d = (cur as ProjectsDoc | undefined)?.v === 1 ? (cur as ProjectsDoc) : { v: 1 as const, projects: {} };
    if (d.noticeAt !== undefined) return { result: false };
    return { next: { ...d, noticeAt: Date.now() }, result: true };
  });
  if (!shown) return undefined;
  const name = unmapped[0][1].name;
  return `project boundaries: sessions no longer follow your default circle (${def}). Each project is private until you share it, so this session in ${name} is seen only by your own devices. To share ${name} with that circle, run \`p2p project share ${def}\` in it (or /peers project share in Claude Code); \`p2p project ls\` lists what you shared`;
}

/** The text of the one-time notice starts so (the mod and the Codex bridge match it). */
export const PROJECT_NOTICE_PREFIX = "project boundaries:";

// ---------------------------------------------------------------------------
// Graph targets (epic #41 piece 5): which Ix graph a project's work may reach

/**
 * Where Ix calls made for a project (or a session) may go. `local`: this machine's own Ix backend,
 * the only target today. `shared`: the shared graph of exactly one circle the project is shared
 * with (Ix-memory, through Ix Pro), once one exists: a later PR adds the registry of shared
 * graphs, and until then nothing resolves to it.
 */
export type GraphTarget = { kind: "local"; endpoint: string; why: string } | { kind: "shared"; circle: string; endpoint: string };

/** `s` without trailing slashes (a loop, not a regex: linear on any input). */
function trimSlashes(s: string): string {
  let n = s.length;
  while (n > 0 && s.charCodeAt(n - 1) === 47) n--;
  return s.slice(0, n);
}

/** What `p2p doctor` and `p2p project show` print for a local target. */
export const GRAPH_LOCAL_ONLY = "local only";

/** Ix's own default backend (ix-cli config.ts DEFAULT_ENDPOINT): `ix docker` runs it on this machine. */
export const DEFAULT_IX_ENDPOINT = "http://localhost:8090";

/**
 * Whether `url` is an Ix backend on this machine: http(s) to localhost, 127.0.0.0/8 or ::1, with no
 * credentials, query or fragment. Anything else (a cloud URL, a LAN host, `localhost.example.com`,
 * `http://127.0.0.1@evil.example`) is not.
 */
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

/** A loopback endpoint as one canonical string: `origin + pathname`, trailing slashes dropped. Undefined when it isn't one. */
export function normalizeLoopbackEndpoint(url: unknown): string | undefined {
  if (!isLoopbackEndpoint(url)) return undefined;
  const u = new URL(url.trim());
  return trimSlashes(u.origin + u.pathname);
}

/**
 * The local Ix endpoint every `local` target names: `ixEndpoint` in config.json (the person's own
 * file) when it is a loopback URL, else Ix's default. Never from the environment (an agent or a
 * project config can set that), and never a non-loopback URL. On a shared machine another user can
 * listen on a loopback port first (threat model, "Graph targets").
 */
export function localGraphEndpoint(_env: Record<string, string | undefined>, file?: { ixEndpoint?: unknown }): string {
  return normalizeLoopbackEndpoint(typeof file?.ixEndpoint === "string" ? file.ixEndpoint.trim() : undefined) ?? DEFAULT_IX_ENDPOINT;
}

/**
 * The circles that have a shared graph, and its endpoint. None yet: the shared cloud graph (epic #41
 * piece 3) comes in a later PR, which fills this from settled, person-made state. Nothing in the
 * environment, config.json, a repository or a peer's message can add to it.
 */
export const SHARED_GRAPHS: ReadonlyMap<string, string> = new Map();

/** One input to a graph target: a bound project's (or a constraint's) share, as the ceiling sees it. */
export interface GraphShareInput {
  name: string;
  share: ProjectShare;
  repoPrivate?: true;
}

/**
 * The graph target of a set of projects (pure: graphTarget gathers the inputs). Intersection, like
 * the session ceiling: any private, repository-private or unmapped project makes it local, and so
 * does an empty set. A shared target needs every input shared with the same circle, and exactly one
 * such circle with a shared graph (an https endpoint); people-only shares, no common circle, or a
 * choice of several circles all stay local.
 */
export function graphTargetOf(inputs: readonly GraphShareInput[], o: { local: string; sharedGraphs?: ReadonlyMap<string, string> }): GraphTarget {
  const local = (why: string): GraphTarget => ({ kind: "local", endpoint: o.local, why });
  if (inputs.length === 0) return local("no project: nothing is shared");
  let circles: Set<string> | undefined;
  for (const i of inputs) {
    if (i.repoPrivate) return local(`${i.name} asks to stay private (${PRIVATE_MARKER})`);
    if (i.share === "private" || typeof i.share !== "object") return local(`${i.name} is private`);
    const cs = Array.isArray(i.share.circles) ? i.share.circles.filter((c) => typeof c === "string") : [];
    circles = circles ? new Set(cs.filter((c) => circles!.has(c))) : new Set(cs);
  }
  if (!circles || circles.size === 0) return local(inputs.length > 1 ? "its projects share no circle in common" : `${inputs[0].name} isn't shared with a circle`);
  const graphs = o.sharedGraphs ?? SHARED_GRAPHS;
  const withGraph = [...circles].filter((c) => {
    const ep = graphs.get(c);
    return normalizeSharedEndpoint(ep) !== undefined;
  });
  if (withGraph.length === 0) return local("no shared graph for its circle yet: Ix stays on this machine");
  if (withGraph.length > 1) return local("it is shared with more than one circle that has a shared graph: Ix stays on this machine");
  return { kind: "shared", circle: withGraph[0], endpoint: normalizeSharedEndpoint(graphs.get(withGraph[0]))! };
}

/** A shared graph's endpoint as `origin + pathname` (https, off this machine, no credentials, query or fragment), else undefined. */
export function normalizeSharedEndpoint(url: unknown): string | undefined {
  if (typeof url !== "string" || url.length > 512 || /[\s\0]/.test(url)) return undefined;
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return undefined;
  }
  if (u.protocol !== "https:" || u.username || u.password || u.search || u.hash || isLoopbackEndpoint(url)) return undefined;
  return trimSlashes(u.origin + u.pathname);
}

/**
 * The chokepoint for every Ix call Peer2Peer makes or lets an extension make (ext-ix takes its
 * endpoint only from here, ExtContext.graphTarget): the graph a session, the folders it works in,
 * or both may reach. A session bound to a private project, or one whose ceiling is private for any
 * reason (an unregistered agent session, too many projects, a private session's message), is local.
 * The folders' own projects are intersected in, so a session can't name a shared sibling to widen
 * a private repository it works in. The process's own cwd and every path the call names (`paths`:
 * its targets, `--path`, `--changed`, the child's cwd) are intersected in as well. A named session
 * that isn't bound yet is local, and a `shared` result needs a session a front end registered (its
 * person token). Read only: binds nothing.
 */
export async function graphTarget(
  app: App,
  o: { sid?: string; dirs?: readonly string[]; paths?: readonly string[]; over?: boolean } = {},
  sharedGraphs: ReadonlyMap<string, string> = SHARED_GRAPHS,
): Promise<GraphTarget> {
  const lo = localGraphEndpoint(app.env, app.file);
  const local = (why: string): GraphTarget => ({ kind: "local", endpoint: lo, why });
  if (o.over) return local(`it works in more than ${MAX_SESSION_DIRS} folders`);
  // The paths a call names (its targets, --path, --changed, the child's cwd): absolute only, capped.
  const paths = o.paths ?? [];
  if (paths.length > MAX_GRAPH_PATHS) return local(`a call named more than ${MAX_GRAPH_PATHS} paths`);
  if (paths.some((p) => typeof p !== "string" || !isAbsolute(p))) return local("a call named a path that isn't absolute");
  const doc = await projectsDoc(app);
  const inputs: GraphShareInput[] = [];
  let registered = false;
  if (o.sid !== undefined && o.sid !== PERSON_SESSION) {
    const b = await sessionBinding(app, o.sid);
    registered = b?.registered === true;
    const c = await sessionCeiling(app, o.sid, b ?? null);
    if (c.kind === "private") return local(`session ${o.sid} is private: ${c.why}`);
    // A session no front end has bound yet has no ceiling to intersect: fail closed.
    if (c.kind === "none") return local(`session ${o.sid} isn't bound to a project yet`);
    if (c.kind === "shared") inputs.push({ name: `session ${o.sid}`, share: { circles: c.circles, people: c.people } });
  }
  const seen = new Set<string>();
  // The process's real cwd always counts too: P2P_WORKDIR replaces it for display, never for the boundary.
  for (const d of [...(o.dirs ?? []), process.cwd(), ...paths]) {
    if (typeof d !== "string" || d.trim() === "") continue;
    const r = projectOf(d);
    if (seen.has(r.id)) continue;
    seen.add(r.id);
    if (seen.size > MAX_SESSION_PROJECTS) return local(`it works in more than ${MAX_SESSION_PROJECTS} projects`);
    inputs.push({ name: r.name, share: shareOf(doc, r.id), ...(r.repoPrivate ? { repoPrivate: true as const } : {}) });
  }
  const t = graphTargetOf(inputs, { local: lo, sharedGraphs });
  // A shared graph only for a session a front end of this user registered (its token), never a bare call.
  if (t.kind === "shared" && !registered) return local(o.sid ? `session ${o.sid} isn't registered by a front end of yours` : "no session: only a session your front end registered may reach a shared graph");
  return t;
}

/** At most this many paths one Ix call may name for its graph target; past it, local. */
export const MAX_GRAPH_PATHS = 64;

/** One project's graph target (`p2p project show`, `p2p doctor`). */
export function projectGraphTarget(app: Pick<App, "env" | "file">, ref: Pick<ProjectRef, "id" | "name" | "repoPrivate">, doc: ProjectsDoc): GraphTarget {
  const lo = localGraphEndpoint(app.env, app.file);
  return graphTargetOf([{ name: ref.name, share: shareOf(doc, ref.id), ...(ref.repoPrivate ? { repoPrivate: true as const } : {}) }], { local: lo });
}

/** How a target reads in one line: `local only (http://localhost:8090)`, or the circle's shared graph. */
export function describeGraphTarget(t: GraphTarget): string {
  return t.kind === "local" ? `${GRAPH_LOCAL_ONLY} (${t.endpoint})` : `the shared graph of circle ${t.circle} (${t.endpoint})`;
}

/**
 * The Ix variables that could send an `ix` call somewhere other than its graph target, or carry a
 * cloud credential: Ix Pro's PAT mode (IX_PAT, IX_ORG, its endpoint override), the cloud push and
 * ingestion knobs, the OAuth secret, auto-map routing to the cloud. Every IX_* variable outside
 * IX_KEEP is dropped as well; these are named so tests and docs can point at them.
 */
export const IX_CLOUD_ENV: readonly string[] = ["IX_ENDPOINT", "IX_PAT", "IX_ORG", "IX_ORG_ID", "IX_PUSH_ENDPOINT", "IX_PUSH_TOKEN", "IX_OAUTH_CLIENT_SECRET", "IX_AUTO_MAP_CLOUD", "IX_AUTO_MAP", "IX_KARTR_UI_URL", "IX_VIEW_BACKEND_URL", "IX_VIEW_BACKEND_TOKEN"];

/** IX_* variables an `ix` call keeps: which binary (read by ext-ix, not ix), where Ix keeps its local state, and the local backend's token (Ix sends it to a loopback endpoint only). */
export const IX_KEEP: readonly string[] = ["IX_BIN", "IX_HOME", "IX_TOKEN"];

/**
 * The environment an extension gets (ExtContext.env), with the target pinned: every IX_* variable
 * outside IX_KEEP set to undefined (so a `{...process.env, ...ctx.env}` merge drops it too: an older
 * ext-ix spreads it), IX_ENDPOINT set to the target's endpoint, and readers kept from starting a
 * background `ix map` (Ix Pro routes a map to the cloud when an org session is active, whatever
 * IX_ENDPOINT says). Defence in depth: ext-ix builds its own allowlisted env from the target.
 */
export function graphPinnedEnv(env: Record<string, string | undefined>, target: GraphTarget, base: Record<string, string | undefined> = process.env): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = { ...env };
  const keep = new Set(IX_KEEP);
  for (const k of new Set([...Object.keys(base), ...Object.keys(env)])) if (/^IX_/i.test(k) && !keep.has(k.toUpperCase())) out[k] = undefined;
  out.IX_ENDPOINT = target.endpoint;
  out.IX_MAP_BACKGROUND_REFRESH = "0";
  out.IX_NO_UPDATE_CHECK = "1";
  return out;
}
