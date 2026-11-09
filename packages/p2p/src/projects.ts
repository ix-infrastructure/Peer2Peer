// Copyright 2026 Ix Infrastructure Inc.
//
// Project boundaries (docs/concepts.md "Projects", threat model "Project boundaries").
//
//  - A project is a git repository, keyed by its normalised remote URL (if any) and its git
//    common dir, so every worktree and subfolder of one clone is the same project. Outside git,
//    the real path of the folder.
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
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { basename, delimiter, dirname, isAbsolute, join, resolve } from "node:path";
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
export function sessionDirs(env: Record<string, string | undefined>): { dirs: string[]; over: boolean } {
  const extra = (env.P2P_PROJECT_DIRS ?? "").split(delimiter).filter((x) => x.trim() !== "" && isAbsolute(x.trim()));
  // Past the cap (or when the front end says it dropped some): private, never "the first N".
  const over = extra.length > MAX_SESSION_DIRS || env.P2P_PROJECT_DIRS_OVER === "1";
  return { dirs: [sessionWorkdir(env), ...extra.slice(0, MAX_SESSION_DIRS)], over };
}

/** At most this many folders a front end passes per call; past it the session is private. */
export const MAX_SESSION_DIRS = 512;

/** At most this many projects per session; past it the session is private. */
export const MAX_SESSION_PROJECTS = 16;
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
}

export type ProjectShare = "private" | { circles: string[]; people: string[] };

export interface ProjectPolicyRec {
  name: string;
  root: string;
  remote?: string;
  share: ProjectShare;
  at: number;
}

export interface ProjectsDoc {
  v: 1;
  projects: Record<string, ProjectPolicyRec>;
  /** When this device showed the one-time notice that sessions no longer follow the default circle. */
  noticeAt?: number;
}

export interface SessionBinding {
  projects: Record<string, { name: string; repoPrivate?: true }>;
  /** More than MAX_SESSION_PROJECTS projects or MAX_SESSION_DIRS folders: private. */
  over?: true;
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

/** What a session may reach. `none`: the person's own session, or one not bound yet. */
export type Ceiling = { kind: "none" } | { kind: "private"; why: string } | { kind: "shared"; circles: string[]; people: string[] };

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

/** The nearest existing directory at or above `p`, as a real path. */
function existingDir(p: string): string {
  let cur = resolve(p);
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
 * The project `dir` belongs to, read from the files alone (git is never run: no hook, fsmonitor
 * or config of the repository's can execute). A `.git` directory or `gitdir:` file up the tree
 * marks a working tree; its common dir (`commondir` for a linked worktree) identifies the clone.
 */
export function projectOf(dir: string): ProjectRef {
  const start = existingDir(isAbsolute(dir) ? dir : resolve(dir));
  let cur = start;
  for (let i = 0; i < 4096; i++) {
    const dotgit = join(cur, ".git");
    // Anything named .git here (a folder, a file, a symlink, even a broken or unreadable one) ends
    // the walk: this folder is its own project, never the parent repository's.
    let present: boolean;
    try {
      lstatSync(dotgit);
      present = true;
    } catch {
      present = false;
    }
    if (present) {
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
        return { id: `pj_${sha(`dir\n${cur}`).slice(0, 24)}`, name: clean(basename(cur)) || "folder", kind: "dir", root: cur };
      }
      {
        let common = gitDir;
        const cd = readSmall(join(gitDir, "commondir"))?.trim();
        if (cd) common = resolve(gitDir, cd);
        common = real(common);
        const urls = remotesOf(readSmall(join(common, "config")) ?? "");
        const remote = urls.map(normalizeRemote).find((x): x is string => x !== undefined);
        const main = basename(common) === ".git" ? dirname(common) : common;
        const name = clean(remote ? (remote.split("/").pop() ?? "") : basename(main)) || clean(basename(cur)) || "project";
        return {
          id: `pj_${sha(`git\n${remote ?? ""}\n${common}`).slice(0, 24)}`,
          name,
          kind: "git",
          root: cur,
          ...(remote ? { remote } : {}),
          ...(existsSync(join(cur, PRIVATE_MARKER)) ? { repoPrivate: true as const } : {}),
        };
      }
    }
    const up = dirname(cur);
    if (up === cur) break;
    cur = up;
  }
  return { id: `pj_${sha(`dir\n${start}`).slice(0, 24)}`, name: clean(basename(start)) || "folder", kind: "dir", root: start };
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
    graph: projectGraphTarget(app, ref, d),
  };
}

/**
 * `p2p project share`: share the project at `dir` with circles you joined and friends. Replaces the
 * project's shares with exactly these (`add` keeps the ones it has). Only ever the person's
 * command: no session or file can run it for them (the mod and the Codex bridge refuse it from a
 * model).
 */
export async function shareProject(app: App, dir: string, targets: { circles?: string[]; people?: string[]; add?: boolean }): Promise<{ project: ProjectView; warnings: string[] }> {
  const ref = projectOf(dir);
  if (ref.repoPrivate) {
    throw new CliError("repo_private", `${ref.name} asks to stay private: its repository has ${PRIVATE_MARKER} at the top level. Peer2Peer never shares it; remove that file from your copy first if you mean to`);
  }
  const { resolveCircle } = await import("./circle-ops.js");
  const circles: string[] = [];
  const warnings: string[] = [];
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
    const next: ProjectsDoc = { ...d, projects: { ...d.projects, [ref.id]: { name: ref.name, root: ref.root, ...(ref.remote ? { remote: ref.remote } : {}), share, at: Date.now() } } };
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

/** `p2p project show`: the project at `dir`, its policy and why. */
export async function showProject(app: App, dir: string): Promise<ProjectView> {
  return projectView(app, projectOf(dir));
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
  o: { person?: boolean; over?: boolean; constraint?: ProjectShare; inbound?: boolean } = {},
): Promise<SessionBinding | undefined> {
  if (sid === PERSON_SESSION) {
    if (o.person) return undefined;
    throw new CliError("usage", `session ${PERSON_SESSION} is your own terminal's (p2p tui, or p2p send typed with no --from-session); an agent sends from its own session`);
  }
  const refs = new Map<string, ProjectRef>();
  for (const d of dirs) {
    if (typeof d !== "string" || d.trim() === "") continue;
    const r = projectOf(d);
    refs.set(r.id, r);
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
    let over = have?.over === true || o.over === true;
    for (const r of refs.values()) {
      const prev = projects[r.id];
      if (!prev && Object.keys(projects).length >= MAX_SESSION_PROJECTS) {
        over = true;
        continue;
      }
      // Once a repository asked for privacy, it stays asked for this session.
      projects[r.id] = { name: r.name, ...(r.repoPrivate || prev?.repoPrivate ? { repoPrivate: true as const } : {}) };
    }
    const constraints = [...(have?.constraints ?? [])];
    if (o.constraint !== undefined && !constraints.some((c) => JSON.stringify(c) === JSON.stringify(o.constraint))) {
      if (constraints.length >= MAX_SESSION_CONSTRAINTS) over = true;
      else constraints.push(o.constraint);
    }
    const registered = front || have?.registered === true;
    const unregistered = !registered && have?.unregistered === true;
    const next: SessionBinding = {
      projects,
      ...(over ? { over: true as const } : {}),
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

/** Whether a person-only path (session `tui`) may run here: the person's front end, or no agent in sight (then a terminal "yes" too). */
export function personHere(app: Pick<App, "env"> & { front?: boolean }): boolean {
  return app.front === true || !agentContext(app.env);
}

export async function sessionBinding(app: App, sid: string): Promise<SessionBinding | undefined> {
  return ((await app.state.get("sessionProjects")) as SessionProjectsDoc | undefined)?.[sid];
}

/**
 * The most a session may reach: the intersection of every bound project's policy. Unmapped,
 * private and repository-private projects make it private, and so does an empty intersection.
 */
export async function sessionCeiling(app: App, sid: string, binding?: SessionBinding | null): Promise<Ceiling> {
  if (sid === PERSON_SESSION) return { kind: "none" };
  const b = binding === null ? undefined : (binding ?? (await sessionBinding(app, sid)));
  if (!b || (Object.keys(b.projects).length === 0 && !b.constraints?.length && !b.unregistered && !b.over)) return { kind: "none" };
  if (b.over) return { kind: "private", why: `it worked in more than ${MAX_SESSION_PROJECTS} projects (or ${MAX_SESSION_DIRS} folders)` };
  if (b.unregistered) return { kind: "private", why: "an agent named it, and no front end of yours has registered it" };
  const doc = await projectsDoc(app);
  let circles: Set<string> | undefined;
  let people: Set<string> | undefined;
  const shares: { name: string; share: ProjectShare }[] = [];
  for (const [id, p] of Object.entries(b.projects)) {
    if (p.repoPrivate) return { kind: "private", why: `${p.name} asks to stay private (${PRIVATE_MARKER})` };
    const share = shareOf(doc, id);
    if (share === "private") return { kind: "private", why: doc.projects[id] ? `${p.name} is private` : `${p.name} isn't shared (projects are private until you share them)` };
    shares.push({ name: p.name, share });
  }
  for (const c of b.constraints ?? []) {
    if (c === "private") return { kind: "private", why: "a private session of yours sent it a message" };
    shares.push({ name: "a session of yours that sent it a message", share: c });
  }
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
    const names = shares.map((x) => x.name);
    return { kind: "private", why: names.length > 1 ? `its projects (${names.join(", ")}) share nobody in common` : `${names[0]} shares nobody you can reach` };
  }
  return { kind: "shared", circles: joined.sort(), people: ppl.sort() };
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

/** How to tell the person to share, for an error a model may read: the person's command, never a flag for the caller. */
export function shareHint(names: string[]): string {
  const what = names.length === 1 ? `the project ${names[0]}` : `each of ${names.join(", ")}`;
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
  throw new CliError("not_shared", `session ${sid} works in ${names.join(", ") || "a project"}, and Peer2Peer won't carry anything from it to ${who}: ${why}. ${shareHint(names).replace(/^o/, "O")}`, {
    delivered: false,
    project: { names, policy: c.kind },
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
  circles?: string[];
  people?: string[];
}

export async function sessionProjectView(app: App, sid: string): Promise<SessionProjectView> {
  const b = await sessionBinding(app, sid);
  const c = await sessionCeiling(app, sid, b ?? null);
  const projects = Object.entries(b?.projects ?? {}).map(([id, p]) => ({ id, name: p.name, ...(p.repoPrivate ? { repoPrivate: true as const } : {}) }));
  if (c.kind === "private") return { projects, policy: "private", why: c.why };
  if (c.kind === "shared") return { projects, policy: "shared", circles: c.circles, people: c.people };
  return { projects, policy: "none" };
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
