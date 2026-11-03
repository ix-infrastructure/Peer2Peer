// Copyright 2026 Ix Infrastructure Inc.
//
// Repository identity: how a sender says "this repo at this revision" so the
// receiver's Ix can find the same code in its own graph, without leaking a
// local path. A repo is named by its normalized remote ("host/owner/name":
// no scheme, no user or token, no port, no ".git", lower case), never by a
// directory.

import { execFile } from "node:child_process";
import { whichAbsolute } from "./which.js";
import { fail, isObj, LIMITS, optStr, str, type O } from "./text.js";

export interface RepoRef {
  /** "github.com/ix-infrastructure/peer2peer". */
  remote: string;
  /** A commit id (7-64 hex). */
  rev?: string;
  branch?: string;
}

const REMOTE_RE = /^[a-z0-9.-]+(?:\/[a-z0-9._~-]+){1,8}$/;
const REV_RE = /^[0-9a-f]{7,64}$/;
const BRANCH_RE = /^[A-Za-z0-9._/+@-]{1,128}$/;

/**
 * "https://user:tok@GitHub.com:443/Org/Repo.git", "git@github.com:org/repo",
 * "ssh://git@host/org/repo" → "github.com/org/repo". Undefined when it isn't a
 * remote (a local path, a file:// URL).
 */
export function normalizeRemote(url: string): string | undefined {
  let s = url.trim();
  if (s === "" || s.startsWith("/") || s.startsWith(".") || /^file:/i.test(s) || /^[A-Za-z]:[\\/]/.test(s)) return undefined;
  let host: string;
  let path: string;
  const scp = /^(?:[^@/\s]+@)?([^:/\s]+):(?!\/)(.+)$/.exec(s);
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s) && scp) {
    host = scp[1];
    path = scp[2];
  } else {
    let u: URL;
    try {
      u = new URL(s);
    } catch {
      return undefined;
    }
    if (u.protocol === "file:") return undefined;
    host = u.hostname;
    path = u.pathname;
  }
  s = `${host}/${path}`
    .toLowerCase()
    .replace(/\/+/g, "/")
    .replace(/\/$/, "")
    .replace(/\.git$/, "");
  return REMOTE_RE.test(s) ? s : undefined;
}

export function parseRepo(v: unknown, what: string): RepoRef {
  if (!isObj(v)) return fail(`${what} must be an object`);
  const o = v as O;
  const remote = str(o, "remote", LIMITS.remote, what);
  if (!REMOTE_RE.test(remote)) fail(`${what}.remote must be a normalized remote (host/owner/name)`);
  const rev = optStr(o, "rev", 64, what);
  if (rev !== undefined && !REV_RE.test(rev)) fail(`${what}.rev must be a commit id`);
  const branch = optStr(o, "branch", LIMITS.branch, what);
  if (branch !== undefined && !BRANCH_RE.test(branch)) fail(`${what}.branch has characters a branch can't`);
  return { remote, ...(rev ? { rev } : {}), ...(branch ? { branch } : {}) };
}

/**
 * Runs git (resolved from PATH's absolute entries: never a git planted in the
 * repo, the cwd) and returns its stdout, or undefined on any failure.
 */
export function gitOut(cwd: string, args: string[], env?: NodeJS.ProcessEnv, opts: { timeoutMs?: number; maxBuffer?: number; trim?: boolean } = {}): Promise<string | undefined> {
  const bin = whichAbsolute("git", env ?? process.env);
  if (!bin) return Promise.resolve(undefined);
  return new Promise((resolve) => {
    execFile(bin, args, { cwd, timeout: opts.timeoutMs ?? 5000, killSignal: "SIGKILL", maxBuffer: opts.maxBuffer ?? 1 << 20, env, windowsHide: true }, (err, stdout) =>
      resolve(err ? undefined : opts.trim === false ? stdout : stdout.trim()),
    );
  });
}

const git = (cwd: string, args: string[], env?: NodeJS.ProcessEnv) => gitOut(cwd, args, env);

export interface LocalRepo {
  /** The working tree's root (absolute: local use only, never sent). */
  root?: string;
  ref?: RepoRef;
}

/** The repo `cwd` is in: its root, normalized origin remote, HEAD and branch. */
export async function localRepo(cwd: string, env?: NodeJS.ProcessEnv): Promise<LocalRepo> {
  const root = await git(cwd, ["rev-parse", "--show-toplevel"], env);
  if (!root) return {};
  const url = await git(cwd, ["remote", "get-url", "origin"], env);
  const remote = url ? normalizeRemote(url) : undefined;
  const rev = await git(cwd, ["rev-parse", "HEAD"], env);
  const branch = await git(cwd, ["rev-parse", "--abbrev-ref", "HEAD"], env);
  if (!remote) return { root };
  return {
    root,
    ref: { remote, ...(rev && REV_RE.test(rev) ? { rev } : {}), ...(branch && branch !== "HEAD" && BRANCH_RE.test(branch) ? { branch } : {}) },
  };
}

/** How a received repo reference compares with the local checkout. */
export function compareRepo(theirs: RepoRef, mine: RepoRef | undefined): { sameRepo: boolean; sameRev?: boolean } {
  if (!mine) return { sameRepo: false };
  const sameRepo = theirs.remote === mine.remote;
  if (!sameRepo || !theirs.rev || !mine.rev) return { sameRepo };
  const n = Math.min(theirs.rev.length, mine.rev.length);
  return { sameRepo, sameRev: theirs.rev.slice(0, n) === mine.rev.slice(0, n) };
}
