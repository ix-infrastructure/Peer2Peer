// Copyright 2026 Ix Infrastructure Inc.
//
// How short-lived processes reach the bridge of their Codex session:
//   - every bridge (MCP server process) writes a registry entry,
//     `<P2P_HOME>/codex/sessions/<pid>.json` (0600, in a 0700 folder), and
//     listens on a local socket (a Unix socket, or a named pipe on Windows);
//   - a Codex hook finds its session's entry by the hook's `session_id`
//     (once a bridge knows its thread), else by the Codex process both
//     descend from, and asks over the socket;
//   - `p2p codex held|release|decline|sessions`, run by the person in their
//     own terminal, reach every live bridge the same way.
// One JSON line each way per connection.

import { execFile } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { safeBinary, safeExecEnv } from "./knobs.js";

export type Entry = {
  v: 1;
  /** The bridge (MCP server) process. */
  pid: number;
  /** Its parent: the Codex process (or app-server) that started it. */
  codexPid: number;
  sock: string;
  sid: string;
  ref?: string;
  threadId?: string;
  cwd: string;
  label?: string;
  startedAt: number;
  activeAt: number;
};

export function registryDir(home: string): string {
  return join(home, "codex", "sessions");
}

function ensurePrivateDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    chmodSync(dir, 0o700);
  } catch {}
}

/** Writes this bridge's entry atomically (0600). */
export function writeEntry(home: string, entry: Entry): void {
  const dir = registryDir(home);
  ensurePrivateDir(dir);
  const file = join(dir, `${entry.pid}.json`);
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(entry), { mode: 0o600 });
  renameSync(tmp, file);
}

export function removeEntry(home: string, pid: number): void {
  rmSync(join(registryDir(home), `${pid}.json`), { force: true });
}

export function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** Live entries; files a crashed bridge left behind are removed. */
export function readEntries(home: string, alive: (pid: number) => boolean = isAlive): Entry[] {
  const dir = registryDir(home);
  let names: string[];
  try {
    names = readdirSync(dir).filter((n) => /^\d+\.json$/.test(n));
  } catch {
    return [];
  }
  const out: Entry[] = [];
  for (const name of names) {
    try {
      const e = JSON.parse(readFileSync(join(dir, name), "utf8")) as Entry;
      if (e.v !== 1 || typeof e.pid !== "number" || typeof e.sock !== "string" || typeof e.sid !== "string") continue;
      if (!alive(e.pid)) {
        rmSync(join(dir, name), { force: true });
        continue;
      }
      out.push(e);
    } catch {}
  }
  return out;
}

/** A socket path for this bridge: under P2P_HOME when short enough, else a private temp folder. */
export function socketPath(home: string, pid: number, platform: string = process.platform): string {
  // A random suffix, recorded only in the 0600 registry: a pipe name nobody can predict and squat first.
  if (platform === "win32") return `\\\\.\\pipe\\p2p-codex-${pid}-${randomBytes(16).toString("hex")}`;
  const dir = registryDir(home);
  ensurePrivateDir(dir);
  const p = join(dir, `${pid}.sock`);
  // sun_path is 104 bytes on macOS, 108 on Linux.
  if (Buffer.byteLength(p) < 100) return p;
  return join(mkdtempSync(join(tmpdir(), "p2p-codex-")), "s.sock");
}

/** Serves one JSON request per connection. */
export function serve(sock: string, handle: (req: Record<string, unknown>, conn: Socket) => Promise<unknown>): Promise<Server> {
  if (process.platform !== "win32") rmSync(sock, { force: true });
  const server = createServer((conn) => {
    let buf = "";
    conn.setEncoding("utf8");
    conn.on("error", () => {});
    conn.on("data", (chunk: string) => {
      buf += chunk;
      if (buf.length > 1_000_000) return conn.destroy();
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      const line = buf.slice(0, nl);
      buf = "";
      let req: Record<string, unknown>;
      try {
        req = JSON.parse(line);
      } catch {
        conn.end(JSON.stringify({ ok: false, reason: "bad request" }) + "\n");
        return;
      }
      handle(req, conn)
        .then((res) => conn.end(JSON.stringify(res) + "\n"))
        .catch((e) => conn.end(JSON.stringify({ ok: false, reason: String((e as Error)?.message ?? e) }) + "\n"));
    });
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(sock, () => {
      if (process.platform !== "win32") {
        try {
          chmodSync(sock, 0o600);
        } catch {}
      }
      server.unref();
      resolve(server);
    });
  });
}

/** One request to a bridge; rejects on timeout or a closed socket. */
export function ask<T = Record<string, unknown>>(sock: string, req: Record<string, unknown>, timeoutMs = 5_000): Promise<T> {
  return new Promise((resolve, reject) => {
    const conn = createConnection(sock);
    let buf = "";
    const timer = setTimeout(() => {
      conn.destroy();
      reject(new Error("timed out"));
    }, timeoutMs);
    conn.setEncoding("utf8");
    conn.on("connect", () => conn.write(JSON.stringify(req) + "\n"));
    conn.on("data", (chunk: string) => (buf += chunk));
    conn.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    conn.on("close", () => {
      clearTimeout(timer);
      try {
        resolve(JSON.parse(buf.trim()) as T);
      } catch {
        reject(new Error("no answer"));
      }
    });
  });
}

/** The parent of `pid` (POSIX `ps`), or undefined. */
function parentOf(pid: number): Promise<number | undefined> {
  return new Promise((resolve) => {
    execFile("/bin/ps", ["-o", "ppid=", "-p", String(pid)], { timeout: 2_000, env: safeExecEnv() }, (err, stdout) => {
      const n = Number(String(stdout).trim());
      resolve(err || !Number.isInteger(n) || n <= 1 ? undefined : n);
    });
  });
}

/** This process's ancestors, nearest first (at most `depth`). */
export async function ancestors(depth = 8): Promise<number[]> {
  const out: number[] = [];
  let pid: number | undefined = process.ppid;
  while (pid && pid > 1 && out.length < depth) {
    out.push(pid);
    if (process.platform === "win32") break;
    pid = await parentOf(pid);
  }
  return out;
}

/**
 * Which bridge a hook belongs to:
 *  1. the one bound to the hook's `session_id` (a bridge binds only to the
 *     thread a tool call's _meta names, never to what a hook says);
 *  2. else the one unbound bridge under the same Codex process. With more
 *     than one there, none: a guess could hand one session's messages to
 *     another, so the hook does nothing until a tool call binds them;
 *  3. on Windows only (no process tree to go by), the one unbound bridge
 *     there is.
 * Undefined when none fits: the hook then does nothing.
 */
export function findEntry(entries: readonly Entry[], o: { sessionId?: string; ancestors: readonly number[]; cwd?: string; platform?: string }): Entry | undefined {
  if (o.sessionId) {
    const bound = entries.find((e) => e.threadId === o.sessionId);
    if (bound) return bound;
  }
  const free = entries.filter((e) => !e.threadId);
  const related = free.filter((e) => o.ancestors.includes(e.codexPid) || o.ancestors.includes(e.pid));
  if (related.length > 0) return related.length === 1 ? related[0] : undefined;
  if ((o.platform ?? process.platform) === "win32" && free.length === 1) return free[0];
  return undefined;
}

// ── who is calling: the person, or something Codex started? ────────────────

/** The process on the other end of an accepted local socket, where the OS says (macOS lsof, Linux ss); else undefined. */
export async function peerPid(conn: Socket, run: (cmd: string, args: string[]) => Promise<string> = runOut): Promise<number | undefined> {
  const fd = (conn as unknown as { _handle?: { fd?: number } })._handle?.fd;
  if (typeof fd !== "number" || fd < 0) return undefined;
  try {
    if (process.platform === "darwin") return parseLsofPeer(await run("lsof", ["-nP", "-U", "-F", "pfdn"]), process.pid, fd);
    if (process.platform === "linux") {
      const link = await run("readlink", [`/proc/self/fd/${fd}`]);
      const inode = /socket:\[(\d+)\]/.exec(link)?.[1];
      return inode ? parseSsPeer(await run("ss", ["-xpn"]), inode) : undefined;
    }
  } catch {}
  return undefined;
}

/**
 * macOS `lsof -U -F pfdn`: our accepted socket (this pid, this fd) has a
 * kernel address `d`; the peer's record names it as `n->0x…`.
 */
export function parseLsofPeer(out: string, pid: number, fd: number): number | undefined {
  type Rec = { pid: string; fd: string; d?: string; n?: string };
  const recs: Rec[] = [];
  let cur: Rec | null = null;
  let p = "";
  for (const line of out.split("\n")) {
    if (!line) continue;
    const k = line[0];
    const v = line.slice(1);
    if (k === "p") p = v;
    else if (k === "f") recs.push((cur = { pid: p, fd: v }));
    else if (cur && (k === "d" || k === "n")) cur[k] = v;
  }
  const mine = recs.find((r) => r.pid === String(pid) && r.fd === String(fd));
  if (!mine?.d) return undefined;
  const peer = recs.find((r) => r.n === `->${mine.d}` && r.pid !== String(pid));
  const n = peer ? Number(peer.pid) : NaN;
  return Number.isInteger(n) && n > 0 ? n : undefined;
}

/**
 * Linux `ss -xpn`: the line whose peer inode is ours names the peer process
 * (`pid=…`). Socket paths may contain spaces, so columns aren't counted from
 * the left: the process column (`users:(…)`) is cut off the end, and the
 * peer's inode is then the last field.
 */
export function parseSsPeer(out: string, inode: string): number | undefined {
  for (const line of out.split("\n")) {
    const at = line.indexOf(" users:((");
    if (at < 0) continue;
    const fields = line.slice(0, at).trim().split(/\s+/);
    if (fields.length < 8 || fields[fields.length - 1] !== inode) continue;
    const m = /pid=(\d+)/.exec(line.slice(at));
    if (m) return Number(m[1]);
  }
  return undefined;
}

function runOut(cmd: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    // By absolute path from the system folders, with a scrubbed environment: never the project's PATH.
    const bin = cmd.startsWith("/") ? cmd : safeBinary(cmd);
    if (!bin) return reject(new Error(`${cmd} not found in the system folders`));
    execFile(bin, args, { timeout: 5_000, maxBuffer: 20_000_000, env: safeExecEnv() }, (err, stdout) => (err ? reject(err) : resolve(String(stdout))));
  });
}

/** The command name of `pid` (POSIX `ps`), or undefined. */
function commOf(pid: number): Promise<string | undefined> {
  return runOut("ps", ["-o", "comm=", "-p", String(pid)]).then(
    (s) => s.trim() || undefined,
    () => undefined,
  );
}

/**
 * Whether `pid` was started (at any depth) by the Codex process that runs
 * this bridge, by the bridge itself, or by any process named `codex`. Such
 * a caller may be the model's own (sandboxed) command, so it can't stand in
 * for the person.
 */
export async function descendsFromCodex(pid: number, codexPids: readonly number[], depth = 24): Promise<boolean> {
  let cur: number | undefined = pid;
  for (let i = 0; cur && cur > 1 && i < depth; i++) {
    if (codexPids.includes(cur)) return true;
    const comm = await commOf(cur);
    if (comm && /(^|\/)codex(\.exe)?$/i.test(comm)) return true;
    cur = await parentOf(cur);
  }
  return false;
}
