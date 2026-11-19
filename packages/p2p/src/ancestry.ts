// Copyright 2026 Ix Infrastructure Inc.
//
// Whether a Claude Code or Codex process is an ancestor of this one (projects.ts agentContext):
// environment variables can be scrubbed by the agent, the process tree only hidden by detaching
// (`setsid`, a daemon), which the /dev/tty confirmation covers (tty-confirm.ts). Its own module so
// the test suites can replace it (vitest setup) without any hook in the shipped CLI.
//
// The tree is read from /proc on Linux and with the system's own `ps` by absolute path elsewhere,
// never through PATH (a `ps` an agent put first on PATH could answer "no agent"). When it can't be
// read, the answer is "unknown", and the person-only gates treat unknown as an agent's session
// (projects.ts assertPersonForWidening): fail closed. The person's token still works there.

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";

export type Ancestry = "agent" | "none" | "unknown";

let cached: Ancestry | undefined;

/** An executable that is Claude Code or Codex, by its basename (argv0) only: never a word elsewhere on a command line. */
export function isAgentProcess(executable: string): boolean {
  const base = (executable.trim().split(/[\\/]/).pop() ?? "").toLowerCase();
  return base === "claude" || base === "codex" || base === "claude.exe" || base === "codex.exe";
}

/** A runtime that runs an agent's npm package as a script (`node …/@anthropic-ai/claude-code/cli.js`). */
function isScriptHost(comm: string): boolean {
  const base = (comm.trim().split(/[\\/]/).pop() ?? "").toLowerCase();
  return base === "node" || base === "nodejs" || base === "bun" || base === "node.exe";
}

/**
 * Whether a script host's command line runs Claude Code's or Codex's npm package: its script (the
 * first argument after the runtime and its options) lies inside `@anthropic-ai/claude-code` or
 * `@openai/codex`. A path, never a word elsewhere on the line.
 */
export function isAgentScript(args: string): boolean {
  const words = args.split(/\s+/).filter(Boolean);
  const script = words.slice(1).find((w) => !w.startsWith("-")) ?? "";
  const p = script.replace(/\\/g, "/");
  return p.includes("/@anthropic-ai/claude-code/") || p.includes("/@openai/codex/");
}

/** One process as the walk sees it: its parent, its executable, and (asked only for a script host) its command line. */
export interface ProcInfo {
  ppid: number;
  comm: string;
  args: () => string;
}

/** The system's `ps`, by absolute path (never PATH), or undefined. */
export const PS_PATHS: readonly string[] = ["/bin/ps", "/usr/bin/ps"];
function systemPs(): string | undefined {
  return PS_PATHS.find((p) => existsSync(p));
}

/** Reads one process from /proc (Linux). Throws when it can't. */
function procRead(pid: number): ProcInfo {
  const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
  // "<pid> (<comm>) <state> <ppid> …": comm may hold spaces and parentheses, so read after the last ")".
  const close = stat.lastIndexOf(")");
  if (close < 0) throw new Error("unreadable stat");
  const ppid = Number(stat.slice(close + 2).split(" ")[1]);
  if (!Number.isSafeInteger(ppid)) throw new Error("unreadable stat");
  // The executable's name, as `ps -o comm=` gives it on Linux.
  const comm = stat.slice(stat.indexOf("(") + 1, close);
  return {
    ppid,
    comm,
    args: () => {
      try {
        return readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0").join(" ").trim();
      } catch {
        return "";
      }
    },
  };
}

/** Reads one process with the system's `ps`. Throws when it can't. */
function psRead(ps: string, pid: number): ProcInfo {
  const line = execFileSync(ps, ["-o", "ppid=,comm=", "-p", String(pid)], { encoding: "utf8", timeout: 2000, stdio: ["ignore", "pipe", "ignore"], env: { LC_ALL: "C" } }).trim();
  const sp = line.search(/\s/);
  if (sp < 0) throw new Error("unreadable ps line");
  const ppid = Number(line.slice(0, sp));
  if (!Number.isSafeInteger(ppid)) throw new Error("unreadable ps line");
  return {
    ppid,
    comm: line.slice(sp + 1),
    args: () => {
      try {
        return execFileSync(ps, ["-o", "args=", "-p", String(pid)], { encoding: "utf8", timeout: 2000, stdio: ["ignore", "pipe", "ignore"], env: { LC_ALL: "C" } }).trim();
      } catch {
        return "";
      }
    },
  };
}

/**
 * Walks parent processes from `start`, comparing each one's executable by basename (and a script
 * host's script path). "agent" on a match; "none" once the walk reaches the root (pid 1 or 0);
 * "unknown" when a process can't be read or the walk runs past 64 steps.
 */
export function walkAncestry(start: number, read: (pid: number) => ProcInfo): Ancestry {
  let pid = start;
  for (let i = 0; i < 64; i++) {
    if (pid <= 1) return "none";
    let p: ProcInfo;
    try {
      p = read(pid);
    } catch {
      return "unknown";
    }
    if (isAgentProcess(p.comm) || (isScriptHost(p.comm) && isAgentScript(p.args()))) return "agent";
    if (p.ppid === pid) return "unknown";
    pid = p.ppid;
  }
  return "unknown";
}

/** This process's ancestry, read once. Windows: "none" (the token and the terminal confirmation still apply). */
export function ancestry(): Ancestry {
  if (cached !== undefined) return cached;
  if (process.platform === "win32") return (cached = "none");
  if (process.platform === "linux" && existsSync("/proc/self/stat")) return (cached = walkAncestry(process.ppid, procRead));
  const ps = systemPs();
  cached = ps ? walkAncestry(process.ppid, (pid) => psRead(ps, pid)) : "unknown";
  return cached;
}

/** Whether a Claude Code or Codex process is an ancestor of this one. */
export function agentAncestor(): boolean {
  return ancestry() === "agent";
}

/** Whether this process's ancestry couldn't be read (the person-only gates then fail closed). */
export function ancestryUnknown(): boolean {
  return ancestry() === "unknown";
}
