// Copyright 2026 Ix Infrastructure Inc.
//
// Whether a Claude Code or Codex process is an ancestor of this one (projects.ts agentContext):
// environment variables can be scrubbed by the agent, the process tree only hidden by detaching
// (`setsid`, a daemon), which the /dev/tty confirmation covers (tty-confirm.ts). Its own module so
// the test suites can replace it (vitest setup) without any hook in the shipped CLI.

import { execFileSync } from "node:child_process";

let cached: boolean | undefined;

/** An executable that is Claude Code or Codex, by its basename (argv0) only: never a word elsewhere on a command line. */
export function isAgentProcess(executable: string): boolean {
  const base = (executable.trim().split(/[\\/]/).pop() ?? "").toLowerCase();
  return base === "claude" || base === "codex" || base === "claude.exe" || base === "codex.exe";
}

/**
 * Walks parent process ids with `ps` (unix), comparing each one's executable (`comm`) by basename.
 * Windows, or `ps` unable to answer: false (the token and the tty confirmation still apply).
 */
export function agentAncestor(): boolean {
  if (cached !== undefined) return cached;
  cached = false;
  if (process.platform === "win32") return cached;
  try {
    let pid = process.ppid;
    for (let i = 0; i < 64 && pid > 1; i++) {
      const line = execFileSync("ps", ["-o", "ppid=,comm=", "-p", String(pid)], { encoding: "utf8", timeout: 2000, stdio: ["ignore", "pipe", "ignore"] }).trim();
      const sp = line.search(/\s/);
      if (sp < 0) break;
      const ppid = Number(line.slice(0, sp));
      if (isAgentProcess(line.slice(sp + 1))) {
        cached = true;
        break;
      }
      if (!Number.isSafeInteger(ppid)) break;
      pid = ppid;
    }
  } catch {
    // unknown
  }
  return cached;
}
