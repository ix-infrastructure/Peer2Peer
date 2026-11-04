// Copyright 2026 Ix Infrastructure Inc.
//
// `p2p codex hook <Event>`: a Codex hook. Codex runs it with the event's JSON
// on stdin and reads JSON from stdout. It:
//   - PreToolUse: refuses shell commands that run mutating `p2p` verbs or
//     read the backup phrase / key store (a backstop, like the Claude mod's
//     guard: parsed conservatively, not a sandbox);
//   - every other event: reports to its session's bridge over the local
//     socket and prints what the bridge answers (context for the model, or a
//     Stop continuation).
// What it reports: the session id, cwd, `permission_mode` and (PostToolUse)
// the files a tool changed. Never the prompt text: that stays in this
// process. The socket is reachable by anything running as the user (a
// sandboxed command too), so the bridge treats a report as untrusted: it
// can only make the mode stricter, it never binds the thread, and files
// must exist in the repo.
// Failing open is safe here (the hold rule lives in the bridge, and no
// bridge means no messages): any error prints nothing and exits 0.

import { isAbsolute } from "node:path";
import type { CodexMode } from "./lib.js";
import { boundaryRefusal, editedFiles, MAX_COMMAND_PATHS, mutatingP2PVerb, namesP2PCli, resolveLike, shellPaths, touchesSecrets } from "./lib.js";
import { ancestors, ask, findEntry, readEntries } from "./ipc.js";

const SHELL_TOOLS = /^(bash|shell|local_shell|exec_command|unified_exec|container\.exec|powershell|write_stdin)$/i;

/** The shell command a PreToolUse payload carries, as one string. */
export function commandOf(input: unknown): string {
  if (typeof input === "string") return input;
  if (typeof input !== "object" || input === null) return "";
  const o = input as Record<string, unknown>;
  const c = o.command ?? o.cmd ?? o.chars;
  if (Array.isArray(c)) return c.map(String).join(" ");
  return typeof c === "string" ? c : "";
}

/** PreToolUse: the denial for a shell command the model may not run, or null. */
export function guard(toolName: string, input: unknown, binNames: readonly string[] = [], ownSid?: string): string | null {
  if (!SHELL_TOOLS.test(toolName)) return null;
  const command = commandOf(input);
  const verb = mutatingP2PVerb(command, binNames);
  if (verb) {
    return `Refused by Peer2Peer: \`p2p ${verb}\` changes who reaches your user (or touches their keys or held messages). Only your user runs it, in their own terminal. Tell them what you'd suggest instead.`;
  }
  if (touchesSecrets(command)) return "Refused by Peer2Peer: that command reaches the Peer2Peer backup phrase or key store, which never enters model context.";
  const boundary = boundaryRefusal(command, ownSid);
  if (boundary) return `Refused by Peer2Peer: ${boundary}.`;
  return null;
}

/**
 * The paths a tool call names outside its folder (a shell command's absolute, ~ and .. paths; the
 * files an apply_patch or edit names), resolved: the bridge binds each one's project (projects.ts).
 */
export function touchedPaths(toolName: string, input: unknown, cwd: string | undefined, home: string | undefined): { paths: string[]; over: boolean } {
  const out: string[] = [];
  let over = false;
  if (SHELL_TOOLS.test(toolName)) {
    // No folder to resolve against: what it names can't be placed, so private.
    if (!cwd) over = true;
    else {
      const r = shellPaths(commandOf(input), cwd, home);
      out.push(...r.paths);
      over ||= r.over;
    }
  }
  for (const f of editedFiles(toolName, input)) {
    if (cwd || isAbsolute(f)) out.push(resolveLike(cwd ?? "/", f));
    else over = true;
  }
  if (out.length > MAX_COMMAND_PATHS) over = true;
  return { paths: out.slice(0, MAX_COMMAND_PATHS), over };
}

export interface HookDeps {
  home: string;
  /** P2P_BIN and the like, so the guard recognises the CLI under another name. */
  binNames?: readonly string[];
  ancestors?: () => Promise<number[]>;
  /** The user's home folder, for `~` in shell paths. */
  homeDir?: string;
}

/** Runs one hook: the JSON to print (empty for nothing). */
export async function runHook(event: string, stdin: string, deps: HookDeps): Promise<string> {
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(stdin || "{}");
    if (typeof payload !== "object" || payload === null) return "";
  } catch {
    return "";
  }
  const name = typeof payload.hook_event_name === "string" ? payload.hook_event_name : event;
  const sessionId = typeof payload.session_id === "string" ? payload.session_id : undefined;
  const cwd = typeof payload.cwd === "string" ? payload.cwd : undefined;
  const entries = readEntries(deps.home);
  // A bridge already bound to this thread needs no process-tree walk (hooks run on every tool call).
  const bound = sessionId ? entries.find((e) => e.threadId === sessionId) : undefined;
  const entry = bound ?? findEntry(entries, { ...(sessionId ? { sessionId } : {}), ancestors: await (deps.ancestors ?? ancestors)(), ...(cwd ? { cwd } : {}) });
  if (name === "PreToolUse") {
    // This bridge's own session is the only one the model's shell may name (none known: none at all).
    // Fails closed: a guard that throws on a command naming p2p denies it.
    let deny: string | null;
    try {
      deny = guard(String(payload.tool_name ?? ""), payload.tool_input, deps.binNames, entry?.sid);
    } catch {
      deny = namesP2PCli(commandOf(payload.tool_input)) ? "Refused by Peer2Peer: this command couldn't be checked; ask your user to run it." : null;
    }
    if (deny) return JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: deny } });
    // Paths the call reaches bind their projects before it runs (any that can't be placed: private).
    const t = entry ? touchedPaths(String(payload.tool_name ?? ""), payload.tool_input, cwd, deps.homeDir) : { paths: [], over: false };
    if (entry && (t.paths.length > 0 || t.over)) {
      await ask(entry.sock, { op: "hook", report: { event: "PreToolUse", ...(sessionId ? { sessionId } : {}), ...(cwd ? { cwd } : {}), mode: {}, dirs: t.paths, ...(t.over ? { over: true } : {}) } }, 8_000).catch(() => undefined);
    }
    return "";
  }
  // Subagents' events belong to the parent's turn: only the main thread reports.
  if (typeof payload.agent_id === "string" && payload.agent_id !== "") return "";
  if (!entry) return "";
  // Only what may make the bridge stricter: it reads the mode itself from
  // this thread's rollout file, and ignores a report that would loosen it.
  const mode: CodexMode = typeof payload.permission_mode === "string" ? { permissionMode: payload.permission_mode } : {};
  const report = {
    event: name,
    ...(sessionId ? { sessionId } : {}),
    ...(cwd ? { cwd } : {}),
    mode,
    ...(name === "PostToolUse" ? { files: editedFiles(String(payload.tool_name ?? ""), payload.tool_input).slice(0, 50) } : {}),
    ...(name === "Stop" ? { stopHookActive: payload.stop_hook_active === true } : {}),
  };
  try {
    const r = await ask<{ ok: boolean; output?: Record<string, unknown> }>(entry.sock, { op: "hook", report }, 8_000);
    return r.ok && r.output && Object.keys(r.output).length > 0 ? JSON.stringify(r.output) : "";
  } catch {
    return "";
  }
}
