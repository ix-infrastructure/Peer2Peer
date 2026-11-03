// Copyright 2026 Ix Infrastructure Inc.
//
// The `p2p codex …` commands, as plain functions the `p2p` CLI wires up:
//   install [--write] [--remove]   print (or apply) the Codex config
//   mcp                            the MCP server Codex starts
//   hook <Event>                   a Codex hook
//   sessions                       this machine's live Codex sessions
//   held                           messages held for the person, with previews
//   release <id> / decline <id>    the person's Deliver / Decline
// `held`, `release`, `decline` and `install --write` are the person's own:
// run from inside a Codex tool call (CODEX_THREAD_ID is set there), they are
// refused. That is a backstop, like the PreToolUse guard, not a sandbox.

import { writeNonce } from "./confirm.js";
import { applyChanges, codexHomeOf, installEnv, planChanges, printedInstructions, type InstallPlan } from "./install.js";
import { ask, readEntries } from "./ipc.js";
import { inert } from "./lib.js";
import { isAbsolute, join, resolve } from "node:path";
import { bridgeHome, pinFile, tempRoots, unsafeLocation, userHome, writePin } from "./knobs.js";
import type { Env } from "./server.js";

export class CodexCommandError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export type Output = { json: unknown; human: string };

/** Refuses a person-only command run from inside a Codex session's own tool call. */
export function requirePerson(env: Env, what: string): void {
  if (env.CODEX_THREAD_ID || env.CODEX_SESSION_ID) {
    throw new CodexCommandError("refused", `${what} is for you to run in your own terminal, not from inside a Codex session (its tool calls set CODEX_THREAD_ID)`);
  }
}

export function installCommand(o: { env: Env; node?: string; script: string; codexHome?: string; write?: boolean; remove?: boolean; now?: Date; pinFile?: string }): Output {
  const env = installEnv(o.env);
  // Codex runs the server with its own PATH (and a project config can change it): the node binary by absolute path.
  const node = o.node && isAbsolute(o.node) ? o.node : process.execPath;
  const plan: InstallPlan = { codexHome: o.codexHome ?? codexHomeOf(o.env), node, script: o.script, ...(Object.keys(env).length > 0 ? { env } : {}) };
  if (!o.write) {
    if (o.remove) return { json: { written: false, remove: true, ...planChanges(plan, { remove: true }) }, human: "Run with --write to remove the peer2peer entries (each file is backed up first)." };
    return { json: { written: false, plan, instructions: printedInstructions(plan) }, human: printedInstructions(plan) };
  }
  requirePerson(o.env, "`p2p codex install --write`");
  const { changes, error } = planChanges(plan, { remove: o.remove === true });
  if (error) throw new CodexCommandError("conflict", error);
  const stamp = (o.now ?? new Date()).toISOString().replace(/[:.]/g, "-");
  const done = applyChanges(changes, stamp);
  // A CODEX_HOME other than ~/.codex is pinned outside any project: where the bridge can't read Codex's
  // own environment (Windows, a non-dumpable Codex), it trusts no other CODEX_HOME (knobs.ts).
  const codexHome = resolve(plan.codexHome);
  const isDefault = codexHome === join(userHome(), ".codex");
  const pin = o.pinFile ?? pinFile();
  const pinned = !isDefault || o.remove ? writePin(codexHome, { file: pin, remove: o.remove === true }) : false;
  const temp = unsafeLocation(codexHome, { projectDirs: [], temp: tempRoots([o.env.TMPDIR]) });
  const lines =
    done.length === 0
      ? [o.remove ? "Nothing to remove: no peer2peer entries found." : "Already installed: nothing changed."]
      : done.map((c) => `${o.remove ? "Updated" : "Wrote"} ${c.path}${c.backup ? ` (backup: ${c.backup})` : ""}`);
  if (pinned) lines.push(`${o.remove ? "Unpinned" : "Pinned"} ${codexHome} in ${pin}`);
  if (temp && !o.remove) lines.push(`Warning: the bridge never uses a CODEX_HOME in a temp folder (${temp}); it will hold every message there. Use a folder of your own.`);
  if (!o.remove && done.length > 0) {
    lines.push("", "Next: restart Codex, then trust the new hooks once with /hooks.", "Your identity: run `p2p setup` (once per machine) and `p2p join <code>` with a code from a friend, in this terminal.");
  }
  return { json: { written: true, files: done.map((c) => ({ path: c.path, ...(c.backup ? { backup: c.backup } : {}) })) }, human: lines.join("\n") };
}

type HeldAnswer = { ok: boolean; session?: Record<string, unknown>; held?: { id: string; from: string; at: number; why: string; kind: string; toUser: boolean }[] };

async function everySession(env: Env): Promise<{ sock: string; answer: HeldAnswer }[]> {
  const home = bridgeHome(env);
  const out: { sock: string; answer: HeldAnswer }[] = [];
  for (const e of readEntries(home)) {
    try {
      out.push({ sock: e.sock, answer: await ask<HeldAnswer>(e.sock, { op: "held" }, 3_000) });
    } catch {}
  }
  return out;
}

export async function sessionsCommand(o: { env: Env }): Promise<Output> {
  const all = await everySession(o.env);
  const sessions = all.map((s) => s.answer.session).filter(Boolean) as Record<string, unknown>[];
  const human =
    sessions.length === 0
      ? "No live Codex sessions with Peer2Peer on this machine."
      : sessions
          .map((s) => `${inert(String(s.address))}  sid ${inert(String(s.sid))}  ${s.status}${s.online ? "" : " (offline)"}  ${s.private ? "private" : `circle ${inert(String(s.circle ?? ""))}`}  held ${s.held}  ${s.holdsFromOthers ? "holds messages from others" : "delivers from friends"} (${inert(String(s.mode))})${s.hooks ? "" : "  [no hooks seen]"}${s.problem ? `\n  ! ${inert(String(s.problem))}` : ""}`)
          .join("\n") + "\n\nShare a session with someone: p2p session roster <sid> --add <user>";
  return { json: { sessions }, human };
}

export async function heldCommand(o: { env: Env; now?: number }): Promise<Output> {
  requirePerson(o.env, "`p2p codex held`");
  const all = await everySession(o.env);
  const rows = all.flatMap((s) => (s.answer.held ?? []).map((h) => ({ ...h, session: String(s.answer.session?.address ?? "") })));
  const now = o.now ?? Date.now();
  const human =
    rows.length === 0
      ? "Nothing is held for you in your Codex sessions."
      : rows
          .map((h) => `${inert(h.id)}  from ${inert(h.from)}  to ${inert(h.session)}  (${Math.max(0, Math.round((now - h.at) / 60_000))} min ago)\n  why: ${inert(h.why)}\n  p2p codex release ${inert(h.id)}   |   p2p codex decline ${inert(h.id)}`)
          .join("\n\n") + "\n\nThe text isn't shown here. `p2p codex release` shows it, with a confirmation code, in that session's Codex window.";
  return { json: { held: rows }, human };
}

export interface PersonIo {
  /** Whether stdin and stdout are a real terminal. */
  isTTY: boolean;
  /** Asks the person one line (on the terminal). */
  prompt?: (question: string) => Promise<string>;
}

/**
 * `p2p codex release|decline <id>`: the person's own, in a real terminal.
 * Each request first writes a nonce file into P2P_HOME/codex/confirm/,
 * which the bridge accepts only while P2P_HOME is out of the session's
 * sandbox; when its Codex window is a terminal, the bridge also prints a
 * one-time code there that the person types back here.
 */
export async function resolveCommand(o: { env: Env; id: string; decline?: boolean; io: PersonIo }): Promise<Output> {
  const op = o.decline ? "decline" : "release";
  requirePerson(o.env, `\`p2p codex ${op}\``);
  if (!o.io.isTTY || !o.io.prompt) throw new CodexCommandError("refused", `\`p2p codex ${op}\` needs a real terminal: run it yourself in your own terminal`);
  const home = bridgeHome(o.env);
  for (const e of readEntries(home)) {
    let held: HeldAnswer;
    try {
      held = await ask<HeldAnswer>(e.sock, { op: "held" }, 5_000);
    } catch {
      continue;
    }
    if (!held.held?.some((h) => h.id === o.id)) continue;
    // Each request carries a fresh nonce file, which only something outside the sandbox can write.
    let r = await ask<{ ok: boolean; needsCode?: boolean; reason?: string }>(e.sock, { op, id: o.id, nonce: writeNonce(home, op, o.id) }, 15_000);
    for (let tries = 0; !r.ok && r.needsCode && tries < 3; tries++) {
      const code = (await o.io.prompt(`Type the code shown in that session's Codex window: `)).trim();
      if (!code) break;
      r = await ask(e.sock, { op, id: o.id, code, nonce: writeNonce(home, op, o.id) }, 15_000);
      if (!r.ok && !r.needsCode && r.reason === "wrong code") r = { ok: false, needsCode: true, reason: r.reason };
    }
    if (!r.ok) throw new CodexCommandError("refused", inert(r.reason ?? `not ${op}d`));
    return {
      json: { id: o.id, [o.decline ? "declined" : "released"]: true },
      human: o.decline ? "Declined: the sender gets one delivery notice." : "Released: the session's model reads it at its next prompt, tool round or turn end.",
    };
  }
  throw new CodexCommandError("not_found", `no live Codex session holds ${inert(o.id)} (it may have expired after 10 minutes)`);
}
