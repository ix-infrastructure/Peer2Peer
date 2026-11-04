// Copyright 2026 Ix Infrastructure Inc.
//
// `p2p tui`: interactive only. It refuses to start unless stdin and stdout
// are both a terminal, and refuses inside an agent's tool call (Codex and
// Claude Code set CODEX_THREAD_ID / CLAUDECODE there); the Claude mod's
// command guard refuses it too. Diagnostics the app would print while the
// TUI owns the screen are kept and printed once the terminal is restored.

import type { ReadStream, WriteStream } from "node:tty";
import type { App, Io } from "../app.js";
import type { Env } from "../config.js";
import { CliError, toErrorJson } from "../errors.js";
import { checkSid } from "../sessions.js";
import { personHere } from "../projects.js";
import { resolveHome } from "../config.js";
import { TtyTerminal, type Terminal } from "./terminal.js";
import { Tui, TUI_SESSION } from "./tui.js";

export interface TuiCommandDeps {
  env: Env;
  io: Io;
  version: string;
  makeApp: (env: Env, io: Io) => App;
  isTTY?: boolean;
  /** Tests: a fake terminal. */
  terminal?: Terminal;
  signal?: AbortSignal;
}

/** Why `p2p tui` won't start here, or undefined. */
export function tuiRefusal(env: Env, isTTY: boolean): string | undefined {
  // An agent's session: its environment, or (scrubbed) a Claude Code or Codex ancestor (projects.ts).
  if (env.CODEX_THREAD_ID || env.CODEX_SESSION_ID || env.CLAUDECODE || !personHere(env, resolveHome(env))) {
    return "p2p tui is for you to run in your own terminal, not from an agent's tool call";
  }
  if (!isTTY) return "p2p tui needs an interactive terminal (stdin and stdout); in scripts use `p2p ls`, `p2p held`, `p2p watch`";
  return undefined;
}

export async function tuiCommand(d: TuiCommandDeps, o: { session?: string }): Promise<number> {
  const isTTY = d.isTTY ?? Boolean(process.stdin.isTTY && process.stdout.isTTY);
  const refusal = tuiRefusal(d.env, d.terminal ? true : isTTY);
  if (refusal) {
    d.io.err(`p2p tui: ${refusal}`);
    return 1;
  }
  let session: string;
  try {
    session = checkSid(o.session ?? TUI_SESSION);
  } catch (e) {
    d.io.err(`p2p tui: ${String(toErrorJson(e).reason)}`);
    return 1;
  }
  const kept: string[] = [];
  const keep = (m: string) => {
    kept.push(m);
    if (kept.length > 200) kept.shift();
  };
  const app = d.makeApp(d.env, { out: () => {}, err: keep });
  try {
    if (!(await app.load(false))) throw new CliError("no_identity", "no identity here yet: run `p2p setup` first");
  } catch (e) {
    const j = toErrorJson(e);
    d.io.err(`p2p tui: ${String(j.error)}: ${String(j.reason)}`);
    return 1;
  }
  const term = d.terminal ?? new TtyTerminal(process.stdin as ReadStream, process.stdout as WriteStream, d.env);
  const tui = new Tui(app, { term, session, version: d.version, ...(d.signal ? { signal: d.signal } : {}), log: keep });
  try {
    await tui.run();
  } catch (e) {
    const j = toErrorJson(e);
    d.io.err(`p2p tui: ${String(j.error)}: ${String(j.reason)}`);
    return 1;
  } finally {
    // What the app said while the screen was ours, now that it is the terminal's again (last few).
    for (const m of kept.slice(-5)) d.io.err(m);
  }
  return 0;
}
