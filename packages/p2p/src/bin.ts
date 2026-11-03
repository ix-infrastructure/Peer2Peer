#!/usr/bin/env node
// Copyright 2026 Ix Infrastructure Inc.
//
// The `p2p` executable.

import { createInterface } from "node:readline/promises";
import { main } from "./cli.js";
import type { Io } from "./app.js";
import { readAll } from "./stdin.js";
import { runPicker } from "./prompt/tty.js";
import { colorWanted } from "./tui/terminal.js";

const interactive = Boolean(process.stdin.isTTY && process.stdout.isTTY);
// Pickers: a person at a terminal only. Never in CI, and never inside an agent's tool call (Claude Code
// and Codex set these), even if it has a terminal: an agent can't pick for the person.
const agent = Boolean(process.env.CLAUDECODE || process.env.CODEX_THREAD_ID || process.env.CODEX_SESSION_ID);
const ci = Boolean(process.env.CI) && process.env.CI !== "0" && process.env.CI !== "false";
const pickers = interactive && !agent && !ci;
const color = colorWanted(process.env, process.stdout);

const io: Io = {
  out: (s) => process.stdout.write(s + "\n"),
  err: (s) => process.stderr.write(s + "\n"),
  ...(interactive
    ? {
        prompt: async (q: string) => {
          const rl = createInterface({ input: process.stdin, output: process.stdout });
          try {
            return await rl.question(q);
          } finally {
            rl.close();
          }
        },
        promptSecret: async (q: string) => {
          // The answer isn't echoed (a backup phrase must not land in scrollback or a screen share).
          process.stdout.write(q);
          const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
          const out = rl as unknown as { _writeToOutput: (s: string) => void };
          out._writeToOutput = () => {};
          try {
            return await rl.question("");
          } finally {
            rl.close();
            process.stdout.write("\n");
          }
        },
      }
    : {}),
  readStdin: (o) => readAll(process.stdin, { implicit: o?.implicit, hint: (m) => process.stderr.write(`p2p: ${m}\n`) }),
  ...(pickers ? { select: (spec) => runPicker(spec, process.stdin, process.stdout, { color }) } : {}),
  // Laid-out output (pretty.ts) only when stdout is a terminal; piped output is the plain text.
  ...(process.stdout.isTTY && !agent ? { pretty: { color, cols: process.stdout.columns || 80 } } : {}),
};

const code = await main(process.argv.slice(2), { env: process.env, io });
process.exitCode = code;
// Every step is bounded, but a socket or timer left behind must not keep the process (and the
// user's terminal) waiting: give stdout a moment to flush, then exit.
setTimeout(() => process.exit(code), 1500).unref();
