// Copyright 2026 Ix Infrastructure Inc.
//
// The picker on a real terminal: raw keys through the TUI's KeyParser, drawn
// inline (no alternate screen) under the command's own output, and the
// terminal always restored: on a choice, on Esc / Ctrl-C, on the input
// ending and, as a last resort, on process exit.
//
// Only bin.ts wires this in, and only when stdin and stdout are both a
// terminal, CI and --no-input are unset, and no agent's tool call is running
// the command (CLAUDECODE / CODEX_THREAD_ID): piped input never reaches a picker.

import { StringDecoder } from "node:string_decoder";
import { KeyParser } from "../tui/terminal.js";
import { COLOR, initialState, PLAIN, reduce, render, summary, type PickerState, type SelectSpec } from "./picker.js";

/** What the driver needs of stdin (a tty.ReadStream, or a fake in tests). */
export interface PickerInput {
  isTTY?: boolean;
  setRawMode?(on: boolean): unknown;
  on(ev: "data", fn: (b: Buffer | string) => void): unknown;
  on(ev: "end", fn: () => void): unknown;
  off(ev: "data", fn: (b: Buffer | string) => void): unknown;
  off(ev: "end", fn: () => void): unknown;
  resume(): unknown;
  pause(): unknown;
}

export interface PickerOutput {
  write(s: string): unknown;
  columns?: number;
  rows?: number;
}

/** How the picker hooks termination signals (tests pass a fake). */
export interface PickerSignals {
  on(sig: NodeJS.Signals, fn: () => void): unknown;
  off(sig: NodeJS.Signals, fn: () => void): unknown;
  /** Re-raises the signal once the terminal is restored, so the process ends as it would have. */
  raise(sig: NodeJS.Signals): void;
}

const PROCESS_SIGNALS: PickerSignals = {
  on: (sig, fn) => process.on(sig, fn),
  off: (sig, fn) => process.off(sig, fn),
  raise: (sig) => process.kill(process.pid, sig),
};

const HOOKED: NodeJS.Signals[] = ["SIGINT", "SIGTERM", "SIGHUP"];

/** Runs one picker: the values chosen, or undefined when cancelled. */
export function runPicker(spec: SelectSpec, input: PickerInput, output: PickerOutput, o: { color: boolean; signals?: PickerSignals }): Promise<string[] | undefined> {
  const signals = o.signals ?? PROCESS_SIGNALS;
  const style = o.color ? COLOR : PLAIN;
  const parser = new KeyParser();
  const decoder = new StringDecoder("utf8");
  let state: PickerState = initialState(spec);
  let drawn = 0;
  let escTimer: NodeJS.Timeout | undefined;
  const size = () => ({ cols: output.columns || 80, rows: output.rows || 24 });
  const erase = () => {
    if (drawn > 0) output.write(`\r${drawn > 1 ? `\u001b[${drawn - 1}A` : ""}\u001b[J`);
    drawn = 0;
  };
  const draw = () => {
    const lines = render(state, { ...size(), style });
    erase();
    output.write(lines.join("\r\n"));
    drawn = lines.length;
  };
  return new Promise((resolve) => {
    let finished = false;
    const restore = () => {
      try {
        input.setRawMode?.(false);
      } catch {
        // already gone
      }
      output.write("\u001b[0m\u001b[?25h");
    };
    const detach = () => {
      finished = true;
      if (escTimer) clearTimeout(escTimer);
      input.off("data", onData);
      input.off("end", onEnd);
      process.off("exit", restore);
      for (const [sig, fn] of onSignals) signals.off(sig, fn);
    };
    const finish = () => {
      if (finished) return;
      detach();
      erase();
      output.write(`${summary(state, { cols: size().cols, style })}\r\n`);
      restore();
      input.pause();
      resolve(state.done ? state.done : undefined);
    };
    // SIGTERM, SIGHUP, or SIGINT from outside (raw mode turns Ctrl-C into a key): the terminal goes
    // back first, then the signal is raised again, so the process ends as it would have (as the TUI does).
    const onSignals = HOOKED.map((sig) => {
      const fn = () => {
        if (finished) return;
        detach();
        erase();
        output.write("\r\n");
        restore();
        input.pause();
        resolve(undefined);
        signals.raise(sig);
      };
      return [sig, fn] as const;
    });
    const keys = (ks: ReturnType<KeyParser["feed"]>) => {
      for (const k of ks) {
        state = reduce(state, k);
        if (state.done !== undefined) return finish();
      }
      draw();
    };
    const onData = (b: Buffer | string) => {
      if (escTimer) clearTimeout(escTimer);
      keys(parser.feed(typeof b === "string" ? b : decoder.write(b)));
      if (finished) return;
      const ms = parser.waitMs;
      if (ms > 0) {
        escTimer = setTimeout(() => keys(parser.idle()), ms);
        escTimer.unref?.();
      }
    };
    const onEnd = () => {
      state = { ...state, done: null };
      finish();
    };
    process.on("exit", restore);
    for (const [sig, fn] of onSignals) signals.on(sig, fn);
    input.setRawMode?.(true);
    input.on("data", onData);
    input.on("end", onEnd);
    input.resume();
    output.write("\u001b[?25l");
    draw();
  });
}
