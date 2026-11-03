// Copyright 2026 Ix Infrastructure Inc.
//
// Reading stdin without hanging silently. A shell can hand a command a stdin
// that never ends: PowerShell running an npm `.cmd`/`.ps1` shim, an IDE
// task, a CI step. So:
//  - when the user didn't ask for stdin (`send` with no text), give up with
//    "" if nothing arrives within `idleMs`;
//  - when they did (`--stdin`, `backup restore`), keep reading, but say how to
//    end the input once nothing has arrived for `hintMs`.

export interface StdinLike {
  isTTY?: boolean;
  on(ev: "data", f: (c: Buffer | string) => void): unknown;
  on(ev: "end", f: () => void): unknown;
  on(ev: "error", f: (e: Error) => void): unknown;
  removeAllListeners(ev?: string): unknown;
  pause(): unknown;
  resume(): unknown;
}

export const STDIN_IDLE_MS = 3000;
export const END_OF_INPUT_HINT = "reading from stdin… (end the input with Ctrl-D, or Ctrl-Z then Enter on Windows)";

export function readAll(
  stream: StdinLike,
  opts: { implicit?: boolean; idleMs?: number; hintMs?: number; hint?: (msg: string) => void } = {},
): Promise<string> {
  if (stream.isTTY) return Promise.resolve("");
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let got = false;
    const finish = (v: string) => {
      clearTimeout(timer);
      stream.removeAllListeners("data");
      stream.removeAllListeners("end");
      stream.removeAllListeners("error");
      stream.pause();
      resolve(v);
    };
    const timer = setTimeout(
      () => {
        if (got) return;
        if (opts.implicit) finish("");
        else opts.hint?.(END_OF_INPUT_HINT);
      },
      opts.implicit ? (opts.idleMs ?? STDIN_IDLE_MS) : (opts.hintMs ?? STDIN_IDLE_MS),
    );
    timer.unref?.();
    stream.on("data", (c) => {
      got = true;
      chunks.push(typeof c === "string" ? Buffer.from(c) : c);
    });
    stream.on("end", () => finish(Buffer.concat(chunks).toString("utf8")));
    stream.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    stream.resume();
  });
}
