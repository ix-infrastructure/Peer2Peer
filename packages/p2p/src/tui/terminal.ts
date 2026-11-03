// Copyright 2026 Ix Infrastructure Inc.
//
// The terminal under the TUI: raw keyboard input, the alternate screen,
// resize events and colour detection, with nothing but node:tty. A fake
// implementation (tests) records frames instead.
//
// Restoring the terminal is the one thing that must always happen: leave()
// is idempotent and runs on quit, on errors, on SIGTERM/SIGHUP and, as a
// last resort, on process exit.

import { StringDecoder } from "node:string_decoder";
import type { ReadStream, WriteStream } from "node:tty";
import type { Key } from "./model.js";

export interface Terminal {
  readonly cols: number;
  readonly rows: number;
  readonly color: boolean;
  enter(): void;
  leave(): void;
  write(s: string): void;
  onKey(fn: (k: Key) => void): void;
  onResize(fn: () => void): void;
}

/** NO_COLOR (any non-empty value) and TERM=dumb turn colour off; otherwise the terminal says. */
export function colorWanted(env: Record<string, string | undefined>, out: { hasColors?: (n?: number) => boolean; isTTY?: boolean }): boolean {
  if (env.NO_COLOR !== undefined && env.NO_COLOR !== "") return false;
  if (env.TERM === "dumb") return false;
  if (env.FORCE_COLOR !== undefined && env.FORCE_COLOR !== "" && env.FORCE_COLOR !== "0") return true;
  try {
    return Boolean(out.isTTY) && (out.hasColors?.(8) ?? true);
  } catch {
    return false;
  }
}

const CSI_KEYS: Record<string, string> = {
  A: "up",
  B: "down",
  C: "right",
  D: "left",
  H: "home",
  F: "end",
  Z: "backtab",
  "1~": "home",
  "4~": "end",
  "5~": "pageup",
  "6~": "pagedown",
  "7~": "home",
  "8~": "end",
  "3~": "delete",
};

/** A bracketed paste longer than this is cut (the rest is dropped). */
const PASTE_MAX = 64 * 1024;
/** An escape sequence left open this long is given up (and nothing of it is typed). */
const PENDING_MAX = 4096;
/** After a paste ends, keys this soon after it count as pasted too (a fake end marker inside the paste). */
export const PASTE_QUIET_MS = 150;
/** A paste, or a terminal answer, with no input for this long is over (its end marker never came). */
export const STUCK_MS = 1000;
/** A lone ESC with nothing after it for this long is the Escape key. */
export const ESC_MS = 50;

const CTRL_C: Key = { name: "c", ctrl: true };

/**
 * Splits raw input into keys, keeping state between chunks: a terminal's
 * answer or a key's escape sequence split across reads is completed by the
 * next one, never leaked as typed characters.
 *
 *  - Escape sequences of the keys we use are recognised; any other escape
 *    or string sequence is dropped whole, however long (a string sequence
 *    is discarded up to its terminator, across chunks).
 *  - Text inside a bracketed paste comes through with `paste: true` (line
 *    breaks as spaces, controls dropped): the model types it only into a
 *    message or a prompt, never as command keys. For PASTE_QUIET_MS after
 *    a paste ends, keys still count as pasted: a paste carrying its own
 *    end marker (`ESC[201~ay`) can't press `a` or `y`.
 *  - Ctrl-C always gets through, even mid-paste or mid-answer: the way out.
 *  - Time-outs (idle(), called by the terminal after waitMs of no input): a
 *    lone ESC is the Escape key; a paste or answer whose end never came is
 *    over (STUCK_MS), so the TUI can't lock up.
 */
export class KeyParser {
  private pending = "";
  private pasting: string | undefined;
  /** Inside a string sequence (OSC, DCS, ...) whose terminator hasn't come: dropping input. */
  private discarding = false;
  private quietUntil = 0;

  constructor(private readonly now: () => number = Date.now) {}

  feed(chunk: string): Key[] {
    const keys: Key[] = [];
    const push = (k: Key) => {
      // Shortly after a paste ended, everything is still pasted (except Ctrl-C).
      if (!k.paste && !(k.ctrl && k.name === "c") && this.now() < this.quietUntil) {
        if (k.ch !== undefined) keys.push({ ...k, paste: true });
        return;
      }
      keys.push(k);
    };
    let data = this.pending + chunk;
    this.pending = "";
    if (this.discarding) {
      const end = data.search(/\u0007|\u001b\\|\u0003/);
      if (end < 0) {
        // Keep a final ESC: it may be the first half of ST.
        this.pending = data.endsWith("\u001b") ? "\u001b" : "";
        return keys;
      }
      this.discarding = false;
      if (data[end] === "\u0003") {
        // Ctrl-C: the way out; whatever came with it in this read is dropped.
        push(CTRL_C);
        return keys;
      }
      data = data.slice(end + 2 - (data[end] === "\u0007" ? 1 : 0));
    }
    if (this.pasting !== undefined) {
      // The paste so far and the new data, searched as one: an end marker split across reads is found.
      const buf = this.pasting + data;
      this.pasting = undefined;
      const after = this.paste(keys, buf, push);
      if (after === undefined) return keys;
      data = after;
    }
    let i = 0;
    while (i < data.length) {
      const c = data[i];
      if (c === "\u001b") {
        const next = data[i + 1];
        if (next === undefined) {
          // Maybe the start of a sequence: wait for more (idle() makes it Escape).
          this.pending = "\u001b";
          break;
        }
        if (next === "\u0003") {
          // ESC then Ctrl-C: Ctrl-C still gets through.
          push(CTRL_C);
          return keys;
        }
        if (next === "[" || next === "O") {
          let j = i + 2;
          while (j < data.length && /[0-9;?]/.test(data[j])) j++;
          if (j >= data.length) {
            // The final byte hasn't arrived yet.
            this.pending = data.slice(i, i + PENDING_MAX);
            break;
          }
          if (data[j] === "\u0003") {
            // Ctrl-C in the middle of a key's sequence: still the way out.
            push(CTRL_C);
            return keys;
          }
          const body = data.slice(i + 2, j + 1);
          i = j + 1;
          if (body === "200~") {
            const after = this.paste(keys, data.slice(i), push);
            if (after === undefined) return keys;
            data = after;
            i = 0;
            continue;
          }
          const name = CSI_KEYS[body] ?? CSI_KEYS[body.replace(/^1;\d/, "")];
          if (name === "backtab") push({ name: "tab", shift: true });
          else if (name) push({ name });
          continue;
        }
        if (next === "]" || next === "P" || next === "_" || next === "^" || next === "X") {
          // A string sequence (a terminal's answer): skip to its terminator, across chunks, however long.
          const rest = data.slice(i + 2);
          const end = rest.search(/\u0007|\u001b\\|\u0003/);
          if (end < 0) {
            this.discarding = true;
            this.pending = rest.endsWith("\u001b") ? "\u001b" : "";
            break;
          }
          if (rest[end] === "\u0003") {
            push(CTRL_C);
            return keys;
          }
          i += 2 + end + (rest[end] === "\u001b" ? 2 : 1);
          continue;
        }
        if (next !== "\u001b") {
          // Alt+key: ignored.
          i += 2;
          continue;
        }
        push({ name: "escape" });
        i++;
        continue;
      }
      const code = c.codePointAt(0)!;
      if (c === "\r" || c === "\n") push({ name: "return" });
      else if (c === "\t") push({ name: "tab" });
      else if (c === "\u007f" || c === "\b") push({ name: "backspace" });
      else if (c === " ") push({ name: "space", ch: " " });
      else if (code < 32) push({ name: String.fromCharCode(code + 96), ctrl: true });
      else if (code >= 0x80 && code < 0xa0) {
        // C1 controls: never typed.
      } else {
        const ch = String.fromCodePoint(data.codePointAt(i)!);
        push({ name: ch, ch });
        i += ch.length;
        continue;
      }
      i++;
    }
    return keys;
  }

  /** How long the terminal should wait for more input before calling idle() (0: no need). */
  get waitMs(): number {
    if (this.pasting !== undefined || this.discarding) return STUCK_MS;
    return this.pending !== "" ? ESC_MS : 0;
  }

  /** No more input came: a lone ESC is Escape, and a paste or answer whose end never came is over. */
  idle(): Key[] {
    const keys: Key[] = [];
    if (this.pasting !== undefined) {
      this.endPaste(keys, this.pasting);
      this.pending = "";
      return keys;
    }
    if (this.discarding) {
      this.discarding = false;
      this.pending = "";
      return keys;
    }
    const p = this.pending;
    this.pending = "";
    return p === "\u001b" ? [{ name: "escape" }] : [];
  }

  /** idle(), for callers that just want what's held. */
  flush(): Key[] {
    return this.idle();
  }

  get waiting(): boolean {
    return this.waitMs > 0;
  }

  /**
   * Text after a paste's start marker: the paste ends at its end marker (the rest is returned, to be
   * read as keys), or waits for more (undefined). Ctrl-C before the end drops the paste and the rest
   * of the read (undefined).
   */
  private paste(keys: Key[], buf: string, push: (k: Key) => void): string | undefined {
    const cc = buf.indexOf("\u0003");
    const end = buf.indexOf("\u001b[201~");
    if (cc >= 0 && (end < 0 || cc < end)) {
      push(CTRL_C);
      return undefined;
    }
    if (end < 0) {
      // Bounded: the head of an over-long paste, and its last few characters (a split end marker).
      this.pasting = buf.length > PASTE_MAX + 16 ? buf.slice(0, PASTE_MAX) + buf.slice(-5) : buf;
      return undefined;
    }
    this.endPaste(keys, buf.slice(0, end));
    return buf.slice(end + 6);
  }

  private endPaste(keys: Key[], text: string): void {
    this.pasting = undefined;
    for (const ch of text.slice(0, PASTE_MAX).replace(/[\r\n\t]+/g, " ")) {
      const cp = ch.codePointAt(0)!;
      if (cp >= 32 && !(cp >= 0x7f && cp < 0xa0)) keys.push({ name: ch, ch, paste: true });
    }
    this.quietUntil = this.now() + PASTE_QUIET_MS;
  }
}

/** One chunk on its own (tests): parse, then flush. */
export function parseKeys(data: string): Key[] {
  const p = new KeyParser();
  return [...p.feed(data), ...p.flush()];
}

export class TtyTerminal implements Terminal {
  readonly color: boolean;
  private active = false;
  private readonly exitHook = () => this.leave();
  private keyFn?: (k: Key) => void;
  private readonly parser = new KeyParser();
  /** Multi-byte characters split across reads stay whole. */
  private readonly decoder = new StringDecoder("utf8");
  private escTimer?: NodeJS.Timeout;
  private readonly onData = (b: Buffer | string) => {
    if (this.escTimer) clearTimeout(this.escTimer);
    for (const k of this.parser.feed(typeof b === "string" ? b : this.decoder.write(b))) this.keyFn?.(k);
    // A lone ESC is Escape unless the rest follows at once; a paste or answer that never ends is over.
    const ms = this.parser.waitMs;
    if (ms > 0) {
      this.escTimer = setTimeout(() => {
        for (const k of this.parser.idle()) this.keyFn?.(k);
      }, ms);
      this.escTimer.unref();
    }
  };

  constructor(
    private readonly input: ReadStream,
    private readonly output: WriteStream,
    env: Record<string, string | undefined>,
  ) {
    this.color = colorWanted(env, output);
  }

  get cols(): number {
    return this.output.columns || 80;
  }

  get rows(): number {
    return this.output.rows || 24;
  }

  enter(): void {
    if (this.active) return;
    this.active = true;
    process.on("exit", this.exitHook);
    this.input.setRawMode(true);
    this.input.resume();
    this.input.on("data", this.onData);
    // Alternate screen, hidden cursor, no line wrap, bracketed paste (pasted text is typed only into a
    // message or a prompt, and a pasted line break is a space there: it never acts as a key).
    this.output.write("\u001b[?1049h\u001b[?25l\u001b[?7l\u001b[?2004h\u001b[2J");
  }

  leave(): void {
    if (!this.active) return;
    this.active = false;
    process.off("exit", this.exitHook);
    this.input.off("data", this.onData);
    if (this.escTimer) clearTimeout(this.escTimer);
    try {
      this.input.setRawMode(false);
    } catch {
      // already gone
    }
    this.input.pause();
    this.output.write("\u001b[0m\u001b[?2004l\u001b[?7h\u001b[?25h\u001b[?1049l");
  }

  write(s: string): void {
    if (this.active) this.output.write(s);
  }

  onKey(fn: (k: Key) => void): void {
    this.keyFn = fn;
  }

  onResize(fn: () => void): void {
    this.output.on("resize", fn);
  }
}
