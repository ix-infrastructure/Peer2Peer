// Copyright 2026 Ix Infrastructure Inc.
//
// A frame: rows of styled spans, exactly `cols` wide. Spans are built only by
// Line.add, which runs every piece of text through cell() (sanitize.ts), so
// nothing reaches the terminal unsanitized. toAnsi() adds the only escape
// sequences the TUI ever writes (SGR colours, erase-line, cursor home); they
// come from this file, never from data.

import { cell, displayWidth } from "./sanitize.js";

export type Color = "green" | "red" | "yellow" | "cyan" | "magenta" | "gray";

export interface Style {
  fg?: Color;
  bold?: boolean;
  dim?: boolean;
  inverse?: boolean;
}

export interface Span {
  text: string;
  style?: Style;
}

export class Line {
  readonly spans: Span[] = [];
  private used = 0;
  constructor(readonly width: number) {}

  get remaining(): number {
    return Math.max(0, this.width - this.used);
  }

  /** Appends sanitized text, cut to `max` columns (and to what's left of the line). */
  add(text: unknown, style?: Style, max = Infinity): this {
    const room = Math.min(this.remaining, max);
    const t = cell(text, room);
    if (t !== "") {
      this.spans.push(style ? { text: t, style } : { text: t });
      this.used += displayWidth(t);
    }
    return this;
  }

  /** Spaces: a fixed gap (raw spaces, not peer text). */
  gap(n = 1): this {
    const k = Math.min(n, this.remaining);
    if (k > 0) {
      this.spans.push({ text: " ".repeat(k) });
      this.used += k;
    }
    return this;
  }

  /** `text` padded (or cut) to exactly `w` columns. */
  col(text: unknown, w: number, style?: Style): this {
    const before = this.used;
    this.add(text, style, w);
    return this.gap(w - (this.used - before));
  }

  /** Pads the line to its width (with `style`, e.g. inverse for a selected row). */
  fill(style?: Style): this {
    const k = this.remaining;
    if (k > 0) {
      this.spans.push(style ? { text: " ".repeat(k), style } : { text: " ".repeat(k) });
      this.used += k;
    }
    return this;
  }

  /** The same line with every span shown selected (inverse). */
  selected(): this {
    for (const s of this.spans) s.style = { ...s.style, inverse: true };
    return this.fill({ inverse: true });
  }

  text(): string {
    return this.spans.map((s) => s.text).join("");
  }
}

export interface Frame {
  cols: number;
  rows: number;
  lines: Line[];
}

export function makeFrame(cols: number, rows: number): Frame {
  return { cols, rows, lines: [] };
}

/** Plain text, one line per row, padded: for snapshot tests and NO_COLOR. */
export function frameText(f: Frame): string {
  const out: string[] = [];
  for (let i = 0; i < f.rows; i++) {
    const l = f.lines[i];
    const t = l ? l.text() : "";
    out.push(t + " ".repeat(Math.max(0, f.cols - displayWidth(t))));
  }
  return out.join("\n");
}

const FG: Record<Color, number> = { red: 31, green: 32, yellow: 33, magenta: 35, cyan: 36, gray: 90 };

function sgr(s: Style | undefined, color: boolean): string {
  if (!s) return "";
  const codes: number[] = [];
  if (s.bold) codes.push(1);
  if (s.dim && color) codes.push(2);
  if (s.inverse) codes.push(7);
  if (s.fg && color) codes.push(FG[s.fg]);
  return codes.length ? `\u001b[${codes.join(";")}m` : "";
}

/**
 * The whole frame as terminal output: cursor home, each row then erase-to-end,
 * styles reset after every styled span. Without colour, only bold and inverse
 * (selection must stay visible) are used.
 */
export function toAnsi(f: Frame, color: boolean): string {
  let out = "\u001b[H";
  for (let i = 0; i < f.rows; i++) {
    const l = f.lines[i];
    if (l) {
      for (const s of l.spans) {
        const on = sgr(s.style, color);
        out += on ? `${on}${s.text}\u001b[0m` : s.text;
      }
    }
    out += "\u001b[K";
    if (i < f.rows - 1) out += "\r\n";
  }
  return out;
}
