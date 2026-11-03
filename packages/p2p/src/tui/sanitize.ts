// Copyright 2026 Ix Infrastructure Inc.
//
// The TUI's one gate for text on its way to the terminal. Everything a peer
// controls (names, labels, statuses, file paths, message text, kinds, relay
// answers) and everything else too passes through cell() before the renderer
// sees it: the frame is built only from what this module returns.
//
//  - Escape sequences (CSI, OSC including OSC 8 links, DCS/SOS/PM/APC, and
//    their 8-bit C1 forms) are removed whole, then every remaining C0/C1
//    control, DEL, line and paragraph separator, format character (bidi
//    overrides and isolates, zero-width characters, tags), lone surrogate,
//    noncharacter and invisible filler goes.
//  - Line breaks and tabs become spaces; runs of whitespace collapse.
//  - Private-use and unassigned code points become "?" (their width is unknown).
//  - Combining marks are kept, at most two in a row (no "zalgo" towers).
//  - The result is cut to a display width (wide CJK and emoji count two),
//    with "…" when it was longer.

/** Whole escape sequences: CSI, OSC (BEL or ST terminated), DCS/SOS/PM/APC, two-byte ESC sequences; 7- and 8-bit forms. */
const ESCAPES = /(?:\u001b\[|\u009b)[ -?]*[@-~]?|(?:\u001b[\]P^_X]|[\u009d\u0090\u009e\u009f\u0098])[\s\S]*?(?:\u0007|\u001b\\|\u009c|$)|\u001b[ -/]*[0-~]?/g;
const BREAKS = /[\t\n\v\f\r\u0085\u2028\u2029]/g;
/** Controls, format characters (incl. bidi and zero-width), surrogates, noncharacters, invisible fillers. */
const STRIP = /[\u0000-\u001f\u007f-\u009fᅟᅠㅤﾠ￹-￻﷐-﷯￾￿]|͏|឴|឵|\p{Cf}|\p{Cs}/gu;
/** Private use and unassigned: rendered as "?". */
const UNKNOWN = /[\p{Co}\p{Cn}]/gu;
const MARK = /\p{M}/u;

/** Display width of one code point: 0 (combining), 2 (wide / emoji) or 1. */
export function cpWidth(cp: number): number {
  if (cp === 0x200d) return 0;
  if (MARK.test(String.fromCodePoint(cp))) return 0;
  if (
    (cp >= 0x1100 && cp <= 0x115f) ||
    (cp >= 0x2e80 && cp <= 0x303e) ||
    (cp >= 0x3041 && cp <= 0x33ff) ||
    (cp >= 0x3400 && cp <= 0x4dbf) ||
    (cp >= 0x4e00 && cp <= 0x9fff) ||
    (cp >= 0xa000 && cp <= 0xa4cf) ||
    (cp >= 0xac00 && cp <= 0xd7a3) ||
    (cp >= 0xf900 && cp <= 0xfaff) ||
    (cp >= 0xfe30 && cp <= 0xfe4f) ||
    (cp >= 0xff00 && cp <= 0xff60) ||
    (cp >= 0xffe0 && cp <= 0xffe6) ||
    (cp >= 0x1f300 && cp <= 0x1f64f) ||
    (cp >= 0x1f900 && cp <= 0x1f9ff) ||
    (cp >= 0x1f680 && cp <= 0x1f6ff) ||
    (cp >= 0x20000 && cp <= 0x3fffd)
  ) {
    return 2;
  }
  return 1;
}

export function displayWidth(s: string): number {
  let w = 0;
  for (const ch of s) w += cpWidth(ch.codePointAt(0)!);
  return w;
}

/** Peer-safe text: escapes and invisible or control characters removed, whitespace collapsed and trimmed. No width limit. */
export function clean(s: unknown): string {
  return cleanKeep(s).trim();
}

/** clean() without the trim: the renderer's own spacing (" Peer2Peer ", "files: ") survives. */
export function cleanKeep(s: unknown): string {
  const str = typeof s === "string" ? s : s === undefined || s === null ? "" : String(s);
  let out = str.replace(ESCAPES, "").replace(BREAKS, " ").replace(STRIP, "").replace(UNKNOWN, "?").replace(/\s+/gu, " ");
  // At most two combining marks after a base character.
  let marks = 0;
  let kept = "";
  for (const ch of out) {
    if (MARK.test(ch)) {
      if (++marks > 2) continue;
    } else marks = 0;
    kept += ch;
  }
  out = kept;
  // A leading combining mark would attach to whatever the renderer drew before it.
  return out.replace(/^\p{M}+/u, "");
}

/** clean(), then cut to `width` columns ("…" marks a cut). */
export function cell(s: unknown, width: number): string {
  const t = cleanKeep(s);
  if (width <= 0) return "";
  if (displayWidth(t) <= width) return t;
  let w = 0;
  let out = "";
  for (const ch of t) {
    const cw = cpWidth(ch.codePointAt(0)!);
    if (w + cw > width - 1) break;
    out += ch;
    w += cw;
  }
  return `${out}…`;
}

/** cell(), padded with spaces to exactly `width` columns. */
export function pad(s: unknown, width: number): string {
  const t = cell(s, width);
  return t + " ".repeat(Math.max(0, width - displayWidth(t)));
}

/** Word-wraps clean text into lines of at most `width` columns (at most `maxLines`, the last one cut). */
export function wrap(s: unknown, width: number, maxLines = 50): string[] {
  const t = clean(s);
  if (width <= 0) return [];
  const lines: string[] = [];
  let line = "";
  for (const word of t.split(" ")) {
    let w = word;
    while (displayWidth(w) > width) {
      // A word longer than the line: hard-cut it.
      if (line) {
        lines.push(line);
        line = "";
      }
      let head = "";
      let hw = 0;
      const chars = [...w];
      let i = 0;
      for (; i < chars.length; i++) {
        const cw = cpWidth(chars[i].codePointAt(0)!);
        // Always at least one character per line (a wide one on a 1-column line), so this ends.
        if (hw + cw > width && i > 0) break;
        head += chars[i];
        hw += cw;
      }
      lines.push(head);
      w = chars.slice(i).join("");
    }
    if (!line) line = w;
    else if (displayWidth(line) + 1 + displayWidth(w) <= width) line += ` ${w}`;
    else {
      lines.push(line);
      line = w;
    }
  }
  if (line) lines.push(line);
  if (lines.length > maxLines) {
    const cut = lines.slice(0, maxLines);
    cut[maxLines - 1] = cell(`${cut[maxLines - 1]} ${lines[maxLines]}`, width);
    return cut;
  }
  return lines;
}
