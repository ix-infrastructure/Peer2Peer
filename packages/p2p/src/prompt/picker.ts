// Copyright 2026 Ix Infrastructure Inc.
//
// The CLI's interactive picker: a pure model (state + key -> state) and a
// renderer (state -> lines). The terminal driver is ./tty.ts; tests drive
// the model with keys and check what it chose.
//
//  - Arrow keys or j/k (while no filter is typed) move; space toggles (multi);
//    enter confirms; typing filters; backspace edits the filter; esc clears the
//    filter, or cancels; Ctrl-C always cancels.
//  - A disabled choice is shown, with its reason, and can't be chosen.
//  - Every label and detail goes through the TUI's sanitiser (cell/clean) on its
//    way to the terminal: a circle or person's name can't carry an escape sequence.

import type { Key } from "../tui/model.js";
import { cell, clean, displayWidth, wrap } from "../tui/sanitize.js";

export interface Choice {
  value: string;
  label: string;
  /** Dimmed after the label (member count, policy, …). */
  detail?: string;
  /** Why it can't be chosen (shown); a disabled choice is never selected. */
  disabled?: string;
  /** Pre-checked (multi). */
  checked?: boolean;
  /** Multi: choosing it clears the others, and choosing another clears it ("friend only"). */
  exclusive?: boolean;
}

export interface SelectSpec {
  message: string;
  /** Lines shown above the message (a preview), sanitised. */
  intro?: string[];
  choices: Choice[];
  multi?: boolean;
  /** Multi: at most this many. */
  max?: number;
  /** Single: the value the cursor starts on. */
  initial?: string;
}

export interface PickerState {
  spec: SelectSpec;
  cursor: number;
  filter: string;
  checked: string[];
  note?: string;
  /** Set once finished: the values chosen, or null (cancelled). */
  done?: string[] | null;
}

export function initialState(spec: SelectSpec): PickerState {
  const checked = spec.multi ? spec.choices.filter((c) => c.checked && !c.disabled).map((c) => c.value) : [];
  const at = spec.initial !== undefined ? spec.choices.findIndex((c) => c.value === spec.initial) : spec.choices.findIndex((c) => !c.disabled);
  return { spec, cursor: Math.max(0, at), filter: "", checked };
}

/** The choices the filter lets through, with their index in spec.choices. */
export function visible(s: PickerState): { c: Choice; i: number }[] {
  const f = s.filter.toLowerCase();
  return s.spec.choices.map((c, i) => ({ c, i })).filter(({ c }) => f === "" || clean(`${c.label} ${c.detail ?? ""}`).toLowerCase().includes(f));
}

function move(s: PickerState, by: number): PickerState {
  const v = visible(s);
  if (v.length === 0) return s;
  const at = Math.max(0, v.findIndex((x) => x.i === s.cursor));
  const next = v[(at + by + v.length * 8) % v.length];
  return { ...s, cursor: next.i, note: undefined };
}

function toggle(s: PickerState, c: Choice): PickerState {
  if (c.disabled) return { ...s, note: c.disabled };
  if (s.checked.includes(c.value)) return { ...s, checked: s.checked.filter((v) => v !== c.value), note: undefined };
  const exclusive = new Set(s.spec.choices.filter((x) => x.exclusive).map((x) => x.value));
  const base = c.exclusive ? [] : s.checked.filter((v) => !exclusive.has(v));
  const max = s.spec.max;
  if (max !== undefined && base.length >= max) return { ...s, note: `at most ${max}` };
  return { ...s, checked: [...base, c.value], note: undefined };
}

/** One key. A finished state is returned as it is. */
export function reduce(s: PickerState, k: Key): PickerState {
  if (s.done !== undefined) return s;
  if (k.ctrl && k.name === "c") return { ...s, done: null };
  const v = visible(s);
  const cur = v.find((x) => x.i === s.cursor) ?? v[0];
  // Pasted text only ever goes into the filter: it never moves, toggles or confirms.
  if (k.paste) return k.ch ? retarget({ ...s, filter: (s.filter + k.ch).slice(0, 64), note: undefined }) : s;
  switch (k.name) {
    case "up":
      return move(s, -1);
    case "down":
    case "tab":
      return move(s, k.shift ? -1 : 1);
    case "home":
      return v.length ? { ...s, cursor: v[0].i } : s;
    case "end":
      return v.length ? { ...s, cursor: v[v.length - 1].i } : s;
    case "escape":
      return s.filter ? retarget({ ...s, filter: "", note: undefined }) : { ...s, done: null };
    case "backspace":
      return retarget({ ...s, filter: s.filter.slice(0, -1), note: undefined });
    case "space":
      if (!cur) return s;
      return s.spec.multi ? toggle(s, cur.c) : s;
    case "return": {
      if (!cur && !(s.spec.multi && s.checked.length)) return { ...s, note: "nothing matches the filter" };
      if (s.spec.multi) {
        if (s.checked.length > 0) return { ...s, done: s.spec.choices.filter((c) => s.checked.includes(c.value)).map((c) => c.value) };
        if (cur.c.disabled) return { ...s, note: cur.c.disabled };
        return { ...s, done: [cur.c.value] };
      }
      if (cur.c.disabled) return { ...s, note: cur.c.disabled };
      return { ...s, done: [cur.c.value] };
    }
  }
  if (k.ctrl && (k.name === "n" || k.name === "p")) return move(s, k.name === "n" ? 1 : -1);
  if (k.ch && !k.ctrl) {
    // j/k move while no filter is typed (vi keys); any other character starts or extends the filter.
    if (s.filter === "" && (k.ch === "j" || k.ch === "k")) return move(s, k.ch === "j" ? 1 : -1);
    return retarget({ ...s, filter: (s.filter + k.ch).slice(0, 64), note: undefined });
  }
  return s;
}

/** After the filter changed: keep the cursor on a visible choice. */
function retarget(s: PickerState): PickerState {
  const v = visible(s);
  if (v.length === 0 || v.some((x) => x.i === s.cursor)) return s;
  return { ...s, cursor: (v.find((x) => !x.c.disabled) ?? v[0]).i };
}

export interface Style {
  bold(s: string): string;
  dim(s: string): string;
  cyan(s: string): string;
  green(s: string): string;
  yellow(s: string): string;
  red(s: string): string;
}

const sgr = (on: string, off: string) => (s: string) => `\u001b[${on}m${s}\u001b[${off}m`;
export const COLOR: Style = { bold: sgr("1", "22"), dim: sgr("2", "22"), cyan: sgr("36", "39"), green: sgr("32", "39"), yellow: sgr("33", "39"), red: sgr("31", "39") };
const id = (s: string) => s;
export const PLAIN: Style = { bold: id, dim: id, cyan: id, green: id, yellow: id, red: id };

export const HINT_MULTI = "up/down j/k move · space select · enter confirm · type to filter · esc cancel";
export const HINT_SINGLE = "up/down j/k move · enter choose · type to filter · esc cancel";

/** The picker as lines, each at most `cols - 1` columns wide (no line ever wraps, so redrawing stays exact). */
export function render(s: PickerState, o: { cols: number; rows: number; style: Style }): string[] {
  const w = Math.max(20, o.cols - 1);
  const st = o.style;
  const lines: string[] = [];
  for (const l of s.spec.intro ?? []) lines.push(...(clean(l) === "" ? [""] : wrap(l, w, 12)));
  lines.push(`${st.cyan("?")} ${st.bold(cell(s.spec.message, w - 2))}`);
  const v = visible(s);
  const room = Math.max(3, Math.min(12, o.rows - lines.length - 4));
  const at = Math.max(0, v.findIndex((x) => x.i === s.cursor));
  const top = Math.min(Math.max(0, at - room + 1), Math.max(0, v.length - room));
  if (v.length === 0) lines.push(st.dim(`  nothing matches "${cell(s.filter, 32)}"`));
  for (const { c, i } of v.slice(top, top + room)) {
    const here = i === s.cursor;
    const mark = s.spec.multi ? (s.checked.includes(c.value) ? "[x]" : "[ ]") : here ? "(*)" : "( )";
    const head = `${here ? ">" : " "} ${mark} `;
    const label = cell(c.label, Math.max(4, w - displayWidth(head) - 2));
    const rest = w - displayWidth(head) - displayWidth(label) - 2;
    const extra = [c.detail, c.disabled ? `unavailable: ${c.disabled}` : undefined].filter(Boolean).join(" · ");
    const tail = extra && rest > 4 ? `  ${cell(extra, rest)}` : "";
    const body = c.disabled ? st.dim(`${label}${tail}`) : `${here ? st.cyan(label) : label}${st.dim(tail)}`;
    lines.push(`${here ? st.cyan(head) : head}${body}`);
  }
  if (v.length > room) lines.push(st.dim(`  … ${v.length - room} more (type to filter)`));
  if (s.filter) lines.push(`  filter: ${cell(s.filter, w - 12)}`);
  if (s.note) lines.push(st.yellow(`  ${cell(s.note, w - 2)}`));
  lines.push(st.dim(cell(s.spec.multi ? HINT_MULTI : HINT_SINGLE, w)));
  return lines;
}

/** The one line left behind once the picker is done: the question and what was chosen. */
export function summary(s: PickerState, o: { cols: number; style: Style }): string {
  const w = Math.max(20, o.cols - 1);
  const chosen = s.done ? s.spec.choices.filter((c) => s.done!.includes(c.value)).map((c) => clean(c.label)) : [];
  const what = s.done === null ? "cancelled" : chosen.join(", ") || "none";
  const msg = cell(s.spec.message, Math.max(8, Math.floor(w / 2)));
  return `${o.style.cyan("?")} ${o.style.bold(msg)} ${s.done === null ? o.style.yellow(cell(what, w - displayWidth(msg) - 3)) : o.style.cyan(cell(what, w - displayWidth(msg) - 3))}`;
}
