// Copyright 2026 Ix Infrastructure Inc.
//
// Renders (ui, data) into a frame. Pure: the same inputs give the same frame,
// so tests snapshot it at fixed sizes. Every string goes through Line.add
// (frame.ts → sanitize.ts); this file never writes raw text to a terminal.

import { Line, makeFrame, type Frame, type Style } from "./frame.js";
import { wrap } from "./sanitize.js";
import { messagesSorted, peopleItems, SCREEN_TITLES, SCREENS, sendTargets, type Data, type MessageRow, type Screen, type Ui } from "./model.js";

const DIM: Style = { dim: true, fg: "gray" };
const OK: Style = { fg: "green" };
const BAD: Style = { fg: "red", bold: true };
const WARN: Style = { fg: "yellow" };
const HEAD: Style = { bold: true };

export function ago(sec: number): string {
  if (sec < 60) return `${Math.max(0, Math.round(sec))}s`;
  if (sec < 3600) return `${Math.round(sec / 60)}m`;
  if (sec < 86_400 * 2) return `${Math.round(sec / 3600)}h`;
  return `${Math.round(sec / 86_400)}d`;
}

const HELP: Record<Screen, string> = {
  people: "↑↓ move · m message · d doctor · 1-5 screens · ? help · q quit",
  held: "↑↓ move · a accept/deliver · x decline · t always deliver · ? help · q quit",
  messages: "↑↓ move · Enter open · r reply · 1-5 screens · ? help · q quit",
  send: "↑↓ pick · Enter write · then Enter send, Esc cancel, Ctrl-U clear · q quit",
  health: "r run doctor · d on People: one person · 1-5 screens · ? help · q quit",
};

/** A scrolling window over `n` rows of `h` lines that keeps `sel` visible. */
function window(n: number, sel: number, h: number): [number, number] {
  if (n <= h) return [0, n];
  const top = Math.max(0, Math.min(sel - Math.floor(h / 2), n - h));
  return [top, top + h];
}

export function render(ui: Ui, d: Data, cols: number, rows: number, now: number): Frame {
  const f = makeFrame(cols, rows);
  const line = () => new Line(cols);
  if (cols < 40 || rows < 10) {
    f.lines.push(line().add("window too small (40x10 min)", BAD));
    return f;
  }
  // Tab bar.
  const tabs = line().add(" Peer2Peer ", { bold: true, inverse: true }).gap();
  SCREENS.forEach((s, i) => {
    const n = s === "held" && d.held.length > 0 ? ` (${d.held.length})` : "";
    tabs.add(`${i + 1} ${SCREEN_TITLES[s]}${n}`, s === ui.screen ? { bold: true, inverse: true } : s === "held" && n ? WARN : undefined).gap(2);
  });
  const up = d.health.relays.filter((r) => r.up).length;
  const relaysTxt = `${up}/${d.health.relays.length} relays`;
  const who = d.me ? d.me.address : "";
  const right = `${who}  ${relaysTxt}`;
  if (tabs.remaining > right.length + 2) {
    tabs.gap(tabs.remaining - right.length - 1);
    tabs.add(who, DIM).gap(2).add(relaysTxt, up === 0 ? BAD : up < d.health.relays.length ? WARN : OK);
  }
  f.lines.push(tabs.fill());
  f.lines.push(line().add("─".repeat(cols), DIM));

  const bodyH = rows - 4;
  const body: Line[] = [];
  switch (ui.screen) {
    case "people":
      people(ui, d, cols, bodyH, body);
      break;
    case "held":
      held(ui, d, cols, bodyH, body, now);
      break;
    case "messages":
      messages(ui, d, cols, bodyH, body, now);
      break;
    case "send":
      send(ui, d, cols, bodyH, body);
      break;
    case "health":
      health(ui, d, cols, bodyH, body, now);
      break;
  }
  for (let i = 0; i < bodyH; i++) f.lines.push(body[i] ?? line());

  // Status line, then the help bar.
  const st = line();
  if (ui.busy) st.add(`… ${ui.busy}`, WARN);
  else if (ui.flash) st.add(ui.flash.text, ui.flash.error ? BAD : OK);
  else if (d.loading) st.add("loading…", DIM);
  f.lines.push(st);
  f.lines.push(line().add(` ${HELP[ui.screen]}`, { inverse: true }).fill({ inverse: true }));

  if (ui.modal) overlay(f, ui, cols, rows);
  return f;
}

function people(ui: Ui, d: Data, cols: number, h: number, out: Line[]): void {
  const items = peopleItems(d);
  if (items.length === 0) {
    out.push(new Line(cols).add(d.loading ? "Loading…" : "No friends or circle-mates yet. `p2p invite` makes a code to send someone.", DIM));
    return;
  }
  // Each item can take several lines (summary, files, agents): lay out, then window by item.
  const blocks = items.map((it) => {
    const ls: Line[] = [];
    if (it.kind === "person") {
      const p = it.person;
      ls.push(new Line(cols).add(p.live ? "●" : "○", p.live ? OK : DIM).gap().add(p.address, HEAD).gap(2).add(p.relation, DIM));
    } else {
      const s = it.session;
      const l = new Line(cols).gap(2).add(s.live ? (s.state === "busy" ? "●" : "○") : "·", s.live ? (s.state === "busy" ? WARN : OK) : DIM).gap();
      l.add(`[${s.ref}]`, DIM).gap().add(s.label, { bold: true }, 24).gap().add(s.live ? s.state : "offline", s.live ? undefined : DIM).gap(2);
      const where = [s.repo, s.branch].filter(Boolean).join("@");
      if (where) l.add(where, { fg: "cyan" }, 40).gap(2);
      l.add(`${ago(s.ageSec)} ago`, DIM);
      if (s.thisDevice) l.gap(2).add("(this device)", DIM);
      ls.push(l);
      if (s.summary) ls.push(new Line(cols).gap(6).add(s.summary));
      if (s.files.length > 0) {
        const more = s.files.length > 6 ? ` +${s.files.length - 6}` : "";
        ls.push(new Line(cols).gap(6).add("files: ", DIM).add(s.files.slice(0, 6).join(", "), undefined, Math.max(10, cols - 20)).add(more, DIM));
      }
      for (const a of s.agents) {
        ls.push(new Line(cols).gap(a.parent ? 8 : 6).add("↳ ", DIM).add(a.id, DIM, 16).gap().add(a.type, { fg: "magenta" }, 20).gap().add(`"${a.task}"`, undefined, 60).gap().add(`(${a.state}${a.branch ? `, ${a.branch}` : ""})`, DIM));
      }
    }
    return ls;
  });
  const sel = ui.sel.people;
  // Window over items so the selected one is fully visible.
  let top = 0;
  const heightOf = (i: number) => blocks[i].length;
  let used = 0;
  for (let i = sel; i >= 0; i--) {
    if (used + heightOf(i) > h) break;
    used += heightOf(i);
    top = i;
  }
  // Prefer showing from the start when everything up to sel fits.
  let total = 0;
  for (let i = 0; i <= sel; i++) total += heightOf(i);
  if (total <= h) top = 0;
  for (let i = top; i < blocks.length && out.length < h; i++) {
    for (const [k, l] of blocks[i].entries()) {
      if (out.length >= h) break;
      out.push(i === sel && k === 0 ? l.selected() : l);
    }
  }
}

function held(ui: Ui, d: Data, cols: number, h: number, out: Line[], now: number): void {
  const note = wrap(d.heldNote, cols - 2, 3);
  const listH = h - note.length - 1;
  if (d.held.length === 0) out.push(new Line(cols).add("Nothing held.", DIM));
  const [a, b] = window(d.held.length, ui.sel.held, Math.max(1, Math.floor(listH / 2)));
  for (let i = a; i < b; i++) {
    const r = d.held[i];
    const l = new Line(cols).add(r.source === "codex" ? "msg " : "item", r.source === "codex" ? { fg: "cyan" } : WARN).gap().col(r.type, 14).add(r.from, HEAD, 48).gap(2);
    if (r.session) l.add(`to ${r.session}`, DIM, 30).gap(2);
    l.add(`${ago((now - r.at) / 1000)} ago`, DIM);
    out.push(i === ui.sel.held ? l.selected() : l);
    out.push(new Line(cols).gap(5).add(r.summary, DIM));
  }
  while (out.length < h - note.length) out.push(new Line(cols));
  for (const n of note) out.push(new Line(cols).gap().add(n, DIM));
}

function outcomeText(m: MessageRow, now: number): { text: string; style?: Style } {
  if (m.state === "outbox") return { text: `queued here (no relay)${m.lastSeen ? `, last seen ${ago((now - m.lastSeen) / 1000)} ago` : ""}`, style: WARN };
  if (m.state === "offline") return { text: `waiting at relays (offline${m.lastSeen ? `, last seen ${ago((now - m.lastSeen) / 1000)} ago` : ""})`, style: WARN };
  if (m.state === "failed") return { text: `not sent${m.note ? `: ${m.note}` : ""}`, style: BAD };
  if (m.state === "expired") return { text: "expired unsent", style: BAD };
  const o = m.outcomes ?? [];
  if (o.length > 0) {
    const last = o[o.length - 1];
    return { text: o.join(" → "), style: last === "shown" ? OK : last === "held" ? WARN : last === "declined" || last === "expired" || last === "ended" ? BAD : undefined };
  }
  return { text: m.receiptId ? "sent, no receipt yet" : "sent", style: DIM };
}

function messages(ui: Ui, d: Data, cols: number, h: number, out: Line[], now: number): void {
  const list = messagesSorted(d);
  if (list.length === 0) {
    out.push(new Line(cols).add("No messages yet. Messages to this TUI's session, replies and your sends appear here.", DIM));
    return;
  }
  const [a, b] = window(list.length, ui.sel.messages, Math.floor(h / 2));
  for (let i = a; i < b; i++) {
    const m = list[i];
    const t = new Date(m.at);
    const hhmm = `${String(t.getHours()).padStart(2, "0")}:${String(t.getMinutes()).padStart(2, "0")}`;
    const l = new Line(cols).add(m.dir === "in" ? "←" : "→", m.dir === "in" ? { fg: "cyan" } : { fg: "magenta" }).gap().add(hhmm, DIM).gap();
    l.add(m.dir === "in" ? m.who : `to ${m.who}`, HEAD, 40);
    if (m.ref) l.gap().add(`[${m.ref}]`, DIM);
    l.gap(2);
    if (m.dir === "out") {
      const o = outcomeText(m, now);
      l.add(o.text, o.style);
    } else {
      if (m.note) l.add(m.note, DIM).gap(2);
    }
    out.push(i === ui.sel.messages ? l.selected() : l);
    out.push(new Line(cols).gap(8).add(m.text));
  }
}

function send(ui: Ui, d: Data, cols: number, h: number, out: Line[]): void {
  if (ui.compose) {
    out.push(new Line(cols).add("To: ", DIM).add(ui.compose.target.label, HEAD));
    out.push(new Line(cols));
    const lines = wrap(ui.compose.text, cols - 4, Math.max(1, h - 5));
    if (lines.length === 0) lines.push("");
    lines.forEach((t, i) => out.push(new Line(cols).add(i === 0 ? "> " : "  ", { fg: "cyan" }).add(t).add(i === lines.length - 1 ? "▏" : "", { fg: "cyan" })));
    out.push(new Line(cols));
    out.push(new Line(cols).add("Enter sends through your relays as this session; Esc cancels.", DIM));
    return;
  }
  const targets = sendTargets(d);
  out.push(new Line(cols).add("Pick who to message (Enter):", HEAD));
  if (targets.length === 0) out.push(new Line(cols).add("Nobody to message yet.", DIM));
  const [a, b] = window(targets.length, ui.sel.send, h - 1);
  for (let i = a; i < b; i++) {
    const l = new Line(cols).gap(2).add(targets[i].label);
    out.push(i === ui.sel.send ? l.selected() : l);
  }
}

const MARK = { ok: "✓", fail: "✗", unknown: "?" } as const;

function health(ui: Ui, d: Data, cols: number, h: number, out: Line[], now: number): void {
  out.push(new Line(cols).add("Relays", HEAD));
  for (const r of d.health.relays) {
    const l = new Line(cols).gap(2).add(r.up ? "●" : "○", r.up ? OK : BAD).gap().add(r.url, undefined, 48).gap(2).add(r.up ? "connected" : `down${r.reason ? `: ${r.reason}` : ""}`, r.up ? OK : BAD, 40);
    if (r.access) l.gap(2).add(r.access === "members" ? "members-only" : "open", DIM);
    if (r.attention) l.gap(2).add("needs operator attention", WARN);
    if (r.software) l.gap(2).add(r.software, DIM, 30);
    if (r.pow) l.gap(2).add(`pow ${r.pow}`, DIM);
    out.push(l);
  }
  if (d.health.relays.length === 0) out.push(new Line(cols).gap(2).add("no relays configured", BAD));
  out.push(new Line(cols));
  const doc = d.health.doctor;
  const title = new Line(cols).add(doc?.who ? `Doctor: can you see ${doc.who}?` : "Doctor: this device", HEAD);
  if (doc) title.gap(2).add(`${doc.summary.ok} ✓  ${doc.summary.fail} ✗  ${doc.summary.unknown} ?`, doc.summary.fail > 0 ? BAD : OK).gap(2).add(`(${ago((now - doc.at) / 1000)} ago)`, DIM);
  if (d.health.running) title.gap(2).add("running…", WARN);
  out.push(title);
  if (!doc) {
    out.push(new Line(cols).gap(2).add(d.health.running ? "Checking identity, relays, clock and sharing…" : "Press r to run the checks.", DIM));
    return;
  }
  // One group per check (its line, and its fix when not ok); failures first when they don't all fit.
  const groups = doc.checks.map((c) => {
    const g = [new Line(cols).gap(2).add(MARK[c.status], c.status === "ok" ? OK : c.status === "fail" ? BAD : WARN).gap().add(c.title, HEAD, 28).add(": ", DIM).add(c.detail)];
    if (c.fix && c.status !== "ok") g.push(new Line(cols).gap(6).add(`${c.status === "unknown" ? "to tell" : "fix"}: `, DIM).add(c.fix, DIM));
    return { status: c.status, lines: g };
  });
  const room = h - out.length;
  const all = groups.flatMap((g) => g.lines);
  const order = all.length > room ? [...groups.filter((g) => g.status === "fail"), ...groups.filter((g) => g.status === "unknown"), ...groups.filter((g) => g.status === "ok")] : groups;
  for (const g of order) {
    if (out.length + g.lines.length > h) break;
    out.push(...g.lines);
  }
}

function overlay(f: Frame, ui: Ui, cols: number, rows: number): void {
  const m = ui.modal!;
  const w = Math.min(cols - 4, 76);
  let title: string;
  let body: string[];
  let footer: string;
  if (m.kind === "help") {
    title = "Keys";
    body = [
      "1 People   2 Held   3 Messages   4 Send   5 Health   (Tab cycles)",
      "↑/↓ or j/k move, PgUp/PgDn, g/G first/last",
      "People: m or Enter message a person or session; d doctor for them",
      "Held: a accept (invites, joins) or deliver (held messages); x decline; t always deliver from the sender (asks first)",
      "Messages: Enter opens one; r replies (this window sends no read receipts)",
      "Send: pick, write, Enter sends; Esc cancels",
      "Health: r runs the doctor again",
      "q or Ctrl-C quits. Nothing is accepted, sent or trusted except on your key press.",
    ];
    footer = "Esc closes";
  } else if (m.kind === "confirm") {
    title = m.title;
    body = m.lines;
    footer = "y confirm   n cancel";
  } else if (m.kind === "typed") {
    title = m.title;
    body = [...m.lines, "", `> ${m.text}▏`];
    footer = "Enter confirm   Esc cancel";
  } else if (m.kind === "prompt") {
    title = m.title;
    body = [...m.lines, "", `> ${m.secret ? "•".repeat([...m.text].length) : m.text}▏`];
    footer = "Enter answer   Esc cancel";
  } else {
    title = m.title;
    body = m.lines;
    footer = "Esc closes";
  }
  const wrapped = body.flatMap((b) => (b === "" ? [""] : wrap(b, w - 4, 30)));
  const maxBody = rows - 6;
  const shown = wrapped.slice(0, maxBody);
  const top = Math.max(1, Math.floor((rows - shown.length - 4) / 2));
  const left = Math.floor((cols - w) / 2);
  const box: Line[] = [];
  const frameRow = (inner: (l: Line) => void, style?: Style) => {
    const l = new Line(cols).gap(left);
    const content = new Line(w - 4);
    inner(content);
    l.add("│ ", style);
    for (const s of content.spans) l.add(s.text, s.style);
    // Padding as raw gaps: add() collapses runs of spaces.
    l.gap(content.remaining);
    l.add(" │", style);
    return l;
  };
  box.push(new Line(cols).gap(left).add(`┌─ ${title} ${"─".repeat(Math.max(0, w - 5 - [...title].length))}┐`, HEAD));
  for (const b of shown) box.push(frameRow((l) => l.add(b)));
  if (wrapped.length > shown.length) box.push(frameRow((l) => l.add(`… (${wrapped.length - shown.length} more lines)`, DIM)));
  box.push(frameRow((l) => l.add(footer, DIM)));
  box.push(new Line(cols).gap(left).add(`└${"─".repeat(w - 2)}┘`, HEAD));
  box.forEach((l, i) => {
    if (top + i < rows) f.lines[top + i] = l;
  });
}
