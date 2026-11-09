// Copyright 2026 Ix Infrastructure Inc.
//
// The TUI's state and its key handling, as pure functions: a key press turns
// (ui, data) into a new ui and, at most, one effect for the controller
// (tui.ts) to run. Only key presses produce effects that change anything
// (accept, decline, trust, send); loading data and live updates
// never do.

export type Screen = "people" | "held" | "messages" | "send" | "health";
export const SCREENS: readonly Screen[] = ["people", "held", "messages", "send", "health"];
export const SCREEN_TITLES: Record<Screen, string> = { people: "People", held: "Held", messages: "Messages", send: "Send", health: "Health" };

export interface AgentRow {
  id: string;
  parent?: string;
  type: string;
  task: string;
  state: string;
  branch?: string;
}

export interface SessionRow {
  own: string;
  sid: string;
  ref: string;
  label: string;
  state: string;
  live: boolean;
  ageSec: number;
  summary?: string;
  repo?: string;
  branch?: string;
  files: string[];
  agents: AgentRow[];
  thisDevice?: boolean;
}

export interface PersonRow {
  userId: string;
  address: string;
  /** How they relate: friend, circle-mate (names of shared circles), or you. */
  relation: string;
  self: boolean;
  live: boolean;
  sessions: SessionRow[];
}

export interface HeldRow {
  /** "item": a CLI held item (p2p held); "codex": a message a Codex session holds. */
  source: "item" | "codex";
  id: string;
  type: string;
  from: string;
  /** codex: the session that holds it. */
  session?: string;
  summary: string;
  at: number;
}

export type Outcome = "shown" | "held" | "declined" | "expired" | "ended";

export interface MessageRow {
  id: string;
  dir: "in" | "out";
  at: number;
  /** The other side: address, and the session (ref) when known. */
  who: string;
  userId?: string;
  own?: string;
  sid?: string;
  ref?: string;
  text: string;
  /** out: delivery state and receipt outcomes. */
  state?: "sent" | "offline" | "outbox" | "failed" | "expired";
  outcomes?: Outcome[];
  lastSeen?: number;
  receiptId?: string;
  note?: string;
  /** From the message history (history.ts): kept past this run, up to its retention. */
  fromHistory?: true;
  /** The person's own inbox (this TUI's session, or no session) rather than one of their agent sessions'. */
  inbox?: boolean;
}

export interface RelayRow {
  url: string;
  up: boolean;
  reason?: string;
  access?: string;
  attention?: boolean;
  software?: string;
  pow?: number;
}

export interface CheckRow {
  status: "ok" | "fail" | "unknown";
  title: string;
  detail: string;
  fix?: string;
}

export interface Health {
  relays: RelayRow[];
  doctor?: { scope: string; who?: string; checks: CheckRow[]; summary: { ok: number; fail: number; unknown: number }; at: number };
  running?: boolean;
}

export interface Data {
  me?: { userId: string; address: string };
  session: string;
  people: PersonRow[];
  held: HeldRow[];
  /** Why held messages of the Claude Code mod aren't listed (shown on the Held screen). */
  heldNote: string;
  messages: MessageRow[];
  health: Health;
  loading: boolean;
}

export type Modal =
  | { kind: "confirm"; title: string; lines: string[]; effect: Effect }
  | { kind: "prompt"; title: string; lines: string[]; text: string; secret?: boolean }
  /** A confirmation that takes a typed word (not y, not a paste): for trust. */
  | { kind: "typed"; title: string; lines: string[]; word: string; text: string; effect: Effect }
  | { kind: "detail"; title: string; lines: string[] }
  | { kind: "help" };

export interface SendTarget {
  label: string;
  /** What sendMessage gets as `to`: a userId, with "[ref]" for one session. */
  to: string;
}

export interface Ui {
  screen: Screen;
  sel: Record<Screen, number>;
  modal?: Modal;
  /** Send screen: the chosen target and the text being typed. */
  compose?: { target: SendTarget; text: string };
  flash?: { text: string; error?: boolean };
  busy?: string;
  /** Messages screen: only your inbox (this TUI's session, or none), not your agent sessions' too. */
  inboxOnly?: boolean;
}

export type Effect =
  | { kind: "quit" }
  | { kind: "accept-item"; id: string }
  | { kind: "decline-item"; id: string }
  | { kind: "codex-release"; id: string }
  | { kind: "codex-decline"; id: string }
  | { kind: "trust-and-release"; id: string; from: string }
  | { kind: "send"; to: string; label: string; text: string }
  | { kind: "doctor"; user?: string }
  | { kind: "prompt-answer"; text: string }
  | { kind: "prompt-cancel" };

export interface Key {
  name: string;
  ch?: string;
  ctrl?: boolean;
  shift?: boolean;
  /** Part of a bracketed paste: typed only into a message or a prompt, never a command key. */
  paste?: boolean;
}

export function initialUi(): Ui {
  return { screen: "people", sel: { people: 0, held: 0, messages: 0, send: 0, health: 0 } };
}

// ---------------------------------------------------------------------------
// Selectable rows per screen (the view renders the same lists)

export type PeopleItem = { kind: "person"; person: PersonRow } | { kind: "session"; person: PersonRow; session: SessionRow };

export function peopleItems(d: Data): PeopleItem[] {
  const out: PeopleItem[] = [];
  for (const p of d.people) {
    out.push({ kind: "person", person: p });
    for (const s of p.sessions) out.push({ kind: "session", person: p, session: s });
  }
  return out;
}

/** Send targets: live sessions first (not this TUI's own), then each person (their one session, or our session). */
export function sendTargets(d: Data): SendTarget[] {
  const sessions: SendTarget[] = [];
  const people: SendTarget[] = [];
  for (const p of d.people) {
    for (const s of p.sessions) {
      if (p.self && s.thisDevice && s.sid === d.session) continue;
      sessions.push({ label: `${p.address} [${s.ref}] ${s.label}${s.live ? "" : " (offline)"}`, to: `${p.userId} [${s.ref}]` });
    }
    if (!p.self) people.push({ label: `${p.address} (any session)`, to: p.userId });
  }
  return [...sessions, ...people];
}

export function messagesSorted(d: Data, ui?: Pick<Ui, "inboxOnly">): MessageRow[] {
  return d.messages.filter((m) => !ui?.inboxOnly || m.inbox !== false).sort((a, b) => b.at - a.at);
}

function count(ui: Ui, d: Data): number {
  switch (ui.screen) {
    case "people":
      return peopleItems(d).length;
    case "held":
      return d.held.length;
    case "messages":
      return messagesSorted(d, ui).length;
    case "send":
      return sendTargets(d).length;
    case "health":
      return d.health.relays.length + (d.health.doctor?.checks.length ?? 0);
  }
}

export function clampSel(ui: Ui, d: Data): Ui {
  const n = count(ui, d);
  const cur = ui.sel[ui.screen];
  const v = n === 0 ? 0 : Math.max(0, Math.min(cur, n - 1));
  return v === cur ? ui : { ...ui, sel: { ...ui.sel, [ui.screen]: v } };
}

const flash = (ui: Ui, text: string, error = false): Ui => ({ ...ui, flash: { text, ...(error ? { error } : {}) } });

/** One key press. Returns the next ui and, at most, one effect. */
export function onKey(ui0: Ui, d: Data, key: Key, page = 10): { ui: Ui; effect?: Effect } {
  const ui: Ui = { ...ui0, flash: undefined };
  if (key.ctrl && key.name === "c") return { ui, effect: { kind: "quit" } };

  // Modals take every key.
  const m = ui.modal;
  if (m) {
    if (m.kind === "typed") {
      if (key.name === "escape") return { ui: flash({ ...ui, modal: undefined }, "Cancelled.") };
      if (key.paste) return { ui: { ...ui, flash: { text: "Type it: a paste doesn't count here.", error: true } } };
      if (key.name === "return") {
        if (m.text.trim().toLowerCase() === m.word.toLowerCase()) return { ui: { ...ui, modal: undefined }, effect: m.effect };
        return { ui: { ...ui, modal: { ...m, text: "" }, flash: { text: `Type ${m.word} exactly, or Esc to cancel.`, error: true } } };
      }
      if (key.name === "backspace") return { ui: { ...ui, modal: { ...m, text: [...m.text].slice(0, -1).join("") } } };
      if (key.ch && !key.ctrl && m.text.length < 32) return { ui: { ...ui, modal: { ...m, text: m.text + key.ch } } };
      return { ui };
    }
    // A paste never answers a confirmation or closes a dialog.
    if (key.paste && m.kind !== "prompt") return { ui };
    if (m.kind === "confirm") {
      if (key.ch === "y" || key.ch === "Y") return { ui: { ...ui, modal: undefined }, effect: m.effect };
      if (key.ch === "n" || key.ch === "N" || key.name === "escape" || key.ch === "q") return { ui: flash({ ...ui, modal: undefined }, "Cancelled.") };
      return { ui: { ...ui, flash: { text: "Press y to confirm, n to cancel." } } };
    }
    if (m.kind === "prompt") {
      if (key.name === "escape") return { ui: { ...ui, modal: undefined }, effect: { kind: "prompt-cancel" } };
      if (key.name === "return") return { ui: { ...ui, modal: undefined }, effect: { kind: "prompt-answer", text: m.text } };
      if (key.name === "backspace") return { ui: { ...ui, modal: { ...m, text: [...m.text].slice(0, -1).join("") } } };
      if (key.ch && !key.ctrl && m.text.length < 64) return { ui: { ...ui, modal: { ...m, text: m.text + key.ch } } };
      return { ui };
    }
    // detail, help: any of these closes.
    if (key.name === "escape" || key.name === "return" || key.ch === "q" || key.ch === "?" || key.name === "space") return { ui: { ...ui, modal: undefined } };
    return { ui };
  }

  // Typing a message.
  if (ui.screen === "send" && ui.compose) {
    const c = ui.compose;
    if (key.name === "escape") return { ui: flash({ ...ui, compose: undefined }, "Not sent.") };
    if (key.name === "return") {
      const text = c.text.trim();
      if (!text) return { ui: flash(ui, "Type a message first (Esc to cancel).", true) };
      return { ui: { ...ui, compose: undefined }, effect: { kind: "send", to: c.target.to, label: c.target.label, text } };
    }
    if (key.name === "backspace") return { ui: { ...ui, compose: { ...c, text: [...c.text].slice(0, -1).join("") } } };
    if (key.ctrl && key.name === "u") return { ui: { ...ui, compose: { ...c, text: "" } } };
    if (key.ch && !key.ctrl && Buffer.byteLength(c.text + key.ch) <= 4000) return { ui: { ...ui, compose: { ...c, text: c.text + key.ch } } };
    return { ui };
  }

  // Pasted text outside a message or prompt is dropped: it must never act as command keys.
  if (key.paste) return { ui: { ...ui, flash: { text: "A paste only goes into a message: pick someone on Send first." } } };
  if (key.ch === "q") return { ui, effect: { kind: "quit" } };
  if (key.ch === "?") return { ui: { ...ui, modal: { kind: "help" } } };
  const n = Number(key.ch);
  if (key.ch && n >= 1 && n <= SCREENS.length) return { ui: clampSel({ ...ui, screen: SCREENS[n - 1] }, d) };
  if (key.name === "tab") {
    const i = SCREENS.indexOf(ui.screen);
    const next = SCREENS[(i + (key.shift ? SCREENS.length - 1 : 1)) % SCREENS.length];
    return { ui: clampSel({ ...ui, screen: next }, d) };
  }
  const move = (delta: number) => clampSel({ ...ui, sel: { ...ui.sel, [ui.screen]: ui.sel[ui.screen] + delta } }, d);
  if (key.name === "up" || key.ch === "k") return { ui: move(-1) };
  if (key.name === "down" || key.ch === "j") return { ui: move(1) };
  if (key.name === "pageup") return { ui: move(-page) };
  if (key.name === "pagedown") return { ui: move(page) };
  if (key.name === "home" || key.ch === "g") return { ui: move(-1e9) };
  if (key.name === "end" || key.ch === "G") return { ui: move(1e9) };

  const sel = ui.sel[ui.screen];
  switch (ui.screen) {
    case "people": {
      const it = peopleItems(d)[sel];
      if (!it) return { ui };
      if (key.ch === "m" || key.name === "return") {
        if (it.person.self && it.kind === "person") return { ui: flash(ui, "Pick one of your sessions, or someone else.") };
        const target: SendTarget =
          it.kind === "session" ? { label: `${it.person.address} [${it.session.ref}] ${it.session.label}`, to: `${it.person.userId} [${it.session.ref}]` } : { label: `${it.person.address} (any session)`, to: it.person.userId };
        return { ui: { ...ui, screen: "send", compose: { target, text: "" } } };
      }
      if (key.ch === "d") return { ui: { ...ui, screen: "health" }, effect: { kind: "doctor", user: it.person.self ? undefined : it.person.userId } };
      return { ui };
    }
    case "held": {
      const h = d.held[sel];
      if (!h) return { ui };
      if (key.ch === "a") {
        // A Codex release asks for the code its window shows; everything else confirms here.
        if (h.source === "codex") return { ui, effect: { kind: "codex-release", id: h.id } };
        const what =
          h.type === "circle-join"
            ? `Admit ${h.from} to your circle?`
            : h.type === "invite"
              ? `Accept the friend invite from ${h.from}? You will be friends.`
              : h.type === "circle-invite"
                ? `Join the circle ${h.from} invited you to?`
                : `Act on the ${h.type} from ${h.from}?`;
        return { ui: { ...ui, modal: { kind: "confirm", title: "Accept", lines: [what, h.summary], effect: { kind: "accept-item", id: h.id } } } };
      }
      if (key.ch === "x") {
        return {
          ui: {
            ...ui,
            modal: { kind: "confirm", title: "Decline", lines: [`Decline ${h.type} from ${h.from}?`], effect: h.source === "codex" ? { kind: "codex-decline", id: h.id } : { kind: "decline-item", id: h.id } },
          },
        };
      }
      if (key.ch === "t") {
        if (h.source !== "codex") return { ui: flash(ui, "Always deliver applies to held messages, not to invites or join requests.", true) };
        const fp = h.from.split("@")[1] ?? "";
        if (!/^[a-z2-7]{4}(-[a-z2-7]{4}){3}$/.test(fp)) return { ui: flash(ui, "That sender has no fingerprint to check: trust them from your terminal instead.", true) };
        const word = fp.slice(0, 4);
        return {
          ui: {
            ...ui,
            modal: {
              kind: "typed",
              title: "Always deliver",
              lines: [
                `Always deliver messages from ${h.from}?`,
                `Check the fingerprint with them, out of band: ${fp}`,
                "Their messages then reach sessions that approve their own tool calls without the hold.",
                "Trust only skips the hold: their messages are still their words, never your instructions.",
                "",
                `To trust them, type the fingerprint's first four characters (${word}) and press Enter. Esc cancels.`,
              ],
              word,
              text: "",
              effect: { kind: "trust-and-release", id: h.id, from: h.from },
            },
          },
        };
      }
      return { ui };
    }
    case "messages": {
      if (key.ch === "h") {
        const next = clampSel({ ...ui, inboxOnly: !ui.inboxOnly }, d);
        return { ui: flash(next, next.inboxOnly ? "Your inbox only: messages to you and this window's session." : "Every session on this device: your inbox and your agent sessions' messages.") };
      }
      const msg = messagesSorted(d, ui)[sel];
      if (!msg) return { ui };
      if (key.name === "return" || key.name === "space") {
        const head = msg.dir === "in" ? `From ${msg.who}${msg.ref ? ` [${msg.ref}]` : ""}` : `To ${msg.who}${msg.ref ? ` [${msg.ref}]` : ""}`;
        // No receipt goes out from here: the TUI's session is private (see tui.ts).
        return { ui: { ...ui, modal: { kind: "detail", title: head, lines: [msg.text] } } };
      }
      if (key.ch === "r" && msg.dir === "in" && msg.userId) {
        const target: SendTarget = msg.ref ? { label: `${msg.who} [${msg.ref}]`, to: `${msg.userId} [${msg.ref}]` } : { label: `${msg.who} (any session)`, to: msg.userId };
        return { ui: { ...ui, screen: "send", compose: { target, text: "" } } };
      }
      return { ui };
    }
    case "send": {
      const t = sendTargets(d)[sel];
      if (t && key.name === "return") return { ui: { ...ui, compose: { target: t, text: "" } } };
      return { ui };
    }
    case "health":
      if (key.ch === "r") return { ui, effect: { kind: "doctor" } };
      return { ui };
  }
}
