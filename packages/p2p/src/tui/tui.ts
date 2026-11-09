// Copyright 2026 Ix Infrastructure Inc.
//
// `p2p tui`: the controller. It owns the terminal, keeps the data model
// current and runs what a key press asks for.
//
//  - Live updates come from the same event stream as `p2p watch`, run
//    in-process (watch.ts) as this TUI's own session: a delivery, a status or
//    a held item redraws within one tick. Nothing polls the network on a
//    timer; the only timers re-read in-memory relay state, refresh relative
//    times, and (while the Held screen is open) ask local Codex sessions what
//    they hold.
//  - Every change (accept, decline, trust, send) is a key press's effect
//    (model.ts onKey). Loading never changes anything.
//  - Receipts: none. The TUI's session is private (it posts no status and
//    has no roster), so senders never ask it for receipts, and it sends
//    none: a `shown` would tell a sender that this session exists and when
//    its person read the message. Replies to its own sends come back like
//    any message, without one.
//  - The terminal is restored on quit, Ctrl-C, SIGTERM/SIGHUP and errors.

import * as codex from "@peer2peer/codex-bridge";
import { RECEIPT_OUTCOMES } from "@peer2peer/core/v3";
import type { App } from "../app.js";
import { approveJoinRequest, circleMembers, joinFromHeld, listCircles } from "../circle-ops.js";
import { doctor } from "../doctor.js";
import { CliError, toErrorJson } from "../errors.js";
import { listPeers, sendSharing, tuiTaintNote } from "../sessions.js";
import { isPersonRecord, readHistory, type HistoryRec } from "../history.js";
import { sessionWorkdir, showProject } from "../projects.js";
import { accept, dropHeld, friends, getHeld, listHeld } from "../social.js";
import { trustAdd } from "../trust.js";
import { watch } from "../watch.js";
import { clean } from "./sanitize.js";
import { clampSel, initialUi, onKey, type Data, type Effect, type HeldRow, type MessageRow, type Outcome, type PersonRow, type SessionRow, type Ui } from "./model.js";
import { toAnsi } from "./frame.js";
import { render } from "./view.js";
import type { Terminal } from "./terminal.js";

export const TUI_SESSION = "tui";
/** A relay's `/.well-known/p2p-relay.json` read at most this far (it is a few hundred bytes). */
export const WELL_KNOWN_MAX = 64 * 1024;
/** Messages kept in memory (the newest). */
export const MESSAGES_MAX = 100;

/** A response body as text, refusing more than `max` bytes (the read stops there). */
export async function readCapped(body: ReadableStream<Uint8Array>, max: number): Promise<string> {
  const reader = body.getReader();
  const parts: Uint8Array[] = [];
  let n = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      n += value.byteLength;
      if (n > max) throw new Error(`more than ${max} bytes`);
      parts.push(value);
    }
  } finally {
    void reader.cancel().catch(() => {});
  }
  return Buffer.concat(parts).toString("utf8");
}

const CLAUDE_HOLD_NOTE =
  "Messages the Claude Code mod holds for a session stay in Claude Code (its /peers panel); the CLI can't see them, so they aren't listed here. Codex sessions' held messages and every invite or join request are.";

export interface TuiOptions {
  term: Terminal;
  session?: string;
  version: string;
  /** Stops the TUI (tests, signals). */
  signal?: AbortSignal;
  now?: () => number;
  /** Lines the app or watch would print to stderr: kept here, shown in the status line. */
  log?: (m: string) => void;
  /** Tests: run without the in-process watch. */
  noWatch?: boolean;
}

const asOutcome = (o: unknown): Outcome | undefined => (RECEIPT_OUTCOMES as readonly string[]).includes(String(o)) ? (o as Outcome) : undefined;

export class Tui {
  readonly data: Data;
  ui: Ui = initialUi();
  private readonly now: () => number;
  private readonly stop = new AbortController();
  private renderQueued = false;
  private timers: NodeJS.Timeout[] = [];
  private refreshTimers = new Map<string, NodeJS.Timeout>();
  private promptAnswer?: (s: string | undefined) => void;
  private sent: MessageRow[] = [];
  private closed?: Promise<void>;
  lastFrame = "";

  constructor(
    readonly app: App,
    private readonly o: TuiOptions,
  ) {
    this.now = o.now ?? Date.now;
    this.data = { session: o.session ?? TUI_SESSION, people: [], held: [], heldNote: CLAUDE_HOLD_NOTE, messages: [], health: { relays: [] }, loading: true };
  }

  /** Runs until quit or abort; the terminal is always restored. */
  async run(): Promise<void> {
    const { term } = this.o;
    const onSignal = () => this.stop.abort();
    process.on("SIGINT", onSignal);
    process.on("SIGTERM", onSignal);
    process.on("SIGHUP", onSignal);
    this.o.signal?.addEventListener("abort", onSignal);
    term.enter();
    try {
      term.onKey((k) => this.key(k));
      term.onResize(() => this.draw());
      this.data.me = { userId: this.app.userId, address: await this.app.addressOf(this.app.userId) };
      this.draw();
      const watching = this.o.noWatch ? Promise.resolve(0) : this.startWatch();
      await this.loadAll();
      this.every(5_000, () => this.relayState());
      this.every(10_000, async () => this.draw());
      this.every(30_000, async () => {
        if (this.ui.screen === "held") await this.loadHeld();
      });
      void this.runDoctor();
      await new Promise<void>((r) => (this.stop.signal.aborted ? r() : this.stop.signal.addEventListener("abort", () => r())));
      // The terminal goes back first; the watch then closes its connections (bounded).
      term.leave();
      let t: NodeJS.Timeout | undefined;
      await Promise.race([watching.catch(() => 0), new Promise((r) => (t = setTimeout(r, 5000)))]);
      clearTimeout(t);
    } finally {
      for (const t of this.timers) clearInterval(t);
      for (const t of this.refreshTimers.values()) clearTimeout(t);
      this.promptAnswer?.(undefined);
      term.leave();
      process.off("SIGINT", onSignal);
      process.off("SIGTERM", onSignal);
      process.off("SIGHUP", onSignal);
      this.o.signal?.removeEventListener("abort", onSignal);
      if (this.o.noWatch) await this.app.close();
    }
  }

  quit(): void {
    this.stop.abort();
  }

  private log(m: string): void {
    this.o.log?.(m);
  }

  private every(ms: number, fn: () => Promise<void>): void {
    const t = setInterval(() => void fn().catch((e) => this.log((e as Error).message)), ms);
    t.unref();
    this.timers.push(t);
  }

  /** Coalesces refreshes of one kind triggered by bursts of events. */
  private soon(kind: string, fn: () => Promise<void>, ms = 300): void {
    if (this.refreshTimers.has(kind)) return;
    const t = setTimeout(() => {
      this.refreshTimers.delete(kind);
      void fn().catch((e) => this.log((e as Error).message));
    }, ms);
    t.unref();
    this.refreshTimers.set(kind, t);
  }

  draw(): void {
    if (this.renderQueued) return;
    this.renderQueued = true;
    setImmediate(() => {
      this.renderQueued = false;
      this.drawNow();
    });
  }

  drawNow(): void {
    const { term } = this.o;
    this.ui = clampSel(this.ui, this.data);
    const f = render(this.ui, this.data, term.cols, term.rows, this.now());
    const out = toAnsi(f, term.color);
    this.lastFrame = out;
    term.write(out);
  }

  // -------------------------------------------------------------------------
  // Data

  private startWatch(): Promise<number> {
    return watch(this.app, {
      session: this.data.session,
      signal: this.stop.signal,
      log: (m) => this.log(m),
      write: async (line) => {
        try {
          this.onEvent(JSON.parse(line) as Record<string, unknown>);
        } catch (e) {
          this.log((e as Error).message);
        }
        return true;
      },
    }).catch((e) => {
      this.flash(`watch stopped: ${String(toErrorJson(e).reason)}`, true);
      return 1;
    });
  }

  /** One event from the stream (already in the shared log). */
  onEvent(e: Record<string, unknown>): void {
    const kind = String(e.kind);
    if (kind === "p2p.message") {
      const m = this.messageFromEvent(e);
      if (m && !this.data.messages.some((x) => x.id === m.id)) {
        this.data.messages.push(m);
        this.capMessages();
      }
    } else if (kind === "p2p.receipt") {
      const id = String(e.receiptId ?? "");
      const o = asOutcome(e.outcome);
      const m = this.data.messages.find((x) => x.receiptId === id);
      if (m && o && !(m.outcomes ?? []).includes(o)) m.outcomes = [...(m.outcomes ?? []), o];
    } else if (kind === "p2p.outbox") {
      this.soon("messages", () => this.loadMessages());
    }
    if (["p2p.status", "p2p.idle", "p2p.friend", "p2p.unfriend", "p2p.circle", "p2p.roster", "p2p.joined"].includes(kind)) this.soon("people", () => this.loadPeople());
    if (["p2p.held", "p2p.circle", "p2p.contact", "p2p.invite-taken"].includes(kind)) this.soon("held", () => this.loadHeld());
    this.draw();
  }

  private messageFromEvent(e: Record<string, unknown>): MessageRow | undefined {
    const from = (e.from ?? {}) as { userId?: unknown; address?: unknown; self?: unknown };
    if (typeof e.id !== "string") return undefined;
    const forUs = e.toSession === this.data.session || (e.toSession === undefined && e.unclaimedFor === undefined);
    return {
      id: e.id,
      dir: "in",
      at: typeof e.at === "number" ? e.at : this.now(),
      who: clean(from.address) || "?",
      ...(typeof from.userId === "string" ? { userId: from.userId } : {}),
      ...(typeof e.own === "string" ? { own: e.own } : {}),
      ...(typeof e.sid === "string" ? { sid: e.sid } : {}),
      ...(typeof e.ref === "string" ? { ref: e.ref } : {}),
      text: clean(e.text),
      inbox: forUs,
      ...(!forUs && typeof e.toSession === "string" ? { note: `for your session ${clean(e.toSession)}` } : {}),
    };
  }

  async loadAll(): Promise<void> {
    await Promise.all([this.loadPeople(), this.loadHeld(), this.loadMessages(), this.relayState()].map((p) => p.catch((e) => this.log((e as Error).message))));
    this.data.loading = false;
    this.draw();
  }

  async loadPeople(): Promise<void> {
    const app = this.app;
    const [peers, fr, circles] = await Promise.all([listPeers(app, { all: true }), friends(app), listCircles(app)]);
    const people = new Map<string, PersonRow>();
    const person = (userId: string, address: string): PersonRow => {
      let p = people.get(userId);
      if (!p) people.set(userId, (p = { userId, address, relation: "", self: userId === app.userId, live: false, sessions: [] }));
      return p;
    };
    const rel = new Map<string, Set<string>>();
    const addRel = (u: string, r: string) => rel.set(u, (rel.get(u) ?? new Set()).add(r));
    for (const f of fr.friends) {
      person(f.userId, f.address);
      addRel(f.userId, "friend");
    }
    for (const c of circles.filter((x) => x.joined)) {
      try {
        const m = await circleMembers(app, c.cid);
        for (const x of m.members) {
          if (x.self || !x.stands) continue;
          person(x.userId, x.address);
          addRel(x.userId, `circle ${clean(c.name)}`);
        }
      } catch {
        // a circle that doesn't load: skip it
      }
    }
    for (const p of peers) {
      const pr = person(p.own, p.address);
      const s: SessionRow = {
        own: p.own,
        sid: p.sid,
        ref: p.ref,
        label: p.label,
        state: p.state,
        live: p.live,
        ageSec: p.ageSec,
        files: p.files,
        agents: (p.agents ?? []).map((a) => ({ id: a.id, ...(a.parent ? { parent: a.parent } : {}), type: a.type, task: a.task, state: a.state, ...(a.branch ? { branch: a.branch } : {}) })),
        ...(p.summary ? { summary: p.summary } : {}),
        ...(p.repo ? { repo: p.repo } : {}),
        ...(p.branch ? { branch: p.branch } : {}),
        ...(p.thisDevice ? { thisDevice: true } : {}),
      };
      pr.sessions.push(s);
      if (p.live) pr.live = true;
    }
    for (const p of people.values()) {
      p.relation = p.self ? "you" : [...(rel.get(p.userId) ?? [])].join(" · ") || "shares a session with you";
      p.sessions.sort((a, b) => Number(b.live) - Number(a.live) || a.ageSec - b.ageSec);
    }
    this.data.people = [...people.values()].sort((a, b) => Number(b.self) - Number(a.self) || Number(b.live) - Number(a.live) || a.address.localeCompare(b.address));
    this.draw();
  }

  async loadHeld(): Promise<void> {
    const items = await listHeld(this.app);
    const rows: HeldRow[] = items.map((h) => ({ source: "item", id: h.id, type: h.type, from: h.address, summary: h.summary, at: h.at }));
    try {
      const c = await codex.heldCommand({ env: this.app.env, now: this.now() });
      const held = ((c.json as { held?: unknown }).held ?? []) as { id: string; from: string; at: number; why: string; kind: string; session: string }[];
      for (const h of held) rows.push({ source: "codex", id: h.id, type: `message (${h.kind})`, from: h.from, session: h.session, summary: h.why, at: h.at });
    } catch {
      // no Codex sessions, or not allowed here
    }
    this.data.held = rows;
    this.draw();
  }

  /**
   * Received messages from the event log, and sent ones: this run's, receipts asked for, the outbox;
   * then the message history (history.ts) for what is older or was sent elsewhere. The TUI runs
   * only on the person's own terminal (command.ts tuiRefusal), so it reads the person's view.
   */
  async loadMessages(): Promise<void> {
    const app = this.app;
    const cutoff = this.now() - 7 * 86_400_000;
    const log = (await app.state.get("events"))?.items ?? [];
    const received = log
      .filter((e) => e.kind === "p2p.message" && e.at >= cutoff && !(e.data.from as { self?: boolean } | undefined)?.self)
      .slice(-100)
      .map((e) => this.messageFromEvent({ ...e.data, kind: e.kind, id: e.id, at: e.at, ...(e.toSession ? { toSession: e.toSession } : {}) }))
      .filter((m): m is MessageRow => m !== undefined);
    const receipts = (await app.state.get("receipts"))?.wanted ?? {};
    const outbox = (await app.state.get("outbox"))?.items ?? [];
    const out: MessageRow[] = [];
    for (const s of this.sent) {
      const w = s.receiptId ? receipts[s.receiptId] : undefined;
      if (w) s.outcomes = w.outcomes.map((x) => x.outcome);
      out.push(s);
    }
    for (const [id, w] of Object.entries(receipts)) {
      if (w.at < cutoff || out.some((m) => m.receiptId === id)) continue;
      out.push({ id: `r:${id}`, dir: "out", at: w.at, who: await app.addressOf(w.to), userId: w.to, own: w.own, ref: w.ref, text: `(sent from session ${w.fromSession}; text not kept)`, state: "sent", receiptId: id, outcomes: w.outcomes.map((x) => x.outcome), inbox: w.fromSession === this.data.session, ...(w.fromSession !== this.data.session ? { note: `from your session ${clean(w.fromSession)}` } : {}) });
    }
    for (const i of outbox) {
      out.push({ id: `o:${i.id}`, dir: "out", at: i.queuedAt, who: i.dest.address, userId: i.dest.userId, own: i.dest.own, ref: i.dest.ref, text: `(sealed in the outbox, from session ${i.fromSession})`, state: "outbox", inbox: i.fromSession === this.data.session });
    }
    const hist = await readHistory(app, { person: true }, { limit: MESSAGES_MAX }, this.now()).catch(() => undefined);
    for (const r of hist?.messages ?? []) {
      if (r.dir === "in") {
        if (!received.some((m) => m.id === r.id)) received.push(historyRow(r, this.data.session));
        continue;
      }
      // A send already listed (this run's, a receipt's, the outbox's): the history fills in its text.
      const same = out.find((m) => m.userId === r.peer.userId && Math.abs(m.at - r.at) < 60_000 && (m.text === r.text || m.text.startsWith("(")));
      if (same) {
        if (same.text.startsWith("(")) same.text = clean(r.text);
        continue;
      }
      out.push(historyRow(r, this.data.session));
    }
    this.data.messages = [...received, ...out];
    this.capMessages();
    this.draw();
  }

  /** Keeps the newest MESSAGES_MAX messages (this run's sends are capped the same way). */
  private capMessages(): void {
    if (this.data.messages.length > MESSAGES_MAX) this.data.messages = [...this.data.messages].sort((a, b) => b.at - a.at).slice(0, MESSAGES_MAX);
    if (this.sent.length > MESSAGES_MAX) this.sent = this.sent.slice(-MESSAGES_MAX);
  }

  /** Relay up/down from the in-memory pool (no network). */
  async relayState(): Promise<void> {
    const app = this.app;
    const connected = new Set(app.pool?.connected ?? app.relayStatus?.connected ?? []);
    const failed = new Map((app.relayStatus?.failed ?? []).map((f) => [f.url, f.reason]));
    const prev = new Map(this.data.health.relays.map((r) => [r.url, r]));
    this.data.health.relays = app.relays.map((url) => ({
      ...prev.get(url),
      url,
      up: connected.has(url),
      ...(connected.has(url) ? { reason: undefined } : failed.has(url) ? { reason: clean(failed.get(url)) } : {}),
    }));
    this.draw();
  }

  /** Each relay's `/.well-known/p2p-relay.json` (access, software, pow): read once per doctor run. */
  private async relayInfo(): Promise<void> {
    await Promise.all(
      this.app.relays.map(async (url) => {
        try {
          const base = new URL(this.app.transport(url).http).origin;
          const res = await fetch(`${base}/.well-known/p2p-relay.json`, { signal: AbortSignal.timeout(5000) });
          if (!res.ok || !res.body) return;
          const j = JSON.parse(await readCapped(res.body, WELL_KNOWN_MAX)) as { access?: unknown; attention?: unknown; software?: { name?: unknown; version?: unknown }; pow?: unknown };
          const r = this.data.health.relays.find((x) => x.url === url);
          if (!r) return;
          if (j.access === "members" || j.access === "open") r.access = j.access;
          r.attention = j.attention === true;
          if (j.software && typeof j.software.version === "string") r.software = clean(`${String(j.software.name ?? "relay")} ${j.software.version}`).slice(0, 40);
          if (typeof j.pow === "number" && Number.isSafeInteger(j.pow)) r.pow = j.pow;
        } catch {
          // unreachable: the doctor says so
        }
      }),
    );
  }

  async runDoctor(user?: string): Promise<void> {
    if (this.data.health.running) return;
    this.data.health.running = true;
    this.draw();
    try {
      await this.relayState();
      await this.relayInfo();
      const r = await doctor(this.app, { version: this.o.version, ...(user ? { user } : {}) });
      this.data.health.doctor = {
        scope: r.scope,
        ...(r.user ? { who: clean(r.user.address ?? r.user.input) } : {}),
        checks: r.checks.map((c) => ({ status: c.status, title: c.title, detail: c.detail, ...(c.fix ? { fix: c.fix } : {}) })),
        summary: r.summary,
        at: this.now(),
      };
    } catch (e) {
      this.flash(`doctor: ${String(toErrorJson(e).reason)}`, true);
    } finally {
      this.data.health.running = false;
      this.draw();
    }
  }

  // -------------------------------------------------------------------------
  // Keys and effects

  key(k: Parameters<typeof onKey>[2]): void {
    // Once quitting, nothing else is dispatched (keys after Ctrl-C in the same read included).
    if (this.stop.signal.aborted) return;
    const r = onKey(this.ui, this.data, k, Math.max(1, Math.floor((this.o.term.rows - 4) / 2)));
    this.ui = r.ui;
    if (r.effect?.kind === "quit") {
      this.quit();
      return;
    }
    this.draw();
    if (r.effect) void this.effect(r.effect);
  }

  flash(text: string, error = false): void {
    this.ui = { ...this.ui, flash: { text, ...(error ? { error } : {}) } };
    this.draw();
  }

  private async busy<T>(what: string, fn: () => Promise<T>): Promise<T | undefined> {
    this.ui = { ...this.ui, busy: what };
    this.draw();
    try {
      return await fn();
    } catch (e) {
      const j = toErrorJson(e);
      this.ui = { ...this.ui, busy: undefined };
      this.flash(`${what}: ${String(j.reason)}`, true);
      return undefined;
    } finally {
      if (this.ui.busy === what) this.ui = { ...this.ui, busy: undefined };
      this.draw();
    }
  }

  /** Asks one line in a modal (Codex release codes, circle-join confirmations). */
  private ask(title: string, lines: string[]): Promise<string | undefined> {
    this.promptAnswer?.(undefined);
    this.ui = { ...this.ui, modal: { kind: "prompt", title, lines, text: "" } };
    this.draw();
    return new Promise((resolve) => (this.promptAnswer = resolve));
  }

  async effect(e: Effect): Promise<void> {
    switch (e.kind) {
      case "quit":
        this.quit();
        return;
      case "prompt-answer":
      case "prompt-cancel": {
        const f = this.promptAnswer;
        this.promptAnswer = undefined;
        f?.(e.kind === "prompt-answer" ? e.text : undefined);
        return;
      }
      case "accept-item": {
        await this.busy("accepting", async () => {
          const h = await getHeld(this.app, e.id);
          if (h.type === "invite") {
            const r = await accept(this.app, h.invite!);
            this.flash(`You and ${clean(r.friend.address)} are friends.`);
          } else if (h.type === "circle-join") {
            const r = await approveJoinRequest(this.app, h);
            await dropHeld(this.app, (x) => x.id === h.id);
            this.flash(`Admitted ${clean(await this.app.addressOf(r.added))} (circle version ${r.ver}).`);
          } else if (h.type === "circle-invite") {
            const r = await joinFromHeld(this.app, h, {
              waitSec: 20,
              confirm: async (q) => ((await this.ask("Join the circle?", [q, "", "Type yes to join anyway."])) ?? "").trim().toLowerCase() === "yes",
            });
            this.flash(`Circle ${clean(r.name ?? r.cid)}: ${r.status}.`);
          } else {
            throw new CliError("usage", `a ${h.type} item needs a choice the CLI makes: \`p2p held approve ${h.id}\` or \`p2p identity\` in your terminal`);
          }
          await Promise.all([this.loadHeld(), this.loadPeople()]);
        });
        return;
      }
      case "decline-item": {
        await this.busy("declining", async () => {
          const h = await getHeld(this.app, e.id);
          if (h.type === "rotation-dispute") throw new CliError("usage", `a contested key is settled in the CLI: \`p2p identity dispute ${h.id}\``);
          await dropHeld(this.app, (x) => x.id === h.id);
          this.flash(`Declined.`);
          await this.loadHeld();
        });
        return;
      }
      case "codex-release":
      case "codex-decline":
        await this.busy(e.kind === "codex-release" ? "delivering" : "declining", async () => {
          const r = await codex.resolveCommand({
            env: this.app.env,
            id: e.id,
            decline: e.kind === "codex-decline",
            io: { isTTY: true, prompt: async (q) => (await this.ask("Confirmation code", [q])) ?? "" },
          });
          this.flash(clean(r.human));
          await this.loadHeld();
        });
        return;
      case "trust-and-release":
        await this.busy("delivering", async () => {
          // The release first (it asks for the code its window shows): trust is saved only once it
          // went through, so a cancelled or failed release trusts nobody.
          const r = await codex.resolveCommand({ env: this.app.env, id: e.id, io: { isTTY: true, prompt: async (q) => (await this.ask("Confirmation code", [q])) ?? "" } });
          const t = await trustAdd(this.app, e.from);
          this.flash(`${clean(r.human)} Always delivering from ${clean(t.address ?? e.from)} from now on.`);
          await this.loadHeld();
        });
        return;
      case "send":
        await this.busy("sending", async () => {
          const at = this.now();
          const row: MessageRow = { id: `s:${at}:${this.sent.length}`, dir: "out", at, who: e.label, text: e.text, state: "sent", inbox: true };
          try {
            // As `p2p send` on a terminal: someone this session isn't shared with is added with the send
            // (undone if it fails), so it lands and their replies come here; and it says so.
            const { result: r, shared } = await sendSharing(this.app, { fromSession: this.data.session, to: e.to, text: e.text });
            Object.assign(row, {
              who: clean(r.to.address),
              userId: r.to.userId,
              own: r.to.own,
              sid: r.to.sid,
              ref: r.to.ref,
              state: r.queued ? (r.state === "outbox" ? "outbox" : "offline") : "sent",
              ...(r.lastSeen ? { lastSeen: r.lastSeen } : {}),
              ...(r.receiptId ? { receiptId: r.receiptId } : {}),
            });
            const note = shared ? ` Shared session ${clean(this.data.session)} with ${clean(shared.address)}.` : "";
            // Your own send crosses no project boundary; it says which one this folder has (projects.ts).
            const here = await showProject(this.app, sessionWorkdir(this.app.env)).catch(() => undefined);
            const boundary = here ? ` Project ${clean(here.name)} here is ${here.policy}: this send was yours.` : "";
            const taint = await tuiTaintNote(this.app, r.to.userId).catch(() => undefined);
            this.flash(`${r.queued ? `Queued for ${clean(r.to.address)} [${r.to.ref}]: it goes out or waits until they're back.` : `Sent to ${clean(r.to.address)} [${r.to.ref}].`}${note}${boundary}${taint ? ` Note: ${taint}.` : ""}`);
          } catch (err) {
            Object.assign(row, { state: "failed", note: clean(toErrorJson(err).reason) });
            throw err;
          } finally {
            this.sent.push(row);
            await this.loadMessages();
          }
        });
        return;
      case "doctor":
        await this.runDoctor(e.user);
        return;
    }
  }

  /** For tests: resolves once the TUI stopped. */
  done(): Promise<void> {
    return (this.closed ??= new Promise((r) => (this.stop.signal.aborted ? r() : this.stop.signal.addEventListener("abort", () => r()))));
  }
}

/** A message history record as a row of the Messages screen (peer text cleaned for the terminal). */
export function historyRow(r: HistoryRec, session: string): MessageRow {
  const mine = isPersonRecord(r) || r.session === session;
  const where = r.session === undefined ? "" : clean(r.session);
  return {
    id: r.id,
    dir: r.dir,
    at: r.at,
    who: clean(r.peer.address) || "?",
    userId: r.peer.userId,
    ...(r.peerSession ? { own: r.peerSession.own, sid: r.peerSession.sid, ref: r.peerSession.ref } : {}),
    text: clean(r.type === "ext" ? `${r.ext ?? "extension"}: ${r.text}` : r.text),
    ...(r.dir === "out" ? { state: r.state === "outbox" ? ("outbox" as const) : r.state === "offline" ? ("offline" as const) : ("sent" as const) } : {}),
    fromHistory: true,
    inbox: mine,
    ...(!mine ? { note: r.dir === "in" ? `for your session ${where}` : `from your session ${where}` } : {}),
  };
}
