// Copyright 2026 Ix Infrastructure Inc.
// Fixture data for the TUI's render tests, with hostile peer strings mixed in,
// and a fake terminal.

import type { Data } from "../model.js";
import type { Terminal } from "../terminal.js";
import type { Key } from "../model.js";

export const NOW = Date.UTC(2026, 9, 28, 15, 0, 0);

/** Strings a hostile peer might send: escapes, OSC 8 links, bidi, zero-width, C1, newlines. */
export const HOSTILE = {
  csi: "evil\u001b[2J\u001b[31mRED\u001b[0m",
  osc8: "\u001b]8;;https://evil.example\u0007click me\u001b]8;;\u0007",
  osc52: "\u001b]52;c;cm0gLXJmIH4=\u0007copied",
  bidi: "safe‮txt.exe‬",
  zw: "ad​min‍﻿",
  c1: "x\u009b31my\u009d0;title\u009c",
  nl: "line1\nline2\r\nline3\ttab",
  title: "\u001b]0;pwned\u0007name",
  dcs: "\u001bP+q\u001b\\ok",
  long: "w".repeat(500),
  zalgo: "Ź̂̃̄̅ok",
  hangul: "ㅤㅤx",
  bell: "ding\u0007dong",
};

export function fixtureData(): Data {
  const min = 60_000;
  return {
    me: { userId: "p2p:me", address: "tanner@k7qm-3xpd-9twa-hf2n" },
    session: "tui",
    loading: false,
    heldNote: "Messages the Claude Code mod holds stay in Claude Code; the CLI can't see them, so they aren't listed here.",
    people: [
      {
        userId: "p2p:me",
        address: "tanner@k7qm-3xpd-9twa-hf2n",
        relation: "you",
        self: true,
        live: true,
        sessions: [{ own: "p2p:me", sid: "s1", ref: "a1b2c3", label: "relay", state: "busy", live: true, ageSec: 20, repo: "Peer2Peer", branch: "feat/tui", summary: "Writing the terminal UI", files: ["packages/p2p/src/tui/view.ts"], agents: [], thisDevice: true }],
      },
      {
        userId: "p2p:alice",
        address: "alice@ab12-cd34-ef56-gh78",
        relation: "friend · circle team",
        self: false,
        live: true,
        sessions: [
          {
            own: "p2p:alice",
            sid: "s2",
            ref: "d4e5f6",
            label: `web ${HOSTILE.csi}`,
            state: "idle",
            live: true,
            ageSec: 75,
            repo: "site",
            branch: "main",
            summary: `Reviewing ${HOSTILE.osc8} ${HOSTILE.bidi}`,
            files: ["src/app.tsx", `src/${HOSTILE.zw}.ts`, "README.md"],
            agents: [
              { id: "a1", type: "Explore", task: `find the bug ${HOSTILE.title}`, state: "running" },
              { id: "a2", parent: "a1", type: "general-purpose", task: "write a test", state: "done", branch: "fix/bug" },
            ],
          },
        ],
      },
      {
        userId: "p2p:bob",
        address: `bob${HOSTILE.c1}@zz99-yy88-xx77-ww66`,
        relation: "circle team",
        self: false,
        live: false,
        sessions: [{ own: "p2p:bob", sid: "s3", ref: "0a0b0c", label: HOSTILE.nl, state: "idle", live: false, ageSec: 7200, files: [], agents: [] }],
      },
    ],
    held: [
      { source: "item", id: "c1", type: "invite", from: `carol${HOSTILE.osc52}@qq11-ww22-ee33-rr44`, summary: "friend invite (first contact)", at: NOW - 5 * min },
      { source: "codex", id: "h7", type: "message (msg)", from: "dave@pq23-oo34-ii45-uu56", session: "codex@k7qm", summary: `this session approves its own tool calls ${HOSTILE.dcs}`, at: NOW - 2 * min },
    ],
    messages: [
      { id: "m1", dir: "in", at: NOW - 3 * min, who: "alice@ab12-cd34-ef56-gh78", userId: "p2p:alice", ref: "d4e5f6", text: `Can you look at the relay? ${HOSTILE.bell} ${HOSTILE.long}` },
      { id: "m2", dir: "out", at: NOW - 2 * min, who: "alice@ab12-cd34-ef56-gh78", ref: "d4e5f6", text: "On it.", state: "sent", receiptId: "r1", outcomes: ["shown"] },
      { id: "m3", dir: "out", at: NOW - min, who: `bob${HOSTILE.c1}@zz99-yy88-xx77-ww66`, ref: "0a0b0c", text: `ping ${HOSTILE.zalgo} ${HOSTILE.hangul}`, state: "offline", lastSeen: NOW - 2 * 3600_000 },
    ],
    health: {
      relays: [
        { url: "wss://relay.team.example/v3", up: true, access: "members", software: "@peer2peer/relay 0.1.0", pow: 0 },
        { url: "wss://backup.example/v3", up: false, reason: `can't reach it ${HOSTILE.csi}` },
      ],
      doctor: {
        scope: "device",
        checks: [
          { status: "ok", title: "identity", detail: "tanner@k7qm-3xpd-9twa-hf2n, document expires in 21 days" },
          { status: "ok", title: "clock", detail: "within 2 s of the relays" },
          { status: "fail", title: "relays", detail: "1 of 2 relays unreachable", fix: "check wss://backup.example/v3 or remove it with `p2p relays remove`" },
          { status: "unknown", title: "sharing", detail: "no live session to check", fix: "start a session" },
        ],
        summary: { ok: 2, fail: 1, unknown: 1 },
        at: NOW - 30_000,
      },
    },
  };
}

export class FakeTerminal implements Terminal {
  readonly frames: string[] = [];
  entered = 0;
  left = 0;
  private keyFn?: (k: Key) => void;
  private resizeFn?: () => void;
  constructor(
    public cols = 80,
    public rows = 24,
    readonly color = false,
  ) {}
  enter(): void {
    this.entered++;
  }
  leave(): void {
    // Like the real one: idempotent.
    if (this.left < this.entered) this.left++;
  }
  write(s: string): void {
    this.frames.push(s);
  }
  onKey(fn: (k: Key) => void): void {
    this.keyFn = fn;
  }
  onResize(fn: () => void): void {
    this.resizeFn = fn;
  }
  press(k: Key): void {
    this.keyFn?.(k);
  }
  type(s: string): void {
    for (const ch of s) this.keyFn?.(ch === "\r" ? { name: "return" } : { name: ch, ch });
  }
  resize(cols: number, rows: number): void {
    this.cols = cols;
    this.rows = rows;
    this.resizeFn?.();
  }
  /** The last frame as plain text (escape sequences removed). */
  get text(): string {
     
    return (this.frames.at(-1) ?? "").replace(/\u001b\[[0-9;?]*[A-Za-z]/g, "");
  }
}
