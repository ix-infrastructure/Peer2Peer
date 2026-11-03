// Copyright 2026 Ix Infrastructure Inc.
// `p2p tui`: the sanitizer against hostile peer strings, key decoding, the key
// model (effects only on key presses) and rendered frames at 80x24 and 120x40.

import { describe, expect, it } from "vitest";
import { cell, clean, displayWidth, wrap } from "../sanitize.js";
import { EventEmitter } from "node:events";
import { KeyParser, parseKeys, colorWanted, PASTE_QUIET_MS, STUCK_MS, TtyTerminal } from "../terminal.js";
import { initialUi, onKey, type Key, type Ui } from "../model.js";
import { frameText, toAnsi } from "../frame.js";
import { render } from "../view.js";
import { tuiRefusal } from "../command.js";
import { FakeTerminal, fixtureData, HOSTILE, NOW } from "./fixtures.js";
import { MESSAGES_MAX, readCapped, Tui, WELL_KNOWN_MAX } from "../tui.js";
import type { App } from "../../app.js";

process.env.TZ = "UTC";

/** Nothing a terminal could act on: no C0 (but our own escapes), no C1, no bidi/zero-width/format characters. */
 
const UNSAFE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029\p{Cf}]|\p{Cs}/u;
 
const OUR_ESCAPES = /\u001b\[(?:H|K|0m|[0-9;]*m)/g;

const k = (name: string, extra: Partial<Key> = {}): Key => ({ name, ...extra });
const ch = (c: string): Key => ({ name: c, ch: c });
const pasted = (c: string): Key => ({ name: c, ch: c, paste: true });

describe("sanitizer", () => {
  it("removes escape sequences whole, controls, bidi and zero-width characters", () => {
    expect(clean(HOSTILE.csi)).toBe("evilREDNo".replace("No", ""));
    expect(clean(HOSTILE.osc8)).toBe("click me");
    expect(clean(HOSTILE.osc52)).toBe("copied");
    expect(clean(HOSTILE.title)).toBe("name");
    expect(clean(HOSTILE.dcs)).toBe("ok");
    expect(clean(HOSTILE.bidi)).toBe("safetxt.exe");
    expect(clean(HOSTILE.zw)).toBe("admin");
    expect(clean(HOSTILE.c1)).not.toMatch(UNSAFE);
    expect(clean(HOSTILE.nl)).toBe("line1 line2 line3 tab");
    expect(clean(HOSTILE.bell)).toBe("dingdong");
    expect(clean(HOSTILE.hangul)).toBe("x");
    expect(clean(HOSTILE.zalgo)).toBe("Ź̂ok");
    // An unterminated OSC swallows the rest: nothing of it reaches the screen.
    expect(clean("ok\u001b]8;;http://x never ends")).toBe("ok");
    // Lone surrogates, private use and noncharacters.
    expect(clean("a\ud800bc￿d")).toBe("ab?cd");
    // Non-strings.
    expect(clean(undefined)).toBe("");
    expect(clean(42)).toBe("42");
    for (const v of Object.values(HOSTILE)) expect(clean(v)).not.toMatch(UNSAFE);
  });

  it("cuts to a display width, counting wide characters twice, and wraps", () => {
    expect(cell("hello world", 8)).toBe("hello w…");
    expect(displayWidth(cell("日本語のテキスト", 7))).toBeLessThanOrEqual(7);
    expect(cell("😀😀😀", 5)).toBe("😀😀…");
    expect(cell(HOSTILE.long, 10)).toHaveLength(10);
    const w = wrap(`${HOSTILE.nl} ${"x".repeat(25)}`, 10);
    expect(w.every((l) => displayWidth(l) <= 10)).toBe(true);
    expect(wrap("a ".repeat(200), 10, 3)).toHaveLength(3);
    // Width 1 with wide characters: one per line, and it ends.
    expect(wrap("日本語", 1)).toEqual(["日", "本", "語"]);
    expect(wrap("abc", 1)).toEqual(["a", "b", "c"]);
  });
});

describe("keys", () => {
  it("decodes keys, drops unknown and string sequences, and types a bracketed paste as text", () => {
    expect(parseKeys("\u001b[A\u001b[B\u001b[5~\u001b[6~\u001b[Z")).toEqual([k("up"), k("down"), k("pageup"), k("pagedown"), k("tab", { shift: true })]);
    expect(parseKeys("a\r\u0003\u007f\t")).toEqual([ch("a"), k("return"), k("c", { ctrl: true }), k("backspace"), k("tab")]);
    expect(parseKeys("\u001b]11;rgb:0/0/0\u0007x")).toEqual([ch("x")]);
    expect(parseKeys("\u001b[200~hi\nthere\u001b[31m\u001b[201~")).toEqual(["h", "i", " ", "t", "h", "e", "r", "e", "[", "3", "1", "m"].map(pasted));
    expect(parseKeys("\u001b")).toEqual([k("escape")]);
    expect(parseKeys("\u009b31m")).toEqual(["3", "1", "m"].map(ch));
  });

  it("keeps state between chunks: a split terminal answer, key sequence or paste never leaks keys", () => {
    const p = new KeyParser();
    // An OSC answer split in three.
    expect(p.feed("\u001b]11;rgb:")).toEqual([]);
    expect(p.feed("ffff/ffff")).toEqual([]);
    expect(p.feed("/ffff\u0007a")).toEqual([ch("a")]);
    // An arrow key split after ESC, and after ESC [.
    expect(p.feed("\u001b")).toEqual([]);
    expect(p.feed("[A")).toEqual([k("up")]);
    expect(p.feed("\u001b[")).toEqual([]);
    expect(p.feed("6~")).toEqual([k("pagedown")]);
    // A paste split across chunks, end marker split too: all of it is paste.
    expect(p.feed("\u001b[200~at")).toEqual([]);
    expect(p.feed("ty\u001b[2")).toEqual([]);
    // `x` right after the paste still counts as pasted (the quiet window, below).
    expect(p.feed("01~x")).toEqual([...["a", "t", "t", "y", "x"].map(pasted)]);
    // A lone ESC is Escape once nothing follows.
    expect(p.feed("\u001b")).toEqual([]);
    expect(p.flush()).toEqual([k("escape")]);
  });

  it("colour: NO_COLOR and TERM=dumb turn it off", () => {
    const tty = { isTTY: true, hasColors: () => true };
    expect(colorWanted({}, tty)).toBe(true);
    expect(colorWanted({ NO_COLOR: "1" }, tty)).toBe(false);
    expect(colorWanted({ TERM: "dumb" }, tty)).toBe(false);
    expect(colorWanted({}, { isTTY: false })).toBe(false);
  });

  it("refuses without a terminal, and inside an agent's tool call", () => {
    expect(tuiRefusal({}, false)).toMatch(/interactive terminal/);
    expect(tuiRefusal({ CLAUDECODE: "1" }, true)).toMatch(/your own terminal/);
    expect(tuiRefusal({ CODEX_THREAD_ID: "t" }, true)).toMatch(/your own terminal/);
    expect(tuiRefusal({}, true)).toBeUndefined();
  });
});

describe("key model", () => {
  const d = fixtureData();
  const press = (ui: Ui, ...keys: Key[]) => {
    const effects: unknown[] = [];
    for (const key of keys) {
      const r = onKey(ui, d, key);
      ui = r.ui;
      if (r.effect) effects.push(r.effect);
    }
    return { ui, effects };
  };

  it("navigation never has an effect", () => {
    const r = press(initialUi(), k("down"), k("down"), k("tab"), ch("3"), k("up"), ch("5"), k("pagedown"), ch("2"), ch("?"), k("escape"));
    expect(r.effects).toEqual([]);
    expect(r.ui.screen).toBe("held");
  });

  it("always deliver needs the fingerprint's first four characters typed (not y, not a paste)", () => {
    const r = press(initialUi(), ch("2"), k("down"), ch("t"));
    expect(r.effects).toEqual([]);
    expect(r.ui.modal).toMatchObject({ kind: "typed", title: "Always deliver", word: "pq23" });
    expect(JSON.stringify(r.ui.modal)).toContain("pq23-oo34-ii45-uu56");
    expect(press(r.ui, ch("y"), k("return")).effects).toEqual([]);
    expect(press(r.ui, ...[..."pq24"].map(ch), k("return")).effects).toEqual([]);
    expect(press(r.ui, ...[..."pq23"].map(pasted), k("return")).effects).toEqual([]);
    expect(press(r.ui, ...[..."pq23"].map(ch), k("escape"), k("return")).effects).toEqual([]);
    expect(press(r.ui, ...[..."pq23"].map(ch), k("return")).effects).toEqual([{ kind: "trust-and-release", id: "h7", from: "dave@pq23-oo34-ii45-uu56" }]);
    // Not for invites.
    expect(press(initialUi(), ch("2"), ch("t")).effects).toEqual([]);
  });

  it("accept and decline both confirm (a Codex release asks for its window's code instead)", () => {
    expect(press(initialUi(), ch("2"), ch("a")).effects).toEqual([]);
    expect(press(initialUi(), ch("2"), ch("a")).ui.modal).toMatchObject({ kind: "confirm", title: "Accept" });
    expect(press(initialUi(), ch("2"), ch("a"), ch("n")).effects).toEqual([]);
    expect(press(initialUi(), ch("2"), ch("a"), ch("y")).effects).toEqual([{ kind: "accept-item", id: "c1" }]);
    expect(press(initialUi(), ch("2"), k("down"), ch("a")).effects).toEqual([{ kind: "codex-release", id: "h7" }]);
    expect(press(initialUi(), ch("2"), ch("x")).effects).toEqual([]);
    expect(press(initialUi(), ch("2"), ch("x"), ch("y")).effects).toEqual([{ kind: "decline-item", id: "c1" }]);
  });

  it("a paste never acts as command keys, on any screen; it only types into a message", () => {
    const hostile = [..."aty1x2ty3q4m5rd"].map(pasted);
    for (const screen of ["1", "2", "3", "4", "5"]) {
      const start = press(initialUi(), ch(screen)).ui;
      const r = press(start, ...hostile, pasted("y"), pasted("y"));
      expect([screen, r.effects]).toEqual([screen, []]);
      expect(r.ui.screen).toBe(start.screen);
      expect(r.ui.modal).toBeUndefined();
    }
    // Nor does it answer a confirmation.
    const confirm = press(initialUi(), ch("2"), ch("x")).ui;
    expect(press(confirm, pasted("y")).effects).toEqual([]);
    expect(press(confirm, pasted("y")).ui.modal).toBeDefined();
    // Into a message it is text.
    const compose = press(initialUi(), ch("4"), k("return")).ui;
    const typed = press(compose, ...[..."hi there"].map(pasted));
    expect(typed.ui.compose?.text).toBe("hi there");
  });

  it("send: pick, type (q is text there), Enter sends; Esc cancels; Ctrl-C always quits", () => {
    const r = press(initialUi(), ch("4"), k("down"), k("return"), ...[..."quick q"].map((c) => (c === " " ? { name: "space", ch: " " } : ch(c))), k("return"));
    expect(r.effects).toEqual([{ kind: "send", to: "p2p:alice [d4e5f6]", label: expect.stringContaining("alice@"), text: "quick q" }]);
    expect(press(initialUi(), ch("4"), k("return"), ch("x"), k("escape"), k("return")).effects).toEqual([]);
    expect(press(initialUi(), ch("4"), k("return"), k("c", { ctrl: true })).effects).toEqual([{ kind: "quit" }]);
  });

  it("opening a received message sends no receipt (the TUI's session is private)", () => {
    const r = press(initialUi(), ch("3"), k("down"), k("down"), k("return"));
    expect(r.effects).toEqual([]);
    expect(r.ui.modal).toMatchObject({ kind: "detail" });
  });

  it("People: m messages the selected session; d runs the doctor for that person", () => {
    let r = press(initialUi(), k("down"), k("down"), k("down"), ch("m"));
    expect(r.ui).toMatchObject({ screen: "send", compose: { target: { to: "p2p:alice [d4e5f6]" } } });
    r = press(initialUi(), k("down"), k("down"), ch("d"));
    expect(r.effects).toEqual([{ kind: "doctor", user: "p2p:alice" }]);
  });
});

describe("frames", () => {
  const sizes: [number, number][] = [
    [80, 24],
    [120, 40],
  ];
  const screens = ["1", "2", "3", "4", "5"];
  for (const [cols, rows] of sizes) {
    for (const s of screens) {
      it(`screen ${s} at ${cols}x${rows}`, () => {
        const d = fixtureData();
        const ui = onKey(initialUi(), d, ch(s)).ui;
        const f = render(ui, d, cols, rows, NOW);
        const text = frameText(f);
        const lines = text.split("\n");
        expect(lines).toHaveLength(rows);
        for (const l of lines) expect(displayWidth(l)).toBe(cols);
        expect(text).not.toMatch(UNSAFE);
        // The only escape sequences in the output are the renderer's own.
        for (const color of [true, false]) expect(toAnsi(f, color).replace(OUR_ESCAPES, "").replace(/\r\n/g, "")).not.toMatch(UNSAFE);
        expect(text).toMatchSnapshot();
      });
    }
  }

  it("modals: help, confirm and a message's full text", () => {
    const d = fixtureData();
    const help = render({ ...initialUi(), modal: { kind: "help" } }, d, 80, 24, NOW);
    expect(frameText(help)).toMatchSnapshot();
    let ui = onKey(initialUi(), d, ch("2")).ui;
    ui = onKey(ui, d, k("down")).ui;
    ui = onKey(ui, d, ch("t")).ui;
    expect(frameText(render(ui, d, 80, 24, NOW))).toMatchSnapshot();
    ui = onKey(onKey(onKey(initialUi(), d, ch("3")).ui, d, k("end")).ui, d, k("return")).ui;
    const detail = frameText(render(ui, d, 80, 24, NOW));
    expect(detail).not.toMatch(UNSAFE);
    expect(detail).toContain("Can you look at the relay?");
  });

  it("a window too small says so", () => {
    expect(frameText(render(initialUi(), fixtureData(), 30, 8, NOW))).toContain("40x10 min");
  });
});

describe("bounds", () => {
  it("reads at most 64 KiB of a relay's well-known body", async () => {
    const big = new Response("x".repeat(WELL_KNOWN_MAX + 1)).body!;
    await expect(readCapped(big, WELL_KNOWN_MAX)).rejects.toThrow(/more than/);
    expect(await readCapped(new Response('{"access":"members"}').body!, WELL_KNOWN_MAX)).toBe('{"access":"members"}');
  });

  it("keeps at most 100 messages in memory, the newest", () => {
    const tui = new Tui({} as App, { term: new FakeTerminal(), version: "test", noWatch: true });
    for (let i = 0; i < 150; i++) tui.onEvent({ kind: "p2p.message", id: `m${i}`, at: NOW + i, from: { userId: "p2p:x", address: "x@aaaa-bbbb-cccc-dddd" }, text: `n${i}` });
    expect(tui.data.messages).toHaveLength(MESSAGES_MAX);
    expect(Math.min(...tui.data.messages.map((m) => m.at))).toBe(NOW + 50);
  });
});

describe("paste and answer edge cases (pre-release re-review)", () => {
  const clock = () => {
    const c = { t: 1_000_000, now: () => c.t };
    return c;
  };
  const joinRequest = () => {
    const d = fixtureData();
    d.held = [{ source: "item", id: "j1", type: "circle-join", from: "eve@abcd-efgh-ijkl-mnop", summary: "asks to join team", at: NOW }];
    return d;
  };
  const run = (d: ReturnType<typeof fixtureData>, keys: Key[]) => {
    let ui = onKey(initialUi(), d, ch("2")).ui;
    const effects: unknown[] = [];
    for (const key of keys) {
      const r = onKey(ui, d, key);
      ui = r.ui;
      if (r.effect) effects.push(r.effect);
    }
    return { ui, effects };
  };

  it("a fake end marker inside a paste can't press a or y on a join request", () => {
    const c = clock();
    const p = new KeyParser(c.now);
    const keys = p.feed("\u001b[200~hello \u001b[201~ay \u001b[201~");
    expect(keys.every((k) => k.paste)).toBe(true);
    const r = run(joinRequest(), keys);
    expect(r.effects).toEqual([]);
    expect(r.ui.modal).toBeUndefined();
    // The same keys a little later, typed for real: a asks to confirm, y admits.
    c.t += PASTE_QUIET_MS + 1;
    const typed = run(joinRequest(), [...p.feed("a"), ...p.feed("y")]);
    expect(typed.effects).toEqual([{ kind: "accept-item", id: "j1" }]);
  });

  it("a paste whose end never comes ends after a second of quiet; Ctrl-C always gets through", () => {
    const c = clock();
    const p = new KeyParser(c.now);
    expect(p.feed("\u001b[200~no end here")).toEqual([]);
    expect(p.waitMs).toBe(STUCK_MS);
    const ended = p.idle();
    expect(ended.map((k) => k.ch).join("")).toBe("no end here");
    expect(ended.every((k) => k.paste)).toBe(true);
    // Keys work again once the quiet window has passed.
    c.t += PASTE_QUIET_MS + 1;
    expect(p.feed("q")).toEqual([ch("q")]);
    // Ctrl-C mid-paste: the way out, and the paste is dropped.
    const q = new KeyParser(c.now);
    expect(q.feed("\u001b[200~stuck")).toEqual([]);
    expect(q.feed("more\u0003")).toEqual([k("c", { ctrl: true })]);
    expect(q.waitMs).toBe(0);
    // The rest of that read is dropped with the paste.
    expect(new KeyParser(c.now).feed("\u001b[200~x\u0003y")).toEqual([k("c", { ctrl: true })]);
    // Inside a terminal answer too.
    const a = new KeyParser(c.now);
    expect(a.feed("\u001b]11;rgb:")).toEqual([]);
    expect(a.feed("ff\u0003")).toEqual([k("c", { ctrl: true })]);
  });

  it("a terminal answer longer than 4096 bytes is dropped whole, its tail included", () => {
    const p = new KeyParser();
    expect(p.feed(`\u001b]52;c;${"A".repeat(5000)}`)).toEqual([]);
    expect(p.feed("B".repeat(3000))).toEqual([]);
    expect(p.feed("aty\u001b")).toEqual([]);
    expect(p.feed("\\q")).toEqual([ch("q")]);
    // One that never ends stops being discarded after a second of quiet.
    const s2 = new KeyParser();
    expect(s2.feed(`\u001bP${"x".repeat(6000)}`)).toEqual([]);
    expect(s2.waitMs).toBe(STUCK_MS);
    expect(s2.idle()).toEqual([]);
    expect(s2.feed("q")).toEqual([ch("q")]);
  });

  it("multi-byte characters split across reads stay whole", () => {
    const input = Object.assign(new EventEmitter(), { setRawMode: () => input, resume: () => input, pause: () => input });
    const output = Object.assign(new EventEmitter(), { columns: 80, rows: 24, isTTY: true, write: () => true, hasColors: () => false });
    const term = new TtyTerminal(input as never, output as never, {});
    const got: Key[] = [];
    term.onKey((key) => got.push(key));
    term.enter();
    const bytes = Buffer.from("é日😀", "utf8");
    // Cut inside each character: 2-byte é, 3-byte 日, 4-byte emoji.
    input.emit("data", bytes.subarray(0, 1));
    input.emit("data", bytes.subarray(1, 3));
    input.emit("data", bytes.subarray(3, 6));
    input.emit("data", bytes.subarray(6));
    term.leave();
    expect(got.map((key) => key.ch).join("")).toBe("é日😀");
    expect(got.every((key) => !key.name.includes("\ufffd"))).toBe(true);
  });
});

describe("Ctrl-C and split end markers (pre-release review)", () => {
  const CC = { name: "c", ctrl: true };
  const joinRequest = () => {
    const d = fixtureData();
    d.held = [{ source: "item" as const, id: "j1", type: "circle-join", from: "eve@abcd-efgh-ijkl-mnop", summary: "asks to join team", at: NOW }];
    return d;
  };

  it("Ctrl-C is never swallowed: after a lone ESC, inside a key's sequence, after a split one", () => {
    expect(new KeyParser().feed("\u001b\u0003")).toEqual([CC]);
    expect(new KeyParser().feed("\u001b[12\u0003")).toEqual([CC]);
    expect(new KeyParser().feed("\u001bO\u0003")).toEqual([CC]);
    const p = new KeyParser();
    expect(p.feed("\u001b")).toEqual([]);
    expect(p.feed("\u0003")).toEqual([CC]);
    const q = new KeyParser();
    expect(q.feed("\u001b[1;5")).toEqual([]);
    expect(q.feed("\u0003a")).toEqual([CC]);
  });

  it("Ctrl-C mid-paste quits; nothing after it in that read is a key, and nothing is dispatched after quit", async () => {
    const keys = new KeyParser().feed("\u001b[200~abc\u0003ay");
    expect(keys).toEqual([CC]);
    // The TUI on a join request: Ctrl-C then keys anyway (as a terminal might deliver them).
    const term = new FakeTerminal();
    const tui = new Tui({} as App, { term, version: "test", noWatch: true });
    Object.assign(tui.data, joinRequest(), { session: "tui" });
    tui.key({ name: "2", ch: "2" });
    for (const key of [...keys, { name: "a", ch: "a" }, { name: "y", ch: "y" }]) tui.key(key);
    await tui.done();
    expect(tui.ui.modal).toBeUndefined();
  });

  it("an end marker split across reads ends the paste, even when the paste began in the first read", () => {
    const p = new KeyParser();
    expect(p.feed("\u001b[200~ab \u001b[2")).toEqual([]);
    const keys = p.feed("01~y");
    expect(keys).toEqual(["a", "b", " ", "y"].map(pasted));
    // On a join request: no accept, no dialog.
    let ui = onKey(initialUi(), joinRequest(), ch("2")).ui;
    const effects: unknown[] = [];
    for (const key of keys) {
      const r = onKey(ui, joinRequest(), key);
      ui = r.ui;
      if (r.effect) effects.push(r.effect);
    }
    expect(effects).toEqual([]);
    expect(ui.modal).toBeUndefined();
    // Split right after ESC, and after ESC[20, too.
    for (const [a, b] of [["\u001b[200~xy\u001b", "[201~"], ["\u001b[200~xy\u001b[20", "1~"]]) {
      const r = new KeyParser();
      expect(r.feed(a)).toEqual([]);
      expect(r.feed(b)).toEqual(["x", "y"].map(pasted));
      expect(r.waitMs).toBe(0);
    }
  });
});
