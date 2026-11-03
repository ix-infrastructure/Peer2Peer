// Copyright 2026 Ix Infrastructure Inc.
//
// The interactive CLI: the picker (keys -> selection) on a fake terminal, the
// commands that pick a missing argument, the laid-out output on a terminal,
// and parity everywhere else: piped, --json, --no-input or CI, every command
// behaves (output and exit code) exactly as before, and nothing is ever
// picked from piped input.

import { EventEmitter } from "node:events";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Io } from "../app.js";
import { main } from "../cli.js";
import { initialState, reduce, render, PLAIN, COLOR, type SelectSpec } from "../prompt/picker.js";
import { runPicker } from "../prompt/tty.js";
import { safePretty, prettyCircles } from "../pretty.js";
import { colorWanted, parseKeys } from "../tui/terminal.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const UP = "\u001b[A";
const DOWN = "\u001b[B";
const ESC = "\u001b";

/** A fake terminal: one scripted key chunk after each full draw of the picker (its hint line). */
function scripted(keys: string[], cols = 100) {
  const input = new EventEmitter() as EventEmitter & { isTTY: boolean; setRawMode(on: boolean): void; resume(): void; pause(): void };
  const raw: boolean[] = [];
  input.isTTY = true;
  input.setRawMode = (on) => void raw.push(on);
  input.resume = () => {};
  input.pause = () => {};
  const written: string[] = [];
  let i = 0;
  const output = {
    columns: cols,
    rows: 30,
    write: (s: string) => {
      written.push(s);
      if (/esc cancel/.test(s) && i < keys.length) {
        const k = keys[i++];
        setImmediate(() => input.emit("data", Buffer.from(k)));
      }
    },
  };
  return { input, output, written, raw, select: (spec: SelectSpec) => runPicker(spec, input, output, { color: false }), left: () => keys.length - i };
}

const keys = (s: SelectSpec, ...chunks: string[]) => {
  let st = initialState(s);
  for (const c of chunks) for (const k of parseKeys(c)) st = reduce(st, k);
  return st;
};

describe("the picker (model)", () => {
  const spec: SelectSpec = {
    message: "Which?",
    multi: true,
    max: 2,
    choices: [
      { value: "", label: "Friend only", exclusive: true },
      { value: "a", label: "alpha", checked: true },
      { value: "b", label: "beta" },
      { value: "c", label: "gamma", disabled: "open" },
      { value: "d", label: "delta" },
    ],
  };

  it("arrows and j/k move, space toggles, enter confirms; the default is pre-checked", () => {
    expect(keys(spec, "\r").done).toEqual(["a"]);
    expect(keys(spec, DOWN, DOWN, " ", "\r").done).toEqual(["a", "b"]);
    expect(keys(spec, "j", "j", " ", "k", " ", "\r").done).toEqual(["b"]);
    expect(keys(spec, " ", "\r").done).toEqual([""]); // the exclusive choice clears the others
    expect(keys(spec, UP, " ", "\r").done).toEqual(["a", "d"]); // up from the top wraps to the last
  });

  it("a disabled choice can't be chosen; at most `max`; esc and Ctrl-C cancel", () => {
    const s = keys(spec, DOWN, DOWN, DOWN, " ");
    expect(s.checked).toEqual(["a"]);
    expect(s.note).toBe("open");
    expect(keys(spec, DOWN, DOWN, " ", DOWN, DOWN, " ").note).toBe("at most 2");
    expect(keys(spec, ESC).done).toBeNull();
    expect(keys(spec, "\u0003").done).toBeNull();
  });

  it("typing filters (j and k too, once a filter is typed); esc clears the filter first", () => {
    const s = keys(spec, "del");
    expect(s.filter).toBe("del");
    expect(keys(spec, "del", " ", "\r").done).toEqual(["a", "d"]);
    expect(keys(spec, "gam", ESC).filter).toBe("");
    expect(keys(spec, "gam", ESC).done).toBeUndefined();
  });

  it("pasted text only filters: a paste can't move, toggle or confirm", () => {
    const s = keys(spec, "\u001b[200~ \r\n j\r\u001b[201~");
    expect(s.done).toBeUndefined();
    expect(s.checked).toEqual(["a"]);
  });

  it("a malicious name is sanitised on its way to the terminal", () => {
    const evil: SelectSpec = { message: "Pick\u001b[2J", choices: [{ value: "x", label: "evil\u001b]0;pwned\u0007\u202e\u200bname\u001b[31m", detail: "\u001b[8m3 members\r\nfake line" }] };
    for (const style of [PLAIN, COLOR]) {
      const out = render(initialState(evil), { cols: 80, rows: 24, style }).join("\n");
      expect(out).not.toMatch(/\u001b\]|\u0007|\u202e|\u200b|\u001b\[2J|\u001b\[8m|\u001b\[31m|\r/);
      expect(out).toContain("evilname");
      // Only our own SGR codes remain.
      expect(out.replace(/\u001b\[[0-9;]*m/g, "")).not.toMatch(/\u001b/);
    }
  });
});

describe("the picker on a (fake) terminal", () => {
  it("keys in, selection out; raw mode on, then restored, and the cursor shown again", async () => {
    const t = scripted([DOWN, " ", DOWN, " ", "\r"]);
    const r = await t.select({ message: "Pick", multi: true, choices: [{ value: "1", label: "one" }, { value: "2", label: "two" }, { value: "3", label: "three" }] });
    expect(r).toEqual(["2", "3"]);
    expect(t.raw).toEqual([true, false]);
    const all = t.written.join("");
    expect(all).toContain("\u001b[?25l");
    expect(all.endsWith("\u001b[0m\u001b[?25h")).toBe(true);
    expect(all).toContain("? Pick two, three");
  });

  it("Ctrl-C cancels cleanly (undefined), with the terminal restored", async () => {
    const t = scripted(["\u0003"]);
    expect(await t.select({ message: "Pick", choices: [{ value: "1", label: "one" }] })).toBeUndefined();
    expect(t.raw).toEqual([true, false]);
    expect(t.written.join("")).toContain("cancelled");
  });

  it("SIGTERM, SIGHUP or SIGINT from outside: the terminal is restored first, then the signal is raised again", async () => {
    for (const sig of ["SIGTERM", "SIGHUP", "SIGINT"] as const) {
      const handlers = new Map<string, () => void>();
      const raised: string[] = [];
      const signals = { on: (s: NodeJS.Signals, fn: () => void) => void handlers.set(s, fn), off: (s: NodeJS.Signals) => void handlers.delete(s), raise: (s: NodeJS.Signals) => void raised.push(s) };
      const t = scripted([]);
      const done = runPicker({ message: "Pick", choices: [{ value: "1", label: "one" }] }, t.input, t.output, { color: false, signals });
      expect([...handlers.keys()].sort()).toEqual(["SIGHUP", "SIGINT", "SIGTERM"]);
      handlers.get(sig)!();
      expect(await done).toBeUndefined();
      expect(t.raw).toEqual([true, false]);
      expect(t.written.join("").endsWith("\u001b[0m\u001b[?25h")).toBe(true);
      expect(raised).toEqual([sig]);
      // Its handlers are gone: nothing else of the picker runs.
      expect(handlers.size).toBe(0);
    }
  });
});

describe("colour", () => {
  it("NO_COLOR and TERM=dumb turn it off, FORCE_COLOR on; without colour nothing but text is written", () => {
    const tty = { isTTY: true, hasColors: () => true };
    expect(colorWanted({}, tty)).toBe(true);
    expect(colorWanted({ NO_COLOR: "1" }, tty)).toBe(false);
    expect(colorWanted({ TERM: "dumb" }, tty)).toBe(false);
    expect(colorWanted({ FORCE_COLOR: "1" }, { isTTY: false })).toBe(true);
    const rows = [{ cid: "c_x", name: "team", ver: 1, policy: "invite" as const, owner: "p2p:o", ownerAddress: "ann@aaaa-bbbb-cccc-dddd", role: "owner" as const, joined: true, members: 2, standing: 2, isDefault: true }];
    expect(prettyCircles(rows, { color: false, cols: 100 })).not.toMatch(/\u001b/);
    expect(prettyCircles(rows, { color: true, cols: 100 })).toMatch(/\u001b\[1m/);
    expect(safePretty("a\u001b]0;x\u0007b\u001b[31mc\u001b[39m")).toBe("a]0;xb\u001b[31mc\u001b[39m");
  });
});

describe("commands", () => {
  const R = "wss://relay-interactive.test/v3";
  let relay: TestRelay;
  let alice: User;
  let team: string;
  let ops: string;
  let lobby: string;
  let tr: Record<string, string>;
  const users: User[] = [];

  async function runWith(u: User, argv: string[], extra: Partial<Io> = {}) {
    const lines = { out: [] as string[], err: [] as string[] };
    const code = await main(argv, { env: u.env, io: { out: (s) => lines.out.push(s), err: (s) => lines.err.push(s), ...extra } });
    process.exitCode = 0;
    return { code, out: lines.out.join("\n"), err: lines.err.join("\n") };
  }

  beforeAll(async () => {
    relay = await startRelay(R);
    tr = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    alice = new User("alice", tr, { P2P_DEFAULT_RELAYS: R });
    users.push(alice);
    await alice.ok(["setup", "--name", "alice", "--no-backup"]);
    team = (await alice.ok(["circle", "create", "team"])).cid;
    ops = (await alice.ok(["circle", "create", "ops"])).cid;
    lobby = (await alice.ok(["circle", "create", "lob\u001b]0;pwned\u0007by", "--open"])).cid;
    await alice.ok(["circle", "default", team]);
  }, 60_000);
  afterAll(async () => {
    await relay?.close();
    for (const u of users) u.cleanup();
  });

  it("p2p invite noah: pick circles (the default pre-checked, open ones unavailable), then the expiry; the link is printed nicely", async () => {
    // Choices: friend only, then the circles in list order. Move to "ops", select it, confirm; then 3 days.
    const order = (await alice.ok(["circle", "ls"])).circles.filter((c: { role: string }) => c.role === "owner").map((c: { cid: string }) => c.cid);
    const toOps = order.indexOf(ops) + 1;
    const t = scripted([...Array(toOps).fill(DOWN), " ", "\r", DOWN, "\r"]);
    const r = await runWith(alice, ["invite", "noah"], { select: t.select, pretty: { color: false, cols: 100 } });
    expect(r.code, r.err).toBe(0);
    const screen = t.written.join("");
    expect(screen).toContain("What should the invite for noah join?");
    expect(screen).toMatch(/\[x\] team/);
    expect(screen).toMatch(/lob]0;pwnedby.*unavailable: open/);
    expect(screen).not.toMatch(/\u001b\]0;pwned/);
    expect(r.out).toMatch(/^Your invite for noah/);
    expect(r.out).toMatch(/https:\/\/ix-infra\.com\/p2p\/invite#/);
    expect(r.out).toContain("or the code: ");
    // The picked 3 days says 3 days (rounded up, not "2d" a few seconds later).
    expect(r.out).toMatch(/works once, for 3 days/);
    // The inline hint and the message use the web link; the message says how to install.
    expect(r.out).toMatch(/\(p2p join 'https:\/\/ix-infra\.com\/p2p\/invite#[^']+'\)/);
    expect(r.out).toContain("Send them this message");
    expect(r.out).toContain("/plugin marketplace add ix-infrastructure/Peer2Peer");
    expect(r.out).not.toContain("npx");
    expect(r.out).toContain("Send it over a channel you trust");
    const inv = (await alice.ok(["invites"])).invites[0];
    expect(inv.circles.map((c: { cid: string }) => c.cid).sort()).toEqual([team, ops].sort());
    expect(inv.exp - Date.now() / 1000).toBeLessThan(3 * 86_400 + 60);
    expect(lobby).toBeTruthy();
  }, 60_000);

  it("Esc cancels a picker: nothing is made, exit 1", async () => {
    const before = (await alice.ok(["invites"])).invites.length;
    const t = scripted([ESC]);
    const r = await runWith(alice, ["invite"], { select: t.select });
    expect(r.code).toBe(1);
    expect(r.err).toContain("cancelled");
    expect((await alice.ok(["invites"])).invites.length).toBe(before);
  });

  it("a missing argument is picked: circle members, circle default, circle leave (listed)", async () => {
    const order = (await alice.ok(["circle", "ls"])).circles.map((c: { cid: string }) => c.cid);
    const t = scripted([...Array(order.indexOf(ops)).fill(DOWN), "\r"]);
    const r = await runWith(alice, ["circle", "default"], { select: t.select });
    expect(r.code, r.err).toBe(0);
    expect((await alice.ok(["whoami"])).defaultCircle).toBe(ops);
    await alice.ok(["circle", "default", team]);
  });

  it("piped (no picker), --json, --no-input: the same commander errors and exit codes as before; nothing is picked", async () => {
    const t = scripted(["\r", "\r", "\r"]);
    for (const [argv, extra] of [
      [["circle", "leave"], {}],
      [["held", "approve"], {}],
      [["remove"], {}],
      [["circle", "leave", "--json"], { select: t.select }],
      [["--no-input", "held", "decline"], { select: t.select }],
    ] as [string[], Partial<Io>][]) {
      const r = await runWith(alice, argv, extra);
      expect(r.code, argv.join(" ")).toBe(1);
      expect(r.err).toMatch(/error: missing required argument '(cid|id|user)'/);
    }
    const s = await runWith(alice, ["send", "hi"], {});
    expect(s.code).toBe(1);
    expect(s.err).toContain("error: required option '--from-session <sid>' not specified");
    // The scripted keys were never read: no picker opened.
    expect(t.left()).toBe(3);
    // `p2p invite` piped: a code for the default circle, as before, no question.
    const inv = await runWith(alice, ["invite", "--json"], { select: t.select });
    expect(inv.code).toBe(0);
    expect(JSON.parse(inv.out).circles.map((c: { cid: string }) => c.cid)).toEqual([team]);
    expect(t.left()).toBe(3);
  }, 60_000);

  it("trust add picks a friend and still takes their fingerprint typed; held decline picks from the list", async () => {
    const bob = new User("bob", tr, { P2P_DEFAULT_RELAYS: R });
    users.push(bob);
    await bob.ok(["setup", "--name", "bob", "--no-backup"]);
    const code = (await alice.ok(["invite", "--no-circle"])).code;
    await bob.ok(["join", "--yes", code, "--wait", "1"]);
    const bobWho = await bob.ok(["whoami"]);
    for (let i = 0; i < 10 && !(await alice.ok(["friends"])).friends.length; i++) await bob.ok(["friends"]);
    const fp = bobWho.address.split("@")[1] as string;
    // A wrong fingerprint: nobody is trusted.
    const wrong = await runWith(alice, ["trust", "add"], { select: scripted(["\r"]).select, prompt: async () => "aaaa-aaaa-aaaa-aaaa" });
    expect(wrong.code).toBe(1);
    expect(wrong.err).toContain("doesn't match");
    expect((await alice.ok(["trust", "ls"])).users).toEqual([]);
    const pick = scripted(["\r"]);
    let asked = "";
    const right = await runWith(alice, ["trust", "add"], { select: pick.select, prompt: async (q) => ((asked = q), fp.toUpperCase()) });
    expect(right.code, right.err).toBe(0);
    // The list names people only: the fingerprint is what the person types, from what they got out of band.
    expect(pick.written.join("")).toMatch(/> \( \) bob|> \(\*\) bob/);
    expect(pick.written.join("").toLowerCase()).not.toContain(fp.toLowerCase());
    expect(asked.toLowerCase()).not.toContain(fp.toLowerCase());
    // The typed form works as before.
    await alice.ok(["trust", "remove", bobWho.userId]);
    expect((await alice.run(["trust", "add", bobWho.address])).code).toBe(0);
    expect((await alice.ok(["trust", "ls"])).users.map((u: { userId: string }) => u.userId)).toEqual([bobWho.userId]);

    // send on a terminal without --from-session: the recipient picked, the text asked, and where it was sent from said.
    // A send that fails shares nothing: the share made for it is undone.
    const failed = await runWith(alice, ["send"], { select: scripted(["bob", "\r"]).select, prompt: async () => "x".repeat(30 * 1024) });
    expect(failed.code).toBe(1);
    expect(failed.err).toContain("too_large");
    expect(failed.out).not.toContain("shared session tui");
    expect((await alice.ok(["session", "roster", "tui"])).roster.parts.map((x: { userId: string }) => x.userId)).not.toContain(bobWho.userId);
    // No `session roster` step: picking the recipient shares the tui session with them, and says so.
    const sent = await runWith(alice, ["send"], { select: scripted(["bob", "\r"]).select, prompt: async () => "hello bob" });
    expect(sent.code, sent.err).toBe(0);
    expect(sent.out).toMatch(/^shared session tui with bob@[a-z2-7-]+\nSent to bob@/);
    expect((await alice.ok(["session", "roster", "tui"])).roster.parts.map((x: { userId: string }) => x.userId)).toContain(bobWho.userId);
    // Again: already shared, so nothing more is said.
    const again = await runWith(alice, ["send", "--to", bobWho.address, "hi again"], { select: scripted([]).select });
    expect(again.code, again.err).toBe(0);
    expect(again.out).toMatch(/^Sent to bob@/);
    // With --from-session (or off a terminal) nothing is shared for you: the old refusal stands.
    const named = await runWith(alice, ["send", "--from-session", "s-other", "--to", bobWho.address, "x"], { select: scripted([]).select });
    expect(named.code).toBe(1);
    expect(named.err).toContain("not_shared");
    const piped = await runWith(alice, ["send", "--from-session", "s-other", "--to", bobWho.address, "x"]);
    expect(piped.code).toBe(1);
    expect(piped.err).toContain("not_shared");
    expect(sent.out.split("\n").at(-1)).toBe("sent from session tui; replies show in `p2p tui`");

    await alice.ok(["circle", "invite", team, bobWho.userId]);
    let held: { id: string }[] = [];
    for (let i = 0; i < 10 && !held.length; i++) held = (await bob.ok(["held"])).held;
    const d = await runWith(bob, ["held", "decline"], { select: scripted(["\r"]).select });
    expect(d.code, d.err).toBe(0);
    expect(d.out).toContain(`Declined ${held[0].id}`);
  }, 90_000);

  it("plain text when stdout isn't a terminal; laid out (no colour with NO_COLOR) when it is", async () => {
    const plain = await runWith(alice, ["circle", "ls"]);
    expect(plain.out.split("\n")[0]).toMatch(/^CIRCLE\s+NAME\s+ROLE/);
    const laid = await runWith(alice, ["circle", "ls"], { pretty: { color: false, cols: 100 } });
    expect(laid.out.split("\n")[0]).toMatch(/^Circles \(\d+\)/);
    expect(laid.out).not.toMatch(/\u001b/);
    expect(laid.out).toContain("team (default)");
    // The malicious circle name, sanitised.
    expect(laid.out).not.toMatch(/\u0007|\u001b\]/);
  });

  it("p2p alone on a terminal: the home screen; piped: the help, as before", async () => {
    const home = await runWith(alice, [], { pretty: { color: false, cols: 100 } });
    expect(home.code).toBe(0);
    expect(home.out).toMatch(/You are alice@/);
    expect(home.out).toContain("relays");
    expect(home.out).toContain("p2p invite");
    const help = await runWith(alice, []);
    expect(help.out + help.err).toMatch(/Usage: p2p/);
  }, 30_000);
});
