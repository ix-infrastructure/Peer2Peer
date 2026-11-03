// Copyright 2026 Ix Infrastructure Inc.
// `p2p tui` end to end over a local relay: the TUI (a fake terminal, real
// app, real in-process watch) sees a friend's live session, sends it a message
// on key presses, gets the reply live, and restores the terminal on Ctrl-C.
// Then, when a pty is available (`script`), the built CLI in a real pty:
// alternate screen in, q, alternate screen out; and refused without one.

import { execFileSync, spawn } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { main } from "../../cli.js";
import { alongside, startRelay, User, type TestRelay } from "../../__tests__/harness.js";
import { Tui } from "../tui.js";
import { FakeTerminal } from "./fixtures.js";

const R = "wss://tui-relay.test/v3";
let relay: TestRelay;
let alice: User;
let bob: User;
let aliceId = "";
let bobId = "";

async function until(what: string, f: () => boolean | Promise<boolean>, ms = 15_000): Promise<void> {
  const t0 = Date.now();
  while (!(await f())) {
    if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

beforeAll(async () => {
  relay = await startRelay(R);
  const t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
  alice = new User("alice", t, { P2P_DEFAULT_RELAYS: R });
  bob = new User("bob", t, { P2P_DEFAULT_RELAYS: R });
  aliceId = (await alice.ok(["setup", "--name", "alice", "--no-backup"])).userId;
  bobId = (await bob.ok(["setup", "--name", "bob", "--no-backup"])).userId;
  const inv = await alice.ok(["invite", "--no-circle"]);
  const j = await alongside(bob.run(["join", "--confirmed", inv.code, "--wait", "5"]), () => alice.ok(["friends"]));
  expect(j.code).toBe(0);
  await alice.ok(["friends"]);
  await bob.ok(["session", "roster", "bs1", "--add", aliceId]);
  await bob.ok(["status", "--session", "bs1", "--state", "idle", "--label", "work", "--summary", "fixing \u001b[31mthe\u001b[0m relay"]);
}, 90_000);

afterAll(async () => {
  await relay?.close();
  alice?.cleanup();
  bob?.cleanup();
});

describe("p2p tui over a relay", () => {
  it("live people, send on key presses, a live reply, clean exit", async () => {
    const term = new FakeTerminal(100, 30);
    const app = await alice.app();
    await app.load();
    const logs: string[] = [];
    const tui = new Tui(app, { term, version: "test", log: (m) => logs.push(m) });
    const running = tui.run();
    await until("bob's session on People", () => term.text.includes("bob@") && term.text.includes("work"));
    // Upstream sanitizing already dropped the ESC bytes; what's left is inert text, never an escape.
    expect(term.text).toContain("fixing");
    expect(term.frames.at(-1)).not.toContain("\u001b[31mthe");
    expect(term.entered).toBe(1);

    // Send: screen 4, pick bob's session, type, Enter.
    term.type("4");
    await until("the send screen", () => term.text.includes("Pick who to message"));
    const targets = tui.data.people.flatMap((p) => p.sessions.map((s) => `${p.address} [${s.ref}]`));
    expect(targets.some((t) => t.startsWith("bob@"))).toBe(true);
    term.press({ name: "return" });
    term.type("hello from the tui");
    term.press({ name: "return" });
    await until("the send", () => term.text.includes("Sent to bob@") || term.text.includes("Queued for bob@"), 20_000);

    const lines = await bob.watch("bs1", 4000);
    expect(lines.some((l) => l.kind === "p2p.message" && l.text === "hello from the tui")).toBe(true);

    // Bob replies into his session; it reaches the TUI's session live.
    await bob.ok(["send", "--from-session", "bs1", "--to", aliceId, "got it, thanks"]);
    term.type("3");
    await until("the reply on Messages", () => term.text.includes("got it, thanks"), 20_000);
    expect(term.text).toContain("hello from the tui");

    term.press({ name: "c", ctrl: true });
    await running;
    expect(term.left).toBe(1);
    void bobId;
  }, 90_000);

  it("a send to someone this session isn't shared with shares it with them, and says so (as p2p send on a terminal)", async () => {
    // carol: a friend of alice with no live session, so a message to her lands in alice's own session.
    const carol = new User("carol", { [R]: `ws://127.0.0.1:${relay.port}/v3` }, { P2P_DEFAULT_RELAYS: R });
    try {
      const carolId = (await carol.ok(["setup", "--name", "carol", "--no-backup"])).userId as string;
      const inv = await alice.ok(["invite", "--no-circle"]);
      await alongside(carol.run(["join", "--confirmed", inv.code, "--wait", "5"]), () => alice.ok(["friends"]));
      await until("alice and carol are friends", async () => (await alice.ok(["friends"])).friends.some((f: { userId: string }) => f.userId === carolId), 20_000);
      expect((await alice.ok(["session", "roster", "tui"])).roster.parts.map((x: { userId: string }) => x.userId)).not.toContain(carolId);
      const term = new FakeTerminal(110, 30);
      const app = await alice.app();
      await app.load();
      const tui = new Tui(app, { term, version: "test", log: () => {}, noWatch: true });
      const running = tui.run();
      await until("carol on People", () => term.text.includes("carol@"));
      term.type("4");
      await until("the send screen", () => term.text.includes("Pick who to message"));
      const { sendTargets } = await import("../model.js");
      const at = sendTargets(tui.data).findIndex((x) => x.to === carolId);
      expect(at).toBeGreaterThanOrEqual(0);
      for (let i = 0; i < at; i++) term.press({ name: "down" });
      term.press({ name: "return" });
      term.type("hi carol");
      term.press({ name: "return" });
      await until("the send", () => /Shared session tui with carol@/.test(term.text), 20_000);
      expect(term.text).toMatch(/(Sent to|Queued for) carol@/);
      term.press({ name: "c", ctrl: true });
      await running;
      expect((await alice.ok(["session", "roster", "tui"])).roster.parts.map((x: { userId: string }) => x.userId)).toContain(carolId);
    } finally {
      carol.cleanup();
    }
  }, 90_000);

  it("refuses without a terminal", async () => {
    const err: string[] = [];
    const code = await main(["tui"], { env: alice.env, io: { out: () => {}, err: (s) => err.push(s) }, isTTY: false });
    expect(code).toBe(1);
    expect(err.join("\n")).toMatch(/needs an interactive terminal/);
    const code2 = await main(["tui"], { env: { ...alice.env, CLAUDECODE: "1" }, io: { out: () => {}, err: (s) => err.push(s) }, isTTY: true });
    expect(code2).toBe(1);
    expect(err.join("\n")).toMatch(/your own terminal/);
  });

  // A real pty, when this machine has `script` and the CLI is built from this source.
  const here = dirname(fileURLToPath(import.meta.url));
  const bin = join(here, "../../../dist/bin.js");
  const built = existsSync(bin) && existsSync(join(here, "../../../dist/tui/tui.js")) && statSync(join(here, "../../../dist/tui/tui.js")).mtimeMs >= statSync(join(here, "../tui.ts")).mtimeMs;
  let script = "";
  try {
    script = execFileSync("sh", ["-c", "command -v script"], { encoding: "utf8" }).trim();
  } catch {
    script = "";
  }
  const ptyOk = built && script !== "" && process.platform !== "win32";
  it.skipIf(!ptyOk)("in a real pty: alternate screen in, q quits, terminal restored", async () => {
    // `script` wants a real pipe on stdin (node's are sockets on macOS): `cat |` gives it one.
    const q = (s: string) => `'${s.replace(/'/g, "'\\''")}'`;
    const inner = process.platform === "darwin" ? `${q(script)} -q /dev/null ${q(process.execPath)} ${q(bin)} tui` : `${q(script)} -qec ${q(`${q(process.execPath)} ${q(bin)} tui`)} /dev/null`;
    const child = spawn("sh", ["-c", `cat | ${inner}`], { env: { ...alice.env, PATH: "/usr/bin:/bin", TERM: "xterm-256color", NO_COLOR: "1" }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (b: Buffer) => (out += b.toString("utf8")));
    let errOut = "";
    let exited: number | null | undefined;
    child.stderr.on("data", (b: Buffer) => (errOut += b.toString("utf8")));
    child.on("exit", (c) => (exited = c));
    await until("the first frame", () => out.includes("Peer2Peer") && out.includes("People"), 20_000).catch((e) => {
      throw new Error(`${(e as Error).message}: ${JSON.stringify(out.slice(0, 400))} ${JSON.stringify(errOut.slice(0, 400))} exit ${String(exited)}`);
    });
    expect(out).toContain("\u001b[?1049h");
    child.stdin.write("q");
    await until("the TUI to quit", () => out.includes("\u001b[?1049l"), 20_000).catch((e) => {
      throw new Error(`${(e as Error).message}: ${JSON.stringify(out.slice(-300))} ${JSON.stringify(errOut.slice(0, 300))}`);
    });
    child.stdin.end();
    const code = exited !== undefined ? exited : await new Promise<number | null>((r) => child.on("exit", (c) => r(c)));
    expect(out).toContain("\u001b[?1049l");
    expect(out).toContain("\u001b[?25h");
    expect(code).toBe(0);
  }, 40_000);
});
