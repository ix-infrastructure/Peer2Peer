// Copyright 2026 Ix Infrastructure Inc.
//
// Ix is optional and recommended; Peer2Peer never installs it. `p2p setup` at a person's terminal
// explains it and asks "Install Ix? [y/N]" (default No): a yes prints the command for the person to
// run, a no is remembered (config.json ixDeclined) and not asked again until `p2p setup --ix`.
// --json, CI, no terminal, and an agent's session never prompt; JSON says what to run instead.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { App, Io } from "../app.js";
import { main } from "../cli.js";
import { ciEnv, ixAdvice, ixInstallCommands, ixInstallLine, setupIx } from "../ix-local.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-ix-optional.test/v3";

describe("Ix advice (pure)", () => {
  it("install commands per platform, from the Ix README; never run", () => {
    expect(ixInstallCommands("linux", "x64")).toEqual(["curl -fsSL https://ix-infra.com/install.sh | sh"]);
    expect(ixInstallCommands("darwin", "arm64")).toEqual(["curl -fsSL https://ix-infra.com/install.sh | sh"]);
    expect(ixInstallCommands("win32", "x64")).toEqual(["irm https://ix-infra.com/install.ps1 | iex"]);
    expect(ixInstallLine("darwin", "x64")).toBe("brew tap ix-infrastructure/ix https://github.com/ix-infrastructure/Ix && brew install ix");
  });

  it("recommended when Ix isn't found and the person hasn't said no; --ix (reoffer) asks again", () => {
    const env = { PATH: "/nonexistent-p2p-test" };
    expect(ixAdvice(env, {})).toMatchObject({ installed: false, declined: false, recommended: true, install: ixInstallLine() });
    expect(ixAdvice(env, { ixDeclined: true })).toMatchObject({ installed: false, declined: true, recommended: false });
    expect(ixAdvice(env, { ixDeclined: true }, { reoffer: true })).toMatchObject({ declined: false, recommended: true });
  });

  it("CI: set means set, except empty, 0 and false", () => {
    expect(ciEnv({ CI: "1" })).toBe(true);
    expect(ciEnv({ CI: "true" })).toBe(true);
    for (const v of [undefined, "", "0", "false", "FALSE"]) expect(ciEnv({ CI: v })).toBe(false);
  });

  it("setupIx without Ix: says what to run, enables nothing; declined: says how to ask again", async () => {
    // The person (their front end's token); an agent (its environment, no token).
    const app = (file: Record<string, unknown>, agent = false) =>
      ({ env: { PATH: "/nonexistent-p2p-test", ...(agent ? { CLAUDECODE: "1" } : {}) }, file, home: "/nonexistent-p2p-home", front: !agent }) as unknown as App;
    expect(await setupIx(app({}), true)).toMatchObject({ found: false, installed: false, recommended: true, enabled: false, install: ixInstallLine(), hint: expect.stringContaining("never installs it") });
    // Read by an agent: ask the user, never "run it yourself".
    const agentHint = (await setupIx(app({}, true), true)).hint ?? "";
    expect(agentHint).toContain("ask your user");
    expect(agentHint).toContain("in their own terminal");
    expect(agentHint).not.toContain("yourself (");
    const declined = await setupIx(app({ ixDeclined: true }), true);
    expect(declined).toMatchObject({ recommended: false, declined: true, enabled: false, hint: expect.stringContaining("p2p setup --ix") });
  });
});

describe("p2p setup: the Ix offer", () => {
  let relay: TestRelay;
  let tr: Record<string, string>;
  const users: User[] = [];
  beforeAll(async () => {
    relay = await startRelay(R);
    tr = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
  }, 30_000);
  afterAll(async () => {
    await relay?.close();
    for (const u of users) u.cleanup();
  });
  const user = (name: string, env: Record<string, string> = {}) => {
    const u = new User(name, tr, { P2P_DEFAULT_RELAYS: R, PATH: "/nonexistent-p2p-test", ...env });
    users.push(u);
    return u;
  };
  /** Runs `p2p <argv>` with a terminal whose answers are `answers` (each prompt takes the next). */
  async function runAt(env: Record<string, string | undefined>, argv: string[], answers: string[] | null) {
    const lines = { out: [] as string[], err: [] as string[] };
    const asked: string[] = [];
    const io: Io = {
      out: (s) => lines.out.push(s),
      err: (s) => lines.err.push(s),
      ...(answers ? { prompt: async (q: string) => (asked.push(q), answers.shift() ?? "") } : {}),
    };
    const code = await main(argv, { env, io });
    process.exitCode = 0;
    return { code, out: lines.out.join("\n"), err: lines.err.join("\n"), asked };
  }
  const config = (u: User) => (existsSync(join(u.home, "config.json")) ? JSON.parse(readFileSync(join(u.home, "config.json"), "utf8")) : {});

  it("explains Ix and asks, default No: Enter declines, is remembered, and isn't asked again", async () => {
    const u = user("ixno");
    const r = await runAt(u.env, ["setup", "--name", "ixno", "--no-backup"], [""]);
    expect(r.code, r.err).toBe(0);
    expect(r.asked).toHaveLength(1);
    expect(r.asked[0]).toMatch(/Install Ix\? \[y\/N\] $/);
    expect(r.asked[0]).toContain("optional, recommended");
    expect(r.asked[0]).toContain("never installs it for you");
    expect(r.out).toContain("You won't be asked again");
    expect(config(u).ixDeclined).toBe(true);
    expect(config(u).extensions).toBeUndefined();
    const again = await runAt(u.env, ["setup"], ["y"]);
    expect(again.code, again.err).toBe(0);
    expect(again.asked).toEqual([]);
    expect(again.out).toContain("p2p setup --ix");
    // --ix offers it again.
    const re = await runAt(u.env, ["setup", "--ix"], ["n"]);
    expect(re.asked).toHaveLength(1);
    expect(config(u).ixDeclined).toBe(true);
  });

  it("a yes prints the command for the person to run; nothing is installed or enabled", async () => {
    const u = user("ixyes");
    const r = await runAt(u.env, ["setup", "--name", "ixyes", "--no-backup"], ["y"]);
    expect(r.code, r.err).toBe(0);
    expect(r.asked).toHaveLength(1);
    expect(r.out).toContain("Peer2Peer doesn't run installers");
    for (const c of ixInstallCommands()) expect(r.out).toContain(c);
    expect(r.out).toContain("p2p setup --ix");
    expect(config(u).ixDeclined).toBeUndefined();
    expect(config(u).extensions).toBeUndefined();
    // Still not installed: asked again next time (no "no" was given).
    expect((await runAt(u.env, ["setup"], [""])).asked).toHaveLength(1);
  });

  it("--json never prompts: the JSON says Ix is recommended and what to run", async () => {
    const u = user("ixjson");
    const r = await runAt(u.env, ["setup", "--name", "ixjson", "--no-backup", "--json"], ["y"]);
    expect(r.code, r.err).toBe(0);
    expect(r.asked).toEqual([]);
    const j = JSON.parse(r.out.split("\n").at(-1) ?? "{}");
    expect(j.ix).toMatchObject({ installed: false, recommended: true, enabled: false, install: ixInstallLine() });
    expect(config(u).ixDeclined).toBeUndefined();
    // And `p2p extensions --json` carries the same advice for front ends.
    const ext = await runAt(u.env, ["extensions", "--json"], null);
    expect(JSON.parse(ext.out.split("\n").at(-1) ?? "{}").ix).toEqual({ installed: false, declined: false, recommended: true, install: ixInstallLine() });
  });

  it("CI=1, or no terminal: never prompts, never installs; the hint says what to run", async () => {
    const ci = user("ixci", { CI: "1" });
    const r = await runAt(ci.env, ["setup", "--name", "ixci", "--no-backup"], ["y"]);
    expect(r.code, r.err).toBe(0);
    expect(r.asked).toEqual([]);
    expect(r.out).toContain(ixInstallLine());
    expect(config(ci).ixDeclined).toBeUndefined();
    const piped = user("ixpipe");
    const p = await runAt(piped.env, ["setup", "--name", "ixpipe", "--no-backup"], null);
    expect(p.code, p.err).toBe(0);
    expect(p.out).toContain("never installs it for you");
    expect(config(piped).ixDeclined).toBeUndefined();
  });

  it("an agent's session is never asked, can't record a no, and can't install or enable Ix", async () => {
    const u = user("ixagent");
    // An agent's environment: no person token, Claude Code's marker.
    const env = { ...u.env, P2P_PERSON_TOKEN: undefined, CLAUDECODE: "1" };
    const r = await runAt(env, ["setup", "--name", "ixagent", "--no-backup", "--ix"], ["y", "y", "yes"]);
    expect(r.code, r.err).toBe(0);
    expect(r.asked).toEqual([]);
    expect(config(u).ixDeclined).toBeUndefined();
    expect(config(u).extensions).toBeUndefined();
    expect(r.out).toContain(ixInstallLine());
    expect(r.out).toContain("ask your user");
  });
});
