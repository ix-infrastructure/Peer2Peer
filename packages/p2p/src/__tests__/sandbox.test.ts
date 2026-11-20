// Copyright 2026 Ix Infrastructure Inc.
//
// Sandbox by default (sandbox.ts): `p2p sandbox enable` (and the offers in `p2p setup` and `p2p codex
// install --write`) add the deny on P2P_HOME to the person's own Claude Code settings and Codex
// config.toml; `p2p doctor` and `p2p sandbox` report it. Every test runs in its own home folder
// (HOME, CLAUDE_CONFIG_DIR, CODEX_HOME), never the person's real config.

import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { main } from "../cli.js";
import { claudeSandboxStatus, planClaudeSandbox, sandboxReport } from "../sandbox.js";
import { personTokenFor, startRelay, type TestRelay } from "./harness.js";

const dirs: string[] = [];
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});
afterEach(() => {
  (globalThis as { __p2pTestAncestry?: string }).__p2pTestAncestry = undefined;
});

/** A fresh person: a home folder with ~/.claude and ~/.codex, and P2P_HOME at ~/.p2p. */
function person(o: { claude?: boolean; codex?: boolean } = {}) {
  const home = realpathSync(mkdtempSync(join(tmpdir(), "p2p-sbx-")));
  dirs.push(home);
  if (o.claude !== false) mkdirSync(join(home, ".claude"));
  if (o.codex !== false) mkdirSync(join(home, ".codex"));
  const p2pHome = join(home, ".p2p");
  mkdirSync(p2pHome, { mode: 0o700 });
  const env: Record<string, string> = { HOME: home, P2P_HOME: p2pHome, P2P_PERSON_TOKEN: "" };
  return { home, p2pHome, env, settings: join(home, ".claude", "settings.json"), config: join(home, ".codex", "config.toml") };
}

async function run(argv: string[], env: Record<string, string>, o: { answers?: string[]; front?: boolean } = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const answers = [...(o.answers ?? [])];
  const asked: string[] = [];
  const code = await main(argv, {
    env,
    ...(o.front ? { front: true } : {}),
    io: {
      out: (l) => out.push(l),
      err: (l) => err.push(l),
      ...(o.answers ? { prompt: async (q: string) => (asked.push(q), answers.shift() ?? "") } : {}),
    },
    confirmTty: async () => true,
  });
  process.exitCode = 0;
  let json: Record<string, unknown> = {};
  try {
    json = JSON.parse(out.at(-1) ?? "{}") as Record<string, unknown>;
  } catch {
    // not JSON
  }
  return { code, out: out.join("\n"), err: err.join("\n"), json, asked };
}

const NO_MANAGED = { managedPath: null } as const;

describe("Claude Code settings.json", () => {
  it("creates the settings when there are none, and reads back as on", () => {
    const p = person();
    const plan = planClaudeSandbox(null, p.env);
    expect(plan.kind).toBe("edit");
    if (plan.kind !== "edit") return;
    const doc = JSON.parse(plan.after);
    expect(doc).toEqual({
      sandbox: { enabled: true, allowUnsandboxedCommands: false, filesystem: { denyRead: ["~/.p2p"], denyWrite: ["~/.p2p"] } },
      permissions: { deny: ["Read(~/.p2p/**)", "Edit(~/.p2p/**)"] },
    });
    writeFileSync(p.settings, plan.after);
    expect(claudeSandboxStatus(p.env, NO_MANAGED).state).toBe("on");
    expect(planClaudeSandbox(plan.after, p.env).kind).toBe("already");
  });

  it("keeps every other key, existing entries and the file's indentation", () => {
    const p = person();
    const before = JSON.stringify(
      {
        $schema: "https://json.schemastore.org/claude-code-settings.json",
        model: "some-model",
        env: { SOME_VAR: "kept" },
        permissions: { allow: ["Bash(npm test)"], deny: ["Read(./.env)"] },
        sandbox: { filesystem: { allowWrite: ["~/.kube"], denyRead: ["~/.aws/credentials"] }, excludedCommands: [] },
        hooks: { Stop: [{ hooks: [{ type: "command", command: "echo done" }] }] },
      },
      null,
      4,
    );
    const plan = planClaudeSandbox(before, p.env);
    expect(plan.kind).toBe("edit");
    if (plan.kind !== "edit") return;
    expect(plan.after).toMatch(/\n {4}"model"/);
    const doc = JSON.parse(plan.after);
    expect(doc.model).toBe("some-model");
    expect(doc.env).toEqual({ SOME_VAR: "kept" });
    expect(doc.hooks.Stop[0].hooks[0].command).toBe("echo done");
    expect(doc.permissions.allow).toEqual(["Bash(npm test)"]);
    expect(doc.permissions.deny).toEqual(["Read(./.env)", "Read(~/.p2p/**)", "Edit(~/.p2p/**)"]);
    expect(doc.sandbox.filesystem).toEqual({ allowWrite: ["~/.kube"], denyRead: ["~/.aws/credentials", "~/.p2p"], denyWrite: ["~/.p2p"] });
    expect(Object.keys(doc)).toEqual(["$schema", "model", "env", "permissions", "sandbox", "hooks"]);
    // Idempotent.
    expect(planClaudeSandbox(plan.after, p.env).kind).toBe("already");
  });

  it("doesn't add what a folder above P2P_HOME already covers", () => {
    const p = person();
    const before = JSON.stringify({ sandbox: { enabled: true, allowUnsandboxedCommands: false, filesystem: { denyRead: ["~/"], denyWrite: ["~"] } }, permissions: { deny: ["Read(~/**)", "Edit(~/**)"] } });
    expect(planClaudeSandbox(before, p.env).kind).toBe("already");
  });

  it("uses an absolute rule for a P2P_HOME outside the home folder", () => {
    const p = person();
    const elsewhere = realpathSync(mkdtempSync(join(tmpdir(), "p2p-sbx-elsewhere-")));
    dirs.push(elsewhere);
    const env = { ...p.env, P2P_HOME: elsewhere };
    const plan = planClaudeSandbox(null, env);
    if (plan.kind !== "edit") throw new Error("expected an edit");
    const doc = JSON.parse(plan.after);
    expect(doc.sandbox.filesystem.denyRead[0]).toBe(elsewhere);
    // `//abs` is an absolute path in a permission rule (a single slash is project-relative).
    expect(doc.permissions.deny[0].startsWith("Read(//")).toBe(true);
  });

  it("refuses a file that isn't valid JSON, or a sandbox that isn't an object", () => {
    const p = person();
    expect(planClaudeSandbox("{ // comment\n}", p.env).kind).toBe("manual");
    expect(planClaudeSandbox('{"sandbox": true}', p.env).kind).toBe("manual");
    expect(planClaudeSandbox('{"permissions": {"deny": "Read(x)"}}', p.env).kind).toBe("manual");
  });

  it("reports what is missing, and an allowRead that opens P2P_HOME again", () => {
    const p = person();
    writeFileSync(p.settings, JSON.stringify({ sandbox: { enabled: true, filesystem: { denyRead: ["~/.p2p"], denyWrite: ["~/.p2p"], allowRead: ["~/.p2p/cli"] } } }));
    const st = claudeSandboxStatus(p.env, NO_MANAGED);
    expect(st.state).toBe("off");
    expect(st.missing.join("\n")).toMatch(/allowUnsandboxedCommands/);
    expect(st.missing.join("\n")).toMatch(/permissions\.deny Read/);
    expect(st.missing.join("\n")).toMatch(/allowRead inside P2P_HOME/);
    expect(claudeSandboxStatus(p.env, { platform: "win32" }).state).toBe("unavailable");
  });

  it("honours CLAUDE_CONFIG_DIR", () => {
    const p = person({ claude: false });
    const dir = join(p.home, "claude-elsewhere");
    mkdirSync(dir);
    const env = { ...p.env, CLAUDE_CONFIG_DIR: dir };
    expect(claudeSandboxStatus(env, NO_MANAGED).settings).toBe(join(dir, "settings.json"));
  });
});

describe("p2p sandbox enable", () => {
  it("shows the changes, asks (Enter is yes), backs up, writes both, and is idempotent", async () => {
    const p = person();
    writeFileSync(p.settings, '{\n  "model": "m"\n}\n');
    writeFileSync(p.config, '# my codex config\nmodel = "x"\n\n[mcp_servers.other]\ncommand = "other"\n');
    const r = await run(["sandbox", "enable"], p.env, { answers: [""] });
    expect(r.code).toBe(0);
    expect(r.asked).toEqual(["Add these? [Y/n] "]);
    expect(r.out).toMatch(/sandbox\.filesystem\.denyRead \+= "~\/\.p2p"/);
    expect(r.out).toMatch(/\+ "~\/\.p2p" = "deny"/);
    expect(r.out).toMatch(/Wrote .*settings\.json \(backup: .*settings\.json\.p2p-backup-/);
    expect(JSON.parse(readFileSync(p.settings, "utf8")).model).toBe("m");
    const toml = readFileSync(p.config, "utf8");
    expect(toml.startsWith('# my codex config\nmodel = "x"\ndefault_permissions = "peer2peer" # p2p sandbox\n\n[mcp_servers.other]\ncommand = "other"\n')).toBe(true);
    expect(readdirSync(join(p.home, ".claude")).some((f) => f.startsWith("settings.json.p2p-backup-"))).toBe(true);
    const report = sandboxReport(p.env, NO_MANAGED);
    expect(report.claude.state).toBe("on");
    expect(report.codex.state).toBe("on");
    // Again: nothing to ask, nothing written.
    const again = await run(["sandbox", "enable"], p.env, { answers: [] });
    expect(again.asked).toEqual([]);
    expect(again.out).toMatch(/Claude Code: already denies P2P_HOME/);
    expect(again.out).toMatch(/Codex: already denies P2P_HOME/);
  });

  it("a no changes nothing and is remembered; setup then doesn't offer it", async () => {
    const p = person();
    const r = await run(["sandbox", "enable"], p.env, { answers: ["n"] });
    expect(r.code).toBe(0);
    expect(existsSync(p.settings)).toBe(false);
    expect(existsSync(p.config)).toBe(false);
    expect(JSON.parse(readFileSync(join(p.p2pHome, "config.json"), "utf8")).sandboxDeclined).toBe(true);
    expect(sandboxReport(p.env, NO_MANAGED).declined).toBe(true);
    // Asked explicitly, it asks again, and a yes clears the "no".
    const yes = await run(["sandbox", "enable", "--claude"], p.env, { answers: ["y"] });
    expect(yes.code).toBe(0);
    expect(claudeSandboxStatus(p.env, NO_MANAGED).state).toBe("on");
    expect(JSON.parse(readFileSync(join(p.p2pHome, "config.json"), "utf8")).sandboxDeclined).toBe(false);
  });

  it("without a terminal it needs --yes; --json --yes writes", async () => {
    const p = person({ codex: false });
    const r = await run(["sandbox", "enable", "--json"], p.env);
    expect(r.code).toBe(1);
    expect(r.json.error).toBe("usage");
    expect(existsSync(p.settings)).toBe(false);
    const w = await run(["sandbox", "enable", "--json", "--yes"], p.env);
    expect(w.code).toBe(0);
    expect((w.json.written as unknown[]).length).toBe(1);
    expect(claudeSandboxStatus(p.env, NO_MANAGED).state).toBe("on");
  });

  it("is refused inside an agent's session, from a front end, and when the process tree can't be read", async () => {
    const p = person();
    for (const env of [{ ...p.env, CLAUDECODE: "1" }, { ...p.env, CODEX_THREAD_ID: "t" }]) {
      const r = await run(["sandbox", "enable", "--yes", "--json"], env);
      expect(r.code).toBe(1);
      expect(r.json.error).toBe("refused");
      expect(String(r.json.reason)).toMatch(/inside an agent's session/);
    }
    const front = await run(["sandbox", "enable", "--yes", "--json"], p.env, { front: true });
    expect(front.json.error).toBe("refused");
    expect(String(front.json.reason)).toMatch(/never changes its own agent's sandbox/);
    (globalThis as { __p2pTestAncestry?: string }).__p2pTestAncestry = "agent";
    expect((await run(["sandbox", "enable", "--yes", "--json"], p.env)).json.error).toBe("refused");
    (globalThis as { __p2pTestAncestry?: string }).__p2pTestAncestry = "unknown";
    const unknown = await run(["sandbox", "enable", "--yes", "--json"], p.env);
    expect(unknown.json.error).toBe("refused");
    expect(String(unknown.json.reason)).toMatch(/process tree/);
    expect(existsSync(p.settings)).toBe(false);
    expect(existsSync(p.config)).toBe(false);
  });

  it("leaves a config it can't edit safely alone, with the lines to add by hand", async () => {
    const p = person({ claude: false });
    writeFileSync(p.config, 'sandbox_mode = "danger-full-access"\n');
    const r = await run(["sandbox", "enable", "--yes"], p.env);
    expect(r.code).toBe(0);
    expect(r.out).toMatch(/Codex: not changed: Codex runs its commands without a sandbox/);
    expect(r.out).toMatch(/\[permissions\.peer2peer\.filesystem\]/);
    expect(readFileSync(p.config, "utf8")).toBe('sandbox_mode = "danger-full-access"\n');
  });
});

describe("p2p sandbox, p2p doctor and the front ends' notice", () => {
  it("reports each installed front end, with the fix", async () => {
    const p = person();
    const r = await run(["sandbox"], p.env);
    expect(r.out).toMatch(/✗ Claude Code: Claude Code's sandbox doesn't keep its commands out of ~\/\.p2p/);
    expect(r.out).toMatch(/✗ Codex: .*no permissions profile/);
    expect(r.out).toMatch(/Fix: run `p2p sandbox enable` in your own terminal/);
    // An agent reading it is told to ask its user.
    const agent = await run(["sandbox"], { ...p.env, CLAUDECODE: "1" });
    expect(agent.out).toMatch(/run by the person in their own terminal .*ask your user/);
    const none = person({ claude: false, codex: false });
    expect((await run(["sandbox"], none.env)).out).toMatch(/Claude Code: not set up here/);
  });

  it("doctor checks both, before and after", async () => {
    const p = person();
    const before = await run(["doctor", "--json"], { ...p.env, P2P_DEFAULT_RELAYS: "" });
    const checks = (before.json.checks ?? []) as { id: string; status: string; fix?: string }[];
    expect(checks.find((c) => c.id === "sandbox-claude")?.status).toBe("fail");
    expect(checks.find((c) => c.id === "sandbox-codex")?.status).toBe("fail");
    expect(checks.find((c) => c.id === "sandbox-claude")?.fix).toMatch(/p2p sandbox enable/);
    await run(["sandbox", "enable", "--yes"], p.env);
    const after = await run(["doctor", "--json"], { ...p.env, P2P_DEFAULT_RELAYS: "" });
    const checks2 = (after.json.checks ?? []) as { id: string; status: string }[];
    // The managed settings file of this machine (if any) may add notes; the user settings are complete.
    expect(["ok", "unknown"]).toContain(checks2.find((c) => c.id === "sandbox-claude")?.status);
    expect(checks2.find((c) => c.id === "sandbox-codex")?.status).toBe("ok");
  });

  it("the notice is shown once, to the front end (or the person), never used up by an agent's shell", async () => {
    const p = person();
    personTokenFor(p.p2pHome);
    const agent = await run(["sandbox", "notice", "--json"], { ...p.env, CLAUDECODE: "1" });
    expect(agent.json.notice).toBeUndefined();
    const first = await run(["sandbox", "notice", "--json"], { ...p.env, CLAUDECODE: "1" }, { front: true });
    expect(String(first.json.notice)).toMatch(/In your own terminal \(not inside Claude Code\), run `p2p sandbox enable`/);
    const second = await run(["sandbox", "notice", "--json"], { ...p.env, CLAUDECODE: "1" }, { front: true });
    expect(second.json.notice).toBeUndefined();
    // Not shown when the sandbox already denies P2P_HOME, or the person said no.
    const q = person();
    await run(["sandbox", "enable", "--yes", "--claude"], q.env);
    expect((await run(["sandbox", "notice", "--json"], q.env, { front: true })).json.notice).toBeUndefined();
    const n = person();
    await run(["sandbox", "enable"], n.env, { answers: ["no"] });
    expect((await run(["sandbox", "notice", "--json"], n.env, { front: true })).json.notice).toBeUndefined();
  });
});

describe("p2p setup offers it once", () => {
  const R = "wss://relay-sandbox-offer.test/v3";
  let relay: TestRelay;
  let tr = "";
  beforeAll(async () => {
    relay = await startRelay(R);
    tr = JSON.stringify({ [R]: `ws://127.0.0.1:${relay.port}/v3` });
  }, 30_000);
  afterAll(async () => {
    await relay?.close();
  });

  /** setup at a terminal: Ix's question is answered no, the sandbox's with `sandbox`. */
  async function setupAt(env: Record<string, string>, sandboxAnswer: string, extra: string[] = []) {
    const asked: string[] = [];
    const out: string[] = [];
    await main(["setup", ...extra], {
      env,
      io: {
        out: (l) => out.push(l),
        err: () => {},
        prompt: async (q: string) => {
          asked.push(q);
          return /Add these/.test(q) ? sandboxAnswer : "n";
        },
      },
      confirmTty: async () => false,
    });
    process.exitCode = 0;
    return { asked: asked.filter((q) => /Add these/.test(q)), out: out.join("\n") };
  }

  it("asks at the person's terminal, writes on Enter, and doesn't ask again", async () => {
    const p = person();
    const env = { ...p.env, P2P_RELAY_TRANSPORT: tr, PATH: "/nonexistent-p2p-test" };
    expect((await run(["init", "--name", "ann", "--relay", R, "--yes", "--json"], env)).code).toBe(0);
    const first = await setupAt(env, "");
    expect(first.asked).toEqual(["Add these? [Y/n] "]);
    expect(first.out).toMatch(/Claude Code: .*settings\.json/);
    expect(first.out).toMatch(/sandbox wrote .*config\.toml/);
    expect(sandboxReport(env, NO_MANAGED).claude.state).toBe("on");
    expect(sandboxReport(env, NO_MANAGED).codex.state).toBe("on");
    expect((await setupAt(env, "")).asked).toEqual([]);
  });

  it("a no is remembered; --sandbox asks again; never inside an agent's session or from a front end", async () => {
    const p = person();
    const env = { ...p.env, P2P_RELAY_TRANSPORT: tr, PATH: "/nonexistent-p2p-test" };
    expect((await run(["init", "--name", "ben", "--relay", R, "--yes", "--json"], env)).code).toBe(0);
    const no = await setupAt(env, "n");
    expect(no.asked.length).toBe(1);
    expect(no.out).toMatch(/You won't be asked again/);
    expect(existsSync(p.settings)).toBe(false);
    expect((await setupAt(env, "")).asked).toEqual([]);
    expect((await setupAt({ ...env, CLAUDECODE: "1" }, "", ["--sandbox"])).asked).toEqual([]);
    const again = await setupAt(env, "y", ["--sandbox"]);
    expect(again.asked.length).toBe(1);
    expect(sandboxReport(env, NO_MANAGED).claude.state).toBe("on");
  });
});
