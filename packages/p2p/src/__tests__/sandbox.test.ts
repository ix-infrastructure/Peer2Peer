// Copyright 2026 Ix Infrastructure Inc.
//
// Sandbox by default (sandbox.ts): `p2p sandbox enable` (and the offers in `p2p setup` and `p2p codex
// install --write`) add the deny on P2P_HOME to the person's own Claude Code settings and Codex
// config.toml; `p2p doctor` and `p2p sandbox` report it. Every test runs in its own home folder
// (HOME, CLAUDE_CONFIG_DIR, CODEX_HOME), never the person's real config.

import { existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { main } from "../cli.js";
import { execFileSync } from "node:child_process";
import { applyPlans, claudeSandboxStatus, MAX_CONFIG_BYTES, offerablePlans, p2pHomeProblem, planClaudeSandbox, planFront, readConfigFile, sandboxReport } from "../sandbox.js";

const edited = (p: ReturnType<typeof planClaudeSandbox>): string => {
  if (p.kind !== "edit") throw new Error(`expected an edit, got ${p.kind}`);
  return p.after;
};
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
  // Linux's sandbox needs bubblewrap and socat: stand-ins on PATH, so the status doesn't depend on the machine.
  mkdirSync(join(home, "bin"));
  for (const b of ["bwrap", "socat"]) writeFileSync(join(home, "bin", b), "", { mode: 0o755 });
  const env: Record<string, string> = { HOME: home, P2P_HOME: p2pHome, P2P_PERSON_TOKEN: "", PATH: `${join(home, "bin")}:${process.env.PATH ?? ""}` };
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
      sandbox: { enabled: true, autoAllowBashIfSandboxed: false, allowUnsandboxedCommands: false, filesystem: { denyRead: ["~/.p2p"], denyWrite: ["~/.p2p"] } },
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
    const before = JSON.stringify({ sandbox: { enabled: true, autoAllowBashIfSandboxed: false, allowUnsandboxedCommands: false, filesystem: { denyRead: ["~/"], denyWrite: ["~"] } }, permissions: { deny: ["Read(~/**)", "Edit(~/**)"] } });
    expect(planClaudeSandbox(before, p.env).kind).toBe("already");
  });

  it("keeps the person's permission prompts: autoAllowBashIfSandboxed false unless they set it", () => {
    const p = person();
    const plan = planClaudeSandbox(null, p.env);
    if (plan.kind !== "edit") throw new Error("expected an edit");
    expect(plan.edits).toContainEqual({ key: "sandbox.autoAllowBashIfSandboxed", value: false });
    const mine = planClaudeSandbox(JSON.stringify({ sandbox: { autoAllowBashIfSandboxed: true } }), p.env);
    if (mine.kind !== "edit") throw new Error("expected an edit");
    expect(JSON.parse(mine.after).sandbox.autoAllowBashIfSandboxed).toBe(true);
    expect(mine.edits.some((e) => e.key === "sandbox.autoAllowBashIfSandboxed")).toBe(false);
  });

  it("refuses a P2P_HOME with rule characters, or one that is the home folder or above it", () => {
    const p = person();
    const odd = join(p.home, "p2p[x]");
    mkdirSync(odd);
    for (const env of [{ ...p.env, P2P_HOME: odd }, { ...p.env, P2P_HOME: p.home }, { ...p.env, P2P_HOME: "/" }, { ...p.env, P2P_HOME: join(p.home, "..") }]) {
      expect(p2pHomeProblem(env)).toBeDefined();
      expect(planFront("claude", env, NO_MANAGED).plan.kind).toBe("manual");
      expect(planFront("codex", env).plan.kind).toBe("manual");
      expect(claudeSandboxStatus(env, NO_MANAGED).state).toBe("unknown");
    }
    expect(p2pHomeProblem(p.env)).toBeUndefined();
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

describe("what else decides it here (doctor)", () => {
  it("a project's settings that turn the sandbox off, or open P2P_HOME, count", () => {
    const p = person();
    writeFileSync(p.settings, edited(planClaudeSandbox(null, p.env)));
    const proj = join(p.home, "work", "repo");
    mkdirSync(join(proj, ".git"), { recursive: true });
    const sub = join(proj, "pkg");
    mkdirSync(join(sub, ".claude"), { recursive: true });
    expect(claudeSandboxStatus(p.env, { ...NO_MANAGED, workdir: sub }).state).toBe("on");
    mkdirSync(join(proj, ".claude"));
    writeFileSync(join(proj, ".claude", "settings.json"), JSON.stringify({ sandbox: { enabled: false } }));
    const off = claudeSandboxStatus(p.env, { ...NO_MANAGED, workdir: sub });
    expect(off.state).toBe("off");
    expect(off.detail).toMatch(/turns it off in this project/);
    // The local file outranks the shared one.
    writeFileSync(join(sub, ".claude", "settings.local.json"), JSON.stringify({ sandbox: { enabled: true, filesystem: { allowRead: ["~/.p2p/cli"] } } }));
    const opened = claudeSandboxStatus(p.env, { ...NO_MANAGED, workdir: sub });
    expect(opened.detail).not.toMatch(/turns it off/);
    expect(opened.detail).toMatch(/allowRead inside P2P_HOME/);
    writeFileSync(join(sub, ".claude", "settings.local.json"), "{ not json");
    expect(claudeSandboxStatus(p.env, { ...NO_MANAGED, workdir: join(p.home, "work") }).state).toBe("on");
    rmSync(join(proj, ".claude"), { recursive: true });
    expect(claudeSandboxStatus(p.env, { ...NO_MANAGED, workdir: sub }).state).toBe("unknown");
  });

  it("on Linux, a missing bubblewrap means no sandbox", () => {
    const p = person();
    writeFileSync(p.settings, edited(planClaudeSandbox(null, p.env)));
    expect(claudeSandboxStatus(p.env, { ...NO_MANAGED, platform: "linux" }).state).toBe("on");
    const st = claudeSandboxStatus({ ...p.env, PATH: "/nonexistent-p2p-test" }, { ...NO_MANAGED, platform: "linux" });
    expect(st.state).toBe("off");
    expect(st.detail).toMatch(/bubblewrap/);
  });

  it("a project's .codex/config.toml that picks its own sandbox makes Codex's line unknown", () => {
    const p = person();
    const plan = planFront("codex", p.env);
    if (plan.plan.kind !== "edit") throw new Error("expected an edit");
    writeFileSync(p.config, plan.plan.after);
    const proj = join(p.home, "repo");
    mkdirSync(join(proj, ".git"), { recursive: true });
    expect(sandboxReport(p.env, { ...NO_MANAGED, workdir: proj }).codex.state).toBe("on");
    mkdirSync(join(proj, ".codex"));
    writeFileSync(join(proj, ".codex", "config.toml"), 'model = "x"\n');
    expect(sandboxReport(p.env, { ...NO_MANAGED, workdir: proj }).codex.state).toBe("on");
    writeFileSync(join(proj, ".codex", "config.toml"), 'sandbox_mode = "danger-full-access"\n');
    const st = sandboxReport(p.env, { ...NO_MANAGED, workdir: proj }).codex;
    expect(st.state).toBe("unknown");
    expect(st.notes.join()).toMatch(/when Codex trusts this project/);
  });
});

describe("config files a repository planted", () => {
  const fifo = (path: string) => execFileSync("/usr/bin/mkfifo", [path]);

  it("a FIFO, a device or an oversize file is never read: status is ?, nothing hangs", () => {
    const p = person();
    writeFileSync(p.settings, edited(planClaudeSandbox(null, p.env)));
    const codexPlan = planFront("codex", p.env);
    if (codexPlan.plan.kind !== "edit") throw new Error("expected an edit");
    writeFileSync(p.config, codexPlan.plan.after);
    const proj = join(p.home, "repo");
    mkdirSync(join(proj, ".git"), { recursive: true });
    mkdirSync(join(proj, ".claude"));
    mkdirSync(join(proj, ".codex"));
    fifo(join(proj, ".claude", "settings.json"));
    fifo(join(proj, ".codex", "config.toml"));
    const r1 = sandboxReport(p.env, { ...NO_MANAGED, workdir: proj });
    expect(r1.claude.state).toBe("unknown");
    expect(r1.claude.notes.join()).toMatch(/couldn't be read/);
    expect(r1.codex.state).toBe("unknown");
    rmSync(join(proj, ".claude", "settings.json"));
    symlinkSync("/dev/zero", join(proj, ".claude", "settings.json"));
    expect(sandboxReport(p.env, { ...NO_MANAGED, workdir: proj }).claude.state).toBe("unknown");
    rmSync(join(proj, ".claude", "settings.json"));
    writeFileSync(join(proj, ".claude", "settings.json"), `{"x": "${"a".repeat(MAX_CONFIG_BYTES)}"}`);
    expect(sandboxReport(p.env, { ...NO_MANAGED, workdir: proj }).claude.state).toBe("unknown");
  });

  it("readConfigFile refuses what isn't a small regular file", () => {
    const p = person();
    const f = join(p.home, "f.json");
    fifo(f);
    expect(() => readConfigFile(f)).toThrow(/isn't a regular file/);
    expect(() => readConfigFile(join(p.home, ".claude"))).toThrow(/isn't a regular file/);
    expect(() => readConfigFile("/dev/zero")).toThrow(/isn't a regular file/);
    const big = join(p.home, "big.json");
    writeFileSync(big, "x".repeat(MAX_CONFIG_BYTES + 1));
    expect(() => readConfigFile(big)).toThrow(/larger than/);
    expect(readConfigFile(join(p.home, "missing.json"))).toBeNull();
  });

  it("a user settings file that is a FIFO is left alone by enable", async () => {
    const p = person({ codex: false });
    fifo(p.settings);
    const r = await run(["sandbox", "enable", "--yes"], p.env);
    expect(r.code).toBe(0);
    expect(r.out).toMatch(/Claude Code: not changed: .*isn't a regular file/);
  });

  it("a stale temp file from a crash doesn't stop the write", () => {
    const p = person({ codex: false });
    writeFileSync(p.settings, "{}\n");
    writeFileSync(`${p.settings}.p2p-tmp-${process.pid}`, "stale");
    const done = applyPlans(offerablePlans(p.env));
    expect(done.length).toBe(1);
    expect(claudeSandboxStatus(p.env, NO_MANAGED).state).toBe("on");
  });
});

describe("p2p sandbox enable", () => {
  it("shows the changes, asks (Enter is yes), backs up, writes both, and is idempotent", async () => {
    const p = person();
    writeFileSync(p.settings, '{\n  "model": "m"\n}\n');
    writeFileSync(p.config, '# my codex config\nmodel = "x"\n\n[mcp_servers.other]\ncommand = "other"\n');
    const r = await run(["sandbox", "enable"], p.env, { answers: ["", ""] });
    expect(r.code).toBe(0);
    // Each agent on its own, with what changes and how to undo it.
    expect(r.asked).toEqual(["Turn on Claude Code's sandbox with this deny? [Y/n] ", "Add this to Codex's config? [Y/n] "]);
    expect(r.out).toMatch(/write only inside the project/);
    expect(r.out).toMatch(/autoAllowBashIfSandboxed: false/);
    expect(r.out).toMatch(/can't run p2p any more/);
    expect(r.out).toMatch(/To undo: put the backup back/);
    expect(r.out).toMatch(/This one extends :read-only: Codex's commands can't write \(it asks first under an on-request approval policy; under "never", a write just fails\)/);
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
    const r = await run(["sandbox", "enable"], p.env, { answers: ["n", "n"] });
    expect(r.code).toBe(0);
    expect(existsSync(p.settings)).toBe(false);
    expect(existsSync(p.config)).toBe(false);
    expect(JSON.parse(readFileSync(join(p.p2pHome, "config.json"), "utf8")).sandboxDeclined).toEqual(["claude", "codex"]);
    expect(sandboxReport(p.env, NO_MANAGED).declined).toBe(true);
    // Asked explicitly, it asks again, and a yes clears the "no".
    const yes = await run(["sandbox", "enable", "--claude"], p.env, { answers: ["y"] });
    expect(yes.code).toBe(0);
    expect(claudeSandboxStatus(p.env, NO_MANAGED).state).toBe("on");
    expect(JSON.parse(readFileSync(join(p.p2pHome, "config.json"), "utf8")).sandboxDeclined).toEqual(["codex"]);
  });

  it("asks for each agent apart: no to one, yes to the other", async () => {
    const p = person();
    const r = await run(["sandbox", "enable"], p.env, { answers: ["n", "y"] });
    expect(r.code).toBe(0);
    expect(existsSync(p.settings)).toBe(false);
    expect(sandboxReport(p.env, NO_MANAGED).codex.state).toBe("on");
    expect(JSON.parse(readFileSync(join(p.p2pHome, "config.json"), "utf8")).sandboxDeclined).toEqual(["claude"]);
  });

  it("writes nothing when the file changed after it was shown", async () => {
    const p = person({ codex: false });
    writeFileSync(p.settings, '{"model": "a"}\n');
    const plans = offerablePlans(p.env);
    writeFileSync(p.settings, '{"model": "b"}\n');
    expect(() => applyPlans(plans)).toThrow(/changed after it was shown/);
    expect(readFileSync(p.settings, "utf8")).toBe('{"model": "b"}\n');
  });

  it("keeps a backup next to a symbolic link (0600), and writes through to its target", () => {
    const p = person({ codex: false });
    const dots = join(p.home, "dotfiles");
    mkdirSync(dots);
    writeFileSync(join(dots, "settings.json"), '{"model": "m"}\n', { mode: 0o644 });
    symlinkSync(join(dots, "settings.json"), p.settings);
    const done = applyPlans(offerablePlans(p.env));
    expect(done[0]?.backup?.startsWith(`${p.settings}.p2p-backup-`)).toBe(true);
    expect(statSync(done[0]?.backup as string).mode & 0o777).toBe(0o600);
    expect(readdirSync(dots)).toEqual(["settings.json"]);
    expect(lstatSync(p.settings).isSymbolicLink()).toBe(true);
    expect(statSync(join(dots, "settings.json")).mode & 0o777).toBe(0o644);
    expect(JSON.parse(readFileSync(join(dots, "settings.json"), "utf8")).sandbox.enabled).toBe(true);
  });

  it("on Windows it needs the person's answer: --yes is refused", async () => {
    const p = person();
    const was = Object.getOwnPropertyDescriptor(process, "platform") as PropertyDescriptor;
    Object.defineProperty(process, "platform", { value: "win32" });
    try {
      const r = await run(["sandbox", "enable", "--yes", "--codex", "--json"], p.env);
      expect(r.json.error).toBe("usage");
      expect(String(r.json.reason)).toMatch(/on Windows/);
    } finally {
      Object.defineProperty(process, "platform", was);
    }
    expect(existsSync(p.config)).toBe(false);
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
    await run(["sandbox", "enable"], n.env, { answers: ["no", "no"] });
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

  const QUESTION = /Turn on Claude Code's sandbox|Add this to Codex's config/;
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
          return QUESTION.test(q) ? sandboxAnswer : "n";
        },
      },
      confirmTty: async () => false,
    });
    process.exitCode = 0;
    return { asked: asked.filter((q) => QUESTION.test(q)), out: out.join("\n") };
  }

  it("asks at the person's terminal, writes on Enter, and doesn't ask again", async () => {
    const p = person();
    const env = { ...p.env, P2P_RELAY_TRANSPORT: tr, PATH: "/nonexistent-p2p-test" };
    expect((await run(["init", "--name", "ann", "--relay", R, "--yes", "--json"], env)).code).toBe(0);
    const first = await setupAt(env, "");
    expect(first.asked.length).toBe(2);
    expect(first.out).toMatch(/Claude Code: .*settings\.json/);
    expect(first.out).toMatch(/sandbox Wrote .*config\.toml/);
    expect(sandboxReport(env, NO_MANAGED).claude.state).toBe("on");
    expect(sandboxReport(env, NO_MANAGED).codex.state).toBe("on");
    expect((await setupAt(env, "")).asked).toEqual([]);
  });

  it("a no is remembered; --sandbox asks again; never inside an agent's session or from a front end", async () => {
    const p = person();
    const env = { ...p.env, P2P_RELAY_TRANSPORT: tr, PATH: "/nonexistent-p2p-test" };
    expect((await run(["init", "--name", "ben", "--relay", R, "--yes", "--json"], env)).code).toBe(0);
    const no = await setupAt(env, "n");
    expect(no.asked.length).toBe(2);
    expect(no.out).toMatch(/You won't be asked again/);
    expect(existsSync(p.settings)).toBe(false);
    expect((await setupAt(env, "")).asked).toEqual([]);
    expect((await setupAt({ ...env, CLAUDECODE: "1" }, "", ["--sandbox"])).asked).toEqual([]);
    const again = await setupAt(env, "y", ["--sandbox"]);
    expect(again.asked.length).toBe(2);
    expect(sandboxReport(env, NO_MANAGED).claude.state).toBe("on");
  });
});
