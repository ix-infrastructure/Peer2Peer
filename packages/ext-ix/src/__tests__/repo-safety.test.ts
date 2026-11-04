// Copyright 2026 Ix Infrastructure Inc.
//
// N1 (PR #30 review): the repository is the agent's to write, and ext-ix runs git in it. A
// `core.fsmonitor` program (or a hook) the repository configures must never run, and git must
// never see a secret of p2p's (the person token) in its environment.

import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { gitEnv, gitOut } from "../repo.js";

const dirs: string[] = [];
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

describe("git in an agent-writable repository (N1)", () => {
  it("a core.fsmonitor program the repository sets never runs, and never sees the person token", async () => {
    const root = mkdtempSync(join(tmpdir(), "p2p-fsmon-"));
    dirs.push(root);
    const repo = join(root, "repo");
    const leak = join(root, "leaked-env.txt");
    const g = (...a: string[]) => execFileSync("git", a, { cwd: repo, env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" } }).toString();
    execFileSync("git", ["init", "-q", "-b", "main", repo]);
    writeFileSync(join(repo, "a.txt"), "x\n");
    g("add", ".");
    g("-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "-m", "init");
    // What a hostile repository (or an agent with write access to it) plants.
    const hook = join(root, "hook.sh");
    writeFileSync(hook, `#!/bin/sh\nenv > "${leak}"\nexit 1\n`);
    chmodSync(hook, 0o755);
    g("config", "core.fsmonitor", hook);
    writeFileSync(join(repo, "a.txt"), "changed\n");
    // The plant works when git is run plainly (the test means something)...
    g("status", "--porcelain");
    expect(existsSync(leak)).toBe(true);
    rmSync(leak);
    // ...and never through ext-ix, even with the token in the caller's environment.
    const env = { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", P2P_PERSON_TOKEN: "x".repeat(43) };
    expect(await gitOut(repo, ["status", "--porcelain"], env)).toContain("a.txt");
    expect(await gitOut(repo, ["diff", "--name-only"], env)).toContain("a.txt");
    expect(existsSync(leak)).toBe(false);
  });

  it("git's environment is an allow-list: nothing of p2p's", () => {
    const e = gitEnv({ PATH: "/bin", HOME: "/h", P2P_PERSON_TOKEN: "secret", P2P_HOME: "/p", NODE_OPTIONS: "--require x", GIT_CONFIG_GLOBAL: "/g" });
    expect(e).toEqual({ PATH: "/bin", HOME: "/h", GIT_CONFIG_GLOBAL: "/g" });
    expect(JSON.stringify(e)).not.toContain("secret");
  });
});
