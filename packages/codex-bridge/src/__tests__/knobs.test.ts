// Copyright 2026 Ix Infrastructure Inc.
//
// M1(b): a trusted repo's .codex/config.toml can add to
// mcp_servers.peer2peer.env (mcp_servers isn't on Codex's project-local
// denylist), so guarded settings come only from the user-level config.

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { bridgeHome, effectiveEnv, readTomlTable } from "../knobs.js";
import { configBlock, managedEnv } from "../install.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const T = ["mcp_servers", "peer2peer", "env"];

describe("readTomlTable: the user-level [mcp_servers.peer2peer.env]", () => {
  it("reads the table, an inline env, dotted keys, and ignores the rest", () => {
    const text = [
      'model = "gpt-5"',
      "[mcp_servers.other.env]",
      'P2P_AUTO_DELIVER = "not ours"',
      "[mcp_servers.peer2peer]",
      'command = "node"',
      'args = [',
      '  "/p2p.mjs", "codex",',
      '  "mcp"]',
      'env.P2P_HOME = "/home/ann/.p2p-work"',
      "[mcp_servers.peer2peer.env]",
      "P2P_AUTO_DELIVER = 'p2p:benbenbenbenbenbenbenbenbenbenbenb' # trusted",
      'P2P_CODEX_CONFIRM_RATE = 5',
      'ESCAPED = "a\\"b\\u00e9"',
      "[[profiles]]",
      'P2P_AUTO_DELIVER = "array of tables: not ours"',
    ].join("\n");
    expect(readTomlTable(text, T)).toEqual({
      P2P_HOME: "/home/ann/.p2p-work",
      P2P_AUTO_DELIVER: "p2p:benbenbenbenbenbenbenbenbenbenbenb",
      P2P_CODEX_CONFIRM_RATE: "5",
      ESCAPED: 'a"bé',
    });
    expect(readTomlTable('[mcp_servers.peer2peer]\nenv = { P2P_HOME = "/x", P2P_BIN = "/b" }\n', T)).toEqual({ P2P_HOME: "/x", P2P_BIN: "/b" });
    expect(readTomlTable('mcp_servers.peer2peer.env.P2P_HOME = "/top"\n', T)).toEqual({ P2P_HOME: "/top" });
    expect(readTomlTable("", T)).toEqual({});
  });

  it("refuses to guess when our table can't be read with confidence", () => {
    expect(readTomlTable('[mcp_servers.peer2peer.env]\nP2P_HOME = """multi\nline"""\n', T)).toBeNull();
    expect(readTomlTable("[mcp_servers.peer2peer.env\n", T)).toBeNull();
  });
});

describe("effectiveEnv: guarded settings only from the user-level config", () => {
  const codexHome = (config: string | null) => {
    const d = mkdtempSync(join(tmpdir(), "codex-home-"));
    dirs.push(d);
    if (config !== null) writeFileSync(join(d, "config.toml"), config);
    return d;
  };

  it("a project-injected P2P_AUTO_DELIVER / CONFIRM_TTY / CONFIRM_RATE / P2P_HOME is ignored; the user's own values apply", async () => {
    const home = codexHome('[mcp_servers.peer2peer.env]\nP2P_HOME = "/home/ann/.p2p"\nP2P_AUTO_DELIVER = "p2p:friendfriendfriendfriendfriend"\n');
    const r = await effectiveEnv({
      temp: [],
      env: { CODEX_HOME: home, P2P_HOME: "/repo/.p2p", P2P_AUTO_DELIVER: "p2p:attackerattackerattackerattacker", P2P_CODEX_CONFIRM_TTY: "/repo/code.txt", P2P_CODEX_CONFIRM_RATE: "1000", P2P_DRAIN_QUIET_MS: "250" },
      projectDirs: ["/repo"],
      parentValue: async () => home,
    });
    expect(r.env.P2P_HOME).toBe("/home/ann/.p2p");
    expect(r.env.P2P_AUTO_DELIVER).toBe("p2p:friendfriendfriendfriendfriend");
    expect(r.env.P2P_CODEX_CONFIRM_TTY).toBeUndefined();
    expect(r.env.P2P_CODEX_CONFIRM_RATE).toBeUndefined();
    expect(r.env.P2P_DRAIN_QUIET_MS).toBe("250"); // not guarded
    expect(r.warnings.join("\n")).toMatch(/ignored P2P_AUTO_DELIVER[\s\S]*ignored P2P_CODEX_CONFIRM_TTY/);
  });

  it("values equal to the user-level ones pass silently", async () => {
    const home = codexHome('[mcp_servers.peer2peer.env]\nP2P_CODEX_CONFIRM_RATE = "30"\n');
    const r = await effectiveEnv({ temp: [], env: { CODEX_HOME: home, P2P_CODEX_CONFIRM_RATE: "30" }, projectDirs: [], parentValue: async () => home });
    expect(r.env.P2P_CODEX_CONFIRM_RATE).toBe("30");
    expect(r.warnings).toEqual([]);
  });

  it("P2P_SHARE_STATUS only tightens, from either place", async () => {
    const home = codexHome('[mcp_servers.peer2peer.env]\nP2P_SHARE_STATUS = "0"\n');
    expect((await effectiveEnv({ temp: [], env: { CODEX_HOME: home, P2P_SHARE_STATUS: "1" }, projectDirs: [], parentValue: async () => home })).env.P2P_SHARE_STATUS).toBe("0");
    const plain = codexHome("");
    expect((await effectiveEnv({ temp: [], env: { CODEX_HOME: plain, P2P_SHARE_STATUS: "0" }, projectDirs: [], parentValue: async () => plain })).env.P2P_SHARE_STATUS).toBe("0");
  });

  it("CODEX_HOME counts only when Codex itself runs with it, or (unknowable) when the installer pinned it", async () => {
    const real = codexHome('[mcp_servers.peer2peer.env]\nP2P_HOME = "/real"\n');
    const fake = codexHome('[mcp_servers.peer2peer.env]\nP2P_HOME = "/fake"\nP2P_AUTO_DELIVER = "p2p:attackerattackerattackerattacker"\n');
    // The parent's environment says otherwise: the injected one is ignored (default ~/.codex then).
    const a = await effectiveEnv({ temp: [], env: { CODEX_HOME: fake }, projectDirs: [], parentValue: async () => real, home: "/nohome" });
    expect(a.codexHome).toBe("/nohome/.codex");
    expect(a.env.P2P_AUTO_DELIVER).toBeUndefined();
    expect(a.warnings[0]).toContain("ignored CODEX_HOME");
    // Matches the parent: used.
    const b = await effectiveEnv({ temp: [], env: { CODEX_HOME: real }, projectDirs: [], parentValue: async () => real });
    expect(b.env.P2P_HOME).toBe("/real");
    // Parent unreadable: pointing into the project is refused even when pinned; elsewhere only a pinned one counts.
    const c = await effectiveEnv({ temp: [], env: { CODEX_HOME: fake }, projectDirs: [join(fake, "..")], parentValue: async () => undefined, pins: () => [fake], home: "/nohome" });
    expect(c.codexHome).toBe("/nohome/.codex");
    const d = await effectiveEnv({ temp: [], env: { CODEX_HOME: real }, projectDirs: ["/repo"], parentValue: async () => undefined, pins: () => [real] });
    expect(d.codexHome).toBe(real);
    const e = await effectiveEnv({ temp: [], env: { CODEX_HOME: real }, projectDirs: ["/repo"], parentValue: async () => undefined, pins: () => [], home: "/nohome" });
    expect(e.codexHome).toBe("/nohome/.codex");
    expect(e.warnings[0]).toContain("pinned");
  });

  it("the person's commands and hooks use the bridge's P2P_HOME", () => {
    const home = codexHome('[mcp_servers.peer2peer.env]\nP2P_HOME = "/from/config"\n');
    expect(bridgeHome({ CODEX_HOME: home, P2P_HOME: "/from/shell" })).toBe("/from/config");
    expect(bridgeHome({ CODEX_HOME: codexHome(null), P2P_HOME: "/from/shell" })).toBe("/from/shell");
  });
});

describe("the installer writes guarded settings where the bridge reads them", () => {
  it("an env table inside the managed block, kept across reinstalls", () => {
    const block = configBlock({ codexHome: "/h", node: "node", script: "/p2p.mjs", env: { P2P_HOME: "/home/ann/.p2p", P2P_AUTO_DELIVER: "p2p:x" } });
    expect(block).toContain("[mcp_servers.peer2peer.env]");
    expect(readTomlTable(block, T)).toEqual({ P2P_AUTO_DELIVER: "p2p:x", P2P_HOME: "/home/ann/.p2p" });
    expect(managedEnv(`a = 1\n\n${block}\n`)).toEqual({ P2P_AUTO_DELIVER: "p2p:x", P2P_HOME: "/home/ann/.p2p" });
    expect(block).toContain('env_vars = ["CODEX_HOME", "P2P_SHARE_STATUS"]');
  });
});
