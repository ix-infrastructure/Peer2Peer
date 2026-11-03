// Copyright 2026 Ix Infrastructure Inc.
import { lstatSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { installCommand, requirePerson } from "../commands.js";
import { BEGIN, configBlock, configConflict, END, HOOK_MARKER, hookCommand, mergeHooks, replaceBlock } from "../install.js";

const homes: string[] = [];
const home = () => {
  const h = mkdtempSync(join(tmpdir(), "codex-home-"));
  homes.push(h);
  return h;
};
/** A pin file of the test's own, never the real ~/.p2p. */
const pinPath = () => join(home(), "p2p", "codex", "codex-homes");
afterEach(() => {
  for (const h of homes.splice(0)) rmSync(h, { recursive: true, force: true });
});

// installCommand writes node by absolute path (a bare `node` is replaced by process.execPath).
const plan = (codexHome: string) => ({ codexHome, node: process.execPath, script: "/opt/p2p/bin/p2p.mjs" });
const USER_CONFIG = 'model = "gpt-5"\napproval_policy = "on-request"\n\n[mcp_servers.other]\ncommand = "other"\n\n[projects."/x"]\ntrust_level = "trusted"\n';
const USER_HOOKS = { hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "python3 mine.py" }] }] } };

describe("p2p codex install", () => {
  it("prints the snippet without touching anything", () => {
    const h = home();
    const r = installCommand({ pinFile: pinPath(), env: {}, codexHome: h, node: "node", script: "/opt/p2p/bin/p2p.mjs" });
    expect(r.human).toContain("[mcp_servers.peer2peer]");
    expect(r.human).toContain('args = ["/opt/p2p/bin/p2p.mjs", "codex", "mcp"]');
    expect(r.human).toContain("env_vars = [");
    expect(r.human).toContain("codex hook UserPromptSubmit");
    expect(r.human).toContain("## Peer2Peer");
    expect(readdirSync(h)).toEqual([]);
  });

  it("--write: backs up, keeps the user's config and hooks, and is idempotent", () => {
    const h = home();
    writeFileSync(join(h, "config.toml"), USER_CONFIG);
    writeFileSync(join(h, "hooks.json"), JSON.stringify(USER_HOOKS));
    const first = installCommand({ pinFile: pinPath(), env: {}, codexHome: h, node: "node", script: "/opt/p2p/bin/p2p.mjs", write: true, now: new Date(0) });
    expect((first.json as { files: unknown[] }).files).toHaveLength(3);
    const config = readFileSync(join(h, "config.toml"), "utf8");
    expect(config.startsWith(USER_CONFIG.trimEnd())).toBe(true);
    expect(config).toContain(configBlock(plan(h)));
    const hooks = JSON.parse(readFileSync(join(h, "hooks.json"), "utf8"));
    expect(hooks.hooks.PreToolUse[0].hooks[0].command).toBe("python3 mine.py");
    expect(hooks.hooks.PreToolUse).toHaveLength(2);
    expect(Object.keys(hooks.hooks).sort()).toEqual(["PostToolUse", "PreToolUse", "SessionStart", "Stop", "UserPromptSubmit"]);
    expect(readFileSync(join(h, "AGENTS.md"), "utf8")).toContain("## Peer2Peer");
    // Backups of what existed before.
    expect(readFileSync(join(h, "config.toml.p2p-backup-1970-01-01T00-00-00-000Z"), "utf8")).toBe(USER_CONFIG);
    expect(readdirSync(h).filter((n) => n.includes("p2p-backup"))).toHaveLength(2);
    // A second run changes nothing.
    const second = installCommand({ pinFile: pinPath(), env: {}, codexHome: h, node: "node", script: "/opt/p2p/bin/p2p.mjs", write: true, now: new Date(1) });
    expect((second.json as { files: unknown[] }).files).toHaveLength(0);
    expect(second.human).toContain("Already installed");
    // A moved script replaces the entries in place, never duplicates them.
    installCommand({ pinFile: pinPath(), env: {}, codexHome: h, node: "node", script: "/new/p2p.mjs", write: true, now: new Date(2) });
    const moved = readFileSync(join(h, "config.toml"), "utf8");
    expect(moved.split("[mcp_servers.peer2peer]")).toHaveLength(2);
    expect(moved).toContain("/new/p2p.mjs");
    const movedHooks = JSON.parse(readFileSync(join(h, "hooks.json"), "utf8"));
    expect(movedHooks.hooks.Stop).toHaveLength(1);
  });

  it("--write --remove takes out exactly what install added", () => {
    const h = home();
    writeFileSync(join(h, "config.toml"), USER_CONFIG);
    writeFileSync(join(h, "hooks.json"), JSON.stringify(USER_HOOKS));
    installCommand({ pinFile: pinPath(), env: {}, codexHome: h, node: "node", script: "/opt/p2p/bin/p2p.mjs", write: true });
    installCommand({ pinFile: pinPath(), env: {}, codexHome: h, node: "node", script: "/opt/p2p/bin/p2p.mjs", write: true, remove: true });
    expect(readFileSync(join(h, "config.toml"), "utf8")).toBe(USER_CONFIG);
    expect(JSON.parse(readFileSync(join(h, "hooks.json"), "utf8"))).toEqual(USER_HOOKS);
    expect(readFileSync(join(h, "AGENTS.md"), "utf8")).toBe("");
  });

  it("refuses a config that defines peer2peer itself, or broken hooks.json, changing nothing", () => {
    const h = home();
    writeFileSync(join(h, "config.toml"), '[mcp_servers.peer2peer]\ncommand = "mine"\n');
    expect(() => installCommand({ pinFile: pinPath(), env: {}, codexHome: h, node: "node", script: "/p", write: true })).toThrow(/outside the managed block/);
    expect(configConflict('mcp_servers = { a = { command = "x" } }')).toMatch(/inline table/);
    expect(configConflict("mcp_servers.peer2peer.command = 'x'")).toMatch(/dotted/);
    expect(configConflict("# [mcp_servers.peer2peer] in a comment\n")).toBeNull();
    const h2 = home();
    writeFileSync(join(h2, "hooks.json"), "{nope");
    expect(() => installCommand({ pinFile: pinPath(), env: {}, codexHome: h2, node: "node", script: "/p", write: true })).toThrow(/not valid JSON/);
    expect(readdirSync(h2)).toEqual(["hooks.json"]);
  });

  it("--write is the person's: refused from inside a Codex tool call", () => {
    const h = home();
    expect(() => installCommand({ pinFile: pinPath(), env: { CODEX_THREAD_ID: "t1" }, codexHome: h, node: "node", script: "/p", write: true })).toThrow(/your own terminal/);
    expect(() => requirePerson({ CODEX_SESSION_ID: "s" }, "x")).toThrow();
    expect(readdirSync(h)).toEqual([]);
  });

  it("paths with spaces and quotes stay valid TOML strings and shell words", () => {
    const p = { codexHome: "/h", node: "node", script: `/Users/a b/it's "here"/p2p.mjs`, platform: "darwin" };
    expect(configBlock(p)).toContain(`args = ["/Users/a b/it's \\"here\\"/p2p.mjs", "codex", "mcp"]`);
    const hooks = mergeHooks({}, p);
    expect(hooks.hooks?.Stop?.[0]?.hooks?.[0]?.command).toBe(`node '/Users/a b/it'\\''s "here"/p2p.mjs' codex hook Stop ${HOOK_MARKER}`);
  });

  it("L4: on Windows, hook commands are double-quoted for cmd", () => {
    const p = { codexHome: "C:\\Users\\Ann B\\.codex", node: "node", script: "C:\\Users\\Ann B\\peer2peer\\p2p.mjs", platform: "win32" };
    expect(hookCommand(p, "Stop")).toBe(`node "C:\\Users\\Ann B\\peer2peer\\p2p.mjs" codex hook Stop ${HOOK_MARKER}`);
    expect(hookCommand({ ...p, script: "C:\\tools\\p2p.mjs" }, "Stop")).toBe(`node C:\\tools\\p2p.mjs codex hook Stop ${HOOK_MARKER}`);
  });

  it("L4: only the installer's own marked entries are replaced or removed", () => {
    const theirs = { hooks: { Stop: [{ hooks: [{ type: "command", command: "node ~/tools/p2p.mjs codex hook Stop" }] }] } };
    const merged = mergeHooks(theirs, plan("/h"));
    expect(merged.hooks?.Stop).toHaveLength(2);
    expect(mergeHooks(merged, null)).toEqual(theirs);
  });

  it.skipIf(process.platform === "win32")("L4: a symlinked config.toml and hooks.json stay symlinks; their targets are written", () => {
    const h = home();
    const dotfiles = home();
    writeFileSync(join(dotfiles, "config.toml"), USER_CONFIG);
    writeFileSync(join(dotfiles, "hooks.json"), JSON.stringify(USER_HOOKS));
    symlinkSync(join(dotfiles, "config.toml"), join(h, "config.toml"));
    symlinkSync(join(dotfiles, "hooks.json"), join(h, "hooks.json"));
    installCommand({ pinFile: pinPath(), env: {}, codexHome: h, node: "node", script: "/opt/p2p/bin/p2p.mjs", write: true, now: new Date(0) });
    expect(lstatSync(join(h, "config.toml")).isSymbolicLink()).toBe(true);
    expect(lstatSync(join(h, "hooks.json")).isSymbolicLink()).toBe(true);
    expect(readFileSync(join(dotfiles, "config.toml"), "utf8")).toContain("[mcp_servers.peer2peer]");
    expect(readFileSync(join(dotfiles, "hooks.json"), "utf8")).toContain(HOOK_MARKER);
    expect(readFileSync(join(dotfiles, "config.toml.p2p-backup-1970-01-01T00-00-00-000Z"), "utf8")).toBe(USER_CONFIG);
  });

  it("forwards CODEX_HOME so the bridge finds its own rollout file", () => {
    expect(configBlock(plan("/h"))).toContain('"CODEX_HOME"');
  });

  it("replaceBlock appends, replaces and removes", () => {
    const once = replaceBlock("a = 1\n", BEGIN, END, `${BEGIN}\nx\n${END}`);
    expect(once).toBe(`a = 1\n\n${BEGIN}\nx\n${END}\n`);
    expect(replaceBlock(once, BEGIN, END, `${BEGIN}\ny\n${END}`)).toBe(`a = 1\n\n${BEGIN}\ny\n${END}\n`);
    expect(replaceBlock(once, BEGIN, END, null)).toBe("a = 1\n");
  });
});
