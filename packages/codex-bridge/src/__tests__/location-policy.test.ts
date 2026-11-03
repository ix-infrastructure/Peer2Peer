// Copyright 2026 Ix Infrastructure Inc.
//
// Follow-ups to a pre-release review: a project config can set HOME, TMPDIR and
// the server's cwd in `[mcp_servers.peer2peer.env]` (and, Codex merging
// `mcp_servers` from trusted project layers, replace the server outright).
// The bridge takes the home folder from the user database, the macOS temp
// folder from confstr, checks the EFFECTIVE Codex home and P2P_HOME every
// time, and refuses outright when a project config touches its table.

import { chmodSync, mkdirSync, mkdtempSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { installCommand } from "../commands.js";
import { darwinUserTempDir, effectiveEnv, envFromPs, homeRefusal, parentCwd, parentEnvValue, projectConfigDirsOf, readPins, realish, tempRoots, touchesTable, unsafeLocation, userHome, writePin } from "../knobs.js";
import { safeTmp } from "./net.js";
import { ANN, makeBridge, ME, message, World } from "./world.js";

const ME_ADDR = "me@meme-meme-meme-meme";
const dirs: string[] = [];
const keep = (d: string) => (dirs.push(d), d);
const tmp = (name: string) => keep(mkdtempSync(join(tmpdir(), name)));
/** A stand-in for the person's home folder, outside every temp folder. */
const fakeHome = () => keep(safeTmp("home-"));
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const userConfig = (table: Record<string, string>) => ["[mcp_servers.peer2peer.env]", ...Object.entries(table).map(([k, v]) => `${k} = ${JSON.stringify(v)}`)].join("\n") + "\n";
const noParent = async (): Promise<string | undefined> => undefined;

describe("HOME from a project config (the pre-release bypass)", () => {
  it("the macOS PoC: HOME under the user temp folder, TMPDIR=/nonexistent, CODEX_HOME empty: no auto-deliver, everything held", async () => {
    const userTemp = darwinUserTempDir() ?? tmpdir();
    const planted = keep(mkdtempSync(join(userTemp, "h-")));
    mkdirSync(join(planted, ".codex"));
    writeFileSync(join(planted, ".codex", "config.toml"), userConfig({ P2P_AUTO_DELIVER: ANN, P2P_HOME: join(planted, "p2p") }));
    const home = fakeHome();
    const r = await effectiveEnv({ env: { HOME: planted, TMPDIR: "/nonexistent", CODEX_HOME: "", P2P_AUTO_DELIVER: ANN }, projectDirs: ["/repo"], parentValue: noParent, home });
    // ~ comes from the user database, so the planted config is never read...
    expect(r.codexHome).toBe(join(home, ".codex"));
    expect(r.env.P2P_AUTO_DELIVER).toBeUndefined();
    expect(r.env.P2P_HOME).toBe(join(home, ".p2p"));
    // ...and a HOME that isn't the person's makes the bridge hold everything.
    expect(r.refusal).toContain(`HOME=${planted} isn't your home folder`);
    expect(r.warnings.join("\n")).toContain("holding every message and refusing every release");
    // TMPDIR=/nonexistent doesn't take the real temp folder out of the temp roots.
    expect(unsafeLocation(join(planted, ".codex"), { temp: tempRoots(["/nonexistent"]), projectDirs: [] })).toContain("the temp folder");

    // The bridge, even handed the planted settings, delivers nothing and releases nothing.
    const { bridge, feed, call, asking } = await makeBridge({ env: { P2P_AUTO_DELIVER: ANN }, refusal: r.refusal as string, codexHome: r.codexHome, p2pHome: r.p2pHome });
    await asking();
    await feed(message({ text: "auto-deliver me" }));
    await feed(message({ text: "from my laptop", self: true, from: ME, address: ME_ADDR }));
    expect((await call("p2p_inbox")).text).not.toMatch(/auto-deliver me|from my laptop/);
    expect(bridge.heldList()).toHaveLength(2);
    expect(bridge.releaseReach(r.p2pHome)).toMatchObject({ ok: false });
    // An item released earlier still doesn't go out.
    (bridge.inbox[0] as { state: string }).state = "released";
    expect(bridge.takeDeliverable({ startsTurn: false })).toEqual([]);
  });

  it.skipIf(process.platform === "win32")("userHome comes from the user database; HOME pointing elsewhere (even into ~/.codex/memories) is refused", () => {
    const saved = process.env.HOME;
    try {
      process.env.HOME = "/tmp/elsewhere";
      expect(userHome()).toBe(userInfo().homedir);
    } finally {
      process.env.HOME = saved;
    }
    const home = fakeHome();
    expect(homeRefusal({ HOME: home }, home)).toBeUndefined();
    expect(homeRefusal({}, home)).toBeUndefined();
    expect(homeRefusal({ HOME: join(home, ".codex", "memories", "h") }, home)).toContain("isn't your home folder");
  });

  it.skipIf(process.platform !== "darwin")("macOS: the per-user temp folder comes from confstr, which TMPDIR can't change", () => {
    expect(realish(darwinUserTempDir() as string)).toBe(realish(tmpdir()));
    expect(tempRoots()).toContain(darwinUserTempDir());
  });
});

describe("the effective Codex home and P2P_HOME are checked every time", () => {
  it("no CODEX_HOME given: a default Codex home or P2P_HOME in a temp folder refuses", async () => {
    const tmpHome = tmp("home-in-tmp-");
    const r = await effectiveEnv({ env: {}, projectDirs: [], parentValue: noParent, home: tmpHome });
    expect(r.refusal).toMatch(/the Codex home isn't safe: .*inside the temp folder/);
    const home = fakeHome();
    mkdirSync(join(home, ".codex"));
    writeFileSync(join(home, ".codex", "config.toml"), userConfig({ P2P_HOME: join(tmp("p2p-"), "home") }));
    const p = await effectiveEnv({ env: {}, projectDirs: [], parentValue: noParent, home });
    expect(p.refusal).toMatch(/P2P_HOME isn't safe: .*inside the temp folder/);
  });

  it("folders Codex lets the sandbox write (memories) are refused for CODEX_HOME and P2P_HOME", async () => {
    const home = fakeHome();
    const mem = join(home, ".codex", "memories", "h");
    mkdirSync(mem, { recursive: true });
    const given = await effectiveEnv({ env: { CODEX_HOME: mem }, projectDirs: [], parentValue: async () => mem, home });
    expect(given.codexHome).toBe(join(home, ".codex"));
    expect(given.warnings[0]).toContain("a folder Codex lets the sandbox write");
    writeFileSync(join(home, ".codex", "config.toml"), userConfig({ P2P_HOME: join(home, ".codex", "memories_v2", "p") }));
    const p = await effectiveEnv({ env: {}, projectDirs: [], parentValue: noParent, home });
    expect(p.refusal).toMatch(/P2P_HOME isn't safe: .*a folder Codex lets the sandbox write/);
  });

  it("a world-writable Codex home refuses (symlinked config.toml: see rereview-lows.test.ts)", async () => {
    const home = fakeHome();
    mkdirSync(join(home, ".codex"));
    chmodSync(join(home, ".codex"), 0o777);
    expect((await effectiveEnv({ env: {}, projectDirs: [], parentValue: noParent, home })).refusal).toContain("world-writable");
  });

  it("the person's own homes: no refusal", async () => {
    const home = fakeHome();
    mkdirSync(join(home, ".codex"), { mode: 0o700 });
    const r = await effectiveEnv({ env: { HOME: home }, projectDirs: ["/repo"], parentValue: noParent, home });
    expect(r.refusal).toBeUndefined();
    expect(r.warnings).toEqual([]);
  });
});

describe("a project config that touches mcp_servers.peer2peer (a trusted repo can replace the server)", () => {
  const withProject = (config: string) => {
    const proj = keep(safeTmp("proj-"));
    mkdirSync(join(proj, ".codex"));
    writeFileSync(join(proj, ".codex", "config.toml"), config);
    return proj;
  };
  const refusalFor = async (config: string) => {
    const proj = withProject(config);
    return (await effectiveEnv({ env: {}, projectDirs: [proj], parentValue: noParent, home: fakeHome(), projectConfigDirs: [proj] })).refusal;
  };

  it("command, args, cwd, env.PATH or an inline table: refused, with a warning", async () => {
    for (const c of ['[mcp_servers.peer2peer]\ncwd = "/elsewhere"\n', '[mcp_servers.peer2peer.env]\nPATH = "/evil"\n', 'mcp_servers.peer2peer.command = "/evil"\n', "[mcp_servers]\npeer2peer = { args = [\"x\"] }\n", 'mcp_servers = { peer2peer = { command = "x" } }\n', "[mcp_servers.peer2peer\n"]) {
      expect(await refusalFor(c), c).toMatch(/sets mcp_servers\.peer2peer/);
    }
  });

  it("other servers, comments and unrelated keys: fine", async () => {
    expect(await refusalFor('[mcp_servers.other]\ncommand = "x"\n# peer2peer is great\nmodel = "gpt-5"\n')).toBeUndefined();
    expect(touchesTable('instructions = """\n[mcp_servers.peer2peer]\n"""\n', ["mcp_servers", "peer2peer"])).toBe(false);
  });

  it("the person's own Codex home (cwd = ~) isn't a project layer", async () => {
    const home = fakeHome();
    mkdirSync(join(home, ".codex"), { mode: 0o700 });
    writeFileSync(join(home, ".codex", "config.toml"), '[mcp_servers.peer2peer]\ncommand = "node"\n');
    const r = await effectiveEnv({ env: {}, projectDirs: [], parentValue: noParent, home, projectConfigDirs: [home] });
    expect(r.refusal).toBeUndefined();
  });

  it("project layers: the cwd and each parent up to the repo root", () => {
    expect(projectConfigDirsOf("/r/a/b", "/r")).toEqual(["/r/a/b", "/r/a", "/r"]);
    expect(projectConfigDirsOf("/r", "/r")).toEqual(["/r"]);
    expect(projectConfigDirsOf("/x/y", undefined)).toEqual(["/x/y"]);
    expect(projectConfigDirsOf("/x/y", "/r")).toEqual(["/x/y"]);
  });
});

describe("the project comes from what a project config can't move", () => {
  it.skipIf(process.platform === "win32")("Codex's own cwd is read from the OS", async () => {
    expect(realish((await parentCwd(process.pid)) as string)).toBe(realish(process.cwd()));
  });

  it("every cwd a trusted rollout declares stays project, even after the session moves on; released items then stay put", async () => {
    const world = new World();
    world.trusted = { mode: { approval: "on-request", sandbox: "read-only", autoReview: false }, seq: 1, writable: ["/somewhere/else"] };
    const { bridge, feed } = await makeBridge({ world, codexHome: "/Users/ann/.codex", p2pHome: "/Users/ann/web/.p2p" });
    bridge.noteToolCall({ threadId: "thread-1", mode: { sandbox: "read-only", autoReview: false } });
    await bridge.refreshTrusted();
    expect(bridge.locationRefusal()).toBeUndefined();
    await feed(message({ text: "released early" }));
    (bridge.inbox[0] as { state: string }).state = "released";
    world.trusted = { ...world.trusted, seq: 2, cwd: "/Users/ann/web" };
    await bridge.refreshTrusted();
    world.trusted = { ...world.trusted, seq: 3, cwd: "/Users/ann/other" };
    await bridge.refreshTrusted();
    expect(bridge.locationRefusal()).toContain("the project /Users/ann/web");
    expect(bridge.takeDeliverable({ startsTurn: false })).toEqual([]);
  });
});

describe("lows", () => {
  it("the installer writes node by absolute path (process.execPath), never a bare `node`", () => {
    const codexHome = tmp("codex-home-");
    for (const node of [undefined, "node"]) {
      const r = installCommand({ env: {}, codexHome, ...(node ? { node } : {}), script: "/opt/p2p.mjs" });
      expect((r.json as { plan: { node: string } }).plan.node).toBe(process.execPath);
      expect(r.human).toContain(`command = ${JSON.stringify(process.execPath)}`);
    }
  });

  it.skipIf(process.platform !== "darwin" && process.platform !== "linux")("the parent's environment is read through /bin/ps or /proc (here: this very process)", async () => {
    expect(await parentEnvValue("P2P_SURELY_NOT_SET_ANYWHERE", process.pid)).toBeNull();
  });

  it("ps -E: a second ` CODEX_HOME=` anywhere in the environment means can't tell", () => {
    const cmd = "/usr/local/bin/codex";
    expect(envFromPs(`${cmd} HOME=/h FOO=x CODEX_HOME=/a CODEX_HOME=/a`, cmd, "CODEX_HOME")).toBeUndefined();
    expect(envFromPs(`${cmd} HOME=/h CODEX_HOME=/a`, cmd, "CODEX_HOME")).toBe("/a");
  });

  it.skipIf(process.platform === "win32")("pins: the P2P home and its codex/ must be real, private folders; writePin tightens them to 0700", () => {
    const base = fakeHome();
    const p2p = join(base, ".p2p");
    const pin = join(p2p, "codex", "codex-homes");
    mkdirSync(join(p2p, "codex"), { recursive: true, mode: 0o755 });
    chmodSync(p2p, 0o755);
    expect(writePin("/Users/ann/.codex-work", { file: pin })).toBe(true);
    expect(statSync(p2p).mode & 0o777).toBe(0o700);
    expect(statSync(join(p2p, "codex")).mode & 0o777).toBe(0o700);
    expect(readPins(pin)).toEqual(["/Users/ann/.codex-work"]);
    chmodSync(p2p, 0o775);
    expect(readPins(pin)).toEqual([]);
    chmodSync(p2p, 0o700);
    // A symlinked codex/ folder: nothing read, nothing written through it.
    const real = join(base, "real-codex");
    mkdirSync(real, { mode: 0o700 });
    writeFileSync(join(real, "codex-homes"), "/Users/ann/.codex-work\n", { mode: 0o600 });
    const p2p2 = join(base, "p2p2");
    mkdirSync(p2p2, { mode: 0o700 });
    symlinkSync(real, join(p2p2, "codex"));
    expect(readPins(join(p2p2, "codex", "codex-homes"))).toEqual([]);
    expect(() => writePin("/x", { file: join(p2p2, "codex", "codex-homes") })).toThrow(/symbolic link/);
  });
});
