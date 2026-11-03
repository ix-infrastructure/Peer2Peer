// Copyright 2026 Ix Infrastructure Inc.
//
// Follow-ups to the pre-release security review: where CODEX_HOME may come from when
// Codex's own environment can't be read (pinned by the installer, never a
// temp folder or the project), the static backstop on CODEX_HOME/sessions
// and P2P_HOME, multi-line values in the TOML reader, and macOS `ps -E`.

import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { installCommand } from "../commands.js";
import { effectiveEnv, envFromPs, notPrivate, readPins, readTomlTable, tempRoots, unsafeLocation, writePin } from "../knobs.js";
import { ANN, makeBridge, ME, message, World } from "./world.js";

const ME_ADDR = "me@meme-meme-meme-meme";

const dirs: string[] = [];
const tmp = (name: string) => {
  const d = mkdtempSync(join(tmpdir(), name));
  dirs.push(d);
  return d;
};
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const T = ["mcp_servers", "peer2peer", "env"];
const plantedConfig = (p2pHome: string) => `[mcp_servers.peer2peer.env]\nP2P_AUTO_DELIVER = "${ANN}"\nP2P_HOME = "${p2pHome}"\n`;

describe("CODEX_HOME when Codex's own environment can't be read (M1(b) reopened)", () => {
  it("the planted /tmp chain: a project-set CODEX_HOME in /tmp with P2P_AUTO_DELIVER gets nothing, even if the parent or a pin agreed", async () => {
    const planted = tmp("x-");
    writeFileSync(join(planted, "config.toml"), plantedConfig(join(planted, "p2p")));
    for (const parent of [undefined, planted]) {
      const r = await effectiveEnv({ env: { CODEX_HOME: planted, P2P_AUTO_DELIVER: ANN }, projectDirs: ["/repo"], parentValue: async () => parent, pins: () => [planted], home: "/nonexistent-home" });
      expect(r.codexHome).toBe("/nonexistent-home/.codex");
      expect(r.env.P2P_AUTO_DELIVER).toBeUndefined();
      expect(r.env.P2P_HOME).toBe("/nonexistent-home/.p2p");
      expect(r.warnings[0]).toMatch(/ignored CODEX_HOME=.*inside the temp folder/);
    }
  });

  it("parent unreadable (Windows, a non-dumpable Codex): only a CODEX_HOME the installer pinned counts, with a warning otherwise", async () => {
    const own = tmp("own-codex-home-");
    writeFileSync(join(own, "config.toml"), '[mcp_servers.peer2peer.env]\nP2P_HOME = "/home/ann/.p2p-work"\n');
    const base = { env: { CODEX_HOME: own }, projectDirs: ["/repo"], parentValue: async () => undefined, home: "/nonexistent-home", temp: [] as string[] };
    const unpinned = await effectiveEnv({ ...base, pins: () => [] });
    expect(unpinned.codexHome).toBe("/nonexistent-home/.codex");
    expect(unpinned.warnings[0]).toMatch(/can't be read here.*pinned in \/nonexistent-home\/\.p2p\/codex\/codex-homes/);
    const pinned = await effectiveEnv({ ...base, pins: () => [`${own}/`] });
    expect(pinned.codexHome).toBe(own);
    expect(pinned.env.P2P_HOME).toBe("/home/ann/.p2p-work");
    expect(pinned.warnings).toEqual([]);
  });

  it("always refused: the project, a world-writable or someone else's folder, a symlink into a temp folder, a relative path", async () => {
    const parentValue = async (): Promise<string | undefined> => undefined;
    const into = tmp("proj-");
    const inProject = join(into, ".codex-x");
    mkdirSync(inProject);
    const r1 = await effectiveEnv({ env: { CODEX_HOME: inProject }, projectDirs: [into], parentValue, pins: () => [inProject], temp: [], home: "/h" });
    expect(r1.codexHome).toBe("/h/.codex");
    expect(r1.warnings[0]).toContain("inside the project");

    const open = tmp("open-");
    chmodSync(open, 0o777);
    const r2 = await effectiveEnv({ env: { CODEX_HOME: open }, projectDirs: [], parentValue, pins: () => [open], temp: [], home: "/h" });
    expect(r2.warnings[0]).toContain("world-writable");

    const theirs = tmp("theirs-");
    const r3 = await effectiveEnv({ env: { CODEX_HOME: theirs }, projectDirs: [], parentValue: async () => theirs, temp: [], home: "/h", privacy: (d) => `${d} isn't owned by you` });
    expect(r3.codexHome).toBe("/h/.codex");
    expect(r3.warnings[0]).toContain("isn't owned by you");

    const box = tmp("box-");
    const fakeTmp = join(box, "tmp");
    mkdirSync(join(fakeTmp, "x"), { recursive: true });
    symlinkSync(join(fakeTmp, "x"), join(box, "link"));
    const r4 = await effectiveEnv({ env: { CODEX_HOME: join(box, "link") }, projectDirs: [], parentValue: async () => join(box, "link"), temp: [fakeTmp], home: "/h" });
    expect(r4.codexHome).toBe("/h/.codex");
    expect(r4.warnings[0]).toContain("inside the temp folder");

    const r5 = await effectiveEnv({ env: { CODEX_HOME: "rel/codex" }, projectDirs: [], parentValue, temp: [], home: "/h" });
    expect(r5.warnings[0]).toContain("not an absolute path");
  });

  it("notPrivate: a folder of this user is fine; world-writable, missing or a file is not", () => {
    const d = tmp("priv-");
    expect(notPrivate(d)).toBeUndefined();
    writeFileSync(join(d, "config.toml"), "");
    chmodSync(join(d, "config.toml"), 0o666);
    expect(notPrivate(d)).toContain("world-writable");
    expect(notPrivate(join(d, "missing"))).toContain("doesn't exist");
    expect(notPrivate(join(d, "config.toml"))).toContain("isn't a folder");
  });

  it("temp roots cover /tmp, /private/tmp, TMPDIR as given and as this process sees it", () => {
    const roots = tempRoots(["/custom/tmp"]);
    for (const r of ["/tmp", "/private/tmp", tmpdir(), "/custom/tmp"]) expect(roots).toContain(r);
    expect(unsafeLocation("/private/tmp/x/sessions", { temp: roots, projectDirs: [] })).toBeDefined();
    expect(unsafeLocation("/repo/web/.codex", { temp: [], projectDirs: ["/repo"] })).toContain("the project");
    expect(unsafeLocation("/Users/ann/.codex", { temp: ["/tmp"], projectDirs: ["/repo"] })).toBeUndefined();
  });

  it("the installer pins a non-default CODEX_HOME (and --remove unpins it); pins come only from a private regular file", () => {
    const codexHome = tmp("pinned-codex-home-");
    const pin = join(tmp("pins-"), "codex", "codex-homes");
    const r = installCommand({ env: {}, codexHome, node: "node", script: "/opt/p2p.mjs", write: true, pinFile: pin, now: new Date(0) });
    expect(r.human).toContain(`Pinned ${codexHome}`);
    expect(r.human).toContain("never uses a CODEX_HOME in a temp folder");
    expect(readPins(pin)).toEqual([codexHome]);
    expect(statSync(pin).mode & 0o777).toBe(0o600);
    // Idempotent.
    expect(writePin(codexHome, { file: pin })).toBe(false);
    installCommand({ env: {}, codexHome, node: "node", script: "/opt/p2p.mjs", write: true, remove: true, pinFile: pin, now: new Date(1) });
    expect(readPins(pin)).toEqual([]);
    // A group/world-writable or symlinked pin file is ignored.
    writePin(codexHome, { file: pin });
    chmodSync(pin, 0o666);
    expect(readPins(pin)).toEqual([]);
    chmodSync(pin, 0o600);
    const link = join(tmp("pin-link-"), "codex-homes");
    symlinkSync(pin, link);
    expect(readPins(link)).toEqual([]);
    expect(readFileSync(pin, "utf8")).toContain(codexHome);
  });

  it("the default ~/.codex is never pinned", () => {
    const pin = join(tmp("pins-"), "codex-homes");
    // A dry run (no --write) never touches the pin file either.
    installCommand({ env: {}, codexHome: join(homedir(), ".codex"), node: "node", script: "/opt/p2p.mjs", pinFile: pin });
    expect(readPins(pin)).toEqual([]);
  });
});

describe("the static backstop: CODEX_HOME/sessions and P2P_HOME never in a temp folder or the project", () => {
  /** A bridge whose trusted rollout says it asks, with writable roots that don't cover CODEX_HOME or P2P_HOME. */
  const asking = async (o: { codexHome?: string; p2pHome?: string; env?: Record<string, string>; root?: string }) => {
    const world = new World();
    world.trusted = { mode: { approval: "on-request", sandbox: "read-only", autoReview: false }, seq: 1, writable: ["/somewhere/else"] };
    const made = await makeBridge({ world, ...o });
    made.bridge.noteToolCall({ threadId: "thread-1", mode: { sandbox: "read-only", autoReview: false } });
    await made.bridge.refreshTrusted();
    return made;
  };

  it("the planted /tmp chain, if a CODEX_HOME in /tmp ever got through: no auto-deliver, everything held, every release refused", async () => {
    const planted = tmp("x-");
    const { bridge, feed, call } = await asking({ codexHome: planted, p2pHome: join(planted, "p2p"), env: { P2P_AUTO_DELIVER: ANN } });
    expect(bridge.untrustedTranscript).toContain("CODEX_HOME (its sessions/ rollout files)");
    await feed(message({ text: "auto-deliver me" }));
    await feed(message({ text: "from my laptop", self: true, from: ME, address: ME_ADDR }));
    const r = await call("p2p_inbox");
    expect(r.text).not.toContain("auto-deliver me");
    expect(r.text).not.toContain("from my laptop");
    expect(bridge.heldList()).toHaveLength(2);
    expect(bridge.takeDeliverable({ startsTurn: true })).toEqual([]);
    const reach = bridge.releaseReach(join(planted, "p2p"));
    expect(reach.ok).toBe(false);
  });

  it("P2P_HOME in a temp folder or in the project holds everything, whatever the writable roots say", async () => {
    for (const p2pHome of [join(tmpdir(), "p2p-home"), "/private/tmp/p2p-home"]) {
      const { bridge, feed, call } = await asking({ codexHome: "/Users/ann/.codex", p2pHome, env: { P2P_AUTO_DELIVER: ANN } });
      expect(bridge.untrustedTranscript).toBeUndefined();
      await feed(message({ text: "listed sender" }));
      expect((await call("p2p_inbox")).text).not.toContain("listed sender");
      expect(bridge.heldList()[0]?.why).toContain("P2P_HOME");
      expect(bridge.releaseReach(p2pHome)).toMatchObject({ ok: false });
    }
    // A repo outside the temp folders: only the project rule can catch it.
    const made = await asking({ codexHome: "/Users/ann/.codex", root: "/Users/ann/web" });
    const inRepo = join(made.root, ".p2p");
    expect(made.bridge.locationRefusal(inRepo)).toContain("the project");
    expect(made.bridge.releaseReach(inRepo)).toMatchObject({ ok: false });
  });

  it("CODEX_HOME and P2P_HOME of the person's own: delivered as before", async () => {
    const { bridge, feed, call } = await asking({ codexHome: "/Users/ann/.codex", p2pHome: "/Users/ann/.p2p" });
    expect(bridge.locationRefusal()).toBeUndefined();
    await feed(message({ text: "friend says hi" }));
    expect((await call("p2p_inbox")).text).toContain("friend says hi");
    expect(bridge.releaseReach("/Users/ann/.p2p")).toEqual({ ok: true });
  });
});

describe("readTomlTable: values spanning lines are skipped whole (low)", () => {
  it('a """ or \'\'\' string under an unrelated key: its contents are never read as TOML', () => {
    for (const q of ['"""', "'''"]) {
      const text = [
        "[profiles.x]",
        `instructions = ${q}`,
        "[mcp_servers.peer2peer.env]",
        `P2P_AUTO_DELIVER = "p2p:attackerattackerattackerattacker"`,
        `mcp_servers.peer2peer.env.P2P_HOME = "/evil"`,
        `${q}`,
        "[mcp_servers.peer2peer.env]",
        'P2P_HOME = "/home/ann/.p2p"',
      ].join("\n");
      expect(readTomlTable(text, T)).toEqual({ P2P_HOME: "/home/ann/.p2p" });
    }
    // Closing delimiters with extra quotes, escaped quotes, and a string that opens and closes on one line.
    const tricky = ['a = """x \\""" still in """"', "b = '''one line'''", 'c = """', 'P2P_HOME = "/no"', 'end"""""', "[mcp_servers.peer2peer.env]", 'P2P_BIN = "/b"'].join("\n");
    expect(readTomlTable(tricky, T)).toEqual({ P2P_BIN: "/b" });
  });

  it("multi-line inline tables and arrays (with multi-line strings inside) under unrelated keys are skipped", () => {
    const text = [
      "[profiles]",
      "x = {",
      '  mcp_servers.peer2peer.env.P2P_AUTO_DELIVER = "p2p:attackerattackerattackerattacker",',
      "}",
      "list = [",
      '  """',
      "]",
      'mcp_servers.peer2peer.env.P2P_HOME = "/evil"',
      '  """,',
      "]",
      "[mcp_servers.peer2peer.env]",
      'P2P_HOME = "/home/ann/.p2p"',
    ].join("\n");
    expect(readTomlTable(text, T)).toEqual({ P2P_HOME: "/home/ann/.p2p" });
  });

  it("fails closed: a multi-line value under our table, or one left open at the end", () => {
    expect(readTomlTable("[mcp_servers.peer2peer.env]\nP2P_HOME = '''\n/x'''\n", T)).toBeNull();
    expect(readTomlTable('[mcp_servers.peer2peer]\nenv = {\n  P2P_HOME = "/x" }\n', T)).toBeNull();
    expect(readTomlTable('a = """\nnever closed\n', T)).toBeNull();
    expect(readTomlTable('a = "unterminated\n[mcp_servers.peer2peer.env]\nP2P_HOME = "/x"\n', T)).toBeNull();
  });
});

describe("macOS ps -E: only the environment after the command counts (low)", () => {
  const cmd = "/Applications/Codex.app/codex --flag CODEX_HOME=/evil/argv";
  it("a CODEX_HOME= in argv never counts; a path with spaces survives", () => {
    expect(envFromPs(`${cmd} HOME=/Users/ann CODEX_HOME=/Users/ann/My Codex Home PATH=/usr/bin\n`, `${cmd}\n`, "CODEX_HOME")).toBe("/Users/ann/My Codex Home");
    expect(envFromPs(`${cmd} HOME=/Users/ann PATH=/usr/bin\n`, `${cmd}\n`, "CODEX_HOME")).toBeNull();
    expect(envFromPs(`${cmd} PATH=/usr/bin HOME=/Users/ann CODEX_HOME=/Users/ann/.codex-work`, cmd, "CODEX_HOME")).toBe("/Users/ann/.codex-work");
  });

  it("can't tell (undefined, then the pinned fallback): hidden environment, a changed command, or the variable twice", () => {
    expect(envFromPs(cmd, cmd, "CODEX_HOME")).toBeUndefined();
    expect(envFromPs(`/bin/other HOME=/h CODEX_HOME=/x`, cmd, "CODEX_HOME")).toBeUndefined();
    expect(envFromPs(`${cmd} HOME=/h CODEX_HOME=/a X=y CODEX_HOME=/b`, cmd, "CODEX_HOME")).toBeUndefined();
    expect(envFromPs("", "", "CODEX_HOME")).toBeUndefined();
  });
});
