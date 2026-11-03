// Copyright 2026 Ix Infrastructure Inc.
//
// A pre-release re-review: the project-override detector on every spelling,
// helper programs by absolute path with a scrubbed environment, Codex's cwd
// failing closed, and two usability fixes (symlinked user config, a home
// folder that is a git repo).

import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { childEnv, cwdPolicy, effectiveEnv, gitBinary, isHomeFolder, notPrivate, safeBinary, safeExecEnv, SAFE_PATH_DIRS, touchesTable, userHome } from "../knobs.js";
import { childWatch, codexQueue, gitIn } from "../server.js";
import { nodeExec } from "../p2p.js";
import { safeTmp } from "./net.js";
import { makeBridge, message, World } from "./world.js";

const dirs: string[] = [];
const keep = (d: string) => (dirs.push(d), d);
const tmp = (name: string) => keep(mkdtempSync(join(tmpdir(), name)));
const safe = (name: string) => keep(safeTmp(name));
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const T = ["mcp_servers", "peer2peer"];
const noParent = async (): Promise<string | undefined> => undefined;

describe("the project-override detector fails closed on every spelling", () => {
  it.each([
    ["a quoted key with an array", '[mcp_servers]\n"peer2peer".args = ["x"]\n'],
    ["a \\u-escaped key with an array", '[mcp_servers]\n"peer\\u0032peer".args = ["x"]\n'],
    ["an escaped header with a \"\"\" value", '[mcp_servers."peer\\u0032peer"]\ncommand = """/evil"""\n'],
    ["an escaped key with an inline table holding \"\"\"", '[mcp_servers]\n"peer\\u0032peer" = { command = """/evil""" }\n'],
    ["a dotted escaped key with a \"\"\" value", 'mcp_servers."peer\\u0032peer".command = """/evil"""\n'],
    ["a nested inline table with an escaped key and an array", 'mcp_servers = { "peer\\u0032peer" = { args = ["x"] } }\n'],
    ["an inline table with an array", '[mcp_servers]\npeer2peer = { command = "x", args = ["a"] }\n'],
    ["a literal-quoted key", "[mcp_servers]\n'peer2peer'.cwd = '/x'\n"],
    ["a \\U-escaped header", '[mcp_servers."\\U00000070eer2peer"]\ncwd = "/x"\n'],
    ["spaces around dots", '[ mcp_servers . peer2peer ]\ncwd = "/x"\n'],
    ["an array of tables", '[[mcp_servers.peer2peer]]\ncommand = "x"\n'],
    ["a multi-line inline table", '[mcp_servers]\npeer2peer = {\n  command = "x" }\n'],
    ["a byte-order mark in front", '\uFEFF[mcp_servers.peer2peer]\ncwd = "/x"\n'],
    ["text the reader can't parse at all", '[mcp_servers\npeer2peer = 1\n'],
  ])("%s", (_name, text) => {
    expect(touchesTable(text, T)).toBe(true);
  });

  it("other servers, comments and unrelated multi-line values don't count", () => {
    expect(touchesTable('[mcp_servers.other]\ncommand = "x"\nargs = ["a"]\n# peer2peer\n', T)).toBe(false);
    expect(touchesTable('model = "gpt-5"\ninstructions = """\n[mcp_servers.peer2peer]\n"""\n', T)).toBe(false);
  });
});

describe("helper programs: absolute paths and a scrubbed environment", () => {
  it.skipIf(process.platform === "win32")("safeExecEnv holds a fixed system PATH and no GIT_* or loader variables", () => {
    const env = safeExecEnv();
    expect(Object.keys(env).sort()).toEqual(["HOME", "LC_ALL", "PATH"]);
    expect(env.PATH).toBe(SAFE_PATH_DIRS.join(":"));
    expect(env.HOME).toBe(userHome());
  });

  it.skipIf(process.platform === "win32" || !gitBinary())("gitIn runs git by absolute path, ignoring a PATH and GIT_DIR the server's env holds", async () => {
    const repo = tmp("repo-");
    execFileSync(gitBinary() as string, ["init", "-q", repo], { env: safeExecEnv() });
    const fake = tmp("fake-bin-");
    const marker = join(fake, "ran");
    writeFileSync(join(fake, "git"), `#!/bin/sh\ntouch '${marker}'\necho /evil\n`, { mode: 0o755 });
    const saved = { PATH: process.env.PATH, GIT_DIR: process.env.GIT_DIR };
    try {
      process.env.PATH = fake;
      process.env.GIT_DIR = "/nonexistent";
      const top = await gitIn()(repo, ["rev-parse", "--show-toplevel"]);
      expect(top && existsSync(top)).toBeTruthy();
      expect(top).not.toBe("/evil");
      expect(existsSync(marker)).toBe(false);
      // A binary that isn't there: nothing runs.
      expect(await gitIn("/nonexistent/git")(repo, ["rev-parse", "--show-toplevel"])).toBeUndefined();
    } finally {
      process.env.PATH = saved.PATH;
      if (saved.GIT_DIR === undefined) delete process.env.GIT_DIR;
      else process.env.GIT_DIR = saved.GIT_DIR;
    }
  });

  it.skipIf(process.platform === "win32")("safeBinary never looks in the env's PATH", () => {
    const fake = tmp("fake-bin-");
    writeFileSync(join(fake, "p2p-surely-not-a-system-tool"), "#!/bin/sh\n", { mode: 0o755 });
    expect(safeBinary("p2p-surely-not-a-system-tool")).toBeUndefined();
    expect(safeBinary("p2p-surely-not-a-system-tool", [fake])).toBe(join(fake, "p2p-surely-not-a-system-tool"));
    expect(safeBinary("ps")).toMatch(/^\/(usr\/)?s?bin\/ps$/);
  });

  it.skipIf(process.platform === "win32")("codex queue: P2P_CODEX_BIN only by absolute path; a relative one is never resolved through PATH", async () => {
    const fake = tmp("fake-codex-");
    const out = join(fake, "args");
    writeFileSync(join(fake, "codex"), `#!/bin/sh\necho "$1 $2 $3" > '${out}'\n`, { mode: 0o755 });
    const q = codexQueue({ P2P_CODEX_BIN: join(fake, "codex") });
    expect(q).toBeDefined();
    expect(await q?.("thread-1", "hi")).toBe(true);
    expect(existsSync(out)).toBe(true);
    const lines: string[] = [];
    const saved = process.env.PATH;
    try {
      process.env.PATH = fake;
      const rel = codexQueue({ P2P_CODEX_BIN: "codex", P2P_CODEX_QUEUE: "1", PATH: fake }, (l) => lines.push(l));
      // Whatever it found, it isn't the one on the env's PATH.
      if (rel) {
        rmSync(out);
        await rel("thread-1", "hi").catch(() => false);
        expect(existsSync(out)).toBe(false);
      } else expect(lines.join("\n")).toContain("set P2P_CODEX_BIN to its full path");
    } finally {
      process.env.PATH = saved;
    }
  });
});

describe("Codex's own cwd fails closed", () => {
  it("unknown: releases refused with a warning; moved without the user's config: everything held", () => {
    const unknown = cwdPolicy({ serverCwd: "/r", codexCwd: undefined });
    expect(unknown.releaseRefusal).toContain("can't be confirmed");
    expect(unknown.refusal).toBeUndefined();
    expect(unknown.warning).toContain("refusing releases");
    expect(cwdPolicy({ serverCwd: "/r", codexCwd: "/r" })).toEqual({});
    expect(cwdPolicy({ serverCwd: "/elsewhere", codexCwd: "/r", configuredCwd: "/elsewhere" })).toEqual({});
    const moved = cwdPolicy({ serverCwd: "/elsewhere", codexCwd: "/r" });
    expect(moved.refusal).toContain("not in Codex's working folder /r");
    expect(moved.warning).toContain("holding every message");
  });

  it("the user-level config's own cwd for the server is read", async () => {
    const home = safe("home-");
    mkdirSync(join(home, ".codex"), { mode: 0o700 });
    writeFileSync(join(home, ".codex", "config.toml"), '[mcp_servers.peer2peer]\ncwd = "/Users/ann/work"\n');
    expect((await effectiveEnv({ env: {}, projectDirs: [], parentValue: noParent, home })).serverCwd).toBe("/Users/ann/work");
  });

  it("a release refusal refuses releases while messages still flow", async () => {
    const world = new World();
    world.trusted = { mode: { approval: "on-request", sandbox: "read-only", autoReview: false }, seq: 1, writable: ["/somewhere/else"] };
    const { bridge, feed, call } = await makeBridge({ world, codexHome: "/Users/ann/.codex", p2pHome: "/Users/ann/.p2p", releaseRefusal: "Codex's own working folder can't be read here" });
    bridge.noteToolCall({ threadId: "thread-1", mode: { sandbox: "read-only", autoReview: false } });
    await bridge.refreshTrusted();
    await feed(message({ text: "friend says hi" }));
    expect((await call("p2p_inbox")).text).toContain("friend says hi");
    expect(bridge.releaseReach("/Users/ann/.p2p")).toMatchObject({ ok: false, reason: expect.stringContaining("can't be read here") });
  });
});

describe("usability: a symlinked user config (stow, chezmoi, Nix)", () => {
  const codexDirWithLink = (target: string) => {
    const home = safe("home-");
    mkdirSync(join(home, ".codex"), { mode: 0o700 });
    symlinkSync(target, join(home, ".codex", "config.toml"));
    return join(home, ".codex");
  };

  it.skipIf(process.platform === "win32")("a private target of the person's, or a read-only root-owned one: fine", () => {
    const dotfiles = safe("dotfiles-");
    writeFileSync(join(dotfiles, "config.toml"), "", { mode: 0o600 });
    expect(notPrivate(codexDirWithLink(join(dotfiles, "config.toml")), { where: { temp: ["/tmp"], projectDirs: ["/repo"] } })).toBeUndefined();
    // Like /nix/store: owned by root, writable by nobody else.
    if (existsSync("/etc/hosts")) expect(notPrivate(codexDirWithLink("/etc/hosts"))).toBeUndefined();
  });

  it.skipIf(process.platform === "win32")("a target in a temp folder or the project, writable by others, or dangling: refused", () => {
    const inTmp = join(tmp("dot-"), "config.toml");
    writeFileSync(inTmp, "", { mode: 0o600 });
    expect(notPrivate(codexDirWithLink(inTmp), { where: { temp: [tmpdir()], projectDirs: [] } })).toContain("the temp folder");
    const proj = safe("proj-");
    writeFileSync(join(proj, "config.toml"), "", { mode: 0o600 });
    expect(notPrivate(codexDirWithLink(join(proj, "config.toml")), { where: { temp: [], projectDirs: [proj] } })).toContain("the project");
    const open = join(safe("open-"), "config.toml");
    writeFileSync(open, "");
    chmodSync(open, 0o664);
    expect(notPrivate(codexDirWithLink(open))).toContain("a group or others can write");
    expect(notPrivate(codexDirWithLink(join(safe("gone-"), "missing.toml")))).toContain("to nothing readable");
  });

  it.skipIf(process.platform === "win32")("effectiveEnv: a stow-style link no longer holds everything", async () => {
    const home = safe("home-");
    const dotfiles = safe("dotfiles-");
    writeFileSync(join(dotfiles, "config.toml"), "", { mode: 0o600 });
    mkdirSync(join(home, ".codex"), { mode: 0o700 });
    symlinkSync(join(dotfiles, "config.toml"), join(home, ".codex", "config.toml"));
    expect((await effectiveEnv({ env: {}, projectDirs: ["/repo"], parentValue: noParent, home })).refusal).toBeUndefined();
  });
});

describe("usability: a home folder that is a git repo", () => {
  it("~ itself isn't a project root, but the cwd subtree is", async () => {
    const home = userHome();
    expect(isHomeFolder(home)).toBe(true);
    expect(isHomeFolder(join(home, "notes"))).toBe(false);
    // git reports ~ as the top for a cwd inside it (makeBridge's git answers `root` for every cwd).
    const { bridge } = await makeBridge({ root: home, cwd: join(home, "p2p-test-notes"), codexHome: join(home, ".codex"), p2pHome: join(home, ".p2p") });
    expect(bridge.locationRefusal()).toBeUndefined();
    expect(bridge.locationRefusal(join(home, "p2p-test-notes", ".p2p"))).toContain("the project");
  });
});

describe("child processes run without project-settable node and loader variables", () => {
  const LOADER = { NODE_OPTIONS: "--require /repo/evil.js", NODE_PATH: "/repo/mods", NODE_EXTRA_CA_CERTS: "/repo/ca.pem", LD_PRELOAD: "/repo/evil.so", LD_LIBRARY_PATH: "/repo/lib", LD_AUDIT: "/repo/a.so", DYLD_INSERT_LIBRARIES: "/repo/evil.dylib", DYLD_LIBRARY_PATH: "/repo/lib", node_options: "--require /repo/x.js" };
  const HOME_P2P = "/Users/ann/.p2p";

  it("childEnv drops them (and CODEX_HOME unless passed as extra), keeping P2P_*", () => {
    const out = childEnv({ ...LOADER, P2P_HOME: HOME_P2P, CODEX_HOME: "/Users/ann/.codex", PATH: "/usr/bin" });
    expect(Object.keys(out).sort()).toEqual(process.platform === "win32" ? ["P2P_HOME", "PATH", "USERPROFILE"] : ["HOME", "P2P_HOME", "PATH"]);
  });

  /** A script that exits 0 only when none of the variables reached it (and P2P_HOME did). */
  const checker = (dir: string) => {
    const vars = ["NODE_OPTIONS", "NODE_PATH", "NODE_EXTRA_CA_CERTS", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "node_options"];
    const p = join(dir, "check");
    writeFileSync(p, `#!/bin/sh\n${vars.map((v) => `[ -z "\${${v}+x}" ] || exit 7`).join("\n")}\n[ "$P2P_HOME" = ${HOME_P2P} ] || exit 8\nexit 0\n`, { mode: 0o755 });
    return p;
  };

  it.skipIf(process.platform === "win32")("p2p watch (childWatch) and codex queue get none of them", async () => {
    const check = checker(tmp("child-env-"));
    const env = { ...LOADER, P2P_HOME: HOME_P2P };
    const r = await childWatch(env)([check], () => {}, new AbortController().signal);
    expect(r.code).toBe(0);
    const q = codexQueue({ ...env, P2P_CODEX_BIN: check });
    expect(await q?.("thread-1", "hi")).toBe(true);
  });

  it.skipIf(process.platform === "win32")("the server's p2p runner (nodeExec over childEnv) gets none of them", async () => {
    const check = checker(tmp("child-env-"));
    const r = await nodeExec(childEnv({ ...LOADER, P2P_HOME: HOME_P2P })).run([check]);
    expect(r.exitCode).toBe(0);
  });
});
