// Copyright 2026 Ix Infrastructure Inc.
//
// A pre-release review: folders above a symlinked config's target, cwd = ~,
// the project-override scan for every cwd learned later, and child
// environments built from an allowlist.

import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { childEnv, effectiveEnv, ixBinOf, notPrivate, unsafeLocation, userHome } from "../knobs.js";
import { safeTmp } from "./net.js";
import { makeBridge, ME, message, World } from "./world.js";

const dirs: string[] = [];
const safe = (name: string) => {
  const d = safeTmp(name);
  dirs.push(d);
  return d;
};
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const noParent = async (): Promise<string | undefined> => undefined;

describe("a symlinked config.toml: every folder above the target", () => {
  const linkTo = (target: string) => {
    const home = safe("home-");
    mkdirSync(join(home, ".codex"), { mode: 0o700 });
    symlinkSync(target, join(home, ".codex", "config.toml"));
    return join(home, ".codex");
  };

  it.skipIf(process.platform === "win32")("a group- or world-writable folder above it without the sticky bit: refused; with the sticky bit: fine", () => {
    const base = safe("dotfiles-");
    const shared = join(base, "shared");
    mkdirSync(shared, { mode: 0o700 });
    const target = join(shared, "config.toml");
    writeFileSync(target, "", { mode: 0o600 });
    const codexDir = linkTo(target);
    expect(notPrivate(codexDir)).toBeUndefined();
    chmodSync(shared, 0o775);
    expect(notPrivate(codexDir)).toContain(`${shared} is group- or world-writable without the sticky bit`);
    chmodSync(shared, 0o1777);
    expect(notPrivate(codexDir)).toBeUndefined();
    chmodSync(shared, 0o700);
  });
});

describe("cwd exactly ~: the person's own config folders aren't project files", () => {
  it("~/.codex and ~/.p2p pass; anything else under ~ still counts as the project", () => {
    const home = safe("home-");
    const where = { projectDirs: [home], temp: [], home };
    expect(unsafeLocation(join(home, ".codex"), where)).toBeUndefined();
    expect(unsafeLocation(join(home, ".p2p"), where)).toBeUndefined();
    expect(unsafeLocation(join(home, "work", ".p2p"), where)).toContain("the project");
    // Only when the project dir IS the home folder: a project inside ~ never covers ~/.codex anyway, and one
    // that contains ~/.codex some other way (a project dir of ~/.codex itself) still counts.
    expect(unsafeLocation(join(home, ".codex"), { projectDirs: [join(home, ".codex")], temp: [], home })).toContain("the project");
  });

  it("effectiveEnv with cwd = ~: no refusal while the folders are private", async () => {
    const home = safe("home-");
    mkdirSync(join(home, ".codex"), { mode: 0o700 });
    expect((await effectiveEnv({ env: {}, projectDirs: [home], parentValue: noParent, home })).refusal).toBeUndefined();
    chmodSync(join(home, ".codex"), 0o777);
    expect((await effectiveEnv({ env: {}, projectDirs: [home], parentValue: noParent, home })).refusal).toContain("world-writable");
    chmodSync(join(home, ".codex"), 0o700);
  });

  it("the bridge with cwd = ~ (the real one): ~/.codex and ~/.p2p aren't refused; ~/somewhere/.p2p is", async () => {
    const home = userHome();
    const { bridge } = await makeBridge({ root: home, cwd: home, codexHome: join(home, ".codex"), p2pHome: join(home, ".p2p") });
    expect(bridge.locationRefusal()).toBeUndefined();
    expect(bridge.locationRefusal(join(home, "p2p-test-elsewhere", ".p2p"))).toContain("the project");
  });
});

describe("the project-override scan runs for every cwd the bridge learns", () => {
  const project = (config: string | null) => {
    const proj = safe("proj-");
    if (config !== null) {
      mkdirSync(join(proj, ".codex"));
      writeFileSync(join(proj, ".codex", "config.toml"), config);
    }
    return proj;
  };

  it("a later cwd whose .codex/config.toml touches mcp_servers.peer2peer: everything held from then on", async () => {
    const world = new World();
    world.trusted = { mode: { approval: "on-request", sandbox: "read-only", autoReview: false }, seq: 1, writable: ["/somewhere/else"] };
    const { bridge, feed, call } = await makeBridge({ world, codexHome: "/Users/ann/.codex", p2pHome: "/Users/ann/.p2p" });
    bridge.noteToolCall({ threadId: "thread-1", mode: { sandbox: "read-only", autoReview: false } });
    await bridge.refreshTrusted();
    await bridge.setCwd(project('[mcp_servers]\nother = { command = "x" }\n'));
    expect(bridge.locationRefusal()).toBeUndefined();
    await bridge.setCwd(project(null));
    expect(bridge.locationRefusal()).toBeUndefined();
    const evil = project('[mcp_servers.peer2peer]\ncwd = "/elsewhere"\n');
    await bridge.setCwd(evil);
    expect(bridge.locationRefusal()).toContain(`${join(evil, ".codex", "config.toml")} sets mcp_servers.peer2peer`);
    await feed(message({ text: "friend says hi" }));
    expect((await call("p2p_inbox")).text).not.toContain("friend says hi");
    expect(bridge.releaseReach("/Users/ann/.p2p")).toMatchObject({ ok: false });
    // Moving on doesn't lift it.
    await bridge.setCwd(project(null));
    expect(bridge.locationRefusal()).toContain("sets mcp_servers.peer2peer");
  });
});

describe("child environments come from an allowlist", () => {
  it("only PATH (fixed), HOME (user database), P2P_* (no extension loaders), LANG, LC_*, TZ, TERM, plus extras", () => {
    const given = {
      NODE_OPTIONS: "--require /repo/evil.js",
      NODE_TLS_REJECT_UNAUTHORIZED: "0",
      HTTPS_PROXY: "http://evil:8080",
      http_proxy: "http://evil:8080",
      ALL_PROXY: "socks5://evil",
      NO_PROXY: "*",
      NODE_ICU_DATA: "/repo/icu",
      GCONV_PATH: "/repo/gconv",
      LD_PRELOAD: "/repo/evil.so",
      DYLD_INSERT_LIBRARIES: "/repo/evil.dylib",
      P2P_EXTENSION_PATH: "/repo/node_modules",
      P2P_EXTENSIONS: "evil",
      P2P_DEFAULTS_FILE: "/repo/defaults.json",
      // review L2 (footprint P1): a project can't switch status caps for the user's session.
      P2P_STATUS_CAPS: "1",
      p2p_status_caps: "0",
      GIT_DIR: "/repo/.git",
      CODEX_HOME: "/repo/.codex",
      HOME: "/repo/home",
      PATH: "/repo/bin",
      P2P_HOME: "/Users/ann/.p2p",
      P2P_DRAIN_QUIET_MS: "250",
      LANG: "en_US.UTF-8",
      LC_ALL: "en_US.UTF-8",
      TZ: "UTC",
      TERM: "xterm",
    };
    const out = childEnv(given, { CODEX_HOME: "/Users/ann/.codex" });
    const home = process.platform === "win32" ? "USERPROFILE" : "HOME";
    expect(Object.keys(out).sort()).toEqual(["CODEX_HOME", home, "LANG", "LC_ALL", "P2P_DRAIN_QUIET_MS", "P2P_HOME", "PATH", "TERM", "TZ"].sort());
    expect(out[home]).toBe(userHome());
    expect(out.CODEX_HOME).toBe("/Users/ann/.codex");
    expect(out.PATH?.split(process.platform === "win32" ? ";" : ":")[0]).toBe(dirname(process.execPath));
    expect(out.PATH).not.toContain("/repo");
  });
});

describe("cwd = ~ in a workspace-write session: the sandbox's reach holds everything", () => {
  const ME_ADDR = "me@meme-meme-meme-meme";
  const inHome = async (writable: string[]) => {
    const home = userHome();
    const world = new World();
    world.trusted = { mode: { approval: "on-request", sandbox: writable.length ? "workspace-write" : "read-only", autoReview: false }, seq: 1, writable, cwd: home };
    const made = await makeBridge({ world, root: home, cwd: home, codexHome: join(home, ".codex"), p2pHome: join(home, ".p2p"), env: { P2P_AUTO_DELIVER: "p2p:annannannannannannannannannannann" } });
    made.bridge.noteToolCall({ threadId: "thread-1", mode: { sandbox: writable.length ? "workspace-write" : "read-only", autoReview: false } });
    await made.bridge.refreshTrusted();
    return { ...made, home };
  };

  it("~ writable (workspace-write in ~): own devices and P2P_AUTO_DELIVER senders held too, releases refused", async () => {
    const { bridge, feed, call, home } = await inHome([userHome()]);
    expect(bridge.locationRefusal()).toContain(`this session's sandbox can write ${join(home, ".codex")}`);
    await feed(message({ text: "listed sender" }));
    await feed(message({ text: "from my laptop", self: true, from: ME, address: ME_ADDR }));
    expect((await call("p2p_inbox")).text).not.toMatch(/listed sender|from my laptop/);
    expect(bridge.heldList()).toHaveLength(2);
    expect(bridge.releaseReach(join(home, ".p2p"))).toMatchObject({ ok: false });
  });

  it("only ~/.p2p writable, or a root inside it: held as well", async () => {
    expect((await inHome([join(userHome(), ".p2p", "codex")])).bridge.locationRefusal()).toContain("can write P2P_HOME");
  });

  it("read-only in ~, or only Codex's memories writable: own devices still delivered", async () => {
    for (const writable of [[], [join(userHome(), ".codex", "memories")], ["/somewhere/else"]]) {
      const { bridge, feed, call } = await inHome(writable);
      expect(bridge.locationRefusal()).toBeUndefined();
      await feed(message({ text: "from my laptop", self: true, from: ME, address: ME_ADDR }));
      expect((await call("p2p_inbox")).text).toContain("from my laptop");
    }
  });
});

describe("IX_BIN for ext-ix: a guarded knob, from the user-level config only", () => {
  const setup = () => {
    const home = safe("home-");
    mkdirSync(join(home, ".codex"), { mode: 0o700 });
    const binDir = safe("ix-");
    const bin = join(binDir, "ix");
    writeFileSync(bin, "#!/bin/sh\n", { mode: 0o755 });
    const config = (v: string) => writeFileSync(join(home, ".codex", "config.toml"), `[mcp_servers.peer2peer.env]\nIX_BIN = ${JSON.stringify(v)}\n`);
    return { home, binDir, bin, config, base: { projectDirs: ["/repo"], parentValue: noParent, home } };
  };

  it.skipIf(process.platform === "win32")("IX_BIN=/bin/sh from the env (a project config can set it) is dropped, with a warning", async () => {
    const { base } = setup();
    const r = await effectiveEnv({ ...base, env: { IX_BIN: "/bin/sh" } });
    expect(r.env.IX_BIN).toBeUndefined();
    expect(r.warnings.join("\n")).toContain("ignored IX_BIN from the environment");
    expect(childEnv(r.env).IX_BIN).toBeUndefined();
  });

  it.skipIf(process.platform === "win32")("the user-level config's value is accepted and reaches the children, whatever the env says", async () => {
    const { base, bin, config } = setup();
    config(bin);
    const r = await effectiveEnv({ ...base, env: { IX_BIN: "/bin/sh" } });
    expect(r.env.IX_BIN).toBe(bin);
    expect(childEnv(r.env).IX_BIN).toBe(bin);
  });

  it.skipIf(process.platform === "win32")("a symlinked IX_BIN is forwarded as the resolved path it was checked at", async () => {
    const { base, bin, config } = setup();
    const link = join(safe("ix-link-"), "ix");
    symlinkSync(bin, link);
    config(link);
    const r = await effectiveEnv({ ...base, env: {} });
    expect(r.env.IX_BIN).toBe(bin);
    expect(childEnv(r.env).IX_BIN).toBe(bin);
  });

  it.skipIf(process.platform === "win32")("a symlink in a safe folder that points into a temp folder is refused", async () => {
    const { base, config } = setup();
    const tmpDir = mkdtempSync(join(tmpdir(), "ix-target-"));
    try {
      const target = join(tmpDir, "ix");
      writeFileSync(target, "#!/bin/sh\n", { mode: 0o755 });
      const link = join(safe("ix-link-"), "ix");
      symlinkSync(target, link);
      config(link);
      const r = await effectiveEnv({ ...base, env: {} });
      expect(r.env.IX_BIN).toBeUndefined();
      expect(r.warnings.join("\n")).toMatch(/ignored IX_BIN=.*the temp folder/);
      expect(childEnv(r.env).IX_BIN).toBeUndefined();
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it.skipIf(process.platform === "win32")("refused: a group-writable folder above it, a group-writable file, relative, missing, a folder, temp, Codex-granted", async () => {
    const { home, binDir, bin, config, base } = setup();
    const check = async (v: string, why: string) => {
      config(v);
      const r = await effectiveEnv({ ...base, env: {} });
      expect(r.env.IX_BIN, v).toBeUndefined();
      expect(r.warnings.join("\n"), v).toContain(why);
    };
    chmodSync(binDir, 0o775);
    await check(bin, `${binDir} is group- or world-writable without the sticky bit`);
    chmodSync(binDir, 0o700);
    chmodSync(bin, 0o775);
    await check(bin, "is writable by a group or others");
    chmodSync(bin, 0o755);
    await check("ix", "absolute");
    await check(join(home, "nope"), "no such file");
    await check(home, "not a regular file");
    const inTmp = join(mkdtempSync(join(tmpdir(), "ix-")), "ix");
    writeFileSync(inTmp, "#!/bin/sh\n", { mode: 0o755 });
    await check(inTmp, "the temp folder");
    rmSync(join(inTmp, ".."), { recursive: true, force: true });
    const granted = join(home, ".codex", "memories", "ix");
    mkdirSync(join(home, ".codex", "memories"), { mode: 0o700 });
    writeFileSync(granted, "#!/bin/sh\n", { mode: 0o755 });
    await check(granted, "a folder Codex lets the sandbox write");
    expect(ixBinOf(undefined, { projectDirs: [], temp: [] })).toEqual({});
  });
});

describe("sandboxReach fails closed once a turn context can't be relied on", () => {
  const ME_ADDR = "me@meme-meme-meme-meme";
  const bridgeWith = async (trusted: Record<string, unknown> | null) => {
    const world = new World();
    world.trusted = trusted as never;
    const made = await makeBridge({ world, codexHome: "/Users/ann/.codex", p2pHome: "/Users/ann/.p2p" });
    made.bridge.noteToolCall({ threadId: "thread-1", mode: { sandbox: "read-only", autoReview: false } });
    await made.bridge.refreshTrusted();
    return made;
  };

  it("writable folders unknown: everything held (own devices too), releases refused", async () => {
    const { bridge, feed, call } = await bridgeWith({ mode: { approval: "on-request", sandbox: "read-only", autoReview: false }, seq: 1, writable: "unknown" });
    expect(bridge.locationRefusal()).toContain("couldn't be read");
    await feed(message({ text: "from my laptop", self: true, from: ME, address: ME_ADDR }));
    expect((await call("p2p_inbox")).text).not.toContain("from my laptop");
    expect(bridge.releaseReach("/Users/ann/.p2p")).toMatchObject({ ok: false });
  });

  it("an untrusted rollout (two files for the thread, a foreign session_meta, ...): everything held, and it stays so", async () => {
    const world = new World();
    world.trusted = { mode: {}, seq: 1, untrusted: "two rollout files claim this thread" } as never;
    const { bridge, feed, call } = await makeBridge({ world, codexHome: "/Users/ann/.codex", p2pHome: "/Users/ann/.p2p" });
    bridge.noteToolCall({ threadId: "thread-1", mode: { sandbox: "read-only", autoReview: false } });
    await bridge.refreshTrusted();
    expect(bridge.locationRefusal()).toContain("two rollout files claim this thread");
    await feed(message({ text: "from my laptop", self: true, from: ME, address: ME_ADDR }));
    expect((await call("p2p_inbox")).text).not.toContain("from my laptop");
    world.trusted = { mode: { approval: "on-request", sandbox: "read-only", autoReview: false }, seq: 2, writable: ["/somewhere/else"] } as never;
    await bridge.refreshTrusted();
    expect(bridge.locationRefusal()).toContain("isn't trusted");
  });

  it("before the first turn context: the static checks alone (own devices delivered)", async () => {
    const { bridge, feed, call } = await bridgeWith(null);
    expect(bridge.locationRefusal()).toBeUndefined();
    await feed(message({ text: "from my laptop", self: true, from: ME, address: ME_ADDR }));
    expect((await call("p2p_inbox")).text).toContain("from my laptop");
  });
});
