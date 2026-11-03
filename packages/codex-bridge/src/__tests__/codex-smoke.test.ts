// Copyright 2026 Ix Infrastructure Inc.
//
// A real Codex session against the bridge, on request only:
//   P2P_CODEX_SMOKE=1 npm test
// Needs `codex` on PATH, logged in. With CODEX_API_KEY set it runs in a
// throwaway CODEX_HOME; otherwise it runs `codex exec --ignore-user-config
// --ephemeral`, which reads only the login from your Codex home and never
// your config.toml or hooks, and writes no session. The MCP server is given
// with `-c` overrides; nothing is written to any Codex config.
//
// It checks, over a real relay: Codex starts `p2p codex mcp`; the model sees
// a CLI peer's status through p2p_list_peers; a message the model sends with
// p2p_send (allowed here by `tools.p2p_send.approval_mode = "approve"`, as a
// person would set it) reaches the peer; each tool call carries Codex's
// `_meta["x-codex-turn-metadata"]` with the thread id and the sandbox.

import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Relay } from "@peer2peer/relay";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { befriend, hasCli, P2P_JS, Person, startRelay, until, watchLines, type Json } from "./net.js";

const enabled = process.env.P2P_CODEX_SMOKE === "1" && hasCli;
const toml = (s: string) => JSON.stringify(s);

describe.skipIf(!enabled)("a real Codex session (P2P_CODEX_SMOKE=1)", () => {
  let relay: Relay;
  let port = 0;
  const cody = new Person("cody", () => port);
  const ann = new Person("ann", () => port);
  const SID_A = "ann-smoke-session";
  let dir = "";
  let annWatch: ChildProcess | null = null;
  const annEvents: Json[] = [];

  beforeAll(async () => {
    ({ relay, port } = await startRelay());
    dir = mkdtempSync(join(tmpdir(), "p2p-codex-smoke-"));
    mkdirSync(join(dir, "web"));
    execFileSync("git", ["init", "-q", "-b", "main", join(dir, "web")]);
  }, 60_000);

  afterAll(async () => {
    annWatch?.kill("SIGTERM");
    await relay?.close().catch(() => {});
    for (const p of [cody, ann]) rmSync(p.home, { recursive: true, force: true });
    rmSync(dir, { recursive: true, force: true });
  });

  it("Codex lists a CLI peer and messages it through the bridge", async () => {
    await befriend(cody, ann);
    // Ann shares her session with Cody and says what she's doing.
    await ann.p2p(["session", "roster", SID_A, `--add=${cody.userId}`]);
    await ann.p2p(["status", `--session=${SID_A}`, "--state=busy", "--label=api", "--repo=api", "--summary=Migrating the billing tables"]);
    annWatch = spawn(process.execPath, [P2P_JS, "watch", `--session=${SID_A}`, "--jsonl"], { env: ann.env, stdio: ["ignore", "pipe", "pipe"] });
    watchLines(annWatch, annEvents);

    const metaLog = join(dir, "meta.log");
    const last = join(dir, "last.txt");
    const env = cody.env;
    // The bridge takes P2P_HOME, the relay transport and the meta log only from the user-level config
    // of the CODEX_HOME its parent runs with: a throwaway one, so the real ~/.codex is never read for them.
    // Outside every temp folder (the bridge never trusts a CODEX_HOME there), and removed with cody's home.
    const bridgeCodexHome = join(cody.home, "bridge-codex-home");
    mkdirSync(bridgeCodexHome, { mode: 0o700 });
    writeFileSync(join(bridgeCodexHome, "config.toml"), cody.codexConfig({ P2P_CODEX_META_LOG: metaLog }));
    const mcpEnv = ["P2P_DRAIN_QUIET_MS", "P2P_DRAIN_MAX_MS", "P2P_DOC_REFRESH_SEC", "P2P_CONNECT_TIMEOUT_MS"].map((k) => `${k}=${toml(String(env[k]))}`).join(",");
    // `env` starts a small node parent with CODEX_HOME in its own environment, which starts the server.
    const fakeCodex = `const c = require("child_process").spawn(process.argv[1], [process.argv[2], "codex", "mcp"], { stdio: "inherit" }); c.on("exit", (code) => process.exit(code ?? 0));`;
    const isolated = !!process.env.CODEX_API_KEY;
    const args = [
      "exec",
      "--skip-git-repo-check",
      "--ephemeral",
      ...(isolated ? [] : ["--ignore-user-config"]),
      "-s",
      "read-only",
      "-C",
      join(dir, "web"),
      "-c",
      'mcp_servers.peer2peer.command="env"',
      "-c",
      `mcp_servers.peer2peer.args=[${[`CODEX_HOME=${bridgeCodexHome}`, process.execPath, "-e", fakeCodex, process.execPath, P2P_JS].map(toml).join(",")}]`,
      "-c",
      `mcp_servers.peer2peer.env={${mcpEnv}}`,
      "-c",
      'mcp_servers.peer2peer.tools.p2p_send.approval_mode="approve"',
      "-o",
      last,
      `Use the peer2peer MCP tools. First call p2p_list_peers. Then call p2p_send to the session listed for ann, with the message "smoke: hello from Codex". Finally reply with ann's working-on summary exactly as listed.`,
    ];
    const codexEnv: NodeJS.ProcessEnv = { ...process.env, ...(isolated ? { CODEX_HOME: mkdtempSync(join(tmpdir(), "codex-home-")) } : {}) };
    // stdin closed: `codex exec` otherwise waits to read more prompt from it.
    const run = await new Promise<{ code: number | null; out: string }>((resolve) => {
      const child = spawn("codex", args, { env: codexEnv, stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      const timer = setTimeout(() => child.kill("SIGTERM"), 240_000);
      child.stdout.on("data", (d) => (out = `${out}${String(d)}`.slice(-20_000)));
      child.stderr.on("data", (d) => (out = `${out}${String(d)}`.slice(-20_000)));
      child.on("error", (e) => resolve({ code: 1, out: String(e) }));
      child.on("close", (code) => {
        clearTimeout(timer);
        resolve({ code, out });
      });
    });
    expect(run.code, run.out.slice(-2_000)).toBe(0);
    expect(readFileSync(last, "utf8")).toContain("Migrating the billing tables");
    const msg = await until("Codex's message at ann", () => annEvents.find((e) => e.kind === "p2p.message" && String(e.text).includes("smoke: hello from Codex")), 60_000);
    expect(msg.from.userId).toBe(cody.userId);
    const metas = readFileSync(metaLog, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    const turn = metas.find((m) => m?.["x-codex-turn-metadata"])?.["x-codex-turn-metadata"];
    expect(turn.thread_id).toMatch(/\S/);
    expect(turn.sandbox_mode).toBe("read-only");
  }, 300_000);
});
