// Copyright 2026 Ix Infrastructure Inc.
import { mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { childEnv } from "../knobs.js";
import { personTokenOf } from "../server.js";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { guard, runHook, touchedPaths } from "../hook.js";
import { loadThread, loadThreadDirs, saveThreadDirs } from "../bridge.js";
import { findEntry, readEntries, serve, socketPath, writeEntry, type Entry } from "../ipc.js";
import { lineFeeder, McpServer, text } from "../mcp.js";

const homes: string[] = [];
afterEach(() => {
  for (const h of homes.splice(0)) rmSync(h, { recursive: true, force: true });
});

const entry = (o: Partial<Entry>): Entry => ({ v: 1, pid: 1, codexPid: 100, sock: "/s", sid: "codex-1", cwd: "/w", startedAt: 1, activeAt: 0, ...o });

describe("PreToolUse guard", () => {
  it("denies mutating p2p verbs and secret reads in shell tools only", () => {
    expect(guard("Bash", { command: "p2p join relay/CODE" })).toContain("Only your user runs it");
    expect(guard("exec_command", { cmd: "p2p held approve h1" })).toContain("held approve");
    expect(guard("shell", { command: ["bash", "-lc", "p2p relays add wss://x"] })).toContain("relays add");
    expect(guard("Bash", { command: "cat ~/.p2p/backup-phrase.txt" })).toContain("backup phrase");
    expect(guard("Bash", { command: "p2p ls" })).toBeNull();
    expect(guard("apply_patch", { command: "p2p join x" })).toBeNull();
  });

  it("prints a deny decision in Codex's PreToolUse shape", async () => {
    const out = await runHook("PreToolUse", JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "node ./p2p.mjs codex release m1" } }), { home: "/nonexistent" });
    const v = JSON.parse(out);
    expect(v.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(v.hookSpecificOutput.permissionDecisionReason).toContain("codex release");
  });
});

describe("finding the session a hook belongs to", () => {
  it("by bound thread, else the ONE unbound bridge under the same Codex process (M1)", () => {
    const a = entry({ pid: 11, codexPid: 100, threadId: "t-a" });
    const b = entry({ pid: 12, codexPid: 200 });
    const c = entry({ pid: 13, codexPid: 200, cwd: "/other", startedAt: 5 });
    const d = entry({ pid: 14, codexPid: 300 });
    expect(findEntry([a, b, c, d], { sessionId: "t-a", ancestors: [999] })).toBe(a);
    expect(findEntry([a, b, c, d], { sessionId: "t-new", ancestors: [50, 300] })).toBe(d);
    // Two free bridges under one Codex process: refuse rather than guess (never "the newest").
    expect(findEntry([a, b, c], { sessionId: "t-new", ancestors: [50, 200], cwd: "/other" })).toBeUndefined();
    // Never another thread's bridge, even under the same process.
    expect(findEntry([a], { sessionId: "t-b", ancestors: [100] })).toBeUndefined();
    // No process tree to go by: only on Windows, and only with exactly one free bridge.
    expect(findEntry([b], { ancestors: [7], platform: "linux" })).toBeUndefined();
    expect(findEntry([b], { ancestors: [7], platform: "win32" })).toBe(b);
    expect(findEntry([b, d], { ancestors: [7], platform: "win32" })).toBeUndefined();
  });

  it("a hook reaches its bridge over the local socket and prints its answer", async () => {
    const home = mkdtempSync(join(tmpdir(), "p2p-hook-"));
    homes.push(home);
    const sock = socketPath(home, process.pid);
    const seen: unknown[] = [];
    const server = await serve(sock, async (req) => {
      seen.push(req);
      return { ok: true, output: { hookSpecificOutput: { hookEventName: "UserPromptSubmit", additionalContext: "hello from the bridge" } } };
    });
    writeEntry(home, entry({ pid: process.pid, codexPid: 4242, sock }));
    expect(readEntries(home)).toHaveLength(1);
    const payload = { hook_event_name: "UserPromptSubmit", session_id: "thread-x", cwd: "/w", permission_mode: "default", prompt: "my secret prompt", transcript_path: "/t" };
    const out = await runHook("UserPromptSubmit", JSON.stringify(payload), { home, ancestors: async () => [4242] });
    server.close();
    expect(JSON.parse(out).hookSpecificOutput.additionalContext).toBe("hello from the bridge");
    const report = (seen[0] as { report: Record<string, unknown> }).report;
    // Only what could make the bridge stricter: no transcript-derived mode (the bridge reads its own).
    expect(report).toEqual({ event: "UserPromptSubmit", sessionId: "thread-x", cwd: "/w", mode: { permissionMode: "default" } });
    // The prompt never leaves the hook process.
    expect(JSON.stringify(seen)).not.toContain("secret prompt");
  });

  it("no bridge, bad input or a subagent's event: prints nothing", async () => {
    expect(await runHook("Stop", "{}", { home: "/nonexistent", ancestors: async () => [] })).toBe("");
    expect(await runHook("Stop", "not json", { home: "/nonexistent" })).toBe("");
    expect(await runHook("PostToolUse", JSON.stringify({ hook_event_name: "PostToolUse", agent_id: "sub" }), { home: "/nonexistent" })).toBe("");
  });

  it("dead bridges' entries are cleaned up", () => {
    const home = mkdtempSync(join(tmpdir(), "p2p-reg-"));
    homes.push(home);
    writeEntry(home, entry({ pid: 2_000_000_000 }));
    expect(readEntries(home)).toEqual([]);
  });
});

describe("MCP transport", () => {
  it("initialize, ping, unknown methods, parse errors", async () => {
    const out: Record<string, any>[] = [];
    const s = new McpServer({ name: "t", version: "1" }, [], (l) => out.push(JSON.parse(l)));
    await s.onLine(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: { elicitation: {} } } }));
    expect(out[0]?.result.protocolVersion).toBe("2025-06-18");
    expect(out[0]?.result.capabilities.tools).toBeDefined();
    await s.onLine(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" }));
    expect(out[1]).toEqual({ jsonrpc: "2.0", id: 2, result: {} });
    await s.onLine(JSON.stringify({ jsonrpc: "2.0", id: 3, method: "nope" }));
    expect(out[2]?.error.code).toBe(-32601);
    await s.onLine("{bad");
    expect(out[3]?.error.code).toBe(-32700);
    await s.onLine(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }));
    expect(out).toHaveLength(4);
  });

  it("a tool waiting on the client doesn't block the client's answer", async () => {
    const out: Record<string, any>[] = [];
    // eslint-disable-next-line prefer-const -- assigned after the feeder that closes over it
    let s: McpServer;
    const feeder = lineFeeder((l) => s.onLine(l));
    s = new McpServer(
      { name: "t", version: "1" },
      [{ name: "ask", description: "", inputSchema: { type: "object" }, call: async (_a, ctx) => text(JSON.stringify(await ctx.request("elicitation/create", {}))) }],
      (l) => {
        const m = JSON.parse(l);
        out.push(m);
        if (m.method === "elicitation/create") feeder.push(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { action: "decline" } }) + "\n");
      },
    );
    feeder.push(JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "ask", arguments: {} } }) + "\n");
    await feeder.end();
    await new Promise((r) => setTimeout(r, 10));
    expect(out.find((m) => m.id === 9)?.result.content[0].text).toBe('{"action":"decline"}');
  });
});

describe("project boundaries in the Codex guard (packages/p2p/src/projects.ts)", () => {
  it("the model's shell speaks only for this bridge's session, however it quotes the id (H5)", () => {
    expect(guard("Bash", { command: "p2p send --from-session=codex-1 --to ben hi" }, [], "codex-1")).toBeNull();
    expect(guard("Bash", { command: "p2p send --from-session=fake --to ben hi" }, [], "codex-1")).toContain("speaks only for this Codex session");
    expect(guard("Bash", { command: "p2p send --from-session=''codex-1x --to ben hi" }, [], "codex-1")).toContain("speaks only for this Codex session");
    // No bridge found for this call: no session id at all.
    expect(guard("Bash", { command: "p2p send --from-session=codex-1 --to ben hi" })).toContain("speaks only for this Codex session");
  });

  it("interpreter code, pseudo-terminals and project shares naming p2p are refused (H4)", () => {
    for (const command of [
      `python3 -c 'import subprocess; subprocess.run(["p2p","project","share","c_x"])'`,
      `node -e 'require("child_process").execSync("p2p send --to ben x")'`,
      "script -q /dev/null p2p send --to ben x",
      "p2p project share c_x",
    ]) expect(guard("Bash", { command }, [], "codex-1"), command).not.toBeNull();
    expect(guard("Bash", { command: "python3 -c 'print(1)'" }, [], "codex-1")).toBeNull();
  });

  it("paths a call reaches outside its folder are reported (H2)", () => {
    expect(touchedPaths("Bash", { command: "cat /secret/keys.ts ../other/x ~/notes" }, "/w/repo", "/home/u")).toEqual({ paths: ["/secret", "/w/other/x", "/home/u/notes"], over: false });
    expect(touchedPaths("apply_patch", { input: "*** Begin Patch\n*** Update File: ../lib/a.ts\n" }, "/w/repo", undefined).paths).toContain("/w/lib/a.ts");
  });

  it("a thread's folders survive a resume (H3)", () => {
    const home = mkdtempSync(join(tmpdir(), "p2p-thread-"));
    homes.push(home);
    saveThreadDirs(home, "thread-1", ["/secret", "/w/repo"]);
    expect(loadThreadDirs(home, "thread-1")).toEqual(["/secret", "/w/repo"]);
    expect(loadThreadDirs(home, "thread-2")).toEqual([]);
  });
});

describe("project boundaries in the Codex guard: caps and residuals (PR #30 re-review)", () => {
  it("padding can't push a session id past what is read (N3), and a long command naming p2p is refused unread", () => {
    expect(guard("Bash", { command: `p2p ${"x ".repeat(6000)} --from-session fake --to ben hi` }, [], "codex-1")).not.toBeNull();
    expect(guard("Bash", { command: `p2p ls ${"y".repeat(20 * 1024)}` }, [], "codex-1")).toContain("too long");
  });

  it("paths built at run time, or too many, make the session private; $HOME and $PWD resolve (M1, H2)", () => {
    expect(touchedPaths("Bash", { command: "cat $HOME/notes/a.md" }, "/w/repo", "/home/u")).toEqual({ paths: ["/home/u/notes"], over: false });
    expect(touchedPaths("Bash", { command: "cat $SECRET/x" }, "/w/repo", "/home/u").over).toBe(true);
    expect(touchedPaths("Bash", { command: Array.from({ length: 300 }, (_, i) => `/p${i}/x`).join(" ") }, "/w/repo", "/home/u").over).toBe(true);
    expect(touchedPaths("Bash", { command: "cat /x" }, undefined, undefined).over).toBe(true);
  });

  it("a thread saved as over stays over; a file it can't read fails closed (H3)", () => {
    const home = mkdtempSync(join(tmpdir(), "p2p-thread-over-"));
    homes.push(home);
    saveThreadDirs(home, "t-over", ["/a"], true);
    expect(loadThread(home, "t-over")).toEqual({ dirs: ["/a"], over: true });
    saveThreadDirs(home, "t-bad", ["/a"]);
    const f = readdirSync(join(home, "codex-threads")).map((n) => join(home, "codex-threads", n));
    for (const x of f) writeFileSync(x, "{not json");
    expect(loadThread(home, "t-bad").over).toBe(true);
  });
});

describe("PR #30 third review: quoting, a bridge that can't be told, the token's reach", () => {
  it("quoted $ is text; $PWD inside a word expands; an expansion in the first segment is private (M2)", () => {
    expect(touchedPaths("Bash", { command: "sed 's/$/;/' notes.txt" }, "/w/repo", "/home/u").over).toBe(false);
    expect(touchedPaths("Bash", { command: "docker run -v $PWD:/app img" }, "/w/repo", "/home/u").over).toBe(false);
    expect(touchedPaths("Bash", { command: "cat src/$NAME.ts" }, "/w/repo", "/home/u")).toEqual({ paths: ["/w/repo/src"], over: false });
    expect(touchedPaths("Bash", { command: "tsc --outDir=$OUT/dist" }, "/w/repo", "/home/u").over).toBe(true);
  });

  it("a call that reaches folders is refused when the bridge can't be told (M6)", async () => {
    const home = mkdtempSync(join(tmpdir(), "p2p-hook-told-"));
    homes.push(home);
    writeEntry(home, entry({ pid: process.pid, threadId: "thread-x", sock: join(home, "no-such.sock"), sid: "codex-1" }));
    const out = await runHook("PreToolUse", JSON.stringify({ hook_event_name: "PreToolUse", session_id: "thread-x", cwd: "/w/repo", tool_name: "Bash", tool_input: { command: "cat /secret/keys.ts" } }), { home });
    expect(JSON.parse(out).hookSpecificOutput.permissionDecision).toBe("deny");
    // Nothing outside to report: allowed, as before.
    expect(await runHook("PreToolUse", JSON.stringify({ hook_event_name: "PreToolUse", session_id: "thread-x", cwd: "/w/repo", tool_name: "Bash", tool_input: { command: "ls" } }), { home })).toBe("");
  });

  it("the person token reaches only p2p's short runs: never another child, never the watch (N1, M3)", () => {
    expect(childEnv({ P2P_PERSON_TOKEN: "x".repeat(43), P2P_HOME: "/h" }).P2P_PERSON_TOKEN).toBeUndefined();
    expect(childEnv({ P2P_HOME: "/h" }, { P2P_PERSON_TOKEN: "t" }).P2P_PERSON_TOKEN).toBe("t");
  });

  it("the bridge makes the person token itself on a fresh install, exclusively (R1)", () => {
    const home = mkdtempSync(join(tmpdir(), "p2p-tok-"));
    homes.push(home);
    const t = personTokenOf(home);
    expect(t).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(personTokenOf(home)).toBe(t);
    expect(statSync(join(home, "cli", "person.key")).mode & 0o777).toBe(0o600);
  });
});
