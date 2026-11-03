// Copyright 2026 Ix Infrastructure Inc.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { guard, runHook } from "../hook.js";
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
