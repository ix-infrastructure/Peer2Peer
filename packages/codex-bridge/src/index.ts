// Copyright 2026 Ix Infrastructure Inc.
//
// @peer2peer/codex-bridge: Peer2Peer for OpenAI Codex. An MCP server Codex
// starts with each session, Codex hooks, and an installer, all over the
// `p2p` CLI. Core software: it never imports Ix or an extension.

export * from "./lib.js";
export { McpServer, lineFeeder, text, PROTOCOL_VERSION, type Tool, type ToolResult } from "./mcp.js";
export { P2P, nodeExec, type Exec } from "./p2p.js";
export { Bridge, type BridgeDeps, type HookReport, type InboxItem } from "./bridge.js";
export { makeTools, refuseMutating, serverInstructions } from "./tools.js";
export { runMcpServer, resolveHome, BRIDGE_VERSION, type McpOptions } from "./server.js";
export { runHook, guard, commandOf } from "./hook.js";
export { effectiveEnv, bridgeHome, readTomlTable, GUARDED_KNOBS } from "./knobs.js";
export { ask, findEntry, readEntries, registryDir, type Entry } from "./ipc.js";
export * from "./install.js";
export { installCommand, sessionsCommand, heldCommand, resolveCommand, requirePerson, CodexCommandError, type Output, type PersonIo } from "./commands.js";
export { PersonGate, ttyWriter, newCode, writeNonce, consumeNonce, confirmDir, nonceFileName } from "./confirm.js";
export { RolloutReader, findRollout, type TranscriptSource } from "./trusted.js";
