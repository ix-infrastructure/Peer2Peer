// Copyright 2026 Ix Infrastructure Inc.
//
// Every suite starts with "no Claude Code or Codex ancestor" (ancestry.ts), whatever runs the
// tests: the module is replaced here, so the shipped CLI carries no test hook. A test about agents
// sets their variables itself; a test about an unreadable process tree sets
// `globalThis.__p2pTestAncestry` to "unknown" (or "agent") and back to undefined after.
import { vi } from "vitest";

vi.mock("../ancestry.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../ancestry.js")>();
  const now = () => (globalThis as { __p2pTestAncestry?: "agent" | "none" | "unknown" }).__p2pTestAncestry ?? "none";
  return { ...real, ancestry: now, agentAncestor: () => now() === "agent", ancestryUnknown: () => now() === "unknown", ancestryWhy: () => (now() === "unknown" ? "a test said so" : "") };
});

// Every suite runs with a throwaway home folder, so nothing reads or writes the person's real
// Claude Code or Codex config (sandbox.ts expands `~` from HOME): `p2p setup` and `p2p doctor` look
// there. A test about those files points HOME, CLAUDE_CONFIG_DIR or CODEX_HOME at its own folder.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const testUserHome = mkdtempSync(join(tmpdir(), "p2p-test-userhome-"));
process.env.HOME = testUserHome;
process.env.USERPROFILE = testUserHome;
delete process.env.CLAUDE_CONFIG_DIR;
delete process.env.CODEX_HOME;
