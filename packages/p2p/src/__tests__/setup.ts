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
  return { ...real, ancestry: now, agentAncestor: () => now() === "agent", ancestryUnknown: () => now() === "unknown" };
});
