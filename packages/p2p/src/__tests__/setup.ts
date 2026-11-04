// Copyright 2026 Ix Infrastructure Inc.
//
// Every suite starts with "no Claude Code or Codex ancestor" (ancestry.ts), whatever runs the
// tests: the module is replaced here, so the shipped CLI carries no test hook. A test about agents
// sets their variables itself.
import { vi } from "vitest";

vi.mock("../ancestry.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../ancestry.js")>();
  return { ...real, agentAncestor: () => false };
});
