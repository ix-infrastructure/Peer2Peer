// Copyright 2026 Ix Infrastructure Inc.
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    testTimeout: 60_000,
    hookTimeout: 30_000,
    // These suites may run inside an agent's session: the process-ancestry check answers "no agent"
    // in-process, and the tests about agents set it (projects.ts setAgentAncestorForTests).
    setupFiles: ["src/__tests__/setup.ts"],
  },
});
