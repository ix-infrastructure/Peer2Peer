// Copyright 2026 Ix Infrastructure Inc.
//
// `npm run test:resilience`. Files run one at a time: every test measures
// event-loop delay and RSS of its own relay process, and parallel files would
// measure each other.
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    root: import.meta.dirname,
    include: ["**/*.resilience.test.ts"],
    globalSetup: ["./global-setup.ts"],
    fileParallelism: false,
    testTimeout: 60_000,
    hookTimeout: 30_000,
    reporters: ["verbose"],
  },
});
