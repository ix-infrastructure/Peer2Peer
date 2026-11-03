// Copyright 2026 Ix Infrastructure Inc.
//
// `npm run test:fuzz`: fast-check property tests against a relay process on 127.0.0.1.
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    root: import.meta.dirname,
    include: ["fuzz/**/*.fuzz.test.ts"],
    globalSetup: ["./global-setup.ts"],
    fileParallelism: false,
    testTimeout: 120_000,
    hookTimeout: 30_000,
    reporters: ["verbose"],
  },
});
