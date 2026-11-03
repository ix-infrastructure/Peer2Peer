// Copyright 2026 Ix Infrastructure Inc.
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    testTimeout: 60_000,
    hookTimeout: 30_000,
  },
});
