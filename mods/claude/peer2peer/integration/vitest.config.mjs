// Copyright 2026 Ix Infrastructure Inc.
//
// The mod's integration test, run with packages/p2p's vitest (see the mod's README.md,
// "Develop"). A plain object, so nothing is imported from here.

export default {
  root: new URL('.', import.meta.url).pathname,
  test: {
    include: ['**/*.e2e.ts'],
    globals: true,
    testTimeout: 120_000,
    hookTimeout: 60_000,
  },
}
