// Copyright 2026 Ix Infrastructure Inc.
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// The tests drive the real `p2p` (@peer2peer/cli), an optional peer of this
// package. Through node_modules it resolves to ../p2p/dist, which exists only
// once p2p is built, and Vite turns an unresolvable optional peer into a stub
// that fails every test file importing it ("Could not resolve @peer2peer/cli
// imported by @peer2peer/ext-ix"). Pointing it at p2p's sources makes the
// tests independent of whether, or how recently, p2p was built (its own
// dependencies still come from packages/p2p/node_modules).
const p2pSource = fileURLToPath(new URL("../p2p/src/index.ts", import.meta.url));

export default defineConfig({
  resolve: {
    alias: [{ find: /^@peer2peer\/cli$/, replacement: p2pSource }],
  },
  test: {
    include: ["src/**/*.test.ts"],
    testTimeout: 60_000,
    hookTimeout: 30_000,
  },
});
