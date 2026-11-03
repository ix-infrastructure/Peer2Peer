// Copyright 2026 Ix Infrastructure Inc.
//
// Compiles the relay (src/, without tests) plus the child entry into
// node_modules/.cache/relay-resilience, once per run. Every resilience and
// fuzz test then forks that build as a child process on 127.0.0.1.

import { execFileSync } from "node:child_process";
import { rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const BUILD_DIR = join(here, "..", "node_modules", ".cache", "relay-resilience");

export default function setup(): void {
  rmSync(BUILD_DIR, { recursive: true, force: true });
  const tsc = join(here, "..", "node_modules", "typescript", "bin", "tsc");
  execFileSync(process.execPath, [tsc, "-p", join(here, "tsconfig.child.json")], { stdio: "inherit" });
}
