// Copyright 2026 Ix Infrastructure Inc.
//
// `npm test` runs the real CLI, so it builds core, relay, this package and
// packages/p2p first, in that order (p2p imports this package's dist). In a
// fresh checkout a sibling package may not have its dependencies yet:
// `npm ci` installs them first (only when its node_modules is missing).

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(dirname(fileURLToPath(import.meta.url)));
const pkgs = join(here, "..");
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const run = (cwd, args) => execFileSync(npm, args, { cwd, stdio: "inherit", shell: process.platform === "win32" });

for (const name of ["core", "relay", "codex-bridge", "p2p"]) {
  const dir = join(pkgs, name);
  if (!existsSync(join(dir, "node_modules"))) run(dir, ["ci", "--no-audit", "--no-fund"]);
  run(dir, ["run", "build"]);
}
