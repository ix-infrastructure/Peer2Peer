#!/usr/bin/env node
// Copyright 2026 Ix Infrastructure Inc.
//
// Sets the lockstep version of the publishable Peer2Peer packages (core,
// relay, codex-bridge, p2p, ext-ix): each package.json, the version constants
// compiled into codex-bridge, p2p and ext-ix, ext-ix's peer range on
// @peer2peer/cli, and every package-lock.json. It doesn't touch git, npm or
// the committed bundles under mods/ (docs/releasing.md has the next steps).
//
//   node scripts/set-version.mjs <version>      e.g. 0.2.0 or 0.2.0-rc.1

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const version = process.argv[2];
if (!version || !/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version)) {
  console.error("usage: node scripts/set-version.mjs <major.minor.patch[-prerelease]>");
  process.exit(2);
}

const DIRS = ["core", "relay", "codex-bridge", "p2p", "ext-ix"];
const CONSTANTS = [
  ["codex-bridge", "src/server.ts", /(export const BRIDGE_VERSION = ")[^"]+(")/],
  ["p2p", "src/version.ts", /(export const VERSION = ")[^"]+(")/],
  ["ext-ix", "src/extension.ts", /(export const VERSION = ")[^"]+(")/],
];

for (const dir of DIRS) {
  const f = join(root, "packages", dir, "package.json");
  const pkg = JSON.parse(readFileSync(f, "utf8"));
  pkg.version = version;
  if (pkg.peerDependencies?.["@peer2peer/cli"]) pkg.peerDependencies["@peer2peer/cli"] = `^${version}`;
  writeFileSync(f, `${JSON.stringify(pkg, null, 2)}\n`);
}
for (const [dir, file, re] of CONSTANTS) {
  const f = join(root, "packages", dir, file);
  const src = readFileSync(f, "utf8");
  if (!re.test(src)) throw new Error(`no version constant in packages/${dir}/${file}`);
  writeFileSync(f, src.replace(re, `$1${version}$2`));
}
// Lockfiles record the root version and the linked (file:) packages' versions.
for (const dir of DIRS) {
  execFileSync("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], {
    cwd: join(root, "packages", dir),
    stdio: "inherit",
  });
}
console.log(`set ${DIRS.length} packages to ${version}`);
