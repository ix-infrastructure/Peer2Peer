#!/usr/bin/env node
// Copyright 2026 Ix Infrastructure Inc.
//
// Writes scripts/install-relay.sha256: the SHA-256 of install-relay.sh and
// install-relay.ps1, in `sha256sum -c` format, so people who download the
// scripts (from the website or a release) can check them before running.
//
//   node scripts/install-relay-checksums.mjs           # rewrite the file
//   node scripts/install-relay-checksums.mjs --check   # exit 1 if it is stale
//
// Also `npm run install-scripts:checksums` in packages/relay.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const SCRIPTS = ["install-relay.sh", "install-relay.ps1"];
export const SUMS_FILE = join(here, "install-relay.sha256");

export function checksums() {
  return SCRIPTS.map((f) => `${createHash("sha256").update(readFileSync(join(here, f))).digest("hex")}  ${f}\n`).join("");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const want = checksums();
  if (process.argv.includes("--check")) {
    let have = "";
    try {
      have = readFileSync(SUMS_FILE, "utf8");
    } catch {
      // missing: stale
    }
    if (have !== want) {
      console.error("scripts/install-relay.sha256 is stale: run node scripts/install-relay-checksums.mjs");
      process.exit(1);
    }
    console.log("install-relay.sha256 is up to date");
  } else {
    writeFileSync(SUMS_FILE, want);
    process.stdout.write(want);
  }
}
