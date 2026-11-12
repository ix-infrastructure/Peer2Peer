#!/usr/bin/env node
// Copyright 2026 Ix Infrastructure Inc.
//
// Writes the install scripts' checksum files, in `sha256sum -c` format, so
// people who download the scripts (from the website or a release) can check
// them before running:
//   scripts/install-relay.sha256  install-relay.sh and install-relay.ps1 (the relay)
//   scripts/install.sha256        install.sh and install.ps1 (the client)
//
//   node scripts/install-relay-checksums.mjs           # rewrite the files
//   node scripts/install-relay-checksums.mjs --check   # exit 1 if one is stale
//
// Also `npm run install-scripts:checksums` in packages/relay.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const SETS = [
  { file: join(here, "install-relay.sha256"), scripts: ["install-relay.sh", "install-relay.ps1"] },
  { file: join(here, "install.sha256"), scripts: ["install.sh", "install.ps1"] },
];
// The relay's set, as before.
export const SCRIPTS = SETS[0].scripts;
export const SUMS_FILE = SETS[0].file;

export function checksums(scripts = SCRIPTS) {
  return scripts.map((f) => `${createHash("sha256").update(readFileSync(join(here, f))).digest("hex")}  ${f}\n`).join("");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const check = process.argv.includes("--check");
  let stale = false;
  for (const { file, scripts } of SETS) {
    const want = checksums(scripts);
    if (check) {
      let have = "";
      try {
        have = readFileSync(file, "utf8");
      } catch {
        // missing: stale
      }
      if (have !== want) {
        console.error(`scripts/${basename(file)} is stale: run node scripts/install-relay-checksums.mjs`);
        stale = true;
      } else {
        console.log(`${basename(file)} is up to date`);
      }
    } else {
      writeFileSync(file, want);
      process.stdout.write(want);
    }
  }
  if (stale) process.exit(1);
}
