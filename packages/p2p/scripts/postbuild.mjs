// Copyright 2026 Ix Infrastructure Inc.
//
// After `tsc`: make the `p2p` entry point executable. The build deletes
// dist/ and tsc writes 0644 files, so an `npm link`ed or globally installed
// `p2p` would fail with "permission denied". Node's chmod, so it runs
// anywhere (on Windows only the read-only bit exists, and it is left alone).
//
//   node scripts/postbuild.mjs [file]    (default: dist/bin.js)

import { chmodSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const file = resolve(process.argv[2] ?? resolve(dirname(fileURLToPath(import.meta.url)), "../dist/bin.js"));
chmodSync(file, 0o755);
if (process.platform !== "win32" && (statSync(file).mode & 0o111) === 0) {
  console.error(`${file} is still not executable`);
  process.exit(1);
}
