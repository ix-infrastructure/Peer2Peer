// Copyright 2026 Ix Infrastructure Inc.
//
// Builds the single-file CLI the Claude mod runs with `node`:
// mods/claude/peer2peer/bin/p2p.mjs, one self-contained ESM file (core,
// commander, ws, uqr inlined; unminified, so it can be read).
//
//   node scripts/bundle.mjs           write it
//   node scripts/bundle.mjs --check   rebuild in memory and fail unless the
//                                     committed file is byte-for-byte the same
//
// Deterministic: esbuild is pinned (devDependencies), paths in the output are
// relative to the repository root, and nothing time- or host-dependent is
// embedded. Needs packages/core and packages/codex-bridge built
// (`npm --prefix ../core run build && npm --prefix ../codex-bridge run build`).
// `defaults.json` beside the output holds the default relay list (empty in
// the repository; a deploy step fills in the team relay).

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { bundledCoreLine, coreFingerprint, coreLine } from "../../../scripts/core-fingerprint.mjs";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const outRel = "mods/claude/peer2peer/bin/p2p.mjs";
const out = join(repo, outRel);
const check = process.argv.includes("--check");
// First line: which core this bundle inlines (scripts/core-fingerprint.mjs); the ext-ix copy carries the same.
const core = coreLine(coreFingerprint(repo));

const result = await build({
  absWorkingDir: repo,
  entryPoints: ["packages/p2p/src/bin.ts"],
  outfile: outRel,
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  write: false,
  minify: false,
  sourcemap: false,
  charset: "utf8",
  legalComments: "eof",
  // ws's optional native helpers: absent, ws falls back to JS.
  external: ["bufferutil", "utf-8-validate"],
  // CommonJS dependencies (ws) require() Node built-ins.
  banner: { js: `${core}\nimport { createRequire as __p2pCreateRequire } from "node:module";\nconst require = __p2pCreateRequire(import.meta.url);` },
  logLevel: "warning",
});
const text = result.outputFiles[0].contents;

if (check) {
  const have = existsSync(out) ? readFileSync(out) : Buffer.alloc(0);
  if (!Buffer.from(text).equals(have)) {
    console.error(`${outRel} is not what the sources build: run \`npm run bundle\` in packages/p2p and commit it`);
    process.exit(1);
  }
  const ext = bundledCoreLine(join(repo, "mods/claude/peer2peer/ext/node_modules/@peer2peer/ext-ix/index.mjs"));
  if (ext !== undefined && ext !== core) {
    console.error(`the ext-ix copy the mod ships inlines another core (${ext.slice(3)}) than ${outRel} (${core.slice(3)}): rebuild it (npm run bundle in packages/ext-ix)`);
    process.exit(1);
  }
  console.log(`${outRel} matches a fresh build (${text.length} bytes)`);
} else {
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, text, { mode: 0o755 });
  const defaults = join(dirname(out), "defaults.json");
  if (!existsSync(defaults)) writeFileSync(defaults, JSON.stringify({ defaultRelays: [] }, null, 2) + "\n");
  console.log(`wrote ${outRel} (${text.length} bytes)`);
}
