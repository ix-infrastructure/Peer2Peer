// Copyright 2026 Ix Infrastructure Inc.
//
// Builds the copy of ext-ix the Claude mod ships, so the bundled `p2p` can
// find it without an npm install: one self-contained ESM file (core inlined,
// unminified) plus its package.json, at
//   mods/claude/peer2peer/ext/node_modules/@peer2peer/ext-ix/
// The mod passes `<plugin>/ext` in P2P_EXTENSION_PATH. Shipping it enables
// nothing: `p2p` loads it only once the user runs `p2p extensions enable ix`.
//
//   node scripts/bundle.mjs           write it
//   node scripts/bundle.mjs --check   fail unless the committed copy is what the sources build
//
// Deterministic like packages/p2p/scripts/bundle.mjs (pinned esbuild, repo-relative paths).
// Needs packages/core built.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { bundledCoreLine, coreFingerprint, coreLine } from "../../../scripts/core-fingerprint.mjs";

const pkgDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repo = resolve(pkgDir, "../..");
const outDirRel = "mods/claude/peer2peer/ext/node_modules/@peer2peer/ext-ix";
const outDir = join(repo, outDirRel);
const check = process.argv.includes("--check");
const pkg = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8"));
// First line: which core this copy inlines; it must be the one the mod's bin/p2p.mjs inlines.
const core = coreLine(coreFingerprint(repo));

const result = await build({
  absWorkingDir: repo,
  entryPoints: ["packages/ext-ix/src/index.ts"],
  outfile: `${outDirRel}/index.mjs`,
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  write: false,
  minify: false,
  sourcemap: false,
  charset: "utf8",
  legalComments: "eof",
  banner: { js: core },
  logLevel: "warning",
});
const files = {
  "index.mjs": Buffer.from(result.outputFiles[0].contents),
  "package.json": Buffer.from(
    JSON.stringify(
      {
        name: pkg.name,
        version: pkg.version,
        description: `${pkg.description} (bundled copy shipped with the Claude Code mod; built by packages/ext-ix/scripts/bundle.mjs)`,
        license: pkg.license,
        type: "module",
        exports: { ".": { default: "./index.mjs" } },
      },
      null,
      2,
    ) + "\n",
  ),
};

if (check) {
  for (const [name, bytes] of Object.entries(files)) {
    const p = join(outDir, name);
    if (!existsSync(p) || !readFileSync(p).equals(bytes)) {
      console.error(`${outDirRel}/${name} is not what the sources build: run \`npm run bundle\` in packages/ext-ix and commit it`);
      process.exit(1);
    }
  }
  const p2p = bundledCoreLine(join(repo, "mods/claude/peer2peer/bin/p2p.mjs"));
  if (p2p !== core) {
    console.error(`mods/claude/peer2peer/bin/p2p.mjs inlines another core (${p2p ? p2p.slice(3) : "none recorded"}) than this copy (${core.slice(3)}): rebuild it (npm run bundle in packages/p2p)`);
    process.exit(1);
  }
  console.log(`${outDirRel} matches a fresh build (${files["index.mjs"].length} bytes)`);
} else {
  mkdirSync(outDir, { recursive: true });
  for (const [name, bytes] of Object.entries(files)) writeFileSync(join(outDir, name), bytes);
  console.log(`wrote ${outDirRel} (${files["index.mjs"].length} bytes)`);
}
