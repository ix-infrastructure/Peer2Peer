#!/usr/bin/env node
// Enforces the layer rule in docs/architecture.md: the core network
// (packages/core, relay, p2p, codex-bridge and mods/*) never imports an extension
// (packages/ext-*) or anything from Ix or Kartr. Extensions may import core.
//
//   node scripts/check-boundaries.mjs                 exit 1 and list every violation
//   node scripts/check-boundaries.mjs --root <dir>    check another tree (tests)
//
// Three rules:
//   1. No core source names an extension, Ix or Kartr in an import, export,
//      require, import() or reference (static or literal dynamic).
//   2. The only non-literal import()/require() in core is the extension
//      loader (LOADERS): p2p finds installed @peer2peer/ext-* packages at run
//      time and imports them by resolved file URL (packages/p2p/src/
//      extensions.ts, documented there). The committed single-file bundle of
//      the CLI inlines that loader, so it is allowed too (scripts/
//      check-bundle.sh proves it is exactly what the sources build).
//   3. No core package.json lists an extension, Ix or Kartr package in any
//      dependency field, so no install of core pulls one in.
//
// A lint, not a sandbox: regex-based, so exotic forms (string literals that
// contain comment markers, a computed member call) can slip past. Review
// still applies.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const rootArg = process.argv.indexOf("--root");
const root = rootArg > 0 && process.argv[rootArg + 1] ? process.argv[rootArg + 1] : join(fileURLToPath(import.meta.url), "..", "..");
const CORE = ["packages/core", "packages/relay", "packages/p2p", "packages/codex-bridge", "mods"];
const SKIP = new Set(["node_modules", "dist", ".claude-plugin", "coverage"]);
const SOURCE = /\.(?:[cm]?[jt]sx?)$/;

// A specifier is forbidden in core when it names an extension package, reaches
// into packages/ext-*, or is an Ix/Kartr package.
// The Claude mod ships a bundled, disabled-by-default copy of ext-ix under
// mods/claude/peer2peer/ext/node_modules (a distribution, loaded only by the
// p2p loader once the user enables it); it is skipped as node_modules, and no
// core code may import it by path either.
const FORBIDDEN = [
  /^@peer2peer\/ext-/,
  /(?:^|\/)node_modules\/@peer2peer\/ext-|(?:^|\/)ext\/node_modules(?:\/|$)/,
  /(?:^|\/)packages\/ext-|^(?:\.\.\/)+ext-[a-z0-9-]+(?:\/|$)/,
  /^@ix\//,
  /^@kartr\//,
];
// Every way a module names another: from "x" (import/export, minified or
// multi-line), side-effect import "x", import("x") / import(`x`), require("x"),
// and /// <reference types="x" />. Comments are blanked first so prose that
// mentions "import" can't pair with a later specifier.
const SPECIFIER = /\bfrom\s*(["'`])([^"'`]+)\1|\bimport\s*(["'`])([^"'`]+)\3|\b(?:import|require)\s*\(\s*(["'`])([^"'`]+)\5\s*\)|<reference\s+(?:types|path)\s*=\s*(["'])([^"']+)\7/g;
const COMMENTS = /\/\*[\s\S]*?\*\/|(?<![:"'`\\/])\/\/(?!\/\s*<reference).*$/gm;
// import(x) / require(x) whose argument is not a string literal.
const COMPUTED = /\b(import|require)\s*\(\s*(?!["'`])(?=[^\s)])/g;
// The extension loader and the committed bundle that inlines it (rule 2).
const LOADERS = new Set(["packages/p2p/src/extensions.ts", "mods/claude/peer2peer/bin/p2p.mjs"]);
const DEP_FIELDS = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "bundleDependencies", "bundledDependencies"];

function* files(dir) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of entries) {
    if (SKIP.has(name)) continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) yield* files(path);
    else if (SOURCE.test(name)) yield path;
  }
}

function* manifests(dir) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of entries) {
    if (SKIP.has(name)) continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) yield* manifests(path);
    else if (name === "package.json") yield path;
  }
}

const violations = [];
for (const area of CORE) {
  for (const file of files(join(root, area))) {
    const rel = relative(root, file).split(sep).join("/");
    // Keep offsets (and so line numbers) stable: comments become spaces.
    const text = readFileSync(file, "utf8").replace(COMMENTS, (c) => c.replace(/[^\n]/g, " "));
    const lineOf = (i) => text.slice(0, i).split("\n").length;
    for (const m of text.matchAll(SPECIFIER)) {
      const spec = m[2] ?? m[4] ?? m[6] ?? m[8];
      if (FORBIDDEN.some((re) => re.test(spec))) violations.push(`${rel}:${lineOf(m.index)}  imports ${spec}`);
    }
    if (!LOADERS.has(rel)) {
      for (const m of text.matchAll(COMPUTED)) violations.push(`${rel}:${lineOf(m.index)}  computed ${m[1]}(): only the extension loader may (packages/p2p/src/extensions.ts)`);
    }
  }
  for (const file of manifests(join(root, area))) {
    let pkg;
    try {
      pkg = JSON.parse(readFileSync(file, "utf8"));
    } catch {
      continue;
    }
    for (const field of DEP_FIELDS) {
      const deps = pkg?.[field];
      const names = Array.isArray(deps) ? deps : Object.keys(deps ?? {});
      for (const name of names) {
        if (FORBIDDEN.some((re) => re.test(name))) violations.push(`${relative(root, file).split(sep).join("/")}  ${field} lists ${name}`);
      }
    }
  }
}

if (violations.length > 0) {
  console.error("Core must not import or depend on extensions, Ix or Kartr (docs/architecture.md):");
  for (const v of violations) console.error(`  ${v}`);
  process.exit(1);
}
console.log("boundaries ok");
