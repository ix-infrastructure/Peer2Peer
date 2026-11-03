// Copyright 2026 Ix Infrastructure Inc.
//
// Which packages/core a bundle inlines: its version and a hash of its sources
// (src/, tests excluded). The two single-file bundles the Claude mod ships,
// mods/claude/peer2peer/bin/p2p.mjs and the ext-ix copy under
// mods/claude/peer2peer/ext, each carry it near the top
// (`// @peer2peer/core <version> <hash>`), and each bundle check refuses a
// pair built from different cores.

import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

export function coreFingerprint(repo) {
  const core = join(repo, "packages", "core");
  const version = JSON.parse(readFileSync(join(core, "package.json"), "utf8")).version;
  const files = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir).sort()) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) {
        if (name !== "__tests__") walk(p);
      } else if (/\.ts$/.test(name)) files.push(p);
    }
  };
  walk(join(core, "src"));
  const h = createHash("sha256");
  for (const f of files) h.update(relative(core, f).split(sep).join("/")).update("\0").update(readFileSync(f)).update("\0");
  return { version, hash: h.digest("hex").slice(0, 16) };
}

export const coreLine = (fp) => `// @peer2peer/core ${fp.version} ${fp.hash}`;

/** The core line a committed bundle carries, or undefined. */
export function bundledCoreLine(file) {
  if (!existsSync(file)) return undefined;
  const head = readFileSync(file, "utf8").slice(0, 400);
  return /^\/\/ @peer2peer\/core \S+ [0-9a-f]+$/m.exec(head)?.[0];
}
