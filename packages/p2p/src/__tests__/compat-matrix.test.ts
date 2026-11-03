// Copyright 2026 Ix Infrastructure Inc.
//
// The cross-version matrix (scripts/compat/matrix.mjs, docs/compatibility.md) as a test: this
// tree's committed CLI bundle against the bundles at earlier refs, both ways. It needs git history
// and a built packages/relay, so it runs only with P2P_COMPAT=1 (P2P_COMPAT_REFS picks the refs);
// the release checklist and the manual CI dispatch run it.

import { describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");

describe.skipIf(process.env.P2P_COMPAT !== "1")("cross-version matrix", () => {
  it("every shared feature works both ways against each earlier ref, and no envelope is rejected", async () => {
    const out = await new Promise<string>((done) =>
      execFile(process.execPath, [join(ROOT, "scripts/compat/matrix.mjs"), "--json"], { cwd: ROOT, maxBuffer: 16 * 1024 * 1024, env: process.env }, (_e, stdout) => done(String(stdout))),
    );
    const r = JSON.parse(out) as { ok: boolean; results: { direction: string; ref: string; checks: { name: string; ok: boolean; detail?: string }[] }[] };
    const failed = r.results.flatMap((x) => x.checks.filter((c) => !c.ok).map((c) => `${x.direction} ${x.ref}: ${c.name}: ${c.detail}`));
    expect(failed).toEqual([]);
    expect(r.results.length).toBeGreaterThanOrEqual(4);
  }, 900_000);
});
