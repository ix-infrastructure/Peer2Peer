// Copyright 2026 Ix Infrastructure Inc.
//
// parseAllowFile strips `#` comments with indexOf, not /#.*$/ (code scanning
// js/polynomial-redos): time grows linearly with a line of many `#`.

import { describe, expect, it } from "vitest";
import { parseAllowFile } from "../config.js";

/** Best-of-5 time for `reps` runs of `f(input)`. */
function cost(f: (s: string) => unknown, input: string, reps = 20): number {
  let best = Infinity;
  for (let t = 0; t < 5; t++) {
    const a = performance.now();
    for (let r = 0; r < reps; r++) f(input);
    best = Math.min(best, performance.now() - a);
  }
  return best;
}

/** How much longer `f` takes on a 100 KB input than on a 10 KB one: ~10 when linear, ~100 when quadratic. */
function growth(f: (s: string) => unknown, make: (n: number) => string): number {
  const small = make(10_000);
  const big = make(100_000);
  f(small);
  f(big);
  return cost(f, big) / Math.max(cost(f, small), 1e-3);
}

/** Deterministic random strings over `alphabet`, up to `max` characters. */
function* samples(alphabet: string, count = 3000, max = 24): Generator<string> {
  let seed = 0x2545f491;
  const next = () => ((seed = (seed * 1103515245 + 12345) >>> 0) >>> 8);
  for (let i = 0; i < count; i++) {
    const n = next() % (max + 1);
    let s = "";
    for (let j = 0; j < n; j++) s += alphabet.charAt(next() % alphabet.length);
    yield s;
  }
}

const LIMIT = 30;

describe("parseAllowFile", () => {
  it("strips comments as before", () => {
    expect(parseAllowFile("alice # friend\n!bob\n# all comment\n\ncarol, dave ##x")).toEqual({ allow: ["alice", "carol", "dave"], deny: ["bob"] });
    for (const s of samples("ab #,!\n\t", 2000, 30)) {
      const old = s.split("\n").map((l) => l.replace(/#.*$/, "").trim()).filter((l) => l !== "").flatMap((l) => l.split(/[\s,]+/));
      expect([...parseAllowFile(s).allow, ...parseAllowFile(s).deny.map((x) => `!${x}`)].sort()).toEqual([...old].sort());
    }
  });
  it("is linear on a line of many # (alert 15)", () => {
    expect(growth(parseAllowFile, (n) => "#".repeat(n))).toBeLessThan(LIMIT);
  });
});
