// Copyright 2026 Ix Infrastructure Inc.
//
// Trailing-separator trims without /[\\/]+$/ or /\/+$/ (code scanning
// js/polynomial-redos): the same results, and time that grows linearly with
// long separator runs.

import { describe, expect, it } from "vitest";
import { splitPattern } from "../subgraph.js";
import { scrubPaths, trimEnd } from "../text.js";

/** Time for `reps` runs of `f(input)`. */
function run(f: (s: string) => unknown, input: string, reps: number): number {
  const a = performance.now();
  for (let r = 0; r < reps; r++) f(input);
  return performance.now() - a;
}

/**
 * How much longer `f` takes on a 100 KB input than on a 10 KB one: ~10 when linear, ~100 when quadratic.
 * Relative, so a slow runner passes: the repeat count is calibrated so the 10 KB timing is at least ~2 ms
 * (well above timer noise), the two sizes are timed alternately (a slow spell on a shared runner hits
 * both), each is the best of 5, and a ratio just over LIMIT (under 2x it) is measured again, up to 3 times,
 * keeping the lowest: noise doesn't repeat, a quadratic scan (~100) does every time and isn't retried.
 */
function growth(f: (s: string) => unknown, make: (n: number) => string): number {
  const small = make(10_000);
  const big = make(100_000);
  f(small);
  f(big);
  let reps = 1;
  while (reps < 1024 && run(f, small, reps) < 2) reps *= 2;
  let ratio = Infinity;
  for (let attempt = 0; attempt < 3 && (attempt === 0 || (ratio >= LIMIT && ratio < 2 * LIMIT)); attempt++) {
    let s = Infinity;
    let b = Infinity;
    for (let t = 0; t < 5; t++) {
      s = Math.min(s, run(f, small, reps));
      b = Math.min(b, run(f, big, reps));
    }
    ratio = Math.min(ratio, b / Math.max(s, 1e-3));
  }
  return ratio;
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

describe("trimEnd", () => {
  it("matches the old regexes", () => {
    for (const s of samples("a/\\ x", 3000, 20)) {
      expect(trimEnd(s, "\\/")).toBe(s.replace(/[\\/]+$/, ""));
      expect(trimEnd(s, "/")).toBe(s.replace(/\/+$/, ""));
    }
  });
  it("scrubPaths: a root with a long separator run is linear (alert 13)", () => {
    expect(growth((r) => scrubPaths("x", { root: r }), (n) => `/a${"/".repeat(n)}a`)).toBeLessThan(LIMIT);
    expect(scrubPaths("see /r/x/a.ts", { root: "/r/x///" })).toBe("see ./a.ts");
  });
  it("splitPattern: a long slash run is linear (alert 12)", () => {
    // splitPattern caps the pattern length, so the scan itself is measured at full size.
    expect(growth((s) => trimEnd(s, "/"), (n) => `a${"/".repeat(n)}a`)).toBeLessThan(LIMIT);
    expect(splitPattern("auth///")).toEqual({ prefix: "auth" });
    expect(splitPattern("auth/*")).toEqual({ prefix: "auth", glob: "*" });
    expect(splitPattern("a".repeat(10) + "/".repeat(200))).toEqual(splitPattern("a".repeat(10)));
  });
});
