// Copyright 2026 Ix Infrastructure Inc.
//
// parseTarget finds a trailing `[ref]` by scanning from the end, not with
// /^(.*?)\s*\[([0-9a-f]{6})\]$/ (code scanning js/polynomial-redos): the same
// results, and time that grows linearly with long whitespace runs.

import { describe, expect, it } from "vitest";
import { parseTarget } from "../sessions.js";

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

function oldParseTarget(to: string): { user: string; pick?: string } {
  const s = to.trim();
  const br = /^(.*?)\s*\[([0-9a-f]{6})\]$/.exec(s);
  if (br) return { user: br[1].trim(), pick: br[2] };
  const i = s.lastIndexOf("/");
  if (i > 0 && i < s.length - 1) return { user: s.slice(0, i), pick: s.slice(i + 1) };
  return { user: s };
}

describe("parseTarget", () => {
  it("matches the old regex", () => {
    for (const s of samples("ab \t\n /[]0f", 4000, 14)) expect(parseTarget(s)).toEqual(oldParseTarget(s));
    for (const s of ["ben [a1b2c3]", "ben\t[a1b2c3]", "ben/api", "ben", "a\nb [a1b2c3]", "[a1b2c3]"]) expect(parseTarget(s)).toEqual(oldParseTarget(s));
  });
  it("is linear on long whitespace runs (alert 14)", () => {
    expect(growth(parseTarget, (n) => `a${"\t".repeat(n)}x`)).toBeLessThan(LIMIT);
    expect(growth(parseTarget, (n) => `a${" ".repeat(n)}[a1b2c3`)).toBeLessThan(LIMIT);
  });
});
