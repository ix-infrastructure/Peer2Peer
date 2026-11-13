// Copyright 2026 Ix Infrastructure Inc.
//
// parseTarget finds a trailing `[ref]` by scanning from the end, not with
// /^(.*?)\s*\[([0-9a-f]{6})\]$/ (code scanning js/polynomial-redos): the same
// results, and time that grows linearly with long whitespace runs.

import { describe, expect, it } from "vitest";
import { parseTarget } from "../sessions.js";

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
