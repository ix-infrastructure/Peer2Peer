// Copyright 2026 Ix Infrastructure Inc.
//
// URL userinfo redaction without the polynomial-backtracking regex (code
// scanning js/polynomial-redos): the same matches as the old regex, and time
// that grows linearly with adversarial input (100 KB costs ~10x 10 KB, not ~100x).

import { describe, expect, it } from "vitest";
import { redactSecrets } from "../redact.js";

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

const OLD = /([A-Za-z][A-Za-z0-9+.-]*:\/\/)[^\s/@]+@/g;

describe("redactSecrets: URL userinfo", () => {
  it("matches the old regex", () => {
    // Inputs short and free of the other secret shapes, so only the userinfo rule applies.
    for (const s of samples("ab1+.-:/@ \tx", 6000, 20)) {
      expect(redactSecrets(s)).toBe(s.replace(OLD, "$1[redacted]@"));
    }
    for (const s of ["https://u:p@h/x", "x1https://u@h", "1+://u@h", "a://@h", "a://u@b://v@c", "git+ssh://git@host:repo", "see http://a b@c"]) {
      expect(redactSecrets(s)).toBe(s.replace(OLD, "$1[redacted]@"));
    }
  });
  it("is linear on long letter runs and repeated schemes (alert 11)", () => {
    expect(growth(redactSecrets, (n) => "A".repeat(n))).toBeLessThan(LIMIT);
    expect(growth(redactSecrets, (n) => "a://".repeat(n / 4))).toBeLessThan(LIMIT);
    expect(growth(redactSecrets, (n) => `a://${"x".repeat(n)}`)).toBeLessThan(LIMIT);
  });
});
