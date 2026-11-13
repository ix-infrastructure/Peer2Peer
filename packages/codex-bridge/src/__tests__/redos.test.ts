// Copyright 2026 Ix Infrastructure Inc.
//
// The scans that replaced polynomial-backtracking regexes (code scanning
// js/polynomial-redos): each gives what the old regex gave, and its time grows
// linearly with adversarial input (a 100 KB input costs ~10x a 10 KB one, not ~100x).

import { describe, expect, it } from "vitest";
import { configConflict, replaceBlock } from "../install.js";
import { addressLabel, cleanSummary, isInside, parseAddress, pathBasename, sanitizeLabel, splitRef, trimChars } from "../lib.js";

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

describe("trimChars / splitRef match the regexes they replaced", () => {
  it("trimChars", () => {
    for (const s of samples("-a/\\\"'`\n x")) {
      expect(trimChars(s, "-", true)).toBe(s.replace(/^-+|-+$/g, ""));
      expect(trimChars(s, "\\/")).toBe(s.replace(/[\\/]+$/, ""));
      expect(trimChars(s, "/")).toBe(s.replace(/\/+$/, ""));
      expect(trimChars(s, "\n")).toBe(s.replace(/\n*$/, ""));
      expect(trimChars(s, "\"'`", true)).toBe(s.replace(/^["'`]+|["'`]+$/g, ""));
    }
  });
  it("splitRef", () => {
    const old = (s: string) => {
      const m = /^(.*?)\s*\[([0-9a-f]{6})\]$/.exec(s);
      return m ? [m[1], m[2]] : null;
    };
    for (const s of samples("ab \t\n\r\u2028[]0f", 4000, 14)) expect(splitRef(s)).toEqual(old(s));
    for (const s of ["x [a1b2c3]", "x\t \t[a1b2c3]", "[a1b2c3]", "a\nb [a1b2c3]", "a [a1b2c3] ", "a [A1B2C3]", "a [a1b2c]"]) expect(splitRef(s)).toEqual(old(s));
  });
});

describe("linear on adversarial input", () => {
  it("parseAddress: a long whitespace run before a would-be ref (alert 6)", () => {
    expect(growth(parseAddress, (n) => `a${"\t".repeat(n)}x`)).toBeLessThan(LIMIT);
    expect(growth(parseAddress, (n) => `a${" ".repeat(n)}[a1b2c3`)).toBeLessThan(LIMIT);
    expect(parseAddress(`p2p:${"a".repeat(24)} \t [a1b2c3]`)).toEqual({ user: `p2p:${"a".repeat(24)}`, ref: "a1b2c3" });
  });
  it("sanitizeLabel / addressLabel: long dash runs (alerts 4, 5)", () => {
    expect(growth(sanitizeLabel, (n) => `${"-".repeat(n)}x`)).toBeLessThan(LIMIT);
    expect(growth(sanitizeLabel, (n) => `x${"-".repeat(n)}x`)).toBeLessThan(LIMIT);
    expect(growth(addressLabel, (n) => `x${"/".repeat(n)}x`)).toBeLessThan(LIMIT);
    expect(growth(addressLabel, (n) => `x${"-".repeat(n)}x`)).toBeLessThan(LIMIT);
    expect(sanitizeLabel("--My Label--")).toBe("my-label");
    expect(addressLabel(" /a b/ ")).toBe("a-b");
  });
  it("pathBasename: long separator runs (alert 7)", () => {
    expect(growth(pathBasename, (n) => `a${"/".repeat(n)}a`)).toBeLessThan(LIMIT);
    expect(pathBasename("C:\\Users\\x\\Repo\\\\")).toBe("Repo");
  });
  it("cleanSummary: long quote runs (alert 8)", () => {
    expect(growth(cleanSummary, (n) => `x${'"'.repeat(n)}x`)).toBeLessThan(LIMIT);
    expect(cleanSummary('"`fixing the parser`"')).toBe("fixing the parser");
  });
  it("isInside: long slash runs (alert 10)", () => {
    expect(growth((s) => isInside(s, "/r", false), (n) => `/r${"/".repeat(n)}x`)).toBeLessThan(LIMIT);
    expect(isInside("/r/a//", "/r//", false)).toBe(true);
  });
  it("replaceBlock / configConflict: newline and `#` runs (alerts 2, 3)", () => {
    expect(growth((s) => replaceBlock(s, "<b>", "<e>", "x"), (n) => `a${"\n".repeat(n)}a`)).toBeLessThan(LIMIT);
    expect(growth(configConflict, (n) => "#".repeat(n))).toBeLessThan(LIMIT);
    expect(replaceBlock("a\n\n\n", "<b>", "<e>", "x")).toBe("a\n\nx\n");
    expect(configConflict("[mcp_servers.peer2peer] # trailing comment")).toMatch(/already defines/);
  });
});
