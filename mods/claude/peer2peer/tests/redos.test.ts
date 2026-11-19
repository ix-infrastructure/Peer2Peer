// Copyright 2026 Ix Infrastructure Inc.

// The scans that replaced polynomial-backtracking regexes (kept in step with
// packages/codex-bridge/src/lib.ts): each gives what the old regex gave, and its
// time grows linearly with adversarial input (100 KB costs ~10x 10 KB, not ~100x).

import { describe, expect, test } from 'claude-code/testing'

import { addressLabel, cleanSummary, isNonAnswer, parseAddress, pathBasename, queuedNote, sanitizeLabel, splitRef, trimChars } from '../hooks/lib'

/** Time for `reps` runs of `f(input)`. */
function run(f: (s: string) => unknown, input: string, reps: number): number {
  const a = performance.now()
  for (let r = 0; r < reps; r++) f(input)
  return performance.now() - a
}

/**
 * How much longer `f` takes on a 100 KB input than on a 10 KB one: ~10 when linear, ~100 when quadratic.
 * Relative, so a slow runner passes: the repeat count is calibrated so the 10 KB timing is at least ~2 ms
 * (well above timer noise), the two sizes are timed alternately (a slow spell on a shared runner hits
 * both), each is the best of 5, and a ratio just over LIMIT (under 2x it) is measured again, up to 3 times,
 * keeping the lowest: noise doesn't repeat, a quadratic scan (~100) does every time and isn't retried.
 */
function growth(f: (s: string) => unknown, make: (n: number) => string): number {
  const small = make(10_000)
  const big = make(100_000)
  f(small)
  f(big)
  let reps = 1
  while (reps < 1024 && run(f, small, reps) < 2) reps *= 2
  let ratio = Infinity
  for (let attempt = 0; attempt < 3 && (attempt === 0 || (ratio >= LIMIT && ratio < 2 * LIMIT)); attempt++) {
    let s = Infinity
    let b = Infinity
    for (let t = 0; t < 5; t++) {
      s = Math.min(s, run(f, small, reps))
      b = Math.min(b, run(f, big, reps))
    }
    ratio = Math.min(ratio, b / Math.max(s, 1e-3))
  }
  return ratio
}

/** Deterministic random strings over `alphabet`, up to `max` characters. */
function* samples(alphabet: string, count = 3000, max = 24): Generator<string> {
  let seed = 0x2545f491
  const next = () => ((seed = (seed * 1103515245 + 12345) >>> 0) >>> 8)
  for (let i = 0; i < count; i++) {
    const n = next() % (max + 1)
    let s = ''
    for (let j = 0; j < n; j++) s += alphabet.charAt(next() % alphabet.length)
    yield s
  }
}

const LIMIT = 30

describe('trimChars / splitRef match the regexes they replaced', () => {
  test('trimChars', () => {
    for (const s of samples("-a/\\\"'`\n x")) {
      expect(trimChars(s, '-', true)).toBe(s.replace(/^-+|-+$/g, ''))
      expect(trimChars(s, '\\/')).toBe(s.replace(/[\\/]+$/, ''))
      expect(trimChars(s, "\"'`", true)).toBe(s.replace(/^["'`]+|["'`]+$/g, ''))
    }
  })
  test('splitRef', () => {
    const old = (s: string) => {
      const m = /^(.*?)\s*\[([0-9a-f]{6})\]$/.exec(s)
      return m ? [m[1], m[2]] : null
    }
    for (const s of samples('ab \t\n\r []0f', 4000, 14)) expect(splitRef(s)).toEqual(old(s))
  })
})

describe('linear on adversarial input', () => {
  test('parseAddress, sanitizeLabel, addressLabel, pathBasename, cleanSummary, isNonAnswer', () => {
    expect(growth(parseAddress, n => `a${'\t'.repeat(n)}x`)).toBeLessThan(LIMIT)
    expect(growth(sanitizeLabel, n => `x${'-'.repeat(n)}x`)).toBeLessThan(LIMIT)
    expect(growth(addressLabel, n => `x${'/'.repeat(n)}x`)).toBeLessThan(LIMIT)
    expect(growth(pathBasename, n => `a${'/'.repeat(n)}a`)).toBeLessThan(LIMIT)
    expect(growth(s => cleanSummary(s), n => `x${'"'.repeat(n)}x`)).toBeLessThan(LIMIT)
    expect(growth(isNonAnswer, n => `x${'”'.repeat(n)}x`)).toBeLessThan(LIMIT)
    expect(isNonAnswer('“I can’t tell from this request.”')).toBe(true)
    expect(isNonAnswer('"Fixing the parser"')).toBe(false)
    expect(parseAddress('p2p:ben@abcd-efgh-ijkl-mnop/api \t [a1b2c3]')).toEqual({ user: 'ben@abcd-efgh-ijkl-mnop', label: 'api', ref: 'a1b2c3' })
  })
})

describe('queuedNote', () => {
  test('the address attribute never carries a double quote', () => {
    const note = queuedNote('p2p:ben@abcd-efgh-ijkl-mnop/a"b', { state: 'offline' }, 0)
    expect(note).toContain('<cross-session-message from="p2p:ben@abcd-efgh-ijkl-mnop/ab">')
  })
})
