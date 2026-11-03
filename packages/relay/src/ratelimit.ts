// Copyright 2026 Ix Infrastructure Inc.
//
// In-memory token buckets. A bucket holds `limit` tokens and refills at
// `limit` per `periodMs`, so a key can burst to its limit and then sustain the
// average rate. A take may cost more than one token (byte budgets).
//
// Memory is bounded: at most `maxKeys` buckets. Buckets are kept in
// least-recently-used order; when the map is full, refilled buckets are
// pruned first and then the least recently used one is evicted. State is per
// relay process, so limits reset on restart, which is acceptable for spam
// control.

export class RateLimiter {
  private readonly buckets = new Map<string, { tokens: number; t: number }>();

  constructor(
    readonly limit: number,
    readonly periodMs: number,
    private readonly now: () => number,
    readonly maxKeys = 100_000,
  ) {}

  private bucket(key: string): { tokens: number; t: number } {
    const now = this.now();
    let b = this.buckets.get(key);
    if (b) {
      // Refresh the LRU position.
      this.buckets.delete(key);
      if (now > b.t) {
        b.tokens = Math.min(this.limit, b.tokens + ((now - b.t) * this.limit) / this.periodMs);
        b.t = now;
      }
    } else {
      if (this.buckets.size >= this.maxKeys) this.prune();
      while (this.buckets.size >= this.maxKeys) {
        const oldest = this.buckets.keys().next().value as string;
        this.buckets.delete(oldest);
      }
      b = { tokens: this.limit, t: now };
    }
    this.buckets.set(key, b);
    return b;
  }

  /** Whether `key` has `cost` tokens, without taking them. */
  has(key: string, cost = 1): boolean {
    return this.bucket(key).tokens >= cost;
  }

  /** Takes `cost` tokens from `key`; false (and nothing taken) when there aren't enough. */
  take(key: string, cost = 1): boolean {
    const b = this.bucket(key);
    if (b.tokens < cost) return false;
    b.tokens -= cost;
    return true;
  }

  /** Drops buckets that have refilled completely: they carry no state. */
  prune(): void {
    const now = this.now();
    for (const [k, b] of this.buckets) {
      if (b.tokens + ((now - b.t) * this.limit) / this.periodMs >= this.limit) this.buckets.delete(k);
    }
  }

  get size(): number {
    return this.buckets.size;
  }
}
