// Copyright 2026 Ix Infrastructure Inc.
// #11 The periodic sweep on a store of many small envelopes: event-loop delay
// during the sweep stays under the threshold.
//
// The store is seeded through SqliteStore directly (the relay's own store
// class, before the relay starts) because minting 120k signed envelopes would
// take minutes; stored envelopes are opaque to the relay anyway.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { SqliteStore } from "../src/sqlite-store.js";
import { assertHealthy, Canary, report, round, Sampler, sleep, THRESHOLDS } from "./harness/load.js";
import { RelayProcess } from "./harness/relay-process.js";

const ENVELOPES = 120_000;
const EXPIRED_SHARE = 3; // one in three is past retention
const MAILBOXES = 2_000;
const SOURCES = 50;
const DAY = 24 * 3600 * 1000;

let relay: RelayProcess | undefined;
let canary: Canary | undefined;
let dir: string | undefined;
afterEach(async () => {
  canary?.close();
  await relay?.dispose();
  if (dir) rmSync(dir, { recursive: true, force: true });
});

function seed(path: string): number {
  const t0 = performance.now();
  const store = new SqliteStore(path);
  const now = Date.now();
  const env = "e".repeat(150);
  store.transaction(() => {
    for (let i = 0; i < ENVELOPES; i++) {
      const mb = i % MAILBOXES;
      store.putEnvelope(
        {
          to: `p:seed${mb}`,
          tdid: `d_seed${mb}`,
          env,
          size: env.length,
          receivedAt: i % EXPIRED_SHARE === 0 ? now - 8 * DAY : now - 1000,
          src: `src${i % SOURCES}`,
        },
        { maxEnvelopes: 1e9, maxBytes: 1e12 },
      );
    }
  });
  store.close();
  return round(performance.now() - t0);
}

/**
 * What incremental expiry must hold: no stall anywhere near the old
 * 250-900 ms. The strict suite thresholds (p99 < 50 ms, sweep max < 100 ms)
 * are in the skipped test below: current main sits right at them (F-4).
 */
const NO_STALL_P99_MS = 100;
const NO_STALL_MAX_MS = 250;

async function sweepUnderLoad() {
  dir = mkdtempSync(join(tmpdir(), "relay-resilience-sweep-"));
  const seedMs = seed(join(dir, "relay.db"));
  relay = await RelayProcess.start({ dir, env: { TRUST_PROXY: "1", SWEEP_INTERVAL_SEC: "1" } });
  const sampler = await Sampler.start(relay);
  canary = await Canary.start(relay, { intervalMs: 100 });
  await sleep(3500); // three or four sweeps, the first expiring 40k rows in batches
  // One more, timed in the relay process itself.
  const sweepMs = round(await relay.sweep());
  await sleep(500);
  const st = await relay.stats({ store: true });
  report({ test: "11 sweep (detail)", envelopesSeeded: ENVELOPES, seedMs, sweepMs, lagMaxMs: round(st.lagMs?.max ?? 0), storeEnvelopes: st.store?.envelopes });
  return { sampler, seedMs, sweepMs };
}

describe("11. periodic sweep on a store of many small envelopes", () => {
  // Was FINDINGS.md F-4 at 250-935 ms; expiry has since been made incremental.
  it("sweeps every second over 120k envelopes without stalling the event loop", async () => {
    const { sampler, seedMs, sweepMs } = await sweepUnderLoad();
    const { stats } = await assertHealthy({
      test: "11a sweep",
      relay: relay!,
      sampler,
      canary,
      limits: { SWEEP_INTERVAL_SEC: 1, envelopes: ENVELOPES },
      lagP99Ms: NO_STALL_P99_MS,
      extra: { seedMs, sweepMs },
    });
    expect(stats.lagMs!.max).toBeLessThan(NO_STALL_MAX_MS);
    expect(stats.store!.envelopes).toBeLessThanOrEqual(ENVELOPES - ENVELOPES / EXPIRED_SHARE + 2);
  });

  // Was FINDINGS.md F-4 (residual): expiry batches now adapt to ~10 ms each
  // and the sweep prelude is chunked and yields.
  it("keeps event-loop delay p99 < 50 ms and max < 100 ms while sweeps run every second over 120k envelopes", async () => {
    const { sampler, seedMs, sweepMs } = await sweepUnderLoad();
    const { stats } = await assertHealthy({ test: "11b sweep (strict)", relay: relay!, sampler, canary, limits: { SWEEP_INTERVAL_SEC: 1, envelopes: ENVELOPES }, extra: { seedMs, sweepMs } });
    expect(stats.lagMs!.max).toBeLessThan(THRESHOLDS.sweepLagMaxMs);
  });
});
