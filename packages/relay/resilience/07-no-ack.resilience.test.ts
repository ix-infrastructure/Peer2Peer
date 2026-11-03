// Copyright 2026 Ix Infrastructure Inc.
// #7 Receivers that never ack: one reads but never acks, one stops reading
// its socket altogether. Relay memory stays flat; the mailbox cap holds.

import { afterEach, describe, expect, it } from "vitest";
import type { Socket } from "node:net";
import { makeCap, type TestClient } from "../src/__tests__/helpers.js";
import { assertHealthy, authedFrom, Canary, collectEnvs, mib, newDevice, Sampler, sendBatched, sendFrame, sleep } from "./harness/load.js";
import { RelayProcess } from "./harness/relay-process.js";

const ATTACK_IP = "198.51.100.90";
const limits = {
  mailboxEnvelopes: 200,
  sendsPerMinute: 5000,
  framesPerConnPerMinute: 10_000,
  sendBytesPerConnPerMinute: 256 * 1024 * 1024,
  sendBytesPerIpPerMinute: 256 * 1024 * 1024,
};
/** Six chunks of 200 envelopes of ~60 KB (~12 MB each); 3 in 4 go to the receiver that isn't reading. */
const CHUNKS = 6;
const PER_CHUNK = 200;
/** The first chunk fills both mailboxes; measurement starts after it. */
const WARM_CHUNKS = 1;
/**
 * "Flat": RSS is read after every chunk. V8 takes one heap-reservation step
 * for large strings (~25-40 MB, in chunk 2 or 3 depending on GC timing), so
 * the largest chunk-to-chunk rise is set aside as that step; the remaining
 * rises together must stay under this. A relay that ignored backpressure
 * would hold the stuck receiver's ~9 MB per chunk and blow through it.
 */
const FLAT_RSS_BYTES = 24 * 1024 * 1024;

let relay: RelayProcess;
let canary: Canary | undefined;
afterEach(async () => {
  canary?.close();
  await relay?.dispose();
});

const rawSocket = (c: TestClient) => (c.ws as unknown as { _socket: Socket })._socket;

describe("7. a receiver that never acks", () => {
  it("keeps relay memory flat while mail piles up for a non-acking and a non-reading receiver", async () => {
    relay = await RelayProcess.start({ limits, env: { TRUST_PROXY: "1" } });
    const lazy = newDevice(relay); // reads, never acks
    const stuck = newDevice(relay); // stops reading its socket
    const lc = await authedFrom(relay, lazy, "198.51.100.91");
    const sc = await authedFrom(relay, stuck, "198.51.100.92");
    rawSocket(sc).pause();
    const m = newDevice(relay);
    const mc = await authedFrom(relay, m, ATTACK_IP);
    const capL = makeCap(lazy, relay.nowSec()).jws;
    const capS = makeCap(stuck, relay.nowSec()).jws;

    // Minted up front: signing 12 MB of envelopes would stall this process and skew the canary's latency.
    const chunks = Array.from({ length: CHUNKS }, () =>
      Array.from({ length: PER_CHUNK }, (_, i) => sendFrame(m, i % 4 ? stuck : lazy, { cap: i % 4 ? capS : capL, padTo: 45_000 })),
    );
    const rss: number[] = [];
    const codes: Record<string, number> = {};
    let bytes = 0;
    let sampler: Sampler | undefined;
    let before = await relay.stats();
    for (let k = 0; k < CHUNKS; k++) {
      if (k === WARM_CHUNKS) {
        sampler = await Sampler.start(relay);
        before = await relay.stats();
        canary = await Canary.start(relay);
      }
      const chunk = chunks[k];
      bytes += chunk.reduce((n, f) => n + Buffer.byteLength(f.env as string), 0);
      for (const [c, v] of Object.entries(await sendBatched(mc, chunk))) codes[c] = (codes[c] ?? 0) + v;
      await sleep(100);
      rss.push((await relay.stats()).rssBytes);
    }
    const lazyGot = await collectEnvs(lc, { quietMs: 200 });
    const mid = await relay.stats({ store: true });

    // The lazy receiver reconnects: everything un-acked comes again, capped by mailboxEnvelopes.
    lc.ws.terminate();
    const lc2 = await authedFrom(relay, lazy, "198.51.100.91");
    const redelivered = await collectEnvs(lc2, { quietMs: 300 });
    // The stuck receiver resumes reading and drains.
    rawSocket(sc).resume();
    const stuckGot = await collectEnvs(sc, { quietMs: 300 });

    const rises = rss.slice(1).map((r, i) => r - rss[i]);
    const step = Math.max(...rises);
    const drift = rises.reduce((a, b) => a + Math.max(0, b), 0) - Math.max(0, step);
    await assertHealthy({
      test: "7 no-ack receiver",
      relay,
      sampler: sampler!,
      canary,
      limits,
      extra: {
        floodMiB: mib(bytes),
        codes,
        rssPerChunkMiB: rss.map(mib),
        heapStepMiB: mib(step),
        driftMiB: mib(drift),
        heapBeforeMiB: mib(before.heapUsedBytes),
        heapAfterMiB: mib(mid.heapUsedBytes),
        storedEnvelopes: mid.store?.envelopes,
        lazyLive: lazyGot.length,
        lazyRedelivered: redelivered.length,
        stuckDrained: stuckGot.length,
      },
    });
    expect(codes).toEqual({ sent: CHUNKS * PER_CHUNK });
    expect(drift).toBeLessThan(FLAT_RSS_BYTES);
    // heapUsed is reported but not asserted: with lazy GC it swings by ~25 MB between reads.
    // Each mailbox holds at most mailboxEnvelopes un-acked envelopes.
    expect(mid.store!.envelopes).toBeLessThanOrEqual(2 * limits.mailboxEnvelopes + 2);
    expect(redelivered.length).toBe(limits.mailboxEnvelopes);
    // Backpressure: the stuck receiver was sent only what fit its buffers, far less than the ~53 MB queued for it.
    expect(stuckGot.length).toBeGreaterThan(0);
    expect(stuckGot.length).toBeLessThan((CHUNKS * PER_CHUNK * 3) / 4);
  });
});
