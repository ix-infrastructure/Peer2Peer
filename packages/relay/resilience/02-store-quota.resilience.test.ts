// Copyright 2026 Ix Infrastructure Inc.
// #2 Store quota and source-first eviction.

import { afterEach, describe, expect, it } from "vitest";
import { makeCap } from "../src/__tests__/helpers.js";
import {
  assertHealthy,
  authedFrom,
  Canary,
  CANARY_IP,
  drainMailbox,
  newDevice,
  register,
  Sampler,
  sendBatched,
  sendFrame,
  sendPipelined,
} from "./harness/load.js";
import { RelayProcess } from "./harness/relay-process.js";

const ATTACK_IP = "198.51.100.20";
const limits = {
  storeMaxBytes: 256 * 1024,
  storeHardMaxBytes: 384 * 1024,
  sendsPerMinute: 1000,
  framesPerConnPerMinute: 5000,
  sendBytesPerConnPerMinute: 4 * 1024 * 1024,
  sendBytesPerIpPerMinute: 8 * 1024 * 1024,
};

let relay: RelayProcess;
let canary: Canary | undefined;
afterEach(async () => {
  canary?.close();
  await relay?.dispose();
});

describe("2. store quota and source-first eviction", () => {
  it("past storeMaxBytes the heaviest source loses its oldest mail; the canary's parked mail survives", async () => {
    relay = await RelayProcess.start({ limits, env: { TRUST_PROXY: "1" } });
    const sampler = await Sampler.start(relay);
    canary = await Canary.start(relay);

    // Parked: 10 canary messages to an offline device, stored until it connects.
    const parked = newDevice(relay);
    await register(relay, parked, CANARY_IP);
    const parkedCap = makeCap(parked, relay.nowSec()).jws;
    const sender = newDevice(relay);
    const sc = await authedFrom(relay, sender, CANARY_IP);
    const parkedFrames = Array.from({ length: 10 }, () => sendFrame(sender, parked, { cap: parkedCap, padTo: 1000 }));
    expect(await sendPipelined(sc, parkedFrames)).toEqual({ sent: 10 });

    // Attacker: 240 x ~4 KiB (about 1 MiB, four times the quota) to its own sink.
    const sink = newDevice(relay);
    await register(relay, sink, ATTACK_IP);
    const sinkCap = makeCap(sink, relay.nowSec()).jws;
    const m = newDevice(relay);
    const mc = await authedFrom(relay, m, ATTACK_IP);
    const flood = Array.from({ length: 240 }, () => sendFrame(m, sink, { cap: sinkCap, padTo: 4000 }));
    const codes = await sendBatched(mc, flood);
    const mid = await relay.stats({ store: true });

    const parkedGot = await drainMailbox(relay, parked, CANARY_IP);
    const sinkGot = await drainMailbox(relay, sink, ATTACK_IP);
    const floodEnvs = flood.map((f) => f.env as string);

    await assertHealthy({
      test: "2 store quota",
      relay,
      sampler,
      canary,
      limits,
      dbLimitBytes: limits.storeHardMaxBytes,
      extra: { attackerCodes: codes, storeBytesAfterFlood: mid.store?.envelopeBytes, parkedDelivered: parkedGot.length, sinkKept: sinkGot.length },
    });
    // Eviction, not denial: the attacker was never refused, the store stayed under the quota.
    expect(codes).toEqual({ sent: 240 });
    expect(mid.store!.envelopeBytes).toBeLessThanOrEqual(limits.storeMaxBytes);
    expect(new Set(parkedGot)).toEqual(new Set(parkedFrames.map((f) => f.env as string)));
    // The sink kept only the newest of the flood, in order.
    expect(sinkGot.length).toBeLessThan(flood.length);
    expect(sinkGot).toEqual(floodEnvs.slice(floodEnvs.length - sinkGot.length));
  });
});
