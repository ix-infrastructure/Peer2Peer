// Copyright 2026 Ix Infrastructure Inc.
// #3 Per-recipient quota fairness.

import { afterEach, describe, expect, it } from "vitest";
import { makeCap } from "../src/__tests__/helpers.js";
import { assertHealthy, authedFrom, Canary, drainMailbox, newDevice, register, Sampler, sendBatched, sendFrame, sendPipelined } from "./harness/load.js";
import { RelayProcess } from "./harness/relay-process.js";

const ATTACK_IP = "198.51.100.30";
const HONEST_IP = "198.51.100.31";
const VICTIM_IP = "198.51.100.32";
const limits = { recipientMaxBytes: 64 * 1024, sendsPerMinute: 1000, framesPerConnPerMinute: 5000 };

let relay: RelayProcess;
let canary: Canary | undefined;
afterEach(async () => {
  canary?.close();
  await relay?.dispose();
});

describe("3. per-recipient quota fairness", () => {
  it("a heavy sender to one recipient evicts its own mail, not another sender's mail to that recipient", async () => {
    relay = await RelayProcess.start({ limits, env: { TRUST_PROXY: "1" } });
    const sampler = await Sampler.start(relay);
    canary = await Canary.start(relay);

    const victim = newDevice(relay);
    await register(relay, victim, VICTIM_IP);
    // The victim gave both senders a cap (a friend can turn noisy).
    const honest = newDevice(relay);
    const heavy = newDevice(relay);
    const hc = await authedFrom(relay, honest, HONEST_IP);
    const mc = await authedFrom(relay, heavy, ATTACK_IP);
    const capH = makeCap(victim, relay.nowSec()).jws;
    const capM = makeCap(victim, relay.nowSec()).jws;

    const honestFrames = Array.from({ length: 6 }, () => sendFrame(honest, victim, { cap: capH, padTo: 1000 }));
    const heavyFrames = Array.from({ length: 160 }, () => sendFrame(heavy, victim, { cap: capM, padTo: 2000 }));
    const honestCodes: Record<string, number> = {};
    const heavyCodes: Record<string, number> = {};
    const add = (into: Record<string, number>, from: Record<string, number>) => {
      for (const [k, v] of Object.entries(from)) into[k] = (into[k] ?? 0) + v;
    };
    // Honest mail goes in before and in between the flood batches.
    add(honestCodes, await sendPipelined(hc, honestFrames.slice(0, 2)));
    for (let i = 0; i < heavyFrames.length; i += 40) {
      add(heavyCodes, await sendBatched(mc, heavyFrames.slice(i, i + 40)));
      const h = honestFrames[2 + i / 40];
      if (h) add(honestCodes, await sendPipelined(hc, [h]));
    }
    const got = await drainMailbox(relay, victim, VICTIM_IP);
    const gotSet = new Set(got);
    const honestKept = honestFrames.filter((f) => gotSet.has(f.env as string)).length;
    const heavyKept = heavyFrames.filter((f) => gotSet.has(f.env as string)).length;
    const keptBytes = got.reduce((n, e) => n + Buffer.byteLength(e), 0);

    await assertHealthy({
      test: "3 recipient fairness",
      relay,
      sampler,
      canary,
      limits,
      extra: { honestCodes, heavyCodes, honestKept, heavyKept, victimBytes: keptBytes },
    });
    expect(honestCodes).toEqual({ sent: 6 });
    expect(honestKept).toBe(6);
    expect(heavyKept).toBeLessThan(heavyFrames.length);
    expect(keptBytes).toBeLessThanOrEqual(limits.recipientMaxBytes);
  });
});
