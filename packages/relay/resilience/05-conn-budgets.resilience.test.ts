// Copyright 2026 Ix Infrastructure Inc.
// #5 Per-connection frame and byte budgets; invalid-signature sends are
// rejected cheaply (before the signature check once the budget is spent).

import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { makeCap, makeEnvelope, type Frame } from "../src/__tests__/helpers.js";
import {
  assertHealthy,
  authedFrom,
  Canary,
  dest,
  newDevice,
  register,
  report,
  round,
  Sampler,
  sendAll,
  sendFrame,
  sendPipelined,
  sleep,
  tally,
  THRESHOLDS,
} from "./harness/load.js";
import { RelayProcess } from "./harness/relay-process.js";

const ATTACK_IP = "198.51.100.80";
const limits = {
  framesPerConnPerMinute: 200,
  sendBytesPerConnPerMinute: 64 * 1024,
  sendBytesPerIpPerMinute: 128 * 1024,
  sendsPerMinute: 1000,
};

let relay: RelayProcess;
let canary: Canary | undefined;
afterEach(async () => {
  canary?.close();
  await relay?.dispose();
});

async function setup(l: Record<string, number> = limits) {
  relay = await RelayProcess.start({ limits: l, env: { TRUST_PROXY: "1" } });
  const sampler = await Sampler.start(relay);
  canary = await Canary.start(relay);
  const sink = newDevice(relay);
  await register(relay, sink, "198.51.100.89");
  return { sampler, sink, sinkCap: makeCap(sink, relay.nowSec()).jws };
}

/** An envelope from `from` whose signature is by some other key. */
function badSigFrame(from: ReturnType<typeof newDevice>, to: ReturnType<typeof newDevice>, cap: string, padTo = 1000): Frame {
  const env = makeEnvelope(from, dest(to), { padTo, signWith: new Uint8Array(randomBytes(32)) });
  return { t: "send", to: to.identity.userId, tdid: to.did, env, cap };
}

describe("5. per-connection frame and byte budgets", () => {
  it("answers frames past framesPerConnPerMinute with rate-limited and keeps the connection open", async () => {
    const { sampler } = await setup();
    const m = newDevice(relay);
    const mc = await authedFrom(relay, m, ATTACK_IP);
    const codes: string[] = [];
    mc.ws.on("message", (d) => {
      const f = JSON.parse(String(d)) as Frame;
      if (f.t === "error") codes.push(String(f.code));
    });
    for (let i = 0; i < 300; i++) mc.send({ t: "no-such-frame", id: `f${i}` });
    await sleep(500);
    const counts = tally(codes);
    const open = mc.ws.readyState === mc.ws.OPEN;
    await assertHealthy({ test: "5a frame budget", relay, sampler, canary, limits, extra: { replies: counts, stillOpen: open } });
    // The auth frame took one of the 200 tokens; refill over the burst may add one.
    expect(counts["bad-request"]).toBeGreaterThanOrEqual(199);
    expect(counts["bad-request"]).toBeLessThanOrEqual(201);
    expect(counts["bad-request"] + counts["rate-limited"]).toBe(300);
    expect(open).toBe(true);
  });

  it("caps envelope bytes per connection and per IP; another IP is unaffected", async () => {
    const { sampler, sink, sinkCap } = await setup();
    const big = (from: ReturnType<typeof newDevice>) => Array.from({ length: 12 }, () => sendFrame(from, sink, { cap: sinkCap, padTo: 8000 }));
    const m1 = newDevice(relay);
    const m2 = newDevice(relay);
    const m3 = newDevice(relay);
    // m1: 12 x 8 KB on one connection (64 KiB/conn); m2: same IP, second
    // connection, until the IP's 128 KiB is gone; m3 on another IP.
    const c1 = await sendAll(await authedFrom(relay, m1, ATTACK_IP), big(m1));
    const c2 = await sendAll(await authedFrom(relay, m2, ATTACK_IP), big(m2));
    const c3 = await sendAll(await authedFrom(relay, m3, "198.51.100.81"), big(m3).slice(0, 4));
    await assertHealthy({ test: "5b byte budgets", relay, sampler, canary, limits, extra: { conn1: c1, conn2SameIp: c2, otherIp: c3 } });
    // Whole envelopes per budget: the per-conn budget for m1, the IP's remainder for m2.
    const size = Buffer.byteLength(big(m1)[0].env as string);
    const perConn = Math.floor(limits.sendBytesPerConnPerMinute / size);
    const ipLeft = Math.floor((limits.sendBytesPerIpPerMinute - perConn * size) / size);
    expect(c1).toEqual({ sent: perConn, "rate-limited": 12 - perConn });
    expect(c2).toEqual({ sent: Math.min(perConn, ipLeft), "rate-limited": 12 - Math.min(perConn, ipLeft) });
    expect(c3).toEqual({ sent: 4 });
  });

  it("rejects invalid-signature sends with bad-envelope, then rate-limited (no signature work) once the byte budget is spent", async () => {
    const { sampler, sink, sinkCap } = await setup();
    const m = newDevice(relay);
    const mc = await authedFrom(relay, m, ATTACK_IP);
    // 150: under the 200-frame budget, so every send gets its own reply.
    const frames = Array.from({ length: 150 }, () => badSigFrame(m, sink, sinkCap));
    const t0 = performance.now();
    const codes = await sendAll(mc, frames);
    const ms = performance.now() - t0;
    const st = await relay.stats({ store: true });
    await assertHealthy({
      test: "5c invalid signatures",
      relay,
      sampler,
      canary,
      limits,
      extra: { codes, msPerReply: round(ms / frames.length, 2), stored: st.store?.envelopes },
    });
    expect(Object.keys(codes).sort()).toEqual(["bad-envelope", "rate-limited"]);
    // Only what fits the 64 KiB byte budget reaches the signature check.
    const size = Buffer.byteLength(frames[0].env as string);
    expect(codes["bad-envelope"]).toBeLessThanOrEqual(Math.ceil(limits.sendBytesPerConnPerMinute / size) + 1);
    // Nothing from the attacker was stored (the canary's mail is acked as it goes).
    expect(st.store!.envelopes).toBeLessThanOrEqual(2);
  });

  it("rejects envelopes for another sender before any signature work", async () => {
    const l = { ...limits, framesPerConnPerMinute: 5000, sendBytesPerConnPerMinute: 64 * 1024 * 1024, sendBytesPerIpPerMinute: 64 * 1024 * 1024 };
    const { sampler, sink, sinkCap } = await setup(l);
    const m = newDevice(relay);
    const victim = newDevice(relay);
    const mc = await authedFrom(relay, m, ATTACK_IP);
    // A captured envelope of someone else, replayed on m's connection.
    const frames = Array.from({ length: 400 }, () => sendFrame(victim, sink, { cap: sinkCap, padTo: 1000 }));
    const t0 = performance.now();
    const codes: Record<string, number> = {};
    for (let i = 0; i < frames.length; i += 50) {
      for (const [k, v] of Object.entries(await sendPipelined(mc, frames.slice(i, i + 50)))) codes[k] = (codes[k] ?? 0) + v;
    }
    const ms = performance.now() - t0;
    await assertHealthy({ test: "5d foreign sender", relay, sampler, canary, limits: l, extra: { codes, msPerReply: round(ms / frames.length, 3) } });
    expect(codes).toEqual({ "bad-envelope": 400 });
  });

  // Was FINDINGS.md F-2 (~2 ms per send, ~80 ms stalls): Ed25519 is now
  // verified natively, verified caps are cached, and frames are processed in
  // bounded slices that yield.
  it("a pipelined burst of 40 valid capped sends from one connection keeps event-loop delay p99 under the threshold", async () => {
    const l = { ...limits, framesPerConnPerMinute: 5000, sendBytesPerConnPerMinute: 8 * 1024 * 1024, sendBytesPerIpPerMinute: 8 * 1024 * 1024 };
    const { sampler, sink, sinkCap } = await setup(l);
    const m = newDevice(relay);
    const mc = await authedFrom(relay, m, ATTACK_IP);
    const frames = Array.from({ length: 160 }, () => sendFrame(m, sink, { cap: sinkCap, padTo: 1000 }));
    const t0 = performance.now();
    const codes: Record<string, number> = {};
    for (let i = 0; i < frames.length; i += 40) {
      for (const [k, v] of Object.entries(await sendPipelined(mc, frames.slice(i, i + 40)))) codes[k] = (codes[k] ?? 0) + v;
    }
    const ms = performance.now() - t0;
    report({ test: "5e pipelined burst", codes, msPerSend: round(ms / frames.length, 2), threshold: THRESHOLDS.lagP99Ms });
    await assertHealthy({ test: "5e pipelined burst", relay, sampler, canary, limits: l, extra: { codes, msPerSend: round(ms / frames.length, 2) } });
  });
});
