// Copyright 2026 Ix Infrastructure Inc.
// #10 A crash (SIGKILL) mid-flood, then a restart on the same database: no
// corruption, un-acked mail is redelivered, acked mail is not, and the limits
// still apply.

import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { makeCap, type TestClient } from "../src/__tests__/helpers.js";
import {
  assertHealthy,
  authedFrom,
  Canary,
  CANARY_IP,
  collectEnvs,
  connectFrom,
  drainMailbox,
  newDevice,
  register,
  round,
  Sampler,
  sendBatched,
  sendFrame,
  sendPipelined,
  sleep,
  tally,
} from "./harness/load.js";
import { RelayProcess } from "./harness/relay-process.js";

const ATTACK_IP = "198.51.100.120";
const limits = {
  storeMaxBytes: 128 * 1024,
  storeHardMaxBytes: 256 * 1024,
  maxConnectionsPerIp: 6,
  maxConnectionsPerIpv4: 6,
  sendsPerMinute: 1000,
  framesPerConnPerMinute: 5000,
};

let relay: RelayProcess;
let canary: Canary | undefined;
const open: TestClient[] = [];
afterEach(async () => {
  canary?.close();
  for (const c of open.splice(0)) c.ws.terminate();
  await relay?.dispose();
});

function inspect(path: string): { integrity: string; totalsMatch: boolean; envelopes: number } {
  const db = new DatabaseSync(path);
  try {
    const integrity = String((db.prepare("PRAGMA integrity_check").get() as { integrity_check: string }).integrity_check);
    const real = db.prepare("SELECT coalesce(sum(size), 0) AS b, count(*) AS n FROM envelopes").get() as { b: number; n: number };
    const tot = db.prepare("SELECT bytes AS b, n FROM totals WHERE kind = 'all'").get() as { b: number; n: number } | undefined;
    return { integrity, totalsMatch: Number(tot?.b ?? 0) === Number(real.b) && Number(tot?.n ?? 0) === Number(real.n), envelopes: Number(real.n) };
  } finally {
    db.close();
  }
}

/** Parked + live canary mail, then an attacker flood that the relay is SIGKILLed in the middle of; then a restart. */
async function crashMidFlood() {
  relay = await RelayProcess.start({ limits, env: { TRUST_PROXY: "1" } });

  // Parked mail: 12 to an offline device.
  const parked = newDevice(relay);
  await register(relay, parked, CANARY_IP);
  const sender = newDevice(relay);
  const sc = await authedFrom(relay, sender, CANARY_IP);
  const parkedFrames = Array.from({ length: 12 }, () => sendFrame(sender, parked, { cap: makeCap(parked, relay.nowSec()).jws, padTo: 1000 }));
  expect(await sendPipelined(sc, parkedFrames)).toEqual({ sent: 12 });
  // Live mail: 10 delivered, the first 5 acked.
  const live = newDevice(relay);
  const lc = await authedFrom(relay, live, "198.51.100.121");
  const liveCap = makeCap(live, relay.nowSec()).jws;
  const liveFrames = Array.from({ length: 10 }, () => sendFrame(sender, live, { cap: liveCap }));
  expect(await sendPipelined(sc, liveFrames)).toEqual({ sent: 10 });
  const got = await collectEnvs(lc, { quietMs: 200 });
  expect(got).toHaveLength(10);
  lc.send({ t: "ack", rids: got.slice(0, 5).map((e) => e.rid as string) });
  await sleep(200);

  // An attacker floods; the relay is killed in the middle of it.
  const sink = newDevice(relay);
  await register(relay, sink, ATTACK_IP);
  const sinkCap = makeCap(sink, relay.nowSec()).jws;
  const m = newDevice(relay);
  const mc = await authedFrom(relay, m, ATTACK_IP);
  const flood = sendBatched(
    mc,
    Array.from({ length: 200 }, () => sendFrame(m, sink, { cap: sinkCap, padTo: 4000 })),
  ).catch(() => ({}));
  await sleep(400);
  await relay.stop("SIGKILL");
  const before = (await flood) as Record<string, number>;
  const disk = inspect(relay.dbPath);

  const t0 = performance.now();
  relay = await relay.restart();
  const restartMs = round(performance.now() - t0);
  const sampler = await Sampler.start(relay);
  canary = await Canary.start(relay);
  /** The attacker floods again after the restart (under a new source tag: the tag key is per process). */
  const floodAgain = async () => {
    const m2c = await authedFrom(relay, m, ATTACK_IP);
    return sendBatched(
      m2c,
      Array.from({ length: 100 }, () => sendFrame(m, sink, { cap: sinkCap, padTo: 4000 })),
    );
  };
  return { parked, parkedFrames, live, got, before, disk, restartMs, sampler, floodAgain };
}

describe("10. restart mid-test", () => {
  it("survives SIGKILL mid-flood: database intact, un-acked mail redelivered, acked mail not, limits still enforced", async () => {
    const { parked, parkedFrames, live, got, before, disk, restartMs, sampler, floodAgain } = await crashMidFlood();

    // Redelivery first: everything un-acked comes again, nothing acked does.
    const parkedGot = await drainMailbox(relay, parked, CANARY_IP);
    const liveGot = await drainMailbox(relay, live, "198.51.100.121");

    // Limits after the restart: per-IP sockets ...
    const outcomes: string[] = [];
    for (let i = 0; i < 8; i++) {
      try {
        open.push(await connectFrom(relay, "198.51.100.122"));
        outcomes.push("open");
      } catch (e) {
        outcomes.push((e as Error).message);
      }
    }
    // ... and the store quota.
    const after = await floodAgain();
    const st = await relay.stats({ store: true });

    await assertHealthy({
      test: "10a restart",
      relay,
      sampler,
      canary,
      limits,
      dbLimitBytes: limits.storeHardMaxBytes,
      extra: {
        floodBeforeKill: before,
        disk,
        restartMs,
        perIpAfter: tally(outcomes),
        floodAfter: after,
        storeBytesAfter: st.store?.envelopeBytes,
        parkedRedelivered: parkedGot.length,
        liveRedelivered: liveGot.length,
      },
    });
    expect(disk.integrity).toBe("ok");
    expect(disk.totalsMatch).toBe(true);
    expect(tally(outcomes)).toEqual({ open: 6, "HTTP 429": 2 });
    expect(after).toEqual({ sent: 100 });
    expect(st.store!.envelopeBytes).toBeLessThanOrEqual(limits.storeMaxBytes);
    expect(new Set(parkedGot)).toEqual(new Set(parkedFrames.map((f) => f.env as string)));
    // Exactly the 5 un-acked come again.
    expect(new Set(liveGot)).toEqual(new Set(got.slice(5).map((e) => e.env as string)));
  });

  // Was FINDINGS.md F-6: after a restart the flooder's bytes are split between
  // its old and new tags. Eviction now takes current-process groups (above a
  // floor) before any older group, so a renewed flood eats its own new data.
  it("after a restart, the parked canary mail survives source-first eviction by a renewed flood", async () => {
    const { parked, parkedFrames, sampler, floodAgain } = await crashMidFlood();
    const after = await floodAgain();
    const st = await relay.stats({ store: true });
    const parkedGot = await drainMailbox(relay, parked, CANARY_IP);
    await assertHealthy({
      test: "10b restart: parked mail vs renewed flood",
      relay,
      sampler,
      canary,
      limits,
      dbLimitBytes: limits.storeHardMaxBytes,
      extra: { floodAfter: after, storeBytesAfter: st.store?.envelopeBytes, parkedRedelivered: parkedGot.length, parkedSent: parkedFrames.length },
    });
    expect(new Set(parkedGot)).toEqual(new Set(parkedFrames.map((f) => f.env as string)));
  });

  it("after a restart, a flood spread across many sources (each under the eviction floor) evicts its own groups, not small honest parked mail", async () => {
    // The pre-release review's case: honest mail parked before the restart is a small
    // group (one envelope, ~2.8 KB); afterwards an attacker sends two
    // envelopes (~5.7 KB) from each of 30 addresses, every group under the
    // floor (storeMaxBytes / 16 = 8 KiB), overflowing the quota. No group is
    // preferred for its generation, so the attacker's larger groups go first.
    relay = await RelayProcess.start({ limits, env: { TRUST_PROXY: "1" } });
    const parked = newDevice(relay);
    await register(relay, parked, CANARY_IP);
    const sender = newDevice(relay);
    const sc = await authedFrom(relay, sender, CANARY_IP);
    const parkedFrames = [sendFrame(sender, parked, { cap: makeCap(parked, relay.nowSec()).jws, padTo: 1000 })];
    expect(await sendPipelined(sc, parkedFrames)).toEqual({ sent: 1 });
    // `sent` is answered before the store work (L2), so let the write land
    // before the kill, as crashMidFlood does.
    await sleep(200);
    await relay.stop("SIGKILL");
    relay = await relay.restart();
    const afterRestart = await relay.stats({ store: true });
    expect(afterRestart.store!.envelopes).toBe(1);
    const sampler = await Sampler.start(relay);
    canary = await Canary.start(relay);

    const outcomes: Record<string, number> = {};
    for (let a = 0; a < 30; a++) {
      const ip = `198.51.100.${140 + a}`;
      const m = newDevice(relay);
      const sink = newDevice(relay);
      await register(relay, sink, ip);
      const mc = await authedFrom(relay, m, ip);
      open.push(mc);
      const cap = makeCap(sink, relay.nowSec()).jws;
      const r = await sendPipelined(mc, Array.from({ length: 2 }, () => sendFrame(m, sink, { cap, padTo: 1000 })));
      for (const [k, v] of Object.entries(r)) outcomes[k] = (outcomes[k] ?? 0) + v;
    }
    const st = await relay.stats({ store: true });
    const parkedGot = await drainMailbox(relay, parked, CANARY_IP);
    await assertHealthy({
      test: "10d restart: many-source flood vs small parked mail",
      relay,
      sampler,
      canary,
      limits,
      dbLimitBytes: limits.storeHardMaxBytes,
      extra: { flood: outcomes, storeBytesAfter: st.store?.envelopeBytes, parkedRedelivered: parkedGot.length, parkedSent: parkedFrames.length },
    });
    expect(outcomes).toEqual({ sent: 60 });
    // The flood did overflow the quota (eviction happened) ...
    expect(st.store!.envelopeBytes).toBeLessThanOrEqual(limits.storeMaxBytes);
    // ... and the honest parked mail survived it.
    expect(new Set(parkedGot)).toEqual(new Set(parkedFrames.map((f) => f.env as string)));
  });

  it("after a restart, when only honest traffic pushes the store over quota, the attacker's old data goes before the parked canary mail", async () => {
    // The attacker flooded only before the crash; afterwards, an honest sender
    // on another address fills past the quota.
    const { parked, parkedFrames, sampler } = await crashMidFlood();
    const before = await relay.stats({ store: true });
    const honest = newDevice(relay);
    const hc = await authedFrom(relay, honest, "198.51.100.130");
    const box = newDevice(relay);
    await register(relay, box, "198.51.100.131");
    const boxCap = makeCap(box, relay.nowSec()).jws;
    const after = await sendBatched(
      hc,
      Array.from({ length: 30 }, () => sendFrame(honest, box, { cap: boxCap, padTo: 2000 })),
    );
    const st = await relay.stats({ store: true });
    const parkedGot = await drainMailbox(relay, parked, CANARY_IP);
    await assertHealthy({
      test: "10c restart: honest traffic vs pre-crash flood",
      relay,
      sampler,
      canary,
      limits,
      dbLimitBytes: limits.storeHardMaxBytes,
      extra: { honestAfter: after, storeBytesBefore: before.store?.envelopeBytes, storeBytesAfter: st.store?.envelopeBytes, parkedRedelivered: parkedGot.length, parkedSent: parkedFrames.length },
    });
    expect(after).toEqual({ sent: 30 });
    expect(st.store!.envelopeBytes).toBeLessThanOrEqual(limits.storeMaxBytes);
    expect(new Set(parkedGot)).toEqual(new Set(parkedFrames.map((f) => f.env as string)));
  });
});
