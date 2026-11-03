// Copyright 2026 Ix Infrastructure Inc.
// #12 Shared IPv4: many honest users behind one address (a campus or carrier
// NAT) sending normal `status` traffic — one envelope per user per 60 s to
// about 10 peers — are never rate-limited. Production default limits.
//
// Time is compressed: users arrive in waves of 20 per relay-minute and each
// traffic round is one relay-minute, with the relay clock moved forward over
// IPC between them, so per-minute buckets refill exactly as they would in
// real time. Within a round, sends are paced over a few wall seconds (each
// user's ten sends one after another) so the relay's CPU, not the limits, is
// never what's measured.

import { afterEach, describe, expect, it } from "vitest";
import { makeCap, type Device, type TestClient } from "../src/__tests__/helpers.js";
import { assertHealthy, Canary, newDevice, report, Sampler, sendFrame, sleep, tally, tryAuthFrom } from "./harness/load.js";
import { RelayProcess } from "./harness/relay-process.js";

const NAT_IP = "192.0.2.10";
const PEERS = 10;
const WAVE = 20;

let relay: RelayProcess;
let canary: Canary | undefined;
const open: TestClient[] = [];
afterEach(async () => {
  canary?.close();
  for (const c of open.splice(0)) c.ws.terminate();
  await relay?.dispose();
});

interface User {
  device: Device;
  client?: TestClient;
  cap: string;
}

async function run(users: number, rounds: number, roundWallMs: number) {
  relay = await RelayProcess.start({ env: { TRUST_PROXY: "1" } });
  // Minted before the canary starts: minting hundreds of devices blocks this
  // (test) process for a while, which would show up as canary latency.
  const pop: User[] = Array.from({ length: users }, () => {
    const device = newDevice(relay);
    return { device, cap: makeCap(device, relay.nowSec()).jws };
  });
  const sampler = await Sampler.start(relay);
  canary = await Canary.start(relay);

  // Arrival: WAVE users per relay-minute.
  const joins: string[] = [];
  for (let i = 0; i < users; i++) {
    if (i > 0 && i % WAVE === 0) await relay.advance(60_000);
    const r = await tryAuthFrom(relay, pop[i].device, NAT_IP);
    joins.push(r.outcome);
    if (r.client) {
      pop[i].client = r.client;
      open.push(r.client);
    }
  }

  // Traffic: each round, every online user sends one status to PEERS peers.
  const sends: string[] = [];
  for (let round = 0; round < rounds; round++) {
    await relay.advance(60_000);
    // Online users start evenly spread over the round's wall time.
    const online = pop.filter((u) => u.client).length;
    let slot = 0;
    await Promise.all(
      pop.map(async (u, i) => {
        if (!u.client) return;
        await sleep((slot++ * roundWallMs) / online);
        for (let k = 1; k <= PEERS; k++) {
          const peer = pop[(i + k) % users];
          const r = await u.client.request(sendFrame(u.device, peer.device, { cap: peer.cap, kind: "status" }));
          sends.push(r.t === "error" ? String(r.code) : String(r.t));
        }
      }),
    );
    for (const u of pop) if (u.client) u.client.frames.length = 0;
  }
  return { sampler, joins: tally(joins), sends: tally(sends) };
}

describe("12. shared IPv4: honest users behind one address", () => {
  it("40 users behind one IP (under the per-IP caps) are never rate-limited", async () => {
    const { sampler, joins, sends } = await run(40, 2, 3000);
    await assertHealthy({ test: "12a shared IPv4, 40 users", relay, sampler, canary, limits: { defaults: "production" }, extra: { users: 40, joins, sends } });
    expect(joins).toEqual({ ok: 40 });
    expect(sends).toEqual({ sent: 40 * PEERS * 2 });
  });

  // Was FINDINGS.md F-5: IPv4 addresses now have their own defaults
  // (maxConnectionsPerIpv4 512, newDevicesPerIpv4PerDay 1000,
  // authsPerIpv4PerMinute 600); IPv6 /64 keeps the tighter ones.
  it("80 users behind one IP are never rate-limited or refused", async () => {
    const { sampler, joins, sends } = await run(80, 1, 3000);
    report({ test: "12b shared IPv4, 80 users (outcomes)", users: 80, joins, sends });
    await assertHealthy({ test: "12b shared IPv4, 80 users", relay, sampler, canary, limits: { defaults: "production" }, extra: { users: 80, joins, sends } });
    expect(joins).toEqual({ ok: 80 });
    expect(sends).toEqual({ sent: 80 * PEERS });
  });

  it("300 users behind one IP are never rate-limited or refused", async () => {
    const { sampler, joins, sends } = await run(300, 1, 8000);
    report({ test: "12c shared IPv4, 300 users (outcomes)", users: 300, joins, sends });
    await assertHealthy({ test: "12c shared IPv4, 300 users", relay, sampler, canary, limits: { defaults: "production" }, extra: { users: 300, joins, sends } });
    expect(joins).toEqual({ ok: 300 });
    expect(sends).toEqual({ sent: 300 * PEERS });
  }, 120_000);
});
