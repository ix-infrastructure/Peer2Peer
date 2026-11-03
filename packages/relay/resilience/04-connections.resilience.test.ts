// Copyright 2026 Ix Infrastructure Inc.
// #4 Connection limits: unauthenticated sockets, per-IP and per-iss caps,
// connect and auth rates. The canary keeps exchanging mail throughout, and a
// fresh honest device tries to connect while each cap is full.

import { afterEach, describe, expect, it } from "vitest";
import { makeDevice, type TestClient } from "../src/__tests__/helpers.js";
import { assertHealthy, Canary, connectFrom, newDevice, Sampler, sleep, tally, tryAuthFrom } from "./harness/load.js";
import { RelayProcess } from "./harness/relay-process.js";
import { CLOSE } from "../src/server.js";

const limits = {
  maxConnections: 60,
  maxUnauthConnections: 20,
  // F-5: IPv4 addresses have their own (higher) defaults; these tests use
  // IPv4 addresses, so the IPv4 knobs are set explicitly.
  maxConnectionsPerIp: 8,
  maxConnectionsPerIpv4: 8,
  maxUnauthPerIp: 4,
  maxConnectionsPerIss: 3,
  connectsPerIpPerMinute: 30,
  authsPerIpPerMinute: 12,
  authsPerIpv4PerMinute: 12,
};
/** An honest newcomer, on an address no attacker uses. */
const NEWCOMER_IP = "203.0.113.77";

let relay: RelayProcess;
let canary: Canary | undefined;
const open: TestClient[] = [];
afterEach(async () => {
  canary?.close();
  for (const c of open.splice(0)) c.ws.terminate();
  await relay?.dispose();
});

async function connectOutcome(ip: string): Promise<string> {
  try {
    open.push(await connectFrom(relay, ip));
    return "open";
  } catch (e) {
    return (e as Error).message;
  }
}

async function setup() {
  relay = await RelayProcess.start({ limits, env: { TRUST_PROXY: "1" } });
  const sampler = await Sampler.start(relay);
  canary = await Canary.start(relay);
  return sampler;
}

/** A fresh honest device connects and authenticates from NEWCOMER_IP. */
async function newcomer(): Promise<string> {
  const r = await tryAuthFrom(relay, newDevice(relay), NEWCOMER_IP);
  if (r.client) open.push(r.client);
  return r.outcome;
}

describe("4. connection limits", () => {
  it("holds unauthenticated sockets at maxUnauthConnections by dropping the oldest; authenticated traffic keeps flowing", async () => {
    const sampler = await setup();
    const outcomes: string[] = [];
    // 30 sockets from 15 addresses (2 each): per-IP caps never bite, only the global unauth cap.
    for (let i = 0; i < 30; i++) outcomes.push(await connectOutcome(`198.51.100.${100 + (i % 15)}`));
    await sleep(200);
    const st = await relay.stats();
    const closes = tally(open.map((c) => String(c.closeCode ?? "open")));
    const oldestClosed = open.slice(0, 10).every((c) => c.closeCode === CLOSE.unauthTimeout);
    await assertHealthy({ test: "4a unauth cap", relay, sampler, canary, limits, extra: { outcomes: tally(outcomes), unauth: st.unauthConnections, closes } });
    // Nobody is refused; the 10 oldest idle sockets are closed (4008) to make room.
    expect(tally(outcomes)).toEqual({ open: 30 });
    expect(st.unauthConnections).toBe(20);
    expect(closes).toEqual({ open: 20, [String(CLOSE.unauthTimeout)]: 10 });
    expect(oldestClosed).toBe(true);
  });

  // Was FINDINGS.md F-3 (fixed before launch: the full unauth cap drops its oldest socket instead of refusing).
  it("an honest newcomer can still connect while the unauth cap is full", async () => {
    const sampler = await setup();
    for (let i = 0; i < 20; i++) await connectOutcome(`198.51.100.${100 + (i % 15)}`);
    const outcome = await newcomer();
    await assertHealthy({ test: "4a' newcomer during unauth cap", relay, sampler, canary, limits, extra: { newcomer: outcome } });
    expect(outcome).toBe("ok");
  });

  it("caps unauthenticated sockets per IP at maxUnauthPerIp; authenticating frees the slot; a newcomer from another IP still gets in", async () => {
    const sampler = await setup();
    const outcomes: string[] = [];
    for (let i = 0; i < 7; i++) outcomes.push(await connectOutcome("198.51.100.45"));
    // One of the four authenticates: its unauth slot frees up for another socket from that IP.
    const ok = await open[0].auth(newDevice(relay));
    const afterAuth = await connectOutcome("198.51.100.45");
    const joined = await newcomer();
    await assertHealthy({ test: "4f unauth per IP", relay, sampler, canary, limits, extra: { outcomes: tally(outcomes), afterAuth, newcomer: joined } });
    expect(tally(outcomes)).toEqual({ open: limits.maxUnauthPerIp, "HTTP 429": 7 - limits.maxUnauthPerIp });
    expect(ok.t).toBe("ok");
    expect(afterAuth).toBe("open");
    expect(joined).toBe("ok");
  });

  it("caps sockets per IP at maxConnectionsPerIp; a newcomer from another IP still gets in", async () => {
    const sampler = await setup();
    const outcomes: string[] = [];
    // Authenticated, so the per-IP unauth cap (4) doesn't bite first.
    for (let i = 0; i < 12; i++) {
      const r = await tryAuthFrom(relay, newDevice(relay), "198.51.100.40");
      if (r.client) open.push(r.client);
      outcomes.push(r.outcome === "ok" ? "open" : r.outcome);
    }
    const joined = await newcomer();
    await assertHealthy({ test: "4b per-IP cap", relay, sampler, canary, limits, extra: { outcomes: tally(outcomes), newcomer: joined } });
    expect(tally(outcomes)).toEqual({ open: 8, "HTTP 429": 4 });
    expect(joined).toBe("ok");
  });

  it("caps connections per userId at maxConnectionsPerIss with `full`; other users still get in", async () => {
    const sampler = await setup();
    const owner = newDevice(relay);
    const outcomes: string[] = [];
    for (let i = 0; i < 5; i++) {
      // Five devices of one identity, each from its own address.
      const d = makeDevice(owner.identity, relay.nowSec());
      const r = await tryAuthFrom(relay, d, `198.51.100.${50 + i}`);
      if (r.client) open.push(r.client);
      outcomes.push(r.outcome);
    }
    const joined = await newcomer();
    await assertHealthy({ test: "4c per-iss cap", relay, sampler, canary, limits, extra: { outcomes: tally(outcomes), newcomer: joined } });
    expect(outcomes).toEqual(["ok", "ok", "ok", "full", "full"]);
    expect(joined).toBe("ok");
  });

  it("rate-limits new connections per IP at connectsPerIpPerMinute; a newcomer from another IP still gets in", async () => {
    const sampler = await setup();
    const outcomes: string[] = [];
    for (let i = 0; i < 36; i++) {
      const o = await connectOutcome("198.51.100.60");
      outcomes.push(o);
      if (o === "open") await open.pop()!.close();
    }
    const joined = await newcomer();
    // A rate, not a ban: a minute later the address connects again.
    await relay.advance(60_000);
    const after = await connectOutcome("198.51.100.60");
    await assertHealthy({ test: "4d connect rate", relay, sampler, canary, limits, extra: { outcomes: tally(outcomes), newcomer: joined, after } });
    expect(tally(outcomes)).toEqual({ open: 30, "HTTP 429": 6 });
    expect(joined).toBe("ok");
    expect(after).toBe("open");
  });

  it("rate-limits auth attempts per IP at authsPerIpPerMinute; a newcomer from another IP still gets in", async () => {
    const sampler = await setup();
    const outcomes: string[] = [];
    for (let i = 0; i < 16; i++) {
      const r = await tryAuthFrom(relay, newDevice(relay), "198.51.100.70");
      outcomes.push(r.outcome);
      if (r.client) await r.client.close();
      await sleep(5);
    }
    const joined = await newcomer();
    await assertHealthy({ test: "4e auth rate", relay, sampler, canary, limits, extra: { outcomes: tally(outcomes), newcomer: joined } });
    expect(tally(outcomes)).toEqual({ ok: 12, "rate-limited": 4 });
    expect(joined).toBe("ok");
  });
});
