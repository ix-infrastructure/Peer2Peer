// Copyright 2026 Ix Infrastructure Inc.
// pre-release review item 2: the higher IPv4 per-address limits must not let a few
// addresses take the global connection pool or the device table.

import { afterEach, describe, expect, it } from "vitest";
import { CLOSE } from "../server.js";
import { makeDevice, makeIdentity, startRelay, TestClient, type TestRelay } from "./helpers.js";

let r: TestRelay | undefined;
const open: TestClient[] = [];
afterEach(async () => {
  for (const c of open.splice(0)) c.ws.terminate();
  await r?.close();
  r = undefined;
});
const R = () => r as TestRelay;

async function connectFrom(ip: string): Promise<string> {
  try {
    open.push(await TestClient.connect(R().url, { "x-forwarded-for": ip }));
    return "open";
  } catch (e) {
    return (e as Error).message;
  }
}

const lots = { connectsPerIpPerMinute: 10_000, maxUnauthConnections: 10_000, maxUnauthPerIp: 10_000, authsPerIpv4PerMinute: 10_000 };

describe("the global connection pool under the IPv4 allowance", () => {
  it("20 IPv4 addresses can't take every slot: past 80% the strict per-IP cap applies, and a newcomer always gets in", async () => {
    r = await startRelay({ config: { trustProxy: 1 }, limits: { ...lots, maxConnections: 100, maxConnectionsPerIpv4: 50, maxConnectionsPerIp: 4 } });
    const per: Record<string, Record<string, number>> = {};
    for (let a = 0; a < 20; a++) {
      const ip = `198.51.100.${a + 1}`;
      per[ip] = {};
      for (let i = 0; i < 50; i++) {
        const o = await connectFrom(ip);
        per[ip][o] = (per[ip][o] ?? 0) + 1;
      }
    }
    // The first address got its NAT allowance; once the pool was 80% full,
    // every address was held to the strict cap.
    expect(per["198.51.100.1"].open).toBe(50);
    expect(per["198.51.100.2"].open).toBe(30);
    // Each later address was held to the strict cap at any one time (refused past it).
    for (let a = 3; a <= 20; a++) expect(per[`198.51.100.${a}`]["HTTP 429"] ?? 0).toBeGreaterThan(0);
    const st = R().relay as unknown as { conns: Set<unknown>; perIp: Map<string, number> };
    expect(st.conns.size).toBeLessThanOrEqual(100);
    // Once the pool filled, room came out of the biggest address, not the newcomers.
    expect(st.perIp.get("198.51.100.1")!).toBeLessThan(50);
    // A newcomer on a fresh address gets in even with the pool full.
    expect(await connectFrom("203.0.113.250")).toBe("open");
    expect(st.conns.size).toBeLessThanOrEqual(100);
  });

  it("when full, evicts the least recently active authenticated connection of the biggest address bucket, never the newcomer", async () => {
    r = await startRelay({ config: { trustProxy: 1 }, limits: { ...lots, maxConnections: 5, maxConnectionsPerIpv4: 10, maxConnectionsPerIp: 2 } });
    const big: TestClient[] = [];
    for (let i = 0; i < 3; i++) {
      const c = await TestClient.connect(R().url, { "x-forwarded-for": "198.51.100.50" });
      expect(await c.auth(makeDevice(makeIdentity(), R().nowSec()))).toEqual({ t: "ok" });
      big.push(c);
      open.push(c);
      R().clock.advance(1000);
    }
    // big[0] is the least recently active: big[1] and big[2] send something.
    for (const c of big.slice(1)) await c.request({ t: "nope" });
    expect(await connectFrom("198.51.100.60")).toBe("open");
    expect(await connectFrom("198.51.100.61")).toBe("open"); // pool now full (5)
    const newcomer = await TestClient.connect(R().url, { "x-forwarded-for": "203.0.113.7" });
    open.push(newcomer);
    expect(newcomer.hello.t).toBe("hello");
    expect(await big[0].closed).toBe(CLOSE.tooManyConnections);
    expect(big[1].closeCode).toBeUndefined();
    expect(big[2].closeCode).toBeUndefined();
  });

  it("the IPv4 new-device allowance falls back to the strict one when the device table is 80% full", async () => {
    r = await startRelay({ limits: { ...lots, maxDevices: 10, newDevicesPerIpv4PerDay: 1000, newDevicesPerIpPerDay: 2 } });
    const out: string[] = [];
    for (let i = 0; i < 11; i++) {
      const c = await TestClient.connect(R().url);
      open.push(c);
      const reply = await c.auth(makeDevice(makeIdentity(), R().nowSec()));
      out.push(reply.t === "ok" ? "ok" : String(reply.code));
    }
    // 8 under the IPv4 allowance (to 80% of 10), then the strict 2 per day, then refused.
    expect(out.slice(0, 10)).toEqual(Array(10).fill("ok"));
    expect(out[10]).toBe("rate-limited");
  });
});

describe("pre-release re-review M-1: pool eviction never pushes an address below the strict per-IP cap", () => {
  const perIp = (ip: string) => (R().relay as unknown as { perIp: Map<string, number> }).perIp.get(ip) ?? 0;
  const authedFrom = async (ip: string, device = makeDevice(makeIdentity(), R().nowSec())) => {
    const c = await TestClient.connect(R().url, { "x-forwarded-for": ip });
    open.push(c);
    expect(await c.auth(device)).toEqual({ t: "ok" });
    return c;
  };

  it("a churning attacker whose addresses stay at the strict cap can't push an honest shared-NAT bucket below it", async () => {
    r = await startRelay({ config: { trustProxy: 1 }, limits: { ...lots, maxConnections: 20, maxConnectionsPerIpv4: 12, maxConnectionsPerIp: 4 } });
    const honest: TestClient[] = [];
    for (let i = 0; i < 12; i++) honest.push(await authedFrom("198.51.100.10"));
    // The attacker fills the rest of the pool at the strict cap per address.
    for (let i = 0; i < 4; i++) expect(await connectFrom("203.0.113.1")).toBe("open");
    for (let i = 0; i < 4; i++) expect(await connectFrom("203.0.113.2")).toBe("open");
    expect(perIp("198.51.100.10")).toBe(12);
    // Then reconnects from fresh addresses, holding every slot it gets.
    const outcomes: string[] = [];
    for (let i = 0; i < 30; i++) outcomes.push(await connectFrom(`203.0.113.${10 + i}`));
    await new Promise((res) => setTimeout(res, 50));
    // The honest bucket gave up only what it held above the strict cap...
    expect(perIp("198.51.100.10")).toBe(4);
    expect(outcomes.slice(0, 8)).toEqual(Array(8).fill("open"));
    // ...and after that every newcomer is refused.
    expect(outcomes.slice(8)).toEqual(Array(22).fill("HTTP 503"));
    expect(honest.filter((c) => c.closeCode === undefined)).toHaveLength(4);
  });

  it("when every address is at or below the strict cap, a newcomer is refused and nobody is evicted", async () => {
    r = await startRelay({ config: { trustProxy: 1 }, limits: { ...lots, maxConnections: 6, maxConnectionsPerIpv4: 2, maxConnectionsPerIp: 2 } });
    const held: TestClient[] = [];
    for (const ip of ["198.51.100.1", "198.51.100.2", "198.51.100.3"]) for (let i = 0; i < 2; i++) held.push(await authedFrom(ip));
    expect(await connectFrom("203.0.113.9")).toBe("HTTP 503");
    await new Promise((res) => setTimeout(res, 50));
    expect(held.every((c) => c.closeCode === undefined)).toBe(true);
  });

  it("one newcomer address causes at most 10 evictions a minute", async () => {
    r = await startRelay({ config: { trustProxy: 1 }, limits: { ...lots, maxConnections: 20, maxConnectionsPerIpv4: 20, maxConnectionsPerIp: 4 } });
    for (let i = 0; i < 16; i++) expect(await connectFrom("198.51.100.10")).toBe("open");
    for (let i = 0; i < 4; i++) expect(await connectFrom(`198.51.100.${20 + i}`)).toBe("open");
    const outcomes: string[] = [];
    for (let i = 0; i < 12; i++) {
      // X connects (evicting one of the big bucket's), leaves, and a fresh filler refills its slot.
      try {
        const x = await TestClient.connect(R().url, { "x-forwarded-for": "203.0.113.99" });
        outcomes.push("open");
        await x.close();
        await new Promise((res) => setTimeout(res, 10));
        expect(await connectFrom(`198.51.100.${40 + i}`)).toBe("open");
      } catch (e) {
        outcomes.push((e as Error).message);
      }
    }
    expect(outcomes).toEqual([...Array(10).fill("open"), "HTTP 503", "HTTP 503"]);
    // Still room to give: the bucket is above the strict cap, so the limit is what refused X.
    expect(perIp("198.51.100.10")).toBe(6);
    R().clock.advance(60_000);
    expect(await connectFrom("203.0.113.99")).toBe("open");
  });

  it("in the victim bucket, the userId with the most connections there gives one up, not another user's idle receiver", async () => {
    r = await startRelay({ config: { trustProxy: 1 }, limits: { ...lots, maxConnections: 4, maxConnectionsPerIpv4: 10, maxConnectionsPerIp: 1 } });
    const ip = "198.51.100.30";
    // B is the least recently active connection in the bucket, but holds only one.
    const b = await authedFrom(ip);
    R().clock.advance(1000);
    const alice = makeIdentity();
    const a1 = await authedFrom(ip, makeDevice(alice, R().nowSec()));
    R().clock.advance(1000);
    const a2 = await authedFrom(ip, makeDevice(alice, R().nowSec()));
    R().clock.advance(1000);
    await a2.request({ t: "nope" });
    expect(await connectFrom("198.51.100.31")).toBe("open"); // full (4)
    const newcomer = await TestClient.connect(R().url, { "x-forwarded-for": "203.0.113.7" });
    open.push(newcomer);
    expect(await a1.closed).toBe(CLOSE.tooManyConnections);
    expect(b.closeCode).toBeUndefined();
    expect(a2.closeCode).toBeUndefined();
  });
});

describe("pre-release re-review L-4: pool eviction happens only after the upgrade succeeds", () => {
  it("a full pool's upgrade that fails evicts nobody", async () => {
    r = await startRelay({ config: { trustProxy: 1 }, limits: { ...lots, maxConnections: 3, maxConnectionsPerIpv4: 10, maxConnectionsPerIp: 1 } });
    const held: TestClient[] = [];
    // 198.51.100.5 holds 2 (above the strict 1, so it could give one up).
    for (const ip of ["198.51.100.5", "198.51.100.5", "198.51.100.6"]) {
      const c = await TestClient.connect(R().url, { "x-forwarded-for": ip });
      open.push(c);
      held.push(c);
    }
    // An upgrade request ws rejects (no Sec-WebSocket-Key) gets past the relay's own checks.
    const { request } = await import("node:http");
    const status = await new Promise<number>((resolve, reject) => {
      const req = request({
        host: "127.0.0.1",
        port: R().port,
        path: new URL(R().url).pathname,
        headers: { Connection: "Upgrade", Upgrade: "websocket", "x-forwarded-for": "203.0.113.5" },
      });
      req.on("response", (res) => resolve(res.statusCode ?? 0));
      req.on("upgrade", () => reject(new Error("upgraded")));
      req.on("error", reject);
      req.end();
    });
    expect(status).toBe(400);
    await new Promise((res) => setTimeout(res, 50));
    expect(held.every((c) => c.closeCode === undefined)).toBe(true);
    expect((R().relay as unknown as { conns: Set<unknown> }).conns.size).toBe(3);
  });
});
