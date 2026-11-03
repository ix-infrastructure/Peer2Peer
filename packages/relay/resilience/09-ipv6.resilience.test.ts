// Copyright 2026 Ix Infrastructure Inc.
// #9 Per-/64 IPv6 bucketing through X-Forwarded-For with TRUST_PROXY=1.

import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import type { TestClient } from "../src/__tests__/helpers.js";
import { assertHealthy, Canary, connectFrom, Sampler, tally, xff } from "./harness/load.js";
import { RelayProcess } from "./harness/relay-process.js";

// maxConnectionsPerIp is the IPv6 /64 cap; the IPv4 part of the test uses the IPv4 knob (F-5).
const limits = { maxConnectionsPerIp: 4, maxConnectionsPerIpv4: 4, connectsPerIpPerMinute: 100, httpPerIpPerMinute: 20 };
const PREFIX = "2001:db8:aa:1";

let relay: RelayProcess;
let canary: Canary | undefined;
const open: TestClient[] = [];
afterEach(async () => {
  canary?.close();
  for (const c of open.splice(0)) c.ws.terminate();
  await relay?.dispose();
});

/** A random address in 2001:db8:aa:1::/64. */
const in64 = (prefix = PREFIX): string => {
  const h = randomBytes(8).toString("hex");
  return `${prefix}:${h.slice(0, 4)}:${h.slice(4, 8)}:${h.slice(8, 12)}:${h.slice(12, 16)}`;
};

async function connectOutcome(forwarded: string): Promise<string> {
  try {
    open.push(await connectFrom(relay, forwarded));
    return "open";
  } catch (e) {
    return (e as Error).message;
  }
}

async function httpStatus(forwarded: string): Promise<number> {
  const res = await fetch(`${relay.http}/.well-known/p2p-relay.json`, { headers: xff(forwarded) });
  await res.arrayBuffer();
  return res.status;
}

describe("9. per-/64 IPv6 bucketing (X-Forwarded-For, TRUST_PROXY=1)", () => {
  it("one /64 shares one bucket however the addresses rotate; neighbours and IPv4-mapped forms bucket correctly", async () => {
    relay = await RelayProcess.start({ limits, env: { TRUST_PROXY: "1" } });
    const sampler = await Sampler.start(relay);
    canary = await Canary.start(relay);
    const base = await relay.stats();

    // Connections: 8 rotating addresses in one /64 against a cap of 4.
    const rotating: string[] = [];
    for (let i = 0; i < 8; i++) rotating.push(await connectOutcome(in64()));
    // Forms of the same /64 that must not escape the bucket.
    const forms = {
      spoofedLeft: await connectOutcome(`198.51.100.1, ${in64()}`),
      bracketedPort: await connectOutcome(`[${in64()}]:443`),
      upperCase: await connectOutcome(in64().toUpperCase()),
      compressed: await connectOutcome(`${PREFIX}::7`),
    };
    // The neighbouring /64 is its own bucket.
    const neighbour = await connectOutcome(in64("2001:db8:aa:2"));
    // IPv4-mapped IPv6 shares the IPv4 address's bucket.
    const v4: string[] = [];
    for (let i = 0; i < 4; i++) v4.push(await connectOutcome("198.51.100.9"));
    const mapped = await connectOutcome("::ffff:198.51.100.9");
    const mappedHex = await connectOutcome("::ffff:c633:6409");

    // HTTP: 30 requests rotating through one /64 against 20 per minute.
    const http: number[] = [];
    for (let i = 0; i < 30; i++) http.push(await httpStatus(in64("2001:db8:bb:1")));
    const httpNeighbour = await httpStatus(in64("2001:db8:bb:2"));
    const st = await relay.stats();

    await assertHealthy({
      test: "9 ipv6 /64",
      relay,
      sampler,
      canary,
      limits,
      extra: { rotating: tally(rotating), forms, neighbour, v4: tally(v4), mapped, mappedHex, http: tally(http.map(String)), httpNeighbour, perIpKeys: st.maps.perIp - base.maps.perIp },
    });
    expect(tally(rotating)).toEqual({ open: 4, "HTTP 429": 4 });
    expect(forms).toEqual({ spoofedLeft: "HTTP 429", bracketedPort: "HTTP 429", upperCase: "HTTP 429", compressed: "HTTP 429" });
    expect(neighbour).toBe("open");
    expect(tally(v4)).toEqual({ open: 4 });
    expect(mapped).toBe("HTTP 429");
    expect(mappedHex).toBe("HTTP 429");
    expect(tally(http.map(String))).toEqual({ "200": 20, "429": 10 });
    expect(httpNeighbour).toBe(200);
    // Open sockets live in three buckets: the /64, its neighbour, the IPv4 address.
    expect(st.maps.perIp - base.maps.perIp).toBe(3);
  });
});
