// Copyright 2026 Ix Infrastructure Inc.
// #8 HTTP route limits: /v3/identity/<userId>, /tips, /chain.

import { afterEach, describe, expect, it } from "vitest";
import { makeDoc } from "../src/__tests__/helpers.js";
import { assertHealthy, authedFrom, Canary, CANARY_IP, newDevice, Sampler, tally, xff } from "./harness/load.js";
import { RelayProcess } from "./harness/relay-process.js";

const ATTACK_IP = "198.51.100.110";
const limits = { httpPerIpPerMinute: 60, chainMaxN: 8 };

let relay: RelayProcess;
let canary: Canary | undefined;
afterEach(async () => {
  canary?.close();
  await relay?.dispose();
});

async function get(path: string, ip: string): Promise<{ status: number; body: any }> {
  const res = await fetch(`${relay.http}${path}`, { headers: xff(ip) });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

describe("8. HTTP route limits", () => {
  it("rate-limits identity, tips and chain lookups per IP, bounds chain walks, and other IPs still read", async () => {
    relay = await RelayProcess.start({ limits, env: { TRUST_PROXY: "1" } });
    const sampler = await Sampler.start(relay);
    canary = await Canary.start(relay);

    // A 12-version identity to walk.
    const x = newDevice(relay);
    const xc = await authedFrom(relay, x, "198.51.100.111");
    let prev: string | null = null;
    let head = "";
    for (let ver = 1; ver <= 12; ver++) {
      const d = makeDoc(x.identity, relay.nowSec(), { ver, prev, devices: [x.did] });
      expect(await xc.request({ t: "identity", doc: d.jws })).toMatchObject({ t: "ok" });
      prev = head = d.hash;
    }
    const uid = x.identity.userId;
    const routes = [`/v3/identity/${uid}`, `/v3/identity/${uid}/tips`, `/v3/identity/${uid}/chain?to=${head}&n=8`];

    // 150 lookups from one IP, 10 in flight at a time.
    const statuses: number[] = [];
    for (let i = 0; i < 150; i += 10) {
      const batch = await Promise.all(Array.from({ length: 10 }, (_, j) => get(routes[(i + j) % 3], ATTACK_IP)));
      statuses.push(...batch.map((r) => r.status));
    }
    // Another IP still reads, and the chain walk is bounded by chainMaxN.
    const fresh = "198.51.100.112";
    const canaryRead = await get(routes[0], CANARY_IP);
    const chain = await get(`/v3/identity/${uid}/chain?to=${head}`, fresh);
    const tooLong = await get(`/v3/identity/${uid}/chain?to=${head}&n=9`, fresh);
    const bad = await Promise.all(
      [`/v3/identity/${uid}/chain?to=${head}&n=0`, `/v3/identity/${uid}/chain?to=${head}&n=abc`, `/v3/identity/${uid}/chain?to=nope`, `/v3/identity/%E0%A4%A/tips`].map(
        (p) => get(p, fresh),
      ),
    );
    const unknown = await get(`/v3/identity/${newDevice(relay).identity.userId}`, fresh);
    const post = await fetch(`${relay.http}/v3/identity/${uid}`, { method: "POST", headers: xff(fresh), body: "x" });

    await assertHealthy({
      test: "8 http routes",
      relay,
      sampler,
      canary,
      limits,
      extra: { attacker: tally(statuses.map(String)), canaryRead: canaryRead.status, chainLen: chain.body?.docs?.length, tooLong: tooLong.status, bad: bad.map((b) => b.status), unknown: unknown.status, post: post.status },
    });
    expect(tally(statuses.map(String))).toEqual({ "200": 60, "429": 90 });
    expect(canaryRead.status).toBe(200);
    expect(chain.status).toBe(200);
    expect(chain.body.docs).toHaveLength(limits.chainMaxN);
    expect(tooLong.status).toBe(400);
    expect(bad.map((b) => b.status)).toEqual([400, 400, 400, 400]);
    expect(unknown.status).toBe(404);
    expect(post.status).toBe(405);
  });
});
