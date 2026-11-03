// Copyright 2026 Ix Infrastructure Inc.
// #1 Identity publish caps: rate per userId and per IP, branch tips, versions kept.

import { afterEach, describe, expect, it } from "vitest";
import { makeDoc } from "../src/__tests__/helpers.js";
import { assertHealthy, authedFrom, Canary, newDevice, Sampler, tally } from "./harness/load.js";
import { RelayProcess } from "./harness/relay-process.js";

const ATTACK_IP = "198.51.100.10";
const limits = { identityPublishPerIssPerHour: 10, identityPublishPerIpPerHour: 16, identityMaxTips: 2, identityMaxVersions: 6 };

let relay: RelayProcess;
let canary: Canary | undefined;
afterEach(async () => {
  canary?.close();
  await relay?.dispose();
});

async function getJson(path: string, ip: string): Promise<{ status: number; body: any }> {
  const res = await fetch(`${relay.http}${path}`, { headers: { "x-forwarded-for": ip } });
  return { status: res.status, body: await res.json() };
}

describe("1. identity publish caps (tips, versions, rate)", () => {
  it("rate-limits publishes per userId and per IP, keeps at most identityMaxVersions, and an honest user still publishes", async () => {
    relay = await RelayProcess.start({ limits, env: { TRUST_PROXY: "1" } });
    const sampler = await Sampler.start(relay);
    canary = await Canary.start(relay);

    // Attacker X publishes a 14-version chain: 10 per hour per userId.
    const x = newDevice(relay);
    const xc = await authedFrom(relay, x, ATTACK_IP);
    const codesX: string[] = [];
    let prev: string | null = null;
    let headX = "";
    for (let ver = 1; ver <= 14; ver++) {
      const doc = makeDoc(x.identity, relay.nowSec(), { ver, prev, devices: [x.did] });
      const r = await xc.request({ t: "identity", doc: doc.jws });
      codesX.push(r.t === "ok" ? "ok" : String(r.code));
      if (r.t === "ok") {
        prev = doc.hash;
        headX = doc.hash;
      }
    }
    expect(tally(codesX)).toEqual({ ok: 10, "rate-limited": 4 });

    // Attacker Y on the same IP: the IP has 16 per hour, 10 already spent.
    const y = newDevice(relay);
    const yc = await authedFrom(relay, y, ATTACK_IP);
    const codesY: string[] = [];
    prev = null;
    for (let ver = 1; ver <= 9; ver++) {
      const doc = makeDoc(y.identity, relay.nowSec(), { ver, prev, devices: [y.did] });
      const r = await yc.request({ t: "identity", doc: doc.jws });
      codesY.push(r.t === "ok" ? "ok" : String(r.code));
      if (r.t === "ok") prev = doc.hash;
    }
    expect(tally(codesY)).toEqual({ ok: 6, "rate-limited": 3 });

    // Versions: 10 published, at most 6 kept; the head is the newest.
    const chain = await getJson(`/v3/identity/${x.identity.userId}/chain?to=${headX}&n=64`, "203.0.113.90");
    expect(chain.status).toBe(200);
    expect(chain.body.docs.length).toBeLessThanOrEqual(limits.identityMaxVersions);

    // The canary's receiver publishes its own document while the attacker is capped.
    const b = canary.b;
    const own = makeDoc(b.identity, relay.nowSec(), { devices: [b.did] });
    expect(await canary.bc.request({ t: "identity", doc: own.jws })).toMatchObject({ t: "ok" });

    // A rate, not a ban: an hour later X publishes again.
    await relay.advance(3600_000);
    const next = makeDoc(x.identity, relay.nowSec(), { ver: 11, prev: headX, devices: [x.did] });
    expect(await xc.request({ t: "identity", doc: next.jws })).toMatchObject({ t: "ok" });
    const stats = await relay.stats({ store: true });

    await assertHealthy({
      test: "1a identity rate + versions",
      relay,
      sampler,
      canary,
      limits,
      extra: { publishesX: tally(codesX), publishesY: tally(codesY), chainLen: chain.body.docs.length, identityDocs: stats.store?.identityDocs },
    });
    // X: 6 kept; Y: 6; canary: 1.
    expect(stats.store?.identityDocs).toBeLessThanOrEqual(2 * limits.identityMaxVersions + 1);
  });

  it("refuses a third branch tip with `full`, and a merge brings the tips back down", async () => {
    relay = await RelayProcess.start({ limits, env: { TRUST_PROXY: "1" } });
    const sampler = await Sampler.start(relay);
    canary = await Canary.start(relay);
    const x = newDevice(relay);
    const xc = await authedFrom(relay, x, ATTACK_IP);
    const now = relay.nowSec();
    const root = makeDoc(x.identity, now, { devices: [x.did] });
    expect(await xc.request({ t: "identity", doc: root.jws })).toMatchObject({ t: "ok" });
    const forks = ["a", "b", "c", "d"].map((n) => makeDoc(x.identity, now, { ver: 2, prev: root.hash, devices: [x.did], name: `fork-${n}` }));
    const codes: string[] = [];
    for (const f of forks) {
      const r = await xc.request({ t: "identity", doc: f.jws });
      codes.push(r.t === "ok" ? "ok" : String(r.code));
    }
    expect(codes).toEqual(["ok", "ok", "full", "full"]);
    const tips = await getJson(`/v3/identity/${x.identity.userId}/tips`, "203.0.113.91");
    expect(tips.body.tips).toHaveLength(limits.identityMaxTips);

    // A merge names the higher-hash tip as `prev`.
    const [hi, lo] = forks[0].hash > forks[1].hash ? [forks[0], forks[1]] : [forks[1], forks[0]];
    const merge = makeDoc(x.identity, now, { ver: 3, prev: hi.hash, merge: lo.hash, devices: [x.did] });
    expect(await xc.request({ t: "identity", doc: merge.jws })).toMatchObject({ t: "ok" });
    expect((await getJson(`/v3/identity/${x.identity.userId}/tips`, "203.0.113.91")).body.tips).toHaveLength(1);

    await assertHealthy({ test: "1b identity tips", relay, sampler, canary, limits, extra: { forkCodes: codes } });
  });
});
