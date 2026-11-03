// Copyright 2026 Ix Infrastructure Inc.
// The public HTTP surface: /healthz, /metrics, /.well-known/p2p-relay.json.

import { afterEach, describe, expect, it } from "vitest";
import { RELAY_SOFTWARE, RELAY_VERSION } from "../server.js";
import { MemoryStore } from "../store.js";
import { authed, makeCap, makeDevice, makeEnvelope, makeIdentity, startRelay, type TestRelay } from "./helpers.js";

let r: TestRelay;
afterEach(async () => {
  await r.close();
});

describe("http", () => {
  it("GET /healthz", async () => {
    r = await startRelay();
    const res = await fetch(`${r.http}/healthz`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("GET /.well-known/p2p-relay.json describes the relay for operators and communities", async () => {
    r = await startRelay({
      config: { powBits: 4, operatorContact: "mailto:ops@example.org", policy: "No logs beyond counters.", name: "Example relay" },
      limits: { mailboxEnvelopes: 5000 },
    });
    const res = await fetch(`${r.http}/.well-known/p2p-relay.json`);
    expect(res.status).toBe(200);
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
    const info = await res.json();
    expect(info).toMatchObject({
      protocol: "p2p/v3",
      relay: "wss://relay.test/v3",
      name: "Example relay",
      software: { name: RELAY_SOFTWARE, version: RELAY_VERSION },
      pow: 4,
      operator: { contact: "mailto:ops@example.org" },
      policy: "No logs beyond counters.",
    });
    expect(info.limits.mailboxEnvelopes).toBe(5000);
    expect(RELAY_VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("serves /metrics on a separate listener (counts only), not on the public port", async () => {
    r = await startRelay({ config: { metricsPort: 0 } });
    const alice = makeDevice(makeIdentity(), r.nowSec());
    const bob = makeDevice(makeIdentity(), r.nowSec());
    const ac = await authed(r, alice);
    await authed(r, bob);
    const env = makeEnvelope(alice, { userId: bob.identity.userId, did: bob.did });
    await ac.request({ t: "send", to: bob.identity.userId, tdid: bob.did, env, cap: makeCap(bob, r.nowSec()).jws });
    expect(r.relay.metricsPort).toBeGreaterThan(0);
    expect(r.relay.metricsPort).not.toBe(r.port);
    const res = await fetch(`http://127.0.0.1:${r.relay.metricsPort}/metrics`);
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toMatch(/^p2p_relay_sends_total\{result="sent"\} 1$/m);
    expect(text).toMatch(/^p2p_relay_auth_total\{result="ok"\} 2$/m);
    expect(text).toMatch(/^p2p_relay_connections_open 2$/m);
    for (const secret of [alice.identity.userId, bob.identity.userId, alice.did, bob.did, "127.0.0.1"]) expect(text).not.toContain(secret);
    // M2: the public port doesn't serve it.
    expect((await fetch(`${r.http}/metrics`)).status).toBe(404);
  });

  it("serves /debug/stats on the metrics listener only when DEBUG_STATS is on", async () => {
    r = await startRelay({ config: { metricsPort: 0 } });
    expect((await fetch(`http://127.0.0.1:${r.relay.metricsPort}/debug/stats`)).status).toBe(404);
    expect((await fetch(`${r.http}/debug/stats`)).status).toBe(404);
    await r.close();
    r = await startRelay({ config: { metricsPort: 0, debugStats: true } });
    const alice = makeDevice(makeIdentity(), r.nowSec());
    await authed(r, alice);
    const res = await fetch(`http://127.0.0.1:${r.relay.metricsPort}/debug/stats?store=1&reset=1`);
    expect(res.status).toBe(200);
    const s = (await res.json()) as Record<string, any>;
    expect(s.rssBytes).toBeGreaterThan(0);
    expect(s.connections).toBe(1);
    expect(s.maps.byIss).toBe(1);
    expect(s.store.devices).toBe(1);
    expect(s.lagMs).toHaveProperty("p99");
    expect(JSON.stringify(s)).not.toContain(alice.identity.userId);
    // Never on the public port.
    expect((await fetch(`${r.http}/debug/stats`)).status).toBe(404);
  });

  it("serves /metrics on the public port only with the operator's bearer token", async () => {
    r = await startRelay({ config: { metricsToken: "s3cret-token" } });
    expect((await fetch(`${r.http}/metrics`)).status).toBe(404);
    expect((await fetch(`${r.http}/metrics`, { headers: { authorization: "Bearer wrong-token!" } })).status).toBe(404);
    const ok = await fetch(`${r.http}/metrics`, { headers: { authorization: "Bearer s3cret-token" } });
    expect(ok.status).toBe(200);
    expect(await ok.text()).toContain("p2p_relay_connections_open");
  });

  it("M2: metrics don't tell a stored contact from a silently dropped one, nor show delivery", async () => {
    let scans = 0;
    class CountingStore extends MemoryStore {
      counts() {
        scans++;
        return super.counts();
      }
    }
    r = await startRelay({ store: new CountingStore() });
    const alice = makeDevice(makeIdentity(), r.nowSec());
    const bob = makeDevice(makeIdentity(), r.nowSec());
    const ghost = makeDevice(makeIdentity(), r.nowSec());
    const ac = await authed(r, alice);
    const bc = await authed(r, bob); // online: would get a delivery
    const contact = (d: typeof bob) =>
      ac.request({ t: "send", to: d.identity.userId, tdid: d.did, env: makeEnvelope(alice, { userId: d.identity.userId, did: d.did }, { kind: "contact" }) });
    const m0 = r.relay.metrics.render();
    expect(await contact(bob)).toMatchObject({ t: "sent" });
    await bc.next((f) => f.t === "env");
    const m1 = r.relay.metrics.render();
    expect(await contact(ghost)).toMatchObject({ t: "sent" });
    const m2 = r.relay.metrics.render();
    const diff = (a: string, b: string) => b.split("\n").filter((l) => !a.split("\n").includes(l));
    // The same lines change by the same amount either way.
    expect(diff(m0, m1).map((l) => l.replace(/ \d+$/, ""))).toEqual(diff(m1, m2).map((l) => l.replace(/ \d+$/, "")));
    expect(m2).not.toMatch(/delivered|silently|acked/);
    // Scrapes read cached counts, not the tables.
    const before = scans;
    for (let i = 0; i < 5; i++) r.relay.metrics.render();
    expect(scans).toBe(before);
  });

  it("405 for other methods, 404 for unknown paths, 426 on the WebSocket path", async () => {
    r = await startRelay();
    expect((await fetch(`${r.http}/healthz`, { method: "POST" })).status).toBe(405);
    expect((await fetch(`${r.http}/nope`)).status).toBe(404);
    expect((await fetch(`${r.http}/v3`)).status).toBe(426);
  });

  it("rate-limits HTTP per IP", async () => {
    r = await startRelay({ limits: { httpPerIpPerMinute: 2 } });
    expect((await fetch(`${r.http}/healthz`)).status).toBe(200);
    expect((await fetch(`${r.http}/healthz`)).status).toBe(200);
    expect((await fetch(`${r.http}/healthz`)).status).toBe(429);
  });

  it("serves the API under a custom path", async () => {
    r = await startRelay({ config: { relayUrl: "wss://relay.test/p2p/v3" } });
    const dev = makeDevice(makeIdentity(), r.nowSec());
    expect(r.url.endsWith("/p2p/v3")).toBe(true);
    await authed(r, dev);
    expect((await fetch(`${r.http}/p2p/v3/identity/${dev.identity.userId}`)).status).toBe(404);
  });
});
