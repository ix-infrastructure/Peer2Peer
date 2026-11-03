// Copyright 2026 Ix Infrastructure Inc.
// §5.2 framing: JSON text frames, one object each, at most 96 KiB; §1/§5.4
// envelopes at most 64 KiB.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CLOSE } from "../server.js";
import { authed, makeCap, makeDevice, makeEnvelope, makeIdentity, startRelay, TestClient, type TestRelay } from "./helpers.js";

let r: TestRelay;
beforeEach(async () => {
  r = await startRelay();
});
afterEach(async () => {
  await r.close();
});

describe("frames", () => {
  it("closes the connection (1009) on a frame over 96 KiB", async () => {
    const c = await TestClient.connect(r.url);
    c.send(JSON.stringify({ t: "link-get", pad: "x".repeat(96 * 1024) }));
    expect(await c.closed).toBe(CLOSE.tooBig);
  });

  it("accepts a frame of exactly 96 KiB", async () => {
    const c = await TestClient.connect(r.url);
    const base = JSON.stringify({ t: "nope", id: "big", pad: "" });
    c.send(JSON.stringify({ t: "nope", id: "big", pad: "x".repeat(96 * 1024 - base.length) }));
    expect(await c.next((f) => f.id === "big")).toMatchObject({ code: "auth-required" });
    await c.close();
  });

  it("answers too-large for an envelope over 64 KiB inside a legal frame", async () => {
    const alice = makeDevice(makeIdentity(), r.nowSec());
    const bob = makeDevice(makeIdentity(), r.nowSec());
    const ac = await authed(r, alice);
    await authed(r, bob);
    const cap = makeCap(bob, r.nowSec());
    const env = makeEnvelope(alice, { userId: bob.identity.userId, did: bob.did }, { padTo: 64 * 1024 });
    expect(env.length).toBeGreaterThan(64 * 1024);
    expect(await ac.request({ t: "send", to: bob.identity.userId, tdid: bob.did, env, cap: cap.jws })).toMatchObject({
      t: "error",
      code: "too-large",
    });
    // Just under the cap goes through.
    const ok = makeEnvelope(alice, { userId: bob.identity.userId, did: bob.did }, { padTo: 44 * 1024 });
    expect(await ac.request({ t: "send", to: bob.identity.userId, tdid: bob.did, env: ok, cap: cap.jws })).toMatchObject({ t: "sent" });
  });

  it("answers bad-request to non-JSON, non-object, binary and unknown frames without closing", async () => {
    const dev = makeDevice(makeIdentity(), r.nowSec());
    const c = await authed(r, dev);
    for (const raw of ["not json", "[1,2]", "42", JSON.stringify({ no: "t" })]) {
      const reply = c.next((f) => f.t === "error");
      c.send(raw);
      expect(await reply).toEqual({ t: "error", code: "bad-request" });
    }
    const bin = c.next((f) => f.t === "error");
    c.ws.send(Buffer.from([1, 2, 3]));
    expect(await bin).toEqual({ t: "error", code: "bad-request" });
    expect(await c.request({ t: "dance" })).toMatchObject({ code: "bad-request" });
    const badId = c.next((f) => f.t === "error");
    c.send({ t: "send", id: "x".repeat(200) });
    expect(await badId).toEqual({ t: "error", code: "bad-request" });
    expect(c.closeCode).toBeUndefined();
    await c.close();
  });

  it("refuses upgrades on other paths and enforces the per-IP connection cap", async () => {
    await expect(TestClient.connect(r.url.replace("/v3", "/v2"))).rejects.toThrow(/404/);
    await r.close();
    r = await startRelay({ limits: { maxConnectionsPerIpv4: 2 } });
    const a = await TestClient.connect(r.url);
    const b = await TestClient.connect(r.url);
    await expect(TestClient.connect(r.url)).rejects.toThrow(/429/);
    await a.close();
    await new Promise((res) => setTimeout(res, 20));
    const c = await TestClient.connect(r.url);
    await b.close();
    await c.close();
  });

  it("closes connections that never authenticate after unauthTimeoutSec", async () => {
    await r.close();
    r = await startRelay({ limits: { unauthTimeoutSec: 1 } });
    const anon = await TestClient.connect(r.url);
    const dev = makeDevice(makeIdentity(), r.nowSec());
    const ok = await authed(r, dev);
    expect(await anon.closed).toBe(CLOSE.unauthTimeout);
    await new Promise((res) => setTimeout(res, 100));
    expect(ok.closeCode).toBeUndefined();
    await ok.close();
  });

  it("closes connections with 1001 on graceful shutdown", async () => {
    const c = await TestClient.connect(r.url);
    await r.close();
    expect(await c.closed).toBe(CLOSE.shutdown);
    r = await startRelay();
  });
});
