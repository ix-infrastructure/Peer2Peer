// Copyright 2026 Ix Infrastructure Inc.
// §5.3 capabilities and §5.4 sending: the check order, caps, revocation,
// `uses`, and the single `undeliverable` code.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { testRelayCrypto, RelayCryptoError } from "../crypto.js";
import {
  authed,
  DAY,
  makeCap,
  makeDevice,
  makeEnvelope,
  makeIdentity,
  startRelay,
  TestClient,
  type Device,
  type TestRelay,
} from "./helpers.js";

let r: TestRelay;
let alice: Device;
let bob: Device;
let aliceC: TestClient;
let bobC: TestClient;

const to = (d: Device) => ({ userId: d.identity.userId, did: d.did });

beforeEach(async () => {
  r = await startRelay();
  alice = makeDevice(makeIdentity(), r.nowSec());
  bob = makeDevice(makeIdentity(), r.nowSec());
  aliceC = await authed(r, alice);
  bobC = await authed(r, bob);
});
afterEach(async () => {
  await r.close();
});

function send(c: TestClient, from: Device, dest: Device, extra: Record<string, unknown> = {}, envOpts = {}) {
  const env = makeEnvelope(from, to(dest), envOpts);
  return c.request({ t: "send", to: dest.identity.userId, tdid: dest.did, env, ...extra });
}

describe("send with a cap", () => {
  it("stores and delivers an envelope sent under a friend cap", async () => {
    const cap = makeCap(bob, r.nowSec(), { sub: alice.identity.userId });
    const env = makeEnvelope(alice, to(bob));
    const delivered = bobC.next((f) => f.t === "env");
    const reply = await aliceC.request({ id: "m1", t: "send", to: bob.identity.userId, tdid: bob.did, env, cap: cap.jws });
    expect(reply).toEqual({ t: "sent", id: "m1" });
    const f = await delivered;
    expect(f.env).toBe(env);
    expect(typeof f.rid).toBe("string");
  });

  it("accepts sub:\"*\" caps", async () => {
    const cap = makeCap(bob, r.nowSec(), { sub: "*" });
    expect(await send(aliceC, alice, bob, { cap: cap.jws })).toMatchObject({ t: "sent" });
  });

  const failures: [string, () => Record<string, unknown>][] = [
    ["a cap naming another relay", () => ({ cap: makeCap(bob, r.nowSec(), { relays: ["wss://other.test/v3"] }).jws })],
    ["a contact-only cap used for msg", () => ({ cap: makeCap(bob, r.nowSec(), { kinds: ["contact"] }).jws })],
    ["a cap for another sender", () => ({ cap: makeCap(bob, r.nowSec(), { sub: makeIdentity().userId }).jws })],
    ["a cap issued by someone other than the recipient", () => ({ cap: makeCap(makeDevice(makeIdentity(), r.nowSec()), r.nowSec()).jws })],
    ["an expired cap", () => ({ cap: makeCap(bob, r.nowSec(), { iat: r.nowSec() - 40 * DAY, exp: r.nowSec() - 1 }).jws })],
    ["a cap living longer than 90 days", () => ({ cap: makeCap(bob, r.nowSec(), { exp: r.nowSec() + 91 * DAY }).jws })],
    ["a cap whose iss differs from its cert", () => ({ cap: makeCap(bob, r.nowSec(), { iss: alice.identity.userId }).jws })],
    ["a cap that isn't a JWS", () => ({ cap: "garbage" })],
  ];
  for (const [name, extra] of failures) {
    it(`answers undeliverable for ${name}`, async () => {
      expect(await send(aliceC, alice, bob, extra())).toMatchObject({ t: "error", code: "undeliverable" });
    });
  }

  it("answers undeliverable for a valid cap to a mailbox the relay doesn't know", async () => {
    const carol = makeDevice(makeIdentity(), r.nowSec()); // never connected
    const cap = makeCap(carol, r.nowSec());
    expect(await send(aliceC, alice, carol, { cap: cap.jws })).toMatchObject({ t: "error", code: "undeliverable" });
  });

  it("answers undeliverable when tdid is bound to a different userId", async () => {
    // Mallory issues a perfectly valid cap for her own userId, then aims it at
    // bob's did: mailbox (mallory, bob.did) doesn't exist, because bob.did is
    // bound to bob.
    const mallory = makeDevice(makeIdentity(), r.nowSec());
    const env = makeEnvelope(alice, { userId: mallory.identity.userId, did: bob.did });
    const cap = makeCap(mallory, r.nowSec());
    const reply = await aliceC.request({ t: "send", to: mallory.identity.userId, tdid: bob.did, env, cap: cap.jws });
    expect(reply).toMatchObject({ t: "error", code: "undeliverable" });
    expect(r.store.counts().envelopes).toBe(0);
  });

  it("revoke: only an authenticated device of cap.iss can revoke", async () => {
    const cap = makeCap(bob, r.nowSec(), { sub: alice.identity.userId });
    // Alice (not the issuer) tries to revoke bob's cap: recorded under alice's iss, so no effect.
    expect(await aliceC.request({ t: "revoke", capid: cap.capid })).toMatchObject({ t: "ok" });
    expect(await send(aliceC, alice, bob, { cap: cap.jws })).toMatchObject({ t: "sent" });
    // Bob's other device revokes it.
    const bob2 = makeDevice(bob.identity, r.nowSec());
    const bob2C = await authed(r, bob2);
    expect(await bob2C.request({ t: "revoke", capid: cap.capid })).toMatchObject({ t: "ok" });
    expect(await send(aliceC, alice, bob, { cap: cap.jws })).toMatchObject({ t: "error", code: "undeliverable" });
  });

  it("revoke requires auth and a 16-byte capid", async () => {
    const c = await TestClient.connect(r.url);
    expect(await c.request({ t: "revoke", capid: "AAAAAAAAAAAAAAAAAAAAAA" })).toMatchObject({ code: "auth-required" });
    expect(await bobC.request({ t: "revoke", capid: "short" })).toMatchObject({ code: "bad-request" });
    await c.close();
  });

  it("enforces uses per relay", async () => {
    const cap = makeCap(bob, r.nowSec(), { uses: 2 });
    expect(await send(aliceC, alice, bob, { cap: cap.jws })).toMatchObject({ t: "sent" });
    expect(await send(aliceC, alice, bob, { cap: cap.jws })).toMatchObject({ t: "sent" });
    expect(await send(aliceC, alice, bob, { cap: cap.jws })).toMatchObject({ t: "error", code: "undeliverable" });
  });

  it("a failing send doesn't spend a use", async () => {
    const cap = makeCap(bob, r.nowSec(), { uses: 1, kinds: ["contact"] });
    expect(await send(aliceC, alice, bob, { cap: cap.jws }, { kind: "msg" })).toMatchObject({ code: "undeliverable" });
    expect(await send(aliceC, alice, bob, { cap: cap.jws }, { kind: "contact" })).toMatchObject({ t: "sent" });
  });
});

describe("send without a cap", () => {
  it("allows only contact", async () => {
    expect(await send(aliceC, alice, bob, {}, { kind: "msg" })).toMatchObject({ t: "error", code: "undeliverable" });
    expect(await send(aliceC, alice, bob, {}, { kind: "contact" })).toMatchObject({ t: "sent" });
    expect((await bobC.next((f) => f.t === "env")).t).toBe("env");
  });

  it("answers sent for a cap-less contact to an unknown mailbox, and drops it", async () => {
    const ghost = makeDevice(makeIdentity(), r.nowSec());
    expect(await send(aliceC, alice, ghost, {}, { kind: "contact" })).toMatchObject({ t: "sent" });
    expect(r.store.counts().envelopes).toBe(0);
  });

  it("delivers a contact to a device listed in a held identity document even before it connects", async () => {
    const carolId = makeIdentity();
    const carol = makeDevice(carolId, r.nowSec());
    const carolKeyDevice = makeDevice(carolId, r.nowSec());
    const kc = await authed(r, carolKeyDevice);
    const { makeDoc } = await import("./helpers.js");
    const doc = makeDoc(carolId, r.nowSec(), { devices: [carolKeyDevice.did, carol.did] });
    expect(await kc.request({ t: "identity", doc: doc.jws })).toMatchObject({ t: "ok" });
    expect(await send(aliceC, alice, carol, {}, { kind: "contact" })).toMatchObject({ t: "sent" });
    expect(r.store.counts().envelopes).toBe(1);
  });
});

describe("§5.4 steps 1 and 2", () => {
  it("rejects env.to / env.tdid that differ from the routing fields", async () => {
    const env = makeEnvelope(alice, to(bob));
    const carol = makeDevice(makeIdentity(), r.nowSec());
    expect(await aliceC.request({ t: "send", to: carol.identity.userId, tdid: bob.did, env })).toMatchObject({ code: "bad-envelope" });
    expect(await aliceC.request({ t: "send", to: bob.identity.userId, tdid: carol.did, env })).toMatchObject({ code: "bad-envelope" });
  });

  it("rejects an envelope whose signature isn't by fcert.spk", async () => {
    const mallory = makeDevice(makeIdentity(), r.nowSec());
    expect(await send(aliceC, alice, bob, {}, { kind: "contact", signWith: mallory.spkSecret })).toMatchObject({ code: "bad-envelope" });
  });

  it("rejects spoofed sender fields", async () => {
    const other = makeIdentity();
    expect(await send(aliceC, alice, bob, {}, { kind: "contact", overrides: { from: other.userId } })).toMatchObject({ code: "bad-envelope" });
    expect(await send(aliceC, alice, bob, {}, { kind: "contact", kid: bob.did })).toMatchObject({ code: "bad-envelope" });
  });

  it("rejects an envelope from another device than the connection's", async () => {
    // Valid, signed by bob, but submitted on alice's connection (a replay).
    const env = makeEnvelope(bob, to(alice), { kind: "contact" });
    expect(await aliceC.request({ t: "send", to: alice.identity.userId, tdid: alice.did, env })).toMatchObject({ code: "bad-envelope" });
  });

  it("rejects v != 3, wrong typ, and non-JWS", async () => {
    expect(await send(aliceC, alice, bob, {}, { kind: "contact", overrides: { v: 2 } })).toMatchObject({ code: "bad-envelope" });
    expect(await aliceC.request({ t: "send", to: bob.identity.userId, tdid: bob.did, env: "x.y.z" })).toMatchObject({ code: "bad-envelope" });
    expect(await aliceC.request({ t: "send", to: bob.identity.userId, tdid: bob.did })).toMatchObject({ code: "bad-envelope" });
  });

  it("enforces 120 sends/min per env.from", async () => {
    await r.close();
    r = await startRelay({ limits: { sendsPerMinute: 3 } });
    alice = makeDevice(makeIdentity(), r.nowSec());
    bob = makeDevice(makeIdentity(), r.nowSec());
    aliceC = await authed(r, alice);
    bobC = await authed(r, bob);
    const cap = makeCap(bob, r.nowSec());
    for (let i = 0; i < 3; i++) expect(await send(aliceC, alice, bob, { cap: cap.jws })).toMatchObject({ t: "sent" });
    expect(await send(aliceC, alice, bob, { cap: cap.jws })).toMatchObject({ code: "rate-limited" });
    r.clock.advance(60_000);
    expect(await send(aliceC, alice, bob, { cap: cap.jws })).toMatchObject({ t: "sent" });
  });
});

describe("undeliverable uniformity", () => {
  it("every capability or mailbox failure produces the identical frame", async () => {
    const used = makeCap(bob, r.nowSec(), { uses: 1 });
    expect(await send(aliceC, alice, bob, { cap: used.jws })).toMatchObject({ t: "sent" });
    const revoked = makeCap(bob, r.nowSec());
    await bobC.request({ t: "revoke", capid: revoked.capid });
    const ghost = makeDevice(makeIdentity(), r.nowSec());

    const cases: [Device, Record<string, unknown>, Record<string, unknown>][] = [
      [bob, { cap: makeCap(bob, r.nowSec(), { relays: ["wss://other.test/v3"] }).jws }, {}],
      [bob, { cap: makeCap(bob, r.nowSec(), { kinds: ["contact"] }).jws }, {}],
      [bob, { cap: revoked.jws }, {}],
      [bob, { cap: used.jws }, {}],
      [bob, { cap: makeCap(bob, r.nowSec(), { exp: r.nowSec() - 1, iat: r.nowSec() - DAY }).jws }, {}],
      [bob, { cap: "not-a-cap" }, {}],
      [ghost, { cap: makeCap(ghost, r.nowSec()).jws }, {}],
      [bob, {}, { kind: "msg" }],
    ];
    const replies = [];
    for (const [dest, extra, envOpts] of cases) {
      replies.push(await send(aliceC, alice, dest, { id: "same", ...extra }, envOpts));
    }
    for (const reply of replies) expect(reply).toEqual({ t: "error", id: "same", code: "undeliverable" });
  });

  it("a crypto-seam failure of any kind maps to undeliverable (test double)", async () => {
    await r.close();
    for (const code of ["bad-signature", "expired", "not-allowed", "malformed"] as const) {
      r = await startRelay({
        crypto: testRelayCrypto({
          verifyCapForSend: () => {
            throw new RelayCryptoError(code);
          },
        }),
      });
      alice = makeDevice(makeIdentity(), r.nowSec());
      bob = makeDevice(makeIdentity(), r.nowSec());
      aliceC = await authed(r, alice);
      await authed(r, bob);
      expect(await send(aliceC, alice, bob, { id: "x", cap: "anything" })).toEqual({ t: "error", id: "x", code: "undeliverable" });
      await r.close();
    }
    r = await startRelay();
  });
});
