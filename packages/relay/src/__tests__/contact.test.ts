// Copyright 2026 Ix Infrastructure Inc.
// §5.4 step 4 and §5.5: cap-less contact limits (per sender, per pair, per
// IP) and proof-of-work.

import { afterEach, describe, expect, it } from "vitest";
import { authed, makeDevice, makeEnvelope, makeIdentity, solvePow, startRelay, TestClient, type Device, type TestRelay } from "./helpers.js";

let r: TestRelay;
afterEach(async () => {
  await r.close();
});

const contact = (c: TestClient, from: Device, dest: Device, extra: Record<string, unknown> = {}) =>
  c.request({
    t: "send",
    to: dest.identity.userId,
    tdid: dest.did,
    env: makeEnvelope(from, { userId: dest.identity.userId, did: dest.did }, { kind: "contact" }),
    ...extra,
  });

async function setup(limits: Record<string, number>, powBits = 0) {
  r = await startRelay({ limits, config: { powBits } });
}

describe("contact rate limits", () => {
  it("per (sender, recipient) pair: 3/h by default", async () => {
    await setup({});
    const alice = makeDevice(makeIdentity(), r.nowSec());
    const bob = makeDevice(makeIdentity(), r.nowSec());
    const carol = makeDevice(makeIdentity(), r.nowSec());
    const ac = await authed(r, alice);
    await authed(r, bob);
    await authed(r, carol);
    for (let i = 0; i < 3; i++) expect(await contact(ac, alice, bob)).toMatchObject({ t: "sent" });
    expect(await contact(ac, alice, bob)).toMatchObject({ t: "error", code: "rate-limited" });
    // Another recipient is a different pair.
    expect(await contact(ac, alice, carol)).toMatchObject({ t: "sent" });
    // Refills over the hour.
    r.clock.advance(20 * 60_000);
    expect(await contact(ac, alice, bob)).toMatchObject({ t: "sent" });
  });

  it("per sender userId across recipients", async () => {
    await setup({ contactPerSenderPerHour: 2, contactPerPairPerHour: 10 });
    const alice = makeDevice(makeIdentity(), r.nowSec());
    const ac = await authed(r, alice);
    const targets = [0, 1, 2].map(() => makeDevice(makeIdentity(), r.nowSec()));
    expect(await contact(ac, alice, targets[0])).toMatchObject({ t: "sent" });
    expect(await contact(ac, alice, targets[1])).toMatchObject({ t: "sent" });
    expect(await contact(ac, alice, targets[2])).toMatchObject({ code: "rate-limited" });
    // A second device of the same user shares the sender limit.
    const alice2 = makeDevice(alice.identity, r.nowSec());
    const a2c = await authed(r, alice2);
    expect(await contact(a2c, alice2, targets[2])).toMatchObject({ code: "rate-limited" });
  });

  it("per source IP across senders (cheap identities)", async () => {
    await setup({ contactPerIpPerHour: 2, contactPerSenderPerHour: 10 });
    const target = makeDevice(makeIdentity(), r.nowSec());
    const replies = [];
    for (let i = 0; i < 3; i++) {
      const sock = makeDevice(makeIdentity(), r.nowSec());
      replies.push(await contact(await authed(r, sock), sock, target));
    }
    expect(replies.map((x) => x.t === "sent" ? "sent" : x.code)).toEqual(["sent", "sent", "rate-limited"]);
  });

  it("uses X-Forwarded-For only when trustProxy is set", async () => {
    r = await startRelay({ limits: { contactPerIpPerHour: 1, contactPerSenderPerHour: 10 }, config: { trustProxy: 1 } });
    const target = makeDevice(makeIdentity(), r.nowSec());
    const viaProxy = async (ip: string) => {
      const d = makeDevice(makeIdentity(), r.nowSec());
      const c = await TestClient.connect(r.url, { "x-forwarded-for": `198.51.100.7, ${ip}` });
      expect(await c.auth(d)).toEqual({ t: "ok" });
      return contact(c, d, target);
    };
    expect(await viaProxy("203.0.113.1")).toMatchObject({ t: "sent" });
    expect(await viaProxy("203.0.113.2")).toMatchObject({ t: "sent" });
    expect(await viaProxy("203.0.113.1")).toMatchObject({ code: "rate-limited" });
  });

  it("caps are not subject to the contact limits", async () => {
    await setup({ contactPerPairPerHour: 1 });
    const { makeCap } = await import("./helpers.js");
    const alice = makeDevice(makeIdentity(), r.nowSec());
    const bob = makeDevice(makeIdentity(), r.nowSec());
    const ac = await authed(r, alice);
    await authed(r, bob);
    const cap = makeCap(bob, r.nowSec(), { sub: alice.identity.userId, kinds: ["contact"] });
    for (let i = 0; i < 4; i++) expect(await contact(ac, alice, bob, { cap: cap.jws })).toMatchObject({ t: "sent" });
  });
});

describe("proof-of-work", () => {
  it("is advertised in hello and required on cap-less contacts", async () => {
    await setup({}, 8);
    const alice = makeDevice(makeIdentity(), r.nowSec());
    const bob = makeDevice(makeIdentity(), r.nowSec());
    const ac = await authed(r, alice);
    const bc = await authed(r, bob);
    expect(ac.hello.pow).toBe(8);

    expect(await contact(ac, alice, bob)).toMatchObject({ code: "undeliverable" });
    expect(await contact(ac, alice, bob, { pow: "!!" })).toMatchObject({ code: "undeliverable" });

    const env = makeEnvelope(alice, { userId: bob.identity.userId, did: bob.did }, { kind: "contact" });
    const nonce = solvePow(env, 8);
    const ok = await ac.request({ t: "send", to: bob.identity.userId, tdid: bob.did, env, pow: nonce });
    expect(ok).toMatchObject({ t: "sent" });
    expect((await bc.next((f) => f.t === "env")).env).toBe(env);

    // A nonce solved for a different envelope doesn't carry over (almost surely).
    const env2 = makeEnvelope(alice, { userId: bob.identity.userId, did: bob.did }, { kind: "contact" });
    const { crypto } = await import("./helpers.js");
    if (!crypto.powOk(new TextEncoder().encode(env2), Buffer.from(nonce, "base64url"), 8)) {
      expect(await ac.request({ t: "send", to: bob.identity.userId, tdid: bob.did, env: env2, pow: nonce })).toMatchObject({
        code: "undeliverable",
      });
    }
  });

  it("is not required with a cap", async () => {
    await setup({}, 12);
    const { makeCap } = await import("./helpers.js");
    const alice = makeDevice(makeIdentity(), r.nowSec());
    const bob = makeDevice(makeIdentity(), r.nowSec());
    const ac = await authed(r, alice);
    await authed(r, bob);
    expect(await contact(ac, alice, bob, { cap: makeCap(bob, r.nowSec()).jws })).toMatchObject({ t: "sent" });
  });

  it("a PoW failure to an unknown mailbox looks the same as to a known one", async () => {
    await setup({}, 8);
    const alice = makeDevice(makeIdentity(), r.nowSec());
    const bob = makeDevice(makeIdentity(), r.nowSec());
    const ghost = makeDevice(makeIdentity(), r.nowSec());
    const ac = await authed(r, alice);
    await authed(r, bob);
    expect(await contact(ac, alice, bob, { id: "p" })).toEqual({ t: "error", id: "p", code: "undeliverable" });
    expect(await contact(ac, alice, ghost, { id: "p" })).toEqual({ t: "error", id: "p", code: "undeliverable" });
  });
});
