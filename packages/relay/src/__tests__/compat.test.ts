// Copyright 2026 Ix Infrastructure Inc.
//
// Forward compatibility at the relay (docs/compatibility.md): /.well-known/p2p-relay.json lists the
// frames and features, and the relay's own parsers (envelope, device cert, cap) ignore fields they
// don't know unless the object lists them in `crit`, which it then refuses.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { RELAY_FEATURES, RELAY_FRAMES, RELAY_PROTOCOL_MINOR } from "../server.js";
import { RelayCryptoError, relayCritCheck } from "../crypto.js";
import { authed, makeCap, makeDevice, makeEnvelope, makeIdentity, startRelay, type Device, type TestClient, type TestRelay } from "./helpers.js";

let r: TestRelay;
let alice: Device;
let bob: Device;
let aliceC: TestClient;

const to = (d: Device) => ({ userId: d.identity.userId, did: d.did });

beforeEach(async () => {
  r = await startRelay();
  alice = makeDevice(makeIdentity(), r.nowSec());
  bob = makeDevice(makeIdentity(), r.nowSec());
  aliceC = await authed(r, alice);
  await authed(r, bob);
});
afterEach(async () => {
  await r.close();
});

describe("relay forward compatibility", () => {
  it("relayCritCheck: core's crit shape, own fields only, an unknown critical field is unsupported-critical", () => {
    const code = (f: () => void) => {
      try {
        f();
        return "ok";
      } catch (e) {
        return (e as RelayCryptoError).code;
      }
    };
    const known = ["a", "b"];
    expect(code(() => relayCritCheck({ a: 1, later: 2 }, known, "x"))).toBe("ok");
    expect(code(() => relayCritCheck({ a: 1, crit: ["a"] }, known, "x"))).toBe("ok");
    expect(code(() => relayCritCheck({ a: 1, later: 2, crit: ["later"] }, known, "x"))).toBe("unsupported-critical");
    for (const crit of [[], "a", ["a", "a"], [1], ["crit"], ["b"], ["toString"], ["bad name"], Array.from({ length: 17 }, (_, i) => `f${i}`)]) {
      expect(code(() => relayCritCheck({ a: 1, crit }, known, "x")), JSON.stringify(crit)).toBe("malformed");
    }
    // `crit` inherited from a prototype is not the object's own: ignored.
    expect(code(() => relayCritCheck(Object.create({ crit: ["later"] }) as Record<string, unknown>, known, "x"))).toBe("ok");
  });

  it("/.well-known/p2p-relay.json lists its protocol minor, frames and features", async () => {
    const info = await (await fetch(`${r.http}/.well-known/p2p-relay.json`)).json();
    expect(info).toMatchObject({ protocol: "p2p/v3", protocolMinor: RELAY_PROTOCOL_MINOR, frames: [...RELAY_FRAMES], features: [...RELAY_FEATURES] });
    expect(info.features).toEqual(expect.arrayContaining(["identity.lenient", "envelope.lenient", "members"]));
    // The members-only relay's own fields sit beside them: a client that doesn't know them ignores them.
    expect(info.access).toBe("open");
    expect(info.frames).toContain("circle-put");
  });

  it("every frame it lists is one it answers; one it doesn't list is refused as unknown", async () => {
    const unknown = () => r.relay.metrics.get("frames_rejected", { reason: "unknown-type" });
    await aliceC.request({ t: "not-a-frame" });
    expect(unknown()).toBe(1);
    // Each listed frame reaches its handler (malformed without arguments, but never the unknown-frame path).
    for (const t of RELAY_FRAMES.filter((f) => f !== "auth")) await aliceC.request({ t }).catch(() => undefined);
    expect(unknown()).toBe(1);
  });

  it("an envelope of a kind it doesn't know, with an unknown outer field, is relayed; an unknown critical field is refused", async () => {
    const cap = makeCap(bob, r.nowSec(), { sub: alice.identity.userId });
    const send = (env: string) => aliceC.request({ t: "send", to: bob.identity.userId, tdid: bob.did, env, cap: cap.jws });
    expect(await send(makeEnvelope(alice, to(bob), { kind: "futurekind", overrides: { later: 1 } }))).toMatchObject({ t: "sent" });
    expect(await send(makeEnvelope(alice, to(bob), { overrides: { later: 1, crit: ["later"] } }))).toMatchObject({ t: "error" });
  });

  it("a cap or device cert with an unknown field is honoured; listed as critical, refused", async () => {
    const send = (capJws: string, from = alice) => aliceC.request({ t: "send", to: bob.identity.userId, tdid: bob.did, env: makeEnvelope(from, to(bob)), cap: capJws });
    expect(await send(makeCap(bob, r.nowSec(), { sub: alice.identity.userId, extra: { later: 1 } }).jws)).toMatchObject({ t: "sent" });
    // A future restricting field the relay can't enforce: the cap must not count as unrestricted.
    expect(await send(makeCap(bob, r.nowSec(), { sub: alice.identity.userId, extra: { maxBytes: 10, crit: ["maxBytes"] } }).jws)).toMatchObject({ t: "error", code: "undeliverable" });
    const bob2 = makeDevice(bob.identity, r.nowSec(), { extra: { hint: "x", crit: ["hint"] } });
    expect(await send(makeCap(bob2, r.nowSec(), { sub: alice.identity.userId }).jws)).toMatchObject({ t: "error", code: "undeliverable" });
  });
});
