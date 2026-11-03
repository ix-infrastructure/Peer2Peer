// Copyright 2026 Ix Infrastructure Inc.
//
// §2.8 identity rotation at the relay. No new endpoint or rule: the relay
// accepts the old identity's final version, which carries `rotation` and
// lists no devices, through core's document validation (P3), and then:
//  - the old allowlist is empty, so live connections of the old devices are
//    closed and the old dids are refused, even a restricted connection (the
//    held-state rule, through the 91-day seen window once history is gone);
//  - nothing may chain onto the final version (P3: it is terminal);
//  - mail queued for an old device is not delivered and expires normally.

import { afterEach, describe, expect, it } from "vitest";
import { b64uEncode, signJws } from "@peer2peer/core";
import { createRotation, identityKeyFromSeed, MAX_JWS_BYTES } from "@peer2peer/core/v3";
import { jwsHash, TYP_IDENTITY } from "../crypto.js";
import { authed, DAY, makeDevice, makeDoc, makeEnvelope, makeIdentity, RELAY_URL, startRelay, TestClient, type Identity, type TestRelay } from "./helpers.js";

let r: TestRelay;
afterEach(async () => {
  await r?.close();
});

function finalDoc(id: Identity, next: Identity, prev: string, ver: number, nowSec: number, o: { devices?: string[]; by?: string } = {}) {
  const rotation = createRotation(identityKeyFromSeed(id.ikSecret), identityKeyFromSeed(next.ikSecret), { iat: nowSec - 30 });
  const payload = {
    iss: id.userId,
    ik: b64uEncode(id.ik),
    ver,
    prev,
    name: "tester",
    relays: [RELAY_URL],
    devices: o.devices ?? [],
    keyholders: [],
    by: o.by ?? "d_aaaaaaaaaaaaaaaaaaaaaaaaaa",
    rotation,
    iat: nowSec - 20,
    exp: nowSec - 20 + 29 * DAY,
  };
  const jws = signJws(TYP_IDENTITY, "ik", payload, id.ikSecret);
  return { jws, hash: jwsHash(jws) };
}

async function rotatedSetup() {
  const id = makeIdentity();
  const next = makeIdentity();
  const a = makeDevice(id, r.nowSec());
  const b = makeDevice(id, r.nowSec());
  const ac = await authed(r, a);
  const v1 = makeDoc(id, r.nowSec(), { devices: [a.did, b.did], keyholders: [a.did] });
  expect(await ac.request({ t: "identity", doc: v1.jws })).toMatchObject({ t: "ok" });
  const bc = await authed(r, b);
  return { id, next, a, b, ac, bc, v1 };
}

describe("§2.8 the old identity's final version at the relay", () => {
  it("is accepted (core validation knows `rotation`) and fits the size caps", async () => {
    r = await startRelay();
    const { id, next, ac, v1 } = await rotatedSetup();
    const fin = finalDoc(id, next, v1.hash, 2, r.nowSec(), { by: "d_bbbbbbbbbbbbbbbbbbbbbbbbbb" });
    expect(fin.jws.length).toBeLessThan(MAX_JWS_BYTES);
    expect(await ac.request({ t: "identity", doc: fin.jws })).toMatchObject({ t: "ok" });
    // Served as the head, so friends refreshing every 10 minutes find the rotation.
    expect(r.relay.identity.head(id.userId)?.hash).toBe(fin.hash);
    const res = await fetch(`${r.http}/v3/identity/${id.userId}`);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(fin.jws);
  });

  it("refuses a rotation on a version that still lists devices", async () => {
    r = await startRelay();
    const { id, next, a, ac, v1 } = await rotatedSetup();
    const bad = finalDoc(id, next, v1.hash, 2, r.nowSec(), { devices: [a.did], by: a.did });
    expect(await ac.request({ t: "identity", doc: bad.jws })).toMatchObject({ t: "error", code: "bad-identity" });
  });

  it("empties the allowlist: live old connections close, old dids are refused, even restricted", async () => {
    r = await startRelay();
    const { id, next, a, b, ac, bc, v1 } = await rotatedSetup();
    const fin = finalDoc(id, next, v1.hash, 2, r.nowSec());
    expect(await ac.request({ t: "identity", doc: fin.jws })).toMatchObject({ t: "ok" });
    expect(await bc.closed).toBe(4001);
    expect(await ac.closed).toBe(4001);
    for (const d of [a, b]) {
      const c = await TestClient.connect(r.url);
      expect(await c.auth(d)).toMatchObject({ t: "error", code: "auth-failed" });
      await c.close();
    }
    // A brand-new did under the old identity gets only a restricted connection, and the
    // only version it could publish on top of the final one is refused (terminal).
    const thief = makeDevice(id, r.nowSec());
    const tc = await TestClient.connect(r.url);
    expect(await tc.auth(thief)).toEqual({ t: "ok", restricted: true });
    const child = makeDoc(id, r.nowSec(), { ver: 3, prev: fin.hash, devices: [thief.did] });
    expect(await tc.request({ t: "identity", doc: child.jws })).toMatchObject({ t: "error" });
    await tc.close();
  });

  it("refuses old dids for the seen window once the history is gone (tombstone)", async () => {
    r = await startRelay();
    const { id, next, a, ac, v1 } = await rotatedSetup();
    const fin = finalDoc(id, next, v1.hash, 2, r.nowSec());
    expect(await ac.request({ t: "identity", doc: fin.jws })).toMatchObject({ t: "ok" });
    // The head expires (29 days) and, 90 days later, the history is swept into a tombstone.
    r.clock.advance(121 * DAY * 1000);
    await r.relay.sweep();
    expect(r.relay.identity.status(id.userId)).toMatchObject({ left: true });
    const c = await TestClient.connect(r.url);
    expect((await c.auth(makeDevice(id, r.nowSec(), {}, a.spkSecret))).t).toBe("error");
    await c.close();
  });

  it("mail queued for an old device is never delivered after the final version", async () => {
    r = await startRelay();
    const { id, next, b, ac, bc, v1 } = await rotatedSetup();
    await bc.close();
    // A friend with a cap from b queues mail for b.
    const friendId = makeIdentity();
    const friend = makeDevice(friendId, r.nowSec());
    const fc = await authed(r, friend);
    const fdoc = makeDoc(friendId, r.nowSec(), { devices: [friend.did] });
    expect(await fc.request({ t: "identity", doc: fdoc.jws })).toMatchObject({ t: "ok" });
    const env = makeEnvelope(friend, { userId: id.userId, did: b.did }, { kind: "contact" });
    expect(await fc.request({ t: "send", id: "1", to: id.userId, tdid: b.did, env })).toMatchObject({ t: "sent" });
    const fin = finalDoc(id, next, v1.hash, 2, r.nowSec());
    expect(await ac.request({ t: "identity", doc: fin.jws })).toMatchObject({ t: "ok" });
    // b can't connect to collect it; a fresh send to an old device is undeliverable.
    const c = await TestClient.connect(r.url);
    expect((await c.auth(b)).t).toBe("error");
    await c.close();
    const env2 = makeEnvelope(friend, { userId: id.userId, did: b.did }, { kind: "contact" });
    const queued = r.store.counts().envelopes;
    // Answered `sent` and dropped (§5.4: nothing reveals whether a mailbox exists).
    const sent = await fc.request({ t: "send", id: "2", to: id.userId, tdid: b.did, env: env2 });
    expect(sent).toMatchObject({ t: "sent" });
    expect(r.store.counts().envelopes).toBe(queued);
    // What was queued before expires with the normal 7-day store.
    r.clock.advance(8 * DAY * 1000);
    await r.relay.sweep();
    expect(r.store.counts().envelopes).toBe(0);
    await fc.close();
  });
});
