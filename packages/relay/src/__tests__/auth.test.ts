// Copyright 2026 Ix Infrastructure Inc.
// §5.2 connection and authentication.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { b64uEncode, randomBytes } from "@peer2peer/core";
import { ed25519 } from "@noble/curves/ed25519.js";
import { helloMatchesDialled } from "../client.js";
import { CLOSE } from "../server.js";
import {
  authSig,
  crypto,
  DAY,
  makeCap,
  makeDevice,
  makeDoc,
  makeEnvelope,
  makeIdentity,
  RELAY_URL,
  signCert,
  startRelay,
  TestClient,
  type TestRelay,
} from "./helpers.js";

let r: TestRelay;
beforeEach(async () => {
  r = await startRelay();
});
afterEach(async () => {
  await r.close();
});

async function expectAuthFails(c: TestClient, frame: Record<string, unknown>): Promise<void> {
  const reply = c.next((f) => f.t === "error" || f.t === "ok");
  c.send(frame);
  expect(await reply).toEqual({ t: "error", code: "auth-failed" });
  expect(await c.closed).toBe(CLOSE.authFailed);
}

describe("hello", () => {
  it("names the canonical relay URL, a 32-byte nonce, pow and limits", async () => {
    const c = await TestClient.connect(r.url);
    expect(c.hello.t).toBe("hello");
    expect(c.hello.relay).toBe(RELAY_URL);
    expect(Buffer.from(c.hello.nonce, "base64url")).toHaveLength(32);
    expect(c.hello.pow).toBe(0);
    expect(c.hello.limits).toMatchObject({
      frameBytes: 96 * 1024,
      envelopeBytes: 64 * 1024,
      mailboxEnvelopes: 10_000,
      mailboxBytes: 64 * 1024 * 1024,
      retentionSec: 7 * DAY,
      sendsPerMinute: 120,
      contactPerSenderPerHour: 60,
      contactPerPairPerHour: 3,
      contactPerIpPerHour: 120,
    });
    const c2 = await TestClient.connect(r.url);
    expect(c2.hello.nonce).not.toBe(c.hello.nonce);
    await c.close();
    await c2.close();
  });

  it("client side: a hello.relay that differs from the dialled URL must make the client close (H5)", async () => {
    // The relay is configured as wss://relay.test/v3. A client that dialled a
    // different name must refuse to sign for it; one that dialled an
    // equivalent spelling of the same URL accepts.
    const c = await TestClient.connect(r.url);
    expect(helloMatchesDialled(crypto, "wss://relay.test/v3", c.hello.relay)).toBe(true);
    expect(helloMatchesDialled(crypto, "wss://RELAY.test:443/v3/", c.hello.relay)).toBe(true);
    expect(helloMatchesDialled(crypto, "wss://evil.test/v3", c.hello.relay)).toBe(false);
    expect(helloMatchesDialled(crypto, "wss://relay.test/v4", c.hello.relay)).toBe(false);
    expect(helloMatchesDialled(crypto, "wss://relay.test:8443/v3", c.hello.relay)).toBe(false);
    expect(helloMatchesDialled(crypto, "not a url", c.hello.relay)).toBe(false);
    await c.close();
  });
});

describe("auth", () => {
  it("binds the connection to (iss, did) and answers ok", async () => {
    const dev = makeDevice(makeIdentity(), r.nowSec());
    const c = await TestClient.connect(r.url);
    expect(await c.auth(dev)).toEqual({ t: "ok" });
    expect(r.store.deviceIssuer(dev.did)).toBe(dev.identity.userId);
    // A second auth on the same connection is refused, but doesn't close it.
    const again = c.next((f) => f.t === "error");
    c.send({ t: "auth", cert: dev.cert, sig: authSig(dev, RELAY_URL, c.hello.nonce) });
    expect(await again).toEqual({ t: "error", code: "bad-request" });
    await c.close();
  });

  it("rejects a signature over another relay's URL (relayed auth)", async () => {
    const dev = makeDevice(makeIdentity(), r.nowSec());
    const c = await TestClient.connect(r.url);
    await expectAuthFails(c, { t: "auth", cert: dev.cert, sig: authSig(dev, "wss://other.test/v3", c.hello.nonce) });
  });

  it("rejects a signature over another connection's nonce", async () => {
    const dev = makeDevice(makeIdentity(), r.nowSec());
    const other = await TestClient.connect(r.url);
    const c = await TestClient.connect(r.url);
    await expectAuthFails(c, { t: "auth", cert: dev.cert, sig: authSig(dev, RELAY_URL, other.hello.nonce) });
    await other.close();
  });

  it("rejects a signature by a key other than the certified spk", async () => {
    const dev = makeDevice(makeIdentity(), r.nowSec());
    const c = await TestClient.connect(r.url);
    const sig = Buffer.from(ed25519.sign(crypto.relayAuthMessage(RELAY_URL, c.hello.nonce), randomBytes(32))).toString("base64url");
    await expectAuthFails(c, { t: "auth", cert: dev.cert, sig });
  });

  it("rejects a forged certificate (signed by a key that isn't the cert's ik)", async () => {
    const victim = makeIdentity();
    const forger = makeIdentity();
    const dev = makeDevice(victim, r.nowSec(), { signWith: forger.ikSecret });
    const c = await TestClient.connect(r.url);
    await expectAuthFails(c, { t: "auth", cert: dev.cert, sig: authSig(dev, RELAY_URL, c.hello.nonce) });
  });

  it("rejects a certificate whose iss is not H(ik)", async () => {
    const id = makeIdentity();
    const dev = makeDevice(id, r.nowSec(), { iss: makeIdentity().userId });
    const c = await TestClient.connect(r.url);
    await expectAuthFails(c, { t: "auth", cert: dev.cert, sig: authSig(dev, RELAY_URL, c.hello.nonce) });
  });

  it("rejects did != H(spk)", async () => {
    const id = makeIdentity();
    const victim = makeDevice(id, r.nowSec());
    // A certificate that claims the victim's did over the attacker's own spk.
    const attacker = makeDevice(id, r.nowSec(), { did: victim.did });
    const c = await TestClient.connect(r.url);
    await expectAuthFails(c, { t: "auth", cert: attacker.cert, sig: authSig(attacker, RELAY_URL, c.hello.nonce) });
  });

  it("rejects expired and not-yet-valid certificates", async () => {
    const id = makeIdentity();
    const now = r.nowSec();
    const expired = makeDevice(id, now, { iat: now - 10 * DAY, exp: now - 1 });
    const future = makeDevice(id, now, { iat: now + 3600, exp: now + 30 * DAY });
    const tooLong = makeDevice(id, now, { iat: now - 60, exp: now + 91 * DAY });
    for (const dev of [expired, future, tooLong]) {
      const c = await TestClient.connect(r.url);
      await expectAuthFails(c, { t: "auth", cert: dev.cert, sig: authSig(dev, RELAY_URL, c.hello.nonce) });
    }
  });

  it("rejects malformed auth frames", async () => {
    const c = await TestClient.connect(r.url);
    await expectAuthFails(c, { t: "auth", cert: 42, sig: "x" });
    const c2 = await TestClient.connect(r.url);
    await expectAuthFails(c2, { t: "auth", cert: "not.a.jws", sig: "x" });
  });

  it("applies §2.3 rule 6 when the relay holds the issuer's identity document", async () => {
    const id = makeIdentity();
    const listed = makeDevice(id, r.nowSec());
    const unlisted = makeDevice(id, r.nowSec());
    const c = await TestClient.connect(r.url);
    expect(await c.auth(listed)).toEqual({ t: "ok" });
    const doc = makeDoc(id, r.nowSec(), { devices: [listed.did] });
    expect(await c.request({ t: "identity", doc: doc.jws })).toMatchObject({ t: "ok" });
    // An unlisted device gets a restricted connection: no mailbox, no frame but `identity`.
    const c2 = await TestClient.connect(r.url);
    expect(await c2.auth(unlisted)).toEqual({ t: "ok", restricted: true });
    for (const t of ["send", "ack", "revoke", "link-open"]) {
      expect(await c2.request({ t })).toMatchObject({ t: "error", code: "forbidden" });
    }
    const env = makeEnvelope(listed, { userId: id.userId, did: unlisted.did }, { nowMs: r.clock.t });
    expect(await c.request({ t: "send", to: id.userId, tdid: unlisted.did, env, cap: makeCap(listed, r.nowSec()).jws })).toMatchObject({ t: "error", code: "undeliverable" });
    expect(await c2.drainEnvs()).toEqual([]);
    await c.close();
    await c2.close();
  });

  it("lets a restricted device publish the version that lists it (§2.7 restore), then binds its mailbox", async () => {
    const id = makeIdentity();
    const old = makeDevice(id, r.nowSec());
    const restored = makeDevice(id, r.nowSec());
    const c = await TestClient.connect(r.url);
    await c.auth(old);
    const v1 = makeDoc(id, r.nowSec(), { devices: [old.did] });
    expect(await c.request({ t: "identity", doc: v1.jws })).toMatchObject({ t: "ok" });
    await c.close();
    const c2 = await TestClient.connect(r.url);
    expect(await c2.auth(restored)).toEqual({ t: "ok", restricted: true });
    const v2 = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [restored.did] });
    expect(await c2.request({ t: "identity", doc: v2.jws })).toMatchObject({ t: "ok" });
    // Now a full connection: it can revoke (any authenticated frame). The old device, which v2
    // dropped (revoked), is refused outright: not even a restricted connection (H1).
    expect(await c2.request({ t: "revoke", capid: b64uEncode(randomBytes(16)) })).toMatchObject({ t: "ok" });
    const c3 = await TestClient.connect(r.url);
    expect(await c3.auth(old)).toEqual({ t: "error", code: "auth-failed" });
    await c2.close();
  });

  it("refuses frames other than auth and link-put/get before auth", async () => {
    const c = await TestClient.connect(r.url);
    for (const t of ["send", "ack", "revoke", "identity", "link-open"]) {
      expect(await c.request({ t })).toMatchObject({ t: "error", code: "auth-required" });
    }
    await c.close();
  });
});

describe("mailbox squatting", () => {
  it("rejects a second iss for a did the relay already knows", async () => {
    const owner = makeIdentity();
    const dev = makeDevice(owner, r.nowSec());
    const c = await TestClient.connect(r.url);
    expect(await c.auth(dev)).toEqual({ t: "ok" });
    await c.close();

    // Same spk (so the same did), certified by a different identity. Even
    // holding the spk secret, nobody can move that did to another iss.
    const squatter = makeIdentity();
    const cert = signCert(squatter, dev.spk, dev.kpk, r.nowSec());
    const squat = { ...dev, identity: squatter, cert };
    const c2 = await TestClient.connect(r.url);
    await expectAuthFails(c2, { t: "auth", cert: squat.cert, sig: authSig(squat, RELAY_URL, c2.hello.nonce) });
    expect(r.store.deviceIssuer(dev.did)).toBe(owner.userId);

    // The rightful owner still gets in.
    const c3 = await TestClient.connect(r.url);
    expect(await c3.auth(dev)).toEqual({ t: "ok" });
    await c3.close();
  });
});
