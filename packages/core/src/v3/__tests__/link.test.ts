// Copyright 2026 Ix Infrastructure Inc.
//
// §2.4 device linking: the link code, lid, the length-prefixed request MAC,
// the compare code, more-than-one-request abort, and the sealed response.

import { describe, expect, it } from "vitest";
import {
  createLinkRequest,
  encodeLinkCode,
  linkCompareCode,
  linkExpired,
  linkId,
  linkRequestMac,
  lp,
  newLinkSecret,
  openLinkResponse,
  parseLinkCode,
  sealLinkResponse,
  selectLinkRequest,
  verifyLinkRequest,
} from "../link.js";
import { createDeviceCert, generateDeviceKeysV3 } from "../device.js";
import { b64uEncode } from "../../encoding.js";
import { randomBytes, x25519PublicKey } from "../../crypto.js";
import { makeUser, NOW } from "./fixtures.js";

function newDevice(userId = "p2p:" + "a".repeat(52)) {
  const keys = generateDeviceKeysV3(userId);
  const xSecret = randomBytes(32);
  return { keys, xSecret, x: x25519PublicKey(xSecret) };
}

describe("§2.4 link code and lid", () => {
  it("encodes p2p-link:<b32(s)>@<relay without wss://> and parses back", () => {
    const s = newLinkSecret();
    const code = encodeLinkCode(s, "wss://Relay.Example:443/v3/");
    expect(code).toMatch(/^p2p-link:[a-z2-7]{26}@relay\.example\/v3$/);
    const parsed = parseLinkCode(code);
    expect(parsed.secret).toEqual(s);
    expect(parsed.relay).toBe("wss://relay.example/v3");
    expect(parseLinkCode(encodeLinkCode(s, "wss://r.example:8443/p")).relay).toBe("wss://r.example:8443/p");
    expect(() => parseLinkCode("p2p-link:abc@x")).toThrow(/malformed/);
    expect(linkId(s)).toMatch(/^[a-z2-7]{26}$/);
    expect(linkId(s)).not.toBe(linkId(newLinkSecret()));
  });

  it("expires after 10 minutes", () => {
    expect(linkExpired(NOW, NOW + 599)).toBe(false);
    expect(linkExpired(NOW, NOW + 600)).toBe(true);
  });

  it("lp is a 4-byte big-endian length of the UTF-8 bytes, then the bytes", () => {
    expect([...lp("é")]).toEqual([0, 0, 0, 2, 0xc3, 0xa9]);
  });
});

describe("§2.4 request", () => {
  it("verifies the MAC; both devices show the same compare code", () => {
    const s = newLinkSecret();
    const nd = newDevice();
    const req = createLinkRequest(s, nd.keys, nd.x, "Work laptop");
    const v = verifyLinkRequest(s, req);
    expect(v.did).toBe(nd.keys.did);
    expect(v.compareCode).toBe(linkCompareCode(s, nd.keys.did));
    expect(v.compareCode).toMatch(/^[a-z2-7]{8}$/);
  });

  it("an eavesdropper without s can't forge a request; tampering breaks the MAC", () => {
    const s = newLinkSecret();
    const nd = newDevice();
    const req = createLinkRequest(s, nd.keys, nd.x, "laptop");
    expect(() => verifyLinkRequest(newLinkSecret(), req)).toThrow(/link-mac-invalid/);
    const evil = newDevice();
    expect(() => verifyLinkRequest(s, { ...req, x: b64uEncode(evil.x) })).toThrow(/link-mac-invalid/);
    expect(() => verifyLinkRequest(s, { ...req, label: "laptoP" })).toThrow(/link-mac-invalid/);
    // Field boundaries are length-prefixed: shifting bytes between fields changes the MAC input.
    expect(() => verifyLinkRequest(s, { ...req, label: "", mac: req.mac })).toThrow(/link-mac-invalid/);
  });

  it("a request whose did does not derive from spk is rejected even with a valid MAC", () => {
    const s = newLinkSecret();
    const nd = newDevice();
    const other = newDevice();
    const req = createLinkRequest(s, nd.keys, nd.x, "x");
    // Re-MAC with a wrong did (the holder of s is the only one who can, but the did check still applies).
    const { mac: _m, ...rest } = req;
    const bad = { ...rest, did: other.keys.did };
    expect(() => verifyLinkRequest(s, { ...bad, mac: b64uEncode(linkRequestMac(s, bad)) })).toThrow(/did-mismatch/);
  });

  it("aborts when more than one valid request arrives; ignores junk", () => {
    const s = newLinkSecret();
    const a = newDevice();
    const b = newDevice();
    const ra = createLinkRequest(s, a.keys, a.x, "a");
    const rb = createLinkRequest(s, b.keys, b.x, "b");
    const junk = createLinkRequest(newLinkSecret(), b.keys, b.x, "junk");
    expect(selectLinkRequest(s, [JSON.stringify(ra), junk, "not json"])?.did).toBe(a.keys.did);
    expect(selectLinkRequest(s, [ra, ra])?.did).toBe(a.keys.did);
    expect(() => selectLinkRequest(s, [ra, rb])).toThrow(/link-multiple-requests/);
    expect(selectLinkRequest(s, [])).toBeUndefined();
  });
});

describe("§2.4 response", () => {
  function linked(keyHolding: boolean) {
    const owner = makeUser("alice");
    const s = newLinkSecret();
    const nd = newDevice(owner.userId);
    const req = verifyLinkRequest(s, createLinkRequest(s, nd.keys, nd.x, "phone"));
    const cert = createDeviceCert(owner.ik, { signingPublicKey: req.signingPublicKey, agreementPublicKey: req.agreementPublicKey, label: req.label }, { iat: NOW - 10 });
    owner.devices.push({ ...nd.keys, cert, label: "phone" });
    if (keyHolding) owner.keyholders.push(nd.keys.did);
    const doc = owner.publish();
    const frame = sealLinkResponse(s, req, { cert, doc: doc.jws, ...(keyHolding ? { ik: b64uEncode(owner.ik.secretKey) } : {}) }, owner.dev);
    return { owner, s, nd, frame, doc };
  }

  it("the new device opens the bundle and checks it is for its own keys", () => {
    const { s, nd, frame, owner } = linked(false);
    const r = openLinkResponse(s, nd.keys, nd.xSecret, frame, { now: NOW });
    expect(r.cert.did).toBe(nd.keys.did);
    expect(r.doc.iss).toBe(owner.userId);
    expect(r.ik).toBeUndefined();
  });

  it("carries ik_secret only for a key-holding device", () => {
    const { s, nd, frame, owner } = linked(true);
    const r = openLinkResponse(s, nd.keys, nd.xSecret, frame, { now: NOW });
    expect(r.ik?.userId).toBe(owner.userId);
  });

  it("a relay without s can't substitute its own response", () => {
    const { s, nd, frame } = linked(false);
    // The relay knows lid and x but not s: a bundle sealed under another secret fails.
    const attacker = makeUser("mallory");
    const fakeS = newLinkSecret();
    const fakeReq = verifyLinkRequest(fakeS, createLinkRequest(fakeS, nd.keys, nd.x, "phone"));
    const cert = createDeviceCert(attacker.ik, nd.keys, { iat: NOW - 10 });
    attacker.devices.push({ ...nd.keys, cert, label: "phone" });
    const doc = attacker.publish();
    const forged = sealLinkResponse(fakeS, fakeReq, { cert, doc: doc.jws }, attacker.dev);
    expect(() => openLinkResponse(s, nd.keys, nd.xSecret, forged, { now: NOW })).toThrow(/decrypt-failed/);
    // Tampering with the frame fails too.
    expect(() => openLinkResponse(s, nd.keys, nd.xSecret, { ...frame, fkpk: b64uEncode(x25519PublicKey(randomBytes(32))) }, { now: NOW })).toThrow(
      /decrypt-failed/,
    );
  });

  it("rejects a bundle whose certificate is for another device", () => {
    const owner = makeUser("alice");
    const s = newLinkSecret();
    const nd = newDevice(owner.userId);
    const req = verifyLinkRequest(s, createLinkRequest(s, nd.keys, nd.x, "phone"));
    // The bundle carries the owner's own first device cert.
    const frame = sealLinkResponse(s, req, { cert: owner.dev.cert, doc: owner.doc.jws }, owner.dev);
    expect(() => openLinkResponse(s, nd.keys, nd.xSecret, frame, { now: NOW })).toThrow(/did-mismatch/);
  });
});
