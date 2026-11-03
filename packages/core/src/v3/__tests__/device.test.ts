// Copyright 2026 Ix Infrastructure Inc.
//
// §2.3 device certificates: rules 1–6, the 90-day lifetime, small-order keys,
// and review H4 (did/spk mismatch = mailbox squatting).

import { describe, expect, it } from "vitest";
import { createDeviceCert, generateDeviceKeysV3, verifyDeviceCertV3, certExpiresWithin } from "../device.js";
import { generateIdentityKey } from "../identity.js";
import { didFromSpk } from "../base.js";
import { b64uEncode } from "../../encoding.js";
import { decodeJws, signJws } from "../../jws.js";
import { DAYS, makeUser, NOW } from "./fixtures.js";

const SMALL_ORDER_ED = (() => {
  const b = new Uint8Array(32);
  b[0] = 1; // the identity point
  return b;
})();
const ZERO_X = new Uint8Array(32);

function forge(payload: Record<string, unknown>, sk: Uint8Array): string {
  return signJws("p2p-device+jws", "ik", payload, sk);
}

describe("§2.3 device certificate", () => {
  it("accepts a valid certificate (rules 1–5) and, with the document, rule 6", () => {
    const u = makeUser("alice");
    const c = verifyDeviceCertV3(u.dev.cert, { now: NOW });
    expect(c.iss).toBe(u.userId);
    expect(c.did).toBe(didFromSpk(u.dev.signingPublicKey));
    expect(c.label).toBe("alice-dev1");
    expect(verifyDeviceCertV3(u.dev.cert, { now: NOW, identityDoc: u.doc.jws }).did).toBe(u.dev.did);
    expect(verifyDeviceCertV3(u.dev.cert, { now: NOW, identityDoc: { iss: u.userId, devices: [u.dev.did] } }).did).toBe(u.dev.did);
  });

  it("rule 1: iss must be the fingerprint of ik", () => {
    const u = makeUser("alice");
    const p = decodeJws(u.dev.cert).payload;
    const other = generateIdentityKey();
    expect(() => verifyDeviceCertV3(forge({ ...p, iss: other.userId }, u.ik.secretKey), { now: NOW })).toThrow(/issuer-mismatch/);
  });

  it("rule 2: the JWS must verify under ik", () => {
    const u = makeUser("alice");
    const p = decodeJws(u.dev.cert).payload;
    const attacker = generateIdentityKey();
    expect(() => verifyDeviceCertV3(forge(p, attacker.secretKey), { now: NOW })).toThrow(/bad-signature/);
    expect(() => verifyDeviceCertV3(signJws("p2p-device+jws", "d_x", p, u.ik.secretKey), { now: NOW })).toThrow(/kid-mismatch/);
    expect(() => verifyDeviceCertV3(signJws("p2p-proof+jws", "ik", p, u.ik.secretKey), { now: NOW })).toThrow(/typ-mismatch/);
  });

  it("rule 3 (H4): a certificate claiming another device's did is rejected (mailbox squatting)", () => {
    const victim = makeUser("victim");
    const attacker = makeUser("mallory");
    const p = decodeJws(attacker.dev.cert).payload;
    // Mallory certifies her own spk under the victim's did.
    const squat = forge({ ...p, did: victim.dev.did }, attacker.ik.secretKey);
    expect(() => verifyDeviceCertV3(squat, { now: NOW })).toThrow(/did-mismatch/);
  });

  it("rule 4: small-order spk, kpk or ik are rejected", () => {
    const u = makeUser("alice");
    const p = decodeJws(u.dev.cert).payload;
    expect(() => verifyDeviceCertV3(forge({ ...p, spk: b64uEncode(SMALL_ORDER_ED), did: didFromSpk(SMALL_ORDER_ED) }, u.ik.secretKey), { now: NOW })).toThrow(
      /small-order-key/,
    );
    expect(() => verifyDeviceCertV3(forge({ ...p, kpk: b64uEncode(ZERO_X) }, u.ik.secretKey), { now: NOW })).toThrow(/small-order-key/);
    expect(() => verifyDeviceCertV3(forge({ ...p, ik: b64uEncode(SMALL_ORDER_ED) }, u.ik.secretKey), { now: NOW })).toThrow(/small-order-key/);
    expect(() => createDeviceCert(u.ik, { signingPublicKey: SMALL_ORDER_ED, agreementPublicKey: u.dev.agreementPublicKey })).toThrow(/small-order/);
  });

  it("rule 5: expiry, lifetime ≤ 90 days, and not issued in the future", () => {
    const u = makeUser("alice");
    const d = generateDeviceKeysV3(u.userId);
    const cert = createDeviceCert(u.ik, d, { iat: NOW - DAYS(10), ttlSec: DAYS(10) });
    expect(() => verifyDeviceCertV3(cert, { now: NOW })).toThrow(/expired/);
    expect(verifyDeviceCertV3(cert, { now: NOW - 1 }).did).toBe(d.did);
    expect(() => createDeviceCert(u.ik, d, { ttlSec: DAYS(91) })).toThrow(/90d/);
    const p = decodeJws(createDeviceCert(u.ik, d, { iat: NOW })).payload;
    expect(() => verifyDeviceCertV3(forge({ ...p, exp: NOW + DAYS(91) }, u.ik.secretKey), { now: NOW })).toThrow(/lifetime/);
    expect(() => verifyDeviceCertV3(forge({ ...p, iat: NOW + 3600, exp: NOW + 7200 }, u.ik.secretKey), { now: NOW })).toThrow(/not-yet-valid/);
    expect(certExpiresWithin(verifyDeviceCertV3(cert, { now: NOW - 10 }), DAYS(7), NOW - 10)).toBe(true);
  });

  it("rule 6: the did must be in the issuer's current document (the allowlist)", () => {
    const u = makeUser("alice");
    const second = u.addDevice({ keyholder: false });
    // Version 1 does not list the second device.
    expect(() => verifyDeviceCertV3(second.cert, { now: NOW, identityDoc: u.doc.jws })).toThrow(/device-not-listed/);
    u.publish();
    expect(verifyDeviceCertV3(second.cert, { now: NOW, identityDoc: u.doc.jws }).did).toBe(second.did);
    // A document of another identity is no allowlist for this one.
    const other = makeUser("bob");
    expect(() => verifyDeviceCertV3(u.dev.cert, { now: NOW, identityDoc: other.doc.jws })).toThrow(/issuer-mismatch/);
    expect(() => verifyDeviceCertV3(u.dev.cert, { now: NOW, identityDoc: { iss: u.userId, ik: other.doc.ik, devices: [u.dev.did] } })).toThrow(/issuer-mismatch/);
  });

  it("a revoked device fails rule 6 after a document update", () => {
    const u = makeUser("alice");
    const laptop = u.addDevice({ keyholder: false });
    u.publish();
    expect(verifyDeviceCertV3(laptop.cert, { now: NOW, identityDoc: u.doc.jws }).did).toBe(laptop.did);
    u.publish({ devices: [u.dev.did] }); // revoke the laptop
    expect(() => verifyDeviceCertV3(laptop.cert, { now: NOW, identityDoc: u.doc.jws })).toThrow(/device-not-listed/);
    // Its certificate is otherwise still fine (rules 1–5): relays without the document still authenticate it.
    expect(verifyDeviceCertV3(laptop.cert, { now: NOW }).did).toBe(laptop.did);
  });

  it("rejects unknown fields and malformed ids", () => {
    const u = makeUser("alice");
    const p = decodeJws(u.dev.cert).payload;
    // Forward compatibility: an unknown field is ignored (never copied), unless the cert lists it in `crit`.
    expect(verifyDeviceCertV3(forge({ ...p, extra: 1 }, u.ik.secretKey), { now: NOW })).not.toHaveProperty("extra");
    expect(() => verifyDeviceCertV3(forge({ ...p, extra: 1, crit: ["extra"] }, u.ik.secretKey), { now: NOW })).toThrow(/critical/);
    expect(() => verifyDeviceCertV3(forge({ ...p, did: "d_AAAA" }, u.ik.secretKey), { now: NOW })).toThrow(/malformed/);
  });
});
