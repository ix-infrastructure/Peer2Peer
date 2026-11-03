// Copyright 2026 Ix Infrastructure Inc.
//
// §5 relay-facing helpers: canonical URLs, relay auth (review H5), mailbox
// capabilities (§5.3, review M4), outer-envelope checks without opening,
// proof-of-work, and identity-document links for the relay store (§5.6).

import { describe, expect, it } from "vitest";
import {
  canonicalRelayUrl,
  checkHelloRelay,
  docListsRelay,
  leadingZeroBits,
  parseOuterEnvelope,
  powOk,
  relayAuthMessage,
  signRelayAuth,
  solvePow,
  verifyCapForSend,
  verifyDeviceCertV3,
  verifyIdentityDocLink,
  verifyOuterEnvelope,
  verifyRelayAuth,
} from "../index.js";
import { createCap, verifyCap } from "../caps.js";
import { parsePlaintextV3 } from "../envelope.js";
import { decodeJws, signJws } from "../../jws.js";
import { utf8 } from "../../encoding.js";
import { DAYS, makeUser, NOW, NOW_MS, RELAY, RELAY2, seal } from "./fixtures.js";

describe("§5.1 canonical relay URL", () => {
  it("lowercases, IDNA-encodes, drops :443 and trailing /, defaults the path to /v3", () => {
    expect(canonicalRelayUrl("wss://Relay.Example")).toBe("wss://relay.example/v3");
    expect(canonicalRelayUrl("wss://relay.example:443/")).toBe("wss://relay.example/v3");
    expect(canonicalRelayUrl("wss://relay.example:8443/custom/")).toBe("wss://relay.example:8443/custom");
    expect(canonicalRelayUrl("wss://bücher.example/v3")).toBe("wss://xn--bcher-kva.example/v3");
    expect(canonicalRelayUrl(canonicalRelayUrl("wss://A.example//"))).toBe(canonicalRelayUrl("wss://A.example//"));
  });

  it("rejects other schemes, query, fragment and userinfo", () => {
    for (const bad of ["ws://relay.example/v3", "https://relay.example", "wss://relay.example/v3?x=1", "wss://relay.example/v3#f", "wss://u:p@relay.example", "relay.example", ""]) {
      expect(() => canonicalRelayUrl(bad)).toThrow(/bad-relay-url/);
    }
  });
});

describe("§5.2 relay authentication", () => {
  it("accepts a device's signature over this relay's URL and nonce; binds (iss, did)", () => {
    const u = makeUser("alice");
    const nonce = "n0nce";
    const sig = signRelayAuth(RELAY, nonce, u.dev.signingSecretKey);
    const cert = verifyRelayAuth({ cert: u.dev.cert, sig, relay: RELAY, nonce, now: NOW });
    expect([cert.iss, cert.did]).toEqual([u.userId, u.dev.did]);
    expect(new TextDecoder().decode(relayAuthMessage(RELAY, nonce))).toBe(`p2p/v3/relay-auth|${RELAY}|n0nce`);
    // With the document, rule 6 applies too.
    expect(verifyRelayAuth({ cert: u.dev.cert, sig, relay: RELAY, nonce, now: NOW, identityDoc: u.doc.jws }).did).toBe(u.dev.did);
  });

  it("H5: a signature made for another relay (or nonce) doesn't authenticate here", () => {
    const u = makeUser("alice");
    const sig = signRelayAuth(RELAY2, "n", u.dev.signingSecretKey);
    expect(() => verifyRelayAuth({ cert: u.dev.cert, sig, relay: RELAY, nonce: "n", now: NOW })).toThrow(/bad-signature/);
    const sig2 = signRelayAuth(RELAY, "n1", u.dev.signingSecretKey);
    expect(() => verifyRelayAuth({ cert: u.dev.cert, sig: sig2, relay: RELAY, nonce: "n2", now: NOW })).toThrow(/bad-signature/);
    expect(() => verifyRelayAuth({ cert: u.dev.cert, sig: "short", relay: RELAY, nonce: "n", now: NOW })).toThrow(/bad-signature/);
  });

  it("H5: the client closes when hello.relay differs from the URL it dialled", () => {
    expect(checkHelloRelay(RELAY, "wss://RELAY.example:443/v3/")).toBe(RELAY);
    expect(() => checkHelloRelay(RELAY2, RELAY)).toThrow(/relay-mismatch/);
    expect(() => checkHelloRelay("wss://relay.example/v3/", RELAY)).toThrow(/relay-mismatch/);
  });

  it("H4: a device can't authenticate as another device's mailbox", () => {
    const victim = makeUser("victim");
    const mallory = makeUser("mallory");
    // Mallory presents the victim's certificate but can only sign with her own spk.
    const sig = signRelayAuth(RELAY, "n", mallory.dev.signingSecretKey);
    expect(() => verifyRelayAuth({ cert: victim.dev.cert, sig, relay: RELAY, nonce: "n", now: NOW })).toThrow(/bad-signature/);
    // A certificate binding her spk to the victim's did fails rule 3.
    const p = decodeJws(mallory.dev.cert).payload;
    const squat = signJws("p2p-device+jws", "ik", { ...p, did: victim.dev.did }, mallory.ik.secretKey);
    expect(() => verifyDeviceCertV3(squat, { now: NOW })).toThrow(/did-mismatch/);
  });

  it("rule 6 when the relay holds the document: a revoked device can't connect", () => {
    const u = makeUser("alice");
    const old = u.addDevice({ keyholder: false });
    u.publish();
    u.publish({ devices: [u.dev.did] });
    const sig = signRelayAuth(RELAY, "n", old.signingSecretKey);
    expect(verifyRelayAuth({ cert: old.cert, sig, relay: RELAY, nonce: "n", now: NOW }).did).toBe(old.did);
    expect(() => verifyRelayAuth({ cert: old.cert, sig, relay: RELAY, nonce: "n", now: NOW, identityDoc: u.doc.jws })).toThrow(/device-not-listed/);
  });
});

describe("§5.3 capabilities", () => {
  it("a friend cap lets exactly that sender reach the issuer on the named relays", () => {
    const bob = makeUser("bob");
    const alice = makeUser("alice");
    const cap = bob.friendCap(alice.userId);
    const ok = verifyCapForSend(cap, { relayUrl: RELAY, to: bob.userId, envFrom: alice.userId, kind: "msg", now: NOW });
    expect(ok.sub).toBe(alice.userId);
    const mallory = makeUser("mallory");
    expect(() => verifyCapForSend(cap, { relayUrl: RELAY, to: bob.userId, envFrom: mallory.userId, kind: "msg", now: NOW })).toThrow(/another sender/);
    expect(() => verifyCapForSend(cap, { relayUrl: RELAY2, to: bob.userId, envFrom: alice.userId, kind: "msg", now: NOW })).toThrow(/this relay/);
    expect(() => verifyCapForSend(cap, { relayUrl: RELAY, to: mallory.userId, envFrom: alice.userId, kind: "msg", now: NOW })).toThrow(/another recipient/);
    expect(() => verifyCapForSend(cap, { relayUrl: RELAY, to: bob.userId, envFrom: alice.userId, kind: "msg", now: NOW, isRevoked: () => true })).toThrow(/revoked/);
    expect(() => verifyCapForSend(cap, { relayUrl: RELAY, to: bob.userId, envFrom: alice.userId, kind: "msg", now: NOW + DAYS(91) })).toThrow(/expired/);
  });

  it("contact-only caps allow only kind contact; join caps are sub * kinds *", () => {
    const bob = makeUser("bob");
    const alice = makeUser("alice");
    const contact = createCap(bob.dev, bob.dev.cert, { purpose: "contact", relays: [RELAY], iat: NOW - 1, uses: 3 });
    expect(verifyCapForSend(contact, { relayUrl: RELAY, to: bob.userId, envFrom: alice.userId, kind: "contact", now: NOW }).uses).toBe(3);
    expect(() => verifyCapForSend(contact, { relayUrl: RELAY, to: bob.userId, envFrom: alice.userId, kind: "msg", now: NOW })).toThrow(/kind msg/);
    const join = bob.joinCap();
    expect(verifyCapForSend(join, { relayUrl: RELAY, to: bob.userId, envFrom: alice.userId, kind: "status", now: NOW }).sub).toBe("*");
    expect(() => verifyCap(join, { now: NOW, purpose: "contact" })).toThrow(/cap-invalid/);
    expect(() => verifyCap(contact, { now: NOW, purpose: "join" })).toThrow(/cap-invalid/);
  });

  it("answer caps (§3.3 want): name their sender, kinds *, live at most a day; a relay treats them like any named cap", () => {
    const bob = makeUser("bob");
    const alice = makeUser("alice");
    const ans = createCap(bob.dev, bob.dev.cert, { purpose: "answer", sub: alice.userId, relays: [RELAY], iat: NOW - 1, ttlSec: 3600 });
    expect(verifyCap(ans, { now: NOW, purpose: "answer" })).toMatchObject({ sub: alice.userId, kinds: ["*"] });
    expect(verifyCapForSend(ans, { relayUrl: RELAY, to: bob.userId, envFrom: alice.userId, kind: "circle", now: NOW }).sub).toBe(alice.userId);
    expect(() => verifyCapForSend(ans, { relayUrl: RELAY, to: bob.userId, envFrom: makeUser("mallory").userId, kind: "circle", now: NOW })).toThrow(/another sender/);
    expect(() => verifyCapForSend(ans, { relayUrl: RELAY, to: bob.userId, envFrom: alice.userId, kind: "circle", now: NOW + 3600 })).toThrow(/expired/);
    expect(() => createCap(bob.dev, bob.dev.cert, { purpose: "answer", sub: alice.userId, relays: [RELAY], ttlSec: DAYS(1) + 1 })).toThrow(/at most a day/);
    expect(() => createCap(bob.dev, bob.dev.cert, { purpose: "answer", sub: "*", relays: [RELAY] })).toThrow(/names its sender/);
    // A friend cap (90 days), a join cap (sub *) and a contact cap are no answer caps.
    expect(() => verifyCap(bob.friendCap(alice.userId), { now: NOW, purpose: "answer" })).toThrow(/cap-invalid/);
    expect(() => verifyCap(bob.joinCap(), { now: NOW, purpose: "answer" })).toThrow(/cap-invalid/);
    expect(() => verifyCap(createCap(bob.dev, bob.dev.cert, { purpose: "contact", sub: alice.userId, relays: [RELAY], iat: NOW - 1 }), { now: NOW, purpose: "answer" })).toThrow(/cap-invalid/);
  });

  it("a circle want may carry one cap (the answer cap); nothing else is added", () => {
    const bob = makeUser("bob");
    const ans = createCap(bob.dev, bob.dev.cert, { purpose: "answer", sub: makeUser("alice").userId, relays: [RELAY], iat: NOW - 1, ttlSec: 3600 });
    const cid = "c_" + "a".repeat(26);
    const parse = (o: unknown) => parsePlaintextV3("circle", utf8(JSON.stringify(o)));
    expect(parse({ want: { cid, fromVer: 1 } })).toEqual({ kind: "circle", want: { cid, fromVer: 1 } });
    expect(parse({ want: { cid, fromVer: 1 }, cap: ans })).toEqual({ kind: "circle", want: { cid, fromVer: 1 }, cap: ans });
    expect(() => parse({ want: { cid, fromVer: 1 }, cap: 5 })).toThrow(/malformed/);
    expect(() => parse({ want: { cid, fromVer: 1 }, cap: "not-a-jws" })).toThrow(/one compact JWS/);
    expect(parse({ want: { cid, fromVer: 1 }, cap: ans, extra: 1 })).not.toHaveProperty("extra");
    expect(() => parse({ want: { cid, fromVer: 1 }, cap: ans, extra: 1, crit: ["extra"] })).toThrow(/critical/);
    // A want and a bundle in one plaintext: two readings of one envelope, refused.
    expect(() => parse({ want: { cid, fromVer: 1 }, circles: [] })).toThrow(/want and a bundle/);
    // A bundle's `cap` was never one of its fields: ignored (not used), as any unknown field.
    expect(parse({ circles: [], joins: [], cap: ans })).not.toHaveProperty("cap");
    const link = "A".repeat(43);
    expect(parse({ want: { cid, fromVer: 3 }, cap: ans, link })).toEqual({ kind: "circle", want: { cid, fromVer: 3 }, cap: ans, link });
    expect(() => parse({ want: { cid, fromVer: 1 }, link: "short" })).toThrow(/jwsHash/);
    const pow = { at: 1_800_000_000, nonce: "AbC_-9" };
    expect(parse({ want: { cid, fromVer: 1 }, pow })).toEqual({ kind: "circle", want: { cid, fromVer: 1 }, pow });
    for (const bad of [{ at: -1, nonce: "a" }, { at: 1.5, nonce: "a" }, { at: 1, nonce: "" }, { at: 1, nonce: "x".repeat(33) }, { at: 1, nonce: "a", more: 1, crit: ["more"] }, "p"]) {
      expect(() => parse({ want: { cid, fromVer: 1 }, pow: bad }), JSON.stringify(bad)).toThrow(/malformed|critical/);
    }
  });

  it("a circle bundle may say which part of an answer it is ({id, i, n}); nothing else", () => {
    const parse = (o: unknown) => parsePlaintextV3("circle", utf8(JSON.stringify(o)));
    const part = { id: "AbCdEfGh_-12", i: 2, n: 3 };
    expect(parse({ circles: [], joins: [], ops: [], part })).toEqual({ kind: "circle", circles: [], joins: [], ops: [], part });
    expect(parse({ circles: [], joins: [], ops: [] })).toEqual({ kind: "circle", circles: [], joins: [], ops: [] });
    for (const bad of [{ ...part, i: 4 }, { ...part, i: 0 }, { ...part, n: 5000, i: 1 }, { ...part, id: "short" }, { ...part, id: "x".repeat(25) }, { ...part, extra: 1, crit: ["extra"] }, { ...part, i: 1.5 }, "p", [1]]) {
      expect(() => parse({ circles: [], joins: [], ops: [], part: bad }), JSON.stringify(bad)).toThrow(/malformed|critical/);
    }
  });

  it("rejects a cap whose cert isn't the issuer's, or with kid != cert.did, or with non-canonical relays", () => {
    const bob = makeUser("bob");
    const mallory = makeUser("mallory");
    const cap = bob.friendCap(mallory.userId);
    const p = decodeJws(cap).payload;
    // Mallory signs a cap claiming to be Bob's, with her own device cert.
    const forged = signJws("p2p-cap+jws", mallory.dev.did, { ...p, cert: mallory.dev.cert }, mallory.dev.signingSecretKey);
    expect(() => verifyCap(forged, { now: NOW })).toThrow(/cap-invalid/);
    const wrongKid = signJws("p2p-cap+jws", mallory.dev.did, p, bob.dev.signingSecretKey);
    expect(() => verifyCap(wrongKid, { now: NOW })).toThrow(/kid-mismatch/);
    const badRelay = signJws("p2p-cap+jws", bob.dev.did, { ...p, relays: ["wss://Relay.example/v3/"] }, bob.dev.signingSecretKey);
    expect(() => verifyCap(badRelay, { now: NOW })).toThrow(/canonical/);
    const badKinds = signJws("p2p-cap+jws", bob.dev.did, { ...p, kinds: ["msg"] }, bob.dev.signingSecretKey);
    expect(() => verifyCap(badKinds, { now: NOW })).toThrow(/kinds/);
    expect(() => createCap(bob.dev, bob.dev.cert, { purpose: "friend", relays: [RELAY] })).toThrow(/names its sender/);
    expect(() => createCap(bob.dev, bob.dev.cert, { purpose: "friend", sub: mallory.userId, relays: [RELAY], ttlSec: DAYS(91) })).toThrow(/90d/);
  });

  it("a cap signed by a revoked device fails rule 6 when the relay holds the document", () => {
    const bob = makeUser("bob");
    const old = bob.addDevice({ keyholder: false });
    bob.publish();
    const cap = createCap(old, old.cert, { purpose: "friend", sub: makeUser("alice").userId, relays: [RELAY], iat: NOW - 1 });
    bob.publish({ devices: [bob.dev.did] });
    const sub = decodeJws(cap).payload.sub as string;
    expect(() => verifyCapForSend(cap, { relayUrl: RELAY, to: bob.userId, envFrom: sub, kind: "msg", now: NOW, identityDoc: bob.doc.jws })).toThrow(/device-not-listed/);
  });
});

describe("§5.4 outer envelope, without opening", () => {
  it("parses and verifies the sender fields against fcert", () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const env = seal(a, b, "msg", { text: "hi" });
    const outer = parseOuterEnvelope(env);
    expect(outer.payload.to).toBe(b.userId);
    expect(outer.bytes.length).toBe(env.length);
    const v = verifyOuterEnvelope(env, { now: NOW });
    expect(v.cert.did).toBe(a.dev.did);
    expect(verifyOuterEnvelope(env, { now: NOW, identityDoc: a.doc.jws }).cert.iss).toBe(a.userId);
  });

  it("rejects spoofed sender fields: fcert of another user or device, or a bad signature", () => {
    const a = makeUser("alice");
    const b = makeUser("bob");
    const m = makeUser("mallory");
    // Mallory's device signs, claiming to be Alice, with Alice's fcert.
    const env = seal(a, b, "msg", { text: "hi" });
    const p = decodeJws(env).payload;
    const resigned = signJws("p2p-msg+jws", a.dev.did, p, m.dev.signingSecretKey);
    expect(() => verifyOuterEnvelope(resigned, { now: NOW })).toThrow(/bad-signature/);
    // Mallory's fcert in an envelope claiming from = Alice.
    const spoof = signJws("p2p-msg+jws", m.dev.did, { ...p, fdid: m.dev.did, fcert: m.dev.cert }, m.dev.signingSecretKey);
    expect(() => verifyOuterEnvelope(spoof, { now: NOW })).toThrow(/cert-mismatch/);
    // kid != fdid.
    const kid = signJws("p2p-msg+jws", m.dev.did, p, a.dev.signingSecretKey);
    expect(() => parseOuterEnvelope(kid)).toThrow(/kid-mismatch/);
    // fcert.did != fdid (Alice's second device's cert on her first device's envelope).
    const a2 = a.addDevice();
    const swapped = signJws("p2p-msg+jws", a.dev.did, { ...p, fcert: a2.cert }, a.dev.signingSecretKey);
    expect(() => verifyOuterEnvelope(swapped, { now: NOW })).toThrow(/kid-mismatch/);
    expect(() => parseOuterEnvelope("x".repeat(70_000))).toThrow(/malformed/);
    void NOW_MS;
  });
});

describe("§5.4 proof-of-work", () => {
  it("counts leading zero bits of H(env || pow)", () => {
    expect(leadingZeroBits(new Uint8Array([0, 0x0f]))).toBe(12);
    expect(leadingZeroBits(new Uint8Array([0x80]))).toBe(0);
    const env = "header.payload.sig";
    const pow = solvePow(env, 12);
    expect(powOk(env, pow, 12)).toBe(true);
    expect(powOk(utf8(env), pow, 12)).toBe(true);
    expect(powOk(env, pow, 0)).toBe(true);
    expect(powOk(env + "x", pow, 12) && powOk(env + "x", pow, 20)).toBe(false);
    expect(powOk(env, "!!", 4)).toBe(false);
    expect(powOk(env, pow, -1)).toBe(false);
  });
});

describe("§5.6 identity documents on relays", () => {
  it("verifyIdentityDocLink accepts a relay's first copy, links, and merges", () => {
    const u = makeUser("alice");
    const v2 = u.publish();
    expect(verifyIdentityDocLink(undefined, v2.jws, { now: NOW }).ver).toBe(2);
    expect(verifyIdentityDocLink(u.docs[0].jws, v2.jws, { now: NOW }).ver).toBe(2);
    expect(docListsRelay(v2, "wss://RELAY.example/v3/")).toBe(true);
    expect(docListsRelay(v2, RELAY2)).toBe(false);
  });
});
