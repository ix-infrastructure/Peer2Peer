// Copyright 2026 Ix Infrastructure Inc.
//
// §2.5 identity documents: signing, the hash chain, gaps, forks and merges,
// expiry and the 60-day fail-closed rule, single writer, compromise
// detection; and the Phase 2 profile addition.

import { describe, expect, it } from "vitest";
import {
  assertNotFailClosed,
  createIdentityDoc,
  daysPastExp,
  detectUnpublishedVersion,
  displayProfile,
  IdentityChain,
  identityFreshness,
  mayPublishMerge,
  mayRepublish,
  mergeFields,
  peekIdentityDoc,
  scheduledWriter,
  verifyIdentityDoc,
  verifyIdentityDocLink,
  verifyIdentityDocSignature,
  type VerifiedIdentityDoc,
} from "../identitydoc.js";
import { generateIdentityKey } from "../identity.js";
import { DAY } from "../base.js";
import { decodeJws, signJws } from "../../jws.js";
import { DAYS, makeUser, NOW, RELAY, RELAY2, TestUser } from "./fixtures.js";

function fork(u: TestUser, parent: VerifiedIdentityDoc, devices: string[], opts: { by?: string; iat?: number } = {}): VerifiedIdentityDoc {
  const keyholders = u.keyholders.filter((k) => devices.includes(k));
  return verifyIdentityDocSignature(
    createIdentityDoc(u.ik, {
      ver: parent.ver + 1,
      prev: parent.hash,
      name: u.name,
      relays: u.relays,
      devices,
      keyholders,
      by: opts.by ?? keyholders[0],
      iat: opts.iat ?? NOW - 300,
    }),
  );
}

function merge(u: TestUser, a: VerifiedIdentityDoc, b: VerifiedIdentityDoc, override: Partial<Parameters<typeof createIdentityDoc>[1]> = {}): string {
  const f = mergeFields(a, b);
  return createIdentityDoc(u.ik, { ...f, by: f.keyholders[0], iat: NOW - 100, ...override });
}

describe("§2.5 document signing", () => {
  it("signs and verifies; iss == H(ik); by is a key holder", () => {
    const u = makeUser("alice");
    const d = verifyIdentityDoc(u.doc.jws, { now: NOW });
    expect(d.iss).toBe(u.userId);
    expect(d.ver).toBe(1);
    expect(d.prev).toBeNull();
    expect(d.by).toBe(u.dev.did);
    expect(d.certs).toHaveLength(1);
  });

  it("rejects structural violations", () => {
    const u = makeUser("alice");
    const base = { ver: 1, prev: null, name: "alice", relays: [RELAY], devices: [u.dev.did], keyholders: [u.dev.did], by: u.dev.did, iat: NOW };
    expect(() => createIdentityDoc(u.ik, { ...base, ttlSec: DAYS(31) })).toThrow(/30 days/);
    expect(() => createIdentityDoc(u.ik, { ...base, relays: [] })).toThrow(/1–5 relays/);
    expect(() => createIdentityDoc(u.ik, { ...base, relays: ["wss://Relay.Example/"] })).toThrow(/canonical/);
    expect(() => createIdentityDoc(u.ik, { ...base, relays: [RELAY, RELAY2, "wss://a.example/v3", "wss://b.example/v3", "wss://c.example/v3", "wss://d.example/v3"] })).toThrow(/more than 5/);
    expect(() => createIdentityDoc(u.ik, { ...base, keyholders: ["d_" + "a".repeat(26)] })).toThrow(/not in devices/);
    expect(() => createIdentityDoc(u.ik, { ...base, by: "d_" + "b".repeat(26) })).toThrow(/by must be one of keyholders/);
    expect(() => createIdentityDoc(u.ik, { ...base, name: "Alice" })).toThrow(/name/);
    expect(() => createIdentityDoc(u.ik, { ...base, prev: "x" })).toThrow(/prev: null/);
    const tooMany = Array.from({ length: 11 }, (_, i) => `d_${String.fromCharCode(97 + i).repeat(26)}`);
    expect(() => createIdentityDoc(u.ik, { ...base, devices: tooMany, keyholders: [] })).toThrow(/more than 10/);
  });

  it("rejects a document whose iss is not the fingerprint of ik, or signed by another key", () => {
    const u = makeUser("alice");
    const p = decodeJws(u.doc.jws).payload;
    const other = generateIdentityKey();
    expect(() => verifyIdentityDocSignature(signJws("p2p-identity+jws", "ik", { ...p, iss: other.userId }, u.ik.secretKey))).toThrow(/issuer-mismatch/);
    expect(() => verifyIdentityDocSignature(signJws("p2p-identity+jws", "ik", p, other.secretKey))).toThrow(/bad-signature/);
    expect(() => verifyIdentityDoc(signJws("p2p-identity+jws", "ik", { ...p, iat: NOW + 3600, exp: NOW + 7200 }, u.ik.secretKey), { now: NOW })).toThrow(
      /not-yet-valid/,
    );
  });
});

describe("§2.5 chain", () => {
  it("links: ver = prev.ver + 1 and prev = jwsHash(previous)", () => {
    const u = makeUser("alice");
    const v1 = u.doc;
    const v2 = u.publish();
    expect(verifyIdentityDocLink(v1.jws, v2.jws, { now: NOW }).ver).toBe(2);
    expect(verifyIdentityDocLink(undefined, v1.jws, { now: NOW }).ver).toBe(1);
    const v3 = u.publish();
    expect(() => verifyIdentityDocLink(v1.jws, v3.jws, { now: NOW })).toThrow(/chain-broken/);
    const other = makeUser("bob");
    expect(() => verifyIdentityDocLink(other.doc.jws, v2.jws, { now: NOW })).toThrow(/issuer-mismatch/);
    // Right prev hash, wrong ver.
    const bad = createIdentityDoc(u.ik, { ver: 5, prev: v2.hash, name: "alice", relays: [RELAY], devices: [u.dev.did], keyholders: [u.dev.did], by: u.dev.did, iat: NOW });
    expect(() => verifyIdentityDocLink(v2.jws, bad, { now: NOW })).toThrow(/chain-broken/);
  });

  it("keeps chain-consistent versions and reports gaps to fill first", () => {
    const u = makeUser("alice");
    const v1 = u.doc;
    const v2 = u.publish();
    const v3 = u.publish();
    const c = new IdentityChain(u.userId);
    expect(c.add(v1.jws, { now: NOW }).status).toBe("accepted");
    expect(c.add(v3.jws, { now: NOW })).toEqual({ status: "gap", need: v2.hash });
    expect(c.add(v2.jws, { now: NOW }).status).toBe("accepted");
    expect(c.add(v3.jws, { now: NOW }).status).toBe("accepted");
    expect(c.add(v3.jws, { now: NOW }).status).toBe("duplicate");
    expect(c.view().head.hash).toBe(v3.hash);
    expect(c.view().forked).toBe(false);
    // Round-trips through storage.
    expect(IdentityChain.fromStored(c.toStored()).view().head.hash).toBe(v3.hash);
  });

  it("a gap that can't be filled may jump to a head under the same ik, flagged as a history gap", () => {
    const u = makeUser("alice");
    const v1 = u.doc;
    u.publish();
    const v3 = u.publish();
    const c = new IdentityChain(u.userId);
    c.add(v1.jws, { now: NOW });
    expect(c.jumpTo(v3.jws, { now: NOW }).ver).toBe(3);
    expect(c.view().historyGap).toBe(true);
    // Never to another key, never backwards.
    const imposter = new TestUser("alice");
    imposter.addDevice();
    const forged = imposter.publish();
    expect(() => c.jumpTo(forged.jws, { now: NOW })).toThrow(/issuer-mismatch/);
    expect(() => c.jumpTo(v1.jws, { now: NOW })).toThrow(/forward/);
  });

  it("a revoked device never returns in a later version", () => {
    const u = makeUser("alice");
    const laptop = u.addDevice({ keyholder: false });
    const v2 = u.publish();
    const v3 = u.publish({ devices: [u.dev.did] }); // revoke
    const v4 = u.publish({ devices: [u.dev.did, laptop.did] }); // re-add the revoked did
    const c = new IdentityChain(u.userId);
    for (const v of [u.docs[0], v2, v3]) c.add(v.jws, { now: NOW });
    expect(() => c.add(v4.jws, { now: NOW })).toThrow(/revoked-device-returned/);
  });
});

describe("§2.5 forks and merges", () => {
  function forked() {
    const u = makeUser("alice");
    const phone = u.addDevice({ keyholder: true });
    const laptop = u.addDevice({ keyholder: false });
    const v2 = u.publish();
    // Two key holders publish at once: A revokes the laptop, B keeps everything.
    const a = fork(u, v2, [u.dev.did, phone.did], { by: u.dev.did });
    const b = fork(u, v2, [u.dev.did, phone.did, laptop.did], { by: phone.did, iat: NOW - 299 });
    const c = new IdentityChain(u.userId);
    for (const v of [u.docs[0], v2, a, b]) c.add(v.jws, { now: NOW });
    return { u, phone, laptop, v2, a, b, c };
  }

  it("keeps both branches and intersects devices and keyholders: a revocation in either branch applies", () => {
    const { c, laptop, u, phone } = forked();
    const view = c.view();
    expect(view.forked).toBe(true);
    expect(view.tips).toHaveLength(2);
    expect(view.devices).not.toContain(laptop.did);
    expect(view.devices.sort()).toEqual([u.dev.did, phone.did].sort());
    expect(view.keyholders.sort()).toEqual([u.dev.did, phone.did].sort());
  });

  it("accepts a valid merge from the single writer; the fork resolves", () => {
    const { c, u, a, b, laptop } = forked();
    const m = merge(u, a, b);
    expect(c.add(m, { now: NOW }).status).toBe("accepted");
    const view = c.view();
    expect(view.forked).toBe(false);
    expect(view.head.merge).toBeDefined();
    expect(view.devices).not.toContain(laptop.did);
    expect(verifyIdentityDocLink(peekIdentityDoc(m).prev === a.hash ? a.jws : b.jws, m, { now: NOW, merge: peekIdentityDoc(m).prev === a.hash ? b.jws : a.jws }).ver).toBe(4);
  });

  it("merge re-adding a device (not in A ∩ B) is rejected", () => {
    const { c, u, a, b, laptop } = forked();
    const f = mergeFields(a, b);
    const bad = merge(u, a, b, { devices: [...f.devices, laptop.did] });
    expect(() => c.add(bad, { now: NOW })).toThrow(/merge-adds-device/);
  });

  it("merge with the wrong prev/merge order or ver is rejected; a merge needs both parents", () => {
    const { c, u, a, b } = forked();
    const f = mergeFields(a, b);
    const swapped = merge(u, a, b, { prev: f.merge!, merge: f.prev! });
    expect(() => c.add(swapped, { now: NOW })).toThrow(/merge-invalid/);
    const wrongVer = merge(u, a, b, { ver: 9 });
    expect(() => c.add(wrongVer, { now: NOW })).toThrow(/merge-invalid/);
    expect(() => verifyIdentityDocLink(undefined, merge(u, a, b), { now: NOW })).toThrow(/merge-invalid/);
    const prevJws = f.prev === a.hash ? a.jws : b.jws;
    expect(() => verifyIdentityDocLink(prevJws, merge(u, a, b), { now: NOW })).toThrow(/merge parent not supplied/);
  });

  it("a merge whose `merge` parent isn't held is a gap", () => {
    const { u, a, b } = forked();
    const c = new IdentityChain(u.userId);
    for (const v of [u.docs[0], u.docs[1], a]) c.add(v.jws, { now: NOW });
    const m = merge(u, a, b);
    const r = c.add(m, { now: NOW });
    expect(r.status).toBe("gap");
  });

  it("mayPublishMerge: the lowest did at once, any key holder after 24 h", () => {
    const kh = ["d_" + "b".repeat(26), "d_" + "a".repeat(26)];
    expect(scheduledWriter(kh)).toBe(kh[1]);
    expect(mayPublishMerge(kh[1], kh, NOW, NOW)).toBe(true);
    expect(mayPublishMerge(kh[0], kh, NOW, NOW + DAY - 1)).toBe(false);
    expect(mayPublishMerge(kh[0], kh, NOW, NOW + DAY)).toBe(true);
    expect(mayPublishMerge("d_" + "c".repeat(26), kh, NOW, NOW + DAYS(5))).toBe(false);
  });
});

describe("§2.5 expiry: warn after exp, fail closed after exp + 60 d", () => {
  it("the fail-closed boundary is exclusive at exp + 60 d", () => {
    const exp = NOW;
    expect(identityFreshness(exp, exp - 1)).toBe("fresh");
    expect(identityFreshness(exp, exp)).toBe("expired");
    expect(identityFreshness(exp, exp + DAYS(60))).toBe("expired");
    expect(identityFreshness(exp, exp + DAYS(60) + 1)).toBe("fail-closed");
    expect(daysPastExp(exp, exp + DAYS(12) + 5)).toBe(12);
    expect(assertNotFailClosed(exp, exp + DAYS(60))).toBe("expired");
    expect(() => assertNotFailClosed(exp, exp + DAYS(60) + 1)).toThrow(/identity-fail-closed/);
    // The user's own sync is exempt, so a user can always recover.
    expect(assertNotFailClosed(exp, exp + DAYS(400), { ownSync: true })).toBe("fail-closed");
  });

  it("single writer: the lowest did re-publishes on schedule, others only within 3 days of exp", () => {
    const kh = ["d_" + "b".repeat(26), "d_" + "a".repeat(26)];
    const head = { keyholders: kh, exp: NOW + DAYS(10) };
    expect(mayRepublish(kh[1], head, NOW)).toBe(true);
    expect(mayRepublish(kh[0], head, NOW)).toBe(false);
    expect(mayRepublish(kh[0], head, NOW + DAYS(7))).toBe(true);
    expect(mayRepublish("d_" + "z".repeat(26), head, NOW + DAYS(9))).toBe(false);
  });
});

describe("§2.5 a version I didn't publish", () => {
  it("alerts when a foreign version adds a device, relay or proof none of the owner's devices added", () => {
    const u = makeUser("alice");
    const v1 = u.doc;
    // The owner's own device adds a phone: logged, no alert.
    const phone = u.addDevice();
    const v2 = u.publish();
    const log = { published: [v1.hash, v2.hash], addedDevices: [phone.did], addedRelays: [], addedProofs: [] };
    expect(detectUnpublishedVersion(v2, [v1], log).alert).toBe(false);
    // A thief with ik adds its own device and relay.
    const thiefDev = u.addDevice();
    const v3 = u.publish({ relays: [RELAY, RELAY2], by: u.dev.did });
    const r = detectUnpublishedVersion(v3, [v2], log, [u.dev.did, phone.did]);
    expect(r.alert).toBe(true);
    expect(r.devices).toEqual([thiefDev.did]);
    expect(r.relays).toEqual([RELAY2]);
    // A re-publish by another key holder that adds nothing is fine.
    const v4 = u.publish({ devices: v3.devices, relays: v3.relays });
    expect(detectUnpublishedVersion(v4, [v3], log).alert).toBe(false);
  });
});

describe("Draft 3 additions: profile", () => {
  it("accepts bio ≤ 280, https/data avatars, ≤ 5 https links; display sanitizes and gates remote avatars", () => {
    const u = makeUser("alice");
    const doc = u.publish({
      profile: { bio: "builds <agents>‮ and\nthings", avatar: "https://img.example/a.png", links: ["https://github.com/alice"] },
    });
    const shown = displayProfile(doc.profile);
    expect(shown.bio).toBe("builds agents and things");
    expect(shown.avatar).toEqual({ kind: "remote", url: "https://img.example/a.png", requiresOptIn: true });
    expect(shown.links).toEqual(["https://github.com/alice"]);
    const inline = u.publish({ profile: { avatar: "data:image/png;base64,iVBORw0KGgo=" } });
    expect(displayProfile(inline.profile).avatar?.kind).toBe("inline");
  });

  it("rejects oversize or unsafe profile fields", () => {
    const u = makeUser("alice");
    expect(() => u.publish({ profile: { bio: "x".repeat(281) } })).toThrow(/bio/);
    expect(() => u.publish({ profile: { avatar: "http://img.example/a.png" } })).toThrow(/avatar/);
    expect(() => u.publish({ profile: { avatar: "data:image/svg+xml;base64,PHN2Zz4=" } })).toThrow(/avatar/);
    expect(() => u.publish({ profile: { avatar: `data:image/png;base64,${"A".repeat(5000)}` } })).toThrow(/avatar/);
    expect(() => u.publish({ profile: { links: ["javascript:alert(1)"] } })).toThrow(/links/);
    expect(() => u.publish({ profile: { links: Array.from({ length: 6 }, (_, i) => `https://e.example/${i}`) } })).toThrow(/more than 5/);
    expect(() => u.publish({ profile: { bio: "hi", extra: 1, crit: ["extra"] } as never })).toThrow(/critical/);
  });
});
