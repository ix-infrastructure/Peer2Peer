// Copyright 2026 Ix Infrastructure Inc.
//
// Deterministic v3 test vectors (fixed seeds) for other implementations:
// userId, fingerprint, did, device certificate, identity document, envelope
// AAD, KDF info and key, a sealed ciphertext, and the device-link values.
// They live in testdata/v3-vectors.json; regenerate with
// `P2P_WRITE_VECTORS=1 npx vitest run src/v3/__tests__/vectors.test.ts`.

import { describe, expect, it } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { identityKeyFromSeed, backupPhraseFromSeed, displayFingerprint } from "../identity.js";
import { createDeviceCert, deviceKeysV3FromSecrets, verifyDeviceCertV3 } from "../device.js";
import { createIdentityDoc, verifyIdentityDoc } from "../identitydoc.js";
import { envelopeAadV3, envelopeKdfInfoV3 } from "../envelope.js";
import { circleIdFor, jwsHash } from "../base.js";
import { createLinkRequest, linkCompareCode, linkId, linkMacKey, encodeLinkCode } from "../link.js";
import { canonicalRelayUrl } from "../relayurl.js";
import { relayAuthMessage, signRelayAuth } from "../relay.js";
import { aeadSeal, hkdfSha256, x25519, x25519PublicKey } from "../../crypto.js";
import { openBox } from "../../envelope.js";
import { b64uDecode, b64uEncode, utf8 } from "../../encoding.js";

const FILE = join(fileURLToPath(new URL(".", import.meta.url)), "testdata", "v3-vectors.json");
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const fill = (n: number, v: number) => new Uint8Array(n).fill(v);

function compute() {
  const IAT = 1_800_000_000;
  const ik = identityKeyFromSeed(fill(32, 1));
  const dev = deviceKeysV3FromSecrets(ik.userId, fill(32, 2), fill(32, 3));
  const cert = createDeviceCert(ik, { ...dev, label: "laptop" }, { iat: IAT, ttlSec: 90 * 86_400 });
  const relay = canonicalRelayUrl("wss://Relay.Example:443/v3/");
  const doc = createIdentityDoc(ik, { ver: 1, prev: null, name: "tanner", relays: [relay], devices: [dev.did], keyholders: [dev.did], by: dev.did, certs: [cert], iat: IAT, ttlSec: 30 * 86_400 });
  const peer = deviceKeysV3FromSecrets(identityKeyFromSeed(fill(32, 9)).userId, fill(32, 10), fill(32, 11));
  const header = { from: ik.userId, fdid: dev.did, to: peer.userId, tdid: peer.did, own: ik.userId, sid: "s1", seq: 7, ts: IAT * 1000, kind: "msg" as const };
  const aad = envelopeAadV3(header);
  const info = envelopeKdfInfoV3(dev.did, peer.did);
  // Sealing with fixed eph and n: ikm = X25519(eph, tkpk) || X25519(fkpk_priv, tkpk); key = HKDF(ikm, salt n, info).
  const eph = fill(32, 5);
  const n = fill(24, 6);
  const ikm = new Uint8Array([...x25519(eph, peer.agreementPublicKey), ...x25519(dev.agreementSecretKey, peer.agreementPublicKey)]);
  const key = hkdfSha256(ikm, n, info, 32);
  const ct = aeadSeal(key, n, utf8(JSON.stringify({ text: "hello" })), aad);
  const s = fill(16, 4);
  const xPub = x25519PublicKey(fill(32, 8));
  const req = createLinkRequest(s, dev, xPub, "laptop");
  return {
    note: "Peer2Peer v3 test vectors (docs/protocol.md). All seeds are fixed byte fills; hex unless noted.",
    identity: {
      ikSeedHex: hex(ik.secretKey),
      ikPub: b64uEncode(ik.publicKey),
      userId: ik.userId,
      displayFingerprint: displayFingerprint(ik.userId),
      backupPhrase: backupPhraseFromSeed(ik.secretKey),
    },
    device: {
      spkSeedHex: hex(dev.signingSecretKey),
      kpkSecretHex: hex(dev.agreementSecretKey),
      spk: b64uEncode(dev.signingPublicKey),
      kpk: b64uEncode(dev.agreementPublicKey),
      did: dev.did,
      cert,
    },
    identityDoc: { relayInput: "wss://Relay.Example:443/v3/", relayCanonical: relay, jws: doc, jwsHash: jwsHash(doc) },
    circle: { founder: ik.userId, nonce: b64uEncode(fill(16, 12)), cid: circleIdFor(ik.userId, b64uEncode(fill(16, 12))) },
    envelope: {
      header,
      aad: new TextDecoder().decode(aad),
      kdfInfo: new TextDecoder().decode(info),
      ephSecretHex: hex(eph),
      nonceHex: hex(n),
      recipientKpk: b64uEncode(peer.agreementPublicKey),
      keyHex: hex(key),
      plaintext: JSON.stringify({ text: "hello" }),
      ct: b64uEncode(ct),
    },
    relayAuth: {
      message: new TextDecoder().decode(relayAuthMessage(relay, "bm9uY2U")),
      sig: signRelayAuth(relay, "bm9uY2U", dev.signingSecretKey),
    },
    link: {
      secretHex: hex(s),
      code: encodeLinkCode(s, relay),
      lid: linkId(s),
      macKeyHex: hex(linkMacKey(s)),
      xPub: b64uEncode(xPub),
      request: req,
      compareCode: linkCompareCode(s, dev.did),
    },
  };
}

describe("v3 test vectors", () => {
  it("match testdata/v3-vectors.json", () => {
    const v = compute();
    if (process.env.P2P_WRITE_VECTORS) writeFileSync(FILE, `${JSON.stringify(v, null, 2)}\n`);
    const want = JSON.parse(readFileSync(FILE, "utf8"));
    expect(v).toEqual(want);
  });

  it("the vector objects verify", () => {
    const v = JSON.parse(readFileSync(FILE, "utf8"));
    const now = 1_800_000_000 + 60;
    expect(verifyDeviceCertV3(v.device.cert, { now, identityDoc: v.identityDoc.jws }).did).toBe(v.device.did);
    expect(verifyIdentityDoc(v.identityDoc.jws, { now }).iss).toBe(v.identity.userId);
    expect(v.identity.backupPhrase.split(" ")).toHaveLength(24);
    // The sealed vector opens with the recipient's secret through the shared openBox.
    const pt = openBox({
      box: { n: Buffer.from(v.envelope.nonceHex, "hex"), epk: x25519PublicKey(Buffer.from(v.envelope.ephSecretHex, "hex")), ct: b64uDecode(v.envelope.ct) },
      recipientAgreementSecretKey: fill(32, 11),
      senderKpk: b64uDecode(v.device.kpk),
      info: utf8(v.envelope.kdfInfo),
      aad: utf8(v.envelope.aad),
    });
    expect(new TextDecoder().decode(pt)).toBe(v.envelope.plaintext);
  });
});
