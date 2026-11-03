// Copyright 2026 Ix Infrastructure Inc.
import { describe, expect, it } from "vitest";
import {
  deleteDeviceKeys,
  generateDeviceKeys,
  HostKeyStore,
  keychainAccount,
  KEYCHAIN_SERVICE,
  loadDeviceKeys,
  MemoryKeyStore,
  saveDeviceKeys,
  type KeychainCapability,
  type KeyStore,
} from "../keys.js";
import { createDevregProof, verifyDevregProof } from "../objects.js";
import { b64uEncode } from "../encoding.js";

function hostCapability() {
  const items = new Map<string, string>();
  const host: KeychainCapability = {
    get: async (a) => items.get(a) ?? null,
    set: async (a, s) => void items.set(a, s),
    delete: async (a) => void items.delete(a),
  };
  return { host, items };
}

describe("device keys", () => {
  it("generates a deviceId and key pairs", () => {
    const k = generateDeviceKeys(" Alice@A.example");
    expect(k.userId).toBe("alice@a.example");
    expect(k.deviceId).toMatch(/^d_[A-Za-z0-9_-]{22}$/);
    expect(k.signingPublicKey).toHaveLength(32);
    expect(k.agreementPublicKey).toHaveLength(32);
    expect(keychainAccount(k.userId, k.deviceId)).toBe(`alice@a.example/${k.deviceId}`);
    expect(KEYCHAIN_SERVICE).toBe("ix-p2p");
  });

  const stores: [string, () => { store: KeyStore; raw?: Map<string, string> }][] = [
    ["MemoryKeyStore", () => ({ store: new MemoryKeyStore() })],
    [
      "HostKeyStore",
      () => {
        const { host, items } = hostCapability();
        return { store: new HostKeyStore(host), raw: items };
      },
    ],
  ];
  for (const [name, make] of stores) {
    it(`${name} saves, loads and deletes`, async () => {
      const { store, raw } = make();
      const k = generateDeviceKeys("alice@a.example");
      await saveDeviceKeys(store, k);
      if (raw) {
        expect([...raw.keys()]).toEqual([`alice@a.example/${k.deviceId}`]);
        expect(raw.get(`alice@a.example/${k.deviceId}`)).toMatch(/^[A-Za-z0-9_-]{86}$/);
      }
      const loaded = await loadDeviceKeys(store, "alice@a.example", k.deviceId);
      expect(b64uEncode(loaded!.signingPublicKey)).toBe(b64uEncode(k.signingPublicKey));
      expect(b64uEncode(loaded!.agreementPublicKey)).toBe(b64uEncode(k.agreementPublicKey));
      await deleteDeviceKeys(store, "alice@a.example", k.deviceId);
      expect(await loadDeviceKeys(store, "alice@a.example", k.deviceId)).toBeUndefined();
    });
  }

  it("builds a devreg proof for registration", () => {
    const k = generateDeviceKeys("alice@a.example");
    const proof = createDevregProof(k, k, { nonce: "srv-nonce" });
    const p = verifyDevregProof(proof);
    expect(p).toMatchObject({ did: k.deviceId, sub: k.userId, spk: b64uEncode(k.signingPublicKey), kpk: b64uEncode(k.agreementPublicKey) });
    const [h] = proof.split(".");
    expect(JSON.parse(Buffer.from(h, "base64url").toString())).toEqual({ alg: "EdDSA", typ: "p2p-devreg+jws", kid: k.deviceId });
  });
});
