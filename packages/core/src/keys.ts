// Copyright 2026 Ix Infrastructure Inc.
//
// Device key generation and the KeyStore that keeps the private halves.
// Private keys never leave the device: a host application can back the
// KeyStore with the OS keychain through a host capability (service `ix-p2p`, account
// `<userId>/<deviceId>`).

import { b64uDecode, b64uEncode } from "./encoding.js";
import { ed25519PublicKey, randomBytes, x25519PublicKey } from "./crypto.js";
import { fail } from "./errors.js";
import { newDeviceId, normalizeUserId, type DeviceSigner } from "./objects.js";

export const KEYCHAIN_SERVICE = "ix-p2p";

export interface DeviceKeys extends DeviceSigner {
  /** Ed25519 seed (32 bytes). */
  signingSecretKey: Uint8Array;
  signingPublicKey: Uint8Array;
  /** X25519 secret (32 bytes). */
  agreementSecretKey: Uint8Array;
  agreementPublicKey: Uint8Array;
}

/** Fresh deviceId plus Ed25519 (`spk`) and X25519 (`kpk`) key pairs. */
export function generateDeviceKeys(userId: string, deviceId: string = newDeviceId()): DeviceKeys {
  return deviceKeysFromSecrets(normalizeUserId(userId), deviceId, randomBytes(32), randomBytes(32));
}

export function deviceKeysFromSecrets(
  userId: string,
  deviceId: string,
  signingSecretKey: Uint8Array,
  agreementSecretKey: Uint8Array,
): DeviceKeys {
  return {
    userId,
    deviceId,
    signingSecretKey,
    signingPublicKey: ed25519PublicKey(signingSecretKey),
    agreementSecretKey,
    agreementPublicKey: x25519PublicKey(agreementSecretKey),
  };
}

/** Keychain account for a device: `<userId>/<deviceId>`. */
export function keychainAccount(userId: string, deviceId: string): string {
  return `${normalizeUserId(userId)}/${deviceId}`;
}

/**
 * Storage for device secrets. A secret is opaque bytes to the store; this
 * package stores `signingSecret(32) || agreementSecret(32)`.
 */
export interface KeyStore {
  get(account: string): Promise<Uint8Array | undefined>;
  set(account: string, secret: Uint8Array): Promise<void>;
  delete(account: string): Promise<void>;
}

/** In-memory KeyStore for tests. Copies on the way in and out. */
export class MemoryKeyStore implements KeyStore {
  private readonly items = new Map<string, Uint8Array>();
  async get(account: string): Promise<Uint8Array | undefined> {
    const v = this.items.get(account);
    return v ? v.slice() : undefined;
  }
  async set(account: string, secret: Uint8Array): Promise<void> {
    this.items.set(account, secret.slice());
  }
  async delete(account: string): Promise<void> {
    this.items.delete(account);
  }
}

/**
 * The host capability (e.g. a host application's keychain bridge). Keychains store
 * strings, so secrets cross this boundary as base64url. The host binds the
 * service name (`ix-p2p`).
 */
export interface KeychainCapability {
  get(account: string): Promise<string | null | undefined>;
  set(account: string, secret: string): Promise<void>;
  delete(account: string): Promise<void>;
}

export class HostKeyStore implements KeyStore {
  constructor(private readonly host: KeychainCapability) {}
  async get(account: string): Promise<Uint8Array | undefined> {
    const v = await this.host.get(account);
    if (v === null || v === undefined) return undefined;
    return b64uDecode(v);
  }
  async set(account: string, secret: Uint8Array): Promise<void> {
    await this.host.set(account, b64uEncode(secret));
  }
  async delete(account: string): Promise<void> {
    await this.host.delete(account);
  }
}

export async function saveDeviceKeys(store: KeyStore, keys: DeviceKeys): Promise<void> {
  const secret = new Uint8Array(64);
  secret.set(keys.signingSecretKey, 0);
  secret.set(keys.agreementSecretKey, 32);
  await store.set(keychainAccount(keys.userId, keys.deviceId), secret);
}

export async function loadDeviceKeys(store: KeyStore, userId: string, deviceId: string): Promise<DeviceKeys | undefined> {
  const secret = await store.get(keychainAccount(userId, deviceId));
  if (!secret) return undefined;
  if (secret.length !== 64) fail("malformed", "stored device secret must be 64 bytes");
  return deviceKeysFromSecrets(normalizeUserId(userId), deviceId, secret.slice(0, 32), secret.slice(32));
}

export async function deleteDeviceKeys(store: KeyStore, userId: string, deviceId: string): Promise<void> {
  await store.delete(keychainAccount(userId, deviceId));
}
