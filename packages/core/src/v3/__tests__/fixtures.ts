// Copyright 2026 Ix Infrastructure Inc.
//
// v3 test fixtures: users with identity keys, devices, certificates and
// identity documents, and stores that know about each other.

import { generateIdentityKey, type IdentityKey } from "../identity.js";
import { createDeviceCert, generateDeviceKeysV3, type DeviceKeysV3 } from "../device.js";
import { createIdentityDoc, verifyIdentityDocSignature, type Profile, type VerifiedIdentityDoc } from "../identitydoc.js";
import { createCap } from "../caps.js";
import { sealEnvelopeV3, type EnvelopeKindV3 } from "../envelope.js";
import { MemoryTrustStoreV3, type TrustStoreV3 } from "../store.js";
import { addIdentityVersion, storeSignerContext } from "../state.js";
import type { SignerContext } from "../signers.js";
import { DAY } from "../base.js";

export const NOW = 1_800_000_000; // seconds
export const NOW_MS = NOW * 1000;
export const RELAY = "wss://relay.example/v3";
export const RELAY2 = "wss://community.example/v3";

export interface TestDevice extends DeviceKeysV3 {
  cert: string;
  label: string;
}

export class TestUser {
  readonly ik: IdentityKey;
  readonly devices: TestDevice[] = [];
  readonly docs: VerifiedIdentityDoc[] = [];
  keyholders: string[] = [];
  relays: string[] = [RELAY];

  constructor(
    readonly name: string,
    ik?: IdentityKey,
  ) {
    this.ik = ik ?? generateIdentityKey();
  }

  get userId(): string {
    return this.ik.userId;
  }

  /** The first device (key-holding). */
  get dev(): TestDevice {
    return this.devices[0];
  }

  get doc(): VerifiedIdentityDoc {
    return this.docs[this.docs.length - 1];
  }

  addDevice(opts: { iat?: number; ttlSec?: number; keyholder?: boolean; label?: string } = {}): TestDevice {
    const keys = generateDeviceKeysV3(this.userId);
    const label = opts.label ?? `${this.name}-dev${this.devices.length + 1}`;
    const cert = createDeviceCert(this.ik, { ...keys, label }, { iat: opts.iat ?? NOW - 3600, ttlSec: opts.ttlSec });
    const d: TestDevice = { ...keys, cert, label };
    this.devices.push(d);
    if (opts.keyholder ?? this.keyholders.length === 0) this.keyholders.push(d.did);
    return d;
  }

  /** Publishes the next version listing `devices` (default: all current). */
  publish(
    opts: { devices?: string[]; keyholders?: string[]; iat?: number; ttlSec?: number; by?: string; profile?: Profile; relays?: string[]; proofs?: string[]; certs?: boolean } = {},
  ): VerifiedIdentityDoc {
    const devices = opts.devices ?? this.devices.map((d) => d.did);
    const keyholders = opts.keyholders ?? this.keyholders.filter((k) => devices.includes(k));
    const prev = this.docs.length > 0 ? this.doc : undefined;
    const jws = createIdentityDoc(this.ik, {
      ver: prev ? prev.ver + 1 : 1,
      prev: prev ? prev.hash : null,
      name: this.name,
      relays: opts.relays ?? this.relays,
      devices,
      keyholders,
      by: opts.by ?? keyholders[0] ?? this.dev.did,
      ...(opts.certs === false ? {} : { certs: this.devices.filter((d) => devices.includes(d.did)).map((d) => d.cert) }),
      ...(opts.proofs ? { proofs: opts.proofs } : {}),
      ...(opts.profile ? { profile: opts.profile } : {}),
      iat: opts.iat ?? NOW - 600,
      ttlSec: opts.ttlSec,
    });
    const doc = verifyIdentityDocSignature(jws);
    this.docs.push(doc);
    return doc;
  }

  /** A friend cap for `sub` from this user's first device. */
  friendCap(sub: string, opts: { iat?: number } = {}): string {
    return createCap(this.dev, this.dev.cert, { purpose: "friend", sub, relays: this.relays, iat: opts.iat ?? NOW - 60 });
  }

  joinCap(opts: { iat?: number; ttlSec?: number } = {}): string {
    return createCap(this.dev, this.dev.cert, { purpose: "join", relays: this.relays, iat: opts.iat ?? NOW - 60, ttlSec: opts.ttlSec });
  }

  signer(d: TestDevice = this.dev) {
    return { userId: this.userId, did: d.did, signingSecretKey: d.signingSecretKey };
  }
}

/** A user with one key-holding device and a published version 1. */
export function makeUser(name: string): TestUser {
  const u = new TestUser(name);
  u.addDevice();
  u.publish();
  return u;
}

/** A store that holds every version of each user's document. */
export async function storeKnowing(...users: TestUser[]): Promise<MemoryTrustStoreV3> {
  const s = new MemoryTrustStoreV3();
  await learn(s, ...users);
  return s;
}

export async function learn(s: TrustStoreV3, ...users: TestUser[]): Promise<void> {
  for (const u of users) for (const d of u.docs) await addIdentityVersion(s, d.jws, { now: NOW });
}

export function ctxFor(store: TrustStoreV3, now = NOW): SignerContext {
  return storeSignerContext(store, { now });
}

/** A resolver context that knows the given users' latest documents (no store). */
export function staticCtx(users: TestUser[], now = NOW): SignerContext {
  const byId = new Map(users.map((u) => [u.userId, u]));
  return {
    now,
    resolveCert: (userId, did) => byId.get(userId)?.devices.find((d) => d.did === did)?.cert,
    resolveIdentity: (userId) => {
      const u = byId.get(userId);
      return u ? { iss: u.userId, ik: u.doc.ik, devices: u.doc.devices } : undefined;
    },
  };
}

let seqCounter = 1;

export function seal(
  from: TestUser,
  to: TestUser,
  kind: EnvelopeKindV3,
  plaintext: object,
  opts: { own?: string; sid?: string; seq?: number; tsMs?: number; fromDev?: TestDevice; toDev?: TestDevice } = {},
): string {
  const fd = opts.fromDev ?? from.dev;
  const td = opts.toDev ?? to.dev;
  const sid = opts.sid ?? (kind === "contact" ? "~contact" : kind === "circle" ? "~circle" : "s1");
  return sealEnvelopeV3({
    from: from.userId,
    fdid: fd.did,
    fcert: fd.cert,
    to: to.userId,
    tdid: td.did,
    own: opts.own ?? from.userId,
    sid,
    seq: opts.seq ?? seqCounter++,
    ts: opts.tsMs ?? NOW_MS,
    kind,
    plaintext,
    sender: fd,
    recipientKpk: td.agreementPublicKey,
  });
}

export const DAYS = (n: number) => n * DAY;
