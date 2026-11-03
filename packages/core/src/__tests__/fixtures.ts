// Copyright 2026 Ix Infrastructure Inc.
//
// An in-memory Kartr authority and device directory for tests.

import { ed25519PublicKey, randomBytes } from "../crypto.js";
import { b64uEncode } from "../encoding.js";
import { jwkFromPublicKey, kartrKeyId, staticKartrKeys, type KartrKeys } from "../jwks.js";
import { generateDeviceKeys, type DeviceKeys } from "../keys.js";
import {
  signDeviceCert,
  signRevocationList,
  signWorkspaceAttestation,
  type CertResolver,
  type DeviceVerifyOptions,
} from "../objects.js";
import { decodeJws } from "../jws.js";
import { sealEnvelope, type EnvelopeKind, type EnvelopePlaintext } from "../envelope.js";
import { MemoryTrustStore, type TrustStore } from "../truststore.js";
import { updateRevocations, verifyIncoming, type IncomingResult } from "../verify.js";
import type { FriendshipProof } from "../objects.js";

export const NOW = 1_800_000_000; // seconds
export const NOW_MS = NOW * 1000;

export class FakeKartr {
  readonly sk = randomBytes(32);
  readonly kid = kartrKeyId(
    `projects/test/locations/global/keyRings/p2p/cryptoKeys/attest/cryptoKeyVersions/${b64uEncode(randomBytes(6))}`,
  );
  readonly certs = new Map<string, string>(); // did -> cert
  readonly revoked = new Set<string>();

  get jwks() {
    return { keys: [jwkFromPublicKey(this.kid, ed25519PublicKey(this.sk))] };
  }

  keys(): KartrKeys {
    return staticKartrKeys(this.jwks);
  }

  issueCert(dev: DeviceKeys, opts: { iat?: number; exp?: number } = {}): string {
    const iat = opts.iat ?? NOW - 3600;
    const cert = signDeviceCert(
      {
        sub: dev.userId,
        did: dev.deviceId,
        spk: b64uEncode(dev.signingPublicKey),
        kpk: b64uEncode(dev.agreementPublicKey),
        iat,
        exp: opts.exp ?? iat + 30 * 24 * 3600,
      },
      this.sk,
      this.kid,
    );
    this.certs.set(dev.deviceId, cert);
    return cert;
  }

  attest(userId: string, orgs: string[], opts: { iat?: number; exp?: number } = {}): string {
    const iat = opts.iat ?? NOW - 60;
    return signWorkspaceAttestation({ sub: userId, orgs, iat, exp: opts.exp ?? iat + 24 * 3600 }, this.sk, this.kid);
  }

  revocations(iat = NOW): string {
    return signRevocationList({ dids: [...this.revoked], iat }, this.sk, this.kid);
  }

  resolver(): CertResolver {
    return async (_userId, did) => this.certs.get(did);
  }

  verifyOpts(extra: Partial<DeviceVerifyOptions> = {}): DeviceVerifyOptions {
    return {
      kartr: this.keys(),
      now: NOW,
      resolveCert: this.resolver(),
      isRevoked: (did) => this.revoked.has(did),
      ...extra,
    };
  }

  /** A device with a fresh cert. */
  device(userId: string): DeviceKeys & { cert: string } {
    const dev = generateDeviceKeys(userId);
    return { ...dev, cert: this.issueCert(dev) };
  }
}

// ---------------------------------------------------------------------------
// Peers: a device plus its TrustStore, talking through a shared FakeKartr.

export class Peer {
  readonly keys: DeviceKeys & { cert: string };
  readonly trust: TrustStore;
  private seqs = new Map<string, number>();
  /** sid -> session owner, learned from rosters sent or received. */
  private owners = new Map<string, string>();
  nowMs = NOW_MS;
  workspace?: string;
  /** The certificate sent as fcert (tests swap in forged/expired ones). */
  cert: string;
  friendships = new Map<string, FriendshipProof>(); // peer userId -> proof
  /** Session owner userId -> that owner's workspace attestation, relayed as ownerWorkspace (D9). */
  ownerWorkspaces = new Map<string, string>();

  constructor(
    readonly kartr: FakeKartr,
    userId: string,
    trust: TrustStore = new MemoryTrustStore(),
  ) {
    this.keys = kartr.device(userId);
    this.cert = this.keys.cert;
    this.trust = trust;
  }

  get userId() {
    return this.keys.userId;
  }

  seal(
    to: Peer,
    opts: {
      sid: string;
      own?: string;
      text?: string;
      kind?: EnvelopeKind;
      roster?: string;
      friendship?: FriendshipProof;
      seq?: number;
      ts?: number;
      fcert?: string;
      plaintext?: Partial<EnvelopePlaintext>;
    },
  ): string {
    if (opts.roster) this.owners.set(opts.sid, decodeJws(opts.roster).payload.iss as string);
    const own = opts.own ?? this.owners.get(opts.sid) ?? this.userId;
    const key = `${to.keys.deviceId}|${own}|${opts.sid}`;
    const seq = opts.seq ?? (this.seqs.get(key) ?? 0) + 1;
    this.seqs.set(key, seq);
    const friendship = opts.friendship ?? this.friendships.get(to.userId);
    const plaintext: EnvelopePlaintext = {
      text: opts.text ?? "hello",
      ...(opts.roster ? { roster: opts.roster } : {}),
      ...(this.ownerWorkspaces.has(own) ? { ownerWorkspace: this.ownerWorkspaces.get(own) } : {}),
      sender: {
        ...(this.workspace ? { workspace: this.workspace } : {}),
        ...(friendship ? { friendship } : {}),
      },
      ...opts.plaintext,
    };
    return sealEnvelope({
      from: this.userId,
      fdid: this.keys.deviceId,
      fcert: opts.fcert ?? this.cert,
      to: to.userId,
      tdid: to.keys.deviceId,
      own,
      sid: opts.sid,
      seq,
      ts: opts.ts ?? this.nowMs,
      kind: opts.kind ?? "msg",
      plaintext,
      sender: this.keys,
      recipientKpk: to.keys.agreementPublicKey,
    });
  }

  /** Poll the revocation list before each receive (tests that need a stale list turn this off). */
  autoPoll = true;

  async receive(envelope: string): Promise<IncomingResult> {
    if (this.autoPoll) {
      const now = Math.floor(this.nowMs / 1000);
      await updateRevocations(this.trust, this.kartr.revocations(now), { kartr: this.kartr.keys(), now, nowMs: this.nowMs });
    }
    const r = await verifyIncoming(envelope, {
      self: { ...this.keys, cert: this.cert, workspace: this.workspace },
      kartr: this.kartr.keys(),
      trust: this.trust,
      resolveCert: this.kartr.resolver(),
      nowMs: this.nowMs,
    });
    if (r.ok) this.owners.set(r.envelope.sid, r.envelope.own);
    return r;
  }
}
