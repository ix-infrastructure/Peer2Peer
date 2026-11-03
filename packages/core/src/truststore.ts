// Copyright 2026 Ix Infrastructure Inc.
//
// Local trust state: friendships, unfriends, rosters (highest ver per
// (iss, sid)), the Kartr JWKS cache, the revocation list, replay state and a
// device-certificate cache. Everything stored here was verified before it was
// written; the store itself does no cryptography.
//
// FileTrustStore keeps one JSON document per kind under a caller-supplied
// directory (default ~/.ix/p2p, mode 0700, files 0600, atomic replace). The
// backends live in docbackend.ts (pure) and filebackend.ts (Node file I/O and
// the cross-process lock), shared with the v3 store.

export * from "./docbackend.js";
export * from "./filebackend.js";

import { fail } from "./errors.js";
import { MemoryDocBackend, type DocBackend } from "./docbackend.js";
import { defaultTrustDir, FileDocBackend, type LockOptions } from "./filebackend.js";
import type { JwksCacheStore } from "./jwks.js";
import { checkReplay, mergeReplay, recordReplay, type ReplayFields, type ReplayRecord, type ReplayVerdict } from "./replay.js";
import type { FriendshipProof } from "./objects.js";

export interface StoredFriendship {
  inviter: string;
  invitee: string;
  inv: string;
  aud: string;
  /** The accept's iat. */
  iat: number;
  /** The invite's iat. */
  inviteIat: number;
  /** Signer devices, so a later revocation of either ends the friendship. */
  inviteDid: string;
  acceptDid: string;
  proof: FriendshipProof;
}

export interface StoredUnfriend {
  iss: string;
  peer: string;
  inv: string;
  iat: number;
  jws: string;
}

export interface StoredRoster {
  iss: string;
  sid: string;
  ver: number;
  jws: string;
}

export interface StoredRevocations {
  iat: number;
  dids: string[];
  jws: string;
  /** When this device last successfully polled the list (ms since the epoch). */
  fetchedAt: number;
}

export interface StoredDeviceCert {
  userId: string;
  did: string;
  exp: number;
  jws: string;
}

/** An invite this device issued, kept so a returning accept can be matched (D8). */
export interface StoredOutgoingInvite {
  /** b64u(sha256(invite compact)): what an accept cites. */
  inv: string;
  aud: string;
  exp: number;
  jws: string;
}

/** A verified Kartr workspace attestation of a session owner, cached for D9. */
export interface StoredOwnerWorkspace {
  userId: string;
  exp: number;
  jws: string;
}

export type RosterPutResult = "stored" | "same" | "stale" | "conflict";

export interface TrustStore extends JwksCacheStore {
  listFriendships(): Promise<StoredFriendship[]>;
  /** Idempotent. Throws invite-already-bound if `inv` is bound to another pair. */
  addFriendship(f: StoredFriendship): Promise<void>;
  listUnfriends(): Promise<StoredUnfriend[]>;
  addUnfriend(u: StoredUnfriend): Promise<void>;
  getRoster(iss: string, sid: string): Promise<StoredRoster | undefined>;
  /** Keeps the highest ver per (iss, sid). */
  putRoster(r: StoredRoster): Promise<RosterPutResult>;
  getRevocations(): Promise<StoredRevocations | undefined>;
  /**
   * Replaces the list only with a newer one (by iat) and returns whether it
   * did; re-polling the same list just refreshes `fetchedAt`.
   */
  putRevocations(r: StoredRevocations): Promise<boolean>;
  getReplay(fdid: string): Promise<ReplayRecord | undefined>;
  /** Merges into the stored record (union of nonces, max seq): never overwrites. */
  putReplay(fdid: string, r: ReplayRecord): Promise<void>;
  /** Atomic check-and-record: undefined (and recorded) when fresh, else why not. */
  admitReplay(fdid: string, p: ReplayFields, nowMs: number): Promise<ReplayVerdict>;
  getDeviceCert(did: string): Promise<StoredDeviceCert | undefined>;
  addOutgoingInvite(i: StoredOutgoingInvite): Promise<void>;
  getOutgoingInvite(inv: string): Promise<StoredOutgoingInvite | undefined>;
  /** D9: the cached owner attestation for `userId` (re-verify before use). */
  getOwnerWorkspace(userId: string): Promise<StoredOwnerWorkspace | undefined>;
  /** Keeps the attestation with the latest exp per owner. */
  putOwnerWorkspace(w: StoredOwnerWorkspace): Promise<void>;
  putDeviceCert(c: StoredDeviceCert): Promise<void>;
}

type Docs = {
  friendships: StoredFriendship[];
  unfriends: StoredUnfriend[];
  rosters: Record<string, StoredRoster>;
  jwks: { fetchedAt: number; jwks: unknown };
  revocations: StoredRevocations;
  replay: Record<string, ReplayRecord>;
  devices: Record<string, StoredDeviceCert>;
  outgoing: Record<string, StoredOutgoingInvite>;
  ownerWorkspaces: Record<string, StoredOwnerWorkspace>;
};

const rosterKey = (iss: string, sid: string) => JSON.stringify([iss, sid]);

/** TrustStore over any DocBackend. Mutations are serialised in-process. */
export class DocTrustStore implements TrustStore {
  private chain: Promise<unknown> = Promise.resolve();

  constructor(private readonly backend: DocBackend) {}

  private async get<K extends keyof Docs>(name: K): Promise<Docs[K] | undefined> {
    return (await this.backend.read(name)) as Docs[K] | undefined;
  }

  private mutate<K extends keyof Docs, R>(name: K, fn: (cur: Docs[K] | undefined) => { next?: Docs[K]; result: R }) {
    const rmw = async () => {
      const { next, result } = fn(await this.get(name));
      if (next !== undefined) await this.backend.write(name, next);
      return result;
    };
    const run = this.chain.then(() => (this.backend.withLock ? this.backend.withLock(rmw) : rmw()));
    this.chain = run.catch(() => {});
    return run;
  }

  async listFriendships() {
    return (await this.get("friendships")) ?? [];
  }

  async addFriendship(f: StoredFriendship) {
    await this.mutate("friendships", (cur = []) => {
      const existing = cur.find((x) => x.inv === f.inv);
      if (existing) {
        if (existing.inviter !== f.inviter || existing.invitee !== f.invitee) {
          fail("invite-already-bound", `invite already accepted by ${existing.invitee}`);
        }
        return { result: undefined };
      }
      return { next: [...cur, f], result: undefined };
    });
  }

  async listUnfriends() {
    return (await this.get("unfriends")) ?? [];
  }

  async addUnfriend(u: StoredUnfriend) {
    await this.mutate("unfriends", (cur = []) =>
      cur.some((x) => x.jws === u.jws) ? { result: undefined } : { next: [...cur, u], result: undefined },
    );
  }

  async getRoster(iss: string, sid: string) {
    return (await this.get("rosters"))?.[rosterKey(iss, sid)];
  }

  putRoster(r: StoredRoster): Promise<RosterPutResult> {
    return this.mutate("rosters", (cur = {}) => {
      const k = rosterKey(r.iss, r.sid);
      const old = cur[k];
      if (old) {
        if (r.ver < old.ver) return { result: "stale" as const };
        if (r.ver === old.ver) return { result: old.jws === r.jws ? ("same" as const) : ("conflict" as const) };
      }
      return { next: { ...cur, [k]: r }, result: "stored" as const };
    });
  }

  async getJwks() {
    return this.get("jwks");
  }

  async putJwks(entry: { fetchedAt: number; jwks: unknown }) {
    await this.mutate("jwks", () => ({ next: entry, result: undefined }));
  }

  async getRevocations() {
    return this.get("revocations");
  }

  putRevocations(r: StoredRevocations): Promise<boolean> {
    return this.mutate("revocations", (cur) => {
      if (!cur || r.iat > cur.iat) return { next: r, result: true };
      if (r.iat === cur.iat && r.fetchedAt > cur.fetchedAt) return { next: { ...cur, fetchedAt: r.fetchedAt }, result: false };
      return { result: false };
    });
  }

  async getReplay(fdid: string) {
    return (await this.get("replay"))?.[fdid];
  }

  async putReplay(fdid: string, r: ReplayRecord) {
    await this.mutate("replay", (cur = {}) => ({ next: { ...cur, [fdid]: mergeReplay(cur[fdid], r) }, result: undefined }));
  }

  admitReplay(fdid: string, p: ReplayFields, nowMs: number): Promise<ReplayVerdict> {
    return this.mutate("replay", (cur = {}) => {
      const verdict = checkReplay(p, cur[fdid], nowMs);
      if (verdict) return { result: verdict };
      return { next: { ...cur, [fdid]: recordReplay(p, cur[fdid]) }, result: undefined };
    });
  }

  async getDeviceCert(did: string) {
    return (await this.get("devices"))?.[did];
  }

  async putDeviceCert(c: StoredDeviceCert) {
    await this.mutate("devices", (cur = {}) => {
      const old = cur[c.did];
      if (old && old.exp >= c.exp && old.jws !== c.jws) return { result: undefined }; // keep the longer-lived
      return { next: { ...cur, [c.did]: c }, result: undefined };
    });
  }

  async addOutgoingInvite(i: StoredOutgoingInvite) {
    await this.mutate("outgoing", (cur = {}) => ({ next: { ...cur, [i.inv]: i }, result: undefined }));
  }

  async getOutgoingInvite(inv: string) {
    return (await this.get("outgoing"))?.[inv];
  }

  async getOwnerWorkspace(userId: string) {
    return (await this.get("ownerWorkspaces"))?.[userId];
  }

  async putOwnerWorkspace(w: StoredOwnerWorkspace) {
    await this.mutate("ownerWorkspaces", (cur = {}) => {
      const old = cur[w.userId];
      if (old && old.exp >= w.exp) return { result: undefined };
      return { next: { ...cur, [w.userId]: w }, result: undefined };
    });
  }
}

export class MemoryTrustStore extends DocTrustStore {
  constructor() {
    super(new MemoryDocBackend());
  }
}

export class FileTrustStore extends DocTrustStore {
  constructor(
    readonly dir: string = defaultTrustDir(),
    lockOpts: Partial<LockOptions> = {},
  ) {
    super(new FileDocBackend(dir, lockOpts));
  }
}
