// Copyright 2026 Ix Infrastructure Inc.
//
// Circles (docs/protocol.md §3.3): single-owner, hash-chained membership
// lists that count only with each member's consent.
//
// Circle version (`p2p-circle+jws`, `kid: "ik"`): accepted only when
//  1. cid recomputes from founder and nonce;
//  2. owner == "p2p:" + b32(H(ik)); the version is signed by the owner named
//     in version ver-1 (by its own ik for ver 1); the signer is not in the
//     §2.5 fail-closed state when it becomes the new head;
//  3. ver 1: prev null and owner == founder. ver > 1: prev ==
//     jwsHash(version ver-1). When the owner changes, the version carries
//     `transfer`: a `p2p-circle-accept+jws` signed by the new owner's ik over
//     {cid, ver, prev}. Versions are never skipped;
//  4. every admin, and the owner, is in members.
//
// Reading of rule 2 for transfer versions: `owner`/`ik` name the successor
// (owner == H(ik) always holds), while the JWS is signed by the previous
// owner, verified under ver-1's `ik`. The successor's consent is `transfer`,
// verified under this version's `ik`. So every version is checkable from its
// parent alone and history stays self-certifying.
//
// Concurrency (only the owner's devices sign):
//  - a sibling replaces the client's branch only when its signer is the owner
//    of the client's current head [review 5, high 1]; everything at or before
//    the latest transfer held is final;
//  - a transfer beats any non-transfer sibling and is never replaced
//    [review 6]. Two different transfer siblings freeze the circle, but only
//    while the client's head is their parent or while bootstrapping; a client
//    already past a transfer ignores (and alerts on) siblings from anyone but
//    the current head's owner [review 7];
//  - between the current owner's other siblings, the lowest jwsHash wins.
// Bootstrap needs the full chain from version 1 [review 5, high 2].

import { b64uDecode, b64uEncode, fromUtf8, utf8 } from "../encoding.js";
import { assertStrongEd25519PublicKey } from "../crypto.js";
import { signJws, verifyJws, MAX_JWS_BYTES } from "../jws.js";
import { fail, P2PError } from "../errors.js";
import {
  asciiCompare,
  bytesField,
  checkIssued,
  cidField,
  circleIdFor,
  DAY,
  decodeTyped,
  DEFAULT_SKEW_SEC,
  HOUR,
  IK_KID,
  int,
  isUserId,
  jwsHash,
  newNonce,
  checkFields,
  nowSec,
  str,
  strArray,
  TYP3,
  userIdField,
  userIdFromIk,
  type Obj,
  type TimeOptions,
} from "./base.js";
import { verifyCap, type VerifiedCap } from "./caps.js";
import type { VerifiedDeviceCertV3 } from "./device.js";
import type { DeviceSignerV3 } from "./friends.js";
import type { IdentityKey } from "./identity.js";
import type { IdentityFreshness } from "./identitydoc.js";
import { sanitizePeerText, PEER_TEXT_CAPS } from "./sanitize.js";
import { verifyDeviceSignedV3, type SignerContext } from "./signers.js";

export const CIRCLE_NAME_MAX = 128;
export const MAX_CIRCLE_MEMBERS = 1000;
/** §3.3: proposals older than this are dropped, and applied nonces pruned. */
export const PROPOSAL_MAX_AGE_SEC = 30 * DAY;
/** §3.3: the owner re-sends the head this often. */
export const HEAD_RESEND_SEC = 24 * HOUR;
/** §3.3: a member whose head is this much older than the newest heard of catches up. */
export const HEAD_CATCH_UP_SEC = 72 * HOUR;
/** §3.3: joiners wait this long for confirmation answers. */
export const JOIN_CONFIRM_WAIT_SEC = 24 * HOUR;
/** Draft 3 additions: default cap on automatic accepts per rolling hour in an open circle. */
export const OPEN_JOIN_MAX_PER_HOUR = 20;
/** Pending (out-of-order) versions kept while a gap is filled. */
export const MAX_PENDING_VERSIONS = 256;

export type CirclePolicy = "invite" | "open";

// ---------------------------------------------------------------------------
// Versions

export interface CircleVersionPayload {
  cid: string;
  founder: string;
  nonce: string;
  ver: number;
  prev: string | null;
  owner: string;
  ik: string;
  name: string;
  admins: string[];
  members: string[];
  transfer?: string;
  /** Draft 3 additions: "invite" (default) or "open". */
  policy?: CirclePolicy;
  iat: number;
}

export interface VerifiedCircleVersion extends CircleVersionPayload {
  jws: string;
  hash: string;
  /** The userId whose ik signed this version (the owner of ver-1, or the founder for ver 1). */
  signer: string;
  isTransfer: boolean;
}

const VERSION_FIELDS = ["cid", "founder", "nonce", "ver", "prev", "owner", "ik", "name", "admins", "members", "transfer", "policy", "iat"];

function userIdList(o: Obj, k: string): string[] {
  return strArray(o, k, {
    max: MAX_CIRCLE_MEMBERS,
    item: (u) => {
      if (!isUserId(u)) fail("malformed", `${k} entry ${u} is not a userId`);
    },
  });
}

/** Identity keys already checked strong (small-order and torsion checks are costly). */
const strongIks = new Set<string>();

/** Structural checks plus rules 1 and 4 and owner == H(ik). No signature. */
export function parseCircleVersion(jws: string): CircleVersionPayload {
  const d = decodeTyped(jws, TYP3.circle);
  if (d.header.kid !== IK_KID) fail("kid-mismatch", `kid ${d.header.kid} != ${IK_KID}`);
  const p = d.payload;
  checkFields(p, VERSION_FIELDS, "circle version");
  const ver = int(p, "ver", 1);
  const v: CircleVersionPayload = {
    cid: cidField(p, "cid"),
    founder: userIdField(p, "founder"),
    nonce: bytesField(p, "nonce", 16),
    ver,
    prev: ver === 1 ? null : bytesField(p, "prev", 32),
    owner: userIdField(p, "owner"),
    ik: bytesField(p, "ik", 32),
    name: str(p, "name"),
    admins: userIdList(p, "admins"),
    members: userIdList(p, "members"),
    iat: int(p, "iat"),
  };
  if (ver === 1 && p.prev !== null) fail("circle-invalid", "ver 1 must have prev: null");
  if ([...v.name].length > CIRCLE_NAME_MAX) fail("malformed", "circle name too long");
  if (p.transfer !== undefined) v.transfer = str(p, "transfer");
  if (p.policy !== undefined) {
    if (p.policy !== "invite" && p.policy !== "open") fail("malformed", 'policy must be "invite" or "open"');
    v.policy = p.policy;
  }
  // Rule 1.
  if (circleIdFor(v.founder, v.nonce) !== v.cid) fail("circle-invalid", "cid does not recompute from founder and nonce");
  // Rule 2 (first half): owner is the fingerprint of ik.
  const ik = b64uDecode(v.ik, 32);
  // Every version of a circle names the same few iks: check each key once (review N3, perf).
  if (!strongIks.has(v.ik)) {
    assertStrongEd25519PublicKey(ik);
    strongIks.add(v.ik);
    if (strongIks.size > 1024) strongIks.delete(strongIks.values().next().value!);
  }
  if (userIdFromIk(ik) !== v.owner) fail("circle-signer", "owner is not the fingerprint of ik");
  // Rule 3 for ver 1.
  if (ver === 1 && v.owner !== v.founder) fail("circle-invalid", "ver 1 owner must be the founder");
  if (ver === 1 && v.transfer !== undefined) fail("circle-invalid", "ver 1 can't carry a transfer");
  // Rule 4.
  if (!v.members.includes(v.owner)) fail("circle-invalid", "the owner must be a member");
  for (const a of v.admins) if (!v.members.includes(a)) fail("circle-invalid", `admin ${a} is not a member`);
  return v;
}

export interface CircleTransferPayload {
  iss: string;
  ik: string;
  cid: string;
  ver: number;
  prev: string;
  iat: number;
}

/** The new owner's consent to take over at exactly `{cid, ver, prev}`. */
export function createCircleTransferAccept(newOwner: IdentityKey, at: { cid: string; ver: number; prev: string; iat?: number }): string {
  const payload: CircleTransferPayload = {
    iss: newOwner.userId,
    ik: b64uEncode(newOwner.publicKey),
    cid: at.cid,
    ver: at.ver,
    prev: at.prev,
    iat: at.iat ?? nowSec(),
  };
  return signJws(TYP3.circleAccept, IK_KID, payload, newOwner.secretKey);
}

function verifyTransfer(v: CircleVersionPayload): void {
  if (v.transfer === undefined) fail("circle-transfer", "ownership changed without transfer");
  const d = decodeTyped(v.transfer, TYP3.circleAccept);
  if (d.header.kid !== IK_KID) fail("kid-mismatch", "transfer kid");
  const p = d.payload;
  checkFields(p, ["iss", "ik", "cid", "ver", "prev", "iat"], "transfer");
  const t: CircleTransferPayload = {
    iss: userIdField(p, "iss"),
    ik: bytesField(p, "ik", 32),
    cid: cidField(p, "cid"),
    ver: int(p, "ver", 2),
    prev: bytesField(p, "prev", 32),
    iat: int(p, "iat"),
  };
  if (t.iss !== v.owner || t.ik !== v.ik) fail("circle-transfer", "transfer is not signed by the new owner");
  if (t.cid !== v.cid || t.ver !== v.ver || t.prev !== v.prev) fail("circle-transfer", "transfer consents to another state");
  verifyJws(v.transfer, { typ: TYP3.circleAccept, kid: IK_KID, publicKey: b64uDecode(t.ik, 32), badSignature: "circle-transfer" });
}

/** Verifies a version 1 (genesis): signed by the founder's own ik. */
export function verifyCircleGenesis(jws: string, parsed?: CircleVersionPayload): VerifiedCircleVersion {
  const v = parsed ?? parseCircleVersion(jws);
  if (v.ver !== 1) fail("circle-chain-broken", "not a version 1");
  verifyJws(jws, { typ: TYP3.circle, kid: IK_KID, publicKey: b64uDecode(v.ik, 32), badSignature: "circle-signer" });
  return { ...v, jws, hash: jwsHash(jws), signer: v.owner, isTransfer: false };
}

/**
 * A lone version, checked as far as it can be without its chain: version 1 as a genesis, a later one
 * under its own ik (its signer is its owner unless the version is a transfer, which verifies only
 * against its parent: refused here). It proves the version was signed by the owner it names, not
 * that it is the circle's current head or that this owner really holds the circle: a P4 code's
 * preview shows what such a version says, and the join itself checks the circle's real chain.
 */
export function verifyCircleVersionAlone(jws: string): VerifiedCircleVersion {
  const v = parseCircleVersion(jws);
  if (v.ver === 1) return verifyCircleGenesis(jws, v);
  if (v.transfer !== undefined) fail("circle-gap", "a transfer version verifies only against its parent");
  verifyJws(jws, { typ: TYP3.circle, kid: IK_KID, publicKey: b64uDecode(v.ik, 32), badSignature: "circle-signer" });
  return { ...v, jws, hash: jwsHash(jws), signer: v.owner, isTransfer: false };
}

/** Verifies `jws` as the child of `parent` (rules 1–4; signer = parent's owner). */
export function verifyCircleLink(parent: VerifiedCircleVersion, jws: string, parsed?: CircleVersionPayload): VerifiedCircleVersion {
  const v = parsed ?? parseCircleVersion(jws);
  if (v.cid !== parent.cid || v.founder !== parent.founder || v.nonce !== parent.nonce) fail("circle-invalid", "another circle");
  if (v.ver !== parent.ver + 1) fail("circle-chain-broken", `ver ${v.ver} != ${parent.ver} + 1`);
  if (v.prev !== parent.hash) fail("circle-chain-broken", "prev is not jwsHash of the parent");
  // Rule 3: the signer is the owner named in ver-1, so verify under its ik.
  verifyJws(jws, { typ: TYP3.circle, kid: IK_KID, publicKey: b64uDecode(parent.ik, 32), badSignature: "circle-signer" });
  const isTransfer = v.owner !== parent.owner;
  if (isTransfer) verifyTransfer(v);
  else {
    if (v.transfer !== undefined) fail("circle-transfer", "transfer without a change of owner");
    if (v.ik !== parent.ik) fail("circle-signer", "ik changed without a change of owner");
  }
  return { ...v, jws, hash: jwsHash(jws), signer: parent.owner, isTransfer };
}

export interface CreateCircleParams {
  name: string;
  members?: string[];
  admins?: string[];
  policy?: CirclePolicy;
  nonce?: string;
  iat?: number;
}

/** Founds a circle: version 1, signed by the founder (its first owner). */
export function createCircle(founder: IdentityKey, p: CreateCircleParams): string {
  const nonce = p.nonce ?? newNonce();
  const members = [...new Set([founder.userId, ...(p.members ?? [])])];
  const payload: CircleVersionPayload = {
    cid: circleIdFor(founder.userId, nonce),
    founder: founder.userId,
    nonce,
    ver: 1,
    prev: null,
    owner: founder.userId,
    ik: b64uEncode(founder.publicKey),
    name: p.name,
    admins: p.admins ?? [],
    members,
    ...(p.policy !== undefined ? { policy: p.policy } : {}),
    iat: p.iat ?? nowSec(),
  };
  return signVersion(founder, payload);
}

export interface NextVersionParams {
  name?: string;
  admins?: string[];
  members?: string[];
  policy?: CirclePolicy;
  /** Hand ownership to this identity: needs its `transfer` accept. */
  newOwner?: { userId: string; ik: string; transfer: string };
  iat?: number;
}

/** The owner's next version on top of `head`. */
export function createNextCircleVersion(owner: IdentityKey, head: VerifiedCircleVersion, p: NextVersionParams = {}): string {
  if (owner.userId !== head.owner) fail("circle-signer", "only the current owner signs the next version");
  const payload: CircleVersionPayload = {
    cid: head.cid,
    founder: head.founder,
    nonce: head.nonce,
    ver: head.ver + 1,
    prev: head.hash,
    owner: p.newOwner?.userId ?? head.owner,
    ik: p.newOwner?.ik ?? head.ik,
    name: p.name ?? head.name,
    admins: p.admins ?? head.admins,
    members: p.members ?? head.members,
    ...(p.newOwner ? { transfer: p.newOwner.transfer } : {}),
    ...((p.policy ?? head.policy) !== undefined ? { policy: p.policy ?? head.policy } : {}),
    iat: p.iat ?? nowSec(),
  };
  return signVersion(owner, payload);
}

function signVersion(signer: IdentityKey, payload: CircleVersionPayload): string {
  const jws = signJws(TYP3.circle, IK_KID, payload, signer.secretKey);
  if (jws.length > MAX_JWS_BYTES) fail("malformed", `circle version is ${jws.length} bytes, max ${MAX_JWS_BYTES}`);
  parseCircleVersion(jws);
  return jws;
}

export function circlePolicy(v: Pick<CircleVersionPayload, "policy">): CirclePolicy {
  return v.policy ?? "invite";
}

/** The circle name, sanitized for display (§4.3). */
export function circleDisplayName(v: Pick<CircleVersionPayload, "name">): string {
  return sanitizePeerText(v.name, PEER_TEXT_CAPS.name);
}

// ---------------------------------------------------------------------------
// The client's chain

export type CircleReceiveStatus =
  /** Became the new head (extension). */
  | "accepted"
  /** Replaced part of the chain (a winning sibling). */
  | "replaced"
  | "duplicate"
  /** A losing sibling, or one from an unknown or discarded branch. */
  | "ignored"
  /** Held until the missing versions arrive. */
  | "gap"
  /** The circle is frozen: nothing is accepted. */
  | "frozen"
  | "rejected";

export interface CircleReceiveResult {
  status: CircleReceiveStatus;
  hash?: string;
  /** Hashes dropped from the chain by a replacement. */
  discarded?: string[];
  /** Ask any member for these (§4.3 `circle` `want`). */
  want?: { cid: string; fromVer: number };
  /** Show this to the user. */
  alert?: string;
  reason?: string;
}

export interface CircleChainOptions extends TimeOptions {
  /**
   * The §2.5 freshness of a userId's identity (for the owner check of rule
   * 2), or undefined when unknown. Only "fail-closed" blocks.
   */
  identityFreshness?: (userId: string) => IdentityFreshness | undefined;
}

export interface StoredCircleChain {
  cid: string;
  versions: string[];
  pending?: string[];
  /** Valid versions off the chain (losing siblings and their descendants), kept so a later version can complete a winning branch. */
  side?: string[];
  frozen?: { at: string; reason: string };
}

/** How far past the head a pending (out-of-order) version may claim to be (pre-release review L2). */
export const MAX_PENDING_AHEAD = 64;
/** Off-chain versions kept for branch comparison; the oldest go first. */
export const MAX_SIDE_VERSIONS = 256;

/** A batch entry, parsed once (parseCircleVersion's payload; `error` when it didn't parse). */
interface Parsed {
  j: string;
  hash: string;
  p?: CircleVersionPayload;
  error?: P2PError;
}

export class CircleChain {
  private chain: VerifiedCircleVersion[] = [];
  /** hash -> index on the chain. */
  private chainIndex = new Map<string, number>();
  /** Out-of-order versions waiting for their parent, parsed once; insertion order = age (oldest evicted first). */
  private pending = new Map<string, Parsed>();
  /** Valid versions that are not on the chain, keyed by hash. */
  private side = new Map<string, VerifiedCircleVersion>();
  private frozenAt?: { at: string; reason: string };
  private bootstrapping = false;

  private constructor(readonly cid: string) {}

  /**
   * §3.3 bootstrap: the full chain from version 1. `versions` may hold
   * siblings and arrive in any order. The chain is built incrementally with
   * exactly the receive() rules (transfer finality included, pre-release review L1),
   * so every client reaches the same chain from the same set of versions.
   * Two different transfers of the same parent anywhere freeze the circle at
   * that parent (bootstrapping). When `head` is given, it must end up on the
   * chain (the offered head of an invite), else `circle-gap`. Only the new
   * head's signer must be valid now; history is vouched for by `prev`.
   */
  static bootstrap(versions: readonly string[], opts: CircleChainOptions & { head?: string } = {}): CircleChain {
    const geneses: VerifiedCircleVersion[] = [];
    const rest: string[] = [];
    for (const j of new Set(versions)) {
      const p = parseCircleVersion(j);
      if (p.ver === 1) geneses.push(verifyCircleGenesis(j));
      else rest.push(j);
    }
    if (geneses.length === 0) fail("circle-gap", "bootstrap needs version 1");
    const cid = geneses[0].cid;
    if (geneses.some((g) => g.cid !== cid)) fail("circle-invalid", "versions of different circles");
    const c = new CircleChain(cid);
    geneses.sort((a, b) => asciiCompare(a.hash, b.hash));
    c.setChain([geneses[0]]);
    c.bootstrapping = true;
    // History is vouched for by prev: no freshness checks until the end.
    c.receive([...geneses.slice(1).map((g) => g.jws), ...rest], { now: opts.now, skewSec: opts.skewSec });
    c.bootstrapping = false;
    c.pending.clear();
    if (opts.head !== undefined && !c.chain.some((v) => v.jws === opts.head)) {
      fail("circle-gap", "the offered head is not on the canonical chain built from these versions");
    }
    c.checkSignerFresh(c.head, opts);
    return c;
  }

  /** Rebuilds a stored chain (re-verifying every link). */
  static fromStored(s: StoredCircleChain): CircleChain {
    const c = new CircleChain(s.cid);
    for (const j of s.versions) {
      c.pushChain(c.chain.length === 0 ? verifyCircleGenesis(j) : verifyCircleLink(c.head, j));
    }
    if (c.chain.length === 0 || c.chain[0].cid !== s.cid) fail("circle-invalid", "stored chain is empty or of another circle");
    // Side versions re-verify against a parent on the chain or on the side.
    const side = (s.side ?? []).map((j) => ({ j, p: parseCircleVersion(j) })).sort((a, b) => a.p.ver - b.p.ver);
    for (const { j, p } of side) {
      try {
        const parent = p.prev === null ? undefined : (c.chain[c.indexOf(p.prev)] ?? c.side.get(p.prev));
        const v = p.prev === null ? verifyCircleGenesis(j, p) : parent ? verifyCircleLink(parent, j, p) : undefined;
        if (v) c.addSide(v);
      } catch (e) {
        if (!(e instanceof P2PError)) throw e;
      }
    }
    // Pending versions are re-admitted under the L2 checks.
    for (const j of s.pending ?? []) {
      try {
        c.holdPending(jwsHash(j), j, parseCircleVersion(j));
      } catch (e) {
        if (!(e instanceof P2PError)) throw e;
      }
    }
    if (s.frozen) c.frozenAt = s.frozen;
    return c;
  }

  toStored(): StoredCircleChain {
    return {
      cid: this.cid,
      versions: this.chain.map((v) => v.jws),
      ...(this.pending.size > 0 ? { pending: [...this.pending.values()].map((x) => x.j) } : {}),
      ...(this.side.size > 0 ? { side: [...this.side.values()].map((v) => v.jws) } : {}),
      ...(this.frozenAt ? { frozen: this.frozenAt } : {}),
    };
  }

  get head(): VerifiedCircleVersion {
    return this.chain[this.chain.length - 1];
  }

  get versions(): readonly VerifiedCircleVersion[] {
    return this.chain;
  }

  get frozen(): { at: string; reason: string } | undefined {
    return this.frozenAt;
  }

  /** Number of valid off-chain versions kept for branch comparison. */
  get sideCount(): number {
    return this.side.size;
  }

  /** Number of out-of-order versions held while a gap is filled. */
  get pendingCount(): number {
    return this.pending.size;
  }

  /** True when `hash` is on the chain, i.e. an ancestor of or equal to the head. */
  hasAncestor(hash: string): boolean {
    return this.chainIndex.has(hash);
  }

  /** The `jws` of every version from `fromVer` on, for a `circle` bundle. */
  versionsFrom(fromVer: number): string[] {
    return this.chain.filter((v) => v.ver >= fromVer).map((v) => v.jws);
  }

  private checkSignerFresh(v: VerifiedCircleVersion, opts: CircleChainOptions): void {
    if (opts.identityFreshness?.(v.signer) === "fail-closed") {
      fail("circle-owner-unavailable", `${v.signer} is in the fail-closed state (§2.5)`);
    }
  }

  private lastTransferIndex(): number {
    for (let i = this.chain.length - 1; i >= 0; i--) if (this.chain[i].isTransfer) return i;
    return -1;
  }

  private addSide(v: VerifiedCircleVersion): void {
    if (this.side.has(v.hash)) return;
    this.side.set(v.hash, v);
    while (this.side.size > MAX_SIDE_VERSIONS) this.side.delete(this.side.keys().next().value!);
  }

  /**
   * Receives versions (one `circle` bundle, or a single version). Within a
   * batch, two different valid transfer children of the current head freeze
   * the circle at the head (review 7: only at the transfers' parent).
   *
   * Each version is parsed once, and only the batch's children of the
   * current head are checked for equivocation (review N3: linear, not
   * quadratic, in the batch).
   */
  receive(input: string | readonly string[], opts: CircleChainOptions = {}): CircleReceiveResult[] {
    const batch = typeof input === "string" ? [input] : [...input];
    const results: CircleReceiveResult[] = [];
    const parsed: Parsed[] = batch.map((j) => {
      try {
        const p = parseCircleVersion(j);
        return { j, hash: jwsHash(j), p };
      } catch (e) {
        if (!(e instanceof P2PError)) throw e;
        return { j, hash: jwsHash(j), error: e };
      }
    });
    parsed.sort((a, b) => (a.p?.ver ?? Number.MAX_SAFE_INTEGER) - (b.p?.ver ?? Number.MAX_SAFE_INTEGER));
    // Children of each parent hash in the batch, for the equivocation check.
    const byPrev = new Map<string, Parsed[]>();
    for (const x of parsed) {
      if (x.p?.prev) byPrev.set(x.p.prev, [...(byPrev.get(x.p.prev) ?? []), x]);
    }
    const done = new Set<Parsed>();
    let checkedHead: string | undefined;
    for (const x of parsed) {
      if (!this.frozenAt && checkedHead !== this.head.hash) {
        checkedHead = this.head.hash;
        this.freezeOnEquivocation((byPrev.get(this.head.hash) ?? []).filter((c) => !done.has(c)));
      }
      done.add(x);
      results.push(this.receiveParsed(x, opts));
    }
    return results;
  }

  private freezeOnEquivocation(children: readonly Parsed[]): void {
    const head = this.head;
    const transfers = new Set<string>();
    for (const c of children) {
      if (!c.p || c.p.owner === head.owner) continue;
      try {
        const v = verifyCircleLink(head, c.j, c.p);
        if (v.isTransfer) transfers.add(v.hash);
      } catch {
        // not a valid child
      }
    }
    if (transfers.size > 1) this.freeze(head.hash);
  }

  private freeze(at: string): void {
    this.frozenAt = { at, reason: "transfer equivocation: two different transfers at the same version" };
    // While bootstrapping, the chain stops at the transfers' parent.
    const i = this.indexOf(at);
    if (this.bootstrapping && i >= 0) this.setChain(this.chain.slice(0, i + 1));
  }

  private indexOf(hash: string | null): number {
    return hash === null ? -1 : (this.chainIndex.get(hash) ?? -1);
  }

  private setChain(chain: VerifiedCircleVersion[]): void {
    this.chain = chain;
    this.chainIndex = new Map(chain.map((v, i) => [v.hash, i]));
  }

  private pushChain(v: VerifiedCircleVersion): void {
    this.chain.push(v);
    this.chainIndex.set(v.hash, this.chain.length - 1);
  }

  private receiveOne(jws: string, opts: CircleChainOptions): CircleReceiveResult {
    try {
      return this.receiveParsed({ j: jws, hash: jwsHash(jws), p: parseCircleVersion(jws) }, opts);
    } catch (e) {
      if (e instanceof P2PError) return { status: "rejected", reason: e.reason, hash: jwsHash(jws) };
      throw e;
    }
  }

  private receiveParsed(x: Parsed, opts: CircleChainOptions): CircleReceiveResult {
    try {
      if (x.error) throw x.error;
      return this.receiveOrThrow(x.j, x.hash, x.p!, opts);
    } catch (e) {
      if (e instanceof P2PError) return { status: "rejected", reason: e.reason, hash: x.hash };
      throw e;
    }
  }

  private receiveOrThrow(jws: string, hash: string, p: CircleVersionPayload, opts: CircleChainOptions): CircleReceiveResult {
    if (this.frozenAt) return { status: "frozen", hash, alert: `circle frozen: ${this.frozenAt.reason}` };
    if (p.cid !== this.cid) fail("circle-invalid", "another circle");
    if (this.chainIndex.has(hash)) return { status: "duplicate", hash };
    if (this.side.has(hash)) return { status: "ignored", hash, reason: "already held off the chain" };
    const head = this.head;
    // Sibling of the root (two version 1s).
    if (p.ver === 1) return this.offChain(verifyCircleGenesis(jws, p), opts);
    const i = this.indexOf(p.prev);
    if (i === this.chain.length - 1) {
      const v = verifyCircleLink(head, jws, p);
      this.checkSignerFresh(v, opts);
      this.pushChain(v);
      if (v.isTransfer) this.pruneSide();
      this.drainPending(opts);
      return { status: "accepted", hash };
    }
    if (i >= 0) return this.offChain(verifyCircleLink(this.chain[i], jws, p), opts);
    const sideParent = p.prev === null ? undefined : this.side.get(p.prev);
    if (sideParent) return this.offChain(verifyCircleLink(sideParent, jws, p), opts);
    if (p.ver > head.ver) return this.holdPending(hash, jws, p);
    return { status: "ignored", hash, reason: "unknown or discarded branch" };
  }

  /**
   * L2: a pending version must claim a ver within MAX_PENDING_AHEAD of the
   * head and be signed by the head's owner or by an owner a held version
   * hands over to; the oldest pending version is evicted first.
   */
  private holdPending(hash: string, jws: string, p: CircleVersionPayload): CircleReceiveResult {
    const want = { cid: this.cid, fromVer: this.head.ver + 1 };
    if (p.ver > this.head.ver + MAX_PENDING_AHEAD) return { status: "ignored", hash, reason: "too far ahead of the head" };
    if (!this.knownOwnerIks().some((ik) => verifiesUnder(jws, ik))) {
      return { status: "ignored", hash, reason: "not signed by a known owner", want };
    }
    // Admitted only when signed by a known owner, so the owner it names is known too.
    this.pending.set(hash, { j: jws, hash, p });
    while (this.pending.size > MAX_PENDING_VERSIONS) this.pending.delete(this.pending.keys().next().value!);
    return { status: "gap", hash, want };
  }

  /** The head owner's ik, plus the owners named by held side versions and by admitted pending versions. */
  private knownOwnerIks(): string[] {
    return [...new Set<string>([this.head.ik, ...[...this.side.values()].map((v) => v.ik), ...[...this.pending.values()].map((x) => x.p!.ik)])];
  }

  /**
   * Where `v`'s branch leaves the chain: the branch from there down to `v`
   * (walking up through side versions), and the index of the chain version
   * it hangs from (-1 for a second version 1). Undefined when the branch
   * doesn't reach the chain.
   */
  private branchOf(v: VerifiedCircleVersion): { branch: VerifiedCircleVersion[]; i: number } | undefined {
    const branch: VerifiedCircleVersion[] = [v];
    for (;;) {
      const first = branch[0];
      if (first.prev === null) return { branch, i: -1 };
      const onChain = this.indexOf(first.prev);
      if (onChain >= 0) return { branch, i: onChain };
      const up = this.side.get(first.prev);
      if (!up || branch.length > this.side.size + 1) return undefined;
      branch.unshift(up);
    }
  }

  /** Could a branch leaving the chain after index `i`, whose first version is `b1`, still win? */
  private couldWin(i: number, b1: VerifiedCircleVersion): boolean {
    return i + 1 > this.lastTransferIndex() && b1.signer === this.head.owner;
  }

  /** Drops side versions that can no longer win (review N3), e.g. after the chain passes a transfer. */
  private pruneSide(): void {
    for (const [h, v] of [...this.side]) {
      if (!this.side.has(h)) continue;
      const b = this.branchOf(v);
      if (!b || !this.couldWin(b.i, b.branch[0])) this.side.delete(h);
    }
  }

  /**
   * `v` is valid but off the chain: a sibling of a chain version, or the
   * descendant of one. Its branch (from where it leaves the chain down to
   * `v`) is compared with the chain:
   *  - everything at or before the latest transfer on the chain is final;
   *  - only the current head's owner can sign a replacement;
   *  - a branch containing a transfer beats one without (review 6, extended
   *    to branches so finality doesn't depend on arrival order, review L1);
   *  - otherwise the lower jwsHash where the branches part wins.
   * Only a version that could still win is kept on the side (review N3), so a
   * former owner can't fill it with dead siblings from before a transfer.
   * While bootstrapping, two different transfers of one parent freeze there.
   */
  private offChain(v: VerifiedCircleVersion, opts: CircleChainOptions): CircleReceiveResult {
    const b = this.branchOf(v);
    if (!b) return { status: "ignored", hash: v.hash, reason: "unknown or discarded branch" };
    const { branch, i } = b;
    const s = this.chain[i + 1];
    if (!s) return { status: "ignored", hash: v.hash };
    const b1 = branch[0];
    if (b1.isTransfer && s.isTransfer) {
      if (this.bootstrapping) {
        this.freeze(i >= 0 ? this.chain[i].hash : s.hash);
        return { status: "frozen", hash: v.hash, alert: `circle frozen: ${this.frozenAt!.reason}` };
      }
      // We are already past the parent (we hold s), so no freeze (review 7).
      return { status: "ignored", hash: v.hash, alert: `conflicting transfer of circle ${this.cid} at ver ${b1.ver} ignored` };
    }
    if (!this.couldWin(i, b1)) {
      return {
        status: "ignored",
        hash: v.hash,
        alert: `a version of circle ${this.cid} at ver ${b1.ver} that would rewrite final history was ignored (signer ${b1.signer})`,
      };
    }
    // Not final, so the chain segment after i holds no transfer.
    const wins = branch.some((x) => x.isTransfer) || asciiCompare(b1.hash, s.hash) < 0;
    if (!wins) {
      this.addSide(v);
      return { status: "ignored", hash: v.hash };
    }
    this.checkSignerFresh(v, opts);
    const dropped = this.chain.slice(i + 1);
    this.setChain([...this.chain.slice(0, i + 1), ...branch]);
    for (const x of branch) this.side.delete(x.hash);
    for (const d of dropped) this.addSide(d);
    if (branch.some((x) => x.isTransfer)) this.pruneSide();
    this.drainPending(opts);
    return { status: "replaced", hash: v.hash, discarded: dropped.map((d) => d.hash) };
  }

  private drainPending(opts: CircleChainOptions): void {
    let progressed = true;
    while (progressed && !this.frozenAt) {
      progressed = false;
      for (const [h, x] of this.pending) {
        const p = x.p!;
        const placeable = p.ver <= this.head.ver || p.prev === this.head.hash || (p.prev !== null && this.side.has(p.prev));
        if (!placeable) continue;
        this.pending.delete(h);
        const r = this.receiveParsed(x, opts);
        if (r.status !== "rejected") progressed = true;
      }
    }
  }

  /** §3.3 freshness: a member whose head is > 72h older than the newest heard of catches up. */
  needsCatchUp(newestHeardIat: number): boolean {
    return newestHeardIat - this.head.iat > HEAD_CATCH_UP_SEC;
  }
}

function verifiesUnder(jws: string, ikB64u: string): boolean {
  try {
    verifyJws(jws, { typ: TYP3.circle, kid: IK_KID, publicKey: b64uDecode(ikB64u, 32) });
    return true;
  } catch {
    return false;
  }
}

/** §3.3: the owner's client re-sends the head every 24 h. */
export function shouldResendHead(lastSentAt: number | undefined, now: number = nowSec()): boolean {
  return lastSentAt === undefined || now - lastSentAt >= HEAD_RESEND_SEC;
}

/** What a circle invite shows (§3.3): founder, owner and inviter, and whether ownership changed hands. */
export function describeCircleInvite(head: VerifiedCircleVersion, inviter: string) {
  return {
    cid: head.cid,
    name: circleDisplayName(head),
    founder: head.founder,
    owner: head.owner,
    inviter,
    ownershipChanged: head.owner !== head.founder,
    policy: circlePolicy(head),
  };
}

// ---------------------------------------------------------------------------
// Confirm before joining (§3.3, review 6/7)

/**
 * Picks whom to ask for the head: the owner, and one other member who isn't
 * the inviter or the viewer, from members the user already knows, otherwise
 * at random (`random()` in [0, 1), injected for testability).
 */
export function pickConfirmers(
  head: VerifiedCircleVersion,
  opts: { inviter: string; self: string; known: ReadonlySet<string>; random?: () => number },
): { owner: string; other?: string } {
  const pool = head.members.filter((m) => m !== head.owner && m !== opts.inviter && m !== opts.self);
  const known = pool.filter((m) => opts.known.has(m));
  const from = known.length > 0 ? known : pool;
  const r = opts.random ?? Math.random;
  const other = from.length > 0 ? from[Math.floor(r() * from.length)] : undefined;
  return { owner: head.owner, ...(other !== undefined ? { other } : {}) };
}

/** Two chains (hash lists from version 1) agree when one is a prefix of the other. */
export function chainsConsistent(a: readonly string[], b: readonly string[]): boolean {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return false;
  return true;
}

export type JoinConfirmation = "confirmed" | "conflict" | "unconfirmed";

/**
 * Refuses (conflict) when any answer conflicts with the offered chain;
 * confirmed when the owner and at least one other member answered
 * consistently; otherwise unconfirmed (the user decides).
 */
export function confirmJoin(
  offered: CircleChain,
  answers: readonly { from: string; chain: CircleChain }[],
  who: { inviter: string; self: string },
): JoinConfirmation {
  const mine = offered.versions.map((v) => v.hash);
  for (const a of answers) {
    if (a.chain.cid !== offered.cid || !chainsConsistent(mine, a.chain.versions.map((v) => v.hash))) return "conflict";
  }
  const head = offered.head;
  const fromOwner = answers.some((a) => a.from === head.owner);
  // The other confirmer must be a listed member, and neither the owner, the inviter nor the viewer (pre-release review L5).
  const fromOther = answers.some((a) => a.from !== head.owner && a.from !== who.inviter && a.from !== who.self && head.members.includes(a.from));
  return fromOwner && fromOther ? "confirmed" : "unconfirmed";
}

// ---------------------------------------------------------------------------
// Membership statements (`p2p-join+jws`, signed by a member's device)

export type MembershipOp = "join" | "leave";

export interface MembershipPayload {
  iss: string;
  cid: string;
  n: number;
  op: MembershipOp;
  /** join only: jwsHash of the circle version the member accepted. */
  at?: string;
  /** join only: a cap with sub "*" and kinds ["*"] for co-members (review M3). */
  cap?: string;
  iat: number;
}

export interface VerifiedMembership extends MembershipPayload {
  jws: string;
  hash: string;
  signer: VerifiedDeviceCertV3;
  joinCap?: VerifiedCap;
}

export function createMembershipStatement(
  signer: DeviceSignerV3,
  p: { cid: string; n: number; op: MembershipOp; at?: string; cap?: string; iat?: number },
): string {
  const payload: MembershipPayload = {
    iss: signer.userId,
    cid: p.cid,
    n: p.n,
    op: p.op,
    ...(p.op === "join" ? { at: p.at, cap: p.cap } : {}),
    iat: p.iat ?? nowSec(),
  };
  membershipPayload(payload as unknown as Obj);
  return signJws(TYP3.join, signer.did, payload, signer.signingSecretKey);
}

function membershipPayload(p: Obj): MembershipPayload {
  checkFields(p, ["iss", "cid", "n", "op", "at", "cap", "iat"], "membership statement");
  const op = p.op;
  if (op !== "join" && op !== "leave") fail("malformed", "op must be join or leave");
  const m: MembershipPayload = { iss: userIdField(p, "iss"), cid: cidField(p, "cid"), n: int(p, "n", 0), op, iat: int(p, "iat") };
  if (op === "join") {
    m.at = bytesField(p, "at", 32);
    m.cap = str(p, "cap");
  } else if (p.at !== undefined || p.cap !== undefined) {
    fail("malformed", "a leave carries no at or cap");
  }
  return m;
}

/**
 * A statement needs a signer valid (§2.3 rules 1–6) when received, not when
 * it claims to have been signed (review N4). A join's cap must be the
 * member's own sub "*", kinds ["*"] cap.
 */
export async function verifyMembershipStatement(jws: string, ctx: SignerContext): Promise<VerifiedMembership> {
  const v = await verifyDeviceSignedV3(jws, TYP3.join, ctx);
  const m = membershipPayload(v.payload);
  checkIssued(m.iat, ctx.now ?? nowSec(), ctx.skewSec ?? DEFAULT_SKEW_SEC);
  let joinCap: VerifiedCap | undefined;
  if (m.op === "join") {
    joinCap = verifyCap(m.cap!, { now: ctx.now, skewSec: ctx.skewSec, purpose: "join", identityDoc: await ctx.resolveIdentity(m.iss) });
    if (joinCap.iss !== m.iss) fail("cap-invalid", "join cap is not the member's");
  }
  return { ...m, jws, hash: jwsHash(jws), signer: v.signer, ...(joinCap ? { joinCap } : {}) };
}

/**
 * Ordering per (member, cid): the higher `n` is current; on a tie `leave`
 * wins, then the lowest jwsHash. Returns < 0 when `a` is current over `b`.
 */
export function compareMembership(a: Pick<VerifiedMembership, "n" | "op" | "hash">, b: Pick<VerifiedMembership, "n" | "op" | "hash">): number {
  if (a.n !== b.n) return b.n - a.n;
  if (a.op !== b.op) return a.op === "leave" ? -1 : 1;
  return asciiCompare(a.hash, b.hash);
}

/** Current statements of one circle, keyed by member userId. */
export type MembershipBook = Record<string, MembershipFact>;

/**
 * What a client keeps of an accepted statement. Signer validity was judged
 * on receipt (review N4); accepted statements are kept without re-checking.
 */
export type MembershipFact = Pick<VerifiedMembership, "iss" | "cid" | "n" | "op" | "at" | "hash" | "jws" | "iat"> & {
  /** A join's cap: what the member re-keys and revokes (open circles, review M4). */
  capInfo?: { capid: string; iat: number; exp: number; relays: string[] };
};

export function membershipFact(s: VerifiedMembership): MembershipFact {
  return {
    iss: s.iss,
    cid: s.cid,
    n: s.n,
    op: s.op,
    ...(s.at !== undefined ? { at: s.at } : {}),
    hash: s.hash,
    jws: s.jws,
    iat: s.iat,
    ...(s.joinCap ? { capInfo: { capid: s.joinCap.capid, iat: s.joinCap.iat, exp: s.joinCap.exp, relays: s.joinCap.relays } } : {}),
  };
}

/**
 * Draft 3 additions P2 (pre-release review M4): in a `policy: "open"` circle, join
 * caps live at most 14 days, so a stranger the owner auto-accepted holds a
 * member's cap only briefly after leaving or being removed.
 */
export const OPEN_JOIN_CAP_MAX_TTL_SEC = 14 * DAY;
/** Members re-sign (n+1, fresh cap) this long before an open circle's join cap lapses. */
export const OPEN_JOIN_CAP_RENEW_SEC = 3 * DAY;

/** The join-cap lifetime to use for a circle with this policy. */
export function joinCapTtlFor(policy: CirclePolicy): number {
  return policy === "open" ? OPEN_JOIN_CAP_MAX_TTL_SEC : 90 * DAY;
}

/** True when a join's cap fits the circle's policy (open: lifetime ≤ 14 days). */
export function joinCapFitsPolicy(cap: { iat: number; exp: number } | undefined, policy: CirclePolicy): boolean {
  return policy !== "open" || (cap !== undefined && cap.exp - cap.iat <= OPEN_JOIN_CAP_MAX_TTL_SEC);
}

/** Applies a verified statement to the book; true when it became current. */
export function applyMembership(book: MembershipBook, s: MembershipFact): boolean {
  const cur = book[s.iss];
  if (cur && cur.hash === s.hash) return false;
  if (cur && compareMembership(s, cur) >= 0) return false;
  book[s.iss] = s;
  return true;
}

/** The next `n` for this device: one more than the highest any of the member's devices has seen (synced). */
export function nextMembershipN(highestSeen: number | undefined): number {
  return (highestSeen ?? -1) + 1;
}

/**
 * §3.3 re-sign triggers: re-sign the current statement (n+1, fresh cap) when
 * its signing device is revoked, its certificate is within 7 days of exp, or
 * its cap within 30 days of exp.
 */
export function membershipNeedsResign(
  s: Pick<VerifiedMembership, "signer" | "joinCap">,
  allowlist: readonly string[],
  now: number = nowSec(),
): boolean {
  if (!allowlist.includes(s.signer.did)) return true;
  if (s.signer.exp - now <= 7 * DAY) return true;
  return s.joinCap !== undefined && s.joinCap.exp - now <= 30 * DAY;
}

// ---------------------------------------------------------------------------
// Standing (§3.3): membership counts only with consent

export interface StandingContext {
  viewer: string;
  /** The viewer explicitly joined this circle on this device (a local action, review C1). */
  joinedByMe: boolean;
  isBlocked?: (userId: string) => boolean;
}

/**
 * `u` stands in the circle on this client when u is in the held version's
 * members, the client holds u's current membership statement and it is a
 * join, and that join's `at` is an ancestor of, or equal to, the held version.
 * The viewer's own standing also needs the viewer to have joined on this
 * device, and a circle the viewer never joined grants nobody anything on it
 * (review C1), so nobody stands while `joinedByMe` is false. Blocked users
 * stand nowhere.
 */
export function standsInCircle(u: string, chain: CircleChain, book: MembershipBook, ctx: StandingContext): boolean {
  if (ctx.isBlocked?.(u)) return false;
  // The viewer's own standing needs its explicit join on this device, and a
  // circle the viewer never joined grants nobody anything here (review C1).
  if (!ctx.joinedByMe) return false;
  if (!chain.head.members.includes(u)) return false;
  const s = book[u];
  if (!s || s.op !== "join" || s.cid !== chain.cid || s.at === undefined) return false;
  return chain.hasAncestor(s.at);
}

// ---------------------------------------------------------------------------
// Proposals (`p2p-circle-op+jws`, signed by an admin's device)

export type ProposalOp = "add" | "remove" | "promote" | "demote" | "rename";

export interface ProposalPayload {
  iss: string;
  cid: string;
  base: number;
  op: ProposalOp;
  target?: string;
  name?: string;
  nonce: string;
  iat: number;
}

export interface VerifiedProposal extends ProposalPayload {
  jws: string;
  signer: VerifiedDeviceCertV3;
}

export function createProposal(
  signer: DeviceSignerV3,
  p: { cid: string; base: number; op: ProposalOp; target?: string; name?: string; nonce?: string; iat?: number },
): string {
  const payload: ProposalPayload = {
    iss: signer.userId,
    cid: p.cid,
    base: p.base,
    op: p.op,
    ...(p.target !== undefined ? { target: p.target } : {}),
    ...(p.name !== undefined ? { name: p.name } : {}),
    nonce: p.nonce ?? newNonce(),
    iat: p.iat ?? nowSec(),
  };
  proposalPayload(payload as unknown as Obj);
  return signJws(TYP3.circleOp, signer.did, payload, signer.signingSecretKey);
}

function proposalPayload(p: Obj): ProposalPayload {
  checkFields(p, ["iss", "cid", "base", "op", "target", "name", "nonce", "iat"], "proposal");
  const op = p.op;
  if (op !== "add" && op !== "remove" && op !== "promote" && op !== "demote" && op !== "rename") fail("malformed", "proposal op");
  const out: ProposalPayload = {
    iss: userIdField(p, "iss"),
    cid: cidField(p, "cid"),
    base: int(p, "base", 1),
    op,
    nonce: bytesField(p, "nonce", 16),
    iat: int(p, "iat"),
  };
  if (op === "rename") {
    out.name = str(p, "name");
    if ([...out.name].length > CIRCLE_NAME_MAX) fail("malformed", "circle name too long");
    if (p.target !== undefined) fail("malformed", "rename has no target");
  } else {
    out.target = userIdField(p, "target");
    if (p.name !== undefined) fail("malformed", "only rename has a name");
  }
  return out;
}

/** The signer must be valid when the proposal is received (§3.3). */
export async function verifyProposal(jws: string, ctx: SignerContext): Promise<VerifiedProposal> {
  const v = await verifyDeviceSignedV3(jws, TYP3.circleOp, ctx);
  const p = proposalPayload(v.payload);
  return { ...p, jws, signer: v.signer };
}

export type ProposalStatus =
  | "applied"
  /** Its effect already holds. */
  | "skipped"
  /** A version after `base` changed the same target: tell the admin to re-propose. */
  | "stale"
  | "not-admin"
  | "expired"
  | "duplicate"
  /** Aimed at the owner, or otherwise not allowed. */
  | "refused"
  /** The owner holds proposals for approval. */
  | "held";

export interface ProposalResult {
  nonce: string;
  iss: string;
  status: ProposalStatus;
  reason?: string;
}

/** Nonces the owner applied, with their proposals' iat; synced across the owner's devices. */
export type AppliedNonces = Record<string, number>;

export interface ProposalDraft {
  name: string;
  admins: string[];
  members: string[];
}

export interface ApplyProposalsResult {
  results: ProposalResult[];
  /** The next version's fields, when anything changed. Sign with createNextCircleVersion. */
  draft?: ProposalDraft;
  /** The applied set, with the new nonces and pruned of those older than 30 days. */
  applied: AppliedNonces;
}

function targetKey(op: ProposalOp, target?: string): string {
  return op === "rename" ? "name" : `user:${target}`;
}

/** Did version `v` (vs its parent) change `key`? */
function changed(parent: VerifiedCircleVersion, v: VerifiedCircleVersion, key: string): boolean {
  if (key === "name") return parent.name !== v.name;
  const u = key.slice(5);
  return parent.members.includes(u) !== v.members.includes(u) || parent.admins.includes(u) !== v.admins.includes(u);
}

/**
 * The owner's client applies proposals automatically, in arrival order, when
 * all of these hold: `iss` is an admin in the current head; `iat` is within
 * the last 30 days and the nonce is not in the applied set; and no version
 * after `base` changed the same target (otherwise stale). It skips proposals
 * whose effect already holds and refuses promote, demote and remove aimed at
 * the owner. With `hold`, everything waits for the owner's approval.
 */
export function applyProposals(
  chain: CircleChain,
  proposals: readonly VerifiedProposal[],
  applied: AppliedNonces,
  opts: { now?: number; skewSec?: number; hold?: boolean } = {},
): ApplyProposalsResult {
  const now = opts.now ?? nowSec();
  const skew = opts.skewSec ?? DEFAULT_SKEW_SEC;
  const head = chain.head;
  const versions = chain.versions;
  const next: AppliedNonces = {};
  for (const [n, iat] of Object.entries(applied)) if (now - iat <= PROPOSAL_MAX_AGE_SEC) next[n] = iat;
  const draft: ProposalDraft = { name: head.name, admins: [...head.admins], members: [...head.members] };
  const results: ProposalResult[] = [];
  const res = (p: VerifiedProposal, status: ProposalStatus, reason?: string) =>
    results.push({ nonce: p.nonce, iss: p.iss, status, ...(reason ? { reason } : {}) });
  for (const p of proposals) {
    if (p.cid !== chain.cid) {
      res(p, "refused", "another circle");
      continue;
    }
    if (opts.hold) {
      res(p, "held");
      continue;
    }
    if (!head.admins.includes(p.iss)) {
      res(p, "not-admin");
      continue;
    }
    if (now - p.iat > PROPOSAL_MAX_AGE_SEC || p.iat > now + skew) {
      res(p, "expired");
      continue;
    }
    if (next[p.nonce] !== undefined) {
      res(p, "duplicate");
      continue;
    }
    if (p.base > head.ver) {
      res(p, "refused", "base is newer than the head");
      continue;
    }
    const key = targetKey(p.op, p.target);
    const stale = versions.some((v, i) => i > 0 && v.ver > p.base && changed(versions[i - 1], v, key));
    if (stale) {
      res(p, "stale", "a version after base changed the same target");
      continue;
    }
    if (p.target === head.owner && p.op !== "add") {
      res(p, "refused", "proposals can't remove, promote or demote the owner");
      continue;
    }
    const t = p.target!;
    let effect = true;
    switch (p.op) {
      case "add":
        if (draft.members.includes(t)) effect = false;
        else draft.members.push(t);
        break;
      case "remove":
        if (!draft.members.includes(t)) effect = false;
        else {
          draft.members = draft.members.filter((m) => m !== t);
          draft.admins = draft.admins.filter((m) => m !== t);
        }
        break;
      case "promote":
        if (draft.admins.includes(t)) effect = false;
        else if (!draft.members.includes(t)) {
          res(p, "refused", "only members can be admins");
          continue;
        } else draft.admins.push(t);
        break;
      case "demote":
        if (!draft.admins.includes(t)) effect = false;
        else draft.admins = draft.admins.filter((m) => m !== t);
        break;
      case "rename":
        if (draft.name === p.name) effect = false;
        else draft.name = p.name!;
        break;
    }
    next[p.nonce] = p.iat;
    res(p, effect ? "applied" : "skipped");
  }
  const changedAny =
    draft.name !== head.name || draft.admins.join("\n") !== head.admins.join("\n") || draft.members.join("\n") !== head.members.join("\n");
  return { results, applied: next, ...(changedAny ? { draft } : {}) };
}

// ---------------------------------------------------------------------------
// Open communities (draft 3 additions, Phase 2)

export const CIRCLE_LINK_PREFIX = "p2p://circle/";
export const CIRCLE_WEB_PREFIX = "https://ix-infra.com/p2p/c#";
/**
 * Deprecated web forms: still parsed (parsing is local, and older clients
 * printed them), never generated. See protocol.md §3.3.
 */
export const LEGACY_CIRCLE_WEB_PREFIXES: readonly string[] = ["https://peer2peer.dev/c#"];

/** `p2p://circle/<b64u(head version jws)>`, or `https://ix-infra.com/p2p/c#<same>`. */
export function circleInviteLink(headJws: string, opts: { web?: boolean } = {}): string {
  parseCircleVersion(headJws);
  return (opts.web ? CIRCLE_WEB_PREFIX : CIRCLE_LINK_PREFIX) + b64uEncode(utf8(headJws));
}

/** The head version JWS a circle link carries (structurally checked; bootstrap still needs the full chain). */
export function parseCircleInviteLink(link: string): string {
  const s = typeof link === "string" ? link.trim() : "";
  const prefix = [CIRCLE_LINK_PREFIX, CIRCLE_WEB_PREFIX, ...LEGACY_CIRCLE_WEB_PREFIXES].find((p) => s.startsWith(p));
  if (prefix === undefined) fail("malformed", "not a circle link");
  const jws = fromUtf8(b64uDecode(s.slice(prefix.length)));
  parseCircleVersion(jws);
  return jws;
}

/** Times (seconds) of recent automatic accepts, for the hourly cap. */
export interface OpenJoinLimiter {
  acceptedAt: number[];
}

export type OpenJoinDecision =
  | { decision: "accept" }
  | { decision: "hold"; reason: "rate-limited" | "previously-removed" | "not-open" }
  | { decision: "ignore"; reason: "already-member" | "not-a-join" | "not-current" | "unknown-version" | "other-circle" | "blocked" | "cap-too-long" };

/**
 * The owner's client, for a verified join statement sent to it. Under
 * `policy: "open"` a valid join from anyone holding the link (its `at` names
 * a version on the owner's chain) is applied automatically, at most
 * `maxPerHour` per rolling hour; beyond that, and for anyone the owner
 * removed, it is held for approval. Under `invite` everything is held. The
 * statement is the joiner's consent by construction; the circle's version
 * chain and every authorisation rule are unchanged.
 */
export function decideOpenJoin(
  chain: CircleChain,
  join: VerifiedMembership,
  book: MembershipBook,
  limiter: OpenJoinLimiter,
  opts: {
    now?: number;
    maxPerHour?: number;
    isBlocked?: (u: string) => boolean;
    /** Required (review N4): members the owner removed (StoredCircleV3.removed), held whatever they signed since. State code uses decideOpenJoinFor, which passes the record. */
    removed: ReadonlySet<string> | readonly string[];
  },
): OpenJoinDecision {
  const now = opts.now ?? nowSec();
  const head = chain.head;
  if (join.cid !== chain.cid) return { decision: "ignore", reason: "other-circle" };
  if (opts.isBlocked?.(join.iss)) return { decision: "ignore", reason: "blocked" };
  if (join.op !== "join" || join.at === undefined) return { decision: "ignore", reason: "not-a-join" };
  const cur = book[join.iss];
  if (cur && cur.hash !== join.hash && compareMembership(join, cur) >= 0) return { decision: "ignore", reason: "not-current" };
  if (!chain.hasAncestor(join.at)) return { decision: "ignore", reason: "unknown-version" };
  if (head.members.includes(join.iss)) return { decision: "ignore", reason: "already-member" };
  if (circlePolicy(head) !== "open") return { decision: "hold", reason: "not-open" };
  if (!joinCapFitsPolicy(join.joinCap, "open")) return { decision: "ignore", reason: "cap-too-long" };
  // Someone the owner removed stays removed, however they sign afterwards
  // (leave, then join): a human decides.
  const removed = opts.removed instanceof Set ? opts.removed : new Set(opts.removed);
  if (removed.has(join.iss)) return { decision: "hold", reason: "previously-removed" };
  // Without the record, a member dropped while its statement was a join was removed.
  const wasMember = chain.versions.some((v) => v.members.includes(join.iss));
  const prior = cur && cur.hash !== join.hash ? cur : undefined;
  if (wasMember && (!prior || prior.op === "join")) return { decision: "hold", reason: "previously-removed" };
  const recent = limiter.acceptedAt.filter((t) => now - t < HOUR);
  if (recent.length >= (opts.maxPerHour ?? OPEN_JOIN_MAX_PER_HOUR)) return { decision: "hold", reason: "rate-limited" };
  limiter.acceptedAt = [...recent, now];
  return { decision: "accept" };
}

/**
 * The circle bundle a client sends (§4.3 `circle`: versions plus membership
 * statements), e.g. the owner's re-send of the head (§3.3). Join statements
 * whose caps don't fit the circle's policy are WITHHELD (review N5): in an open
 * circle, a member's join carrying a cap longer than 14 days (signed before
 * the circle opened, or not yet re-signed) is never redistributed, so
 * auto-accepted strangers can't collect long-lived caps. Leaves are always
 * included. Every bundle-send path builds its bundle through this
 * (state.ts outgoingCircleBundle).
 */
export function buildCircleBundle(
  chain: CircleChain,
  book: MembershipBook,
  opts: { fromVer?: number } = {},
): { circles: string[]; joins: string[]; ops: string[]; withheld: string[] } {
  const policy = circlePolicy(chain.head);
  const joins: string[] = [];
  const withheld: string[] = [];
  for (const [member, s] of Object.entries(book)) {
    if (s.cid !== chain.cid) continue;
    if (s.op === "join" && !joinCapFitsPolicy(s.capInfo, policy)) withheld.push(member);
    else joins.push(s.jws);
  }
  return { circles: chain.versionsFrom(opts.fromVer ?? 1), joins, ops: [], withheld };
}
