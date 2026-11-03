// Copyright 2026 Ix Infrastructure Inc.
//
// Members-only mode (docs/run-a-relay.md "Members-only relays"). With
// `allow` and/or `allowCircle` configured, only these userIds may
// authenticate:
//
//  - full members: every userId on the allowlist, and every current member of
//    the configured circle (the head of a chain the relay verifies itself,
//    from version 1, with core's CircleChain: owner-signed versions only);
//  - provisional members: a userId that redeemed an admission grant an
//    allowed member attached to a short-code invite (`invite-put` `admit`),
//    for `inviteAdmitSec`, or until it becomes a full member (then the circle
//    or the list alone decides), or its sponsor stops being a full member.
//
// With neither configured the relay is open and nothing here applies.
//
// State that must survive a restart (the circle chain, outstanding grants,
// provisional members) lives in the store's meta table as JSON. All of it is
// bounded: grants per sponsor, provisional members per sponsor and in total,
// and the stored chain's size.

import { b64uDecode, b64uEncode, sha256 } from "@peer2peer/core";
import { CircleChain, circlePolicy, type StoredCircleChain } from "@peer2peer/core/v3";
import type { Logger } from "./log.js";
import type { Store } from "./store.js";

/** Grants one sponsor may hold at once; the oldest goes first. */
export const GRANTS_PER_SPONSOR = 64;
/** Provisional members one sponsor may have at once. */
export const PROVISIONAL_PER_SPONSOR = 64;
export const PROVISIONAL_MAX = 10_000;
/** Versions accepted in one `circle-put` frame. */
export const CIRCLE_PUT_MAX_VERSIONS = 64;
/** A stored chain larger than this is kept in memory only (and the operator warned). */
const CIRCLE_STORE_MAX_BYTES = 32 * 1024 * 1024;

const META_CIRCLE = "members.circle";
const META_GRANTS = "members.grants";
const META_PROVISIONAL = "members.provisional";

/** An admission key or its hash: 32 bytes, base64url. */
export const ADMIT_RE = /^[A-Za-z0-9_-]{43}$/;

interface Grant {
  /** The invite's lookup id: `invite-del` of it also drops the grant. */
  lid: string;
  /** b64u(sha256(admission key)). */
  h: string;
  /** The sponsor (the full member who put the invite). */
  by: string;
  /** Expiry, ms. */
  exp: number;
}

interface Provisional {
  by: string;
  /** The invite whose grant admitted it: revoking that invite (`invite-del`) removes it. */
  lid?: string;
  /** ms. */
  until: number;
}

export interface MembershipOptions {
  allow?: readonly string[];
  /** Never admitted, whatever the list, the circle or an invite says (RELAY_DENY, `!` lines). */
  deny?: readonly string[];
  circle?: string;
  inviteAdmitSec: number;
  store: Store;
  now: () => number;
  log: Logger;
}

export type CirclePutResult =
  | { ok: true; ver: number; changed: boolean; status: string }
  | { ok: false; code: "forbidden" | "bad-request" | "not-found"; reason: string };

/** Hashes an admission key the way the grant stores it. */
export function admitHash(key: string): string {
  return b64uEncode(sha256(b64uDecode(key, 32)));
}

export class Membership {
  private allow?: Set<string>;
  private deny: Set<string>;
  /**
   * The followed circle's head is open (anyone may join it): admitting its
   * members would admit the public, so the circle admits nobody until a later
   * head is invite-only again. Shown as `attention` in the relay info.
   */
  private circleOpen = false;
  readonly circleId?: string;
  readonly inviteAdmitSec: number;
  private chain?: CircleChain;
  private circleMembers = new Set<string>();
  private grants = new Map<string, Grant>();
  private provisional = new Map<string, Provisional>();
  private readonly store: Store;
  private readonly now: () => number;
  private readonly log: Logger;

  constructor(o: MembershipOptions) {
    this.allow = o.allow ? new Set(o.allow) : undefined;
    this.deny = new Set(o.deny ?? []);
    this.circleId = o.circle;
    this.inviteAdmitSec = o.inviteAdmitSec;
    this.store = o.store;
    this.now = o.now;
    this.log = o.log;
  }

  /** Reads persisted state (after the store's init). */
  load(): void {
    if (this.circleId) {
      const raw = this.store.getMeta(META_CIRCLE);
      if (raw) {
        try {
          const s = JSON.parse(raw) as StoredCircleChain;
          if (s.cid !== this.circleId) {
            this.log.warn("members-only: the stored circle is not the configured one; waiting for a member to seed it");
          } else {
            this.setChain(CircleChain.fromStored(s));
          }
        } catch (e) {
          this.log.error("members-only: the stored circle chain did not verify; waiting for a member to seed it", { error: (e as Error).message });
        }
      }
    }
    const grants = this.readMeta<Grant[]>(META_GRANTS) ?? [];
    for (const g of grants) this.grants.set(g.h, g);
    const prov = this.readMeta<Record<string, Provisional>>(META_PROVISIONAL) ?? {};
    for (const [u, p] of Object.entries(prov)) this.provisional.set(u, p);
    this.expire();
    if (this.enabled) {
      this.log.info("members-only relay", {
        allowlisted: this.allow?.size ?? 0,
        circle: this.circleId ?? undefined,
        circleVer: this.chain?.head.ver,
        circleMembers: this.chain ? this.circleMembers.size : undefined,
        inviteAdmitSec: this.inviteAdmitSec,
      });
      if (this.circleId && !this.chain && (this.allow?.size ?? 0) === 0) {
        this.log.warn("members-only: RELAY_ALLOW_CIRCLE is set but the circle isn't seeded and RELAY_ALLOW is empty, so nobody can authenticate");
      }
    }
  }

  private readMeta<T>(key: string): T | undefined {
    const raw = this.store.getMeta(key);
    if (!raw) return undefined;
    try {
      return JSON.parse(raw) as T;
    } catch {
      return undefined;
    }
  }

  get enabled(): boolean {
    return this.allow !== undefined || this.circleId !== undefined;
  }

  /** On the allowlist, or a member of the circle's head. */
  isFull(iss: string): boolean {
    if (this.deny.has(iss)) return false;
    return (this.allow?.has(iss) ?? false) || this.circleMembers.has(iss);
  }

  /** May authenticate (always true on an open relay). */
  admitted(iss: string): boolean {
    if (!this.enabled) return true;
    if (this.deny.has(iss)) return false;
    if (this.isFull(iss)) return true;
    const p = this.provisional.get(iss);
    return p !== undefined && p.until > this.now() && this.isFull(p.by);
  }

  allowlisted(iss: string): boolean {
    return !this.deny.has(iss) && (this.allow?.has(iss) ?? false);
  }

  /** Something needs the operator (the followed circle turned open). No details: they're in the logs. */
  get attention(): boolean {
    return this.circleOpen;
  }

  /** What an authenticated member is told about the circle the relay follows: `ver` 0 until seeded. */
  circleInfo(): { cid: string; ver: number } | undefined {
    if (!this.circleId) return undefined;
    return { cid: this.circleId, ver: this.chain?.head.ver ?? 0 };
  }

  /** Replaces the allowlist (undefined: none) and, when given, the deny list. */
  setAllow(list: readonly string[] | undefined, deny?: readonly string[]): void {
    this.allow = list ? new Set(list) : undefined;
    if (deny) this.deny = new Set(deny);
    this.settle();
  }

  // ---------------------------------------------------------------------------
  // Invite admission

  /**
   * Records the grant an `invite-put` carries. Only full members sponsor one.
   * Returns false when the sponsor may not.
   */
  grant(lid: string, h: string, by: string, exp: number): boolean {
    if (!this.enabled || this.inviteAdmitSec <= 0 || !this.isFull(by)) return false;
    const mine = [...this.grants.values()].filter((g) => g.by === by).sort((a, b) => a.exp - b.exp);
    while (mine.length >= GRANTS_PER_SPONSOR) this.grants.delete(mine.shift()!.h);
    this.grants.set(h, { lid, h, by, exp });
    this.saveGrants();
    return true;
  }

  /**
   * `invite-del` by the sponsor revokes what the code admits: its grant, taken
   * or not, and the provisional member it already admitted. Returns whether
   * someone lost admission (their connections must close).
   */
  revokeInvite(lid: string, by: string): boolean {
    for (const g of this.grants.values()) {
      if (g.lid === lid && g.by === by) {
        this.grants.delete(g.h);
        this.saveGrants();
        break;
      }
    }
    let removed = false;
    for (const [u, p] of this.provisional) {
      if (p.lid === lid && p.by === by) {
        this.provisional.delete(u);
        removed = true;
      }
    }
    if (removed) this.saveProvisional();
    return removed;
  }

  /**
   * At auth, a userId that isn't admitted may present an admission key: a live
   * grant from a sponsor who is still a full member admits it provisionally.
   * The grant is single-use.
   */
  redeem(key: string, iss: string): boolean {
    if (!this.enabled || this.inviteAdmitSec <= 0 || !ADMIT_RE.test(key)) return false;
    // A denied userId never redeems: checked before the grant is touched, so it isn't spent.
    if (this.deny.has(iss)) return false;
    let h: string;
    try {
      h = admitHash(key);
    } catch {
      return false;
    }
    const g = this.grants.get(h);
    const now = this.now();
    if (!g || g.exp <= now || !this.isFull(g.by) || g.by === iss) return false;
    let sponsored = 0;
    for (const p of this.provisional.values()) if (p.by === g.by && p.until > now) sponsored++;
    if (sponsored >= PROVISIONAL_PER_SPONSOR || this.provisional.size >= PROVISIONAL_MAX) {
      this.log.warn("members-only: provisional member cap reached; admission refused");
      return false;
    }
    this.grants.delete(h);
    this.saveGrants();
    this.provisional.set(iss, { by: g.by, lid: g.lid, until: now + this.inviteAdmitSec * 1000 });
    this.saveProvisional();
    return true;
  }

  /** Drops expired grants and provisional members. Returns whether a provisional member lapsed. */
  expire(): boolean {
    const now = this.now();
    let g = false;
    for (const [h, x] of this.grants) {
      if (x.exp <= now) {
        this.grants.delete(h);
        g = true;
      }
    }
    if (g) this.saveGrants();
    let p = false;
    for (const [u, x] of this.provisional) {
      if (x.until <= now) {
        this.provisional.delete(u);
        p = true;
      }
    }
    if (p) this.saveProvisional();
    return p;
  }

  /**
   * After the full membership changed: provisional members who became full
   * ones are provisional no more (so a later removal from the list or circle
   * cuts them off), and grants of sponsors who are no longer full members go.
   */
  private settle(): void {
    let p = false;
    for (const [u] of this.provisional) {
      // Full now (the list or circle decides from here), or denied (gone for good, not only while denied).
      if (this.isFull(u) || this.deny.has(u)) {
        this.provisional.delete(u);
        p = true;
      }
    }
    if (p) this.saveProvisional();
    let g = false;
    for (const [h, x] of this.grants) {
      if (!this.isFull(x.by)) {
        this.grants.delete(h);
        g = true;
      }
    }
    if (g) this.saveGrants();
  }

  private saveGrants(): void {
    this.store.setMeta(META_GRANTS, JSON.stringify([...this.grants.values()]));
  }

  private saveProvisional(): void {
    this.store.setMeta(META_PROVISIONAL, JSON.stringify(Object.fromEntries(this.provisional)));
  }

  // ---------------------------------------------------------------------------
  // Circle admission

  private setChain(c: CircleChain): void {
    this.chain = c;
    const open = circlePolicy(c.head) === "open";
    if (open && !this.circleOpen) {
      this.log.error("members-only: the followed circle is now OPEN (anyone may join it), so it admits nobody here; only the allowlist does until its owner makes it invite-only again", { ver: c.head.ver });
    } else if (!open && this.circleOpen) {
      this.log.warn("members-only: the followed circle is invite-only again; its members are admitted", { ver: c.head.ver });
    }
    this.circleOpen = open;
    // Fail closed: an open circle's members are whoever asked, i.e. the public.
    this.circleMembers = open ? new Set() : new Set(c.head.members);
  }

  /**
   * Versions of the configured circle from an authenticated member. The first
   * (the bootstrap, from version 1) only from an allowlisted userId; after
   * that any member may push newer versions, which the chain accepts only
   * when owner-signed and on top of what it holds.
   */
  putCircle(iss: string, versions: unknown): CirclePutResult {
    if (!this.circleId) return { ok: false, code: "not-found", reason: "no circle configured" };
    if (!Array.isArray(versions) || versions.length === 0 || versions.length > CIRCLE_PUT_MAX_VERSIONS || !versions.every((v) => typeof v === "string")) {
      return { ok: false, code: "bad-request", reason: "versions" };
    }
    const list = versions as string[];
    const before = this.chain?.head.hash;
    let status: string;
    let chain = this.chain;
    try {
      if (!chain) {
        if (!this.allowlisted(iss)) return { ok: false, code: "forbidden", reason: "only an allowlisted member seeds the circle" };
        chain = CircleChain.bootstrap(list, { now: Math.floor(this.now() / 1000) });
        if (chain.cid !== this.circleId) return { ok: false, code: "bad-request", reason: "another circle" };
        if (circlePolicy(chain.head) === "open") return { ok: false, code: "bad-request", reason: "an open circle can't admit members (anyone may join it)" };
        status = "seeded";
      } else {
        const rs = chain.receive(list, { now: Math.floor(this.now() / 1000) });
        status = rs.some((r) => r.status === "accepted" || r.status === "replaced")
          ? "accepted"
          : (rs.find((r) => r.status !== "duplicate")?.status ?? "duplicate");
      }
    } catch (e) {
      return { ok: false, code: "bad-request", reason: (e as Error).message };
    }
    this.setChain(chain);
    const changed = chain.head.hash !== before;
    if (changed || status === "gap") this.saveChain();
    if (changed) this.settle();
    return { ok: true, ver: chain.head.ver, changed, status };
  }

  private saveChain(): void {
    if (!this.chain) return;
    const json = JSON.stringify(this.chain.toStored());
    if (json.length > CIRCLE_STORE_MAX_BYTES) {
      this.log.warn("members-only: the circle chain is too large to store; it is held in memory only", { bytes: json.length });
      return;
    }
    this.store.setMeta(META_CIRCLE, json);
  }

  /** Aggregates for logs and /debug/stats. */
  stats(): Record<string, number> {
    return {
      allowlisted: this.allow?.size ?? 0,
      circleMembers: this.circleMembers.size,
      circleVer: this.chain?.head.ver ?? 0,
      grants: this.grants.size,
      provisional: this.provisional.size,
    };
  }
}
