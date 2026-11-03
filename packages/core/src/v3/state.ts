// Copyright 2026 Ix Infrastructure Inc.
//
// Store-level operations over TrustStoreV3: identity chains and views,
// resolvers for signer checks, friendships, blocks, and circle state
// (bootstrap, own joins and leaves, bundles, the owner's proposal inbox).
// Pure apart from the injected store.

import { fail, P2PError } from "../errors.js";
import { decodeTyped, jwsHash, nowSec, TYP3, userIdFromIk, type TimeOptions } from "./base.js";
import { b64uDecode } from "../encoding.js";
import { decodeJws } from "../jws.js";
import {
  applyMembership,
  applyProposals,
  buildCircleBundle,
  CircleChain,
  decideOpenJoin,
  type OpenJoinDecision,
  type OpenJoinLimiter,
  circlePolicy,
  joinCapFitsPolicy,
  OPEN_JOIN_CAP_MAX_TTL_SEC,
  OPEN_JOIN_CAP_RENEW_SEC,
  type VerifiedCircleVersion,
  membershipFact,
  parseCircleVersion,
  standsInCircle,
  verifyMembershipStatement,
  verifyProposal,
  type ApplyProposalsResult,
  type CircleChainOptions,
  type CircleReceiveResult,
  type MembershipBook,
  type VerifiedMembership,
  type VerifiedProposal,
} from "./circles.js";
import { unfriendApplies, verifyFriendshipV3, verifyInviteV3, type VerifiedFriendshipV3, type VerifiedInviteV3 } from "./friends.js";
import { verifyDeviceCertV3 } from "./device.js";
import { assertNotFailClosed, docCertFor, identityFreshness, IdentityChain, peekIdentityDoc, verifyIdentityDocSignature, type ChainAddResult, type IdentityView, type VerifiedIdentityDoc } from "./identitydoc.js";
import type { CertResolverV3, IdentityResolver, SignerContext } from "./signers.js";
import type { StoredCapV3, StoredCircleV3, TrustStoreV3 } from "./store.js";

// ---------------------------------------------------------------------------
// Identities

/**
 * Adds a version to the stored chain of its issuer (chain-consistent, §2.5).
 * The read, the add and the write are one atomic store update, so concurrent
 * adds (two fork tips arriving at once) can't lose a version (pre-release review M2).
 */
export async function addIdentityVersion(store: TrustStoreV3, jws: string, opts: TimeOptions = {}): Promise<ChainAddResult> {
  const iss = peekIdentityDoc(jws).iss;
  return store.updateIdentity(iss, (stored) => {
    const chain = stored ? IdentityChain.fromStored(stored) : new IdentityChain(iss);
    const r = chain.add(jws, opts);
    return r.status === "accepted" ? { next: chain.toStored(), result: r } : { result: r };
  });
}

/** §2.5 gap jump (after fetching failed): replaces the held history with this head and flags a history gap. Atomic, like addIdentityVersion. */
export async function jumpIdentity(store: TrustStoreV3, jws: string, opts: TimeOptions = {}): Promise<VerifiedIdentityDoc> {
  const iss = peekIdentityDoc(jws).iss;
  return store.updateIdentity(iss, (stored) => {
    const chain = stored ? IdentityChain.fromStored(stored) : new IdentityChain(iss);
    const doc = chain.jumpTo(jws, opts);
    return { next: chain.toStored(), result: doc };
  });
}

/**
 * What a fetch returns: either one list, or one list per relay
 * (`Record<relay URL, JWS[]>`, pre-release review S1). refreshIdentity asks each
 * relay separately (`relays` holds just that relay); a single list is taken
 * as that relay's answer, so plain fetchers keep working.
 */
export type FetchResult = readonly string[] | Readonly<Record<string, readonly string[]>>;

/** Fetches identity document versions (tips, and whatever chain they hold) for `userId` from the given relays. */
export type TipsFetcher = (userId: string, relays: readonly string[]) => Promise<FetchResult>;

/**
 * The §5.6 chain walk: `GET .../identity/<userId>/chain?to=<jwsHash>&n=<n>`
 * on the given relays, returning the versions walked back from `to` along
 * `prev` (and `merge`).
 */
export type ChainFetcher = (userId: string, relays: readonly string[], to: string, n: number) => Promise<FetchResult>;

/**
 * Network I/O for refreshIdentity, injected: a tips fetcher, optionally
 * with a chain walker (needed to fill gaps over anchored or forked history).
 */
export type IdentityFetcher = TipsFetcher | { tips: TipsFetcher; chain?: ChainFetcher };

/** How many versions one chain request asks for, and keeps per relay (§5.6: n <= 64). */
export const CHAIN_WALK_PAGE = 64;
/** Upper bound on chain requests per refresh. */
export const CHAIN_WALK_MAX_REQUESTS = 32;
/** Valid tips kept per relay, highest `ver` first (review S1). */
export const MAX_TIPS_PER_RELAY = 8;
/** Entries examined per relay response (signature checks), highest claimed `ver` first. */
export const MAX_EXAMINED_PER_RELAY = 256;
/** Upper bound on documents a refresh examines in all. */
export const MAX_REFRESH_DOCS = 1024;
/** Upper bound on the local CPU and chain work of a refresh (fetch time doesn't count, S1). */
export const REFRESH_BUDGET_MS = 2000;
/** Documents the chain walk may examine per relay, in all, apart from the tips phase (pre-release review). */
export const WALK_ALLOWANCE_PER_RELAY = 256;
/** Default per-relay fetch timeout; a relay that doesn't answer in time is skipped (S1). */
export const RELAY_FETCH_TIMEOUT_MS = 5000;

/** refreshIdentity's result: the view, and whether the work bound cut the refresh short. */
export type RefreshedView = IdentityView & {
  /** True when the work budget or document cap was hit: what was placed is committed, but the head may be stale. */
  incomplete?: boolean;
  /** The listed relays that answered the tips request (pre-release review). */
  answeredRelays: string[];
};

function forRelay(result: FetchResult | undefined, relay: string): readonly string[] {
  if (result === undefined) return [];
  if (Array.isArray(result)) return result;
  const r = (result as Readonly<Record<string, readonly string[]>>)[relay];
  return Array.isArray(r) ? r : [];
}

async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T | undefined> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<undefined>((resolve) => {
    timer = setTimeout(() => resolve(undefined), ms);
  });
  try {
    return await Promise.race([p.catch(() => undefined), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Refreshes a user's identity from the relays its stored chain lists, the
 * relays a cached provisional entry lists, or `opts.relays`, and returns the
 * view that results. This (or an approval re-verification, which calls it)
 * is the only way a stranger's identity enters the identity store, and it
 * uses what the relays return, never a bundled document (review N1).
 *  - Each relay is asked separately, with its own timeout (a relay that
 *    doesn't answer is skipped), and its answer is capped on its own: the
 *    highest-`ver` signature-valid tips first, at most 8 per relay, so one
 *    slow or hostile relay can't push out another relay's revoking head
 *    (review S1).
 *  - Hostile input is cheap to reject (review R2): every document's signature,
 *    `iss == H(ik) == userId` and the held `ik` are checked before any chain
 *    work, and the refresh's local work is bounded (1024 documents, 2 s of
 *    CPU and chain work, never counting fetch time). Hitting the bound
 *    commits what was placed and returns `incomplete: true`.
 *  - The held chain is built and verified once; documents are placed in
 *    `ver` order, each once. Gaps are filled by walking back with the §5.6
 *    chain request.
 *  - A version the chain rules REJECT is never adopted (N6).
 *  - When the newest version still can't be fitted: over no history, or
 *    only unanchored history (re-checked at commit, S4), the client jumps to
 *    it (carrying a revocation denylist); over anchored or forked history it
 *    fails closed with `chain-broken` (N7), leaving the jump to an explicit
 *    jumpIdentity.
 *  - Fails closed if no relay returns anything usable, or if the identity is
 *    in the §2.5 fail-closed state. On success the provisional entry is
 *    dropped.
 *  - Freshness (review T1): an `incomplete` result is NOT a refresh, and
 *    neither is one that only a minority of the listed relays answered
 *    (`answeredRelays` says which did). Only a complete refresh answered by
 *    a majority records `lastRefreshed(store, userId)`, which clients
 *    use to schedule the §2.5 10-minute refresh; an incomplete one leaves it
 *    (and the provisional entry) as it was, so the view isn't mistaken for a
 *    fresh one.
 *  - Real fetchers should implement `chain` (§5.6): without it, a client
 *    more than 8 versions behind can't fill the gap (each relay contributes
 *    at most 8 tips) and fails closed with `chain-broken`.
 */
export async function refreshIdentity(
  store: TrustStoreV3,
  userId: string,
  fetch: IdentityFetcher,
  opts: TimeOptions & {
    relays?: readonly string[];
    /** Per-relay fetch timeout (default RELAY_FETCH_TIMEOUT_MS). */
    fetchTimeoutMs?: number;
    /** Work bounds (defaults MAX_REFRESH_DOCS, REFRESH_BUDGET_MS). */
    maxDocs?: number;
    budgetMs?: number;
  } = {},
): Promise<RefreshedView> {
  const now = opts.now ?? nowSec();
  const timeoutMs = opts.fetchTimeoutMs ?? RELAY_FETCH_TIMEOUT_MS;
  const tipsOf = typeof fetch === "function" ? fetch : fetch.tips;
  const chainOf = typeof fetch === "function" ? undefined : fetch.chain;

  // Local work is metered section by section; awaits on the network aren't counted.
  let cpuMs = 0;
  let sectionStart = 0;
  let exhausted = false;
  const maxDocs = opts.maxDocs ?? MAX_REFRESH_DOCS;
  const budgetMs = opts.budgetMs ?? REFRESH_BUDGET_MS;
  let examined = 0;
  const begin = () => {
    sectionStart = Date.now();
  };
  const end = () => {
    cpuMs += Date.now() - sectionStart;
  };
  /** CPU and chain work: stops admission and placement. */
  const overBudget = () => {
    if (!exhausted && cpuMs + (Date.now() - sectionStart) > budgetMs) exhausted = true;
    return exhausted;
  };
  /** The document cap: stops admission only, so admitted documents are still placed. */
  let docsCapped = false;
  const overDocs = () => {
    if (examined >= maxDocs) docsCapped = true;
    return docsCapped || overBudget();
  };

  const stored = await store.getIdentity(userId);
  begin();
  // The chain is built (and verified) once; all placement happens on it.
  const chain = stored && stored.versions.length > 0 ? IdentityChain.fromStored(stored) : new IdentityChain(userId);
  const before = chain.size > 0 ? chain.view() : undefined;
  // Automatic jumps only over nothing or unanchored history (N7).
  const anchoredBefore = chain.size > 0 && chain.anchored;
  end();
  const provisional = await store.getProvisional(userId, now);
  const relays = opts.relays ?? [...new Set([...(before?.relays ?? []), ...(provisional?.relays ?? [])])];
  if (relays.length === 0) fail("identity-unknown", `no relays to refresh ${userId} from`);

  const seen = new Set<string>();
  /**
   * Cheap admission of one relay's answer: the entries claiming the highest
   * `ver` are signature-checked first (at most MAX_EXAMINED_PER_RELAY), and
   * the first `keep` valid ones (iss == H(ik) == userId, the held ik) are kept.
   */
  const admit = (list: readonly string[], keep: number, quota: number, walk = false): { docs: VerifiedIdentityDoc[]; cut: boolean; used: number } => {
    // Cheap filters first (pre-release review T2): after the JSON decode, and before
    // any curve work, the payload must name this userId and (when a chain is
    // held) its ik. Foreign-key junk costs a decode and uses no quota.
    const claimed = list
      .filter((j): j is string => typeof j === "string")
      .slice(0, MAX_EXAMINED_PER_RELAY * 4)
      .map((j) => {
        try {
          const p = decodeJws(j).payload;
          if (p.iss !== userId || (before && p.ik !== before.ik)) return undefined;
          // Hash first: iss must be the fingerprint of the ik it names, before any curve work.
          if (typeof p.ik !== "string" || userIdFromIk(b64uDecode(p.ik, 32)) !== userId) return undefined;
          return { j, ver: typeof p.ver === "number" ? p.ver : -1 };
        } catch {
          return undefined;
        }
      })
      .filter((x): x is { j: string; ver: number } => x !== undefined)
      .sort((a, b) => b.ver - a.ver)
      .slice(0, MAX_EXAMINED_PER_RELAY);
    const out: VerifiedIdentityDoc[] = [];
    let used = 0;
    let cut = false;
    for (const { j } of claimed) {
      if (out.length >= keep) break; // the top `keep` valid ones: complete for this relay
      // Each relay gets its own share of the document cap (T1), so hostile relays can't starve an honest one.
      // The walk has its own allowance: only the CPU budget applies to it, not the tips-phase document cap.
      if (used >= quota || (walk ? overBudget() : overDocs())) {
        cut = true;
        break;
      }
      used++;
      examined++;
      try {
        const d = verifyIdentityDocSignature(j);
        if (d.iss !== userId || (before && d.ik !== before.ik) || seen.has(d.hash)) continue;
        seen.add(d.hash);
        out.push(d);
      } catch (e) {
        if (!(e instanceof P2PError)) throw e;
      }
    }
    return { docs: out, cut, used };
  };
  const accepted: string[] = [];
  const rejected = new Set<string>();
  let gaps: { d: VerifiedIdentityDoc; need: string }[] = [];
  /** New documents in ver order, each once, then one pass over the earlier gaps. */
  const place = (docs: VerifiedIdentityDoc[]) => {
    const pending = [...docs, ...gaps.map((g) => g.d)].sort((a, b) => a.ver - b.ver);
    const next: typeof gaps = [];
    for (const d of pending) {
      if (overBudget()) break; // the rest stays unplaced; what was placed is committed
      try {
        const r = chain.add(d.jws, { now, skewSec: opts.skewSec });
        if (r.status === "gap") next.push({ d, need: r.need });
        else if (r.status === "accepted") accepted.push(d.jws);
      } catch (e) {
        if (!(e instanceof P2PError)) throw e;
        rejected.add(d.hash); // never adopted, not even by a jump (N6)
      }
    }
    gaps = next;
  };
  const answeredRelays = new Set<string>();
  /** Per-relay document allowance of the chain walk, separate from the tips phase (pre-release review). */
  const walkLeft = new Map(relays.map((r) => [r, WALK_ALLOWANCE_PER_RELAY]));
  const fetchEach = async (f: (relay: string) => Promise<FetchResult>, keep: number, walk = false): Promise<VerifiedIdentityDoc[]> => {
    const answers = await Promise.all(relays.map(async (r) => ({ r, res: await withTimeout(f(r), timeoutMs) })));
    if (!walk) for (const { r, res } of answers) if (res !== undefined) answeredRelays.add(r);
    // T1: the remaining tips-phase allowance is split evenly between the relays.
    const quota = Math.floor((maxDocs - examined) / relays.length);
    if (!walk && quota <= 0) {
      docsCapped = true;
      return [];
    }
    begin();
    const results = answers.map(({ r, res }) => {
      const q = walk ? walkLeft.get(r)! : quota;
      const a = admit(forRelay(res, r), keep, q, walk);
      if (walk) walkLeft.set(r, q - a.used);
      return { answered: res !== undefined, ...a };
    });
    // Complete as long as one relay that answered was examined in full; a
    // relay cut short by its quota (junk) doesn't make the refresh incomplete.
    const answered = results.filter((x) => x.answered);
    if (answered.length > 0 && answered.every((x) => x.cut)) docsCapped = true;
    const out = results.flatMap((x) => x.docs);
    end();
    return out;
  };

  const tips = await fetchEach((r) => tipsOf(userId, [r]), MAX_TIPS_PER_RELAY);
  if (tips.length === 0 && !exhausted && !docsCapped) fail("identity-unknown", `no listed relay returned a valid identity document for ${userId}`);
  begin();
  place(tips);
  end();
  // Walk back from the LOWEST gap with the chain request (§5.6), per relay,
  // on the walk's own allowance (pre-release review): filling the lowest gap first
  // connects the most versions, and a hostile majority's tips can't use it up.
  for (let req = 0; chainOf && gaps.length > 0 && !exhausted && req < CHAIN_WALK_MAX_REQUESTS; req++) {
    const lowestGap = gaps.reduce((a, b) => (b.d.ver < a.d.ver ? b : a));
    const page = await fetchEach((r) => chainOf(userId, [r], lowestGap.need, CHAIN_WALK_PAGE), CHAIN_WALK_PAGE, true);
    if (page.length === 0) break;
    begin();
    place(page);
    end();
  }

  // The newest version the relays returned that the chain rules didn't reject.
  const newest = tips.filter((d) => !rejected.has(d.hash)).sort((a, b) => b.ver - a.ver)[0];
  const behind = () => newest !== undefined && (chain.size === 0 || chain.view().head.ver < newest.ver);
  let jumpTo: string | undefined;
  const incomplete = exhausted || docsCapped;
  if (!incomplete && behind()) {
    if (!gaps.some((g) => g.d.hash === newest!.hash)) fail("chain-broken", `could not fit ${userId}'s newest version (ver ${newest!.ver})`);
    if (anchoredBefore) {
      fail("chain-broken", `${userId}'s newest version (ver ${newest!.ver}) doesn't connect to the held history; jumping is the user's call (jumpIdentity)`);
    }
    jumpTo = newest!.jws;
  }
  // Commit once, re-applied onto whatever is stored by now. Nothing new and no jump (the usual
  // refresh): nothing to write, and no need to queue for the store's lock to find that out.
  const unchanged = accepted.length === 0 && jumpTo === undefined && chain.size > 0;
  const jumped = unchanged ? false : await store.updateIdentity(userId, (cur) => {
    const c = cur && cur.versions.length > 0 ? IdentityChain.fromStored(cur) : new IdentityChain(userId);
    // S4: whether the stored history is anchored is re-checked here, before our versions are added.
    const anchoredAtCommit = c.size > 0 && c.anchored;
    for (const j of accepted) {
      try {
        c.add(j, { now, skewSec: opts.skewSec });
      } catch (e) {
        if (!(e instanceof P2PError)) throw e;
      }
    }
    let didJump = false;
    if (jumpTo !== undefined && !anchoredAtCommit && (c.size === 0 || c.view().head.ver < newest!.ver)) {
      c.jumpTo(jumpTo, { now, skewSec: opts.skewSec });
      didJump = true;
    }
    // Nothing new: the stored chain stays as it is, with no write (every write is an fsync under
    // the store's cross-process lock, which every p2p process of the home queues for).
    if (accepted.length === 0 && !didJump && cur) return { result: false };
    return { next: c.toStored(), result: didJump };
  });
  const view = await getIdentityView(store, userId);
  if (!view) return fail("identity-unknown", `no usable identity document for ${userId}`);
  // What was committed must reach the newest version: a concurrent writer may
  // have anchored the history meanwhile (S4), so versions placed on the
  // in-memory copy might not fit what is stored now.
  if (!incomplete && newest !== undefined && view.head.ver < newest.ver) {
    fail("chain-broken", `${userId}'s newest version (ver ${newest.ver}) doesn't connect to the stored history${jumpTo !== undefined && !jumped ? " (anchored meanwhile)" : ""}`);
  }
  assertNotFailClosed(view.exp, now);
  const answered = [...answeredRelays];
  if (incomplete) return { ...view, incomplete: true, answeredRelays: answered };
  await store.deleteProvisional(userId);
  // Freshness needs a majority of the listed relays (pre-release review): with an
  // honest relay unreachable, a stale answer from a minority isn't "fresh".
  if (answered.length * 2 > relays.length) await store.markRefreshed(userId, now);
  return { ...view, answeredRelays: answered };
}

/**
 * Results produced by the approval re-verifications, branded with when
 * (review N8): `reverifiedAt` is informational; only this module-private brand
 * proves re-verification, so a caller can't set it. A copy loses it.
 */
const reverified = new WeakMap<object, number>();
/** How recent a re-verification must be for recordFriendshipV3 to accept a provisional friendship. */
export const REVERIFY_MAX_AGE_SEC = 10 * 60;

/** A store-only signer context: rule 6 never falls back to a bundled document. */
function storeOnly(store: TrustStoreV3, opts: TimeOptions & { resolveCert?: CertResolverV3 }): SignerContext {
  return storeSignerContext(store, { now: opts.now, skewSec: opts.skewSec, resolveCert: opts.resolveCert });
}

/** Relays named by a bundled document, so a refresh can find a stranger the cache has since dropped. */
function bundledRelays(bundledDoc: unknown, userId: string): string[] {
  if (typeof bundledDoc !== "string") return [];
  try {
    const d = peekIdentityDoc(bundledDoc);
    return d.iss === userId ? d.relays : [];
  } catch {
    return [];
  }
}

async function refreshFor(store: TrustStoreV3, userId: string, bundledDoc: unknown, fetch: IdentityFetcher, opts: TimeOptions) {
  const known = (await getIdentityView(store, userId))?.relays ?? [];
  const cached = (await store.getProvisional(userId, opts.now ?? nowSec()))?.relays ?? [];
  const relays = [...new Set([...known, ...cached, ...bundledRelays(bundledDoc, userId)])];
  const view = await refreshIdentity(store, userId, fetch, { ...opts, relays });
  // Approval needs the current head: a refresh cut short by its work bound doesn't qualify.
  if (view.incomplete) fail("chain-broken", `refreshing ${userId} was cut short; try again before approving`);
  return view;
}

/**
 * Before acting on the user's approval of an invite from someone first met
 * through it (review M1): refreshes the inviter's head from its relays, then
 * re-verifies the invite against the stored chain only. A revoked device's
 * invite carrying an old document fails here. The result carries
 * `reverifiedAt`.
 */
export async function reverifyInviteForApproval(
  store: TrustStoreV3,
  inviteJws: string,
  fetch: IdentityFetcher,
  opts: TimeOptions & { resolveCert?: CertResolverV3 } = {},
): Promise<VerifiedInviteV3 & { reverifiedAt: number }> {
  const p = decodeTyped(inviteJws, TYP3.invite).payload;
  if (typeof p.iss !== "string") fail("malformed", "invite iss");
  await refreshFor(store, p.iss, p.doc, fetch, opts);
  const inv = await verifyInviteV3(inviteJws, storeOnly(store, opts), { bundled: false });
  const out = { ...inv, reverifiedAt: opts.now ?? nowSec() };
  reverified.set(out, out.reverifiedAt);
  return out;
}

/**
 * Before adopting a friendship (recordFriendshipV3) with someone first met
 * through it: refreshes the head of every party other than `self` and
 * re-verifies the pair against stored chains only. Only a friendship that
 * went through this (it carries `reverifiedAt`) or was never provisional can
 * be recorded (review N1).
 *
 * API contract (pre-release review): pass the returned object, unchanged, to
 * recordFriendshipV3 in the same process within 10 minutes; the brand that
 * proves re-verification lives in memory only and doesn't survive
 * serialization or copying.
 */
export async function reverifyFriendshipForApproval(
  store: TrustStoreV3,
  proof: { invite: string; accept: string },
  fetch: IdentityFetcher,
  opts: TimeOptions & { resolveCert?: CertResolverV3; self: string },
): Promise<VerifiedFriendshipV3> {
  const inv = decodeTyped(proof.invite, TYP3.invite).payload;
  const acc = decodeTyped(proof.accept, TYP3.accept).payload;
  if (typeof inv.iss !== "string" || typeof acc.iss !== "string") fail("malformed", "friendship iss");
  if (inv.iss !== opts.self) await refreshFor(store, inv.iss, inv.doc, fetch, opts);
  if (acc.iss !== opts.self) await refreshFor(store, acc.iss, acc.doc, fetch, opts);
  const f = await verifyFriendshipV3(proof, storeOnly(store, opts), { bundled: false });
  const out = { ...f, reverifiedAt: opts.now ?? nowSec() };
  reverified.set(out, out.reverifiedAt);
  return out;
}

export async function getIdentityView(store: TrustStoreV3, userId: string): Promise<IdentityView | undefined> {
  const stored = await store.getIdentity(userId);
  if (!stored || stored.versions.length === 0) return undefined;
  // Verified views are cached per store, keyed by the exact stored versions
  // (review N2): signatures are checked once per distinct chain, not per call.
  const key = `${stored.historyGap ? "g" : "a"}:${jwsHash(stored.versions.join("."))}`;
  let cache = viewCache.get(store);
  if (!cache) viewCache.set(store, (cache = new Map()));
  const hit = cache.get(userId);
  if (hit && hit.key === key) return frozenCopy(hit.view);
  const view = IdentityChain.fromStored(stored).view();
  cache.set(userId, { key, view });
  if (cache.size > VIEW_CACHE_MAX) cache.delete(cache.keys().next().value!);
  return frozenCopy(view);
}

/**
 * A deep, frozen copy of a cached value (review N9), so a caller can't corrupt
 * the cache. Typed arrays are copied (they can't be frozen).
 */
function frozenCopy<T>(v: T): T {
  if (v instanceof Uint8Array) return v.slice() as T;
  if (Array.isArray(v)) return Object.freeze(v.map(frozenCopy)) as T;
  if (v !== null && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) out[k] = frozenCopy(x);
    return Object.freeze(out) as T;
  }
  return v;
}

const VIEW_CACHE_MAX = 4096;
const viewCache = new WeakMap<TrustStoreV3, Map<string, { key: string; view: IdentityView }>>();

/** Resolves identities from the store, then `fallback` (e.g. a document bundled with an invite). */
export function storeIdentityResolver(store: TrustStoreV3, fallback?: IdentityResolver): IdentityResolver {
  return async (userId) => (await getIdentityView(store, userId)) ?? (await fallback?.(userId));
}

/** Resolves certificates from the store's cache, then the identity document's `certs`, then `fallback`. */
export function storeCertResolver(store: TrustStoreV3, fallback?: CertResolverV3, now?: number): CertResolverV3 {
  return async (userId, did) => {
    // Every candidate (cache, the documents' `certs`, the fallback); the longest-lived wins.
    const candidates: string[] = [];
    const c = await store.getDeviceCert(did);
    if (c && c.userId === userId) candidates.push(c.jws);
    const view = await getIdentityView(store, userId);
    for (const t of view?.tips ?? []) {
      const found = docCertFor(t, did);
      if (found) candidates.push(found);
    }
    const fb = await fallback?.(userId, did);
    if (fb) candidates.push(fb);
    return longestLived(candidates, { now });
  };
}

/**
 * Of several certificate JWS for one device, the one to use: certificates are
 * verified first (§2.3 rules 1–5 at `now`) and only verified ones are ranked
 * by `exp` (pre-release review L9), so an unverified certificate with a far `exp`
 * can't crowd out a valid one. When none verifies, the latest-`exp` one is
 * returned so the caller's own verification reports the precise reason.
 */
export function longestLived(certs: readonly string[], opts: TimeOptions = {}): string | undefined {
  const rank = (list: readonly string[], check: boolean) => {
    let best: string | undefined;
    let bestExp = -Infinity;
    for (const j of list) {
      try {
        const exp = check ? verifyDeviceCertV3(j, opts).exp : decodeTyped(j, TYP3.device).payload.exp;
        if (typeof exp === "number" && exp > bestExp) {
          best = j;
          bestExp = exp;
        }
      } catch (e) {
        if (!(e instanceof P2PError)) throw e;
      }
    }
    return best;
  };
  return rank(certs, true) ?? rank(certs, false);
}

export function storeSignerContext(store: TrustStoreV3, opts: TimeOptions & { resolveCert?: CertResolverV3; resolveIdentity?: IdentityResolver } = {}): SignerContext {
  return {
    now: opts.now,
    skewSec: opts.skewSec,
    resolveCert: storeCertResolver(store, opts.resolveCert, opts.now),
    resolveIdentity: storeIdentityResolver(store, opts.resolveIdentity),
  };
}

/**
 * The §2.5 freshness of held identities, for circle rule 2 (sync, after
 * preloading). Pass `only` to load just the userIds that can matter (the
 * possible signers), and views come from the verified-view cache (review N2).
 * Never reads the provisional cache.
 */
export async function freshnessLookup(store: TrustStoreV3, now: number = nowSec(), only?: Iterable<string>) {
  const map = new Map<string, ReturnType<typeof identityFreshness>>();
  for (const u of only ? new Set(only) : await store.listIdentities()) {
    const v = await getIdentityView(store, u);
    if (v) map.set(u, identityFreshness(v.exp, now));
  }
  return (u: string) => map.get(u);
}

// ---------------------------------------------------------------------------
// Friendships and blocks

/**
 * Stores a verified friendship. As in v2 (C4), the only way friendships
 * enter the store: the app calls it right after this user accepts an invite,
 * or when an accept arrives for an invite this user issued, or when the
 * user's own devices sync one. One already ended by a stored unfriend is
 * refused (`unfriended`), and so is a provisional one that wasn't
 * re-verified (`provisional`).
 *
 * API contract (pre-release review): for a provisional friendship, call this in the
 * SAME PROCESS as reverifyFriendshipForApproval, with the very object it
 * returned, within 10 minutes (REVERIFY_MAX_AGE_SEC). The re-verification
 * brand is in-memory only: it doesn't survive serialization, structured
 * cloning or a copy, so a result sent across processes must be re-verified
 * again.
 */
export async function recordFriendshipV3(store: TrustStoreV3, f: VerifiedFriendshipV3, opts: { now?: number } = {}): Promise<void> {
  // A friendship whose rule-6 check leaned on a bundled document must first
  // go through reverifyFriendshipForApproval (review N1), recently (N8).
  if (f.provisional) {
    const at = reverified.get(f);
    const now = opts.now ?? nowSec();
    if (at === undefined) fail("provisional", "re-verify the friendship against refreshed identities before recording it");
    if (now - at > REVERIFY_MAX_AGE_SEC) fail("provisional", "the re-verification is stale; re-verify again");
  }
  const unfriends = await store.listUnfriends();
  if (unfriends.some((u) => unfriendApplies(f, u))) fail("unfriended", `friendship ${f.inv} was ended by an unfriend`);
  await store.addFriendship({
    inviter: f.inviter,
    invitee: f.invitee,
    inv: f.inv,
    aud: f.aud,
    iat: f.iat,
    inviteIat: f.inviteIat,
    inviteDid: f.invite.did,
    acceptDid: f.accept.did,
    proof: f.proof,
  });
}

/** Re-verifies stored friendships now (both signers still valid, rules 1–6) and returns the live facts. */
export async function liveFriendshipsV3(store: TrustStoreV3, ctx: SignerContext, involving?: (f: { inviter: string; invitee: string }) => boolean) {
  const out: VerifiedFriendshipV3[] = [];
  for (const f of await store.listFriendships()) {
    if (involving && !involving(f)) continue;
    try {
      // Stored chains only: a bundled document in an old invite never counts (review M1).
      out.push(await verifyFriendshipV3(f.proof, ctx, { bundled: false }));
    } catch (e) {
      if (!(e instanceof P2PError)) throw e;
      // A signer since revoked or lapsed: not a live friendship now.
    }
  }
  return out;
}

/**
 * §3.2: blocks a userId (local, unsigned) and takes back every cap issued to
 * it. The caller sends `{"t":"revoke","capid"}` for each returned cap to
 * every relay it names.
 */
export async function blockUser(store: TrustStoreV3, userId: string, now: number = nowSec()): Promise<StoredCapV3[]> {
  await store.addBlock({ userId, at: now });
  return store.takeCapsIssued((c) => c.sub === userId);
}

/** On unfriend: the caps issued to that friend, to revoke (§5.3). */
export async function capsToRevokeOnUnfriend(store: TrustStoreV3, peer: string): Promise<StoredCapV3[]> {
  return store.takeCapsIssued((c) => c.sub === peer);
}

// ---------------------------------------------------------------------------
// Circles

export interface LoadedCircle {
  record: StoredCircleV3;
  chain: CircleChain;
  book: MembershipBook;
}

export async function loadCircle(store: TrustStoreV3, cid: string): Promise<LoadedCircle | undefined> {
  const record = await store.getCircle(cid);
  if (!record) return undefined;
  return { record, chain: CircleChain.fromStored(record.chain), book: { ...record.statements } };
}

/**
 * A synchronous `stands(user, cid)` over every stored circle (for
 * authorisation). Nobody stands in a circle the viewer hasn't joined (C1),
 * and blocked users stand nowhere.
 */
export async function standsLookup(store: TrustStoreV3, viewer: string): Promise<(user: string, cid: string) => boolean> {
  const blocks = new Set((await store.listBlocks()).map((b) => b.userId));
  const circles = new Map<string, LoadedCircle>();
  for (const r of await store.listCircles()) {
    try {
      circles.set(r.cid, { record: r, chain: CircleChain.fromStored(r.chain), book: r.statements });
    } catch (e) {
      if (!(e instanceof P2PError)) throw e;
    }
  }
  return (user, cid) => {
    const c = circles.get(cid);
    if (!c) return false;
    return standsInCircle(user, c.chain, c.book, { viewer, joinedByMe: c.record.joinedByMe, isBlocked: (u) => blocks.has(u) });
  };
}

/**
 * Stores a circle offered in an invite, bootstrapped from its full chain
 * (§3.3), not yet joined. Joining is a separate, explicit user action
 * (recordOwnJoin). An already-held circle is left alone (its versions go
 * through receive instead).
 */
export async function storeOfferedCircle(store: TrustStoreV3, versions: readonly string[], opts: CircleChainOptions & { head?: string } = {}): Promise<CircleChain> {
  // Rule 2's owner freshness comes from the store unless the caller supplies it (review L3).
  const identityFreshness = opts.identityFreshness ?? (await freshnessLookup(store, opts.now, circleOwners(versions)));
  const chain = CircleChain.bootstrap(versions, { ...opts, identityFreshness });
  await store.updateCircle(chain.cid, (cur) =>
    cur ? { result: undefined } : { next: { cid: chain.cid, chain: chain.toStored(), statements: {}, joinedByMe: false }, result: undefined },
  );
  return chain;
}

/**
 * The viewer's own join (the explicit, local action of §3.3): records the
 * signed statement and marks the circle joined on this device. The statement
 * must be the viewer's own (pre-release review L6) and name a version on the held
 * chain.
 */
export async function recordOwnJoin(store: TrustStoreV3, self: string, join: VerifiedMembership): Promise<void> {
  if (join.iss !== self) fail("cert-mismatch", `the join is ${join.iss}'s, not this user's`);
  if (join.op !== "join" || join.at === undefined) fail("malformed", "not a join statement");
  await store.updateCircle(join.cid, (cur) => {
    if (!cur) return fail("circle-gap", `circle ${join.cid} is not held`);
    const chain = CircleChain.fromStored(cur.chain);
    if (!chain.hasAncestor(join.at!)) fail("circle-invalid", "join names a version not on the held chain");
    const statements = { ...cur.statements };
    applyMembership(statements, membershipFact(join));
    return { next: { ...cur, statements, joinedByMe: true, myN: Math.max(cur.myN ?? -1, join.n) }, result: undefined };
  });
}

/** The viewer's own leave: honoured at once, and the circle no longer counts on this device. */
export async function recordOwnLeave(store: TrustStoreV3, self: string, leave: VerifiedMembership): Promise<void> {
  if (leave.iss !== self) fail("cert-mismatch", `the leave is ${leave.iss}'s, not this user's`);
  if (leave.op !== "leave") fail("malformed", "not a leave statement");
  await store.updateCircle(leave.cid, (cur) => {
    if (!cur) return { result: undefined };
    const statements = { ...cur.statements };
    applyMembership(statements, membershipFact(leave));
    return { next: { ...cur, statements, joinedByMe: false, myN: Math.max(cur.myN ?? -1, leave.n) }, result: undefined };
  });
}

export interface CircleBundleResult {
  versions: Record<string, CircleReceiveResult[]>;
  joins: { jws: string; status: "applied" | "ignored" | "rejected"; reason?: string; statement?: VerifiedMembership }[];
  ops: { jws: string; status: "queued" | "ignored" | "rejected"; reason?: string; proposal?: VerifiedProposal }[];
}

/**
 * Applies an authorised `circle` bundle (§4.3) to held circles:
 *  - versions go through each held chain's receive() (unknown circles are
 *    ignored here: an offered circle is stored by storeOfferedCircle);
 *  - membership statements need a signer valid now (N4) and become current
 *    by the §3.3 ordering;
 *  - proposals are queued for the owner's client when `self` owns the circle.
 */
export async function applyCircleBundle(
  store: TrustStoreV3,
  bundle: { circles: readonly string[]; joins: readonly string[]; ops: readonly string[] },
  ctx: SignerContext & CircleChainOptions & { self: string },
): Promise<CircleBundleResult> {
  const now = ctx.now ?? nowSec();
  // Rule 2's owner freshness comes from the store unless the caller supplies it (review L3).
  const out: CircleBundleResult = { versions: {}, joins: [], ops: [] };
  const byCid = new Map<string, string[]>();
  const owners = new Set<string>();
  for (const j of bundle.circles) {
    try {
      const v = parseCircleVersion(j);
      byCid.set(v.cid, [...(byCid.get(v.cid) ?? []), j]);
      owners.add(v.owner);
    } catch (e) {
      if (!(e instanceof P2PError)) throw e;
    }
  }
  // Only the possible signers matter: the held heads' owners and owners the versions name (review N2).
  for (const cid of byCid.keys()) {
    const held = (await store.getCircle(cid))?.chain.versions;
    if (held?.length) owners.add(String(decodeJws(held[held.length - 1]).payload.owner));
  }
  const identityFreshness = ctx.identityFreshness ?? (await freshnessLookup(store, now, owners));
  for (const [cid, list] of byCid) {
    out.versions[cid] = await store.updateCircle<CircleReceiveResult[]>(cid, (cur) => {
      if (!cur) return { result: list.map(() => ({ status: "ignored" as const, reason: "circle not held" })) };
      const chain = CircleChain.fromStored(cur.chain);
      const before = chain.head;
      const results = chain.receive(list, { ...ctx, identityFreshness });
      return { next: { ...trackRemovals(cur, before, chain.head, now), chain: chain.toStored() }, result: results };
    });
  }
  for (const j of bundle.joins) {
    let s: VerifiedMembership;
    try {
      s = await verifyMembershipStatement(j, ctx);
    } catch (e) {
      if (!(e instanceof P2PError)) throw e;
      out.joins.push({ jws: j, status: "rejected", reason: e.reason });
      continue;
    }
    const applied = await store.updateCircle<boolean | "cap-too-long">(s.cid, (cur) => {
      if (!cur) return { result: false };
      // Open circles: join caps live at most 14 days (review M4).
      if (s.op === "join" && !joinCapFitsPolicy(s.joinCap, circlePolicy(CircleChain.fromStored(cur.chain).head))) return { result: "cap-too-long" };
      const statements = { ...cur.statements };
      if (!applyMembership(statements, membershipFact(s))) return { result: false };
      const myN = s.iss === ctx.self ? Math.max(cur.myN ?? -1, s.n) : cur.myN;
      return { next: { ...cur, statements, ...(myN !== undefined ? { myN } : {}) }, result: true };
    });
    if (applied === "cap-too-long") out.joins.push({ jws: j, status: "rejected", reason: "cap-invalid", statement: s });
    else out.joins.push({ jws: j, status: applied ? "applied" : "ignored", statement: s });
  }
  for (const j of bundle.ops) {
    let p: VerifiedProposal;
    try {
      p = await verifyProposal(j, ctx);
    } catch (e) {
      if (!(e instanceof P2PError)) throw e;
      out.ops.push({ jws: j, status: "rejected", reason: e.reason });
      continue;
    }
    const queued = await store.updateCircle(p.cid, (cur) => {
      if (!cur) return { result: false };
      const head = CircleChain.fromStored(cur.chain).head;
      if (head.owner !== ctx.self) return { result: false };
      if ((cur.proposals ?? []).includes(j)) return { result: false };
      return { next: { ...cur, proposals: [...(cur.proposals ?? []), j] }, result: true };
    });
    out.ops.push({ jws: j, status: queued ? "queued" : "ignored", proposal: p });
  }
  return out;
}

/**
 * The owner's client: applies queued proposals (§3.3) against the held head.
 * Proposals are re-verified now (signer valid when applied, too); applied,
 * skipped, stale and refused ones leave the inbox, held ones stay. The
 * application itself (head, applied nonces, inbox) is one atomic store
 * update, so two concurrent runs can't both apply a nonce (pre-release review L4);
 * proposals queued meanwhile wait for the next run. The caller signs `draft`
 * with createNextCircleVersion, then feeds that version back through
 * applyCircleBundle (and sends it to every member and its own devices), and
 * tells admins about `stale` results.
 */
export async function applyOwnerProposals(
  store: TrustStoreV3,
  cid: string,
  ctx: SignerContext & { hold?: boolean },
): Promise<ApplyProposalsResult | undefined> {
  const snapshot = await store.getCircle(cid);
  if (!snapshot) return undefined;
  // Signature checks are async, so they run first; the store update is synchronous.
  const verified = new Map<string, VerifiedProposal>();
  const invalid = new Set<string>();
  for (const j of snapshot.proposals ?? []) {
    try {
      verified.set(j, await verifyProposal(j, ctx));
    } catch (e) {
      if (!(e instanceof P2PError)) throw e;
      invalid.add(j);
    }
  }
  return store.updateCircle<ApplyProposalsResult | undefined>(cid, (cur) => {
    if (!cur) return { result: undefined };
    const inbox = cur.proposals ?? [];
    const now = inbox.filter((j) => verified.has(j)).map((j) => verified.get(j)!);
    const r = applyProposals(CircleChain.fromStored(cur.chain), now, cur.applied ?? {}, { now: ctx.now, skewSec: ctx.skewSec, hold: ctx.hold });
    const held = new Set(r.results.filter((x) => x.status === "held").map((x) => x.nonce));
    // Keep held proposals, and anything queued after the snapshot (not yet verified).
    const proposals = inbox.filter((j) => (verified.has(j) && held.has(verified.get(j)!.nonce)) || (!verified.has(j) && !invalid.has(j)));
    return { next: { ...cur, applied: r.applied, proposals }, result: r };
  });
}

/**
 * Records removals (pre-release review M3): members the new head drops while their
 * current statement is a join (they didn't leave) go into `removed`, which
 * an open circle consults whatever they sign later; a member the head lists
 * again leaves it. A removal also stamps `removalSeenAt` (M4).
 */
function trackRemovals(cur: StoredCircleV3, before: VerifiedCircleVersion, after: VerifiedCircleVersion, now: number): StoredCircleV3 {
  if (before.hash === after.hash) return cur;
  const removed = new Set(cur.removed ?? []);
  let removal = false;
  for (const m of before.members) {
    if (after.members.includes(m)) continue;
    if (cur.statements[m]?.op === "leave") continue;
    removed.add(m);
    removal = true;
  }
  for (const m of after.members) removed.delete(m);
  const next: StoredCircleV3 = { ...cur, removed: [...removed] };
  if (next.removed!.length === 0) delete next.removed;
  if (removal) next.removalSeenAt = now;
  return next;
}

/** What the member's client must do about its join cap in an open circle (pre-release review M4). */
export interface JoinCapAction {
  cid: string;
  /** removal: someone was removed since the cap was issued; too-long: the cap outlives 14 days; renew: it lapses soon. */
  reason: "removal" | "too-long" | "renew";
  /** Sign a new join with this n, naming `at` (the held head), with a fresh cap of `capTtlSec`. */
  nextN: number;
  at: string;
  capTtlSec: number;
  /** Then send `{"t":"revoke","capid"}` to each of these relays. */
  revoke?: { capid: string; relays: string[] };
}

/**
 * Draft 3 additions P2 (pre-release review M4): in each joined `policy: "open"`
 * circle, the actions this user's client must take on its join cap: re-sign
 * (n+1, fresh cap of at most 14 days) when the owner removed anyone since the
 * cap was issued, when the cap outlives 14 days (e.g. the circle just became
 * open), or when it lapses within 3 days; and revoke the old capid at the
 * relays it names. Pure: the caller signs, sends and revokes.
 */
export async function openCircleCapActions(store: TrustStoreV3, self: string, now: number = nowSec()): Promise<JoinCapAction[]> {
  const out: JoinCapAction[] = [];
  for (const rec of await store.listCircles()) {
    if (!rec.joinedByMe) continue;
    let head: VerifiedCircleVersion;
    try {
      head = CircleChain.fromStored(rec.chain).head;
    } catch (e) {
      if (!(e instanceof P2PError)) throw e;
      continue;
    }
    if (circlePolicy(head) !== "open") continue;
    const mine = rec.statements[self];
    if (!mine || mine.op !== "join") continue;
    const cap = mine.capInfo;
    let reason: JoinCapAction["reason"] | undefined;
    if (!cap || !joinCapFitsPolicy(cap, "open")) reason = "too-long";
    else if (rec.removalSeenAt !== undefined && cap.iat < rec.removalSeenAt) reason = "removal";
    else if (cap.exp - now <= OPEN_JOIN_CAP_RENEW_SEC) reason = "renew";
    if (!reason) continue;
    out.push({
      cid: rec.cid,
      reason,
      nextN: Math.max(rec.myN ?? -1, mine.n) + 1,
      at: head.hash,
      capTtlSec: OPEN_JOIN_CAP_MAX_TTL_SEC,
      ...(cap ? { revoke: { capid: cap.capid, relays: cap.relays } } : {}),
    });
  }
  return out;
}

/** Owners named by circle versions (the possible signers for rule 2). */
export function circleOwners(versions: readonly string[]): string[] {
  const out = new Set<string>();
  for (const j of versions) {
    try {
      const o = decodeJws(j).payload.owner;
      if (typeof o === "string") out.add(o);
    } catch (e) {
      if (!(e instanceof P2PError)) throw e;
    }
  }
  return [...out];
}

/**
 * The owner's client, for a verified join statement sent to it (review N4):
 * decideOpenJoin with the circle's own `removed` record and hourly limiter,
 * updated atomically. On "accept" the caller adds the joiner in the next
 * version (createNextCircleVersion) and feeds it back through
 * applyCircleBundle.
 */
export async function decideOpenJoinFor(
  store: TrustStoreV3,
  join: VerifiedMembership,
  opts: { now?: number; maxPerHour?: number } = {},
): Promise<OpenJoinDecision> {
  const blocked = await store.isBlocked(join.iss);
  return store.updateCircle<OpenJoinDecision>(join.cid, (cur) => {
    if (!cur) return { result: { decision: "ignore", reason: "other-circle" } };
    const limiter: OpenJoinLimiter = { acceptedAt: [...(cur.openJoins?.acceptedAt ?? [])] };
    const decision = decideOpenJoin(CircleChain.fromStored(cur.chain), join, cur.statements, limiter, {
      now: opts.now,
      maxPerHour: opts.maxPerHour,
      isBlocked: () => blocked,
      removed: cur.removed ?? [],
    });
    return { next: { ...cur, openJoins: limiter }, result: decision };
  });
}

/**
 * The bundle to send for a held circle (review N5): its versions from `fromVer`
 * and the membership statements held, through buildCircleBundle, which
 * withholds joins whose caps don't fit the circle's policy. Every
 * bundle-send path (the owner's 24 h re-send, answers to `want`, invites)
 * uses this.
 */
export async function outgoingCircleBundle(store: TrustStoreV3, cid: string, opts: { fromVer?: number } = {}) {
  const loaded = await loadCircle(store, cid);
  if (!loaded) return undefined;
  return buildCircleBundle(loaded.chain, loaded.book, opts);
}

/** When `userId`'s identity was last completely refreshed (seconds), if ever. Incomplete refreshes don't count. */
export async function lastRefreshed(store: TrustStoreV3, userId: string): Promise<number | undefined> {
  return store.getRefreshed(userId);
}
