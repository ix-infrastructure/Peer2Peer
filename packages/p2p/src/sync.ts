// Copyright 2026 Ix Infrastructure Inc.
//
// `sync` envelopes (§4.3, from == to only): how a user's devices share
// state. Each object is re-verified on arrival where it can be (friendships,
// unfriends, caps held, circle chains and statements); local preferences
// (blocks, petnames, the default circle) are taken as the user's own.
//
// Reading: joining a circle is the user's explicit action (review C1); it is
// carried to the user's own devices by sync, with `myN` kept in step (§3.3).

import {
  applyCircleBundle,
  CircleChain,
  loadCircle,
  P2PError,
  recordFriendshipV3,
  storeOfferedCircle,
  verifyCap,
  peekIdentityDoc,
  reverifyFriendshipForApproval,
  verifyUnfriendV3,
  type StoredCapV3,
  type StoredOutgoingInviteV3,
  parseCircleVersion,
} from "@peer2peer/core/v3";
import { FileDocBackend } from "@peer2peer/core/v3/node";
import { App } from "./app.js";
import { importCodes } from "./codes.js";
import { importWantAnswered } from "./circle-ops.js";
import { importRotationApprovals, importRotationDispute, importRotationResolved, noteOwnRotation, untrustedImportSigner } from "./rotation.js";

export interface SyncCircle {
  cid: string;
  versions: string[];
  statements: string[];
  joinedByMe: boolean;
  myN?: number;
  /** The owner's removal record (StoredCircleV3.removed): it only ever holds a join, never admits one. */
  removed?: string[];
}

export interface SyncBody {
  friendships?: { invite: string; accept: string }[];
  unfriends?: string[];
  blocks?: string[];
  unblocks?: string[];
  petnames?: Record<string, string | null>;
  capsHeld?: string[];
  capsIssued?: StoredCapV3[];
  outgoing?: StoredOutgoingInviteV3[];
  circles?: SyncCircle[];
  contacts?: string[];
  defaultCircle?: string | null;
  /** The default circle was set by a code join (running sessions don't move into it). */
  defaultFromJoin?: string;
  /** Wants this device answered (circle-ops noteAnswered): our other devices' fallback stays quiet, and budgets are shared. */
  wantAnswered?: unknown[];
  /** P4 short codes this user issued (CodeRecord). */
  codes?: unknown[];
  /**
   * §2.8 step 4: our identity is rotating. `{statement, link, keyholder?}`:
   * the two-part statement and a one-time link code minted by the new
   * identity for this device only.
   */
  rotation?: unknown;
  /** pre-release re-review M2: rotations this user carried over on one device (`{old, to, kind, cid?}`), so every device suspends on a later conflict. */
  rotationApprovals?: unknown[];
  /** A contested rotation (`{old, candidates, suspended}`): every device suspends the same identities and holds the dispute. */
  rotationDispute?: unknown;
  /** A dispute a key holder settled (`{old, keep, rejected}`); taken from a current key holder only. */
  rotationResolved?: unknown;
}

/**
 * Keeps each sync (and circle bundle) plaintext under the 64 KiB envelope cap (§1). Sealing and the
 * two layers of base64 (the ciphertext, then the JWS payload) make an envelope about 16/9 of its
 * plaintext, plus ~3 KiB of certificate and fields: 36 KiB came out at ~66 KB, and a long circle
 * chain could no longer be sent at all (found by the soak harness). 30 KiB leaves ~9 KiB spare.
 */
export const SYNC_CHUNK_BYTES = 30 * 1024;

const bytes = (v: unknown) => Buffer.byteLength(JSON.stringify(v ?? null), "utf8");

/** Sync fields that are maps merged key by key on import, so a large one can be split (review M2). */
const MAP_FIELDS = new Set(["petnames"]);

/**
 * A circle export cut into items that each fit a chunk (review M2): its versions in order, then its
 * statements, each item carrying the circle's metadata. importCircle puts them back together.
 */
export function splitCircle(c: SyncCircle, max = SYNC_CHUNK_BYTES - 1024): SyncCircle[] {
  if (bytes(c) <= max) return [c];
  const { versions, statements, ...meta } = c;
  const out: SyncCircle[] = [];
  let cur: SyncCircle = { ...meta, versions: [], statements: [] };
  let size = bytes(cur);
  const add = (field: "versions" | "statements", v: string) => {
    const s = bytes(v) + 1;
    if (size + s > max && (cur.versions.length > 0 || cur.statements.length > 0)) {
      out.push(cur);
      cur = { ...meta, versions: [], statements: [] };
      size = bytes(cur);
    }
    cur[field].push(v);
    size += s;
  };
  for (const v of versions) add("versions", v);
  for (const s of statements) add("statements", s);
  out.push(cur);
  return out;
}

/** Splits a body of arrays into several bodies, each at most `max` bytes of UTF-8 JSON (single items may exceed it). */
export function chunkBody<T extends Record<string, unknown>>(body: T, max = SYNC_CHUNK_BYTES): T[] {
  const out: Record<string, unknown>[] = [];
  let cur: Record<string, unknown> = {};
  let size = 2;
  const flush = () => {
    if (Object.keys(cur).length > 0) out.push(cur);
    cur = {};
    size = 2;
  };
  for (const [k, v] of Object.entries(body)) {
    if (!Array.isArray(v)) {
      const s = bytes(v) + Buffer.byteLength(k, "utf8") + 4;
      // A map (petnames) too big for one chunk goes in parts: the receiver merges it key by key.
      if (MAP_FIELDS.has(k) && v !== null && typeof v === "object" && s > max / 2) {
        for (const [mk, mv] of Object.entries(v as Record<string, unknown>)) {
          const es = bytes(mk) + bytes(mv) + 2;
          if (size + es + k.length + 8 > max) flush();
          const m = ((cur[k] as Record<string, unknown> | undefined) ??= {});
          m[mk] = mv;
          size += es + (Object.keys(m).length === 1 ? Buffer.byteLength(k, "utf8") + 6 : 0);
        }
        continue;
      }
      if (size + s > max) flush();
      cur[k] = v;
      size += s;
      continue;
    }
    for (const item of v) {
      const s = bytes(item) + Buffer.byteLength(k, "utf8") + 4;
      if (size + s > max) flush();
      (cur[k] = (cur[k] as unknown[] | undefined) ?? []);
      (cur[k] as unknown[]).push(item);
      size += s;
    }
  }
  flush();
  return out as T[];
}

export async function exportCircle(app: App, cid: string): Promise<SyncCircle | undefined> {
  const c = await loadCircle(app.store, cid);
  if (!c) return undefined;
  return {
    cid,
    versions: c.chain.versionsFrom(1),
    statements: Object.values(c.book).map((s) => s.jws),
    joinedByMe: c.record.joinedByMe,
    ...(c.record.myN !== undefined ? { myN: c.record.myN } : {}),
    ...(c.record.removed?.length ? { removed: c.record.removed } : {}),
  };
}

/**
 * Takes over another store of ours' removal record (a device of ours by sync, or our old identity
 * on rotation): the union of the removed members still off the head. It can only add holds: every
 * former member's open re-join is held anyway (review H1, as on main).
 */
export async function mergeRemovals(app: App, cid: string, removed: readonly string[] | undefined): Promise<void> {
  if (!removed?.length) return;
  await app.store.updateCircle(cid, (cur) => {
    if (!cur) return { result: undefined };
    const head = CircleChain.fromStored(cur.chain).head;
    const all = [...new Set([...(cur.removed ?? []), ...(removed ?? [])])].filter((m) => !head.members.includes(m));
    const next = { ...cur, ...(all.length ? { removed: all } : {}) };
    if (!all.length) delete next.removed;
    return { next, result: undefined };
  });
}

/** Everything a newly linked device needs (§2.4 is followed by a sync). */
export async function exportAll(app: App): Promise<SyncBody> {
  const circles: SyncCircle[] = [];
  for (const r of await app.store.listCircles()) {
    const c = await exportCircle(app, r.cid);
    if (c) circles.push(c);
  }
  const contacts: string[] = [];
  for (const u of await app.store.listIdentities()) {
    if (u === app.userId) continue;
    const v = await app.view(u);
    if (v) contacts.push(v.head.jws);
  }
  return {
    friendships: (await app.store.listFriendships()).map((f) => f.proof),
    unfriends: (await app.store.listUnfriends()).map((u) => u.jws),
    blocks: (await app.store.listBlocks()).map((b) => b.userId),
    petnames: await app.store.listPetnames(),
    capsHeld: (await app.store.listCapsHeld()).map((c) => c.jws),
    capsIssued: await app.store.listCapsIssued(),
    outgoing: await listOutgoing(app),
    circles,
    contacts,
    defaultCircle: app.self?.defaultCircle ?? null,
    codes: Object.values((await app.state.get("codes")) ?? {}),
  };
}

/** The store keeps outgoing invites by `inv` without a list API; read its document directly (read-only). */
export async function listOutgoing(app: App): Promise<StoredOutgoingInviteV3[]> {
  const doc = (await new FileDocBackend(app.store.dir).read("v3-outgoing")) as Record<string, StoredOutgoingInviteV3> | undefined;
  return Object.values(doc ?? {});
}

/** Sends `body` to our other devices (all of them, or `only`), chunked. */
export async function sendSync(app: App, body: SyncBody, only?: readonly string[]): Promise<number> {
  const view = await app.view(app.userId);
  if (!view || view.devices.filter((d) => d !== app.did).length === 0) return 0;
  let n = 0;
  // A circle with a long chain is more than one envelope: its export goes in slices (review M2).
  const split = body.circles ? { ...body, circles: body.circles.flatMap((c) => splitCircle(c)) } : body;
  for (const part of chunkBody(split as Record<string, unknown>)) {
    try {
      const d = await app.deliver(app.userId, "sync", { own: app.userId, sid: "~sync" }, part, only ? { onlyDevices: only } : {});
      if (d.relays.length > 0) n++;
    } catch (e) {
      app.io.err(`sync to your other devices failed: ${(e as Error).message}`);
    }
  }
  return n;
}

/** One bad item never aborts the rest of a sync: each is applied on its own, failures logged. */
let syncLog: ((m: string) => void) | undefined;
const ignore = (e: unknown) => {
  if (!(e instanceof P2PError)) syncLog?.(`sync: skipped an item: ${(e as Error)?.message ?? String(e)}`);
};

export async function importSync(app: App, raw: Record<string, unknown>, meta: { fdid?: string } = {}): Promise<void> {
  syncLog = (m) => app.io.err(m);
  const body = raw as SyncBody;
  const ctx = app.signerCtx();
  // Contacts' documents: refreshed from the relays they list, never taken as sent.
  for (const c of body.contacts ?? []) {
    let iss: string | undefined;
    try {
      iss = peekIdentityDoc(c).iss;
    } catch {
      continue;
    }
    await app.refreshIdentity(iss, App.relaysOf(c), { force: true, quiet: true }).catch(ignore);
  }
  for (const proof of body.friendships ?? []) {
    try {
      // Re-verified against refreshed identities (the friend may be new to this device).
      const f = await reverifyFriendshipForApproval(app.store, proof, app.fetcher(), { self: app.userId });
      // pre-release re-review L1: while our identity is rotating (or was rotated by someone), a friendship
      // our side of which a device we can't vouch for signed isn't taken: a thief's device could
      // plant accomplices that way for the rotation to carry over.
      const why = await untrustedImportSigner(app, f.inviter === app.userId ? f.invite.did : f.accept.did);
      if (why) {
        syncLog?.(`sync: not taking a friendship made by another device while your identity is rotating (${why})`);
        continue;
      }
      await recordFriendshipV3(app.store, f);
    } catch (e) {
      ignore(e);
    }
  }
  for (const j of body.unfriends ?? []) {
    try {
      const u = await verifyUnfriendV3(j, ctx);
      await app.store.addUnfriend({ iss: u.iss, peer: u.peer, inv: u.inv, iat: u.iat, jws: u.jws });
    } catch (e) {
      ignore(e);
    }
  }
  for (const u of body.blocks ?? []) await app.store.addBlock({ userId: u, at: Math.floor(Date.now() / 1000) }).catch(ignore);
  for (const u of body.unblocks ?? []) await app.store.removeBlock(u).catch(ignore);
  for (const [u, p] of Object.entries(body.petnames ?? {})) await app.store.setPetname(u, p ?? undefined).catch(ignore);
  for (const j of body.capsHeld ?? []) {
    try {
      const c = verifyCap(j);
      await app.store.addCapHeld({ capid: c.capid, iss: c.iss, sub: c.sub, relays: c.relays, kinds: c.kinds, exp: c.exp, jws: c.jws });
    } catch (e) {
      ignore(e);
    }
  }
  // review M5: a record is rebuilt from its verified JWS (our own signature), never trusted field by field.
  for (const c of body.capsIssued ?? []) {
    const v = verifiedIssuedCap(app, c.jws);
    if (v) await app.store.addCapIssued(v).catch(ignore);
  }
  for (const o of body.outgoing ?? []) await app.store.addOutgoingInvite(o).catch(ignore);
  for (const c of body.circles ?? []) await importCircle(app, c).catch(ignore);
  if (Array.isArray(body.codes)) await importCodes(app, body.codes).catch(ignore);
  if (body.wantAnswered !== undefined) await importWantAnswered(app, body.wantAnswered).catch(ignore);
  if (body.rotation !== undefined) await noteOwnRotation(app, body.rotation, meta.fdid).catch(ignore);
  if (body.rotationApprovals !== undefined) await importRotationApprovals(app, body.rotationApprovals).catch(ignore);
  if (body.rotationDispute !== undefined) await importRotationDispute(app, body.rotationDispute).catch(ignore);
  if (body.rotationResolved !== undefined) await importRotationResolved(app, body.rotationResolved, meta.fdid).catch(ignore);
  if (body.defaultCircle !== undefined) {
    const byJoin = typeof body.defaultFromJoin === "string" && body.defaultFromJoin === body.defaultCircle ? body.defaultFromJoin : undefined;
    await app.updateSelf((s) => {
      const { defaultFromJoin: _was, ...rest } = s;
      return { ...rest, defaultCircle: body.defaultCircle ?? undefined, ...(byJoin ? { defaultFromJoin: byJoin } : {}) };
    });
  }
}

/** A cap this user issued, from its JWS: signature and cert checked, every field taken from the payload. */
export function verifiedIssuedCap(app: App, jws: unknown): StoredCapV3 | undefined {
  if (typeof jws !== "string") return undefined;
  try {
    const c = verifyCap(jws);
    if (c.iss !== app.userId) return undefined;
    return { capid: c.capid, iss: c.iss, sub: c.sub, relays: c.relays, kinds: c.kinds, exp: c.exp, jws };
  } catch (e) {
    ignore(e);
    return undefined;
  }
}

function verOf(v: string): number {
  try {
    return parseCircleVersion(v).ver;
  } catch {
    return 0;
  }
}

function sortVersions(vs: readonly string[]): string[] {
  return [...vs].sort((a, b) => verOf(a) - verOf(b));
}

/** Slices waiting for the rest of their circle are dropped this long after the circle's first one. */
const SYNC_SLICE_TTL_MS = 24 * 3600_000;
/** At most this much waiting for one circle (beyond it the slice is dropped), and for all. */
const SYNC_SLICE_MAX_BYTES = 4 * 1024 * 1024;
const SYNC_SLICES_TOTAL_BYTES = 16 * 1024 * 1024;

async function importCircle(app: App, c: SyncCircle): Promise<void> {
  try {
    // A slice of a split export (splitCircle), together with what earlier slices left waiting. The
    // buffer is bounded per circle and in all, and its 24 h starts with a circle's first slice.
    const now = Date.now();
    const held = await app.store.getCircle(c.cid);
    const headVer = held ? CircleChain.fromStored(held.chain).head.ver : 0;
    // A version that doesn't parse is dropped, not kept: it would stall the circle's slices for good.
    const fresh = c.versions.filter((v) => verOf(v) > headVer);
    const waiting = await app.state.update("syncCircles", (cur = {}) => {
      const keep = Object.fromEntries(Object.entries(cur).filter(([, w]) => now - w.at < SYNC_SLICE_TTL_MS));
      const w = keep[c.cid] ?? { versions: [], statements: [], at: now };
      // `held` is re-read here, under the state lock, from what the buffer says was applied: a slice
      // another process applied meanwhile is not kept again.
      const merged = { versions: [...new Set([...w.versions.filter((v) => verOf(v) > headVer), ...fresh])], statements: [...new Set([...w.statements, ...c.statements])], at: w.at };
      if (bytes(merged) > SYNC_SLICE_MAX_BYTES) return { result: undefined };
      const others = Object.entries(keep).filter(([cid]) => cid !== c.cid);
      // Over the overall cap, the oldest other circles' slices go first.
      others.sort((x, y) => x[1].at - y[1].at);
      let total = bytes(merged) + others.reduce((n, [, x]) => n + bytes(x), 0);
      while (total > SYNC_SLICES_TOTAL_BYTES && others.length > 0) total -= bytes(others.shift()![1]);
      return { next: { ...Object.fromEntries(others), [c.cid]: merged }, result: merged };
    });
    if (!waiting) return;
    // Applied only once the versions line up (from 1, or from the held head): each slice is
    // verified once, not again with every later slice.
    const versions = sortVersions(waiting.versions);
    const vers = versions.map(verOf);
    const contiguous = vers.every((v, i) => v === (i === 0 ? headVer + 1 : vers[i - 1] + 1) || (i > 0 && v === vers[i - 1]));
    if (versions.length > 0 && !contiguous) return;
    if (!held) {
      if (versions.length === 0) return;
      await storeOfferedCircle(app.store, versions);
    }
    await applyCircleBundle(app.store, { circles: held ? versions : [], joins: waiting.statements, ops: [] }, { ...app.signerCtx(), self: app.userId });
    // Under the lock, from the head now held: only what was applied leaves the buffer; slices that
    // arrived meanwhile (another process) stay for their turn.
    const newHead = CircleChain.fromStored((await app.store.getCircle(c.cid))!.chain).head.ver;
    await app.state.update("syncCircles", (cur = {}) => {
      const w = cur[c.cid];
      if (!w) return { result: undefined };
      const versionsLeft = w.versions.filter((v) => verOf(v) > newHead);
      const statementsLeft = w.statements.filter((x) => !waiting.statements.includes(x));
      const { [c.cid]: _done, ...others } = cur;
      return { next: versionsLeft.length || statementsLeft.length ? { ...others, [c.cid]: { versions: versionsLeft, statements: statementsLeft, at: w.at } } : others, result: undefined };
    });
    await app.store.updateCircle(c.cid, (cur) => {
      if (!cur) return { result: undefined };
      const myN = Math.max(cur.myN ?? -1, c.myN ?? -1);
      // A leave synced from another device ends the join here too; a join is carried over.
      const mine = cur.statements[app.userId];
      const joinedByMe = mine ? mine.op === "join" && (c.joinedByMe || cur.joinedByMe) && CircleChain.fromStored(cur.chain).hasAncestor(mine.at ?? "") : false;
      return { next: { ...cur, joinedByMe, ...(myN >= 0 ? { myN } : {}) }, result: undefined };
    });
    await mergeRemovals(app, c.cid, c.removed);
  } catch (e) {
    ignore(e);
  }
}
