// Copyright 2026 Ix Infrastructure Inc.
//
// Friends, blocks, petnames and held first contacts (docs/protocol.md §3.1,
// §3.2, §5.3).
//
//  - `invite` mints a contact-only cap (§5.3) and an invite carrying our
//    ik, relays and identity document, so the invitee needs no lookup.
//  - `accept` records the friendship, then sends the accept (with our friend
//    cap and document) as a `contact` envelope using the invite's cap.
//  - The inviter, on the accept, records the friendship and grants its own
//    friend cap back in a `contact` envelope (§5.3: caps in both directions).
//  - Invites from anyone are held for the user (§3.1); nothing is acted on
//    automatically.
//  - Unfriend and block revoke the caps issued to that user at every relay
//    they name.
//
// Reading of `--uses N`: the cap's per-relay use count (§5.3 SHOULD for
// shareable codes). An invite still binds to the first person who accepts it
// (v2 "invite-already-bound").

import {
  b32Encode,
  blockUser,
  sha256,
  capsToRevokeOnUnfriend,
  createAcceptV3,
  createCap,
  createInviteV3,
  createUnfriendV3,
  DEFAULT_SKEW_SEC,
  INVITE_MAX_TTL_SEC,
  inviteIatAfterUnfriends,
  inviteHashV3,
  inviteLink,
  liveFriendshipsV3,
  nowSec,
  P2PError,
  parseInviteLink,
  recordFriendshipV3,
  verifyInviteV3,
  reverifyInviteForApproval,
  reverifyFriendshipForApproval,
  type VerifiedInviteV3,
  verifyFriendshipV3,
  parseCircleVersion,
  unfriendApplies,
  unfriendEndingInvite,
  circleDisplayName,
  verifyUnfriendV3,
  type AcceptedMessageV3,
  peekIdentityDoc,
} from "@peer2peer/core/v3";
import { isOwnRelay, refusePrivateRelays, refusePrivateResolved } from "./shortcode.js";
import type { App, Delivery } from "./app.js";
import { CliError } from "./errors.js";
import { isTransient } from "./transient.js";
import { fromOf, makeEvent, type NewEvent } from "./inbound.js";
import { recordJoinAnswer, rekeyJoinsExcluding } from "./circle-ops.js";
import { listOutgoing, sendSync, type SyncBody } from "./sync.js";
import { codeByInv, codeHint, onCodeRedeemed } from "./codes.js";
import { onRotationContact } from "./rotation.js";
import type { HeldItem } from "./state.js";

export interface InviteResult {
  invite: { inv: string; aud: string; exp: number; uses: number };
  link: string;
  web: string;
  delivered?: Delivery;
}

/** A minted invite (§3.1): recorded as outgoing, its contact cap as issued, both synced. */
export interface MintedInvite {
  jws: string;
  inv: string;
  aud: string;
  exp: number;
  uses: number;
  cap: string;
}

export async function mintInvite(app: App, opts: { aud: string; uses: number; ttlSec: number; extraSync?: Partial<SyncBody> }): Promise<MintedInvite> {
  const { aud, uses } = opts;
  const ttl = Math.min(INVITE_MAX_TTL_SEC, opts.ttlSec);
  const head = (await app.ownView()).head;
  // An unfriend ends every friendship of the pair whose invite was issued at or before it (whole
  // seconds, by the unfriender's clock): date the invite after every unfriend we know of, so a
  // re-friend in the same second, or with the other side's clock ahead, isn't refused.
  const now = nowSec();
  const iat = inviteIatAfterUnfriends(app.userId, aud, await app.store.listUnfriends(), now);
  if (iat - now > DEFAULT_SKEW_SEC) {
    throw new CliError(
      "clock_skew",
      `an unfriend between you is dated ${iat - 1 - now}s ahead of this device's clock, more than the ${DEFAULT_SKEW_SEC}s tolerated: check this clock (\`p2p doctor\`), or wait ${iat - now - DEFAULT_SKEW_SEC}s and invite again`,
    );
  }
  const cap = createCap(app.device!, app.keys!.cert, { purpose: "contact", sub: aud, relays: app.relays, uses, ttlSec: ttl });
  let jws: string;
  try {
    jws = createInviteV3(app.signer(), { aud, ik: head.ik, relays: app.relays, doc: head.jws, cap, ttlSec: ttl, iat });
  } catch (e) {
    if (e instanceof P2PError && e.reason === "malformed") {
      throw new CliError("too_large", `the invite doesn't fit 16 KiB with your identity document (${e.message}); a smaller avatar helps`);
    }
    throw e;
  }
  const inv = inviteHashV3(jws);
  const exp = iat + ttl;
  await app.store.addOutgoingInvite({ inv, aud, exp, jws });
  const issued = await app.recordIssued(cap);
  await sendSync(app, { outgoing: [{ inv, aud, exp, jws }], capsIssued: [issued], ...(opts.extraSync ?? {}) });
  return { jws, inv, aud, exp, uses, cap };
}

export async function invite(app: App, opts: { to?: string; uses?: number; ttlDays?: number }): Promise<InviteResult> {
  const aud = opts.to ? await app.resolveUser(opts.to) : "*";
  if (aud === app.userId) throw new CliError("usage", "you can't invite yourself (link a device with `p2p link start`)");
  const uses = opts.uses ?? (aud === "*" ? 5 : 3);
  if (!Number.isSafeInteger(uses) || uses < 1 || uses > 1000) throw new CliError("usage", "--uses must be 1..1000");
  // An unfriend queued for us must be known before the invite is dated (mintInvite), or a
  // re-friend right after it would be refused. Best effort: an invite works offline too.
  await app.connectAndDrain().catch(() => undefined);
  const m = await mintInvite(app, { aud, uses, ttlSec: Math.round((opts.ttlDays ?? 14) * 86_400) });
  const out: InviteResult = { invite: { inv: m.inv, aud, exp: m.exp, uses }, link: inviteLink(m.jws), web: inviteLink(m.jws, { web: true }) };
  if (aud !== "*" && (await app.view(aud))) {
    try {
      out.delivered = await app.deliver(aud, "contact", { own: app.userId, sid: "~contact" }, { text: m.jws });
    } catch (e) {
      app.warn(`couldn't deliver the invite directly: ${(e as Error).message}`);
    }
  }
  return out;
}

export interface AcceptResult {
  friend: { userId: string; address: string };
  delivered: Delivery;
}

/** Accepts an invite (a link, or the JWS of a held invite). */
/** The relays an invite names, unverified (a parse-time look): its `relays`, its bundled document's, its cap's. */
export function inviteRelays(jws: string): string[] {
  const payload = (j: string): Record<string, unknown> => {
    try {
      const v = JSON.parse(Buffer.from(j.split(".")[1] ?? "", "base64url").toString("utf8")) as unknown;
      return typeof v === "object" && v !== null ? (v as Record<string, unknown>) : {};
    } catch {
      return {};
    }
  };
  const strs = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
  const p = payload(jws);
  const out = strs(p.relays);
  if (typeof p.doc === "string") {
    try {
      out.push(...peekIdentityDoc(p.doc).relays);
    } catch {
      // checked properly later
    }
  }
  if (typeof p.cap === "string") out.push(...strs(payload(p.cap).relays));
  return out;
}

/**
 * `p2p accept <link>`, before accept(): a link the person pasted, from anyone. The relays it names (its own list, its
 * bundled document's, its cap's) are dialed to check it, so one on a loopback, link-local or private
 * address is refused unless opted in, literally and where its name resolves (App.guardRelays).
 * Invites that arrived otherwise (held, a rotation, the TUI) go to accept() as they are.
 */
export async function guardInviteLink(app: App, input: string, opts: { allowPrivateRelay?: boolean } = {}): Promise<void> {
  let jws: string;
  try {
    jws = input.includes("://") ? parseInviteLink(input) : input.trim();
  } catch {
    return; // not a link: accept() says so
  }
  await guardForeignRelays(app, inviteRelays(jws), "invite", opts.allowPrivateRelay || app.env.P2P_ALLOW_PRIVATE_RELAY === "1");
}

/** Refuses private relays someone else named (literal hosts, and names resolving to private addresses), then guards their connections. */
export async function guardForeignRelays(app: App, input: readonly string[], what: string, allow: boolean, opts: { code?: boolean } = {}): Promise<void> {
  if (allow) return;
  // The user's own relays are theirs to choose (a team relay on Tailscale or a LAN): left out, as guardedLookup leaves them.
  const relays = input.filter((r) => !isOwnRelay(r, app.self?.relays ?? []));
  refusePrivateRelays(relays, what, false, opts);
  await refusePrivateResolved(
    relays.map((r) => {
      try {
        return { relay: r, dial: app.transport(r).ws };
      } catch {
        return { relay: r, dial: r };
      }
    }),
    what,
    opts,
  );
  app.guardRelays(relays);
}

export async function accept(app: App, input: string): Promise<AcceptResult> {
  let jws: string;
  try {
    jws = input.includes("://") ? parseInviteLink(input) : input.trim();
  } catch {
    throw new CliError("usage", "that is not an invite link (p2p://invite/… or https://ix-infra.com/p2p/i#…)");
  }
  await app.connectAndDrain();
  // Structure and signature with whatever we know (the bundled document may stand in), to fail fast...
  const first = await verifyInviteV3(jws, app.signerCtx());
  if (first.iss === app.userId) throw new CliError("usage", "that is your own invite");
  if (await app.store.isBlocked(first.iss)) throw new CliError("blocked", "you blocked the inviter; `p2p unblock` first");
  await refuseIfUnfriendedAfter(app, first);
  // ...then, before acting on it (pre-release review M1), the inviter's head from its relays, and the invite against that alone.
  let inv: VerifiedInviteV3;
  try {
    inv = await reverifyInviteForApproval(app.store, jws, app.fetcher());
  } catch (e) {
    if (e instanceof P2PError && (e.reason === "identity-unknown" || e.reason === "chain-broken")) {
      throw new CliError("unknown_user", `couldn't confirm the inviter's identity document on the relays the invite names (${e.message})`);
    }
    throw e;
  }
  const head = (await app.ownView()).head;
  const friendCap = createCap(app.device!, app.keys!.cert, { purpose: "friend", sub: inv.iss, relays: app.relays });
  const acc = createAcceptV3(app.signer(), jws, { cap: friendCap, doc: head.jws });
  const f = await verifyFriendshipV3({ invite: jws, accept: acc }, app.signerCtx());
  await recordFriendshipV3(app.store, f);
  const issued = await app.recordIssued(friendCap);
  if (inv.contactCap) {
    const c = inv.contactCap;
    await app.store.addCapHeld({ capid: c.capid, iss: c.iss, sub: c.sub, relays: c.relays, kinds: c.kinds, exp: c.exp, jws: c.jws });
  }
  const delivered = await app.deliver(inv.iss, "contact", { own: app.userId, sid: "~contact" }, { text: acc }, { extraCaps: inv.cap ? [inv.cap] : [] });
  await dropHeld(app, (h) => h.invite === jws);
  await sendSync(app, { friendships: [{ invite: jws, accept: acc }], capsIssued: [issued], ...(inv.contactCap ? { capsHeld: [inv.contactCap.jws] } : {}) });
  const friend = { userId: inv.iss, address: await app.addressOf(inv.iss) };
  if (delivered.relays.length === 0) {
    throw new CliError("undelivered", `friendship recorded, but the accept was delivered via 0 relays: ${inv.iss} won't know yet (run accept again later)`, {
      friend,
      delivered,
    });
  }
  return { friend, delivered };
}

/**
 * Refuses, before anything is accepted or sent, an invite issued at or before an unfriend
 * between its issuer and us: the friendship it makes would be ended at once, on every client
 * (core unfriendApplies). That happens when we re-friend within the unfriend's second, or when
 * the unfriender's clock is ahead of the inviter's and the inviter didn't yet hold the unfriend.
 */
export async function refuseIfUnfriendedAfter(app: App, invite: { iss: string; iat: number }): Promise<void> {
  const u = unfriendEndingInvite(invite, app.userId, await app.store.listUnfriends());
  if (!u) return;
  const who = await app.addressOf(invite.iss);
  const skew = u.iat - invite.iat;
  throw new CliError(
    "invite_predates_unfriend",
    `this invite from ${who} is dated ${skew === 0 ? "in the same second as" : `${skew}s before`} the unfriend between you, so it can't re-friend you (one of your clocks may be off: \`p2p doctor\`). Nothing was accepted: ask ${who} for a new invite`,
    { inviter: invite.iss, unfriendIat: u.iat, inviteIat: invite.iat },
  );
}

/** `contact` envelopes (§4.3): invites are held; accepts, unfriends and cap grants are applied. */
export async function onContact(app: App, env: string, r: AcceptedMessageV3): Promise<NewEvent[]> {
  const c = r.contact!;
  const from = await fromOf(app, r);
  const at = r.envelope.ts;
  switch (c.type) {
    case "invite": {
      const item = withHeldId({ type: "invite", from: c.invite.iss, at, invite: c.invite.jws });
      await hold(app, item);
      return [makeEvent(env, "p2p.held", at, { from, held: { id: item.id, type: item.type, exp: c.invite.exp } })];
    }
    case "accept": {
      let f = c.friendship;
      // P4: a revoked code's invite is refused, even when someone took the code before the revoke.
      const code = await codeByInv(app, f.inv);
      if (code?.status === "revoked") {
        app.io.err(`refused ${from.address}: they used your revoked code ${codeHint(code.code)}`);
        return [makeEvent(env, "p2p.invite-taken", at, { from, invite: { inv: f.inv }, revoked: true })];
      }
      try {
        // A first-time invitee's document is only provisional: refresh it from the relays and re-verify (review N1).
        if (f.provisional) f = await reverifyFriendshipForApproval(app.store, f.proof, app.fetcher(), { self: app.userId });
        await recordFriendshipV3(app.store, f);
      } catch (e) {
        if (e instanceof P2PError && e.reason === "invite-already-bound") {
          return [makeEvent(env, "p2p.invite-taken", at, { from, invite: { inv: f.inv } })];
        }
        if (e instanceof P2PError && e.reason === "unfriended") {
          // Their client refuses this too (refuseIfUnfriendedAfter): a newer invite works.
          app.io.err(`refused ${from.address}'s accept: your invite is dated at or before an unfriend between you (a clock may be off); send a new invite`);
          return [makeEvent(env, "p2p.invite-taken", at, { from, invite: { inv: f.inv }, unfriended: true })];
        }
        throw e;
      }
      if (f.inviteeCap) {
        const k = f.inviteeCap;
        await app.store.addCapHeld({ capid: k.capid, iss: k.iss, sub: k.sub, relays: k.relays, kinds: k.kinds, exp: k.exp, jws: k.jws });
      }
      // §5.3: our friend cap goes back as a contact grant now the accept is recorded.
      const mine = createCap(app.device!, app.keys!.cert, { purpose: "friend", sub: f.invitee, relays: app.relays });
      const issued = await app.recordIssued(mine);
      try {
        await app.deliver(f.invitee, "contact", { own: app.userId, sid: "~contact" }, { text: mine });
      } catch (e) {
        // A short network drop must not lose the grant (they could never message us): the accept
        // is handled again on its redelivery, within the attempt limit (inbound.ts, review M-A).
        if (isTransient(e)) throw e;
        app.io.err(`couldn't send your cap to ${from.address}: ${(e as Error).message}`);
      }
      await sendSync(app, { friendships: [f.proof], capsIssued: [issued], ...(f.inviteeCap ? { capsHeld: [f.inviteeCap.jws] } : {}) });
      const events = [makeEvent(env, "p2p.friend", at, { from, friend: { userId: f.invitee, address: from.address, inv: f.inv } })];
      // P4: one of our short codes. Issuing it was our consent: finish our side (the circle), and tell the user.
      if (code?.status === "open" && f.inviter === app.userId) events.push(...(await onCodeRedeemed(app, env, at, from, code, f.invitee)));
      return events;
    }
    case "unfriend": {
      const u = c.unfriend;
      await app.store.addUnfriend({ iss: u.iss, peer: u.peer, inv: u.inv, iat: u.iat, jws: u.jws });
      await afterUnfriend(app, u.iss);
      return [makeEvent(env, "p2p.unfriend", at, { from, peer: u.iss })];
    }
    case "cap": {
      const k = c.cap;
      await app.store.addCapHeld({ capid: k.capid, iss: k.iss, sub: k.sub, relays: k.relays, kinds: k.kinds, exp: k.exp, jws: k.jws });
      await sendSync(app, { capsHeld: [k.jws] });
      return [makeEvent(env, "p2p.contact", at, { from, what: "cap", relays: k.relays, exp: k.exp })];
    }
    case "rotation":
      // §2.8: "<friend> moved to a new key", held for the user's approval.
      return onRotationContact(app, env, at, from, c.rotation, c.invite);
    case "circle-invite": {
      const chain = c.chain ? c.chain.versions.map((v) => v.jws) : [c.head];
      if (await recordJoinAnswer(app, r.envelope.from, chain, [])) {
        return [makeEvent(env, "p2p.circle", at, { from, event: "join-answer", cid: c.chain?.cid })];
      }
      const head = parseCircleVersion(c.head);
      const item = withHeldId({ type: "circle-invite", from: r.envelope.from, at, head: c.head, chain, cid: head.cid });
      await hold(app, item);
      return [makeEvent(env, "p2p.held", at, { from, held: { id: item.id, type: item.type, cid: head.cid } })];
    }
  }
}

/** The `unfriend` kind (§4.3): the core already stored it; take back our caps. */
export async function onUnfriendKind(app: App, env: string, r: AcceptedMessageV3): Promise<NewEvent[]> {
  await afterUnfriend(app, r.envelope.from);
  return [makeEvent(env, "p2p.unfriend", r.envelope.ts, { from: await fromOf(app, r), peer: r.envelope.from })];
}

async function afterUnfriend(app: App, peer: string): Promise<void> {
  // Only when it ended the last friendship with them (issue #3). An unfriend that arrives after a
  // re-friend (a late copy, another device's, one queued while this device was away) ends only the
  // friendships invited at or before it: the new one stands, and so must the caps it exchanged
  // (caps name no friendship). Revoking them anyway left a "friend" neither side could message.
  if (await stillFriends(app, peer)) return;
  const caps = await capsToRevokeOnUnfriend(app.store, peer);
  await app.revokeCaps(caps).catch(() => 0);
  await app.store.removeCapsHeld((c) => c.iss === peer);
}

/** A friendship with `peer` that no unfriend this device holds ends. */
async function stillFriends(app: App, peer: string): Promise<boolean> {
  const unfriends = await app.store.listUnfriends();
  return (await liveFriendshipsV3(app.store, app.signerCtx())).some((f) => (f.inviter === peer || f.invitee === peer) && !unfriends.some((u) => unfriendApplies(f, u)));
}

export async function unfriend(app: App, who: string): Promise<{ unfriended: string; address: string; delivered: Delivery[]; revoked: number }> {
  const peer = await app.resolveUser(who);
  // Handle what's queued first: it was sent while we were still friends.
  await app.connectAndDrain();
  const fs = (await app.store.listFriendships()).filter((f) => (f.inviter === peer && f.invitee === app.userId) || (f.invitee === peer && f.inviter === app.userId));
  if (fs.length === 0) throw new CliError("not_friends", `${await app.addressOf(peer)} is not a friend`);
  const ctx = app.signerCtx();
  const delivered: Delivery[] = [];
  const jwsList: string[] = [];
  for (const inv of new Set(fs.map((f) => f.inv))) {
    const j = createUnfriendV3(app.signer(), { peer, inv });
    const u = await verifyUnfriendV3(j, ctx);
    await app.store.addUnfriend({ iss: u.iss, peer: u.peer, inv: u.inv, iat: u.iat, jws: j });
    jwsList.push(j);
    try {
      delivered.push(await app.deliver(peer, "contact", { own: app.userId, sid: "~contact" }, { text: j }));
    } catch (e) {
      app.warn(`couldn't tell ${await app.addressOf(peer)}: ${(e as Error).message}`);
    }
  }
  const caps = await capsToRevokeOnUnfriend(app.store, peer);
  const revoked = await app.revokeCaps(caps);
  await app.store.removeCapsHeld((c) => c.iss === peer);
  await sendSync(app, { unfriends: jwsList });
  return { unfriended: peer, address: await app.addressOf(peer), delivered, revoked };
}

export async function block(app: App, who: string): Promise<{ blocked: string; address: string; revoked: number; rekeyedCircles: string[] }> {
  const u = await app.resolveUser(who);
  if (u === app.userId) throw new CliError("usage", "you can't block yourself");
  const pool = await app.connect({ allowNone: true });
  await pool.drain(app.tun.drainQuietMs, app.tun.drainMaxMs);
  const caps = await blockUser(app.store, u);
  // Their copy of our circle join cap must stop working too: re-key our joins (a pre-release live test).
  const rekeyed = await rekeyJoinsExcluding(app, u);
  const revoked = await app.revokeCaps(caps);
  await dropHeld(app, (h) => h.from === u);
  await sendSync(app, { blocks: [u] });
  return { blocked: u, address: await app.addressOf(u), revoked: revoked + rekeyed.length, rekeyedCircles: rekeyed };
}

export async function unblock(app: App, who: string): Promise<{ unblocked: string; address: string }> {
  const u = await app.resolveUser(who);
  await app.store.removeBlock(u);
  await sendSync(app, { unblocks: [u] }).catch(() => 0);
  return { unblocked: u, address: await app.addressOf(u) };
}

export async function petname(app: App, who: string, name: string | undefined): Promise<{ userId: string; petname: string | null; address: string }> {
  const u = await app.resolveUser(who);
  try {
    await app.store.setPetname(u, name);
  } catch (e) {
    throw new CliError("usage", (e as Error).message);
  }
  await sendSync(app, { petnames: { [u]: name ?? null } }).catch(() => 0);
  return { userId: u, petname: (await app.store.getPetname(u)) ?? null, address: await app.addressOf(u) };
}

export interface FriendRow {
  userId: string;
  address: string;
  since: number;
  direction: "outgoing" | "incoming";
  canMessage: boolean;
}

export async function friends(app: App): Promise<{ friends: FriendRow[]; invites: { outgoing: { inv: string; aud: string; exp: number }[]; held: number }; blocked: { userId: string; address: string }[] }> {
  const live = await liveFriendshipsV3(app.store, app.signerCtx());
  const unfriends = await app.store.listUnfriends();
  const rows = new Map<string, FriendRow>();
  for (const f of live) {
    if (unfriends.some((u) => unfriendApplies(f, u))) continue;
    const other = f.inviter === app.userId ? f.invitee : f.inviter;
    if (rows.has(other)) continue;
    const caps = await app.capsFor(other, "msg");
    rows.set(other, { userId: other, address: await app.addressOf(other), since: f.iat, direction: f.inviter === app.userId ? "outgoing" : "incoming", canMessage: caps.size > 0 });
  }
  const bound = new Set((await app.store.listFriendships()).map((f) => f.inv));
  const now = nowSec();
  const outgoing = (await listOutgoing(app)).filter((o) => o.exp > now && !bound.has(o.inv)).map((o) => ({ inv: o.inv, aud: o.aud, exp: o.exp }));
  const held = ((await app.state.get("held")) ?? []).length;
  const blocked = await Promise.all((await app.store.listBlocks()).map(async (b) => ({ userId: b.userId, address: await app.addressOf(b.userId) })));
  return { friends: [...rows.values()], invites: { outgoing, held }, blocked };
}

// ---------------------------------------------------------------------------
// Held items (§3.1, §3.3)

const HELD_PREFIX: Record<HeldItem["type"], string> = { invite: "i", "circle-invite": "c", "circle-join": "j", rotation: "r", "rotation-join": "s", "rotation-follow": "f", "rotation-dispute": "d" };
/** Why a held item waits, in words (rotation items carry these, §2.8). */
const REASON_TEXT: Record<string, string> = {
  conflict: "conflict: more than one rotation from this identity",
  "previously-removed": "previously removed from this circle",
  "not-final-yet": "their old identity hasn't published this move yet",
  "held-by-policy": "you hold changes to this circle for approval",
  "not-member": "their old identity isn't a member now",
  blocked: "blocked",
};

/** Minimum length of an id prefix `held approve|decline` accepts. */
export const HELD_ID_MIN_PREFIX = 8;

/**
 * A held item's id: a type letter and 16 b32 characters (80 bits) of
 * SHA-256 over the whole held object (everything but when it arrived), so no
 * peer can grind an item that collides with another.
 */
export function withHeldId(item: Omit<HeldItem, "id">): HeldItem {
  const { at: _at, ...rest } = item;
  const canonical = JSON.stringify(Object.keys(rest).sort().map((k) => [k, (rest as Record<string, unknown>)[k]]));
  return { ...item, id: `${HELD_PREFIX[item.type]}${b32Encode(sha256(new TextEncoder().encode(canonical))).slice(0, 16)}` };
}

export async function hold(app: App, item: HeldItem): Promise<void> {
  await app.state.update("held", (cur = []) => (cur.some((h) => h.id === item.id) ? { result: undefined } : { next: [...cur, item], result: undefined }));
}

export async function dropHeld(app: App, pred: (h: HeldItem) => boolean): Promise<HeldItem[]> {
  const gone = await app.state.update("held", (cur = []) => {
    const out = cur.filter(pred);
    return out.length === 0 ? { result: [] as HeldItem[] } : { next: cur.filter((h) => !pred(h)), result: out };
  });
  // A dropped rotation of our own identity takes its (secret) link code with it.
  const follows = gone.filter((h) => h.type === "rotation-follow").map((h) => h.id);
  if (follows.length > 0) {
    await app.state.update("follows", (cur = {}) => {
      const next = { ...cur };
      for (const id of follows) delete next[id];
      return { next, result: undefined };
    });
  }
  return gone;
}

export async function listHeld(
  app: App,
): Promise<(HeldItem & { address: string; summary: string; oldAddress?: string; confirmedByDocument?: boolean; choices?: { userId: string; address: string }[] })[]> {
  const list = (await app.state.get("held")) ?? [];
  return Promise.all(
    list.map(async (h) => {
      let summary = "";
      let extra: { oldAddress?: string; confirmedByDocument?: boolean; choices?: { userId: string; address: string }[] } = {};
      if (h.type === "rotation-dispute") {
        // pre-release re-review N1: an approved move, now contested. Keep one, or neither.
        const oldAddress = h.old ? await app.addressOf(h.old) : "?";
        const choices = await Promise.all((h.candidates ?? []).map(async (u) => ({ userId: u, address: await app.addressOf(u) })));
        extra = { oldAddress, choices };
        summary = `CONTESTED: more than one new key claims to be ${oldAddress} (${choices.map((c) => c.address).join(", ")}); the one you approved is suspended. Confirm out of band which is really them, then \`p2p identity dispute ${h.id} --keep <userId>\` or \`--neither\``;
      } else if (h.type === "rotation-follow") {
        // Never followed by itself (pre-release review H2): the user says so, on this device.
        const by = h.deviceLabel ? `your device "${h.deviceLabel}" (${h.device})` : `your device ${h.device ?? "?"}`;
        summary = `your identity is moving to a new key (${h.newFingerprint ?? "?"}), started by ${by}: follow it with \`p2p identity follow ${h.id}\` only if you started it; if not, contest it from a key-holding device`;
      } else if (h.type === "rotation" || h.type === "rotation-join") {
        // §2.8: the old address is shown (petname first), and whether its own document names this move.
        const oldAddress = h.old ? await app.addressOf(h.old) : "?";
        // The old identity's own (relay-served, self-certifying) final version names this same move.
        const inDoc = h.old && h.rotation ? ((await app.view(h.old))?.rotations ?? []).some((s) => s.old === h.rotation!.old && s.new === h.rotation!.new) : false;
        extra = { oldAddress, confirmedByDocument: inDoc };
        if (h.type === "rotation") summary = `${oldAddress} moved to a new key`;
        else {
          const name = h.head ? circleDisplayName(parseCircleVersion(h.head)) : h.cid;
          summary =
            h.reason === "admin"
              ? `${oldAddress} moved to a new key and was an admin of circle "${name}" (${h.cid}): approve to make the new key an admin too`
              : `${oldAddress} moved to a new key and asks to take their place in circle "${name}" (${h.cid})`;
        }
      } else if (h.type === "invite") summary = "friend invite";
      else if (h.head) {
        const v = parseCircleVersion(h.head);
        summary = `${h.type === "circle-join" ? "join request for" : "invite to"} circle "${circleDisplayName(v)}" (${v.cid})`;
      } else if (h.cid) summary = `join request for circle ${h.cid}`;
      if (h.reason && h.reason !== "admin") summary += ` [${REASON_TEXT[h.reason] ?? h.reason}]`;
      // Held objects carry signed statements and invites, never secrets; the list shows them as data.
      return { ...h, address: await app.addressOf(h.from), summary, ...extra };
    }),
  );
}

/** An exact id, or a unique prefix of at least 8 characters; ambiguous prefixes are refused. */
export async function getHeld(app: App, id: string): Promise<HeldItem> {
  const list = (await app.state.get("held")) ?? [];
  const exact = list.find((x) => x.id === id);
  if (exact) return exact;
  if (id.length < HELD_ID_MIN_PREFIX) throw new CliError("not_found", `no held item ${id} (give the full id, or at least ${HELD_ID_MIN_PREFIX} characters of it; see \`p2p held\`)`);
  const hits = list.filter((x) => x.id.startsWith(id));
  if (hits.length > 1) throw new CliError("ambiguous", `${id} matches ${hits.length} held items: give more of the id`, { candidates: hits.map((h) => h.id) });
  if (hits.length === 0) throw new CliError("not_found", `no held item ${id} (see \`p2p held\`)`);
  return hits[0];
}

