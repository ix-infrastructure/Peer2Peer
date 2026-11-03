// Copyright 2026 Ix Infrastructure Inc.
//
// Short-code invites (docs/protocol.md P4): friend, and join circles, in one
// step.
//
//  - A code joins up to CODE_MAX_CIRCLES circles the inviter owns or
//    administers (`--circle`, repeatable; by default the default circle). The
//    bundle's `circle` is the first, which every client joins; `circles` holds
//    the rest (heads only), which a client from before multi-circle codes
//    ignores: it joins the first one, and the inviter's adds of the others
//    reach it as ordinary held circle invites.
//  - The code also travels as a web link, `https://ix-infra.com/p2p/invite#<relay>/<CODE>`:
//    the same single-use, relay-held code (the secret is in the fragment, which
//    never reaches the web server).
//  - Before anything is accepted, the redeemer sees who made the code (address
//    and fingerprint) and every circle with its member count, and says yes once
//    (`--yes` for scripts).
//
//  - `p2p invite [label]` mints an ordinary invite (§3.1), bundles it with the
//    circle to join (by default the default circle, when this user owns or
//    administers it), seals the bundle under a fresh 100-bit code and puts it
//    in one relay's invite mailbox. The code is all the user shares.
//  - `p2p join <code>` takes the bundle (single use), opens and verifies it,
//    and accepts: typing the command is the consent, so nothing is held. When
//    the bundle names a circle, the join completes once the inviter's client
//    adds us (it is told by the accept), under the §3.3 confirmation rules.
//  - The inviter's client completes its side on the accept, because issuing
//    the code was the consent: the friendship is recorded (as for every
//    accept) and the redeemer is added to the circle. It also tells the user
//    who redeemed the code, with `p2p remove <userId>` at hand, since anyone
//    who saw the code first could have used it.
//  - A revoked code's invite is refused even if someone took it before the
//    revoke, and its contact cap is revoked at the relays.

import {
  CircleChain,
  circleDisplayName,
  circlePolicy,
  displayFingerprint,
  inviteHashV3,
  isUserId,
  loadCircle,
  nowSec,
  parseCircleVersion,
  verifyCircleVersionAlone,
  verifyInviteV3,
  type CirclePolicy,
  type LoadedCircle,
  type VerifiedCircleVersion,
} from "@peer2peer/core/v3";
import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import type { App, Delivery } from "./app.js";
import { capPeek } from "./app.js";
import { defaultRelays, normalizeRelays } from "./config.js";
import { CliError } from "./errors.js";
import { addMemberViaCode, joinCircle, removeMember, resolveCircle, setDefaultCircle } from "./circle-ops.js";
import { makeEvent, type EventFrom, type NewEvent } from "./inbound.js";
import { inviteDel, inviteGet, inviteList, invitePut, openLinkConnection } from "./relay-client.js";
import {
  canonicalShortCode,
  CODE_MAX_CIRCLES,
  CODE_MAX_TTL_SEC,
  codeRelayPart,
  codeWebLink,
  decodeCodeChars,
  encodeCodeChars,
  formatShortCode,
  groupCode,
  INVITE_BLOB_MAX,
  inviteAdmitHash,
  inviteAdmitKey,
  inviteLid,
  newCodeSecret,
  openInviteBundle,
  parseInviteBundle,
  parseShortCode,
  isOwnRelay,
  isPrivateAddress,
  isPrivateRelayHost,
  PRIVATE_RESOLVE_MARK,
  privateGuardLookup,
  privateRelayMessage,
  sealInviteBundle,
  type InviteBundle,
} from "./shortcode.js";
import type { CodeJoin, CodeRecord, HeldItem } from "./state.js";
import { accept, dropHeld, guardForeignRelays, inviteRelays, mintInvite, unfriend } from "./social.js";
import { sendSync } from "./sync.js";
import { CAP_INVITE_CIRCLES, peerLacks } from "./features.js";

async function looksOlderThanMultiCircle(app: App, who: string): Promise<boolean> {
  return peerLacks(app, who, CAP_INVITE_CIRCLES).catch(() => false);
}

export const CODE_LABEL_MAX = 64;
/** Records of codes that ended longer ago than this are pruned. */
const CODE_RECORD_RETENTION_SEC = 30 * 86_400;
/** A code join still waiting for the inviter after this long is dropped. */
const CODE_JOIN_RETENTION_MS = 30 * 86_400 * 1000;

/** `K7QM…`: how a code is named once it is no longer secret. */
export const codeHint = (code: string) => `${code.slice(0, 4)}…`;

// ---------------------------------------------------------------------------
// Issuing

export interface InviteCodeResult {
  /** `<relay host>/K7QM-3XPD-9TWA-HF2N-6RJC`: what the other person types after `p2p join`. */
  code: string;
  /** A line to paste into a message. */
  line: string;
  relay: string;
  label: string | null;
  to: { userId: string; address: string } | null;
  /** The first circle (what clients before multi-circle codes join). */
  circle: { cid: string; name: string } | null;
  /** Every circle the code joins, the first one first. */
  circles: { cid: string; name: string; members: number }[];
  /** The same code as a web link: `https://ix-infra.com/p2p/invite#<code>`. */
  web: string;
  /** Unix seconds. */
  expiresAt: number;
  /** Always 1: a code is single-use. */
  uses: 1;
  /** The relay lookup id: a hash of the code, not secret. The inviter's `p2p.joined` event carries the same `lid`. */
  lid: string;
  /**
   * A message to paste into Slack, Signal, …, for someone who may not have Peer2Peer yet: the web link,
   * how to install the Claude Code plugin, the join command (with --allow-private-relay and a note when
   * the code's relay is on a private network), and where the Codex instructions are.
   */
  message: string;
  /** The code's relay is on a private network (Tailscale, a LAN): joining it takes --allow-private-relay. */
  privateRelay: boolean;
}

/** The Claude Code plugin's install steps, as the invite message gives them. */
export const PLUGIN_INSTALL = ["/plugin marketplace add ix-infrastructure/Peer2Peer", "/plugin install peer2peer@peer2peer", "/reload-plugins"];
export const CODEX_INSTALL_URL = "https://github.com/ix-infrastructure/Peer2Peer/blob/main/packages/codex-bridge/README.md#install";

/** What a code's web link is made of (codeWebLink: the prefix, a relay part, the code): nothing a shell treats specially inside single quotes. */
const WEB_LINK_SAFE = /^https:\/\/ix-infra\.com\/p2p\/invite#[A-Za-z0-9.:[\]/_~-]+$/;

/** POSIX single quotes: `'` closes, an escaped quote, and opens again, so nothing can break out. */
export function shellQuote(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}

/** The `p2p join` line for a code's web link (quoted for the shell), with --allow-private-relay when it needs it. */
export function joinCommandFor(web: string, privateRelay: boolean): string {
  // A web link is always of the safe charset; anything else is quoted so a `'` can't break out anyway.
  const quoted = WEB_LINK_SAFE.test(web) ? `'${web}'` : shellQuote(web);
  return `p2p join${privateRelay ? " --allow-private-relay" : ""} ${quoted}`;
}

/** The message `p2p invite` prints to send: self-contained for someone who has never installed Peer2Peer. */
export function inviteMessage(web: string, privateRelay: boolean): string {
  const flag = privateRelay ? " --allow-private-relay" : "";
  // TODO(after the first npm release): add "No Claude Code? npx @peer2peer/cli join '<web>'". Nothing is
  // published to npm yet, so the line isn't printed.
  return [
    `Join me on Peer2Peer: ${web}`,
    ...(privateRelay ? ["You need to be on the same private network as me (e.g. Tailscale) for it to work."] : []),
    "New to it? In Claude Code run:",
    ...PLUGIN_INSTALL.map((l) => `  ${l}`),
    `then: /peers join${flag} ${web}`,
    `Using Codex? See ${CODEX_INSTALL_URL}`,
    `(Already have the p2p command? ${joinCommandFor(web, privateRelay)})`,
  ].join("\n");
}

/**
 * Is this relay on a private network as this machine sees it (its host a private address, or a name
 * resolving to one, as a Tailscale MagicDNS name does)? Bounded; unknown counts as not.
 */
export async function relayLooksPrivate(relay: string): Promise<boolean> {
  let host: string;
  try {
    host = new URL(relay).hostname;
  } catch {
    return false;
  }
  if (isPrivateRelayHost(host)) return true;
  if (host.startsWith("[") || /^[\d.]+$/.test(host)) return false;
  const addrs = await new Promise<LookupAddress[]>((done) => {
    const t = setTimeout(() => done([]), 1500);
    t.unref?.();
    dnsLookup(host, { all: true }, (err, a) => {
      clearTimeout(t);
      done(err ? [] : a);
    });
  });
  return addrs.some((a) => isPrivateAddress(a.address));
}

function checkLabel(label: string | undefined): string | undefined {
  if (label === undefined) return undefined;
  const t = label.trim();
  if (t === "") return undefined;
  if (t.length > CODE_LABEL_MAX || /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/.test(t)) {
    throw new CliError("usage", `a label is at most ${CODE_LABEL_MAX} printable characters`);
  }
  return t;
}

/** Whether this device may add people to `c`: its owner's key holder, or an admin, and a member. */
function canAdd(app: App, c: LoadedCircle): string | undefined {
  const h = c.chain.head;
  if (!c.record.joinedByMe || !h.members.includes(app.userId)) return "you're not a member of it";
  if (h.owner === app.userId && !app.isKeyholder) return "this device doesn't hold your identity key";
  if (h.owner !== app.userId && !h.admins.includes(app.userId)) return "only its owner or an admin can add people";
  // An open circle has a link anyone can use (`p2p circle invite <cid> --link`): a code adds nothing.
  if (circlePolicy(h) === "open") return "it is open: share its own link instead (p2p circle invite <cid> --link)";
  return undefined;
}

/**
 * The circles a code joins: each one named (in order, without repeats), or the default circle when
 * none is and this device may add people to it. A named circle this device can't add people to is
 * an error naming it: never silently left out.
 */
async function circlesForCode(app: App, opts: { circles?: string[]; noCircle?: boolean }): Promise<LoadedCircle[]> {
  if (opts.noCircle) {
    if ((opts.circles ?? []).length > 0) throw new CliError("usage", "--circle and --no-circle don't go together");
    return [];
  }
  const named = opts.circles ?? [];
  if (named.length === 0) {
    const want = app.self?.defaultCircle;
    if (!want) return [];
    let c: LoadedCircle;
    try {
      c = await resolveCircle(app, want);
    } catch {
      app.warn(`your default circle ${want} isn't held here: the code is a friend invite only`);
      return [];
    }
    const why = canAdd(app, c);
    if (why) {
      app.warn(`the code doesn't include your default circle "${circleDisplayName(c.chain.head)}": ${why}`);
      return [];
    }
    return [c];
  }
  const out: LoadedCircle[] = [];
  const refused: string[] = [];
  for (const name of named) {
    let c: LoadedCircle;
    try {
      c = await resolveCircle(app, name);
    } catch (e) {
      refused.push(`${name}: ${(e as Error).message}`);
      continue;
    }
    if (out.some((x) => x.record.cid === c.record.cid)) continue;
    const why = canAdd(app, c);
    if (why) refused.push(`"${circleDisplayName(c.chain.head)}" (${c.record.cid}): ${why}`);
    else out.push(c);
  }
  if (refused.length > 0) throw new CliError("not_admin", `the code can't join ${refused.length === 1 ? "this circle" : "these circles"}, so no code was made: ${refused.join("; ")}`);
  if (out.length > CODE_MAX_CIRCLES) throw new CliError("usage", `a code joins at most ${CODE_MAX_CIRCLES} circles (you named ${out.length})`);
  return out;
}

export async function inviteCode(
  app: App,
  opts: { label?: string; circles?: string[]; noCircle?: boolean; to?: string; ttlDays?: number; relay?: string },
): Promise<InviteCodeResult> {
  const label = checkLabel(opts.label);
  const days = opts.ttlDays ?? 7;
  if (!Number.isFinite(days) || days <= 0 || days * 86_400 > CODE_MAX_TTL_SEC) throw new CliError("usage", "--ttl-days must be 1..7");
  if ((opts.circles ?? []).length > CODE_MAX_CIRCLES) throw new CliError("usage", `a code joins at most ${CODE_MAX_CIRCLES} circles`);
  const ttlSec = Math.round(days * 86_400);
  const aud = opts.to ? await app.resolveUser(opts.to) : "*";
  if (aud === app.userId) throw new CliError("usage", "you can't invite yourself (link a device with `p2p link start`)");
  const pool = await app.connectAndDrain();
  const circles = await circlesForCode(app, opts);
  const targets = opts.relay ? normalizeRelays([opts.relay]) : app.relays;

  const m = await mintInvite(app, { aud, uses: 3, ttlSec });
  const s = newCodeSecret();
  const lid = inviteLid(s);
  // The bundle must fit the relay's blob cap. The first circle's chain may go (the inviter sends it on the
  // accept); a circle never does: past that, no code is made, rather than a code that joins less than asked.
  const [first, ...rest] = circles;
  const more = rest.length > 0 ? { circles: rest.map((c) => ({ head: c.chain.head.jws })) } : {};
  const tries: InviteBundle[] = first
    ? [
        { v: 1, invite: m.jws, circle: { head: first.chain.head.jws, chain: first.chain.versionsFrom(1) }, ...more },
        { v: 1, invite: m.jws, circle: { head: first.chain.head.jws }, ...more },
      ]
    : [{ v: 1, invite: m.jws }];
  const max = Math.min(INVITE_BLOB_MAX, app.tun.inviteBlobMax ?? INVITE_BLOB_MAX);
  let blob: string | undefined;
  let bundle: InviteBundle | undefined;
  for (const b of tries) {
    const sealed = sealInviteBundle(s, b);
    if (sealed.length <= max) {
      blob = sealed;
      bundle = b;
      break;
    }
  }
  if (!blob || !bundle) {
    throw new CliError(
      "too_large",
      circles.length > 1
        ? `an invite joining these ${circles.length} circles doesn't fit in a code (at most ${Math.round(max / 1024)} KiB): name fewer circles, or make a second code`
        : `the invite doesn't fit in a code (at most ${Math.round(max / 1024)} KiB); a smaller avatar helps`,
    );
  }

  let relay: string | undefined;
  let exp = 0;
  const errors: string[] = [];
  for (const r of targets) {
    try {
      // On a members-only relay the code also admits its redeemer there (open relays ignore `admit`).
      exp = await invitePut(await pool.ensure(r), lid, blob, ttlSec, inviteAdmitHash(inviteAdmitKey(s)));
      relay = r;
      break;
    } catch (e) {
      errors.push(`${r}: ${(e as Error).message}`);
    }
  }
  if (!relay) throw new CliError("not_published", `no relay took the code (${errors.join("; ")})`);

  const chars = encodeCodeChars(s);
  const cap = capPeek(m.cap);
  const cids = circles.map((c) => c.record.cid);
  const rec: CodeRecord = {
    lid,
    code: groupCode(chars),
    short: formatShortCode(relay, s),
    relay,
    inv: m.inv,
    ...(cap ? { capid: cap.capid, capRelays: cap.relays } : {}),
    aud,
    ...(label ? { label } : {}),
    ...(cids.length > 0 ? { cid: cids[0], cids } : {}),
    createdAt: nowSec(),
    exp: Math.min(exp, m.exp),
    status: "open",
  };
  await app.state.update("codes", (cur = {}) => ({ next: pruneCodes({ ...cur, [lid]: rec }), result: undefined }));
  await sendSync(app, { codes: [rec] });
  const list = circles.map((c) => ({ cid: c.record.cid, name: circleDisplayName(c.chain.head), members: c.chain.head.members.length }));
  const web = codeWebLink(rec.short);
  const privateRelay = await relayLooksPrivate(relay);
  return {
    code: rec.short,
    line: `Join me on Peer2Peer: ${web} (or: p2p join ${rec.short})`,
    relay,
    label: label ?? null,
    to: aud === "*" ? null : { userId: aud, address: await app.addressOf(aud) },
    circle: list[0] ? { cid: list[0].cid, name: list[0].name } : null,
    circles: list,
    web,
    expiresAt: rec.exp,
    uses: 1,
    lid,
    message: inviteMessage(web, privateRelay),
    privateRelay,
  };
}

function pruneCodes(all: Record<string, CodeRecord>, now = nowSec()): Record<string, CodeRecord> {
  const out: Record<string, CodeRecord> = {};
  for (const [k, c] of Object.entries(all)) {
    const ended = c.status === "open" ? c.exp : (c.redeemedAt ?? c.exp);
    if (now - ended < CODE_RECORD_RETENTION_SEC) out[k] = c;
  }
  return out;
}

/** Merges code records from another of our devices: a later status wins. */
export async function importCodes(app: App, recs: unknown[]): Promise<void> {
  const rank = { open: 0, redeemed: 1, revoked: 2 } as const;
  await app.state.update("codes", (cur = {}) => {
    const next = { ...cur };
    for (const x of recs) {
      const r = x as CodeRecord;
      if (typeof r !== "object" || r === null || typeof r.lid !== "string" || !/^[a-z2-7]{26}$/.test(r.lid) || !(r.status in rank)) continue;
      if (typeof r.inv !== "string" || typeof r.code !== "string" || typeof r.exp !== "number") continue;
      const have = next[r.lid];
      if (!have || rank[r.status] > rank[have.status] || (rank[r.status] === rank[have.status] && (r.removedAt ?? 0) > (have.removedAt ?? 0))) next[r.lid] = { ...have, ...r };
    }
    return { next: pruneCodes(next), result: undefined };
  });
}

// ---------------------------------------------------------------------------
// The inviter's side of a redeemed code (from the accept, social.ts)

export async function codeByInv(app: App, inv: string): Promise<CodeRecord | undefined> {
  const all = (await app.state.get("codes")) ?? {};
  return Object.values(all).find((c) => c.inv === inv);
}

/** Runs after the accept of one of our codes' invites was recorded: the redeemer is added to each circle, the user is told. */
export async function onCodeRedeemed(app: App, env: string, at: number, from: EventFrom, rec: CodeRecord, who: string): Promise<NewEvent[]> {
  // Compare-and-set under the state lock: only one process (a watch and a short command can both
  // handle copies of the accept) flips open -> redeemed and runs the side effects below.
  const updated = await app.state.update("codes", (cur = {}) => {
    const now = cur[rec.lid];
    if (!now || now.status !== "open") return { result: undefined };
    const next: CodeRecord = { ...now, status: "redeemed", redeemedBy: who, redeemedAt: nowSec() };
    return { next: { ...cur, [rec.lid]: next }, result: next };
  });
  if (!updated) return [];
  // Each circle the code names, the first one first: added, proposed (an admin's add goes to the owner) or failed.
  const outcomes: { cid: string; name?: string; status: string; reason?: string }[] = [];
  for (const cid of rec.cids ?? (rec.cid ? [rec.cid] : [])) {
    try {
      outcomes.push({ cid, ...(await addMemberViaCode(app, cid, who)) });
    } catch (e) {
      outcomes.push({ cid, status: "failed", reason: (e as Error).message });
    }
  }
  // What `p2p remove` undoes: only the circles this code put them in (added, or proposed to the owner),
  // never one they were in already.
  const added = outcomes.filter((o) => o.status === "added" || o.status === "proposed").map((o) => o.cid);
  const recorded = await app.state.update("codes", (cur = {}) => {
    const now = cur[rec.lid];
    if (!now) return { result: updated };
    const next: CodeRecord = { ...now, added };
    return { next: { ...cur, [rec.lid]: next }, result: next };
  });
  const circle = outcomes[0] ?? null;
  const address = from.address;
  const lines = outcomes.map((o) =>
    o.status === "added"
      ? `  added to "${o.name ?? o.cid}"`
      : o.status === "already"
        ? `  already in "${o.name ?? o.cid}"`
        : o.status === "proposed"
          ? `  their add to "${o.name ?? o.cid}" went to its owner`
          : `  couldn't add them to "${o.name ?? o.cid}": ${o.reason}`,
  );
  // A redeemer whose client predates multi-circle codes joins only the first circle by itself; the others
  // reach it as held circle invites. Said when its statuses show it (no invite.circles.v1): unknown otherwise.
  const old = outcomes.length > 1 && (await looksOlderThanMultiCircle(app, who));
  // One circle: said in the sentence, as before multi-circle codes; several: one line each.
  const one = outcomes.length === 1 ? outcomes[0] : undefined;
  const where =
    one?.status === "added" ? ` and was added to "${one.name}"` : one?.status === "already" ? ` (already in "${one.name}")` : one?.status === "proposed" ? ` (their add to "${one.name}" went to the owner)` : "";
  app.io.err(
    `${address} joined via your code ${codeHint(rec.code)}${rec.label ? ` ("${rec.label}")` : ""}${where}. Not who you meant? p2p remove ${who}` +
      (one ? (one.status === "failed" ? `\n  couldn't add them to the circle: ${one.reason}` : "") : lines.length ? `\n${lines.join("\n")}` : "") +
      (old ? `\n  their client looks older: it joins only "${outcomes[0].name ?? outcomes[0].cid}" by itself, and shows the others as circle invites to approve` : ""),
  );
  await sendSync(app, { codes: [recorded] });
  return [
    makeEvent(env, "p2p.joined", at, {
      from,
      code: codeHint(rec.code),
      lid: rec.lid,
      ...(rec.label ? { label: rec.label } : {}),
      ...(circle ? { cid: circle.cid, ...(circle.name ? { circleName: circle.name } : {}), circleStatus: circle.status } : {}),
      ...(outcomes.length > 1 ? { circles: outcomes.map((o) => ({ cid: o.cid, ...(o.name ? { name: o.name } : {}), status: o.status })) } : {}),
      ...(old ? { olderClient: true } : {}),
      remove: `p2p remove ${who}`,
    }),
  ];
}

// ---------------------------------------------------------------------------
// Redeeming

export interface JoinCircleOutcome {
  cid: string;
  name: string;
  /**
   * joined; pending: the inviter hasn't added us yet (finished by a later command); needs-approval: no
   * second member confirmed it (`p2p held approve <held>`); held: not joined from the code (unverified,
   * open, not run by the inviter, or not what was previewed): its circle invite, when it comes, is
   * approved on its own (`reason` says why).
   */
  status: "joined" | "already" | "pending" | "needs-approval" | "held";
  default: boolean;
  held?: string;
  reason?: string;
}

/** A circle as a code's preview shows it. */
export interface PreviewCircle {
  cid: string;
  name: string;
  members: number;
  policy: CirclePolicy;
  owner: string;
  ownerAddress: string;
  /** Signed by the owner it names (verifyCircleVersionAlone, or the first circle's chain). */
  verified: boolean;
  /** Joined on the yes: verified, not open, and the inviter is its owner or an admin. Else `note` says why not. */
  auto: boolean;
  note?: "unverified" | "open" | "not-admin";
}

/**
 * What a code offers, shown before anything is accepted. Each circle is as its version in the code
 * says, checked for the owner's signature (`verified`); only `auto` circles are joined on the yes, and
 * each again only once its real chain arrives and matches (see completeCodeJoin).
 */
export interface CodePreview {
  from: { userId: string; address: string; fingerprint: string };
  /** Set when the code was made for one person (it is this user, or nothing is accepted). */
  to: string | null;
  toAddress?: string;
  circles: PreviewCircle[];
  /** When the invite inside expires (unix seconds). */
  expiresAt: number;
}

export interface JoinCodeResult {
  from: { userId: string; address: string; fingerprint: string };
  friend: { userId: string; address: string };
  delivered: Delivery | null;
  /** The first circle's outcome (what clients before multi-circle codes report). */
  circle: JoinCircleOutcome | null;
  /** Every circle the code joins, the first one first. */
  circles: JoinCircleOutcome[];
  /** The default circle after the join (set to the code's circle when there was none). */
  defaultCircle: string | null;
  created: { userId: string; address: string; relays: string[] } | null;
  /** Set when the identity this join created has only the code's relay (that host): show it to the user. */
  relayWarning?: string;
}

export interface JoinCodeOpts {
  waitSec?: number;
  /** Scripts: consent to the join, and join a circle even when no second member confirmed it (§3.3). */
  yes?: boolean;
  /** The person already saw the preview and said yes (the Claude mod's Join button): no second question. */
  consent?: boolean;
  /** Only open the code and say what it offers: nothing is accepted, no identity is created. */
  previewOnly?: boolean;
  name?: string;
  confirm?: (q: string) => Promise<boolean>;
  /** Accept a code whose relay is a loopback, link-local or private host (a team relay on your own network). */
  allowPrivateRelay?: boolean;
  /** Creates an identity when there is none (identity.init); passed in to keep the module graph acyclic. */
  create?: (app: App, opts: { name?: string; relays: string[] }) => Promise<{ userId: string; address: string; relays: string[] }>;
}

async function fetchBlob(app: App, lid: string, relays: readonly string[], opts: { guardPrivate?: boolean } = {}): Promise<{ blob: string; relay: string } | undefined> {
  const errors: string[] = [];
  for (const relay of relays) {
    let conn;
    try {
      // The code's own relay: what its name resolves to is checked too, before anyone says yes.
      conn = await openLinkConnection(relay, app.transport, app.tun.connectTimeoutMs, app.progress, opts.guardPrivate ? { lookup: privateGuardLookup() } : {});
      const blob = await inviteGet(conn, lid);
      if (blob !== undefined) return { blob, relay };
    } catch (e) {
      if (e instanceof CliError && e.code === "rate_limited") throw e;
      if ((e as Error).message.includes(PRIVATE_RESOLVE_MARK)) {
        const at = /\(([^()]+)\)\s*$/.exec((e as Error).message)?.[1];
        throw new CliError("private_relay", privateRelayMessage("code's relay", new URL(relay).hostname, { code: true, ...(at ? { detail: `it resolves to ${at}` } : {}) }));
      }
      errors.push(`${relay}: ${(e as Error).message}`);
    } finally {
      conn?.close();
    }
  }
  if (errors.length === relays.length && relays.length > 0) throw new CliError("network", `couldn't reach the code's relay (${errors.join("; ")})`);
  return undefined;
}

/** What a code offers, in words: who made it and every circle with its member count. */
export function previewText(p: CodePreview): string {
  const circles = p.circles.map((c) => {
    const n = `${c.members} member${c.members === 1 ? "" : "s"}`;
    if (c.note === "unverified") return `"${c.name}" (unverified: not joined from this code; if its invite comes, you approve it on its own)`;
    const owner = c.owner === p.from.userId ? "theirs" : `owner ${c.ownerAddress}`;
    if (c.note === "open") return `"${c.name}" (${n}, open, ${owner}: not joined from this code; if its invite comes, you approve it on its own)`;
    if (c.note === "not-admin") return `"${c.name}" (${n}, ${owner}, which they don't run: not joined from this code; if its invite comes, you approve it on its own)`;
    return `"${c.name}" (${n}, invite-only, ${owner})`;
  });
  const to = p.to ? ` This code is for ${p.toAddress ?? p.to}.` : "";
  return `${p.from.address} (fingerprint ${p.from.fingerprint}) invites you to be friends${circles.length ? `, and to join ${circles.join(", ")}` : ""}.${to}`;
}

/** The preview's view of one circle version from a code (never trusted beyond what its signature shows). */
async function previewCircle(app: App, inviter: string, headJws: string, chain?: readonly string[]): Promise<PreviewCircle> {
  const head = parseCircleVersion(headJws);
  let verified = false;
  try {
    verifyCircleVersionAlone(headJws);
    verified = true;
  } catch {
    // A transfer version verifies only against its parent: with the first circle's chain, if the code carries it.
    if (chain?.length) {
      try {
        verified = CircleChain.bootstrap([...chain, headJws], { head: headJws }).head.jws === headJws;
      } catch {
        verified = false;
      }
    }
  }
  const policy = circlePolicy(head);
  const runs = head.owner === inviter || head.admins.includes(inviter);
  const note: PreviewCircle["note"] = !verified ? "unverified" : policy === "open" ? "open" : !runs ? "not-admin" : undefined;
  return {
    cid: head.cid,
    name: circleDisplayName(head),
    members: head.members.length,
    policy,
    owner: head.owner,
    ownerAddress: await app.addressOf(head.owner),
    verified,
    auto: note === undefined,
    ...(note ? { note } : {}),
  };
}

export async function joinCode(app: App, input: string, opts: JoinCodeOpts = {}): Promise<JoinCodeResult> {
  const allowPrivate = opts.allowPrivateRelay || app.env.P2P_ALLOW_PRIVATE_RELAY === "1";
  // The user's own relays at the start of the command (a teammate's code on the team's own relay is fine).
  const own = (await app.load(false)) ? (app.self?.relays ?? []) : [];
  const parsed = parseShortCode(input, { allowPrivate, own });
  const codeRelayIsOwn = !!parsed.relay && isOwnRelay(parsed.relay, own);
  // What the messages below name: rebuilt from the parsed code, never the raw input (L2).
  const shown = canonicalShortCode(parsed);
  // A members-only code relay admits whoever presents the code's admission key at auth: keep it
  // before anything connects there (the identity created below publishes to it first).
  if (parsed.relay && !opts.previewOnly) await app.saveAdmit(admitRelay(parsed.relay), inviteAdmitKey(parsed.secret));
  const loaded = await app.load(false);
  let defaults: string[] = [];
  if (!loaded) {
    defaults = defaultRelays(app.env, app.file);
    if (defaults.length === 0 && !parsed.relay) {
      throw new CliError("no_relays", "no identity here yet and no relays configured: run `p2p setup` first, or use the code with its relay part (relay.example/K7QM-…)");
    }
  }

  // 1. Open the code (single use on the relay; kept here, so a retry or the join after a preview works).
  const lid = inviteLid(parsed.secret);
  const local = (await app.state.get("redeemed"))?.[lid];
  let blob = local?.blob;
  if (!blob) {
    const got = await fetchBlob(app, lid, parsed.relay ? [parsed.relay] : loaded ? app.relays : defaults, { guardPrivate: !!parsed.relay && !allowPrivate && !codeRelayIsOwn });
    if (!got) {
      throw new CliError("code_not_found", `no invite under that code${parsed.relay ? ` on ${parsed.relay}` : " on your relays"}: it was already used or revoked, it expired, or it was mistyped`);
    }
    blob = got.blob;
    if (got.relay !== parsed.relay && !opts.previewOnly) await app.saveAdmit(admitRelay(got.relay), inviteAdmitKey(parsed.secret));
    await app.state.update("redeemed", (cur = {}) => {
      const keep = Object.fromEntries(Object.entries(cur).filter(([, r]) => Date.now() - r.at < CODE_JOIN_RETENTION_MS));
      return { next: { ...keep, [lid]: { lid, relay: got.relay, blob: got.blob, at: Date.now() } }, result: undefined };
    });
  }
  let bundle: InviteBundle;
  try {
    bundle = parseInviteBundle(openInviteBundle(parsed.secret, blob));
  } catch (e) {
    await forgetRedeemed(app, lid);
    throw e;
  }
  // Before an identity exists here, the inviter is found through the code's relay or the default relays.
  // The inviter's document is fetched from the code's relay over HTTP: its name is checked where it resolves too.
  // Guarded for the rest of this command even if it becomes this user's only relay below (a new identity).
  if (parsed.relay && !allowPrivate && !codeRelayIsOwn) app.guardRelays([parsed.relay]);
  // The relays the invite inside names (the inviter's), dialed for its document and the accept: the same
  // rule, under the same opt-in, before anything is shown or accepted.
  // Refused here, the code stays kept on this device: the same command with the opt-in joins after all.
  await guardForeignRelays(app, inviteRelays(bundle.invite), "inviter", allowPrivate, { code: true });
  const first = await verifyInviteV3(bundle.invite, app.signerCtx(parsed.relay ? [parsed.relay] : defaults));
  if (loaded && first.iss === app.userId) throw new CliError("usage", "that is your own code");
  if (loaded && first.aud !== "*" && first.aud !== app.userId) {
    await forgetRedeemed(app, lid);
    throw new CliError("not_for_you", `this code was made for someone else (${await app.addressOf(first.aud)}); nothing was accepted`);
  }

  // 2. Say what it offers, and have the person say yes once (or --yes): nothing is accepted before.
  const heads = bundle.circle ? [bundle.circle.head, ...(bundle.circles ?? []).map((c) => c.head)] : [];
  const offered: PreviewCircle[] = [];
  const offeredHeads: string[] = [];
  for (const [i, h] of heads.entries()) {
    let pc: PreviewCircle;
    try {
      pc = await previewCircle(app, first.iss, h, i === 0 ? bundle.circle?.chain : undefined);
    } catch {
      await forgetRedeemed(app, lid);
      throw new CliError("code_invalid", "a circle in this code is malformed; nothing was accepted");
    }
    if (!offered.some((c) => c.cid === pc.cid)) {
      offered.push(pc);
      offeredHeads.push(h);
    }
  }
  const preview: CodePreview = {
    from: { userId: first.iss, address: await app.addressOf(first.iss), fingerprint: displayFingerprint(first.iss) },
    to: first.aud === "*" ? null : first.aud,
    ...(first.aud === "*" ? {} : { toAddress: await app.addressOf(first.aud) }),
    circles: offered,
    expiresAt: first.exp,
  };
  if (opts.previewOnly) throw new CodePreviewReady(preview);
  // A code for one person can't be for an identity not made yet: say so before making one (L4). The
  // code stays kept here, so it still joins once that identity is set up on this device.
  if (!loaded && first.aud !== "*") {
    throw new CliError("not_for_you", `this code is for ${preview.toAddress}, and there is no identity here yet: a new one can't be them. Set up that identity here first, then run p2p join ${shown} again; nothing was accepted`, { preview });
  }
  if (!opts.yes && !opts.consent) {
    if (!opts.confirm) throw new CliError("confirm_required", `${previewText(preview)} Join with --yes (or run it in a terminal to be asked).`, { preview });
    if (!(await opts.confirm(`${previewText(preview)}\nJoin?`))) {
      throw new CliError("declined", `nothing was accepted. The code is kept here: \`p2p join ${shown}\` again joins after all (it no longer works for anyone else)`, { preview });
    }
  }

  // 3. An identity, if there is none (lowest friction: the first command can be `p2p join`).
  let created: JoinCodeResult["created"] = null;
  let relayWarning: string | undefined;
  if (!loaded) {
    // The default relays, or, with none, the code's relay alone, chosen by whoever made the code: never silently (review M1).
    let relays: string[];
    if (defaults.length > 0) relays = defaults;
    else {
      relays = [parsed.relay!];
      relayWarning = codeRelayPart(parsed.relay!);
    }
    if (!opts.create) throw new CliError("no_identity", "no identity here yet: run `p2p setup` first");
    if (parsed.relay) await app.saveAdmit(admitRelay(parsed.relay), inviteAdmitKey(parsed.secret));
    created = await opts.create(app, { name: opts.name, relays });
    if (relayWarning) {
      app.warn(`Your only relay is ${relayWarning}, chosen by whoever gave you this code: it sees when you are online and could drop your mail. Add another with \`p2p relays add <wss://…>\`.`);
    }
    if (first.aud !== "*" && first.aud !== app.userId) {
      await forgetRedeemed(app, lid);
      throw new CliError("not_for_you", `this code was made for someone else (${await app.addressOf(first.aud)}); nothing was accepted`);
    }
  }

  // 4. Accept: friends at once; the inviter's client adds us to each circle when it gets the accept.
  const inv = inviteHashV3(bundle.invite);
  let delivered: Delivery | null = null;
  const already = (await app.store.listFriendships()).find((f) => f.inv === inv);
  if (!already) {
    try {
      delivered = (await accept(app, bundle.invite)).delivered;
    } catch (e) {
      if (e instanceof CliError && e.code === "invite_predates_unfriend") {
        // The code was single-use and its invite can never re-friend: say so, keep nothing.
        await forgetRedeemed(app, lid);
        throw new CliError(e.code, `${e.message} (this code is used up)`, e.extra);
      }
      if (!(e instanceof CliError && e.code === "undelivered")) throw e;
      delivered = (e.extra.delivered as Delivery) ?? null;
      app.warn(`the accept reached 0 relays: run \`p2p join ${shown}\` again later to resend it`);
      await app.state.update("redeemed", (cur = {}) => (cur[lid] ? { next: { ...cur, [lid]: { ...cur[lid], undelivered: true } }, result: undefined } : { result: undefined }));
    }
  } else if ((await app.state.get("redeemed"))?.[lid]?.undelivered) {
    delivered = await app.deliver(first.iss, "contact", { own: app.userId, sid: "~contact" }, { text: already.proof.accept }, { extraCaps: first.cap ? [first.cap] : [] });
    if (delivered.relays.length > 0) {
      await app.state.update("redeemed", (cur = {}) => (cur[lid] ? { next: { ...cur, [lid]: { lid, relay: cur[lid].relay, blob: cur[lid].blob, at: cur[lid].at } }, result: undefined } : { result: undefined }));
    }
  }
  const fromAddr = await app.addressOf(first.iss);
  const circles = offered.length > 0 ? await joinCodeCircles(app, first.iss, lid, offeredHeads, offered, opts) : [];
  return {
    from: { userId: first.iss, address: fromAddr, fingerprint: displayFingerprint(first.iss) },
    friend: { userId: first.iss, address: fromAddr },
    delivered,
    circle: circles[0] ?? null,
    circles,
    defaultCircle: app.self?.defaultCircle ?? null,
    created,
    ...(relayWarning ? { relayWarning } : {}),
  };
}

/** A code as messages show it: rebuilt from its parsed parts, never the raw input (which may be anything pasted). */
export function shownCode(input: string): string {
  try {
    return canonicalShortCode(parseShortCode(input, { allowPrivate: true }));
  } catch {
    return "<code>";
  }
}

/** joinCode with `previewOnly`: what the code offers (thrown so nothing after the preview can run). */
export class CodePreviewReady extends Error {
  constructor(readonly preview: CodePreview) {
    super("preview");
  }
}

/** `p2p join --preview`: opens the code (kept here, used up on the relay) and says what it offers; accepts nothing. */
export async function previewCode(app: App, input: string, opts: { allowPrivateRelay?: boolean } = {}): Promise<CodePreview> {
  try {
    await joinCode(app, input, { previewOnly: true, allowPrivateRelay: opts.allowPrivateRelay });
  } catch (e) {
    if (e instanceof CodePreviewReady) return e.preview;
    throw e;
  }
  throw new CliError("internal", "no preview");
}

/** The relay as connections name it (the key of `admits`). */
function admitRelay(relay: string): string {
  try {
    return normalizeRelays([relay])[0] ?? relay;
  } catch {
    return relay;
  }
}

async function forgetRedeemed(app: App, lid: string): Promise<void> {
  await app.state.update("redeemed", (cur = {}) => {
    if (!cur[lid]) return { result: undefined };
    const { [lid]: _gone, ...rest } = cur;
    return { next: rest, result: undefined };
  });
}

function findCircleInvite(held: readonly HeldItem[], cid: string, inviter: string): HeldItem | undefined {
  return [...held].reverse().find((h) => h.type === "circle-invite" && h.cid === cid && h.from === inviter);
}

/**
 * The circles a code joins: each one waits for the inviter's client to add us (it does when it gets the
 * accept), all within one wait, then is joined under the §3.3 confirmation rules. Only the code's first
 * circle may become the default circle, and only when there is none.
 */
async function joinCodeCircles(app: App, inviter: string, lid: string, heads: string[], offered: PreviewCircle[], opts: JoinCodeOpts): Promise<JoinCircleOutcome[]> {
  const out: (JoinCircleOutcome | { entry: CodeJoin })[] = [];
  for (const [i, headJws] of heads.entries()) {
    const pc = offered[i];
    const cid = pc.cid;
    const rec = await app.store.getCircle(cid);
    if (rec?.joinedByMe) {
      out.push({ cid, name: pc.name, status: "already", default: app.self?.defaultCircle === cid });
      continue;
    }
    // Never joined from the code (M1): its invite, if one comes, is a held item like any other.
    if (!pc.auto) {
      out.push({ cid, name: pc.name, status: "held", default: false, reason: autoRefusal(pc.note) });
      continue;
    }
    // What the person said yes to: the join completes only for this circle, as it was shown.
    const confirmed = { name: pc.name, policy: pc.policy, owner: pc.owner };
    const entry: CodeJoin = { cid, inviter, lid, head: headJws, at: Date.now(), confirmed, ...(i === 0 ? { first: true } : {}) };
    await app.state.update("codeJoins", (cur = {}) => ({ next: { ...cur, [cid]: entry }, result: undefined }));
    out.push({ entry });
  }
  const waiting = out.filter((x): x is { entry: CodeJoin } => "entry" in x);
  if (waiting.length > 0) {
    const pool = await app.connect();
    const deadline = Date.now() + (opts.waitSec ?? 15) * 1000;
    for (;;) {
      const held = (await app.state.get("held")) ?? [];
      if (waiting.every((w) => findCircleInvite(held, w.entry.cid, inviter)) || Date.now() >= deadline) break;
      await pool.drain(Math.min(500, app.tun.drainQuietMs), Math.max(0, Math.min(2000, deadline - Date.now())));
    }
  }
  const held = (await app.state.get("held")) ?? [];
  const results: JoinCircleOutcome[] = [];
  for (const x of out) {
    if (!("entry" in x)) {
      results.push(x);
      continue;
    }
    const item = findCircleInvite(held, x.entry.cid, inviter);
    const name = x.entry.confirmed?.name ?? circleDisplayName(parseCircleVersion(x.entry.head));
    // Finished meanwhile by a drain (finishCodeJoins runs after each one): joined, not pending.
    if (!item && (await app.store.getCircle(x.entry.cid))?.joinedByMe) results.push({ cid: x.entry.cid, name, status: "joined", default: app.self?.defaultCircle === x.entry.cid });
    else if (!item) results.push({ cid: x.entry.cid, name, status: "pending", default: false });
    else results.push(await completeCodeJoin(app, x.entry, item, { waitSec: opts.waitSec ?? 15, yes: opts.yes, confirm: opts.confirm }));
  }
  return results;
}

function autoRefusal(note: PreviewCircle["note"]): string {
  return note === "unverified"
    ? "its version in the code isn't signed by the owner it names"
    : note === "open"
      ? "it is open"
      : "whoever made the code is not its owner or an admin";
}

/**
 * Why the circle that arrived can't be joined on the code's yes (M1), or undefined when it can: its
 * chain must verify from version 1, and say what the person saw and said yes to (cid, name, policy,
 * owner), with the inviter its owner or an admin, and the circle not open. A malicious inviter's code
 * can claim anything; this is checked against the circle itself.
 */
function codeJoinRefusal(entry: CodeJoin, item: HeldItem): string | undefined {
  let h;
  try {
    h = CircleChain.bootstrap(item.chain?.length ? item.chain : [item.head!], { head: item.head! }).head;
  } catch (e) {
    return `its chain doesn't verify (${(e as Error).message})`;
  }
  return codeHeadRefusal(entry, h);
}

/** The code-join rules on one verified head: the offered one, and again the one the join commits to. */
function codeHeadRefusal(entry: CodeJoin, h: VerifiedCircleVersion): string | undefined {
  const want = entry.confirmed ?? (() => {
    const v = parseCircleVersion(entry.head);
    return { name: circleDisplayName(v), policy: circlePolicy(v), owner: v.owner };
  })();
  if (h.cid !== entry.cid) return "it is another circle";
  if (circlePolicy(h) === "open") return "it is open";
  if (h.owner !== entry.inviter && !h.admins.includes(entry.inviter)) return "whoever made the code is not its owner or an admin";
  if (circleDisplayName(h) !== want.name || circlePolicy(h) !== want.policy || h.owner !== want.owner) return "it isn't the circle you said yes to (its name, policy or owner differs)";
  return undefined;
}

async function completeCodeJoin(app: App, entry: CodeJoin, item: HeldItem, opts: { waitSec: number; yes?: boolean; confirm?: (q: string) => Promise<boolean> }): Promise<JoinCircleOutcome> {
  const refused = codeJoinRefusal(entry, item);
  if (refused) {
    // Not joined, and not the default: the held invite stays for the person to approve on its own.
    await app.state.update("codeJoins", (cur = {}) => {
      const { [entry.cid]: _gone, ...rest } = cur;
      return { next: rest, result: undefined };
    });
    return { cid: entry.cid, name: entry.confirmed?.name ?? circleDisplayName(parseCircleVersion(item.head!)), status: "held", default: false, held: item.id, reason: refused };
  }
  const r = await joinCircle(app, { head: item.head!, chain: item.chain, joins: item.joins, inviter: entry.inviter, accept: (h) => codeHeadRefusal(entry, h) }, opts);
  const name = r.name;
  if (r.status === "refused") {
    // A newer chain from the members (open now, or another owner or name): not joined from the code.
    await app.state.update("codeJoins", (cur = {}) => {
      const { [entry.cid]: _gone, ...rest } = cur;
      return { next: rest, result: undefined };
    });
    return { cid: entry.cid, name, status: "held", default: false, held: item.id, reason: r.refused };
  }
  if (r.status === "joined" || r.status === "already") {
    await app.state.update("codeJoins", (cur = {}) => {
      const { [entry.cid]: _gone, ...rest } = cur;
      return { next: rest, result: undefined };
    });
    await dropHeld(app, (h) => h.id === item.id);
    let isDefault = app.self?.defaultCircle === entry.cid;
    // Never replaces a default circle; and sessions already running don't move into this one (sessions.ts).
    // A code from before multi-circle codes has one circle, which counts as its first.
    // The policy of the chain as joined and stored (never the offered head's): an open circle is never a code's default.
    const joined = await loadCircle(app.store, entry.cid);
    const open = !joined || circlePolicy(joined.chain.head) === "open" || r.policy === "open";
    if (!app.self?.defaultCircle && entry.first !== false && !open) {
      await setDefaultCircle(app, entry.cid, { byJoin: true });
      isDefault = true;
    }
    return { cid: entry.cid, name, status: r.status, default: isDefault };
  }
  await app.state.update("codeJoins", (cur = {}) => (cur[entry.cid] ? { next: { ...cur, [entry.cid]: { ...cur[entry.cid], needsApproval: item.id } }, result: undefined } : { result: undefined }));
  return { cid: entry.cid, name, status: "needs-approval", default: false, held: item.id };
}

let finishing = false;

/**
 * After a drain (App.afterDrain): finishes code joins whose circle has
 * arrived since `p2p join` returned. Joins that need the user's say stay
 * held (`p2p held approve`).
 */
export async function finishCodeJoins(app: App): Promise<NewEvent[]> {
  if (finishing || !app.keys) return [];
  finishing = true;
  try {
    const all = (await app.state.get("codeJoins")) ?? {};
    const held = (await app.state.get("held")) ?? [];
    const events: NewEvent[] = [];
    for (const entry of Object.values(all)) {
      if (Date.now() - entry.at > CODE_JOIN_RETENTION_MS || (await app.store.getCircle(entry.cid))?.joinedByMe) {
        await app.state.update("codeJoins", (cur = {}) => {
          const { [entry.cid]: _gone, ...rest } = cur;
          return { next: rest, result: undefined };
        });
        continue;
      }
      if (entry.needsApproval) continue;
      const item = findCircleInvite(held, entry.cid, entry.inviter);
      if (!item) continue;
      try {
        const r = await completeCodeJoin(app, entry, item, { waitSec: 5 });
        if (r.status === "joined") app.io.err(`joined "${r.name}" (from your code join)${r.default ? "; it is your default circle" : ""}`);
        else if (r.status === "needs-approval") app.io.err(`"${r.name}" couldn't be confirmed with a second member: \`p2p held approve ${r.held}\` to join anyway`);
        else if (r.status === "held") app.io.err(`"${r.name}" wasn't joined from your code (${r.reason}): \`p2p held approve ${r.held}\` joins it, if you want it`);
        events.push(makeEvent(`code-join|${entry.cid}|${entry.lid}`, "p2p.circle", Math.floor(Date.now()), { event: r.status === "joined" ? "code-joined" : "code-join-held", cid: entry.cid, name: r.name, ...(r.reason ? { reason: r.reason } : {}) }));
      } catch (e) {
        app.io.err(`couldn't finish joining ${entry.cid}: ${(e as Error).message}`);
      }
    }
    if (events.length) await app.state.addEvents(events);
    return events;
  } finally {
    finishing = false;
  }
}

// ---------------------------------------------------------------------------
// Listing, revoking, removing

export interface CodeRow {
  code: string;
  label: string | null;
  to: { userId: string; address: string } | null;
  circle: { cid: string; name: string } | null;
  /** Every circle the code joins (multi-circle codes), the first one first. */
  circles: { cid: string; name: string }[];
  createdAt: number;
  exp: number;
  /** open: waiting on the relay; taken: fetched, nobody joined (yet); redeemed; expired; revoked. */
  /** evicted: the relay dropped it to make room (full store); make a new code. */
  status: "open" | "taken" | "evicted" | "redeemed" | "expired" | "revoked";
  redeemedBy?: { userId: string; address: string };
  redeemedAt?: number;
}

export async function listCodes(app: App): Promise<CodeRow[]> {
  let pool;
  try {
    pool = await app.connectAndDrain();
  } catch (e) {
    app.io.err(`p2p: offline: ${(e as Error).message}`);
  }
  const all = Object.values(pruneCodes((await app.state.get("codes")) ?? {}));
  const now = nowSec();
  const onRelay = new Map<string, { lids: Set<string>; evicted: Set<string> } | undefined>();
  for (const r of new Set(all.filter((c) => c.status === "open" && c.exp > now).map((c) => c.relay))) {
    try {
      const l = pool ? await inviteList(await pool.ensure(r)) : undefined;
      onRelay.set(r, l ? { lids: new Set(l.lids), evicted: new Set(l.evicted) } : undefined);
    } catch {
      onRelay.set(r, undefined);
    }
  }
  const rows: CodeRow[] = [];
  for (const c of all.sort((a, b) => b.createdAt - a.createdAt)) {
    let status: CodeRow["status"] = c.status;
    if (c.status === "open") {
      if (c.exp <= now) status = "expired";
      else {
        const on = onRelay.get(c.relay);
        if (on?.evicted.has(c.lid)) status = "evicted";
        else if (on && !on.lids.has(c.lid)) status = "taken";
      }
    }
    const circles: CodeRow["circles"] = [];
    for (const cid of c.cids ?? (c.cid ? [c.cid] : [])) {
      const lc = await loadCircle(app.store, cid);
      circles.push({ cid, name: lc ? circleDisplayName(lc.chain.head) : cid });
    }
    const circle: CodeRow["circle"] = circles[0] ?? null;
    rows.push({
      code: c.short,
      label: c.label ?? null,
      to: c.aud === "*" ? null : { userId: c.aud, address: await app.addressOf(c.aud) },
      circle,
      circles,
      createdAt: c.createdAt,
      exp: c.exp,
      status,
      ...(c.redeemedBy ? { redeemedBy: { userId: c.redeemedBy, address: await app.addressOf(c.redeemedBy) } } : {}),
      ...(c.redeemedAt ? { redeemedAt: c.redeemedAt } : {}),
    });
  }
  return rows;
}

/** A full code (with or without its relay part), or a unique prefix of at least 4 of its characters. */
async function findCode(app: App, input: string): Promise<CodeRecord> {
  const all = Object.values((await app.state.get("codes")) ?? {});
  const t = input.trim();
  const last = t.slice(t.lastIndexOf("/") + 1);
  const s = decodeCodeChars(last);
  if (s) {
    const lid = inviteLid(s);
    const hit = all.find((c) => c.lid === lid);
    if (hit) return hit;
  }
  const norm = (x: string) => x.toUpperCase().replace(/[\s-]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1").replace(/…$/, "");
  const want = norm(last);
  if (want.length < 4) throw new CliError("not_found", `no code ${input} (give the code, or at least its first 4 characters; see \`p2p invites\`)`);
  const hits = all.filter((c) => norm(c.code).startsWith(want));
  if (hits.length > 1) throw new CliError("ambiguous", `${input} matches ${hits.length} codes: give more of it`);
  if (hits.length === 0) throw new CliError("not_found", `no code ${input} (see \`p2p invites\`)`);
  return hits[0];
}

export async function revokeCode(app: App, input: string): Promise<{ code: string; revoked: boolean; wasOpen: boolean; redeemedBy: string | null }> {
  const rec = await findCode(app, input);
  if (rec.status === "revoked") return { code: rec.short, revoked: true, wasOpen: false, redeemedBy: null };
  const pool = await app.connect({ allowNone: true });
  let wasOpen = false;
  try {
    wasOpen = await inviteDel(await pool.ensure(rec.relay), rec.lid);
  } catch (e) {
    app.warn(`couldn't reach ${rec.relay} to delete the code (${(e as Error).message}); it is refused here anyway`);
  }
  if (rec.capid) {
    const caps = (await app.store.listCapsIssued()).filter((c) => c.capid === rec.capid);
    await app.revokeCaps(caps).catch(() => 0);
  }
  const updated: CodeRecord = { ...rec, status: rec.status === "redeemed" ? "redeemed" : "revoked" };
  if (rec.status !== "redeemed") {
    await app.state.update("codes", (cur = {}) => ({ next: { ...cur, [rec.lid]: updated }, result: undefined }));
    await sendSync(app, { codes: [updated] });
  }
  if (rec.status === "redeemed") app.warn(`${codeHint(rec.code)} was already redeemed by ${await app.addressOf(rec.redeemedBy!)}: \`p2p remove ${rec.redeemedBy}\` undoes that`);
  return { code: rec.short, revoked: rec.status !== "redeemed", wasOpen, redeemedBy: rec.redeemedBy ?? null };
}

export interface RemoveResult {
  removed: string;
  address: string;
  unfriended: boolean;
  circles: { cid: string; result: "removed" | "proposed" | "not-member" | "not-allowed" }[];
}

/** Undoes a code redemption: unfriends `who` and takes them out of the circles our codes added them to. */
export async function removeUser(app: App, who: string): Promise<RemoveResult> {
  const u = await app.resolveUser(who);
  if (!isUserId(u) || u === app.userId) throw new CliError("usage", "name someone else");
  await app.connectAndDrain();
  const recs = Object.values((await app.state.get("codes")) ?? {}).filter((c) => c.redeemedBy === u);
  const circles: RemoveResult["circles"] = [];
  // Only the circles a code put them in (L3); a record from before `added` was kept: every circle it named.
  for (const cid of new Set(recs.flatMap((c) => c.added ?? c.cids ?? (c.cid ? [c.cid] : [])))) {
    circles.push({ cid, result: await removeMember(app, cid, u) });
  }
  let unfriended = false;
  try {
    await unfriend(app, u);
    unfriended = true;
  } catch (e) {
    if (!(e instanceof CliError && e.code === "not_friends")) throw e;
  }
  const at = nowSec();
  const changed = recs.map((c) => ({ ...c, removedAt: at }));
  if (changed.length) {
    await app.state.update("codes", (cur = {}) => ({ next: { ...cur, ...Object.fromEntries(changed.map((c) => [c.lid, c])) }, result: undefined }));
    await sendSync(app, { codes: changed });
  }
  if (!unfriended && circles.length === 0) throw new CliError("not_found", `${await app.addressOf(u)} is neither a friend nor in a circle one of your codes added them to`);
  return { removed: u, address: await app.addressOf(u), unfriended, circles };
}
