// Copyright 2026 Ix Infrastructure Inc.
//
// Agent sessions (docs/protocol.md §3.4, §4.2, §4.3, §6): rosters, `status`
// envelopes, messages, `ls`, and `watch`.
//
//  - A session's roster follows its project (projects.ts, §6): private until
//    the person shares the project, and never wider than every project the
//    session has worked in allows. It rides in every status and message we
//    send into our own session.
//  - `status` goes to everyone the roster allows (§4.2, computed with the
//    core's own rule) and to our other devices. A session is live for 150 s
//    after the `ts` of its last status (§4.3).
//  - `send --to` resolves a user, then one of their live sessions (a `[ref]`
//    or `/sid` picks one); with none, the message goes into our own session,
//    whose roster must allow the recipient.
//  - `--notify-when-idle` is a local, one-shot subscription: the next time
//    that session's status goes busy → idle (or it sends `idle`), the sender
//    session's watcher gets `p2p.idle`. It expires after an hour.

import { sessionEnded } from "./running.js";
import { enqueue, flushOutbox, OUTBOX_RETRYABLE, OUTBOX_TTL_MS, retryable } from "./outbox.js";
import { basename, dirname, resolve as resolvePath } from "node:path";
import {
  createRosterV3,
  displayStatus,
  extensionFallbackText,
  FALLBACK_MAX,
  isExtensionKind,
  isLive,
  isSafeRelativePath,
  liveFriendshipsV3,
  loadCircle,
  partyAuthorizedV3,
  sanitizePeerText,
  sha256,
  standsLookup,
  circlePolicy,
  isStatusCap,
  STATUS_CAP_MAX_LEN,
  STATUS_CAPS_MAX,
  STATUS_CAP_RECEIPTS,
  STATUS_CAP_AGENTS,
  STATUS_AGENTS_MAX,
  STATUS_AGENT_FILES_MAX,
  STATUS_AGENT_TASK_MAX,
  isStatusAgentBranch,
  isStatusAgentFile,
  isStatusAgentId,
  isStatusAgentType,
  statusAgentsError,
  summaryWithAgents,
  redactSecrets,
  stripAbsolutePaths,
  type AcceptedMessageV3,
  type ProjectBound,
  parseBound,
  type ExtensionKind,
  type StatusAgent,
  type StatusAgentState,
  type StatusBody,
} from "@peer2peer/core/v3";
import type { App, Delivery } from "./app.js";
import { CliError } from "./errors.js";
import {
  assertMayReach,
  bindSession,
  ceilingAudience,
  defaultCircleNotice,
  friendIds,
  PERSON_SESSION,
  sessionBinding,
  agentContext,
  sessionCeiling,
  sessionProjectView,
  sessionDirs,
  sessionWorkdir,
  MAX_SESSION_DIRS,
  SCRATCH_ENV,
  sessionScratch,
  overWhys,
  privateRemedy,
  shareHint,
  type Ceiling,
  type OverWhy,
  type SessionProjectView,
} from "./projects.js";
import { renderExtension, type ExtSendResult } from "./extensions.js";
import { fromOf, makeEvent, type NewEvent } from "./inbound.js";
import { receiptsEnabled, statusCapsEnabled } from "./config.js";
import { CAP_PROJECTS, CLI_CAPS, protoMinor, supportsIn } from "./features.js";
import { asksReceipts, newReceiptId, rememberAsked, rememberWanted } from "./receipts.js";
import { recordSent } from "./history.js";
import { sessKey, type IdleSub, type LocalSend, type PeerStatusRec, type SessionDoc } from "./state.js";
import { isStateEnvelope, liveStates, onStateEnvelope, stateKindCaps, stateSummaries, type StateSummary } from "./xstate.js";

/** Session ids: what Claude Code and Codex use (UUIDs and the like). */
export const SID_RE = /^[A-Za-z0-9._-]{1,128}$/;
export const MAX_TEXT_BYTES = 24 * 1024;
export const MAX_FILES = 25;
export const IDLE_SUB_TTL_MS = 3600_000;
/**
 * What this CLI itself understands (§4.3 "Status caps"): the tolerant status
 * parser, `status.agents` (it parses, stores and lists them), and extension
 * state kinds (xstate.v1: it keeps them latest-wins and never logs them as
 * events; xstate.ts). `p2p status` adds `<kind>.v1` for each state kind a
 * loaded extension declares. A caller
 * (the mod, the Codex bridge) adds its own with `--cap`.
 *
 * Two-step rollout, step 2 (footprint P1): statuses carry `caps` by default.
 * Clients older than the amendment reject a status that carries `caps`, so a
 * user whose peers still run one opts out with `P2P_STATUS_CAPS=0` or
 * `"statusCaps": false` in config.json (see statusCapsEnabled).
 */
export const CLI_STATUS_CAPS: readonly string[] = CLI_CAPS;
/** §4.3 "Status agents": at most this many distinct paths across `files` and every agent's. */
export const MAX_STATUS_PATHS = 60;
/** §4.3: a sender keeps a status plaintext under 8 KiB; agents are trimmed (oldest first) to fit. */
export const STATUS_SOFT_MAX_BYTES = 8 * 1024;

export function checkSid(sid: string | undefined, flag = "--session"): string {
  if (!sid || !SID_RE.test(sid)) throw new CliError("usage", `${flag} must be a session id ([A-Za-z0-9._-], at most 128)`);
  return sid;
}

/** First 6 hex characters of sha256(own + "/" + sid): a short session reference. */
export function sessionRef(own: string, sid: string): string {
  return [...sha256(new TextEncoder().encode(`${own}/${sid}`)).slice(0, 3)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// Rosters (§3.4)

/** A roster as a change wants it: what follows from the session's doc as stored, or nothing to change. */
type RosterSpec = Pick<SessionDoc, "vis" | "circle" | "parts" | "auto">;

/**
 * Decides and writes a session's roster under the state lock, against the doc
 * as stored at that moment (review M1): two commands at once (a status post
 * following the default circle, and `session roster --private`) can't undo
 * each other, and a version is never reused or lowered. The trust store must
 * take the new version too; a stale or conflicting one stops here, nothing
 * written.
 */
async function writeRoster(app: App, sid: string, decide: (have: SessionDoc | undefined) => RosterSpec | undefined, want?: { vis: "circle" | "private"; circle?: string }): Promise<SessionDoc> {
  // What this device would sign as the default roster now (`want`): an adopted one equal to it still follows the project.
  return app.state.updateAsync("sessions", async (cur = {}) => {
    const have = cur[sid];
    // The trust store may hold a newer version than state (written by an older client, a crash
    // between the two writes): adopt it first, and number past it, or the session's roster could
    // never change again (review M-new). Only one this device signed (pre-release review low): anything
    // else fails closed.
    const stored = await app.store.getRoster(app.userId, sid);
    let base = have;
    if (stored && stored.ver > (have?.ver ?? 0) && stored.jws !== have?.jws) base = docFromStored(sid, stored, app.did, want);
    const spec = decide(base);
    if (!spec) {
      if (!base) throw new CliError("conflict", `session ${sid} has no roster`);
      return base === have ? { result: base } : { next: { ...cur, [sid]: base }, result: base };
    }
    const ver = Math.max(base?.ver ?? 0, stored?.ver ?? 0) + 1;
    const jws = createRosterV3(app.signer(), { sid, ver, vis: spec.vis, ...(spec.circle ? { circle: spec.circle } : {}), parts: spec.parts });
    const put = await app.store.putRoster({ iss: app.userId, sid, ver, jws });
    if (put === "stale" || put === "conflict") {
      throw new CliError("conflict", `session ${sid}: roster version ${ver} is ${put} against the one already held; run the command again`);
    }
    const doc: SessionDoc = { sid, ver, vis: spec.vis, ...(spec.circle ? { circle: spec.circle } : {}), parts: [...spec.parts], jws, ...(spec.auto !== undefined ? { auto: spec.auto } : {}) };
    return { next: { ...cur, [sid]: doc }, result: doc };
  });
}

/**
 * A stored roster of our own as a session doc: its signed payload read back
 * (it is ours, verified when stored). Only a roster this device signed is
 * adopted (pre-release review low); one signed by another device of ours, or one this
 * client can't read, fails closed: nothing is written. Its provenance is
 * unknown, so it counts as set explicitly (no auto-follow), unless it is
 * exactly the default roster this device would sign now (`want`, no
 * participants): then it keeps following the default.
 */
export function docFromStored(sid: string, r: { ver: number; jws: string }, did: string, want?: { vis: "circle" | "private"; circle?: string }): SessionDoc {
  let p: Record<string, unknown>;
  try {
    p = JSON.parse(Buffer.from(r.jws.split(".")[1] ?? "", "base64url").toString("utf8")) as Record<string, unknown>;
  } catch {
    p = {};
  }
  if (p.sid !== sid || p.ver !== r.ver || (p.vis !== "circle" && p.vis !== "private") || !Array.isArray(p.parts)) {
    throw new CliError("conflict", `session ${sid}: the trust store holds roster version ${r.ver}, which this client can't read; it is not adopted, and the roster is left as it is`);
  }
  if (p.did !== did) {
    throw new CliError(
      "conflict",
      `session ${sid}: the trust store holds roster version ${r.ver} signed by another device (${sanitizePeerText(String(p.did), 80)}), not this one (${did}); this device won't adopt or overwrite it: use another session id here`,
    );
  }
  const parts = p.parts.filter((x): x is string => typeof x === "string");
  const circle = p.vis === "circle" && typeof p.circle === "string" ? p.circle : undefined;
  const auto = want !== undefined && parts.length === 0 && p.vis === want.vis && circle === want.circle;
  return { sid, ver: r.ver, vis: p.vis, ...(circle ? { circle } : {}), parts, jws: r.jws, auto };
}

/**
 * What a session's roster may be now (projects.ts): its ceiling, everyone the ceiling lets in,
 * and the roster a session nobody narrowed by hand gets. A shared project's roster names one
 * circle (the default circle when the project shares it, else the first) and, as participants,
 * the people it shares and the friends among the members of its other circles (a roster names
 * one circle, §3.4: a member of a second circle who isn't a friend can't be reached through it).
 */
interface RosterCtx {
  ceiling: Ceiling;
  /** Undefined for `none`. */
  audience?: Set<string>;
  auto: RosterSpec;
}

async function rosterCtx(app: App, sid: string): Promise<RosterCtx> {
  const ceiling = await sessionCeiling(app, sid);
  const audience = await ceilingAudience(app, ceiling);
  if (ceiling.kind !== "shared" || !audience) return { ceiling, ...(audience ? { audience } : {}), auto: { vis: "private", parts: [], auto: true } };
  const def = app.self?.defaultCircle;
  const circle = def && ceiling.circles.includes(def) ? def : ceiling.circles[0];
  const inCircle = new Set<string>();
  if (circle) for (const m of (await loadCircle(app.store, circle).catch(() => undefined))?.chain.head.members ?? []) inCircle.add(m);
  const friends = await friendIds(app);
  const parts = [...audience].filter((u) => !inCircle.has(u) && friends.has(u)).sort();
  return { ceiling, audience, auto: { vis: circle ? "circle" : "private", ...(circle ? { circle } : {}), parts, auto: true } };
}

/** A roster cut down to what the ceiling allows (never wider than it was). */
function clip(spec: RosterSpec, ctx: RosterCtx): RosterSpec {
  if (ctx.ceiling.kind === "none" || !ctx.audience) return spec;
  if (ctx.ceiling.kind === "private") return { vis: "private", parts: [], auto: spec.auto };
  const circle = spec.vis === "circle" && spec.circle && ctx.ceiling.circles.includes(spec.circle) ? spec.circle : undefined;
  return { vis: circle ? "circle" : "private", ...(circle ? { circle } : {}), parts: spec.parts.filter((u) => ctx.audience!.has(u)), auto: spec.auto };
}

function sameRoster(a: SessionDoc, b: RosterSpec): boolean {
  const pa = [...new Set(a.parts)].sort();
  const pb = [...new Set(b.parts)].sort();
  return a.vis === b.vis && a.circle === b.circle && pa.length === pb.length && pa.every((x, i) => x === pb[i]) && isAutoRoster(a) === (b.auto ?? false);
}

/**
 * Whether a session's roster is still the default one, never set explicitly.
 * A doc from before `auto` existed counts when it is the first version with
 * no participants: every explicit change (`session roster`) bumps the version.
 */
export function isAutoRoster(d: SessionDoc): boolean {
  return d.auto ?? (d.ver === 1 && d.parts.length === 0);
}

export const OPEN_CIRCLE_SHARED = "is shared with an open circle (its policy is open now): anyone its owner admits can see it; `p2p session roster <sid> --private` (or /peers private) stops that";

/**
 * Review L-c: a session shared with a circle whose policy is (or became) open
 * says so once, on its next status (a warning in the result), and once more
 * only if it moves to another open circle.
 */
async function noteOpenCircle(app: App, sess: SessionDoc, notes: string[]): Promise<SessionDoc> {
  if (sess.vis !== "circle" || !sess.circle || sess.openNoted === sess.circle) return sess;
  const c = await loadCircle(app.store, sess.circle).catch(() => undefined);
  if (!c || circlePolicy(c.chain.head) !== "open") return sess;
  notes.push(`session ${sess.sid} ${OPEN_CIRCLE_SHARED}`);
  const circle = sess.circle;
  return app.state.update("sessions", (cur = {}) => {
    const d = cur[sess.sid];
    if (!d || d.jws !== sess.jws) return { result: sess };
    const next = { ...d, openNoted: circle };
    return { next: { ...cur, [sess.sid]: next }, result: next };
  });
}

/** Kept for clients that match these notes (older mods); this CLI no longer says them: sessions follow their project. */
export const CODE_JOIN_NO_FOLLOW =
  "kept as it was: a code you redeemed set your default circle, and a session already running doesn't move into a circle by itself; share it with `p2p session roster <sid> --circle <cid>` (or /peers circle <cid>). New sessions start in it";
export const OPEN_CIRCLE_NO_FOLLOW =
  "kept private: your default circle is open (anyone its owner admits can see what's shared there), so a session already running doesn't move into it by itself; share it with `p2p session roster <sid> --circle <cid>` (or /peers circle <cid>)";

/**
 * The session's roster, made on first use, and kept within its project ceiling (projects.ts):
 * one nobody set by hand follows its projects' policies (private until the person shares the
 * project); one set by hand is cut down to the ceiling when the ceiling narrows (a session that
 * worked in a private project stays private until it ends). The person's own session, and one
 * no project is bound to yet, have no ceiling: their roster is private until set by hand.
 */
export async function getSession(app: App, sid: string, notes?: string[]): Promise<SessionDoc> {
  void notes;
  const ctx = await rosterCtx(app, sid);
  return writeRoster(
    app,
    sid,
    (have) => {
      if (ctx.ceiling.kind === "none") return have ? undefined : { vis: "private", parts: [], auto: true };
      const spec = !have || isAutoRoster(have) ? ctx.auto : clip({ vis: have.vis, ...(have.circle ? { circle: have.circle } : {}), parts: have.parts, auto: false }, ctx);
      return have && sameRoster(have, spec) ? undefined : spec;
    },
    ctx.auto,
  );
}

export interface RosterView {
  sid: string;
  ref: string;
  ver: number;
  vis: "circle" | "private";
  circle?: string;
  circleName?: string;
  parts: { userId: string; address: string }[];
  openCircle?: boolean;
}

async function rosterView(app: App, s: SessionDoc): Promise<RosterView> {
  const c = s.circle ? await loadCircle(app.store, s.circle) : undefined;
  return {
    sid: s.sid,
    ref: sessionRef(app.userId, s.sid),
    ver: s.ver,
    vis: s.vis,
    ...(s.circle ? { circle: s.circle } : {}),
    ...(c ? { circleName: sanitizePeerText(c.chain.head.name, 64) } : {}),
    parts: await Promise.all(s.parts.map(async (u) => ({ userId: u, address: await app.addressOf(u) }))),
    ...(c && circlePolicy(c.chain.head) === "open" ? { openCircle: true } : {}),
  };
}

export async function roster(
  app: App,
  sid: string,
  opts: { circle?: string; private?: boolean; add?: string[]; remove?: string[] },
): Promise<RosterView> {
  checkSid(sid, "sid");
  const cur = await getSession(app, sid);
  const change = opts.circle !== undefined || opts.private || (opts.add?.length ?? 0) > 0 || (opts.remove?.length ?? 0) > 0;
  if (!change) return rosterView(app, cur);
  // A change (even a narrowing one) only from the session's front end once one registered it, and
  // never from an agent's own shell (projects.ts bindSession, N2).
  if (!app.front) {
    if (agentContext(app.env)) throw new CliError("refused", `session ${sid}: inside an agent's session only its front end changes who sees a session`);
    if ((await sessionBinding(app, sid))?.registered) throw new CliError("refused", `session ${sid} belongs to a front end of yours (the Claude mod or the Codex bridge): only it changes who sees that session`);
  }
  if (opts.circle !== undefined && opts.private) throw new CliError("usage", "--circle and --private are exclusive");
  let vis = cur.vis;
  let circle = cur.circle;
  if (opts.circle !== undefined) {
    const { resolveCircle } = await import("./circle-ops.js");
    const c = await resolveCircle(app, opts.circle);
    if (!c.record.joinedByMe) throw new CliError("usage", "you haven't joined that circle");
    vis = "circle";
    circle = c.record.cid;
  }
  if (opts.private) {
    vis = "private";
    circle = undefined;
  }
  const add: string[] = [];
  for (const a of opts.add ?? []) {
    const u = await app.resolveUser(a);
    if (u !== app.userId) add.push(u);
  }
  const remove = await Promise.all((opts.remove ?? []).map((r) => app.resolveUser(r)));
  // Never wider than the session's projects allow (projects.ts): sharing beyond them is the
  // project's policy, which only the person changes (`p2p project share`).
  const ctx = await rosterCtx(app, sid);
  if (ctx.ceiling.kind !== "none" && ctx.audience) {
    const names = Object.values((await sessionBinding(app, sid))?.projects ?? {}).map((p) => p.name);
    const ceiling = ctx.ceiling;
    const deny = (what: string): never => {
      const remedy = ceiling.kind === "private" ? privateRemedy(ceiling.causes, ceiling.blocking?.length ? ceiling.blocking : names) : shareHint(names);
      throw new CliError("not_shared", `session ${sid} works in ${names.join(", ")}, which ${ceiling.kind === "private" ? `is private (${ceiling.why}), so it isn't shared` : "isn't shared"} ${what}: ${remedy}`, {
        project: { names, policy: ceiling.kind, ...(ceiling.kind === "private" ? { causes: ceiling.causes } : {}) },
      });
    };
    if (opts.circle !== undefined && circle !== undefined && (ceiling.kind !== "shared" || !ceiling.circles.includes(circle))) deny(`with circle ${circle}`);
    for (const u of add) if (!ctx.audience.has(u)) deny(`with ${await app.addressOf(u)}`);
  }
  // Applied to the doc as stored when the lock is held, not as read above (review M1).
  // Set explicitly: it no longer follows the project.
  const next = await writeRoster(
    app,
    sid,
    (have) => {
      const parts = new Set(have?.parts ?? []);
      for (const u of add) parts.add(u);
      for (const u of remove) parts.delete(u);
      const v = opts.private ? "private" : opts.circle !== undefined ? "circle" : (have?.vis ?? vis);
      const c = opts.private ? undefined : opts.circle !== undefined ? circle : have?.circle;
      return clip({ vis: v, ...(c ? { circle: c } : {}), parts: [...parts], auto: false }, ctx);
    },
    ctx.auto,
  );
  const v = await rosterView(app, next);
  if (v.openCircle) {
    app.warn("this session is shared with an open circle: anyone the owner admits can see it");
    // Warned here already: its next status doesn't say it again.
    await app.state.update("sessions", (cur = {}) => (cur[sid]?.jws === next.jws ? { next: { ...cur, [sid]: { ...cur[sid]!, openNoted: next.circle } }, result: undefined } : { result: undefined }));
  }
  return v;
}

/**
 * Who a session's status reaches, as an extension may know it (ExtContext.audience): its
 * roster's visibility, the circle and whether that circle is open, and how many people the
 * roster lets see it besides this user. Read only: a session with no roster yet, or whose circle
 * can't be loaded, is undefined (nothing is created). `orgs` (distinct verified organisations) is absent until a trust
 * provider supplies org labels (§8.2).
 */
export async function sessionAudience(app: App, sid: string): Promise<{ vis: "circle" | "private"; circle?: string; open?: true; people: number; members: string[] } | undefined> {
  checkSid(sid, "sid");
  const sess = (await app.state.get("sessions"))?.[sid];
  if (!sess) return undefined;
  const c = sess.vis === "circle" && sess.circle ? await loadCircle(app.store, sess.circle).catch(() => undefined) : undefined;
  // A circle that can't be loaded: who it reaches is unknown (an extension then fails closed).
  if (sess.vis === "circle" && sess.circle && !c) return undefined;
  let members = (await rosterAudience(app, sess).catch(() => [] as string[])).filter((u) => u !== app.userId);
  // The stored roster may predate a narrower ceiling (no status since): never wider than the ceiling now.
  const cap = await ceilingAudience(app, await sessionCeiling(app, sid));
  if (cap) members = members.filter((u) => cap.has(u));
  return { vis: sess.vis, ...(sess.circle ? { circle: sess.circle } : {}), ...(c && circlePolicy(c.chain.head) === "open" ? { open: true as const } : {}), people: members.length, members };
}

/** Who the roster lets see this session, besides us (§4.2, the core rule). */
export async function rosterAudience(app: App, s: SessionDoc): Promise<string[]> {
  const facts = {
    friendships: await liveFriendshipsV3(app.store, app.signerCtx()),
    unfriends: await app.store.listUnfriends(),
    stands: await standsLookup(app.store, app.userId),
  };
  const r = { iss: app.userId, vis: s.vis, ...(s.circle ? { circle: s.circle } : {}), parts: s.parts };
  const cands = new Set(s.parts);
  if (s.circle) {
    const c = await loadCircle(app.store, s.circle);
    for (const m of c?.chain.head.members ?? []) cands.add(m);
  }
  cands.delete(app.userId);
  const blocks = new Set((await app.store.listBlocks()).map((b) => b.userId));
  return [...cands].filter((u) => !blocks.has(u) && partyAuthorizedV3(u, r, facts).ok);
}

// ---------------------------------------------------------------------------
// status (§4.3)

export interface StatusOpts {
  session: string;
  state: string;
  summary?: string;
  files?: string[];
  label?: string;
  repo?: string;
  branch?: string;
  mode?: string;
  cwd?: string;
  /** Caps the caller's client understands, added to {@link CLI_STATUS_CAPS}. Ignored when `emitCaps` is off. */
  caps?: string[];
  /** Whether this status carries `caps` (and `agents`) at all (statusCapsEnabled); on by default. */
  emitCaps?: boolean;
  /**
   * Directories the session works in besides its working directory (P2P_WORKDIR, else the
   * process's): a folder it moved to, files it touched elsewhere. Each binds the session to that
   * project for the rest of its life (projects.ts), which can only narrow who sees it.
   */
  projectDirs?: string[];
  /**
   * The front end dropped folders past its cap, or couldn't resolve a path (`--project-dirs-over`):
   * private. A list says why (projects.ts OverWhy: `--project-dirs-over=unresolved,folders`); `true`
   * is an older front end's bare flag.
   */
  projectDirsOver?: boolean | string[];
  /**
   * The session's subagents (`--agents-json`), as the caller has them: entries
   * are normalized (sanitized, capped, ordered, trimmed), never trusted as is.
   */
  agents?: unknown;
}

export interface StatusResult {
  status: StatusBody;
  roster: RosterView;
  /** `agents`: whether that recipient got `status.agents` (its live sessions all advertise agents.v1). */
  delivered: (Delivery & { address: string; agents: boolean })[];
  failed: { userId: string; address: string; error: string }[];
  /** What was left out rather than failing the post (review L3): caller caps that were off, invalid or over the limit. */
  warnings?: string[];
  /** The projects this session works in and what they allow (projects.ts). */
  project?: SessionProjectView;
  /** The folders it was given are bound for good (a front end may stop passing them). */
  bound?: true;
}

/**
 * The status this session posts. Never fails over what a caller adds on top
 * of the original fields (review L3): with status caps off (the opt-out),
 * caller caps and agents are left out (agents still count in the summary); an
 * invalid or surplus cap is dropped. Each is noted in `warnings`.
 */
export function buildStatus(o: StatusOpts, prev?: StatusBody, warnings: string[] = []): StatusBody {
  if (o.state !== "busy" && o.state !== "idle") throw new CliError("usage", "--state must be busy or idle");
  const files = o.files ?? [];
  if (files.length > MAX_FILES) throw new CliError("usage", `at most ${MAX_FILES} --file`);
  for (const f of files) if (!isSafeRelativePath(f) || f.length > 200) throw new CliError("usage", `--file ${f} must be a relative path with no . or .. segments`);
  if (o.summary !== undefined && [...o.summary].length > 280) throw new CliError("usage", "--summary is at most 280 characters");
  const label = (o.label ?? basename(o.cwd ?? process.cwd())).slice(0, 64) || "session";
  const s: StatusBody = { state: o.state, label };
  if (o.repo) s.repo = o.repo;
  if (o.branch) s.branch = o.branch;
  if (o.mode) s.mode = o.mode;
  if (o.summary) {
    s.summary = o.summary;
    // The line as written, without a `(+N agents)` this CLI added (caps off stores the folded one; review L1).
    s.summaryAt = prev?.summary !== undefined && withoutAgentCount(prev.summary) === o.summary && prev.summaryAt ? prev.summaryAt : Date.now();
  }
  if (files.length > 0) s.files = files;
  const agents = o.agents === undefined ? undefined : normalizeAgents(o.agents, files);
  if (o.emitCaps) {
    s.caps = statusCaps(o.caps, warnings);
    if (agents && agents.length > 0) {
      s.agents = agents;
      fitAgents(s);
    }
  } else {
    if ((o.caps?.length ?? 0) > 0) warnings.push("status caps are off (P2P_STATUS_CAPS=0 or \"statusCaps\": false), so --cap was left out");
    // Off: the status carries only the original fields; agents at work still show as `(+N agents)`.
    const folded = summaryWithAgents(s.summary, agents);
    if (folded !== s.summary && folded !== undefined) s.summary = folded;
  }
  return s;
}

/** A summary without the ` (+N agents)` summaryWithAgents() appends (or the whole of one that is only that). */
export function withoutAgentCount(summary: string): string {
  return summary.replace(/(^| )\(\+\d+ agents?\)$/, "");
}

/** CLI_STATUS_CAPS plus the caller's valid ones, deduplicated and within STATUS_CAPS_MAX; the rest are noted. */
function statusCaps(extra: readonly string[] = [], warnings: string[] = []): string[] {
  const caps = [...CLI_STATUS_CAPS];
  for (const c of extra) {
    if (caps.includes(c)) continue;
    if (!isStatusCap(c)) warnings.push(`--cap ${JSON.stringify(c).slice(0, 60)} was left out: at most ${STATUS_CAP_MAX_LEN} characters of [a-z0-9._-], starting with a letter (x: for an extension's)`);
    else if (caps.length >= STATUS_CAPS_MAX) warnings.push(`--cap ${c} was left out: at most ${STATUS_CAPS_MAX} caps in a status (${CLI_STATUS_CAPS.length} are the CLI's own)`);
    else caps.push(c);
  }
  return caps;
}

const AGENT_STATE: Record<string, StatusAgentState> = {
  running: "running",
  pending: "running",
  waiting: "waiting",
  idle: "idle",
  done: "done",
  completed: "done",
  failed: "failed",
  killed: "failed",
};
const isDone = (a: StatusAgent) => a.state === "done" || a.state === "failed";

/**
 * `--agents-json` as a valid §4.3 `agents` list: each entry's fields
 * sanitized or dropped, at most 10 files each (never under `.claude/worktrees/`
 * or `.git/`), ordered (at work first, then most recent), at most 8, nesting
 * flattened to depth 2. Not an array is a usage error.
 */
export function normalizeAgents(raw: unknown, mainFiles: readonly string[] = []): StatusAgent[] {
  if (!Array.isArray(raw)) throw new CliError("usage", "--agents-json must be a JSON array of agents");
  const out: StatusAgent[] = [];
  const seen = new Set<string>();
  for (const x of raw.slice(0, 64)) {
    if (typeof x !== "object" || x === null || Array.isArray(x)) continue;
    const e = x as Record<string, unknown>;
    if (!isStatusAgentId(e.id) || seen.has(e.id)) continue;
    const state = typeof e.state === "string" ? AGENT_STATE[e.state] : undefined;
    if (!state) continue;
    seen.add(e.id);
    const typeRaw = typeof e.type === "string" ? e.type.replace(/[^A-Za-z0-9:_ .-]/g, "").replace(/\s+/g, " ").trim().slice(0, 32).trim() : "";
    const type = isStatusAgentType(typeRaw) ? typeRaw : "agent";
    // No absolute or home paths, no secret shapes (review M3), before the 80-character cap.
    // Sanitized first (one line, no controls), then no absolute or home paths and no secret shapes, then capped.
    const task = sanitizePeerText(redactSecrets(stripAbsolutePaths(sanitizePeerText(typeof e.task === "string" ? e.task.slice(0, 2000) : "", 2000))), STATUS_AGENT_TASK_MAX) || type;
    const files: string[] = [];
    for (const f of Array.isArray(e.files) ? e.files : []) {
      if (files.length >= STATUS_AGENT_FILES_MAX) break;
      if (!isStatusAgentFile(f) || files.includes(f)) continue;
      const lower = f.toLowerCase().replace(/\\/g, "/");
      if (lower === ".git" || lower.startsWith(".git/") || lower === ".claude/worktrees" || lower.startsWith(".claude/worktrees/")) continue;
      files.push(f);
    }
    const at = typeof e.at === "number" && Number.isSafeInteger(e.at) && e.at >= 0 ? e.at : Date.now();
    out.push({
      id: e.id,
      ...(isStatusAgentId(e.parent) && e.parent !== e.id ? { parent: e.parent } : {}),
      type,
      task,
      state,
      ...(files.length > 0 ? { files } : {}),
      ...(e.wt === true ? { wt: true as const } : {}),
      ...(e.wt === true && isStatusAgentBranch(e.branch) ? { branch: e.branch } : {}),
      at,
    });
  }
  // At work first, then the most recent; done and failed last.
  out.sort((a, b) => Number(isDone(a)) - Number(isDone(b)) || b.at - a.at);
  // Over the cap: done agents with no files go first, then the oldest.
  while (out.length > STATUS_AGENTS_MAX) {
    let drop = out.length - 1;
    for (let i = out.length - 1; i >= 0; i--) {
      if (isDone(out[i]) && !out[i].files) {
        drop = i;
        break;
      }
    }
    out.splice(drop, 1);
  }
  flatten(out);
  // At most MAX_STATUS_PATHS distinct paths across the main loop's files and every agent's.
  const paths = new Set(mainFiles);
  for (const a of out) {
    if (!a.files) continue;
    a.files = a.files.filter((f) => {
      if (paths.has(f)) return true;
      if (paths.size >= MAX_STATUS_PATHS) return false;
      paths.add(f);
      return true;
    });
    if (a.files.length === 0) delete a.files;
  }
  return out;
}

/** Parents that aren't listed are dropped (the agent shows as the main loop's); deeper nesting attaches to the depth-1 ancestor. */
function flatten(agents: StatusAgent[]): void {
  const byId = new Map(agents.map((a) => [a.id, a]));
  for (const a of agents) {
    let p = a.parent !== undefined ? byId.get(a.parent) : undefined;
    for (let hops = 0; p?.parent !== undefined && hops < STATUS_AGENTS_MAX; hops++) p = byId.get(p.parent);
    if (p === undefined || p === a || p.parent !== undefined) delete a.parent;
    else a.parent = p.id;
  }
}

/** Trims `s.agents` from the end until the status plaintext is under STATUS_SOFT_MAX_BYTES; a list that still fails validation is dropped whole. */
function fitAgents(s: StatusBody): void {
  const agents = s.agents;
  if (!agents) return;
  while (agents.length > 0 && Buffer.byteLength(JSON.stringify({ status: s }), "utf8") > STATUS_SOFT_MAX_BYTES) {
    agents.pop();
    flatten(agents);
  }
  if (agents.length === 0 || statusAgentsError(agents) !== undefined) delete s.agents;
}

/**
 * The status a recipient without agents.v1 gets: no `agents` (a client from
 * before P1 would drop it, one from before the amendment would reject the
 * status), and the agents at work counted in the summary instead.
 */
export function statusWithoutAgents(s: StatusBody): StatusBody {
  if (s.agents === undefined) return s;
  const { agents, ...rest } = s;
  const summary = summaryWithAgents(s.summary, agents);
  return { ...rest, ...(summary !== undefined ? { summary } : {}) };
}

/**
 * Whether user `u` gets `status.agents`: every live session of theirs we
 * know of (other than this device's own) advertises agents.v1, and there is
 * at least one. Status goes to a user, one plaintext for all their devices,
 * so one session from an older client (or none at all) means the summary
 * fallback for that user.
 */
export function understandsAgents(peers: Record<string, PeerStatusRec>, u: string, self: { userId: string; did: string }, now = Date.now()): boolean {
  return supportsIn({ peers, self, now }, u, { all: true }, STATUS_CAP_AGENTS);
}

/** How many recipients a status goes to at once. */
export const STATUS_FANOUT = 8;

/** `fn` over `items`, at most `limit` at a time; results in input order. */
export async function mapLimit<T, R>(items: readonly T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

export async function sendStatus(app: App, o: StatusOpts): Promise<StatusResult> {
  const sid = checkSid(o.session);
  // The folders of the files it says it changes are folders it works in too (a nested repository,
  // a path through a symlink): each binds its project.
  const work = sessionWorkdir(app.env);
  const fileDirs = (o.files ?? []).filter((f) => typeof f === "string").map((f) => dirname(resolvePath(work, f)));
  await bindFromEnv(app, sid, [...(o.projectDirs ?? []), ...fileDirs], { ...(o.projectDirsOver !== undefined && o.projectDirsOver !== false ? { over: overOf(o.projectDirsOver) } : {}) });
  const prev = (await app.state.get("peers"))?.[sessKey(app.userId, sid)];
  const before = (await app.state.get("sessions"))?.[sid];
  const warnings: string[] = [];
  // The loaded extensions' state kinds are advertised as `<kind>.v1` (after the caller's own caps).
  // receipts.v1 is the caller's to claim (it reports the outcomes), and this user's to turn off.
  const asked = (o.caps ?? []).filter((c) => c !== STATUS_CAP_RECEIPTS || receiptsEnabled(app.env, app.home));
  const caps = [...asked, ...stateKindCaps(app.extensions).filter((c) => !asked.includes(c))];
  const status = buildStatus({ ...o, caps, emitCaps: o.emitCaps ?? statusCapsEnabled(app.env, app.home) }, prev?.status, warnings);
  // Handle what's queued first (cap grants, roster and circle changes decide who gets this), then
  // read the roster: a circle join approved in that drain makes a default roster the circle's now.
  await app.connectAndDrain();
  const sess = await noteOpenCircle(app, await getSession(app, sid, warnings), warnings);
  const audience = await rosterAudience(app, sess);
  // Narrowed since the last status: whoever could see it and no longer can gets one blank,
  // private status under the roster they hold, so its last real one doesn't linger in their list.
  if (before && before.jws !== sess.jws) {
    // Never silently: whoever didn't get the blank status still lists the last real one until it expires.
    for (const miss of await retract(app, sid, before, audience)) {
      warnings.push(`the blank private status didn't reach ${miss.address} (${miss.error}): they still see its last status until it is no longer live`);
    }
  }
  if (audience.length === 0) {
    // Nobody but this user's own devices sees it: no summary goes out (the front end skips making one).
    delete status.summary;
    delete status.summaryAt;
    const notice = await defaultCircleNotice(app, sid);
    if (notice) warnings.push(notice);
  }
  const peers = (await app.state.get("peers")) ?? {};
  const lite = statusWithoutAgents(status);
  const delivered: StatusResult["delivered"] = [];
  const failed: StatusResult["failed"] = [];
  // Every recipient at once (a few at a time), not one after another: each delivery is its own
  // identity refresh and round trip. Results keep the audience's order.
  const outcomes = await mapLimit([...audience, app.userId], STATUS_FANOUT, async (u) => {
    if (u === app.userId) {
      const v = await app.view(app.userId);
      if (!v || !v.devices.some((d) => d !== app.did)) return undefined;
    }
    const agents = status.agents !== undefined && understandsAgents(peers, u, { userId: app.userId, did: app.did });
    try {
      const d = await app.deliver(u, "status", { own: app.userId, sid }, { status: agents ? status : lite, roster: sess.jws });
      if (d.relays.length > 0) return { ok: { ...d, address: await app.addressOf(u), agents } };
      return { failed: { userId: u, address: await app.addressOf(u), error: "delivered via 0 relays" } };
    } catch (e) {
      return { failed: { userId: u, address: await app.addressOf(u), error: (e as Error).message } };
    }
  });
  for (const o of outcomes) {
    if (o?.ok) delivered.push(o.ok);
    else if (o?.failed) failed.push(o.failed);
  }
  // This device keeps the full status: its own `ls` and ExtContext.ownStatus see the agents.
  const rec: PeerStatusRec = { own: app.userId, sid, did: app.did, ts: Date.now(), status, self: true };
  await app.state.update("peers", (cur = {}) => ({ next: { ...cur, [sessKey(app.userId, sid)]: rec }, result: undefined }));
  // Another session here asked to hear when this one next goes idle (`send --notify-when-idle` to a
  // session on this device): its statuses never come back here as envelopes, so it is noticed here.
  if (status.state === "idle" && prev?.status.state === "busy") await localIdle(app, sid, rec.ts);
  // `bound`: the folders the front end passed are bound for good (it can stop sending them).
  return { status, roster: await rosterView(app, sess), delivered, failed, ...(warnings.length > 0 ? { warnings } : {}), project: await sessionProjectView(app, sid), bound: true };
}

/**
 * The blank status a narrowed session leaves with those it no longer reaches (under their roster).
 * Returns whom it didn't reach (an error, or no relay took it), for the caller to say so.
 */
async function retract(app: App, sid: string, before: SessionDoc, now: readonly string[]): Promise<{ userId: string; address: string; error: string }[]> {
  const gone = (await rosterAudience(app, before)).filter((u) => !now.includes(u));
  const out = await mapLimit(gone, STATUS_FANOUT, async (u) => {
    let error: string | undefined;
    try {
      const d = await app.deliver(u, "status", { own: app.userId, sid }, { status: { state: "idle", label: "private" }, roster: before.jws });
      if (d.relays.length === 0) error = `delivered via 0 relays${d.errors?.length ? ` (${[...new Set(d.errors.map((e) => e.code))].join(", ")})` : ""}`;
    } catch (e) {
      error = (e as Error).message;
    }
    return error === undefined ? undefined : { userId: u, address: await app.addressOf(u).catch(() => u), error };
  });
  return out.filter((x): x is { userId: string; address: string; error: string } => x !== undefined);
}

// ---------------------------------------------------------------------------
// ls

export interface PeerRow {
  own: string;
  sid: string;
  ref: string;
  address: string;
  self: boolean;
  thisDevice: boolean;
  live: boolean;
  ageSec: number;
  state: "busy" | "idle";
  label: string;
  repo?: string;
  branch?: string;
  mode?: string;
  summary?: string;
  summaryAt?: number;
  files: string[];
  /** What the session's client understands (§4.3 "Status caps"); absent from older clients. */
  caps?: string[];
  /** The device it runs on, and its client's protocol minor (docs/compatibility.md; from its caps). */
  did?: string;
  proto?: number;
  /** Its subagents (§4.3 "Status agents"), validated; only from a session that sent them to this user. */
  agents?: StatusAgent[];
  /** Its extension state (§4.3 "Extension state kinds"): a bounded summary (kind, times, fallback, size), never a body. */
  xstate?: StateSummary[];
  /** How this user is authorised for the session (§4.2): "owner" for our own sessions. */
  rule?: string;
  viewerRule?: string;
  /** How the session's sender was authorised (the owner, for statuses). */
  senderRule?: string;
  /** The circle that gives standing, when the session is shared through one. */
  circle?: string;
}

export async function listPeers(app: App, opts: { all?: boolean } = {}): Promise<PeerRow[]> {
  const peers = (await app.state.get("peers")) ?? {};
  const now = Date.now();
  const blocks = new Set((await app.store.listBlocks()).map((b) => b.userId));
  const states = await liveStates(app, {}, now);
  const rows: PeerRow[] = [];
  for (const p of Object.values(peers)) {
    if (blocks.has(p.own)) continue;
    const live = isLive(p.ts, now);
    if (!live && !opts.all) continue;
    const d = displayStatus(p.status);
    const rosterCircle = await rosterCircleOf(app, p.own, p.sid);
    const viewerRule = p.own === app.userId ? "owner" : p.viewerRule;
    const viaCircle = viewerRule === "circle" || viewerRule === "participant-circle";
    rows.push({
      own: p.own,
      sid: p.sid,
      ref: sessionRef(p.own, p.sid),
      address: await app.addressOf(p.own),
      self: p.own === app.userId,
      thisDevice: p.own === app.userId && p.did === app.did,
      live,
      ageSec: Math.max(0, Math.round((now - p.ts) / 1000)),
      ...d,
      did: p.did,
      ...(d.caps ? { proto: protoMinor(d.caps) } : {}),
      ...(live ? stateOf(states, p.own, p.sid) : {}),
      ...(viewerRule ? { rule: viewerRule, viewerRule } : {}),
      ...(p.rule ? { senderRule: p.rule } : {}),
      ...(viaCircle && rosterCircle ? { circle: rosterCircle } : p.own === app.userId && rosterCircle ? { circle: rosterCircle } : {}),
    });
  }
  return rows.sort((a, b) => Number(b.self) - Number(a.self) || a.address.localeCompare(b.address) || b.ageSec - a.ageSec);
}

function stateOf(states: Parameters<typeof stateSummaries>[0], own: string, sid: string): { xstate?: StateSummary[] } {
  const mine = states.filter((x) => x.own === own && x.sid === sid);
  return mine.length > 0 ? { xstate: stateSummaries(mine) } : {};
}

/** The `circle` a session's held roster names, if any. */
async function rosterCircleOf(app: App, own: string, sid: string): Promise<string | undefined> {
  const r = own === app.userId ? (await app.state.get("sessions"))?.[sid] : await app.store.getRoster(own, sid);
  if (!r) return undefined;
  if ("circle" in r && typeof r.circle === "string") return r.circle;
  try {
    const c = JSON.parse(Buffer.from(r.jws.split(".")[1], "base64url").toString()).circle;
    return typeof c === "string" ? c : undefined;
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// send

export interface SendOpts {
  fromSession: string;
  to: string;
  text: string;
  notifyWhenIdle?: boolean;
  /** Directories the sending session works in besides its working directory (see StatusOpts.projectDirs). */
  projectDirs?: string[];
  /** See StatusOpts.projectDirsOver. */
  projectDirsOver?: boolean | string[];
  /**
   * The person at their own terminal (`p2p send` typed with no --from-session, `p2p tui`): their
   * session is theirs, never bound to a project. Set only by those two paths, never from a flag.
   */
  person?: boolean;
}

export interface SendResult {
  delivered: boolean;
  to: { userId: string; address: string; own: string; sid: string; ref: string };
  relays: number;
  devices: number;
  messageId?: string;
  notifyWhenIdle?: boolean;
  /**
   * Held for later delivery instead of reaching a live session. `state`: "offline" when the
   * relays took it for a session that isn't live (it gets it when it reconnects; `lastSeen` is
   * when its last status was, which the sender's `ls` shows anyway), "outbox" when no relay took
   * it and this device keeps it (outbox.ts) until one does. Either way it expires at `expiresAt`.
   */
  queued?: true;
  state?: "offline" | "outbox";
  lastSeen?: number;
  expiresAt?: number;
  /**
   * Delivery receipts (§4.3): "requested" when the session advertises receipts.v1 and the message
   * asked for them (`receiptId` names it in the `p2p.receipt` events that come back); "unsupported"
   * when it doesn't (an older client, or one with receipts off: the two look the same).
   */
  receipts?: "requested" | "unsupported";
  receiptId?: string;
  /** The folders it was given are bound for good (see StatusResult.bound). */
  bound?: true;
}

/** `user`, `user [ref]`, `user/ref` or `user/sid`. */
export function parseTarget(to: string): { user: string; pick?: string } {
  const s = to.trim();
  const br = /^(.*?)\s*\[([0-9a-f]{6})\]$/.exec(s);
  if (br) return { user: br[1].trim(), pick: br[2] };
  // userIds, addresses and petnames never contain "/", so the last one separates a session.
  const i = s.lastIndexOf("/");
  if (i > 0 && i < s.length - 1) return { user: s.slice(0, i), pick: s.slice(i + 1) };
  return { user: s };
}

interface ResolvedTarget {
  userId: string;
  target: { own: string; sid: string; did?: string };
  to: SendResult["to"];
  /** The session isn't live (no status within STATUS_LIVE_MS) but was seen within OFFLINE_TARGET_MS: when. */
  offlineSince?: number;
}

/**
 * How recently a session must have been seen (its last status) for a message to be held for it
 * while it is offline. Relays keep an envelope for 7 days, and a recipient accepts one whose ts is
 * at most 7 days old; but a session silent for a day has most likely ended (`/exit`, `/clear`),
 * and a message for it would only reach its user as an unclaimed notice. A day covers a laptop
 * asleep overnight or a dropped connection, which is what this is for; older sessions are
 * refused as before (not_found), so a sender never queues into one long gone.
 */
export const OFFLINE_TARGET_MS = 24 * 3600 * 1000;

/**
 * Where a message to `toArg` goes: one of their live sessions, or our own
 * session `fromSession` when its roster lets them in (see the header).
 *
 * Our own sessions on this device are reached only by name (`<you> [ref]`, `<you>/<sid>`), never
 * by a bare `--to <you>`, and never `fromSession` itself (`self_send`). The message is sealed to
 * this device and goes through a relay like one to our other devices, so the receive side applies
 * the same checks: signature, replay, the receiving session's roster and project bound.
 */
async function resolveTarget(app: App, fromSession: string, toArg: string): Promise<ResolvedTarget> {
  const { user, pick } = parseTarget(toArg);
  const userId = await app.resolveUser(user);
  if (await app.store.isBlocked(userId)) throw new CliError("blocked", "you blocked that user");
  // A session never messages itself (a loop with nothing in between): refused, never "not found".
  if (userId === app.userId && pick !== undefined && (pick === fromSession || pick === sessionRef(app.userId, fromSession))) {
    throw new CliError("self_send", `that is session ${fromSession} itself: a session can't send to itself`, { delivered: false });
  }
  const peers = (await app.state.get("peers")) ?? {};
  const now = Date.now();
  // Our own sessions on this device are candidates only when one is named (`[ref]` or `/sid`): a bare
  // `--to <you>` still means your other devices' sessions, never every session here at once.
  const eligible = (p: PeerStatusRec) =>
    p.own === userId && !(p.own === app.userId && (p.sid === fromSession || (p.did === app.did && pick === undefined))) && (!pick || p.sid === pick || sessionRef(p.own, p.sid) === pick);
  const live = Object.values(peers).filter((p) => eligible(p) && isLive(p.ts, now));
  let target: { own: string; sid: string; did?: string };
  let offlineSince: number | undefined;
  // Not live now, but seen recently (a dropped connection, a laptop asleep): the same sessions a
  // live one would be picked from, by the same rules, only within OFFLINE_TARGET_MS.
  const recent =
    live.length > 0
      ? []
      : Object.values(peers)
          .filter((p) => eligible(p) && now - p.ts <= OFFLINE_TARGET_MS)
          .sort((a, b) => b.ts - a.ts);
  if (live.length === 1) target = { own: userId, sid: live[0].sid, did: live[0].did };
  else if (live.length === 0 && recent.length === 1) {
    target = { own: userId, sid: recent[0].sid, did: recent[0].did };
    offlineSince = recent[0].ts;
  } else if (live.length === 0 && recent.length > 1) {
    throw new CliError("ambiguous", `${await app.addressOf(userId)} has no live session and ${recent.length} seen recently: pick one with "<user> [ref]"`, {
      delivered: false,
      candidates: await Promise.all(
        recent.map(async (p) => ({ address: await app.addressOf(p.own), sid: p.sid, ref: sessionRef(p.own, p.sid), label: sanitizePeerText(p.status.label, 64), state: "offline", lastSeen: p.ts })),
      ),
    });
  } else if (live.length > 1) {
    throw new CliError("ambiguous", `${await app.addressOf(userId)} has ${live.length} live sessions: pick one with "<user> [ref]"`, {
      delivered: false,
      candidates: await Promise.all(live.map(async (p) => ({ address: await app.addressOf(p.own), sid: p.sid, ref: sessionRef(p.own, p.sid), label: sanitizePeerText(p.status.label, 64) }))),
    });
  } else if (pick) {
    throw new CliError("not_found", `no live session ${pick} of ${await app.addressOf(userId)}`, { delivered: false });
  } else {
    // No live session of theirs: into our own session, if its roster lets them in.
    const sess = await getSession(app, fromSession);
    if (userId !== app.userId && !(await rosterAudience(app, sess)).includes(userId)) {
      throw new CliError(
        "not_shared",
        `${await app.addressOf(userId)} has no live session you can see, and your session ${fromSession} isn't shared with them: \`p2p session roster ${fromSession} --add ${user}\``,
        { delivered: false },
      );
    }
    target = { own: app.userId, sid: fromSession };
  }
  const ref = sessionRef(target.own, target.sid);
  return { userId, target, to: { userId, address: await app.addressOf(userId), own: target.own, sid: target.sid, ref }, ...(offlineSince !== undefined ? { offlineSince } : {}) };
}

/** The roster JWS that rides with a message into (own, sid). */
async function rosterFor(app: App, target: { own: string; sid: string; did?: string }): Promise<string | undefined> {
  // One of ours on another device: its roster as held (that device signs it, never this one).
  const here = target.own === app.userId && (target.did === undefined || target.did === app.did);
  return here ? (await getSession(app, target.sid)).jws : (await app.store.getRoster(target.own, target.sid))?.jws;
}

/** How long a same-device send's record (Docs.localSends) is kept: as long as a relay keeps the envelope. */
export const LOCAL_SEND_TTL_MS = 7 * 86_400_000 + 600_000;
/** At most this many same-device send records; the oldest go first. */
export const LOCAL_SENDS_MAX = 4096;

/**
 * For a message to another session on this device: before the copy goes out, this device notes which
 * session sent it and whether the person did (Docs.localSends). Local only: nothing changes on the
 * wire, and the receive side (this same device) reads it by the envelope's (sid, seq).
 */
function localSend(app: App, target: { own: string; sid: string; did?: string }, fromSession: string, person: boolean): { beforeSend?: (copies: { did: string; seq: number }[]) => Promise<void> } {
  if (target.own !== app.userId || target.did !== app.did) return {};
  const via: LocalSend["via"] = person || fromSession === PERSON_SESSION ? "person" : "agent";
  return {
    beforeSend: async (copies) => {
      const now = Date.now();
      await app.state.update("localSends", (cur = {}) => {
        const kept = Object.entries(cur).filter(([, v]) => now - v.at < LOCAL_SEND_TTL_MS);
        for (const c of copies) if (c.did === app.did) kept.push([`${target.sid}|${c.seq}`, { from: fromSession, via, at: now }]);
        return { next: Object.fromEntries(kept.sort((a, b) => a[1].at - b[1].at).slice(-LOCAL_SENDS_MAX)), result: undefined };
      });
    },
  };
}

/**
 * What an own-session message's event says about where it came from (sessions on this device only):
 * `via` "person" for the person's own terminal session, else "agent" (also for every other device
 * of yours, which this device can't tell apart: fail closed); `fromRef` names the sending session
 * here. Whether `p2p own-agents` lets it through is never stamped here: the front end asks at
 * delivery time (`p2p own-agents check <did>`).
 */
async function ownOrigin(app: App, e: { fdid: string; sid: string; seq: number }): Promise<Record<string, unknown>> {
  const local = e.fdid === app.did ? (await app.state.get("localSends"))?.[`${e.sid}|${e.seq}`] : undefined;
  return { via: local?.via ?? "agent", ...(local ? { fromRef: sessionRef(app.userId, local.from) } : {}) };
}

/** How long after a bounded session's text reached `tui` a send from there to someone else is warned about. */
export const TUI_TAINT_MS = 24 * 3600 * 1000;

/**
 * A warning (never a refusal) for the person sending from their own session `tui` to someone else
 * after a message from a bounded session of theirs reached it: they may be passing its text on.
 */
export async function tuiTaintNote(app: App, toUserId: string, now = Date.now()): Promise<string | undefined> {
  if (toUserId === app.userId) return undefined;
  const t = await app.state.get("tuiTaint");
  if (!t || now - t.at > TUI_TAINT_MS) return undefined;
  return `a ${t.bound === "private" ? "private" : "project-bounded"} session of yours sent text to this terminal session lately: check you aren't passing it on`;
}

/**
 * A send by a person at a terminal (the `tui` session: `p2p send` with no --from-session, or `p2p tui`):
 * a recipient who isn't in the session's audience is added to its roster first, so the message can
 * land there and their replies reach it, and the add is undone if the send fails. `shared` names whom
 * it shared with. Never used for --from-session or off a terminal: there a missing share is refused.
 */
export async function sendSharing(app: App, o: SendOpts): Promise<{ result: SendResult; shared?: { userId: string; address: string } }> {
  const sid = checkSid(o.fromSession, "--from-session");
  const uid = await app.resolveUser(o.to.replace(/\s*\[[^\]]*\]\s*$/, "").replace(/\/[^/]*$/, ""));
  let added = false;
  if (uid !== app.userId && !(await rosterAudience(app, await getSession(app, sid))).includes(uid)) {
    await roster(app, sid, { add: [uid] });
    added = true;
  }
  try {
    const result = await sendMessage(app, { ...o, person: true });
    return added ? { result, shared: { userId: uid, address: await app.addressOf(uid) } } : { result };
  } catch (e) {
    // Nothing was sent: the session goes back to whom it was shared with before.
    if (added) await roster(app, sid, { remove: [uid] }).catch(() => undefined);
    throw e;
  }
}

export async function sendMessage(app: App, o: SendOpts): Promise<SendResult> {
  const fromSession = checkSid(o.fromSession, "--from-session");
  if (Buffer.byteLength(o.text, "utf8") > MAX_TEXT_BYTES) throw new CliError("too_large", `message text is at most ${MAX_TEXT_BYTES} bytes`);
  if (o.text === "" && !o.notifyWhenIdle) throw new CliError("usage", "nothing to send (give text, or --notify-when-idle)");
  // Bound before anything is read or sent: the project ceiling decides who this may reach.
  await bindFromEnv(app, fromSession, o.projectDirs ?? [], { person: o.person === true, ...(o.projectDirsOver !== undefined && o.projectDirsOver !== false ? { over: overOf(o.projectDirsOver) } : {}) });
  // This device can't reach any of its relays: the message can still be sealed and kept in the
  // outbox (outbox.ts) for `watch` to send once it can.
  let offline = false;
  await app.connectAndDrain().catch((e) => {
    if (e instanceof CliError && e.code === "no_relay") offline = true;
    else throw e;
  });
  const { userId, target, to, offlineSince } = await resolveTarget(app, fromSession, o.to);
  // The exfiltration barrier (projects.ts): nothing from this session to anyone its projects don't share.
  if (o.text !== "") await assertMayReach(app, fromSession, userId, { person: o.person === true, address: to.address });
  let d: Delivery | undefined;
  let outboxed: { expiresAt: number } | undefined;
  // Receipts only from a session whose live status says it sends them: an older client rejects the
  // whole message for `rcpt` (§4.3). Not when this device can't reach a relay either: the sealed copy
  // may wait in the outbox for days, long past the status that advertised it (pre-release review R2).
  const rcpt = o.text !== "" && !offline && offlineSince === undefined && (await asksReceipts(app, target.own, target.sid)) ? newReceiptId() : undefined;
  if (o.text !== "") {
    // Anything this device couldn't send earlier goes first (order, and it may be the same peer).
    if (!offline) await flushOutbox(app).catch(() => undefined);
    const rosterJws = await rosterFor(app, target);
    const plaintext = { text: o.text, ...(rcpt ? { rcpt } : {}), ...(rosterJws ? { roster: rosterJws } : {}), ...(o.person ? {} : await ownBound(app, fromSession, target, userId)) };
    if (rcpt) await rememberWanted(app, rcpt, { to: userId, own: target.own, ref: to.ref, fromSession });
    d = await app.deliver(userId, "msg", target, plaintext, userId === app.userId && target.did ? { onlyDevices: [target.did], ...localSend(app, target, fromSession, o.person === true) } : {});
    const unsent = d.unsent ?? [];
    if (d.relays.length === 0 && !retryable(unsent)) {
      throw new CliError("undelivered", `delivered via 0 relays${d.errors?.length ? ` (${[...new Set(d.errors.map((e) => e.code))].join(", ")})` : ""}`, { delivered: false, to });
    }
    // Copies no relay took, for reasons a retry gets past: kept, sealed, for watch to send. When
    // other copies did go out the message is delivered already; these reach the other devices.
    const later = d.relays.length === 0 ? unsent : unsent.filter((u) => u.codes.every((c) => OUTBOX_RETRYABLE.has(c)));
    if (later.length > 0) outboxed = await enqueue(app, later, { kind: "msg", dest: to, fromSession });
  }
  if (target.own !== app.userId) {
    await app.state.update("spoke", (cur = {}) => ({ next: { ...cur, [sessKey(target.own, target.sid)]: fromSession }, result: undefined }));
  }
  if (o.notifyWhenIdle) {
    const sub: IdleSub = { own: target.own, sid: target.sid, toSession: fromSession, at: Date.now() };
    await app.state.update("subs", (cur = []) => ({ next: [...cur.filter((s) => !(s.own === sub.own && s.sid === sub.sid && s.toSession === sub.toSession)), sub], result: undefined }));
  }
  const relays = d?.relays.length ?? 0;
  const queued =
    d && relays === 0 && outboxed
      ? { queued: true as const, state: "outbox" as const, expiresAt: outboxed.expiresAt, ...(offlineSince !== undefined ? { lastSeen: offlineSince } : {}) }
      : d && offlineSince !== undefined
        ? { queued: true as const, state: "offline" as const, lastSeen: offlineSince, expiresAt: Date.now() + OUTBOX_TTL_MS }
        : {};
  // Message history (history.ts): what this session sent, kept on this device only.
  if (d) await recordSent(app, { fromSession, to, text: o.text, state: "state" in queued ? queued.state : "sent" });
  return {
    ...(o.person ? {} : { bound: true as const }),
    // Accepted by a relay (it stores ciphertext for its session for 7 days), or not yet.
    delivered: d !== undefined && relays > 0,
    to,
    relays,
    devices: d?.devices ?? 0,
    ...(d ? { messageId: `m${Date.now().toString(36)}` } : {}),
    ...(o.notifyWhenIdle ? { notifyWhenIdle: true } : {}),
    ...queued,
    ...(d ? (rcpt ? { receipts: "requested" as const, receiptId: rcpt } : { receipts: "unsupported" as const }) : {}),
  };
}

// ---------------------------------------------------------------------------
// Extension kinds (§4.3 `x:<ns>.<type>`), sent for an extension (extensions.ts)

export interface SendExtOpts {
  fromSession: string;
  to: string;
  kind: string;
  v: number;
  body: unknown;
  fallback: string;
  /** Directories the sending session works in besides its working directory (see StatusOpts.projectDirs). */
  projectDirs?: string[];
}

/**
 * The budget for `{v, body}`: the same as a message's text, which leaves room in the 64 KiB
 * envelope (§4.1) for the roster, the certificate and two layers of base64.
 */
export const MAX_EXT_PLAINTEXT_BYTES = MAX_TEXT_BYTES;

export async function sendExtension(app: App, o: SendExtOpts): Promise<ExtSendResult> {
  const fromSession = checkSid(o.fromSession, "--from-session");
  if (!isExtensionKind(o.kind)) throw new CliError("usage", `${o.kind} is not an extension kind (x:<ns>.<type>)`);
  if (!Number.isSafeInteger(o.v) || o.v < 0) throw new CliError("usage", "ext.v must be a non-negative integer");
  if (typeof o.fallback !== "string" || o.fallback.trim() === "" || [...o.fallback].length > FALLBACK_MAX) {
    throw new CliError("usage", `an extension kind needs a plain-text fallback of 1-${FALLBACK_MAX} characters (§8.1)`);
  }
  const ext = { v: o.v, body: o.body };
  const bytes = Buffer.byteLength(JSON.stringify(ext) ?? "", "utf8");
  if (bytes > MAX_EXT_PLAINTEXT_BYTES) throw new CliError("too_large", `the extension body is ${bytes} bytes; at most ${MAX_EXT_PLAINTEXT_BYTES}`);
  await bindFromEnv(app, fromSession, o.projectDirs ?? []);
  await app.connectAndDrain();
  const { userId, target, to } = await resolveTarget(app, fromSession, o.to);
  await assertMayReach(app, fromSession, userId, { address: to.address });
  const rosterJws = await rosterFor(app, target);
  const plaintext = { ext, fallback: o.fallback, ...(rosterJws ? { roster: rosterJws } : {}), ...(await ownBound(app, fromSession, target, userId)) };
  const d = await app.deliver(userId, o.kind as ExtensionKind, target, plaintext, userId === app.userId && target.did ? { onlyDevices: [target.did], ...localSend(app, target, fromSession, false) } : {});
  if (d.relays.length === 0) {
    throw new CliError("undelivered", `delivered via 0 relays${d.errors?.length ? ` (${[...new Set(d.errors.map((e) => e.code))].join(", ")})` : ""}`, { delivered: false, to });
  }
  if (target.own !== app.userId) {
    await app.state.update("spoke", (cur = {}) => ({ next: { ...cur, [sessKey(target.own, target.sid)]: fromSession }, result: undefined }));
  }
  // Message history: an extension kind as its one-line fallback, never its body.
  await recordSent(app, { fromSession, to, text: o.fallback, ext: o.kind });
  return { delivered: true, to, relays: d.relays.length, devices: d.devices, kind: o.kind, bytes, bound: true };
}

// ---------------------------------------------------------------------------
// Inbound session kinds

export async function onSessionEnvelope(app: App, env: string, r: AcceptedMessageV3): Promise<NewEvent[]> {
  const accepted = r;
  const e = r.envelope;
  const from = await fromOf(app, r);
  const ref = sessionRef(e.own, e.sid);
  const spoke = (await app.state.get("spoke")) ?? {};
  let toSession: string | undefined = e.own === app.userId ? e.sid : spoke[sessKey(e.own, e.sid)];
  const pt = r.plaintext;
  // A reply into a session of ours that spoke to theirs: only while that session may still reach
  // the sender (projects.ts). Otherwise it is a message to this user, routed by `routable` below.
  const carries = pt.kind === "msg" || ("ext" in pt && !isStateEnvelope(app.extensions, pt));
  if (carries && toSession !== undefined && e.own !== app.userId && !from.self && !(await mayReach(app, toSession, e.from))) toSession = undefined;
  // Into a session of ours from someone its projects don't reach: dropped here, whatever roster came
  // with it (one signed by another device of ours, an older client's, can't widen this one's).
  if (carries && e.own === app.userId && !from.self && !(await mayReach(app, e.sid, e.from))) return [];
  // From another session of ours: whatever bounded it now bounds the session it went into.
  const bound = (pt as { bound?: ProjectBound }).bound;
  if (carries && from.self && bound !== undefined && toSession !== undefined && toSession !== PERSON_SESSION) {
    await bindSession(app, toSession, [], { constraint: bound, inbound: true });
  }
  // The person's own session is never bound: it only remembers that a bounded session's text reached it,
  // so `p2p tui` can warn before the person passes it on.
  if (carries && from.self && bound !== undefined && toSession === PERSON_SESSION) {
    await app.state.update("tuiTaint", () => ({ next: { at: Date.now(), bound: bound === "private" ? ("private" as const) : ("shared" as const) }, result: undefined }));
  }
  const origin = carries && from.self ? await ownOrigin(app, e) : {};
  const sess = { own: e.own, sid: e.sid, ref, rule: r.rule, ...(r.viewerRule ? { viewerRule: r.viewerRule } : {}) };
  const extra = { own: e.own, sid: e.sid, ...(toSession ? { toSession } : {}) };
  // Named for no session of ours: which local sessions may hold it (watch shows it only to those).
  const routable = carries && toSession === undefined && !from.self ? { routable: await routableSessions(app, e.from) } : {};
  switch (pt.kind) {
    case "msg": {
      // §4.3 "Delivery receipts": the sender asked. Remembered for `p2p receipt` (receipts.ts), which
      // decides what goes back; the event says only that one may (`receipt: true`), never the id.
      const asks = typeof pt.rcpt === "string" && receiptsEnabled(app.env, app.home);
      const main = makeEvent(env, "p2p.message", e.ts, { from, ...sess, ...origin, text: pt.text, ...(asks ? { receipt: true } : {}), ...routable }, extra);
      const out = [main];
      if (asks) await rememberAsked(app, main.id, { id: pt.rcpt!, from: e.from, did: e.fdid, ...(toSession !== undefined ? { toSession } : {}) });
      // For a session of this device that has ended (its watch stopped: /exit, or replaced after
      // /clear): also logged as a message for no session, so the user's current session holds it
      // for Deliver (the mod's rule for those) instead of it waiting for a session that won't come
      // back. Same sender, same text, same hold and screen rules; if the session does resume, it
      // still gets the message itself (and this copy isn't shown there).
      if (toSession !== undefined && sessionEnded(app, toSession)) {
        // From another session of ours with a bound: only sessions already within it may hold it, and the
        // one that does takes the bound on (the front end binds it on Deliver: `bound` rides with it).
        const held = from.self ? (bound !== undefined ? { routable: await sessionsWithin(app, bound), bound } : {}) : { routable: await routableSessions(app, e.from) };
        const copy = makeEvent(env, "p2p.message", e.ts, { from, ...sess, ...origin, text: pt.text, unclaimedFor: toSession, ...(asks ? { receipt: true } : {}), ...held }, {}, "unclaimed");
        out.push(copy);
        if (asks) await rememberAsked(app, copy.id, { id: pt.rcpt!, from: e.from, did: e.fdid, unclaimedFor: toSession });
      }
      return out;
    }
    case "idle": {
      const reason = pt.reason === "exited" ? "exited" : "idle";
      const subs = await takeSubs(app, e.own, e.sid);
      const out = [makeEvent(env, "p2p.idle", e.ts, { from, ...sess, reason }, extra)];
      for (const s of subs) out.push(makeEvent(env, "p2p.idle", e.ts, { from, ...sess, reason }, { own: e.own, sid: e.sid, toSession: s.toSession }, s.toSession));
      return out;
    }
    case "status": {
      const key = sessKey(e.own, e.sid);
      const prev = await app.state.update("peers", (cur = {}) => {
        const old = cur[key];
        if (old && old.ts >= e.ts) return { result: { old, newer: false } };
        const rec: PeerStatusRec = { own: e.own, sid: e.sid, did: e.fdid, ts: e.ts, status: pt.status, rule: r.rule, ...(r.viewerRule ? { viewerRule: r.viewerRule } : {}), ...(e.own === app.userId ? { self: true } : {}) };
        return { next: { ...cur, [key]: rec }, result: { old, newer: true } };
      });
      if (!prev.newer) return [];
      const out = [makeEvent(env, "p2p.status", e.ts, { from, ...sess, status: displayStatus(pt.status), live: isLive(e.ts, Date.now()) }, extra)];
      if (pt.status.state === "idle" && prev.old?.status.state === "busy") {
        for (const s of await takeSubs(app, e.own, e.sid)) {
          out.push(makeEvent(env, "p2p.idle", e.ts, { from, ...sess, reason: "idle" }, { own: e.own, sid: e.sid, toSession: s.toSession }, s.toSession));
        }
      }
      return out;
    }
    case "roster":
      return [makeEvent(env, "p2p.roster", e.ts, { from, ...sess }, extra)];
    default: {
      if ("ext" in pt) {
        // A state kind (§4.3 "Extension state kinds") is stored latest-wins, and is never an event:
        // not logged, not printed by watch, never toasted or shown to a model.
        if (isStateEnvelope(app.extensions, pt)) {
          await onStateEnvelope(app, accepted, pt, from);
          return [];
        }
        const fallback = extensionFallbackText(from.address, pt.fallback);
        // §4.3: the extension, when installed, validates and renders; it never acts. Without one,
        // the body is never interpreted (nor kept) and the fallback stands.
        const r = renderExtension(app.extensions, {
          kind: pt.kind,
          v: pt.ext.v,
          body: pt.ext.body,
          fallback,
          from: { userId: from.userId, address: from.address, self: from.self },
          session: { own: e.own, sid: e.sid, ref },
        });
        const data: Record<string, unknown> = { from, ...sess, ...origin, ext: pt.kind, fallback, ...routable };
        if (r.rendered) data.rendered = r.rendered;
        if (r.extError) data.extError = r.extError;
        // Underscore fields stay in the local log for user-initiated actions; `watch` never prints them.
        if (r.kept) data._kept = r.kept;
        return [makeEvent(env, "p2p.ext", e.ts, data, extra)];
      }
      return [];
    }
  }
}

/**
 * Binds `sid` to the folders its front end reports (projects.ts sessionDirs: P2P_WORKDIR,
 * P2P_PROJECT_DIRS, past its cap private) and any more the caller names.
 */
export async function bindFromEnv(app: App, sid: string, extra: readonly string[] = [], o: { person?: boolean; over?: OverWhy[] } = {}): Promise<void> {
  const { dirs, why } = sessionDirs(app.env);
  // Past the cap in folders named on the command line too: private, never the first N.
  const over = new Set<OverWhy>([...why, ...(o.over ?? [])]);
  if (extra.length > MAX_SESSION_DIRS) over.add("folders");
  // The session's own scratch, as its front end names it: only a front end holding the person token.
  const scratch = app.front === true ? sessionScratch(app.env[SCRATCH_ENV]) : undefined;
  await bindSession(app, sid, [...dirs, ...extra.slice(0, MAX_SESSION_DIRS)], { ...(o.person ? { person: true } : {}), ...(over.size > 0 ? { over: [...over] } : {}), ...(scratch ? { scratch } : {}) });
}

/** A front end's `--project-dirs-over` as reasons: a bare flag (an older front end) is `front`. */
function overOf(v: boolean | string[]): OverWhy[] {
  const out = v === true ? ["front" as const] : overWhys(Array.isArray(v) ? v.flatMap((x) => String(x).split(",")) : []);
  return out.length > 0 ? out : ["front"];
}

/** Whether a ceiling is within a bound (narrower or equal): private always is. */
function within(c: Ceiling, b: ProjectBound): boolean {
  if (c.kind === "private") return true;
  if (c.kind === "none" || b === "private") return false;
  return c.circles.every((x) => b.circles.includes(x)) && c.people.every((x) => b.people.includes(x));
}

/** This device's live sessions already within a bound (and the person's own terminal session): who may hold an own-session message that carries it. */
export async function sessionsWithin(app: App, b: ProjectBound, now = Date.now()): Promise<string[]> {
  const peers = (await app.state.get("peers")) ?? {};
  const out = new Set<string>([PERSON_SESSION]);
  for (const p of Object.values(peers)) {
    if (p.own !== app.userId || p.did !== app.did || !isLive(p.ts, now) || out.has(p.sid)) continue;
    if (within(await sessionCeiling(app, p.sid), b)) out.add(p.sid);
  }
  return [...out].sort();
}

/** `p2p session bound`: a front end binds the session that took an own-session message to that message's bound (sticky). */
export async function bindBound(app: App, sid: string, bound: unknown): Promise<SessionProjectView> {
  checkSid(sid, "sid");
  let b: ProjectBound;
  try {
    b = parseBound(bound, "bound");
  } catch {
    throw new CliError("usage", 'bound must be "private" or {circles, people}');
  }
  await bindSession(app, sid, [], { constraint: b });
  return sessionProjectView(app, sid);
}

/**
 * What a session of ours may reach, for a message to another session of ours (`bound`, cap
 * projects.v1): undefined when it has no ceiling (the person's own session, one never bound).
 */
async function boundOf(app: App, sid: string): Promise<ProjectBound | undefined> {
  const c = await sessionCeiling(app, sid);
  if (c.kind === "none") return undefined;
  return c.kind === "private" ? "private" : { circles: c.circles, people: c.people };
}

/**
 * A message from a bounded session to another session of ours carries its bound (laundering
 * through your own sessions, projects.ts). One on another device whose client can't honour it
 * (its live status doesn't advertise projects.v1) is refused here; the field is critical, so an
 * older client that gets one anyway rejects it.
 */
async function ownBound(app: App, fromSession: string, target: { own: string; sid: string; did?: string }, userId: string): Promise<Record<string, unknown>> {
  if (userId !== app.userId || target.own !== app.userId) return {};
  const bound = await boundOf(app, fromSession);
  if (bound === undefined) return {};
  if (target.did && target.did !== app.did) {
    const rec = (await app.state.get("peers"))?.[sessKey(target.own, target.sid)];
    const caps = rec ? (displayStatus(rec.status).caps ?? []) : [];
    if (!caps.includes(CAP_PROJECTS)) {
      throw new CliError(
        "not_shared",
        `session ${fromSession} works in a project with limits, and your session ${target.sid} runs on another device whose client doesn't keep project boundaries: update Peer2Peer there first (docs/compatibility.md)`,
        { delivered: false },
      );
    }
  }
  return { bound, crit: ["bound"] };
}

/** Whether a session of ours may reach `user` (projects.ts): the same rule its sends follow. */
export async function mayReach(app: App, sid: string, user: string): Promise<boolean> {
  return assertMayReach(app, sid, user).then(
    () => true,
    () => false,
  );
}

/**
 * The local sessions a message for no session may be held in: this device's live sessions whose
 * projects reach the sender, and the person's own terminal session. Every other session's watch
 * never shows it (watch.ts eventFor), and the mod picks its holder among these.
 */
export async function routableSessions(app: App, sender: string, now = Date.now()): Promise<string[]> {
  const peers = (await app.state.get("peers")) ?? {};
  const out = new Set<string>([PERSON_SESSION]);
  for (const p of Object.values(peers)) {
    if (p.own !== app.userId || p.did !== app.did || !isLive(p.ts, now) || out.has(p.sid)) continue;
    if ((await sessionCeiling(app, p.sid)).kind === "none") continue;
    if (await mayReach(app, p.sid, sender)) out.add(p.sid);
  }
  return [...out].sort();
}

/** `p2p.idle` for the subscriptions of this device's sessions to `sid`, another session on this device. */
async function localIdle(app: App, sid: string, ts: number): Promise<void> {
  const subs = await takeSubs(app, app.userId, sid);
  if (subs.length === 0) return;
  const from = { userId: app.userId, did: app.did, address: await app.addressOf(app.userId), self: true };
  const ref = sessionRef(app.userId, sid);
  await app.state.addEvents(
    subs.map((s) => ({ id: `p2p.idle:local:${sid}:${s.toSession}:${ts}`, at: ts, kind: "p2p.idle", own: app.userId, sid, toSession: s.toSession, data: { from, own: app.userId, sid, ref, reason: "idle" } })),
  );
}

async function takeSubs(app: App, own: string, sid: string): Promise<IdleSub[]> {
  return app.state.update("subs", (cur = []) => {
    const hit = cur.filter((s) => s.own === own && s.sid === sid);
    return hit.length === 0 ? { result: [] } : { next: cur.filter((s) => !(s.own === own && s.sid === sid)), result: hit };
  });
}

/** Subscriptions older than an hour end with `p2p.idle {reason: "expired"}` (v1 semantics). */
export async function expireSubs(app: App, now = Date.now()): Promise<void> {
  const gone = await app.state.update("subs", (cur = []) => {
    const old = cur.filter((s) => now - s.at > IDLE_SUB_TTL_MS);
    return old.length === 0 ? { result: [] } : { next: cur.filter((s) => now - s.at <= IDLE_SUB_TTL_MS), result: old };
  });
  const events: NewEvent[] = [];
  for (const s of gone) {
    events.push({
      id: `p2p.idle:exp:${s.own}:${s.sid}:${s.toSession}:${s.at}`,
      at: now,
      kind: "p2p.idle",
      own: s.own,
      sid: s.sid,
      toSession: s.toSession,
      data: { from: { userId: s.own, did: "", address: await app.addressOf(s.own), self: s.own === app.userId }, own: s.own, sid: s.sid, ref: sessionRef(s.own, s.sid), reason: "expired" },
    });
  }
  await app.state.addEvents(events);
}

