// Copyright 2026 Ix Infrastructure Inc.
//
// v3 envelopes (docs/protocol.md §4.1, §4.3): v2's `p2p-msg+jws` with
// `v: 3`, v3 ids, and the `p2p/v3` profile:
//
//   aad  = UTF-8("p2p/v3|" + from + "|" + fdid + "|" + to + "|" + tdid + "|"
//                + own + "|" + sid + "|" + seq + "|" + ts + "|" + kind)
//   info = "p2p/v3/msg|" + fdid + "|" + tdid
//
// sealed with the shared envelope sealing (../envelope.ts sealBox/openBox).
// Outer fields: v, from, fdid, fcert, to, tdid, own, sid, seq, ts, n, epk,
// ct, kind. `ts` is in milliseconds, as in v2.

import { b64uDecode, b64uEncode, fromUtf8, utf8 } from "../encoding.js";
import { XCHACHA_NONCE_LEN } from "../crypto.js";
import { envelopeAad, envelopeKdfInfo, openBox, sealBox, type EnvelopeProfile } from "../envelope.js";
import { decodeJws, signJws, verifyJws, MAX_ENVELOPE_BYTES, MAX_JWS_BYTES, type DecodedJws } from "../jws.js";
import { fail } from "../errors.js";
import { checkFields, isCircleId, isDid, isUserId, TYP3 } from "./base.js";
import { parseRotationStatement, type RotationStatement } from "./identity.js";
import { isSafeRelativePath, PEER_TEXT_CAPS, sanitizeFiles, sanitizePeerText } from "./sanitize.js";

export const ENVELOPE_VERSION_V3 = 3;
export const ENVELOPE_PROFILE_V3: EnvelopeProfile = { aadPrefix: "p2p/v3", kdfInfoPrefix: "p2p/v3/msg" };

/** §4.3: the reserved session ids of the `contact` and `circle` kinds. */
export const CONTACT_SID_V3 = "~contact";
export const CIRCLE_SID = "~circle";
/** §4.3 "Delivery receipts": the reserved session id of the `receipt` kind. */
export const RECEIPT_SID = "~receipt";

/** What became of a message that asked for a receipt (§4.3 "Delivery receipts"). */
export type ReceiptOutcome = "shown" | "held" | "declined" | "expired" | "ended";
export const RECEIPT_OUTCOMES: readonly ReceiptOutcome[] = ["shown", "held", "declined", "expired", "ended"];
/** A message's receipt id (`msg.rcpt`, `receipt.id`): random, chosen by the sender. */
export const RECEIPT_ID_RE = /^[A-Za-z0-9_-]{8,32}$/;
/** The status cap of a client that accepts `msg.rcpt` and sends receipts. */
export const STATUS_CAP_RECEIPTS = "receipts.v1";

export type CoreKindV3 = "msg" | "roster" | "idle" | "status" | "sync" | "unfriend" | "contact" | "circle" | "receipt";
export type ExtensionKind = `x:${string}.${string}`;
export type EnvelopeKindV3 = CoreKindV3 | ExtensionKind;

const CORE_KINDS: readonly CoreKindV3[] = ["msg", "roster", "idle", "status", "sync", "unfriend", "contact", "circle", "receipt"];
const EXT_KIND_RE = /^x:[a-z][a-z0-9]{0,15}\.[a-z][a-z0-9_-]{0,31}$/;

export function isExtensionKind(k: unknown): k is ExtensionKind {
  return typeof k === "string" && EXT_KIND_RE.test(k);
}

export function isKindV3(k: unknown): k is EnvelopeKindV3 {
  return CORE_KINDS.includes(k as CoreKindV3) || isExtensionKind(k);
}

/** Kinds authorised by §4.2 against the (own, sid) roster. */
export function isSessionKind(k: EnvelopeKindV3): boolean {
  return k === "msg" || k === "roster" || k === "idle" || k === "status" || isExtensionKind(k);
}

export interface EnvelopeV3Payload {
  v: 3;
  from: string;
  fdid: string;
  /** The sender device's §2.3 certificate. */
  fcert: string;
  to: string;
  tdid: string;
  own: string;
  sid: string;
  seq: number;
  /** Milliseconds since the epoch. */
  ts: number;
  n: string;
  epk: string;
  ct: string;
  kind: EnvelopeKindV3;
}

export type EnvelopeV3Header = Omit<EnvelopeV3Payload, "v" | "n" | "epk" | "ct">;

export function envelopeAadV3(h: Pick<EnvelopeV3Payload, "from" | "fdid" | "to" | "tdid" | "own" | "sid" | "seq" | "ts" | "kind">): Uint8Array {
  return envelopeAad(h as Parameters<typeof envelopeAad>[0], ENVELOPE_PROFILE_V3);
}

export function envelopeKdfInfoV3(fdid: string, tdid: string): Uint8Array {
  return envelopeKdfInfo(fdid, tdid, ENVELOPE_PROFILE_V3);
}

/** Structural validation of the outer payload (all a relay can check without keys). */
export function validateEnvelopeV3Payload(p: Record<string, unknown>): EnvelopeV3Payload {
  if (p.v !== ENVELOPE_VERSION_V3) fail("malformed", `unsupported envelope v ${JSON.stringify(p.v)}`);
  const allowed = ["v", "from", "fdid", "fcert", "to", "tdid", "own", "sid", "seq", "ts", "n", "epk", "ct", "kind"];
  // An unknown outer field is ignored unless listed in `crit` (protocol.md "Forward compatibility"). It
  // is covered by the signature; it is not in the AAD, so nothing this version reads depends on it.
  checkFields(p, allowed, "envelope");
  for (const k of ["fcert", "sid", "n", "epk", "ct"]) {
    if (typeof p[k] !== "string" || p[k] === "") fail("malformed", `${k} must be a non-empty string`);
  }
  for (const k of ["from", "to", "own"]) if (!isUserId(p[k])) fail("malformed", `${k} must be a v3 userId`);
  if (!isDid(p.fdid) || !isDid(p.tdid)) fail("malformed", "fdid/tdid must be v3 device ids");
  for (const k of ["seq", "ts"]) {
    const v = p[k];
    if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) fail("malformed", `${k} must be an integer`);
  }
  // A kind this version doesn't know (a later core kind, by its name's shape) passes structure: the
  // receiver verifies it like any envelope (signature, sender, replay window), then tells its user
  // once that it can't show it (incoming.ts, rule "unknown-kind"). Anything else is malformed.
  if (!isKindV3(p.kind) && !isFutureKind(p.kind)) fail("malformed", `unknown kind ${JSON.stringify(p.kind)}`);
  // "|" separates AAD fields; ids can't contain it, sid must not.
  if ((p.sid as string).includes("|")) fail("malformed", 'sid must not contain "|"');
  const reserved: Record<string, string> = { contact: CONTACT_SID_V3, circle: CIRCLE_SID, receipt: RECEIPT_SID };
  const want = reserved[p.kind as string];
  if (want !== undefined) {
    if (p.sid !== want) fail("malformed", `kind ${p.kind} requires sid ${want}`);
    if (p.own !== p.from) fail("malformed", `kind ${p.kind} requires own == from`);
  } else if (p.sid === CONTACT_SID_V3 || p.sid === CIRCLE_SID || p.sid === RECEIPT_SID) {
    fail("malformed", `sid ${p.sid} is reserved`);
  }
  b64uDecode(p.n as string, XCHACHA_NONCE_LEN);
  b64uDecode(p.epk as string, 32);
  b64uDecode(p.ct as string);
  // Field by field: an ignored field never travels on with the payload.
  return {
    v: 3,
    from: p.from as string,
    fdid: p.fdid as string,
    fcert: p.fcert as string,
    to: p.to as string,
    tdid: p.tdid as string,
    own: p.own as string,
    sid: p.sid as string,
    seq: p.seq as number,
    ts: p.ts as number,
    n: p.n as string,
    epk: p.epk as string,
    ct: p.ct as string,
    kind: p.kind as EnvelopeKindV3,
  };
}

/** The name of a core kind defined after this version (lowercase, like `msg` or `receipt`). */
const FUTURE_KIND_RE = /^[a-z][a-z0-9_-]{0,31}$/;

/** A kind this version doesn't know, shaped like a core kind: verified, then surfaced as not understood. */
export function isFutureKind(k: unknown): k is string {
  return typeof k === "string" && FUTURE_KIND_RE.test(k) && !isKindV3(k);
}

export interface SealV3Params extends EnvelopeV3Header {
  plaintext: object;
  sender: { signingSecretKey: Uint8Array; agreementSecretKey: Uint8Array };
  /** The recipient device's `kpk` (from its certificate). */
  recipientKpk: Uint8Array;
}

/** Seals and signs a v3 envelope for one recipient device. */
export function sealEnvelopeV3(params: SealV3Params): string {
  const h: EnvelopeV3Header = {
    from: params.from,
    fdid: params.fdid,
    fcert: params.fcert,
    to: params.to,
    tdid: params.tdid,
    own: params.own,
    sid: params.sid,
    seq: params.seq,
    ts: params.ts,
    kind: params.kind,
  };
  const box = sealBox({
    plaintext: utf8(JSON.stringify(params.plaintext)),
    recipientKpk: params.recipientKpk,
    senderAgreementSecretKey: params.sender.agreementSecretKey,
    info: envelopeKdfInfoV3(h.fdid, h.tdid),
    aad: envelopeAadV3(h),
  });
  const payload: EnvelopeV3Payload = {
    v: 3,
    from: h.from,
    fdid: h.fdid,
    fcert: h.fcert,
    to: h.to,
    tdid: h.tdid,
    own: h.own,
    sid: h.sid,
    seq: h.seq,
    ts: h.ts,
    n: b64uEncode(box.n),
    epk: b64uEncode(box.epk),
    ct: b64uEncode(box.ct),
    kind: h.kind,
  };
  validateEnvelopeV3Payload(payload as unknown as Record<string, unknown>);
  const jws = signJws(TYP3.msg, h.fdid, payload, params.sender.signingSecretKey);
  if (jws.length > MAX_ENVELOPE_BYTES) fail("malformed", `envelope is ${jws.length} bytes, max ${MAX_ENVELOPE_BYTES}`);
  return jws;
}

/** Structural decode: size cap, typ, payload shape and kid == fdid. No signature check. */
export function decodeEnvelopeV3(jws: string): DecodedJws<EnvelopeV3Payload> {
  const d = decodeJws(jws, MAX_ENVELOPE_BYTES);
  if (d.header.typ !== TYP3.msg) fail("typ-mismatch", `typ ${d.header.typ} != ${TYP3.msg}`);
  const p = validateEnvelopeV3Payload(d.payload);
  if (d.header.kid !== p.fdid) fail("kid-mismatch", `kid ${d.header.kid} != fdid ${p.fdid}`);
  return { ...d, payload: p };
}

export function verifyEnvelopeV3Signature(jws: string, senderSpk: Uint8Array): DecodedJws<EnvelopeV3Payload> {
  const d = decodeEnvelopeV3(jws);
  verifyJws(jws, { typ: TYP3.msg, kid: d.payload.fdid, publicKey: senderSpk, maxBytes: MAX_ENVELOPE_BYTES });
  return d;
}

/** Decrypts. The caller must already have run the §4.1 receiver checks. */
export function openEnvelopeV3(payload: EnvelopeV3Payload, recipientAgreementSecretKey: Uint8Array, senderKpk: Uint8Array): Uint8Array {
  return openBox({
    box: { n: b64uDecode(payload.n, XCHACHA_NONCE_LEN), epk: b64uDecode(payload.epk, 32), ct: b64uDecode(payload.ct) },
    recipientAgreementSecretKey,
    senderKpk,
    info: envelopeKdfInfoV3(payload.fdid, payload.tdid),
    aad: envelopeAadV3(payload),
  });
}

// ---------------------------------------------------------------------------
// Plaintexts (§4.3)

export interface PresentedFriendship {
  invite: string;
  accept: string;
}

/** Fields any session-kind plaintext may carry besides its own. */
export interface SessionExtras {
  /** The session's roster (the owner's), when the receiver may not hold it. */
  roster?: string;
  /** A friendship proof for the sender's side only (v2 H1). */
  friendship?: PresentedFriendship;
}

export interface StatusBody {
  state: "busy" | "idle";
  label: string;
  repo?: string;
  branch?: string;
  mode?: string;
  summary?: string;
  files?: string[];
  /** When `summary` was written (ms). */
  summaryAt?: number;
  /** What the sending client understands (§4.3 "Status caps"), e.g. `agents.v1`. */
  caps?: string[];
  /** The session's subagents (§4.3 "Status agents"); sent only to sessions whose caps include `agents.v1`. */
  agents?: StatusAgent[];
}

/** One subagent of a session (§4.3 "Status agents", cap `agents.v1`). */
export interface StatusAgent {
  /** Session-local ordinal (`a1`, `a2`, …), never the engine's own agent id. */
  id: string;
  /** The agent that spawned it, by `id`; absent when the session's main loop did. */
  parent?: string;
  /** Its agent type (`Explore`, `general-purpose`, `teammate`, …). */
  type: string;
  /** One line: what it was asked to do (the spawn's short description). */
  task: string;
  state: StatusAgentState;
  /** Repo-relative files it changed (relative to its own worktree when `wt`), most recent first. */
  files?: string[];
  /** Its edits are in its own git worktree, not yet on the session's branch. */
  wt?: true;
  /** That worktree's git branch. */
  branch?: string;
  /** Its last activity (ms). */
  at: number;
}

export type StatusAgentState = "running" | "waiting" | "idle" | "done" | "failed";

export type PlaintextV3 =
  /** `rcpt` (§4.3 "Delivery receipts"): the sender asks for receipts, by this id. */
  | ({ kind: "msg"; text: string; rcpt?: string } & SessionExtras)
  /** §4.3 "Delivery receipts": what became of the sender's message `id`. Never carries text, never receipted. */
  | { kind: "receipt"; receipt: { id: string; outcome: ReceiptOutcome } }
  /**
   * An envelope of a kind this version doesn't know (isFutureKind): verified and opened, never parsed.
   * `envKind` is the kind as sent (its charset is FUTURE_KIND_RE's).
   */
  | { kind: "unknown"; envKind: string }
  | ({ kind: "roster"; roster: string } & Omit<SessionExtras, "roster">)
  | ({ kind: "idle"; reason: string } & SessionExtras)
  | ({ kind: "status"; status: StatusBody } & SessionExtras)
  | ({ kind: ExtensionKind; ext: { v: number; body: unknown }; fallback: string; state?: ExtStateMarker } & SessionExtras)
  | { kind: "sync"; body: Record<string, unknown> }
  | { kind: "unfriend"; text: string }
  | { kind: "contact"; text: string }
  | { kind: "contact"; circle: string; chain?: string[] }
  /** P3 (§2.8): the new identity's invite to a friend of the old one, with the rotation statement as proof. */
  | { kind: "contact"; rotation: RotationStatement; invite: string }
  /** P3 (§2.8): `rotation` rides with a rotated member's join (and the old identity's leave) to the owner. */
  /** `part` (draft 3 amendment): this envelope is part `i` of `n` of one answer `id` to a `want`, so the asker knows when it is whole. */
  | { kind: "circle"; circles: string[]; joins: string[]; ops: string[]; rotation?: RotationStatement; part?: AnswerPart }
  /**
   * `cap` (draft 3 amendment): the asker's answer cap for the recipient, so the answer can span
   * several `circle` envelopes. `link`: the jwsHash of the version the asker was offered (a link
   * or an invite), which puts a non-member's answer in the members' reserved budget.
   */
  | { kind: "circle"; want: { cid: string; fromVer: number }; cap?: string; link?: string; pow?: WantPow };

/**
 * Proof of work on a non-member's `want` (§3.3, re-review N3): `nonce` such that
 * sha256("p2p/v3/want-pow|" + from + "|" + cid + "|" + fromVer + "|" + at + "|" + nonce) has at
 * least the member's required number of leading zero bits; `at` is the asker's clock (seconds).
 */
export interface WantPow {
  at: number;
  nonce: string;
}

/** One part of a chunked answer to a circle `want` (§3.3): answer `id` (b64u, 8 to 24 chars), part `i` of `n`. */
export interface AnswerPart {
  id: string;
  i: number;
  n: number;
}

/** At most this many parts in one answer (a version is at most 16 KiB, a part about 30 KiB). */
export const MAX_ANSWER_PARTS = 4096;

// ---------------------------------------------------------------------------
// §4.3 "Extension state kinds" (cap xstate.v1)

/**
 * The cap that says a client takes extension state kinds: it keeps the latest
 * per (sender, session, kind), replacing the previous one, and never logs,
 * toasts or shows one to a model. A sender sends a state kind only to a user
 * whose live sessions all advertise it.
 */
export const STATUS_CAP_XSTATE = "xstate.v1";
/** A state kind's time to live (seconds), as `state.ttl` carries it. */
export const EXT_STATE_TTL_MIN = 10;
export const EXT_STATE_TTL_MAX = 3600;
export const EXT_STATE_TTL_DEFAULT = 600;
/** At most this many bytes of `{v, body}` in a state kind (less than an ordinary extension kind's 24 KiB). */
export const EXT_STATE_MAX_BYTES = 16 * 1024;
/** A sender updates one state kind of one session at most this often; a receiver drops faster updates. */
export const EXT_STATE_MIN_INTERVAL_MS = 5_000;

/** The marker a state kind's plaintext carries: `state: {ttl}`. */
export interface ExtStateMarker {
  ttl: number;
}

export function isExtStateTtl(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= EXT_STATE_TTL_MIN && v <= EXT_STATE_TTL_MAX;
}

/** The cap a client advertises for an extension kind it understands: `<kind>.v<n>` (e.g. `x:ix.footprint.v1`); undefined when it wouldn't be a valid cap. */
export function extensionKindCap(kind: string, v = 1): string | undefined {
  if (!isExtensionKind(kind) || !Number.isSafeInteger(v) || v < 1) return undefined;
  const cap = `${kind}.v${v}`;
  return isStatusCap(cap) ? cap : undefined;
}

/** §4.3: `fallback` is at most 200 characters of plain text. */
export const FALLBACK_MAX = 200;
export const MAX_CHAIN_IN_BUNDLE = 4096;

type O = Record<string, unknown>;

function parseAnswerPart(v: unknown): AnswerPart {
  const p = v as O;
  const okInt = (x: unknown, max: number) => typeof x === "number" && Number.isSafeInteger(x) && x >= 1 && x <= max;
  if (typeof p !== "object" || p === null || Array.isArray(p) || typeof p.id !== "string" || !/^[A-Za-z0-9_-]{8,24}$/.test(p.id) || !okInt(p.n, MAX_ANSWER_PARTS) || !okInt(p.i, p.n as number)) {
    fail("malformed", "circle.part must be {id, i, n} with 1 <= i <= n");
  }
  known(p, ["id", "i", "n"], "circle.part");
  return { id: p.id as string, i: p.i as number, n: p.n as number };
}

/**
 * The plaintext fields this version knows (protocol.md "Forward compatibility"): any other is
 * ignored (the parsers below copy known fields only), unless the plaintext lists it in `crit`.
 * Known fields keep every type and size check; the envelope cap still bounds the whole plaintext.
 */
function known(o: O, keys: readonly string[], what: string): void {
  checkFields(o, keys, what);
}

/** Exactly one of these fields, which say what the plaintext is: never two readings of one envelope. */
function oneOf(o: O, keys: readonly string[], what: string): void {
  if (keys.filter((k) => o[k] !== undefined).length !== 1) fail("malformed", `${what} must carry exactly one of ${keys.join(", ")}`);
}

function s(o: O, k: string, what: string): string {
  if (typeof o[k] !== "string") fail("malformed", `${what}.${k} must be a string`);
  return o[k] as string;
}

function optS(o: O, k: string, what: string): string | undefined {
  return o[k] === undefined ? undefined : s(o, k, what);
}

function jwsList(o: O, k: string, what: string): string[] {
  const v = o[k] ?? [];
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string") || v.length > MAX_CHAIN_IN_BUNDLE) {
    fail("malformed", `${what}.${k} must be an array of JWS`);
  }
  return v as string[];
}

function extras(o: O, what: string): SessionExtras {
  const out: SessionExtras = {};
  if (o.roster !== undefined) out.roster = s(o, "roster", what);
  if (o.friendship !== undefined) {
    const f = o.friendship as O;
    if (typeof f !== "object" || f === null || typeof f.invite !== "string" || typeof f.accept !== "string") {
      fail("malformed", `${what}.friendship must be {invite, accept}`);
    }
    out.friendship = { invite: f.invite as string, accept: f.accept as string };
  }
  return out;
}

/**
 * §4.3 "Status caps": at most 16 entries, each at most 40 characters of
 * `[a-z0-9._-]` (an optional `x:` prefix for an extension's), starting with a
 * letter. A cap names something the sending client understands, such as
 * `agents.v1` or `x:ix.footprint.v1`.
 */
export const STATUS_CAPS_MAX = 16;
export const STATUS_CAP_MAX_LEN = 40;
const STATUS_CAP_RE = /^(?:x:)?[a-z][a-z0-9_-]*(?:\.[a-z0-9_-]+)*$/;

/**
 * The cap every client that sends `caps` includes: "I ignore status fields I
 * don't know", so a sender may add newer ones for this session. (Two-step
 * rollout: clients send `caps` only once enabled, so a missing list doesn't
 * prove an old client yet.)
 */
export const STATUS_CAP_TOLERANT = "status.tolerant.v1";

export function isStatusCap(c: unknown): c is string {
  return typeof c === "string" && c.length <= STATUS_CAP_MAX_LEN && STATUS_CAP_RE.test(c);
}

/** A strict check of a `caps` list: an array of distinct valid caps, at most {@link STATUS_CAPS_MAX}. */
export function validStatusCaps(v: unknown): v is string[] {
  return Array.isArray(v) && v.length <= STATUS_CAPS_MAX && v.every(isStatusCap) && new Set(v).size === v.length;
}

/**
 * Whether a session's status says its client understands `cap`. A status
 * without `caps` (one from a client older than the amendment) understands
 * nothing optional.
 */
export function statusHasCap(status: { caps?: unknown } | undefined, cap: string): boolean {
  // review L1: `caps` of a hand-built or foreign object may be a string, whose `includes` is a substring test.
  const caps = status?.caps;
  return Array.isArray(caps) && caps.includes(cap);
}

// ---------------------------------------------------------------------------
// §4.3 "Status agents" (cap agents.v1)

/** The cap that says a client parses and shows `status.agents`. */
export const STATUS_CAP_AGENTS = "agents.v1";
export const STATUS_AGENTS_MAX = 8;
export const STATUS_AGENT_FILES_MAX = 10;
export const STATUS_AGENT_TASK_MAX = 80;
export const STATUS_AGENT_TYPE_MAX = 32;
export const STATUS_AGENT_BRANCH_MAX = 128;
export const STATUS_AGENT_FILE_MAX_LEN = 200;
export const STATUS_AGENT_STATES: readonly StatusAgentState[] = ["running", "waiting", "idle", "done", "failed"];
const AGENT_ID_RE = /^a[1-9][0-9]{0,3}$/;
const AGENT_TYPE_RE = /^[A-Za-z0-9:_ .-]{1,32}$/;
const AGENT_BRANCH_RE = /^[A-Za-z0-9._/-]{1,128}$/;
const AGENT_FIELDS = ["id", "parent", "type", "task", "state", "files", "wt", "branch", "at"] as const;

export function isStatusAgentId(v: unknown): v is string {
  return typeof v === "string" && AGENT_ID_RE.test(v);
}

/** A task line as it may travel: already one sanitized line (sanitizePeerText leaves it unchanged), 1-80 code points. */
export function isStatusAgentTask(v: unknown): v is string {
  return typeof v === "string" && v !== "" && [...v].length <= STATUS_AGENT_TASK_MAX && sanitizePeerText(v, STATUS_AGENT_TASK_MAX) === v;
}

export function isStatusAgentType(v: unknown): v is string {
  return typeof v === "string" && AGENT_TYPE_RE.test(v) && v.trim() === v;
}

/** A git branch name in a conservative charset (no `..`, no leading `-` or `/`). */
export function isStatusAgentBranch(v: unknown): v is string {
  return typeof v === "string" && AGENT_BRANCH_RE.test(v) && !v.includes("..") && !/^[-/]/.test(v) && !v.endsWith("/");
}

export function isStatusAgentFile(v: unknown): v is string {
  return isSafeRelativePath(v) && v.length <= STATUS_AGENT_FILE_MAX_LEN && sanitizePeerText(v, PEER_TEXT_CAPS.file) === v;
}

/** Why `v` is not a valid `agents` list, or undefined when it is (§4.3 "Status agents"). */
export function statusAgentsError(v: unknown, opts: { lenient?: boolean } = {}): string | undefined {
  if (!Array.isArray(v)) return "must be an array";
  if (v.length > STATUS_AGENTS_MAX) return `at most ${STATUS_AGENTS_MAX} agents`;
  const ids = new Set<string>();
  const parentOf = new Map<string, string | undefined>();
  for (const [i, a] of v.entries()) {
    if (typeof a !== "object" || a === null || Array.isArray(a)) return `[${i}] must be an object`;
    const o = a as O;
    // Received (`lenient`): a field this version doesn't know is ignored (copyAgents drops it), as at
    // the top level of the status (protocol.md "Forward compatibility"). A sender's own list stays strict.
    if (!opts.lenient) for (const k of Object.keys(o)) if (!(AGENT_FIELDS as readonly string[]).includes(k)) return `[${i}] unknown field ${k.slice(0, 32)}`;
    if (!isStatusAgentId(o.id)) return `[${i}].id must match a1..a9999`;
    if (ids.has(o.id)) return `[${i}].id repeats ${o.id}`;
    ids.add(o.id);
    if (o.parent !== undefined && (!isStatusAgentId(o.parent) || o.parent === o.id)) return `[${i}].parent must be another agent's id`;
    parentOf.set(o.id, o.parent as string | undefined);
    if (!isStatusAgentType(o.type)) return `[${i}].type must be 1-${STATUS_AGENT_TYPE_MAX} of [A-Za-z0-9:_ .-]`;
    if (!isStatusAgentTask(o.task)) return `[${i}].task must be one sanitized line of 1-${STATUS_AGENT_TASK_MAX} characters`;
    if (!(STATUS_AGENT_STATES as readonly unknown[]).includes(o.state)) return `[${i}].state must be ${STATUS_AGENT_STATES.join("|")}`;
    if (o.files !== undefined) {
      if (!Array.isArray(o.files) || o.files.length > STATUS_AGENT_FILES_MAX) return `[${i}].files must be at most ${STATUS_AGENT_FILES_MAX} paths`;
      if (!o.files.every(isStatusAgentFile)) return `[${i}].files must be repo-relative paths (no . or .. segments, at most ${STATUS_AGENT_FILE_MAX_LEN})`;
      if (new Set(o.files).size !== o.files.length) return `[${i}].files repeats a path`;
    }
    if (o.wt !== undefined && o.wt !== true) return `[${i}].wt must be true when present`;
    if (o.branch !== undefined && !isStatusAgentBranch(o.branch)) return `[${i}].branch must be a branch name of [A-Za-z0-9._/-]`;
    if (typeof o.at !== "number" || !Number.isSafeInteger(o.at) || o.at < 0) return `[${i}].at must be a time in ms`;
  }
  // Nesting is flattened to depth 2: a parent is listed and has no parent itself (so no cycles).
  for (const [id, parent] of parentOf) {
    if (parent === undefined) continue;
    if (!ids.has(parent)) return `${id}.parent ${parent} is not listed`;
    if (parentOf.get(parent) !== undefined) return `${id}.parent ${parent} has a parent itself (at most depth 2)`;
  }
  return undefined;
}

/** A strict check of an `agents` list (§4.3 "Status agents"). */
export function validStatusAgents(v: unknown): v is StatusAgent[] {
  return statusAgentsError(v) === undefined;
}

/** A deep copy with only the known fields, of a list validStatusAgents accepted. */
function copyAgents(v: readonly StatusAgent[]): StatusAgent[] {
  return v.map((a) => ({
    id: a.id,
    ...(a.parent !== undefined ? { parent: a.parent } : {}),
    type: a.type,
    task: a.task,
    state: a.state,
    ...(a.files !== undefined ? { files: [...a.files] } : {}),
    ...(a.wt ? { wt: true as const } : {}),
    ...(a.branch !== undefined ? { branch: a.branch } : {}),
    at: a.at,
  }));
}

/** Agents still at work (not done or failed): what the `(+N agents)` summary counts. */
export function activeAgentCount(agents: readonly StatusAgent[] | undefined): number {
  return (agents ?? []).filter((a) => a.state !== "done" && a.state !== "failed").length;
}

/**
 * The summary a recipient without `agents.v1` gets instead of `agents`:
 * `<summary> (+N agents)`, still within the summary's 280 characters, or
 * `summary` unchanged when no agent is at work.
 */
export function summaryWithAgents(summary: string | undefined, agents: readonly StatusAgent[] | undefined): string | undefined {
  const n = activeAgentCount(agents);
  if (n === 0) return summary;
  const tail = `(+${n} agent${n === 1 ? "" : "s"})`;
  if (!summary) return tail;
  const room = PEER_TEXT_CAPS.summary - tail.length - 1;
  const cps = [...summary];
  return `${cps.length > room ? cps.slice(0, room).join("").trimEnd() : summary} ${tail}`;
}

/**
 * The status fields this client knows (§4.3). A receiver MUST ignore any other
 * top-level status field (forward compatibility): it is dropped here, so it
 * never reaches the store, `ls`, a watch line, a model or the UI. Known fields
 * stay strictly validated, and the envelope cap (MAX_ENVELOPE_BYTES) still
 * bounds the whole status.
 */
export const STATUS_FIELDS = ["state", "label", "repo", "branch", "mode", "summary", "files", "summaryAt", "caps", "agents"] as const;

function statusBody(v: unknown): StatusBody {
  if (typeof v !== "object" || v === null || Array.isArray(v)) fail("malformed", "status must be an object");
  const o = v as O;
  if (o.state !== "busy" && o.state !== "idle") fail("malformed", "status.state must be busy|idle");
  const b: StatusBody = { state: o.state, label: s(o, "label", "status") };
  for (const k of ["repo", "branch", "mode", "summary"] as const) {
    const x = optS(o, k, "status");
    if (x !== undefined) b[k] = x;
  }
  if (o.files !== undefined) {
    if (!Array.isArray(o.files) || o.files.some((f) => typeof f !== "string")) fail("malformed", "status.files must be strings");
    b.files = o.files as string[];
  }
  if (o.summaryAt !== undefined) {
    if (typeof o.summaryAt !== "number" || !Number.isSafeInteger(o.summaryAt) || o.summaryAt < 0) fail("malformed", "status.summaryAt");
    b.summaryAt = o.summaryAt;
  }
  if (o.caps !== undefined) {
    if (!validStatusCaps(o.caps)) {
      fail("malformed", `status.caps must be at most ${STATUS_CAPS_MAX} distinct caps of at most ${STATUS_CAP_MAX_LEN} characters [a-z0-9._-]`);
    }
    b.caps = [...o.caps];
  }
  if (o.agents !== undefined) {
    const why = statusAgentsError(o.agents, { lenient: true });
    if (why !== undefined) fail("malformed", `status.agents ${why}`);
    b.agents = copyAgents(o.agents as StatusAgent[]);
  }
  // `b` is built field by field from STATUS_FIELDS: any other key is dropped, never copied.
  return b;
}

/** Parses and shape-checks the decrypted plaintext of `kind`. */
export function parsePlaintextV3(kind: EnvelopeKindV3, bytes: Uint8Array): PlaintextV3 {
  let v: unknown;
  try {
    v = JSON.parse(fromUtf8(bytes));
  } catch {
    return fail("malformed", "plaintext is not JSON");
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) fail("malformed", "plaintext must be an object");
  const o = v as O;
  switch (kind) {
    case "msg":
      known(o, ["text", "roster", "friendship", "rcpt"], "msg");
      if (o.rcpt !== undefined && (typeof o.rcpt !== "string" || !RECEIPT_ID_RE.test(o.rcpt))) fail("malformed", "msg.rcpt must be a receipt id");
      return { kind, text: s(o, "text", "msg"), ...(typeof o.rcpt === "string" ? { rcpt: o.rcpt } : {}), ...extras(o, "msg") };
    case "receipt": {
      known(o, ["receipt"], "receipt");
      const r = o.receipt as O;
      if (typeof r !== "object" || r === null || Array.isArray(r)) fail("malformed", "receipt must be {id, outcome}");
      known(r, ["id", "outcome"], "receipt.receipt");
      if (typeof r.id !== "string" || !RECEIPT_ID_RE.test(r.id)) fail("malformed", "receipt.id must be a receipt id");
      if (!RECEIPT_OUTCOMES.includes(r.outcome as ReceiptOutcome)) fail("malformed", "receipt.outcome is not a known outcome");
      return { kind, receipt: { id: r.id as string, outcome: r.outcome as ReceiptOutcome } };
    }
    case "roster": {
      known(o, ["roster", "friendship"], "roster");
      const { friendship } = extras(o, "roster");
      return { kind, roster: s(o, "roster", "roster"), ...(friendship ? { friendship } : {}) };
    }
    case "idle":
      known(o, ["reason", "roster", "friendship"], "idle");
      return { kind, reason: s(o, "reason", "idle"), ...extras(o, "idle") };
    case "status":
      known(o, ["status", "roster", "friendship"], "status");
      return { kind, status: statusBody(o.status), ...extras(o, "status") };
    case "sync":
      return { kind, body: o };
    case "unfriend":
      known(o, ["text"], "unfriend");
      return { kind, text: s(o, "text", "unfriend") };
    case "contact":
      oneOf(o, ["text", "circle", "rotation"], "contact");
      if (o.rotation !== undefined) {
        known(o, ["rotation", "invite"], "contact");
        return { kind, rotation: parseRotationStatement(o.rotation), invite: s(o, "invite", "contact") };
      }
      if (o.circle !== undefined) {
        known(o, ["circle", "chain"], "contact");
        return { kind, circle: s(o, "circle", "contact"), ...(o.chain !== undefined ? { chain: jwsList(o, "chain", "contact") } : {}) };
      }
      known(o, ["text"], "contact");
      return { kind, text: s(o, "text", "contact") };
    case "circle":
      // A want or a bundle, never both (each was refused with the other's fields before).
      if (o.want !== undefined && (o.circles !== undefined || o.joins !== undefined || o.ops !== undefined || o.rotation !== undefined || o.part !== undefined)) {
        fail("malformed", "circle carries a want and a bundle");
      }
      if (o.want !== undefined) {
        known(o, ["want", "cap", "link", "pow"], "circle");
        const w = o.want as O;
        if (typeof w !== "object" || w === null || !isCircleId(w.cid) || typeof w.fromVer !== "number" || !Number.isSafeInteger(w.fromVer) || w.fromVer < 1) {
          fail("malformed", "circle.want must be {cid, fromVer}");
        }
        const cap = optS(o, "cap", "circle");
        if (cap !== undefined && (cap.length > MAX_JWS_BYTES || cap.split(".").length !== 3)) fail("malformed", "circle.cap must be one compact JWS");
        const link = optS(o, "link", "circle");
        if (link !== undefined && !/^[A-Za-z0-9_-]{43}$/.test(link)) fail("malformed", "circle.link must be a version's jwsHash");
        let pow: WantPow | undefined;
        if (o.pow !== undefined) {
          const q = o.pow as O;
          if (typeof q !== "object" || q === null || Array.isArray(q) || typeof q.at !== "number" || !Number.isSafeInteger(q.at) || q.at < 0 || typeof q.nonce !== "string" || !/^[A-Za-z0-9_-]{1,32}$/.test(q.nonce)) {
            fail("malformed", "circle.pow must be {at, nonce}");
          }
          known(q, ["at", "nonce"], "circle.pow");
          pow = { at: q.at as number, nonce: q.nonce as string };
        }
        return {
          kind,
          want: { cid: w.cid as string, fromVer: w.fromVer as number },
          ...(cap !== undefined ? { cap } : {}),
          ...(link !== undefined ? { link } : {}),
          ...(pow !== undefined ? { pow } : {}),
        };
      }
      known(o, ["circles", "joins", "ops", "rotation", "part"], "circle");
      return {
        kind,
        circles: jwsList(o, "circles", "circle"),
        joins: jwsList(o, "joins", "circle"),
        ops: jwsList(o, "ops", "circle"),
        ...(o.rotation !== undefined ? { rotation: parseRotationStatement(o.rotation) } : {}),
        ...(o.part !== undefined ? { part: parseAnswerPart(o.part) } : {}),
      };
    default: {
      // x:<ns>.<type>
      // `state` (§4.3 "Extension state kinds", cap xstate.v1): clients from before it reject the field,
      // and a sender only sends it to recipients that advertise xstate.v1.
      known(o, ["ext", "fallback", "roster", "friendship", "state"], kind);
      const ext = o.ext as O;
      if (typeof ext !== "object" || ext === null || typeof ext.v !== "number" || !Number.isSafeInteger(ext.v) || !("body" in ext)) {
        fail("malformed", `${kind}.ext must be {v, body}`);
      }
      const fallback = s(o, "fallback", kind);
      if ([...fallback].length > FALLBACK_MAX) fail("malformed", `${kind}.fallback is longer than ${FALLBACK_MAX}`);
      let state: ExtStateMarker | undefined;
      if (o.state !== undefined) {
        const st = o.state as O;
        if (typeof st !== "object" || st === null || Array.isArray(st)) fail("malformed", `${kind}.state must be {ttl}`);
        known(st, ["ttl"], `${kind}.state`);
        if (!isExtStateTtl(st.ttl)) fail("malformed", `${kind}.state.ttl must be an integer of ${EXT_STATE_TTL_MIN}-${EXT_STATE_TTL_MAX} seconds`);
        state = { ttl: st.ttl as number };
      }
      return { kind, ext: { v: ext.v as number, body: ext.body }, fallback, ...(state ? { state } : {}), ...extras(o, kind) };
    }
  }
}

// ---------------------------------------------------------------------------
// Display helpers (every peer string through the one sanitizer)

export interface DisplayStatus {
  state: "busy" | "idle";
  label: string;
  repo?: string;
  branch?: string;
  mode?: string;
  summary?: string;
  files: string[];
  summaryAt?: number;
  caps?: string[];
  agents?: StatusAgent[];
}

export function displayStatus(b: StatusBody): DisplayStatus {
  const out: DisplayStatus = { state: b.state, label: sanitizePeerText(b.label, PEER_TEXT_CAPS.label), files: sanitizeFiles(b.files) };
  if (b.repo !== undefined) out.repo = sanitizePeerText(b.repo, 128);
  if (b.branch !== undefined) out.branch = sanitizePeerText(b.branch, 128);
  if (b.mode !== undefined) out.mode = sanitizePeerText(b.mode, 32);
  if (b.summary !== undefined) out.summary = sanitizePeerText(b.summary, PEER_TEXT_CAPS.summary);
  if (b.summaryAt !== undefined) out.summaryAt = b.summaryAt;
  // Already strict (charset and caps); re-checked so a hand-built StatusBody can't smuggle text.
  if (b.caps !== undefined && validStatusCaps(b.caps)) out.caps = [...b.caps];
  // Re-validated the same way: a stored or hand-built list that no longer passes is left out whole.
  // Every string in a valid list is already one sanitized line (task) or of a strict charset.
  if (b.agents !== undefined && validStatusAgents(b.agents)) out.agents = copyAgents(b.agents);
  return out;
}

/**
 * §4.3: a receiver without the extension shows the sanitized `fallback`,
 * prefixed with the sender's address, and never interprets `body`.
 */
export function extensionFallbackText(senderAddress: string, fallback: string): string {
  return `${sanitizePeerText(senderAddress, 80)}: ${sanitizePeerText(fallback, FALLBACK_MAX)}`;
}

/** §4.3: a session is live for 150 s after the `ts` of its last status, not after arrival. */
export const STATUS_LIVE_MS = 150_000;
/** §4.3: senders emit status on change, and otherwise every 60 s. */
export const STATUS_INTERVAL_MS = 60_000;

export function isLive(lastStatusTs: number | undefined, nowMs: number): boolean {
  return lastStatusTs !== undefined && nowMs - lastStatusTs <= STATUS_LIVE_MS && lastStatusTs <= nowMs + 10 * 60_000;
}
