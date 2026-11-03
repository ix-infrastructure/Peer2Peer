// Copyright 2026 Ix Infrastructure Inc.
//
// The v2 `p2p-msg+jws` envelope, and the sealing every version shares: sealed
// per recipient device, signed by the sender device. The relay sees only the
// outer JWS. v3 (src/v3/envelope.ts) reuses sealBox/openBox with the `p2p/v3`
// profile (docs/protocol.md §4.1).
//
//   ikm = X25519(eph, tdid.kpk) || X25519(sender.kpk_priv, tdid.kpk)
//   key = HKDF-SHA256(ikm, salt = n, info = "p2p/v1/msg|" + fdid + "|" + tdid)
//   ct  = XChaCha20-Poly1305(key, n, plaintext, aad)
//   aad = UTF-8("p2p/v1|" + from + "|" + fdid + "|" + to + "|" + tdid + "|"
//               + own + "|" + sid + "|" + seq + "|" + ts + "|" + kind)
//
// The AAD is the fixed-string form (docs/protocol-v2.md, C1; `own` added in
// draft 2, C9). The sender's device certificate rides in the outer payload
// as `fcert` (draft 2, C2) so the receiver can verify it before opening.

import { b64uDecode, b64uEncode, concat, fromUtf8, utf8 } from "./encoding.js";
import { aeadOpen, aeadSeal, hkdfSha256, randomBytes, x25519, x25519PublicKey, XCHACHA_NONCE_LEN } from "./crypto.js";
import { decodeJws, MAX_ENVELOPE_BYTES, signJws, verifyJws, type DecodedJws } from "./jws.js";
import { fail } from "./errors.js";
import { isDeviceId, normalizeUserId, TYP, type FriendshipProof } from "./objects.js";

export const ENVELOPE_VERSION = 1;

export type EnvelopeKind = "msg" | "roster" | "idle" | "sync" | "unfriend" | "contact";
const KINDS: readonly EnvelopeKind[] = ["msg", "roster", "idle", "sync", "unfriend", "contact"];

/**
 * Draft 2 D8: the reserved session id of `kind: "contact"` envelopes, which
 * carry one invite, accept or unfriend between users who share no session.
 * It is valid with that kind only, and that kind is valid with it only.
 */
export const CONTACT_SID = "~contact";

export interface EnvelopePayload {
  v: 1;
  from: string;
  fdid: string;
  /** The sender device's certificate (`p2p-device+jws`; issued by Kartr in v2). */
  fcert: string;
  to: string;
  tdid: string;
  /** The session owner's userId: a session is identified by (own, sid). */
  own: string;
  sid: string;
  seq: number;
  /** Milliseconds since the epoch. */
  ts: number;
  n: string;
  epk: string;
  ct: string;
  kind: EnvelopeKind;
}

/** The routing header: everything in the payload except the crypto fields. */
export type EnvelopeHeader = Omit<EnvelopePayload, "v" | "n" | "epk" | "ct">;

/** The fields the AAD binds. */
export type AadFields = Pick<EnvelopePayload, "from" | "fdid" | "to" | "tdid" | "own" | "sid" | "seq" | "ts" | "kind">;

export interface EnvelopePlaintext {
  text: string;
  roster?: string;
  /**
   * D9: the session owner's Kartr workspace attestation. A roster's `org`
   * confers workspace standing only if this attestation includes it. When
   * the sender is the owner, sealEnvelope fills it from `sender.workspace`;
   * other senders relay the owner's.
   */
  ownerWorkspace?: string;
  /** Proofs about the sender; its device certificate is the outer `fcert`. */
  sender: {
    workspace?: string;
    friendship?: FriendshipProof;
  };
}

/**
 * The protocol-specific strings of the envelope AAD and KDF info. v2 uses
 * `p2p/v1`; v3 (docs/protocol.md §4.1) uses `p2p/v3`. The sealing itself is
 * shared.
 */
export interface EnvelopeProfile {
  /** AAD = UTF-8(aadPrefix + "|" + from + "|" + ... + "|" + kind). */
  aadPrefix: string;
  /** KDF info = UTF-8(kdfInfoPrefix + "|" + fdid + "|" + tdid). */
  kdfInfoPrefix: string;
}

export const ENVELOPE_PROFILE_V2: EnvelopeProfile = { aadPrefix: "p2p/v1", kdfInfoPrefix: "p2p/v1/msg" };

export function envelopeAad(h: AadFields, profile: EnvelopeProfile = ENVELOPE_PROFILE_V2): Uint8Array {
  return utf8(`${profile.aadPrefix}|${h.from}|${h.fdid}|${h.to}|${h.tdid}|${h.own}|${h.sid}|${h.seq}|${h.ts}|${h.kind}`);
}

export function envelopeKdfInfo(fdid: string, tdid: string, profile: EnvelopeProfile = ENVELOPE_PROFILE_V2): Uint8Array {
  return utf8(`${profile.kdfInfoPrefix}|${fdid}|${tdid}`);
}

/** The three crypto fields of a sealed box. */
export interface SealedBox {
  n: Uint8Array;
  epk: Uint8Array;
  ct: Uint8Array;
}

/**
 * The envelope sealing, shared by every protocol version and by v3 device
 * linking (§2.4):
 *
 *   ikm = X25519(eph, recipientKpk) [|| X25519(senderStatic, recipientKpk)] [|| extraIkm]
 *   key = HKDF-SHA256(ikm, salt = n, info)
 *   ct  = XChaCha20-Poly1305(key, n, plaintext, aad)
 *
 * Envelopes always pass the sender's static X25519 key; `extraIkm` lets a
 * caller bind a shared secret into the key (v3 linking binds the link secret).
 */
export function sealBox(p: {
  plaintext: Uint8Array;
  recipientKpk: Uint8Array;
  senderAgreementSecretKey?: Uint8Array;
  extraIkm?: Uint8Array;
  info: Uint8Array;
  aad: Uint8Array;
}): SealedBox {
  const eph = randomBytes(32);
  const n = randomBytes(XCHACHA_NONCE_LEN);
  const ikm = concat(
    x25519(eph, p.recipientKpk),
    p.senderAgreementSecretKey ? x25519(p.senderAgreementSecretKey, p.recipientKpk) : new Uint8Array(0),
    p.extraIkm ?? new Uint8Array(0),
  );
  const key = hkdfSha256(ikm, n, p.info, 32);
  return { n, epk: x25519PublicKey(eph), ct: aeadSeal(key, n, p.plaintext, p.aad) };
}

/** Inverse of sealBox: pass the sender's static `kpk` iff the sealer used its static key. */
export function openBox(p: {
  box: SealedBox;
  recipientAgreementSecretKey: Uint8Array;
  senderKpk?: Uint8Array;
  extraIkm?: Uint8Array;
  info: Uint8Array;
  aad: Uint8Array;
}): Uint8Array {
  const ikm = concat(
    x25519(p.recipientAgreementSecretKey, p.box.epk),
    p.senderKpk ? x25519(p.recipientAgreementSecretKey, p.senderKpk) : new Uint8Array(0),
    p.extraIkm ?? new Uint8Array(0),
  );
  const key = hkdfSha256(ikm, p.box.n, p.info, 32);
  return aeadOpen(key, p.box.n, p.box.ct, p.aad);
}

// "|" separates AAD fields; forbidding it keeps the AAD unambiguous.
function noPipe(field: string, v: string): void {
  if (v.includes("|")) fail("malformed", `${field} must not contain "|"`);
}

export function validateEnvelopePayload(p: Record<string, unknown>): EnvelopePayload {
  if (p.v !== ENVELOPE_VERSION) fail("malformed", `unsupported envelope v ${JSON.stringify(p.v)}`);
  for (const k of ["from", "fcert", "to", "own", "sid", "n", "epk", "ct"]) {
    if (typeof p[k] !== "string" || p[k] === "") fail("malformed", `${k} must be a non-empty string`);
  }
  for (const k of ["from", "to", "own"]) {
    if (p[k] !== normalizeUserId(p[k] as string)) fail("malformed", `${k} is not a normalised userId`);
  }
  if (!isDeviceId(p.fdid) || !isDeviceId(p.tdid)) fail("malformed", "fdid/tdid must be deviceIds");
  for (const k of ["seq", "ts"]) {
    const v = p[k];
    if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) fail("malformed", `${k} must be an integer`);
  }
  if (!KINDS.includes(p.kind as EnvelopeKind)) fail("malformed", `unknown kind ${JSON.stringify(p.kind)}`);
  for (const k of ["from", "to", "own", "sid"]) noPipe(k, p[k] as string);
  if (p.kind === "contact") {
    if (p.sid !== CONTACT_SID) fail("malformed", `kind contact requires sid ${CONTACT_SID}`);
    if (p.own !== p.from) fail("malformed", "kind contact requires own == from");
  } else if (p.sid === CONTACT_SID) {
    fail("malformed", `sid ${CONTACT_SID} is reserved for kind contact`);
  }
  b64uDecode(p.n as string, XCHACHA_NONCE_LEN);
  b64uDecode(p.epk as string, 32);
  b64uDecode(p.ct as string);
  return p as unknown as EnvelopePayload;
}

export interface SealParams extends EnvelopeHeader {
  plaintext: EnvelopePlaintext;
  sender: { signingSecretKey: Uint8Array; agreementSecretKey: Uint8Array };
  /** The recipient device's X25519 public key (`kpk` from its certificate). */
  recipientKpk: Uint8Array;
}

/** Seals and signs an envelope for one recipient device. */
export function sealEnvelope(params: SealParams): string {
  // D9: an owner's own attestation doubles as the owner attestation.
  if (params.from === params.own && params.plaintext.ownerWorkspace === undefined && params.plaintext.sender.workspace !== undefined) {
    params = { ...params, plaintext: { ...params.plaintext, ownerWorkspace: params.plaintext.sender.workspace } };
  }
  const header: EnvelopeHeader = {
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
  const { n, epk, ct } = sealBox({
    plaintext: utf8(JSON.stringify(params.plaintext)),
    recipientKpk: params.recipientKpk,
    senderAgreementSecretKey: params.sender.agreementSecretKey,
    info: envelopeKdfInfo(header.fdid, header.tdid),
    aad: envelopeAad(header),
  });
  const payload: EnvelopePayload = {
    v: 1,
    from: header.from,
    fdid: header.fdid,
    fcert: header.fcert,
    to: header.to,
    tdid: header.tdid,
    own: header.own,
    sid: header.sid,
    seq: header.seq,
    ts: header.ts,
    n: b64uEncode(n),
    epk: b64uEncode(epk),
    ct: b64uEncode(ct),
    kind: header.kind,
  };
  validateEnvelopePayload(payload as unknown as Record<string, unknown>);
  const jws = signJws(TYP.msg, header.fdid, payload, params.sender.signingSecretKey);
  if (jws.length > MAX_ENVELOPE_BYTES) fail("malformed", `envelope is ${jws.length} bytes, max ${MAX_ENVELOPE_BYTES}`);
  return jws;
}

/**
 * Structural decode of an envelope (no signature check): typ, kid == fdid and
 * payload shape. This is all a relay can, or needs to, check.
 */
export function decodeEnvelope(jws: string): DecodedJws<EnvelopePayload> {
  const d = decodeJws(jws, MAX_ENVELOPE_BYTES);
  if (d.header.typ !== TYP.msg) fail("typ-mismatch", `typ ${d.header.typ} != ${TYP.msg}`);
  const p = validateEnvelopePayload(d.payload);
  if (d.header.kid !== p.fdid) fail("kid-mismatch", `kid ${d.header.kid} != fdid ${p.fdid}`);
  return { ...d, payload: p };
}

/** Checks the envelope signature against the sender device's `spk`. */
export function verifyEnvelopeSignature(jws: string, senderSpk: Uint8Array): DecodedJws<EnvelopePayload> {
  const d = decodeEnvelope(jws);
  verifyJws(jws, { typ: TYP.msg, kid: d.payload.fdid, publicKey: senderSpk, maxBytes: MAX_ENVELOPE_BYTES });
  return d;
}

/** Decrypts the ciphertext. The caller must already have checked the signature. */
export function openEnvelope(
  payload: EnvelopePayload,
  recipientAgreementSecretKey: Uint8Array,
  senderKpk: Uint8Array,
): Uint8Array {
  return openBox({
    box: { n: b64uDecode(payload.n, XCHACHA_NONCE_LEN), epk: b64uDecode(payload.epk, 32), ct: b64uDecode(payload.ct) },
    recipientAgreementSecretKey,
    senderKpk,
    info: envelopeKdfInfo(payload.fdid, payload.tdid),
    aad: envelopeAad(payload),
  });
}

export function parsePlaintext(bytes: Uint8Array): EnvelopePlaintext {
  let v: unknown;
  try {
    v = JSON.parse(fromUtf8(bytes));
  } catch {
    return fail("malformed", "plaintext is not JSON");
  }
  const p = v as EnvelopePlaintext;
  if (typeof p !== "object" || p === null || typeof p.text !== "string") fail("malformed", "plaintext.text missing");
  if (typeof p.sender !== "object" || p.sender === null || Array.isArray(p.sender)) {
    fail("malformed", "plaintext.sender must be an object");
  }
  if (p.roster !== undefined && typeof p.roster !== "string") fail("malformed", "plaintext.roster must be a JWS");
  if (p.ownerWorkspace !== undefined && typeof p.ownerWorkspace !== "string") {
    fail("malformed", "plaintext.ownerWorkspace must be a JWS");
  }
  if (p.sender.workspace !== undefined && typeof p.sender.workspace !== "string") {
    fail("malformed", "plaintext.sender.workspace must be a JWS");
  }
  const f = p.sender.friendship;
  if (f !== undefined && (typeof f !== "object" || f === null || typeof f.invite !== "string" || typeof f.accept !== "string")) {
    fail("malformed", "plaintext.sender.friendship must be {invite, accept}");
  }
  return p;
}

export interface SealContactParams {
  from: string;
  fdid: string;
  fcert: string;
  to: string;
  tdid: string;
  seq: number;
  ts: number;
  /** Exactly one invite, accept or unfriend compact JWS. */
  object: string;
  sender: { signingSecretKey: Uint8Array; agreementSecretKey: Uint8Array };
  recipientKpk: Uint8Array;
}

/** Seals a `kind: "contact"` envelope (own = from, sid = ~contact) carrying one object. */
export function sealContact(p: SealContactParams): string {
  return sealEnvelope({
    from: p.from,
    fdid: p.fdid,
    fcert: p.fcert,
    to: p.to,
    tdid: p.tdid,
    own: p.from,
    sid: CONTACT_SID,
    seq: p.seq,
    ts: p.ts,
    kind: "contact",
    plaintext: { text: p.object, sender: {} },
    sender: p.sender,
    recipientKpk: p.recipientKpk,
  });
}
