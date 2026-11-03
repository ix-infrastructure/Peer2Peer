// Copyright 2026 Ix Infrastructure Inc.
//
// Device linking (docs/protocol.md §2.4): pure functions only. The relay I/O
// (pre-auth link mailboxes, §5.7) is the caller's.
//
//  1. The linked, key-holding device makes a 16-byte link secret `s` and
//     shows `p2p-link:<b32(s)>@<relay host[:port][/path]>`. The link mailbox
//     id is lid = b32(H("p2p/v3/link-id|" || s))[:26].
//  2. The new device puts {did, spk, kpk, x, label, mac} into slot `req`, with
//     mac = HMAC-SHA256(HKDF(s, info "p2p/v3/link-mac"),
//                       lp(did) || lp(spk) || lp(kpk) || lp(x) || lp(label)),
//     and shows its compare code b32(H("p2p/v3/link-cmp|" || s || "|" || did))[:8].
//  3. The linked device verifies mac, shows the same compare code for the
//     user to confirm, aborts if more than one valid request arrived, and
//     seals {cert, doc, ik?} to `x` with the envelope sealing, info
//     "p2p/v3/link", into slot `resp`.
//
// Byte strings: `s` enters the hashes as its raw 16 bytes; the prefixes,
// separators and did as UTF-8. The HKDF salt is empty. The response key also
// mixes in HKDF(s, info "p2p/v3/link-key"), so only a holder of `s` can make
// a response the new device accepts (a relay can't substitute its own).

import { b32Decode, b32Encode, b64uDecode, b64uEncode, bytesEqual, concat, fromUtf8, utf8 } from "../encoding.js";
import {
  assertStrongEd25519PublicKey,
  assertStrongX25519PublicKey,
  hkdfSha256,
  hmacSha256,
  randomBytes,
  sha256,
  XCHACHA_NONCE_LEN,
} from "../crypto.js";
import { openBox, sealBox } from "../envelope.js";
import { fail } from "../errors.js";
import { didFromSpk, isDid, MAX_JWS_BYTES, nowSec, userIdFromIk } from "./base.js";
import { verifyDeviceCertV3, type VerifiedDeviceCertV3 } from "./device.js";
import { identityKeyFromSeed, type IdentityKey } from "./identity.js";
import { verifyIdentityDoc, type VerifiedIdentityDoc } from "./identitydoc.js";
import { relayFromLinkPart, relayLinkPart } from "./relayurl.js";
import { sanitizePeerText, PEER_TEXT_CAPS } from "./sanitize.js";


export const LINK_SECRET_LEN = 16;
/** §2.4: a link secret expires after 10 minutes and works once. */
export const LINK_TTL_SEC = 10 * 60;
export const LINK_LABEL_MAX = 64;

export const LINK_ID_PREFIX = "p2p/v3/link-id|";
export const LINK_MAC_INFO = "p2p/v3/link-mac";
export const LINK_CMP_PREFIX = "p2p/v3/link-cmp|";
export const LINK_SEAL_INFO = "p2p/v3/link";
export const LINK_KEY_INFO = "p2p/v3/link-key";

export function newLinkSecret(): Uint8Array {
  return randomBytes(LINK_SECRET_LEN);
}

function checkSecret(s: Uint8Array): void {
  if (!(s instanceof Uint8Array) || s.length !== LINK_SECRET_LEN) fail("malformed", "link secret must be 16 bytes");
}

/** `p2p-link:<b32(s)>@<canonical relay URL without wss://>`. */
export function encodeLinkCode(s: Uint8Array, relay: string): string {
  checkSecret(s);
  return `p2p-link:${b32Encode(s)}@${relayLinkPart(relay)}`;
}

export function parseLinkCode(code: string): { secret: Uint8Array; relay: string } {
  const m = /^p2p-link:([a-z2-7]{26})@(.+)$/.exec(typeof code === "string" ? code.trim() : "");
  if (!m) fail("malformed", "not a p2p-link code");
  return { secret: b32Decode(m[1], LINK_SECRET_LEN), relay: relayFromLinkPart(m[2]) };
}

/** lid = b32(H("p2p/v3/link-id|" || s))[:26]. */
export function linkId(s: Uint8Array): string {
  checkSecret(s);
  return b32Encode(sha256(concat(utf8(LINK_ID_PREFIX), s))).slice(0, 26);
}

/** HKDF-SHA256(ikm = s, salt = empty, info = "p2p/v3/link-mac", 32). */
export function linkMacKey(s: Uint8Array): Uint8Array {
  checkSecret(s);
  return hkdfSha256(s, new Uint8Array(0), utf8(LINK_MAC_INFO), 32);
}

function linkSealKey(s: Uint8Array): Uint8Array {
  return hkdfSha256(s, new Uint8Array(0), utf8(LINK_KEY_INFO), 32);
}

/** lp(v): the 4-byte big-endian length of UTF-8(v), then those bytes. */
export function lp(v: string): Uint8Array {
  const b = utf8(v);
  const out = new Uint8Array(4 + b.length);
  new DataView(out.buffer).setUint32(0, b.length, false);
  out.set(b, 4);
  return out;
}

/** b32(H("p2p/v3/link-cmp|" || s || "|" || did))[:8]: shown on both devices. */
export function linkCompareCode(s: Uint8Array, did: string): string {
  checkSecret(s);
  return b32Encode(sha256(concat(utf8(LINK_CMP_PREFIX), s, utf8(`|${did}`)))).slice(0, 8);
}

export function linkExpired(createdAt: number, now: number = nowSec()): boolean {
  return now - createdAt >= LINK_TTL_SEC;
}

/** The `req` frame: every value a string (keys b64u), so lp() is well defined. */
export interface LinkRequest {
  did: string;
  spk: string;
  kpk: string;
  x: string;
  label: string;
  mac: string;
}

export function linkRequestMac(s: Uint8Array, r: Omit<LinkRequest, "mac">): Uint8Array {
  return hmacSha256(linkMacKey(s), concat(lp(r.did), lp(r.spk), lp(r.kpk), lp(r.x), lp(r.label)));
}

/** New device: builds the request for its device keys and an ephemeral X25519 key `x`. */
export function createLinkRequest(
  s: Uint8Array,
  device: { signingPublicKey: Uint8Array; agreementPublicKey: Uint8Array },
  xPublicKey: Uint8Array,
  label: string,
): LinkRequest {
  if ([...label].length > LINK_LABEL_MAX) fail("malformed", `label is longer than ${LINK_LABEL_MAX}`);
  const r = {
    did: didFromSpk(device.signingPublicKey),
    spk: b64uEncode(device.signingPublicKey),
    kpk: b64uEncode(device.agreementPublicKey),
    x: b64uEncode(xPublicKey),
    label,
  };
  return { ...r, mac: b64uEncode(linkRequestMac(s, r)) };
}

export interface VerifiedLinkRequest extends LinkRequest {
  signingPublicKey: Uint8Array;
  agreementPublicKey: Uint8Array;
  xPublicKey: Uint8Array;
  /** The label, sanitized for display (§4.3). */
  displayLabel: string;
  compareCode: string;
}

/** Linked device: checks the MAC (constant time), did == H(spk), and the keys. */
export function verifyLinkRequest(s: Uint8Array, req: unknown): VerifiedLinkRequest {
  if (typeof req !== "object" || req === null) fail("malformed", "link request must be an object");
  const r = req as Record<string, unknown>;
  for (const k of ["did", "spk", "kpk", "x", "label", "mac"]) {
    if (typeof r[k] !== "string") fail("malformed", `link request ${k} must be a string`);
  }
  if (Object.keys(r).length !== 6) fail("malformed", "link request has unknown fields");
  const lr = r as unknown as LinkRequest;
  const mac = b64uDecode(lr.mac, 32);
  if (!bytesEqual(mac, linkRequestMac(s, lr))) fail("link-mac-invalid", "link request MAC does not verify");
  if (!isDid(lr.did)) fail("malformed", "link request did");
  const signingPublicKey = b64uDecode(lr.spk, 32);
  const agreementPublicKey = b64uDecode(lr.kpk, 32);
  const xPublicKey = b64uDecode(lr.x, 32);
  assertStrongEd25519PublicKey(signingPublicKey);
  assertStrongX25519PublicKey(agreementPublicKey);
  assertStrongX25519PublicKey(xPublicKey);
  if (didFromSpk(signingPublicKey) !== lr.did) fail("did-mismatch", "link request did does not derive from spk");
  if ([...lr.label].length > LINK_LABEL_MAX) fail("malformed", "link request label too long");
  return {
    ...lr,
    signingPublicKey,
    agreementPublicKey,
    xPublicKey,
    displayLabel: sanitizePeerText(lr.label, PEER_TEXT_CAPS.label),
    compareCode: linkCompareCode(s, lr.did),
  };
}

/**
 * Linked device: the one request to proceed with, from everything in the
 * `req` slot. Entries that fail the MAC are ignored (anyone can put); more
 * than one distinct valid request aborts the link (§2.4), as someone else
 * holds `s`.
 */
export function selectLinkRequest(s: Uint8Array, entries: readonly unknown[]): VerifiedLinkRequest | undefined {
  const valid = new Map<string, VerifiedLinkRequest>();
  for (const e of entries) {
    let parsed: unknown = e;
    if (typeof e === "string") {
      try {
        parsed = JSON.parse(e);
      } catch {
        continue;
      }
    }
    try {
      const v = verifyLinkRequest(s, parsed);
      valid.set(v.mac, v);
    } catch {
      // not from a holder of s
    }
  }
  if (valid.size > 1) fail("link-multiple-requests", "more than one valid link request: aborting the link");
  return valid.values().next().value;
}

/** What the linked device sends back, sealed. */
export interface LinkBundle {
  cert: string;
  doc: string;
  /** b64u of the 32-byte ik seed: only when the user made the new device key-holding. */
  ik?: string;
}

/** The `resp` frame. `fkpk` is the linked device's X25519 key (the static sealing term). */
export interface LinkResponseFrame {
  fkpk: string;
  n: string;
  epk: string;
  ct: string;
}

function linkAad(s: Uint8Array, did: string): Uint8Array {
  return utf8(`${LINK_SEAL_INFO}|${linkId(s)}|${did}`);
}

/** Linked device: seals the bundle to the request's `x`. */
export function sealLinkResponse(
  s: Uint8Array,
  req: VerifiedLinkRequest,
  bundle: LinkBundle,
  sender: { agreementSecretKey: Uint8Array; agreementPublicKey: Uint8Array },
): LinkResponseFrame {
  const box = sealBox({
    plaintext: utf8(JSON.stringify(bundle)),
    recipientKpk: req.xPublicKey,
    senderAgreementSecretKey: sender.agreementSecretKey,
    extraIkm: linkSealKey(s),
    info: utf8(LINK_SEAL_INFO),
    aad: linkAad(s, req.did),
  });
  const frame = { fkpk: b64uEncode(sender.agreementPublicKey), n: b64uEncode(box.n), epk: b64uEncode(box.epk), ct: b64uEncode(box.ct) };
  if (JSON.stringify(frame).length > MAX_JWS_BYTES) fail("malformed", "link response is larger than a 16 KiB slot entry");
  return frame;
}

export interface OpenedLink {
  cert: VerifiedDeviceCertV3;
  doc: VerifiedIdentityDoc;
  /** Present when the new device was made key-holding. */
  ik?: IdentityKey;
}

/**
 * New device: opens the `resp` frame and checks that the bundle is for it:
 * the certificate verifies (rules 1–6 against the bundled document) for its
 * own did, spk and kpk; and, with `ik`, the secret matches the document's
 * issuer and this device is a key holder.
 */
export function openLinkResponse(
  s: Uint8Array,
  device: { signingPublicKey: Uint8Array; agreementPublicKey: Uint8Array },
  xSecretKey: Uint8Array,
  frame: LinkResponseFrame,
  opts: { now?: number } = {},
): OpenedLink {
  const did = didFromSpk(device.signingPublicKey);
  const pt = openBox({
    box: { n: b64uDecode(frame.n, XCHACHA_NONCE_LEN), epk: b64uDecode(frame.epk, 32), ct: b64uDecode(frame.ct) },
    recipientAgreementSecretKey: xSecretKey,
    senderKpk: b64uDecode(frame.fkpk, 32),
    extraIkm: linkSealKey(s),
    info: utf8(LINK_SEAL_INFO),
    aad: linkAad(s, did),
  });
  let bundle: LinkBundle;
  try {
    bundle = JSON.parse(fromUtf8(pt)) as LinkBundle;
  } catch {
    return fail("malformed", "link bundle is not JSON");
  }
  if (typeof bundle?.cert !== "string" || typeof bundle.doc !== "string") fail("malformed", "link bundle needs cert and doc");
  const doc = verifyIdentityDoc(bundle.doc, opts);
  const cert = verifyDeviceCertV3(bundle.cert, { now: opts.now, identityDoc: { iss: doc.iss, ik: doc.ik, devices: doc.devices } });
  if (cert.did !== did) fail("did-mismatch", "the bundled certificate is for another device");
  if (!bytesEqual(cert.signingPublicKey, device.signingPublicKey) || !bytesEqual(cert.agreementPublicKey, device.agreementPublicKey)) {
    fail("cert-mismatch", "the bundled certificate names other keys");
  }
  let ik: IdentityKey | undefined;
  if (bundle.ik !== undefined) {
    if (typeof bundle.ik !== "string") fail("malformed", "bundle ik");
    ik = identityKeyFromSeed(b64uDecode(bundle.ik, 32));
    if (ik.userId !== doc.iss || userIdFromIk(cert.ikPublicKey) !== ik.userId) fail("issuer-mismatch", "bundled ik is not the document's");
    if (!doc.keyholders.includes(did)) fail("malformed", "a key-holding device must be in keyholders");
  }
  return { cert, doc, ...(ik ? { ik } : {}) };
}
