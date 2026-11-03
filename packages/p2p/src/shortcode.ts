// Copyright 2026 Ix Infrastructure Inc.
//
// Short-code invites (docs/protocol.md P4): the pure part.
//
//  - The secret `s` is 100 random bits, as 13 bytes big-endian whose top 4
//    bits are zero. The code shows them as 20 Crockford base32 characters in
//    groups of four, `K7QM-3XPD-9TWA-HF2N-6RJC`
//    (case-insensitive; O reads as 0, I and L as 1; hyphens and spaces
//    ignored), after the relay part: `<host[:port][/path]>/<CODE>`, where the
//    relay part is the canonical relay URL without `wss://` and without a
//    trailing `/v3`.
//  - lid = b32(SHA-256("p2p/v3/invite-id|" || s))[:26]: the relay's key.
//  - The bundle is sealed with ChaCha20-Poly1305 (RFC 8439) under
//    HKDF-SHA256(ikm = s, salt = empty, info = "p2p/v3/invite-key", 32), a
//    random 12-byte nonce and aad "p2p/v3/invite|" || lid:
//    blob = b64u(nonce || ciphertext || tag). The relay holds only lid and
//    blob, so it can neither read the bundle nor substitute another: either
//    fails to open under the code.

import { createCipheriv, createDecipheriv, hkdfSync, randomBytes as nodeRandom } from "node:crypto";
import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import type { LookupFunction } from "node:net";
import { b32Encode, b64uDecode, b64uEncode, canonicalRelayUrl, relayFromLinkPart, relayLinkPart, sha256 } from "@peer2peer/core/v3";
import { CliError } from "./errors.js";

/** 100 bits, carried in 13 bytes whose top 4 bits are zero. */
export const CODE_SECRET_LEN = 13;
export const CODE_CHARS = 20;
export const INVITE_ID_PREFIX = "p2p/v3/invite-id|";
export const INVITE_KEY_INFO = "p2p/v3/invite-key";
export const INVITE_AAD_PREFIX = "p2p/v3/invite|";
export const INVITE_ADMIT_INFO = "p2p/v3/relay-admit";
/** The relay's default cap on a blob (it advertises `inviteBlobBytes`). */
export const INVITE_BLOB_MAX = 32 * 1024;
/** P4: a code lives at most 7 days. */
export const CODE_MAX_TTL_SEC = 7 * 86_400;
/** At most this many circles one code joins (`circle` plus `circles`). */
export const CODE_MAX_CIRCLES = 5;
/**
 * The web form of a code: `https://ix-infra.com/p2p/invite#<relay part>/<CODE>`. It wraps the same
 * single-use, relay-held code; the part after `#` (the secret) never reaches the web server.
 */
export const CODE_WEB_PREFIX = "https://ix-infra.com/p2p/invite#";
const CODE_WEB_HOST = "ix-infra.com";
const CODE_WEB_PATH = "/p2p/invite";
const CODE_WEB_ORIGIN = `https://${CODE_WEB_HOST}`;
/** What a web link's fragment may hold: a relay part (host, port, path) and the code. */
const CODE_FRAGMENT_RE = /^(?:[A-Za-z0-9.[\]:-]+(?:\/[A-Za-z0-9._~-]+)*\/)?[0-9A-Za-z][0-9A-Za-z-]{18,28}$/;

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const enc = new TextEncoder();

export function newCodeSecret(): Uint8Array {
  const s = new Uint8Array(nodeRandom(CODE_SECRET_LEN));
  s[0] &= 0x0f;
  return s;
}

function checkSecret(s: Uint8Array): void {
  if (!(s instanceof Uint8Array) || s.length !== CODE_SECRET_LEN || s[0] > 0x0f) throw new CliError("usage", "a code secret is 100 bits (13 bytes, top 4 bits zero)");
}

/** The 100-bit secret -> 20 Crockford base32 characters (no padding). */
export function encodeCodeChars(s: Uint8Array): string {
  checkSecret(s);
  let out = "";
  let acc = 0n;
  for (const b of s) acc = (acc << 8n) | BigInt(b);
  for (let i = CODE_CHARS - 1; i >= 0; i--) out += CROCKFORD[Number((acc >> BigInt(i * 5)) & 31n)];
  return out;
}

/** Inverse of encodeCodeChars, forgiving of case, hyphens, spaces and O/I/L. Undefined when it isn't a code. */
export function decodeCodeChars(input: string): Uint8Array | undefined {
  const c = input.toUpperCase().replace(/[\s-]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1");
  if (c.length !== CODE_CHARS) return undefined;
  let acc = 0n;
  for (const ch of c) {
    const v = CROCKFORD.indexOf(ch);
    if (v < 0) return undefined;
    acc = (acc << 5n) | BigInt(v);
  }
  const out = new Uint8Array(CODE_SECRET_LEN);
  for (let i = CODE_SECRET_LEN - 1; i >= 0; i--) {
    out[i] = Number(acc & 0xffn);
    acc >>= 8n;
  }
  return out;
}

/** `K7QM3XPD9TWAHF2N6RJC` -> `K7QM-3XPD-9TWA-HF2N-6RJC`. */
export function groupCode(chars: string): string {
  return chars.match(/.{1,4}/g)!.join("-");
}

/** The relay part of a short code: the canonical URL without `wss://`, and without a trailing `/v3`. */
export function codeRelayPart(relay: string): string {
  const p = relayLinkPart(relay);
  const i = p.indexOf("/");
  return p.slice(i) === "/v3" ? p.slice(0, i) : p;
}

/** `<relay part>/<K7QM-3XPD-9TWA-HF2N-6RJC>`. */
export function formatShortCode(relay: string, s: Uint8Array): string {
  return `${codeRelayPart(relay)}/${groupCode(encodeCodeChars(s))}`;
}

/** The code as a web link: `https://ix-infra.com/p2p/invite#<relay part>/<CODE>`. */
export function codeWebLink(short: string): string {
  return CODE_WEB_PREFIX + short;
}

/**
 * The code inside a web link, or undefined when `input` isn't one. Strict: https only, host exactly
 * ix-infra.com (no port, no user info), path exactly /p2p/invite, no query, and a fragment that is a
 * relay part and a code. Anything else that looks like a URL is refused, never guessed at.
 */
export function codeFromWebLink(input: string): string | undefined {
  const t = input.trim();
  // A URL has a scheme and `//`; a relay part with a port (`relay.example:8443/…`) does not.
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) return undefined;
  // Never left to URL normalisation: whitespace or control characters anywhere are refused.
  if (/[\s\u0000-\u001f\u007f]/.test(t)) throw new CliError("usage", "that link has spaces or control characters in it: copy it again, whole");
  // The other links have their own commands: say which, rather than "not an invite".
  if (/^(?:https:\/\/(?:ix-infra\.com\/p2p|peer2peer\.dev)\/i#|p2p:\/\/invite\/)/i.test(t)) throw new CliError("usage", "that is a long invite link: use `p2p accept <link>`");
  if (/^(?:https:\/\/(?:ix-infra\.com\/p2p|peer2peer\.dev)\/c#|p2p:\/\/circle\/)/i.test(t)) throw new CliError("usage", "that is a circle link: use `p2p circle join <link>`");
  const refuse = (why: string) => new CliError("usage", `that is not a Peer2Peer invite link (${why}): it looks like ${CODE_WEB_PREFIX}relay.example/K7QM-3XPD-9TWA-HF2N-6RJC`);
  let u: URL;
  try {
    u = new URL(t);
  } catch {
    throw refuse("not a URL");
  }
  if (u.protocol !== "https:") throw refuse("only https links");
  if (u.username !== "" || u.password !== "" || u.port !== "" || u.hostname !== CODE_WEB_HOST || !t.toLowerCase().startsWith(`https://${CODE_WEB_HOST}/`)) throw refuse(`the host must be ${CODE_WEB_HOST}`);
  if (u.pathname !== CODE_WEB_PATH) throw refuse(`the path must be ${CODE_WEB_PATH}`);
  if (u.search !== "" || t.includes("?")) throw refuse("a query string");
  // The raw text, not the parsed URL: `/p2p/./invite`, `/x/../p2p/invite`, `%2e` and the like are
  // refused rather than normalised into the one path that is accepted.
  if (t.slice(0, CODE_WEB_ORIGIN.length).toLowerCase() !== CODE_WEB_ORIGIN || !t.slice(CODE_WEB_ORIGIN.length).startsWith(`${CODE_WEB_PATH}#`)) {
    throw refuse(`the path must be ${CODE_WEB_PATH}`);
  }
  const frag = t.slice(CODE_WEB_ORIGIN.length + CODE_WEB_PATH.length + 1);
  if (frag === "" || !CODE_FRAGMENT_RE.test(frag)) throw refuse("the part after # isn't an invite code");
  return frag;
}

/**
 * Parses `host[:port][/path]/CODE` (an optional `p2p join ` or `wss://`
 * prefix is ignored) or a bare CODE. `relay` is undefined for a bare code.
 */
/**
 * What a private-relay refusal says: what it is, and exactly what to do about it. `what` names the
 * thing ("code's relay", "invite's relay"); `detail` the address it resolved to; `code` adds the
 * Claude Code form for codes.
 */
export function privateRelayMessage(what: string, host: string, opts: { detail?: string; code?: boolean } = {}): string {
  const how = opts.code ? "run the same command again with --allow-private-relay (in Claude Code: /peers join --allow-private-relay <code>)" : "run the same command again with --allow-private-relay";
  return `the ${what} ${host}${opts.detail ? ` (${opts.detail})` : ""} is on a private network (for example Tailscale or a LAN). If you trust the person who sent it, ${how}, or set P2P_ALLOW_PRIVATE_RELAY=1. Your own relays never need this`;
}

/** Is `relay` one of `own` (the user's own relays: never refused or guarded, whatever their address)? */
export function isOwnRelay(relay: string, own: readonly string[]): boolean {
  try {
    const c = canonicalRelayUrl(relay);
    return own.some((r) => {
      try {
        return canonicalRelayUrl(r) === c;
      } catch {
        return false;
      }
    });
  } catch {
    return false;
  }
}

export function parseShortCode(input: string, opts: { allowPrivate?: boolean; own?: readonly string[] } = {}): { secret: Uint8Array; relay?: string } {
  let t = (typeof input === "string" ? input : "").trim().replace(/^p2p\s+join\s+/i, "").trim();
  // Pasted with the shell quoting the web page adds (`p2p join 'https://…'`): one pair of quotes is dropped.
  const q = /^(['"])(.*)\1$/s.exec(t);
  if (q) t = q[2].trim();
  // The web link wraps the same code (codeFromWebLink is strict); wss:// is a relay part's own prefix.
  if (!/^wss:\/\//i.test(t)) t = codeFromWebLink(t) ?? t;
  t = t.replace(/^wss:\/\//i, "");
  t = t.replace(/\/+$/, "");
  const slash = t.lastIndexOf("/");
  const codePart = slash >= 0 ? t.slice(slash + 1) : t;
  const secret = decodeCodeChars(codePart);
  if (!secret) throw new CliError("usage", "that is not an invite code (it looks like relay.example/K7QM-3XPD-9TWA-HF2N-6RJC)");
  if (slash < 0) return { secret };
  let relay: string;
  try {
    relay = relayFromLinkPart(t.slice(0, slash));
  } catch {
    throw new CliError("usage", "the code's relay part is not a relay host");
  }
  // A code from someone else connects to its relay before anyone says yes (to open it): a loopback,
  // link-local or private host would let it reach this machine or the local network. A team relay on
  // a private network is opted into (`p2p join --allow-private-relay`, or P2P_ALLOW_PRIVATE_RELAY=1).
  // The user's own relays are theirs to choose (a team relay on Tailscale, say): never refused.
  const host = new URL(relay).hostname;
  if (!opts.allowPrivate && isPrivateRelayHost(host) && !isOwnRelay(relay, opts.own ?? [])) {
    throw new CliError("private_relay", privateRelayMessage("code's relay", host, { code: true }));
  }
  return { secret, relay };
}

/** The code as typed, rebuilt from its parsed parts (never the raw input): `<relay part>/<CODE>`, or the bare CODE. */
export function canonicalShortCode(p: { secret: Uint8Array; relay?: string }): string {
  return p.relay ? formatShortCode(p.relay, p.secret) : groupCode(encodeCodeChars(p.secret));
}

/** An IPv4 address's four octets, or undefined. */
function parseV4(x: string): number[] | undefined {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(x);
  if (!m) return undefined;
  const o = m.slice(1).map(Number);
  return o.every((n) => n <= 255) ? o : undefined;
}

/** An IPv6 address's eight 16-bit groups (a trailing dotted quad and a %zone allowed), or undefined. */
function parseV6(x: string): number[] | undefined {
  let h = x.replace(/%.*$/, "");
  const tail = /^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(h);
  if (tail) {
    const o = parseV4(tail[2]);
    if (!o) return undefined;
    h = `${tail[1]}${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }
  const halves = h.split("::");
  if (halves.length > 2) return undefined;
  const part = (p: string) => (p === "" ? [] : p.split(":"));
  const head = part(halves[0]);
  const rest = halves.length === 2 ? part(halves[1]) : [];
  const fill = halves.length === 2 ? 8 - head.length - rest.length : 0;
  if (fill < (halves.length === 2 ? 1 : 0)) return undefined;
  const groups = [...head, ...Array(fill).fill("0"), ...rest];
  if (groups.length !== 8 || !groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return undefined;
  return groups.map((g) => parseInt(g, 16));
}

/**
 * IPv4 that is not a public unicast address: 0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12,
 * 192.168/16, 198.18/15 (benchmarking), 224/4 (multicast) and 240/4 (reserved, with 255.255.255.255).
 */
function v4Private(o: number[]): boolean {
  const [a, b] = o;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19))
  );
}

/**
 * An IP literal (v4 or v6, no brackets) that is loopback, link-local, private, multicast or otherwise
 * not public unicast, including IPv6 forms that carry such an IPv4 address: IPv4-compatible
 * (`::/96`, refused whole), IPv4-mapped (`::ffff:0:0/96`), IPv4-translated (`::ffff:0:0:0/96`), Teredo
 * (`2001::/32`, refused whole), NAT64 (`64:ff9b::/96`, and the local-use
 * `64:ff9b:1::/48`) and 6to4 (`2002::/16`); and fc00::/7, fe80::/10, fec0::/10 and ff00::/8.
 * Not an IP literal: false (names are checked by isPrivateRelayHost, and when resolved, by the lookup).
 */
export function isPrivateAddress(ip: string): boolean {
  const o = parseV4(ip);
  if (o) return v4Private(o);
  const g = parseV6(ip.toLowerCase());
  if (!g) return false;
  const v4of = (hi: number, lo: number) => [hi >> 8, hi & 255, lo >> 8, lo & 255];
  if (g.slice(0, 6).every((x) => x === 0)) return true;
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return v4Private(v4of(g[6], g[7]));
  // IPv4-translated (`::ffff:0:a.b.c.d`, ::ffff:0:0/96).
  if (g.slice(0, 4).every((x) => x === 0) && g[4] === 0xffff && g[5] === 0) return v4Private(v4of(g[6], g[7]));
  // Teredo (2001::/32): the client address inside is obfuscated; refused whole.
  if (g[0] === 0x2001 && g[1] === 0) return true;
  if (g[0] === 0x64 && g[1] === 0xff9b) return g[2] === 1 || v4Private(v4of(g[6], g[7]));
  if (g[0] === 0x2002) return v4Private(v4of(g[1], g[2]));
  return (g[0] & 0xfe00) === 0xfc00 || (g[0] & 0xffc0) === 0xfe80 || (g[0] & 0xffc0) === 0xfec0 || (g[0] & 0xff00) === 0xff00;
}

/**
 * A relay host a code may not name without the opt-in: `localhost`, `*.localhost`, `*.local`, and
 * every IP literal isPrivateAddress refuses. `host` is a URL hostname (IPv6 in brackets). A DNS
 * name that resolves to such an address is caught when the code's relay is dialed (privateGuardLookup).
 */
export function isPrivateRelayHost(host: string): boolean {
  let h = host.toLowerCase().replace(/\.$/, "");
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (h === "localhost" || h.endsWith(".localhost") || h === "local" || h.endsWith(".local")) return true;
  return isPrivateAddress(h);
}

/**
 * Refuses relays named by a link (a long invite's or a circle link's) whose host isPrivateRelayHost
 * refuses, unless `allow` (--allow-private-relay, P2P_ALLOW_PRIVATE_RELAY=1): the link's relays are
 * dialed before anyone says yes. Names that aren't URLs are left to the link's own checks.
 */
export function refusePrivateRelays(relays: readonly string[], what: string, allow: boolean, opts: { code?: boolean } = {}): void {
  if (allow) return;
  for (const r of relays) {
    let host: string;
    try {
      host = new URL(r).hostname;
    } catch {
      continue;
    }
    if (isPrivateRelayHost(host)) {
      throw new CliError("private_relay", privateRelayMessage(`${what}'s relay`, host, opts));
    }
  }
}

/**
 * Resolves each relay's dialed host once, up front, for a clear error before anything is accepted;
 * a name that doesn't resolve is skipped (the connection fails on its own). The connections
 * themselves still go through privateGuardLookup (App.guardRelays): this only says it early.
 */
export async function refusePrivateResolved(
  relays: readonly { relay: string; dial: string }[],
  what: string,
  opts: { code?: boolean } = {},
  resolve: Resolver = dnsLookup as unknown as Resolver,
): Promise<void> {
  for (const { relay, dial } of relays) {
    let host: string;
    try {
      host = new URL(dial).hostname;
    } catch {
      continue;
    }
    if (host.startsWith("[") || parseV4(host) || parseV6(host)) continue; // literals: refusePrivateRelays
    const addrs = await new Promise<LookupAddress[]>((r) => resolve(host, { all: true }, (err, a) => r(err ? [] : a)));
    const bad = addrs.find((a) => isPrivateAddress(a.address));
    if (bad) {
      throw new CliError("private_relay", privateRelayMessage(`${what}'s relay`, new URL(relay).hostname, { ...opts, detail: `it resolves to ${bad.address}` }));
    }
  }
}

/** What privateGuardLookup's error says, so a caller can tell it from an unreachable relay. */
export const PRIVATE_RESOLVE_MARK = "resolves to a loopback, link-local or private address";

type Resolver = (host: string, opts: { all: true; family?: number }, cb: (err: NodeJS.ErrnoException | null, addrs: LookupAddress[]) => void) => void;

/**
 * A `lookup` for the socket that dials a code's relay: the name is resolved once, here, and refused
 * when any address it resolves to is one isPrivateAddress refuses (`127.0.0.1.nip.io`,
 * `localtest.me`, a rebinding name). The socket connects to the address handed back, so nothing is
 * resolved again after the check. IP literals never reach a lookup: the parser checked those.
 */
export function privateGuardLookup(resolve: Resolver = dnsLookup as unknown as Resolver): LookupFunction {
  return (hostname, options, callback) => {
    const family = typeof options === "object" && options !== null && typeof options.family === "number" ? options.family : undefined;
    resolve(hostname, { all: true, ...(family ? { family } : {}) }, (err, addrs) => {
      if (err) return (callback as (e: NodeJS.ErrnoException | null, a: string, f: number) => void)(err, "", 0);
      const bad = addrs.find((a) => isPrivateAddress(a.address));
      if (bad || addrs.length === 0) {
        const e: NodeJS.ErrnoException = new Error(bad ? `${hostname} ${PRIVATE_RESOLVE_MARK} (${bad.address})` : `${hostname} has no address`);
        e.code = bad ? "EP2PPRIVATE" : "ENOTFOUND";
        return (callback as (e: NodeJS.ErrnoException | null, a: string, f: number) => void)(e, "", 0);
      }
      if (typeof options === "object" && options !== null && options.all) return (callback as unknown as (e: null, a: LookupAddress[]) => void)(null, addrs);
      (callback as (e: null, a: string, f: number) => void)(null, addrs[0].address, addrs[0].family);
    });
  };
}

/** lid = b32(H("p2p/v3/invite-id|" || s))[:26]. */
export function inviteLid(s: Uint8Array): string {
  checkSecret(s);
  const pre = enc.encode(INVITE_ID_PREFIX);
  const buf = new Uint8Array(pre.length + s.length);
  buf.set(pre);
  buf.set(s, pre.length);
  return b32Encode(sha256(buf)).slice(0, 26);
}

function inviteKey(s: Uint8Array): Buffer {
  return Buffer.from(hkdfSync("sha256", s, new Uint8Array(0), enc.encode(INVITE_KEY_INFO), 32));
}

/**
 * Members-only relays: the key a redeemer presents at auth (`auth.admit`). The inviter's
 * `invite-put` carries only its hash, so the relay learns the key when it is used, and only
 * someone who holds the code can use it.
 */
export function inviteAdmitKey(s: Uint8Array): string {
  checkSecret(s);
  return b64uEncode(new Uint8Array(hkdfSync("sha256", s, new Uint8Array(0), enc.encode(INVITE_ADMIT_INFO), 32)));
}

/** What `invite-put` carries: b64u(SHA-256(key)). */
export function inviteAdmitHash(key: string): string {
  return b64uEncode(sha256(b64uDecode(key, 32)));
}

const aad = (lid: string) => enc.encode(INVITE_AAD_PREFIX + lid);

/** Seals `bundle` (JSON) under the code: b64u(nonce || ciphertext || tag). */
export function sealInviteBundle(s: Uint8Array, bundle: unknown): string {
  const lid = inviteLid(s);
  const nonce = nodeRandom(12);
  const pt = Buffer.from(JSON.stringify(bundle), "utf8");
  const c = createCipheriv("chacha20-poly1305", inviteKey(s), nonce, { authTagLength: 16 });
  c.setAAD(aad(lid), { plaintextLength: pt.length });
  const ct = Buffer.concat([c.update(pt), c.final()]);
  return b64uEncode(new Uint8Array(Buffer.concat([nonce, ct, c.getAuthTag()])));
}

/** Opens a blob sealed under `s`; throws `code_invalid` if it was sealed under anything else, or altered. */
export function openInviteBundle(s: Uint8Array, blob: string): unknown {
  const bad = () => new CliError("code_invalid", "what the relay returned doesn't open under this code: it was altered or swapped (nothing was accepted)");
  let raw: Uint8Array;
  try {
    raw = b64uDecode(blob);
  } catch {
    throw bad();
  }
  if (raw.length < 12 + 16 + 2) throw bad();
  const nonce = raw.subarray(0, 12);
  const tag = raw.subarray(raw.length - 16);
  const ct = raw.subarray(12, raw.length - 16);
  try {
    const d = createDecipheriv("chacha20-poly1305", inviteKey(s), nonce, { authTagLength: 16 });
    d.setAAD(aad(inviteLid(s)), { plaintextLength: ct.length });
    d.setAuthTag(tag);
    const pt = Buffer.concat([d.update(ct), d.final()]).toString("utf8");
    return JSON.parse(pt) as unknown;
  } catch {
    throw bad();
  }
}

/** The sealed bundle (version 1). */
export interface InviteBundle {
  v: 1;
  /** The invite JWS (§3.1): ik, relays, identity document and contact cap. */
  invite: string;
  /** The (first) circle the code joins: its head and (when it fits) the chain from version 1. */
  circle?: { head: string; chain?: string[] };
  /**
   * More circles the code joins (protocol 3.1, at most CODE_MAX_CIRCLES - 1): heads only, so the bundle
   * fits the relay's blob cap; the inviter sends each chain when it adds the redeemer. A client from
   * before this field ignores it (the bundle is parsed field by field) and joins only `circle`: an
   * accepted downgrade, so it isn't critical.
   */
  circles?: { head: string }[];
}

export function parseInviteBundle(v: unknown): InviteBundle {
  const o = v as Record<string, unknown>;
  const bad = () => new CliError("code_invalid", "the invite under this code is malformed");
  if (typeof o !== "object" || o === null || o.v !== 1 || typeof o.invite !== "string") throw bad();
  const out: InviteBundle = { v: 1, invite: o.invite };
  if (o.circle !== undefined) {
    const c = o.circle as Record<string, unknown>;
    if (typeof c !== "object" || c === null || typeof c.head !== "string") throw bad();
    if (c.chain !== undefined && (!Array.isArray(c.chain) || c.chain.some((x) => typeof x !== "string") || c.chain.length > 512)) throw bad();
    out.circle = { head: c.head, ...(c.chain ? { chain: c.chain as string[] } : {}) };
  }
  if (o.circles !== undefined) {
    const cs = o.circles;
    if (!out.circle || !Array.isArray(cs) || cs.length > CODE_MAX_CIRCLES - 1 || cs.some((c) => typeof c !== "object" || c === null || typeof (c as Record<string, unknown>).head !== "string")) throw bad();
    if (cs.length > 0) out.circles = cs.map((c) => ({ head: (c as { head: string }).head }));
  }
  return out;
}
