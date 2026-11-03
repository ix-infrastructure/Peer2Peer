// Copyright 2026 Ix Infrastructure Inc.
//
// Envelope replay protection (draft 2, D6 and D7):
//  - a timestamp window that tolerates late delivery: ts may be up to 10 min
//    in the future (skew) and up to 24h + 10 min in the past (the relay's
//    24h store-and-replay window plus skew). v3 widens the past bound to
//    7d + 10 min (REPLAY_MAX_AGE_MS_V3, docs/protocol.md §4.4);
//  - a persisted IPsec/DTLS-style sliding anti-replay window per
//    (fdid, own, sid): the highest accepted seq H plus a bitmap of the last
//    W = 512 seqs. seq > H is accepted (sliding the window); H - W < seq <= H
//    is accepted once (its bit must be unset); seq <= H - W is rejected as
//    seq-too-old. Reordered delivery is therefore fine, and every seq is
//    accepted at most once;
//  - an LRU of the last 10k nonces per sender device, as defence in depth.
//
// checkReplay() and recordReplay() are pure. The TrustStore applies them as
// one atomic check-and-record (TrustStore.admitReplay) once the sender's
// signature has verified, so only authentic sender traffic touches the state
// and concurrent deliveries can't both pass. mergeReplay() is commutative and
// idempotent (OR of bitmaps aligned to the larger H), so records written by
// different processes combine without losing an accepted seq.

import { b64uDecode, b64uEncode } from "./encoding.js";
import type { RejectReason } from "./errors.js";

/** How far in the future an envelope's ts may be (clock skew). */
export const REPLAY_FUTURE_SKEW_MS = 10 * 60 * 1000;
/** v2: how old an envelope's ts may be: the relay's 24h replay store plus skew. */
export const REPLAY_MAX_AGE_MS = 24 * 60 * 60 * 1000 + REPLAY_FUTURE_SKEW_MS;
/**
 * v3 (docs/protocol.md §4.4): the relays' 7-day store plus skew. Replay
 * windows must also be retained at least this long after their last admit.
 */
export const REPLAY_MAX_AGE_MS_V3 = 7 * 24 * 60 * 60 * 1000 + REPLAY_FUTURE_SKEW_MS;
export const NONCE_LRU_SIZE = 10_000;
/** Anti-replay window size in seqs (a multiple of 8). */
export const REPLAY_WINDOW = 512;
const WINDOW_BYTES = REPLAY_WINDOW / 8;

/**
 * Sliding window for one session: `h` is the highest accepted seq and `bits`
 * is b64u of a REPLAY_WINDOW-bit map in which bit i stands for seq h - i.
 */
export interface SeqWindow {
  h: number;
  bits: string;
}

/** Replay state for one sender device (fdid). */
export interface ReplayRecord {
  /** Accepted nonces, oldest first, at most NONCE_LRU_SIZE. */
  nonces: string[];
  /** Anti-replay windows, keyed by sessionKey(own, sid). */
  windows: Record<string, SeqWindow>;
}

/** A session is identified by (owner, sid). */
export function sessionKey(own: string, sid: string): string {
  return JSON.stringify([own, sid]);
}

export interface ReplayFields {
  own: string;
  sid: string;
  seq: number;
  ts: number;
  n: string;
}

export type ReplayVerdict = { reason: RejectReason; message: string } | undefined;

function getBit(bits: Uint8Array, i: number): boolean {
  return (bits[i >> 3] & (1 << (i & 7))) !== 0;
}

function setBit(bits: Uint8Array, i: number): void {
  bits[i >> 3] |= 1 << (i & 7);
}

/** Bit i moves to i + shift; bits shifted past the window drop off. */
function shifted(bits: Uint8Array, shift: number): Uint8Array {
  const out = new Uint8Array(WINDOW_BYTES);
  if (shift >= REPLAY_WINDOW) return out;
  for (let i = 0; i + shift < REPLAY_WINDOW; i++) if (getBit(bits, i)) setBit(out, i + shift);
  return out;
}

function decodeBits(w: SeqWindow): Uint8Array {
  return b64uDecode(w.bits, WINDOW_BYTES);
}

/** The window's verdict for `seq`, without the timestamp or nonce checks. */
export function checkSeq(seq: number, w: SeqWindow | undefined): ReplayVerdict {
  if (!w || seq > w.h) return undefined;
  const i = w.h - seq;
  if (i >= REPLAY_WINDOW) {
    return { reason: "seq-too-old", message: `seq ${seq} is at or below ${w.h} - ${REPLAY_WINDOW}` };
  }
  if (getBit(decodeBits(w), i)) return { reason: "replayed-seq", message: `seq ${seq} already accepted` };
  return undefined;
}

/** The window after accepting `seq` (which checkSeq must have allowed). */
export function advanceWindow(seq: number, w: SeqWindow | undefined): SeqWindow {
  if (!w || seq > w.h) {
    const bits = w ? shifted(decodeBits(w), seq - w.h) : new Uint8Array(WINDOW_BYTES);
    setBit(bits, 0);
    return { h: seq, bits: b64uEncode(bits) };
  }
  const bits = decodeBits(w);
  setBit(bits, w.h - seq);
  return { h: w.h, bits: b64uEncode(bits) };
}

/** OR of two windows after aligning both to the larger h. */
export function mergeWindows(a: SeqWindow | undefined, b: SeqWindow | undefined): SeqWindow | undefined {
  if (!a) return b;
  if (!b) return a;
  const h = Math.max(a.h, b.h);
  const x = shifted(decodeBits(a), h - a.h);
  const y = shifted(decodeBits(b), h - b.h);
  for (let i = 0; i < WINDOW_BYTES; i++) x[i] |= y[i];
  return { h, bits: b64uEncode(x) };
}

/**
 * `maxAgeMs` is the oldest acceptable ts: REPLAY_MAX_AGE_MS (v2, the default)
 * or REPLAY_MAX_AGE_MS_V3.
 */
export function checkReplay(
  p: ReplayFields,
  rec: ReplayRecord | undefined,
  nowMs: number,
  maxAgeMs: number = REPLAY_MAX_AGE_MS,
): ReplayVerdict {
  if (p.ts > nowMs + REPLAY_FUTURE_SKEW_MS) {
    return { reason: "stale-timestamp", message: `ts ${p.ts} is more than 10 min ahead of ${nowMs}` };
  }
  if (p.ts < nowMs - maxAgeMs) {
    return { reason: "stale-timestamp", message: `ts ${p.ts} is older than ${maxAgeMs} ms before ${nowMs}` };
  }
  // The seq window is the primary replay defence; the nonce LRU backs it up.
  const seq = checkSeq(p.seq, rec?.windows[sessionKey(p.own, p.sid)]);
  if (seq) return seq;
  if (rec?.nonces.includes(p.n)) return { reason: "replayed-nonce", message: `nonce ${p.n} already seen` };
  return undefined;
}

/** The state after accepting `p`. */
export function recordReplay(p: ReplayFields, rec: ReplayRecord | undefined): ReplayRecord {
  const k = sessionKey(p.own, p.sid);
  return mergeReplay(rec, { nonces: [p.n], windows: { [k]: advanceWindow(p.seq, rec?.windows[k]) } });
}

/** Union of nonces (oldest first, capped) and the OR-merge of every window. */
export function mergeReplay(a: ReplayRecord | undefined, b: ReplayRecord): ReplayRecord {
  const seen = new Set(a?.nonces ?? []);
  const nonces = [...(a?.nonces ?? []), ...b.nonces.filter((n) => !seen.has(n) && (seen.add(n), true))];
  if (nonces.length > NONCE_LRU_SIZE) nonces.splice(0, nonces.length - NONCE_LRU_SIZE);
  const windows: Record<string, SeqWindow> = { ...(a?.windows ?? {}) };
  for (const [k, w] of Object.entries(b.windows)) windows[k] = mergeWindows(windows[k], w)!;
  return { nonces, windows };
}
