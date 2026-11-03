// Copyright 2026 Ix Infrastructure Inc.
//
// What a peer's client understands, and the one helper every feature-gated send asks
// (docs/compatibility.md, protocol.md "Forward compatibility").
//
//  - A feature is a cap id: `receipts.v1`, `agents.v1`, `xstate.v1`, `status.tolerant.v1`, and the
//    protocol minor `proto.3.<n>` (3.1: unknown fields and kinds degrade instead of failing). The
//    exact client version is only in the opt-in identity document entry (`dinfo.client`).
//  - Where it is learnt, per device: the device's entry in its user's identity document (`dinfo`,
//    when present), else the latest status we have from any session on that device. Per session: that
//    session's live status (a front end's own caps, such as receipts.v1, are per session).
//  - peerSupports says yes only on positive evidence. No evidence is "no": a sender then leaves the
//    feature out, which every older client handles.

import { isLive, STATUS_CAP_AGENTS, STATUS_CAP_TOLERANT, STATUS_CAP_XSTATE, statusHasCap, type DeviceInfo, type IdentityView } from "@peer2peer/core/v3";
import type { App } from "./app.js";
import { sessKey, type PeerStatusRec } from "./state.js";

/** This client's protocol minor: 3.1 is forward compatibility (must-ignore, crit, unknown kinds). */
export const PROTO_MINOR = 1;
export const PROTO_CAP = `proto.3.${PROTO_MINOR}`;
/** This client redeems codes that join several circles (the bundle's `circles`, docs/protocol.md P4). */
export const CAP_INVITE_CIRCLES = "invite.circles.v1";
const PROTO_RE = /^proto\.3\.(\d{1,4})$/;

/**
 * This CLI's own: its protocol minor. Not its exact version: a status goes to everyone the roster
 * allows, and an exact version would help single out a device (and its unpatched bugs); the version
 * rides only in the opt-in identity document entry (`dinfo.client`). docs/compatibility.md.
 */
export const CLI_FEATURE_CAPS: readonly string[] = [PROTO_CAP, CAP_INVITE_CIRCLES];

/**
 * Everything this CLI itself understands (§4.3 "Status caps"), as its statuses and its identity
 * document entry (`dinfo`) advertise it. A front end adds its own (the mod's receipts.v1).
 */
export const CLI_CAPS: readonly string[] = [STATUS_CAP_TOLERANT, STATUS_CAP_AGENTS, STATUS_CAP_XSTATE, ...CLI_FEATURE_CAPS];

/** The protocol minor a cap list advertises (0: none, a client from before 3.1). */
export function protoMinor(caps: readonly string[] | undefined): number {
  let best = 0;
  for (const c of caps ?? []) {
    const m = PROTO_RE.exec(c);
    if (m) best = Math.max(best, Number(m[1]));
  }
  return best;
}

/** Features a person may care about, in words (doctor's "unavailable between you"). */
export const KNOWN_FEATURES: readonly { cap: string; what: string; session?: boolean }[] = [
  { cap: "status.tolerant.v1", what: "statuses that can grow new fields" },
  { cap: "agents.v1", what: "subagents in statuses" },
  { cap: "xstate.v1", what: "extension state (Ix footprints)" },
  { cap: "receipts.v1", what: "delivery receipts", session: true },
  { cap: PROTO_CAP, what: "forward compatibility (newer fields and kinds degrade instead of failing)" },
  { cap: CAP_INVITE_CIRCLES, what: "invite codes that join several circles" },
];

/** Where peerSupports looks: a session (its live status), a device, or every live session of the user. */
export type FeatureScope = { sid: string } | { did: string } | { all: true };

export interface FeatureSources {
  peers: Record<string, PeerStatusRec>;
  /** The user's identity document `dinfo`, when it has one. */
  dinfo?: Record<string, DeviceInfo>;
  self: { userId: string; did: string };
  now?: number;
}

/** The latest status we hold from any session on device `did` of `userId`. */
function latestFromDevice(peers: Record<string, PeerStatusRec>, userId: string, did: string): PeerStatusRec | undefined {
  let best: PeerStatusRec | undefined;
  for (const p of Object.values(peers)) if (p.own === userId && p.did === did && (!best || p.ts > best.ts)) best = p;
  return best;
}

/** The caps a device advertises: its identity document entry, else its latest status. */
export function deviceCaps(src: Pick<FeatureSources, "peers" | "dinfo">, userId: string, did: string): { caps: string[]; source: "identity" | "status" } | undefined {
  const d = src.dinfo?.[did];
  if (d) return { caps: [...d.caps], source: "identity" };
  const s = latestFromDevice(src.peers, userId, did)?.status.caps;
  return Array.isArray(s) ? { caps: [...s], source: "status" } : undefined;
}

/**
 * Whether `userId`'s client understands `feature`, from what we hold (no network):
 *  - `{sid}`: that session is live now and its status lists it (a stale status never decides: a session
 *    since restarted on an older client would reject what it doesn't know, pre-release review R2);
 *  - `{did}`: that device's identity-document entry lists it, else its latest status does;
 *  - `{all}`: every live session of theirs we know of (other than this device's own) lists it, and
 *    there is at least one (a status goes to a user: one plaintext for all their devices).
 */
export function supportsIn(src: FeatureSources, userId: string, scope: FeatureScope, feature: string): boolean {
  const now = src.now ?? Date.now();
  if ("sid" in scope) {
    const rec = src.peers[sessKey(userId, scope.sid)];
    return rec !== undefined && isLive(rec.ts, now) && statusHasCap(rec.status, feature);
  }
  if ("did" in scope) return deviceCaps(src, userId, scope.did)?.caps.includes(feature) === true;
  const live = Object.values(src.peers).filter((p) => p.own === userId && isLive(p.ts, now) && !(p.own === src.self.userId && p.did === src.self.did));
  return live.length > 0 && live.every((p) => statusHasCap(p.status, feature));
}

async function sources(app: App, userId: string): Promise<FeatureSources> {
  const view: IdentityView | undefined = await app.view(userId).catch(() => undefined);
  return { peers: (await app.state.get("peers")) ?? {}, ...(view?.head.dinfo ? { dinfo: view.head.dinfo } : {}), self: { userId: app.userId, did: app.did } };
}

/** supportsIn over this device's state: the helper every feature-gated send uses. */
export async function peerSupports(app: App, userId: string, scope: FeatureScope, feature: string): Promise<boolean> {
  return supportsIn(await sources(app, userId), userId, scope, feature);
}

export interface PeerDevice {
  did: string;
  label?: string;
  keyholder: boolean;
  /** Where the caps came from; absent when we know nothing of this device's client. */
  source?: "identity" | "status";
  client?: string;
  proto: number;
  caps: string[];
  /** When its latest status was sent (ms), if any. */
  lastSeen?: number;
}

/** A user's devices as their identity document lists them, with what each one's client understands. */
export async function peerDevices(app: App, userId: string): Promise<PeerDevice[]> {
  const view = await app.view(userId).catch(() => undefined);
  if (!view) return [];
  const src = await sources(app, userId);
  const labels = new Map<string, string>();
  for (const c of view.head.certs ?? []) {
    try {
      const p = JSON.parse(Buffer.from(c.split(".")[1] ?? "", "base64url").toString()) as { did?: unknown; label?: unknown };
      if (typeof p.did === "string" && typeof p.label === "string") labels.set(p.did, p.label);
    } catch {
      // not ours to judge here: the cert was verified when the document was
    }
  }
  return view.devices.map((did) => {
    const d = deviceCaps(src, userId, did);
    const seen = latestFromDevice(src.peers, userId, did)?.ts;
    // The exact version only from the device's own (opt-in) identity document entry.
    const client = src.dinfo?.[did]?.client;
    return {
      did,
      ...(labels.has(did) ? { label: labels.get(did) } : {}),
      keyholder: view.keyholders.includes(did),
      ...(d ? { source: d.source } : {}),
      ...(client ? { client } : {}),
      proto: protoMinor(d?.caps),
      caps: d?.caps ?? [],
      ...(seen !== undefined ? { lastSeen: seen } : {}),
    };
  });
}

/**
 * The known features one side has and the other lacks, given the caps of this client and of every
 * one of the peer's devices we know of (a feature counts for them only when all of them have it).
 */
export function unavailableBetween(mine: readonly string[], theirs: readonly (readonly string[])[]): { theyLack: string[]; weLack: string[] } {
  const all = (cap: string) => theirs.length > 0 && theirs.every((t) => t.includes(cap));
  const theyLack: string[] = [];
  const weLack: string[] = [];
  // A front end's own features (receipts.v1: the mod's, per session) aren't this client's to compare.
  for (const f of KNOWN_FEATURES.filter((x) => !x.session)) {
    if (mine.includes(f.cap) && !all(f.cap)) theyLack.push(f.cap);
    if (!mine.includes(f.cap) && theirs.length > 0 && all(f.cap)) weLack.push(f.cap);
  }
  return { theyLack, weLack };
}

/**
 * Whether what we hold of `userId`'s client shows it lacks `feature`: its latest status (any session,
 * any age) or its identity document entry lists caps, and not that one. No evidence is "no" here too:
 * this is only for telling the user something, never for deciding what to send.
 */
export async function peerLacks(app: App, userId: string, feature: string): Promise<boolean> {
  const src = await sources(app, userId);
  const dinfo = Object.values(src.dinfo ?? {});
  if (dinfo.length > 0) return dinfo.some((d) => !d.caps.includes(feature));
  let latest: PeerStatusRec | undefined;
  for (const p of Object.values(src.peers)) if (p.own === userId && (!latest || p.ts > latest.ts)) latest = p;
  const caps = latest?.status.caps;
  return Array.isArray(caps) && !caps.includes(feature);
}
