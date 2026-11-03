// Copyright 2026 Ix Infrastructure Inc.
//
// What a relay supports, from its /.well-known/p2p-relay.json (docs/compatibility.md): the frames
// it answers, its protocol minor and its features. A relay from before this listed none: it is
// taken to support the baseline (everything up to protocol 3.0), and nothing newer is asked of it.
// An older client never asks, and works with a newer relay as before.
//
//  - Cached in state (`relayInfo`) for RELAY_INFO_TTL_MS; a relay that didn't answer is asked again
//    after RELAY_INFO_RETRY_MS (and counts as baseline meanwhile).
//  - Features this client checks: `identity.lenient` (the relay stores identity documents and caps
//    that carry fields it doesn't know, under the crit rule), before it publishes an identity
//    document with device info (`dinfo`). Unknown features are kept and shown, never relied on.

import { canonicalRelayUrl } from "@peer2peer/core/v3";
import type { App } from "./app.js";
import { fetchRelayInfo } from "./relay-client.js";

export interface RelayInfoRec {
  /** When it was fetched (ms). */
  at: number;
  /** Whether the relay answered with its info. */
  ok: boolean;
  /** Its protocol minor (0: a relay from before features were listed). */
  minor: number;
  features: string[];
  frames: string[];
  software?: string;
}

export const RELAY_INFO_TTL_MS = 24 * 3600 * 1000;
export const RELAY_INFO_RETRY_MS = 3600 * 1000;
const RELAY_INFO_TIMEOUT_MS = 5000;
/** The frames every v3 relay answers (protocol 3.0). */
export const BASELINE_RELAY_FRAMES: readonly string[] = ["auth", "send", "ack", "revoke", "identity", "link-put", "link-get", "link-open"];
/** A relay that stores identity documents and caps with fields it doesn't know (the crit rule). */
export const RELAY_FEATURE_LENIENT_IDENTITY = "identity.lenient";

const strs = (v: unknown, max: number): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && /^[a-z][a-z0-9._-]{0,47}$/.test(x)).slice(0, max) : [];

/** A relay's info, from the cache or fetched; never throws (an unreachable relay is the baseline). */
export async function relayInfo(app: App, relay: string, opts: { refresh?: boolean } = {}): Promise<RelayInfoRec> {
  const url = canonicalRelayUrl(relay);
  const now = Date.now();
  const held = ((await app.state.get("relayInfo")) ?? {})[url];
  if (held && !opts.refresh && now - held.at < (held.ok ? RELAY_INFO_TTL_MS : RELAY_INFO_RETRY_MS)) return held;
  let rec: RelayInfoRec;
  try {
    const j = await fetchRelayInfo(app.transport(url), RELAY_INFO_TIMEOUT_MS, app.progress);
    const minor = typeof j?.protocolMinor === "number" && Number.isSafeInteger(j.protocolMinor) && j.protocolMinor >= 0 ? j.protocolMinor : 0;
    const sw = (j?.software as { version?: unknown } | undefined)?.version;
    rec = j
      ? { at: now, ok: true, minor, features: strs(j.features, 64), frames: strs(j.frames, 64), ...(typeof sw === "string" ? { software: sw.slice(0, 40) } : {}) }
      : { at: now, ok: false, minor: 0, features: [], frames: [] };
  } catch {
    rec = { at: now, ok: false, minor: 0, features: [], frames: [] };
  }
  await app.state.update("relayInfo", (cur = {}) => ({ next: { ...cur, [url]: rec }, result: undefined }));
  return rec;
}

/** Whether every one of `relays` lists `feature` (no relay: no). */
export async function relaysSupport(app: App, relays: readonly string[], feature: string): Promise<boolean> {
  if (relays.length === 0) return false;
  for (const r of relays) if (!(await relayInfo(app, r)).features.includes(feature)) return false;
  return true;
}
