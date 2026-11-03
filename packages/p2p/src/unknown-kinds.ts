// Copyright 2026 Ix Infrastructure Inc.
//
// Envelopes of a kind this version doesn't know (protocol.md "Forward compatibility", core's
// rule "unknown-kind"). Core verified the envelope like any other (signature, sender, blocks, the
// replay window), and opened it; nothing in it is parsed or acted on. This logs it, and tells the
// user once (per sender and kind, a day) that a peer sent something this version can't show:
// never dropped silently, never shown as anything but that sentence. The caller commits the replay
// claim afterwards, as for every applied envelope.

import { sanitizePeerText, standsLookup, unfriendApplies, type AcceptedMessageV3 } from "@peer2peer/core/v3";
import type { App } from "./app.js";
import { fromOf, makeEvent, type NewEvent } from "./inbound.js";
import { sessKey } from "./state.js";

/** One notice per (sender, kind) in this long. */
export const UNKNOWN_KIND_NOTICE_MS = 24 * 3600 * 1000;
/** Notices remembered at most (the oldest go first). */
export const UNKNOWN_KIND_KEPT = 256;
/** At most this many notices per sender a day, whatever kinds they send (kind names are theirs to make up). */
export const UNKNOWN_KIND_PER_SENDER = 3;
/** The log line: once per (sender, kind) in this long, in this process. */
export const UNKNOWN_KIND_LOG_MS = 3600 * 1000;
const logged = new Map<string, number>();

/** Whether the user knows this sender: their own device, a friend (not unfriended), or someone who stands in a circle with them. */
async function isKnownSender(app: App, from: string): Promise<boolean> {
  if (from === app.userId) return true;
  const unfriends = await app.store.listUnfriends();
  const friends = (await app.store.listFriendships()).filter((f) => (f.inviter === from || f.invitee === from) && !unfriends.some((u) => unfriendApplies(f, u)));
  if (friends.length > 0) return true;
  const stands = await standsLookup(app.store, app.userId);
  return (await app.store.listCircles()).some((c) => c.joinedByMe && stands(from, c.cid));
}

export async function onUnknownKind(app: App, env: string, r: AcceptedMessageV3): Promise<NewEvent[]> {
  const e = r.envelope;
  const kind = sanitizePeerText((r.plaintext as { envKind?: string }).envKind ?? String(e.kind), 32);
  // Someone the user doesn't know gets nothing: no notice, no log line, and their device cert isn't kept
  // (a stranger can't use an unknown kind to reach the user, fill the store or flood the log).
  if (!(await isKnownSender(app, e.from))) return [];
  await app.store.putDeviceCert({ userId: r.sender.iss, did: r.sender.did, exp: r.sender.exp, jws: r.sender.jws });
  const from = await fromOf(app, r);
  const key = `${e.from}|${kind}`;
  const now = Date.now();
  if (now - (logged.get(key) ?? -Infinity) >= UNKNOWN_KIND_LOG_MS) {
    logged.set(key, now);
    if (logged.size > UNKNOWN_KIND_KEPT) logged.delete(logged.keys().next().value as string);
    app.io.err(`p2p: ${from.address} sent a "${kind}" envelope this version doesn't understand: update to see it`);
  }
  const fresh = await app.state.update("unknownKinds", (cur = {}) => {
    if (now - (cur[key] ?? -Infinity) < UNKNOWN_KIND_NOTICE_MS) return { result: false };
    const recent = Object.entries(cur).filter(([k, at]) => k.startsWith(`${e.from}|`) && now - at < UNKNOWN_KIND_NOTICE_MS).length;
    if (recent >= UNKNOWN_KIND_PER_SENDER) return { result: false };
    const kept = Object.entries({ ...cur, [key]: now })
      .sort(([, a], [, b]) => b - a)
      .slice(0, UNKNOWN_KIND_KEPT);
    return { next: Object.fromEntries(kept), result: true };
  });
  if (!fresh) return [];
  // To the session it was meant for when that is one of ours (or one ours spoke to); else to no session.
  const spoke = (await app.state.get("spoke")) ?? {};
  const toSession = e.own === app.userId ? e.sid : spoke[sessKey(e.own, e.sid)];
  return [makeEvent(env, "p2p.unknown", e.ts, { from, envKind: kind, own: e.own, sid: e.sid }, toSession ? { toSession } : {})];
}
