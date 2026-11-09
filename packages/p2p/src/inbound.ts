// Copyright 2026 Ix Infrastructure Inc.
//
// Every envelope a relay delivers goes through here, whichever command is
// connected: verifyIncomingV3 (the §4 receive chain, including the replay
// window that drops the copies other relays deliver), then the effect of the
// accepted kind, and finally zero or more events appended to the event log
// that `p2p watch` prints from. Keeping processing apart from printing means
// a message picked up by `p2p ls` still reaches the session's watcher.

import { randomBytes } from "node:crypto";
import { hostname } from "node:os";
import { processStartMs } from "./procstart.js";
import { isTransient } from "./transient.js";
export { isTransient } from "./transient.js";
import { decodeEnvelopeV3, jwsHash, P2PError, sanitizePeerText, verifyIncomingV3, type AcceptedMessageV3, type ReplayClaim } from "@peer2peer/core/v3";
import type { App } from "./app.js";
import { answerDeferredWants, onCircleEnvelope } from "./circle-ops.js";
import { onSessionEnvelope } from "./sessions.js";
import { recordEvents } from "./history.js";
import { onReceipt } from "./receipts.js";
import { onUnknownKind } from "./unknown-kinds.js";
import { onContact, onUnfriendKind } from "./social.js";
import { importSync } from "./sync.js";
import { finishCodeJoins } from "./codes.js";
import { alertForeignRotations, retryRotationJoins } from "./rotation.js";
import type { EventRec } from "./state.js";

/** Rejections that only mean "already handled" (another relay's copy). */
const DUPLICATE = new Set(["replayed-seq", "replayed-nonce"]);

// Replay claims (core IncomingContextV3.replayClaim): an envelope enters the replay window only
// once it was applied, so a crash in between can't make its redelivery a "replayed" drop.
// A claim is alive while the attempt holding it runs: in this process, while its token is
// in flight; in another process on this machine, while that process lives; from another
// machine (a shared home), until the claim's TTL.
const HOST = hostname();
/** When this process started (ms). */
const STARTED = Math.round(Date.now() - process.uptime() * 1000);
/** Start times are compared to the second (ps prints seconds), with room for clock rounding. */
const START_SLACK_MS = 2500;
const PROCESS_TOKEN = randomBytes(9).toString("base64url");
let attempts = 0;
const inFlight = new Set<string>();
/** Attempts running now, by token, with their envelope (abandonInFlight). */
const running = new Map<string, { app: App; env: string }>();
/** Attempts given up because this process is exiting with them still running. */
const abandoned = new Set<string>();

/**
 * The command is exiting with these attempts still running (its close waited CLOSE_GRACE_MS):
 * their claims are released now, without counting an attempt, and they apply nothing more. Left
 * as they were, each exit counted an attempt against the envelope, and three short commands cut
 * off in a row gave a legitimate envelope up unapplied (pre-release review M-A). If an attempt had written
 * some effects already, the redelivery applies the envelope again: events are deduplicated by id,
 * as after a crash between applying and committing (review M2).
 */
export async function abandonInFlight(app: App): Promise<number> {
  let n = 0;
  for (const [token, a] of running) {
    if (a.app !== app || abandoned.has(token)) continue;
    abandoned.add(token);
    n++;
    try {
      const p = decodeEnvelopeV3(a.env).payload;
      await app.store.releaseReplay(p.fdid, p, token, { uncount: true });
    } catch {
      // Malformed (it would never have been claimed), or the store is unwritable: the claim's
      // holder is gone in a moment either way, and the next attempt takes it over.
    }
  }
  return n;
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** Liveness only on this machine (never age: pre-release re-review M-1); another host's claim: the TTL decides. */
function claimAlive(c: ReplayClaim): boolean | undefined {
  if (c.host !== HOST) return undefined;
  if (c.pid === process.pid && (c.started === undefined || Math.abs(c.started - STARTED) < START_SLACK_MS)) return inFlight.has(c.token);
  if (!pidAlive(c.pid)) return false;
  // review L-C: a pid can be reused; it is the holder only if it started when the holder did.
  if (c.started === undefined) return true;
  const started = processStartMs(c.pid);
  return started === undefined ? true : Math.abs(started - c.started) < START_SLACK_MS;
}

export type NewEvent = Omit<EventRec, "n">;

export interface EventFrom {
  userId: string;
  did: string;
  address: string;
  self: boolean;
}

export async function fromOf(app: App, r: AcceptedMessageV3): Promise<EventFrom> {
  return { userId: r.envelope.from, did: r.envelope.fdid, address: await app.addressOf(r.envelope.from), self: r.envelope.from === app.userId };
}

/** Builds an event; `id` is derived from the envelope so every process logs it once. */
export function makeEvent(env: string, kind: string, at: number, data: Record<string, unknown>, extra: Partial<NewEvent> = {}, salt = ""): NewEvent {
  return { id: `${kind}:${jwsHash(env + salt).slice(0, 22)}`, at, kind, data, ...extra };
}

/**
 * How long one envelope may take before the command goes on without it (review M-A): the attempt
 * keeps running (its claim stays alive) and counts toward the envelope's attempt limit, but a
 * short command's drain isn't spent on it. P2P_ENVELOPE_TIMEOUT_MS overrides it.
 */
export const ENVELOPE_TIMEOUT_MS = 8000;

export async function processEnvelope(app: App, env: string, relay: string): Promise<"ack" | "keep"> {
  const token = `${PROCESS_TOKEN}.${++attempts}`;
  inFlight.add(token);
  running.set(token, { app, env });
  const work = processClaimed(app, env, relay, token).finally(() => {
    inFlight.delete(token);
    running.delete(token);
    abandoned.delete(token);
  });
  const limit = Number(app.env.P2P_ENVELOPE_TIMEOUT_MS ?? "") || ENVELOPE_TIMEOUT_MS;
  let timer: NodeJS.Timeout | undefined;
  const late = new Promise<"timeout">((r) => {
    timer = setTimeout(() => r("timeout"), limit);
    timer.unref();
  });
  try {
    const v = await Promise.race([work, late]);
    if (v !== "timeout") return v;
    // Not acked: the relay redelivers it, and the attempt still running may finish it first.
    work.catch(() => undefined);
    app.io.err(`handling an envelope from ${sanitizePeerText(relay, 200)} is taking over ${Math.round(limit / 1000)}s; going on without it`);
    return "keep";
  } finally {
    clearTimeout(timer);
  }
}

/** Envelopes this device dropped unapplied, for `p2p doctor` (a count only, never content). */
async function noteGaveUp(app: App): Promise<void> {
  await app.state.update("inbound", (cur = { gaveUp: 0 }) => ({ next: { gaveUp: cur.gaveUp + 1, at: Date.now() }, result: undefined })).catch(() => undefined);
}

async function processClaimed(app: App, env: string, relay: string, token: string): Promise<"ack" | "keep"> {
  const r = await verifyIncomingV3(env, {
    self: { userId: app.userId, did: app.did, agreementSecretKey: app.device!.agreementSecretKey, cert: app.keys!.cert },
    store: app.store,
    resolveIdentity: (u) => app.discover(u, [relay]),
    onWarning: (m) => app.io.err(`warning: ${sanitizePeerText(m, 300)}`),
    replayClaim: { claimant: { token, host: HOST, pid: process.pid, started: STARTED }, isAlive: claimAlive, retryable: isTransient },
  });
  // Another process (or another relay's copy here) is applying it right now: not acked, so the
  // relay keeps it until that one acks (or redelivers it, if that one never finishes).
  if (!r.ok && r.reason === "replay-in-progress") return "keep";
  if (!r.ok && r.reason === "gave-up") {
    app.io.err(`gave-up: an envelope from ${sanitizePeerText(relay, 200)} failed every attempt; dropped unapplied (see \`p2p doctor\`)`);
    await noteGaveUp(app);
    return "ack";
  }
  if (!r.ok && r.reason === "seq-too-old") {
    // Below the replay window: a duplicate, or an envelope that arrived after more than 512 later
    // ones from the same session. Either way it can't be told apart from a replay, so it is acked
    // (it would only come back), but counted for `p2p doctor` (review M1): never silently.
    await app.state.update("inbound", (cur = { gaveUp: 0 }) => ({ next: { ...cur, tooOld: (cur.tooOld ?? 0) + 1, at: Date.now() }, result: undefined })).catch(() => undefined);
    return "ack";
  }
  if (!r.ok) {
    // Core messages can quote raw envelope fields: one line, sanitized (review M2).
    if (!DUPLICATE.has(r.reason)) app.io.err(`rejected an envelope from ${sanitizePeerText(relay, 200)}: ${sanitizePeerText(r.reason, 64)}: ${sanitizePeerText(r.message, 300)}`);
    return "ack";
  }
  // Abandoned while it was being verified (and claimed): give the claim back, uncounted.
  if (abandoned.has(token)) {
    await r.releaseReplay?.({ uncount: true }).catch(() => undefined);
    return "keep";
  }
  try {
    const events = await dispatch(app, env, r, relay);
    if (abandoned.has(token)) {
      await r.releaseReplay?.({ uncount: true }).catch(() => undefined);
      return "keep";
    }
    const added = await app.state.addEvents(events);
    // Message history (history.ts): the messages just logged, once each (a redelivery adds none).
    await recordEvents(app, added);
  } catch (e) {
    const what = `applying ${sanitizePeerText(r.envelope.kind, 40)} from ${r.envelope.from} failed: ${sanitizePeerText((e as Error).message, 300)}`;
    if (!(e instanceof P2PError) && isTransient(e)) {
      // This command closing, a lock timeout, a full disk: give the claim up unrecorded and don't
      // ack, so it is applied in full on a redelivery (review L-2), within the attempt limit.
      app.io.err(`${what} (attempt ${r.attempt ?? 1}; kept for a retry)`);
      // Cut off by this process exiting: not an attempt that failed (pre-release review M-A).
      await r.releaseReplay?.({ uncount: abandoned.has(token) }).catch(() => undefined);
      return "keep";
    }
    // A protocol rejection, or anything else (a bug, the network): final, as retrying would only
    // repeat it, and its side effects.
    app.io.err(what);
    if (!(e instanceof P2PError)) await noteGaveUp(app);
  }
  // Abandoned after its effects were written: not recorded; the redelivery applies it again
  // (events deduplicated by id), as after a crash here.
  if (abandoned.has(token)) {
    await r.releaseReplay?.({ uncount: true }).catch(() => undefined);
    return "keep";
  }
  // Applied (its effects and events written), or failed for good: only now is it a replay.
  const lost = await r.commitReplay?.();
  // Another host's attempt recorded it first (its claim was taken over after the TTL): this one
  // was a duplicate. Its events were deduplicated by id; say so, and go on.
  if (lost) app.io.err(`an envelope from ${r.envelope.from} was also handled elsewhere meanwhile (${sanitizePeerText(lost.reason, 64)})`);
  return "ack";
}

async function dispatch(app: App, env: string, r: AcceptedMessageV3, relay: string): Promise<NewEvent[]> {
  switch (r.rule) {
    case "contact":
      return onContact(app, env, r);
    case "self-sync": {
      // review L3: a device revoked moments ago could still sync. Refresh our own document
      // (rate-limited by P2P_DOC_REFRESH_SEC) and require the sender to still be listed.
      await app.refreshIdentity(app.userId, app.relays, { quiet: true });
      const own = await app.view(app.userId);
      if (!own?.devices.includes(r.envelope.fdid)) {
        app.io.err(`ignored a sync from ${r.envelope.fdid}: no longer one of your devices`);
        return [];
      }
      await importSync(app, (r.plaintext as { body: Record<string, unknown> }).body, { fdid: r.envelope.fdid });
      // §2.8: a rotation of our identity this device didn't publish is raised loudly.
      await alertForeignRotations(app);
      return [];
    }
    case "unfriend":
      return onUnfriendKind(app, env, r);
    case "receipt":
      return onReceipt(app, env, r);
    case "unknown-kind":
      return onUnknownKind(app, env, r);
    case "circle":
      // "circle" names both the circle kind's rule and an exchange rule (§4.2: a circle-mate writing
      // into a session shared with the circle). Only the kind tells them apart: a message routed to
      // the circle handler failed there and was dropped (found by the doctor tests).
      return r.plaintext.kind === "circle" ? onCircleEnvelope(app, env, r, relay) : onSessionEnvelope(app, env, r);
    default:
      return onSessionEnvelope(app, env, r);
  }
}

/** Installs the handler and returns the app, for commands that connect. */
export function receiving(app: App): App {
  app.onEnvelope = (env, relay) => processEnvelope(app, env, relay);
  app.afterDrain = async () => {
    // §2.8 (pre-release review H2): nothing here ever follows a rotation of our own identity; that is the
    // user's own `p2p identity follow`. A rotation this device didn't publish is raised, and rotated
    // members whose old identity's final version is now out are swapped in.
    await alertForeignRotations(app);
    await retryRotationJoins(app);
    // Re-review N6: a want the first device in line didn't answer in time, answered here.
    await answerDeferredWants(app).catch((e) => app.io.err(`p2p: ${(e as Error).message}`));
    return finishCodeJoins(app);
  };
  app.onIdentityRotated = () => alertForeignRotations(app);
  app.onAbandon = () => abandonInFlight(app);
  return app;
}
