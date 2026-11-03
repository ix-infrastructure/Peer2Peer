// Copyright 2026 Ix Infrastructure Inc.
//
// No command hangs silently: every network step runs through `step`, which
//  - says what it is doing on stderr once it has taken longer than `slowMs`
//    (default 3 s), e.g. "p2p: connecting to wss://relay.example/v3 (relay 1/2)…";
//  - with P2P_DEBUG=1, logs every step's start, end and duration instead;
//  - optionally bounds the step, failing with `timeout` and a message that
//    names the step (and so the relay).
// Labels carry relay URLs, userIds and frame types only: never keys, caps,
// envelopes, codes or phrases.

import { CliError } from "./errors.js";

export interface Progress {
  log(msg: string): void;
  debug: boolean;
  slowMs: number;
  /** The step in flight (named by the command deadline's message). */
  current?: string;
  /**
   * Hosts (`host:port` of the dial URL) this command found unreachable, with
   * the error: later connects and fetches to them fail at once instead of
   * waiting out another timeout each (a firewall that drops SYNs).
   */
  unreachable?: Map<string, CliError>;
  /** Aborted when the command's deadline passes: no new network step starts after that. */
  signal?: AbortSignal;
}

export const SILENT: Progress = { log: () => {}, debug: false, slowMs: 3000 };

export function makeProgress(env: Record<string, string | undefined>, log: (msg: string) => void): Progress {
  const debug = /^(1|true|yes|on)$/i.test(env.P2P_DEBUG?.trim() ?? "");
  const raw = env.P2P_SLOW_MS?.trim();
  const slow = raw ? Number(raw) : NaN;
  return { log, debug, slowMs: Number.isFinite(slow) && slow >= 0 ? slow : 3000, unreachable: new Map() };
}

const secs = (ms: number) => `${Math.round(ms / 100) / 10}s`;

/** Runs `fn` as the step `label` (see the file comment). */
export async function step<T>(p: Progress | undefined, label: string, fn: () => Promise<T>, opts: { timeoutMs?: number; noDebug?: boolean } = {}): Promise<T> {
  const pr0 = p ?? SILENT;
  // noDebug: a frequent step (state lock) logs only when slow, even under P2P_DEBUG.
  const pr = opts.noDebug && pr0.debug ? { ...pr0, debug: false, log: pr0.log } : pr0;
  // Once the command is out of time, nothing new goes on the wire (steps already running finish
  // or time out on their own, so in-flight sends and writes settle).
  if (pr0.signal?.aborted) throw new CliError("aborted", `not ${label}: the command ran out of time`);
  const prev = pr.current;
  pr.current = label;
  const t0 = Date.now();
  if (pr.debug) pr.log(`debug: ${label}…`);
  let slow: NodeJS.Timeout | undefined;
  if (!pr.debug) {
    slow = setTimeout(() => pr.log(`${label}…`), pr.slowMs);
    slow.unref?.();
  }
  let to: NodeJS.Timeout | undefined;
  try {
    const work = fn();
    const r =
      opts.timeoutMs !== undefined
        ? await Promise.race([
            work,
            new Promise<never>((_, reject) => {
              to = setTimeout(() => reject(new CliError("timeout", `${label}: no answer after ${secs(opts.timeoutMs!)}`)), opts.timeoutMs);
              to.unref?.();
            }),
          ])
        : await work;
    if (pr.debug) pr.log(`debug: ${label}: done in ${Date.now() - t0}ms`);
    return r;
  } catch (e) {
    if (pr.debug) pr.log(`debug: ${label}: failed after ${Date.now() - t0}ms: ${(e as Error).message}`);
    throw e;
  } finally {
    if (slow) clearTimeout(slow);
    if (to) clearTimeout(to);
    pr.current = prev;
  }
}

/** `host:port` of a ws(s):// or http(s):// URL (the default port filled in). */
export function hostKey(url: string): { key: string; port: string } {
  const u = new URL(url);
  const port = u.port || (u.protocol === "wss:" || u.protocol === "https:" ? "443" : "80");
  return { key: `${u.hostname}:${port}`, port };
}

/** A debug-only line. */
export function debug(p: Progress | undefined, msg: string): void {
  if (p?.debug) p.log(`debug: ${msg}`);
}
