// Copyright 2026 Ix Infrastructure Inc.
// Deterministic checkpoint-watchdog tests: the store's watchdog reads a virtual
// clock the test advances, and the test waits for the worker's reports (events),
// never for wall-clock time. A loaded machine (the full suite on Node 22) only
// makes them slower, never different.

import type { Worker } from "node:worker_threads";

export interface CkptReport {
  t: "ckpt";
  ok: boolean;
  busy?: number;
  log?: number;
  checkpointed?: number;
}

/** A clock the store's watchdog reads (SqliteStoreOptions.now); it moves only when told. */
export function virtualClock(start = 1_000_000): { now: () => number; advance(ms: number): void } {
  let t = start;
  return {
    now: () => t,
    advance(ms: number) {
      t += ms;
    },
  };
}

/** The worker's next checkpoint report (after the store's own handler has seen it). */
export function nextReport(w: Worker): Promise<CkptReport> {
  return new Promise((resolve) => {
    const on = (m: CkptReport) => {
      if (m?.t !== "ckpt") return;
      w.off("message", on);
      resolve(m);
    };
    w.on("message", on);
  });
}

/** Waits for reports until `done()` holds; fails after `max` reports, so it can't hang. */
export async function untilReport(w: Worker, done: () => boolean, max = 400): Promise<void> {
  for (let i = 0; i < max && !done(); i++) await nextReport(w);
  if (!done()) throw new Error(`condition not met after ${max} checkpoint reports`);
}

/** Wedges the worker (its test hook) and waits until no report of it can still arrive. */
export function stall(w: Worker): Promise<void> {
  return new Promise((resolve) => {
    const on = (m: { t?: string }) => {
      if (m?.t !== "stalled") return;
      w.off("message", on);
      resolve();
    };
    w.on("message", on);
    w.postMessage("stall");
  });
}

let passIds = 0;

/** One checkpoint pass run now (the worker's test hook): its report sees every commit made before the call. */
export function passNow(w: Worker): Promise<CkptReport> {
  const id = ++passIds;
  return new Promise((resolve) => {
    const on = (m: CkptReport & { id?: number }) => {
      if (m?.t !== "ckpt" || m.id !== id) return;
      w.off("message", on);
      resolve(m);
    };
    w.on("message", on);
    w.postMessage({ t: "pass", id });
  });
}
