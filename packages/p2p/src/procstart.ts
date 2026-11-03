// Copyright 2026 Ix Infrastructure Inc.
//
// When another process on this machine started (ms since the epoch), so a replay claim held by a
// pid that has since been reused isn't taken for its holder's (pre-release review L-C). Only asked when a
// claim from another local process is found (rare), so a spawn is fine. Undefined when the
// platform can't say cheaply: the caller then keeps going by the pid alone.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

let bootMs: number | undefined;

function linuxStartMs(pid: number): number | undefined {
  // Field 22 of /proc/<pid>/stat: start time in clock ticks after boot (USER_HZ, 100 on Linux).
  const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
  const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
  const ticks = Number(fields[19]);
  if (!Number.isFinite(ticks)) return undefined;
  if (bootMs === undefined) {
    const m = /^btime (\d+)$/m.exec(readFileSync("/proc/stat", "utf8"));
    if (!m) return undefined;
    bootMs = Number(m[1]) * 1000;
  }
  return bootMs + (ticks / 100) * 1000;
}

function psStartMs(pid: number): number | undefined {
  const out = execFileSync("ps", ["-o", "lstart=", "-p", String(pid)], { encoding: "utf8", timeout: 2000, stdio: ["ignore", "pipe", "ignore"], env: { LC_ALL: "C", PATH: process.env.PATH ?? "" } }).trim();
  const t = Date.parse(out);
  return Number.isFinite(t) ? t : undefined;
}

/**
 * Answers are remembered for CACHE_MS per pid. On macOS and the BSDs each answer is a `ps` spawn
 * (30-100 ms, synchronous) and it is asked while the trust store's lock is held (claimReplay's
 * liveness check): a watch and a short command racing for the same envelopes asked it for every
 * one of them, and every other p2p process of the home waited on the lock meanwhile. A pid's
 * start time doesn't change while it lives; a pid reused within CACHE_MS would only make its
 * claim look alive a little longer (the envelope isn't acked, and is redelivered).
 */
const CACHE_MS = 5_000;
const CACHE_MAX = 256;
const cache = new Map<number, { at: number; ms: number | undefined }>();

export function processStartMs(pid: number): number | undefined {
  if (!Number.isSafeInteger(pid) || pid <= 0) return undefined;
  const now = Date.now();
  const hit = cache.get(pid);
  if (hit && now - hit.at < CACHE_MS) return hit.ms;
  const ms = lookup(pid);
  cache.delete(pid);
  cache.set(pid, { at: now, ms });
  if (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value!);
  return ms;
}

function lookup(pid: number): number | undefined {
  try {
    if (process.platform === "linux") return linuxStartMs(pid);
    if (process.platform === "darwin" || process.platform.endsWith("bsd")) return psStartMs(pid);
  } catch {
    // gone, or no ps
  }
  return undefined;
}
