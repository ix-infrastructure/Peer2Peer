// Copyright 2026 Ix Infrastructure Inc.
//
// One `p2p identity rotate` run per home at a time (#91 review, #99).

import { randomBytes, createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { CliError } from "./errors.js";
import { processStartMs } from "./procstart.js";

/** #91 review: where a running rotation step records who it is (one run per home at a time). */
export const rotationLockOf = (home: string) => join(home, "rotation.lock");

/** Start times compare to the second (ps), with room for clock rounding (as running.ts and inbound.ts). */
const START_SLACK_MS = 2500;
/** A lock this build writes is well under this; anything larger isn't read. */
const MAX_LOCK_BYTES = 4096;
/** An empty lock (a run that died between creating and writing it) older than this is stale. */
const EMPTY_STALE_MS = 60_000;
const MARKER_RE = /^rotation\.lock\.[0-9a-f]{32}\.takeover$/;

/** What a run records in the lock (#99): its pid, that process's start time (ms, when known), a random run id, and when. */
interface LockRecord {
  pid: number;
  started?: number;
}

type LockRead = { kind: "gone" } | { kind: "read"; raw: string; mtimeMs: number };

/**
 * Reads the lock file without following a symbolic link or blocking on a FIFO (#99 review, as sandbox.ts
 * readConfigFile): only a regular file of at most MAX_LOCK_BYTES. Anything else refuses, naming the file.
 */
async function readLock(file: string): Promise<LockRead> {
  let fh;
  try {
    fh = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return { kind: "gone" };
    throw lockError(file, `${file} couldn't be read (${(e as NodeJS.ErrnoException).code ?? (e as Error).message})`);
  }
  try {
    const st = await fh.stat();
    if (!st.isFile()) throw lockError(file, `${file} isn't a regular file`);
    if (st.size > MAX_LOCK_BYTES) throw lockError(file, `${file} is larger than a rotation lock`);
    const buf = Buffer.alloc(MAX_LOCK_BYTES + 1);
    let n = 0;
    for (;;) {
      const { bytesRead } = await fh.read(buf, n, buf.length - n, null);
      if (bytesRead === 0) break;
      n += bytesRead;
      if (n > MAX_LOCK_BYTES) throw lockError(file, `${file} is larger than a rotation lock`);
    }
    return { kind: "read", raw: buf.subarray(0, n).toString("utf8"), mtimeMs: st.mtimeMs };
  } finally {
    await fh.close();
  }
}

function parseLock(raw: string): LockRecord | undefined {
  const t = raw.trim();
  // A lock from an older build: just the pid.
  if (/^[0-9]{1,10}$/.test(t)) {
    const pid = Number.parseInt(t, 10);
    return pid > 0 ? { pid } : undefined;
  }
  try {
    const o = JSON.parse(t) as Record<string, unknown> | null;
    if (!o || typeof o !== "object" || typeof o.pid !== "number" || !Number.isSafeInteger(o.pid) || o.pid <= 0) return undefined;
    return { pid: o.pid, ...(typeof o.started === "number" && Number.isFinite(o.started) ? { started: o.started } : {}) };
  } catch {
    return undefined;
  }
}

function running(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * Whether the run that wrote `rec` may still be running. A process with its pid must exist; when the lock records
 * the process's start time and the OS tells the current one, they must match (#99: a pid reused by another process
 * doesn't hold the lock forever). When the start time can't be told, it counts as running (fail closed: the error
 * names the lock file, to delete when nothing is rotating).
 */
function lockLive(rec: LockRecord): boolean {
  if (!running(rec.pid)) return false;
  if (rec.started === undefined) return true;
  const now = processStartMs(rec.pid);
  return now === undefined || Math.abs(now - rec.started) < START_SLACK_MS;
}

const deleteHint = (file: string) => `If nothing is rotating here (a run was killed, or its process id is in use again), delete ${file}`;

function lockError(file: string, why: string): CliError {
  return new CliError("rotation_in_progress", `${why}, so \`p2p identity rotate\` can't tell whether another run is in progress. ${deleteHint(file)}`);
}

const lockBusy = (file: string) =>
  new CliError("rotation_in_progress", `another \`p2p identity rotate\` run is in progress for this identity: wait for it to finish, then try again. ${deleteHint(file)}`);

/** How a takeover marker is named: after the stale lock's content, which nothing but its (gone) run would remove. */
const markerOf = (file: string, raw: string) => `${file}.${createHash("sha256").update(raw).digest("hex").slice(0, 32)}.takeover`;

/** Exclusive create: true when this call created `file`, false when it already existed. */
async function createExclusive(file: string, content: string): Promise<boolean> {
  try {
    await writeFile(file, content, { mode: 0o600, flag: "wx" });
    return true;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") return false;
    throw e;
  }
}

/**
 * Leftover takeover markers (a run that died during a takeover) once we hold the lock. Safe: a marker only lets its
 * creator remove a lock with the content it is named after, and the lock now holds ours, which no marker names
 * (we run).
 */
async function sweepMarkers(home: string): Promise<void> {
  const names = await readdir(home).catch(() => [] as string[]);
  await Promise.all(names.filter((n) => MARKER_RE.test(n)).map((n) => rm(join(home, n), { force: true }).catch(() => undefined)));
}

/**
 * Runs `fn` holding the rotation lock of `home`, so a second run (`--resume --contest` while the first is in
 * followers(), or `--plan --exclude X` while a `--resume --yes` run saves) can't have its state overwritten by the
 * other's saves.
 *
 * The lock is created with O_EXCL and records the run (LockRecord). A lock left by a run that no longer runs
 * (lockLive), or an empty one older than EMPTY_STALE_MS, is taken over, exclusively (#99): the run first creates,
 * with O_EXCL, a takeover marker named after the stale lock's exact content. Only the run that creates it removes the
 * lock, and only while the lock still holds that content; nothing else removes a lock with that content (its own run
 * is gone). Then it takes the lock with O_EXCL like any other run. So two runs taking over the same stale lock leave
 * exactly one owner: the other's marker fails, or (created after the first removed its marker, which is after the
 * first took the lock) it finds the first's live lock and refuses. A fresh run racing a takeover gets the lock or
 * doesn't, by O_EXCL. Every refusal names the lock file.
 */
export async function withRotationLock<T>(home: string, fn: () => Promise<T>): Promise<T> {
  const file = rotationLockOf(home);
  const started = processStartMs(process.pid) ?? Math.round(Date.now() - process.uptime() * 1000);
  const mine = `${JSON.stringify({ pid: process.pid, started, run: randomBytes(16).toString("hex"), at: Date.now() })}\n`;
  if (!(await createExclusive(file, mine))) {
    const cur = await readLock(file);
    if (cur.kind === "gone") {
      // Gone in the meantime (its run finished): take it like any other run.
      if (!(await createExclusive(file, mine))) throw lockBusy(file);
    } else {
      const { raw } = cur;
      if (raw.trim() === "") {
        // A run that died between creating and writing it, or one writing it right now.
        if (Date.now() - cur.mtimeMs < EMPTY_STALE_MS) throw lockBusy(file);
      } else {
        const rec = parseLock(raw);
        if (!rec) throw lockError(file, `${file} doesn't hold a rotation lock this build can read`);
        if (lockLive(rec)) throw lockBusy(file);
      }
      const marker = markerOf(file, raw);
      if (!(await createExclusive(marker, mine))) {
        throw new CliError("rotation_in_progress", `another \`p2p identity rotate\` run is taking over a stale rotation lock: try again. ${deleteHint(file)}`);
      }
      try {
        const now = await readLock(file);
        if (now.kind === "read" && now.raw === raw) await rm(file, { force: true });
        if (!(await createExclusive(file, mine))) throw lockBusy(file);
      } finally {
        await rm(marker, { force: true }).catch(() => undefined);
      }
    }
  }
  await sweepMarkers(home);
  try {
    return await fn();
  } finally {
    // Only our own lock is removed.
    const now = await readLock(file).catch(() => undefined);
    if (now?.kind === "read" && now.raw === mine) await rm(file, { force: true }).catch(() => undefined);
  }
}
