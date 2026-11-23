// Copyright 2026 Ix Infrastructure Inc.
//
// One `p2p identity rotate` run per home at a time (#91 review, #99).

import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { CliError } from "./errors.js";

const execFileP = promisify(execFile);

/** #91 review: where a running rotation step records who it is (one run per home at a time). */
export const rotationLockOf = (home: string) => join(home, "rotation.lock");

/** What a run records in the lock (#99): its pid, that process's start time (when known), a random run id, and when. */
interface LockRecord {
  pid: number;
  /** The process's start time as the OS reports it (opaque): a pid reused by a later process has another one. */
  start?: string;
  run?: string;
  at?: number;
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
    return {
      pid: o.pid,
      ...(typeof o.start === "string" ? { start: o.start } : {}),
      ...(typeof o.run === "string" ? { run: o.run } : {}),
      ...(typeof o.at === "number" ? { at: o.at } : {}),
    };
  } catch {
    return undefined;
  }
}

/**
 * The start time of process `pid` as the OS reports it, or undefined when it can't be told (no such process, or no
 * way to ask). Linux: /proc/<pid>/stat field 22 (clock ticks since boot); other Unix systems: `ps -o lstart=`.
 */
export async function processStart(pid: number): Promise<string | undefined> {
  if (process.platform === "linux") {
    try {
      const stat = await readFile(`/proc/${pid}/stat`, "utf8");
      // Field 2 (the command) is in parentheses and may hold spaces: count from after the last ")".
      const f = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
      return f[19] ? `linux:${f[19]}` : undefined;
    } catch {
      return undefined;
    }
  }
  if (process.platform === "win32") return undefined;
  try {
    const { stdout } = await execFileP("ps", ["-o", "lstart=", "-p", String(pid)], { timeout: 5_000, env: { PATH: process.env.PATH ?? "/usr/bin:/bin", LC_ALL: "C" } });
    const t = stdout.trim();
    return t ? `ps:${t}` : undefined;
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
async function lockLive(rec: LockRecord): Promise<boolean> {
  if (!running(rec.pid)) return false;
  if (rec.start === undefined) return true;
  const now = await processStart(rec.pid);
  return now === undefined || now === rec.start;
}

const lockBusy = (file: string) =>
  new CliError(
    "rotation_in_progress",
    `another \`p2p identity rotate\` run is in progress for this identity: wait for it to finish, then try again. If nothing is rotating here (a run was killed and its process id is in use again), delete ${file}`,
  );

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
 * Runs `fn` holding the rotation lock of `home`, so a second run (`--resume --contest` while the first is in
 * followers(), or `--plan --exclude X` while a `--resume --yes` run saves) can't have its state overwritten by the
 * other's saves.
 *
 * The lock is created with O_EXCL and records the run (LockRecord). A lock left by a run that no longer runs
 * (lockLive) is taken over, exclusively (#99): the run first creates, with O_EXCL, a takeover marker named after the
 * stale lock's exact content. Only the run that creates it removes the lock, and only while the lock still holds that
 * content; nothing else removes a lock with that content (its own run is gone). Then it takes the lock with O_EXCL
 * like any other run. So two runs taking over the same stale lock leave exactly one owner: the other's marker fails,
 * or (created after the first removed its marker, which is after the first took the lock) it finds the first's live
 * lock and refuses. A fresh run racing a takeover gets the lock or doesn't, by O_EXCL.
 */
export async function withRotationLock<T>(home: string, fn: () => Promise<T>): Promise<T> {
  const file = rotationLockOf(home);
  const start = await processStart(process.pid);
  const mine = `${JSON.stringify({ pid: process.pid, ...(start !== undefined ? { start } : {}), run: randomBytes(16).toString("hex"), at: Date.now() })}\n`;
  if (!(await createExclusive(file, mine))) {
    const raw = await readFile(file, "utf8").catch((e: NodeJS.ErrnoException) => {
      if (e.code === "ENOENT") return undefined;
      throw e;
    });
    if (raw === undefined) {
      // Gone in the meantime (its run finished): take it like any other run.
      if (!(await createExclusive(file, mine))) throw lockBusy(file);
    } else {
      const rec = parseLock(raw);
      // Content no build wrote is left alone: the user decides (the error names the file).
      if (!rec || (await lockLive(rec))) throw lockBusy(file);
      const marker = markerOf(file, raw);
      if (!(await createExclusive(marker, mine))) throw lockBusy(file);
      try {
        if ((await readFile(file, "utf8").catch(() => undefined)) === raw) await rm(file, { force: true });
        if (!(await createExclusive(file, mine))) throw lockBusy(file);
      } finally {
        await rm(marker, { force: true }).catch(() => undefined);
      }
    }
  }
  try {
    return await fn();
  } finally {
    // Only our own lock is removed.
    if ((await readFile(file, "utf8").catch(() => undefined)) === mine) await rm(file, { force: true }).catch(() => undefined);
  }
}
