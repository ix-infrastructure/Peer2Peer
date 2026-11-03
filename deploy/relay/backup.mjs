// Copyright 2026 Ix Infrastructure Inc.
//
// One backup of the relay's SQLite database, safe while the relay runs and
// writes. backup.sh runs it inside the relay image (node:sqlite, no sqlite3
// binary); backup.test.mjs runs it against a database under concurrent writes.
//
//   node backup.mjs <db> <out-dir> <keep> [deadline-sec]
//
// Why VACUUM INTO and not the online backup API: the backup API copies in
// steps and restarts from the beginning whenever another connection writes,
// so under steady write load it never finishes (and its open read keeps the
// WAL from being checkpointed). VACUUM INTO reads one consistent snapshot in a
// single statement, so writers never restart it, and it writes a compacted
// copy: the size of the live data, not the file's high-water mark.
//
// The copy is written to <name>.tmp, fsynced, made 0640, and renamed into
// place only on success, so a reader of <out-dir> never sees a partial file.
// Then all but the newest <keep> backups are deleted; the one just made is
// always kept, even with keep=0. Prints the new file's path on stdout.
//
// While it runs, its snapshot holds the relay's checkpoints back (the WAL grows
// until it ends). It says so in `<db>-backup` (JSON: pid, started, until =
// started + deadline-sec, default 600), which the relay's checkpoint watchdog
// reads: a backup is not a stalled checkpoint worker, and the relay keeps its
// checkpoints off the main thread (packages/relay sqlite-store.ts). The marker
// is removed when the backup ends, and the relay ignores one past `until` or
// written over an hour ago, so a killed run can't leave the watchdog off.
//
// It refuses to run as root (it would leave root-owned files in the relay's
// volume), and creates <out-dir> (0750) when it is missing.

import { chownSync, closeSync, fsyncSync, mkdirSync, openSync, readdirSync, renameSync, rmSync, chmodSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

const [dbPath, outDir, keepArg, deadlineArg] = process.argv.slice(2);
if (!dbPath || !outDir) {
  console.error("usage: node backup.mjs <db> <out-dir> <keep> [deadline-sec]");
  process.exit(2);
}
if (process.getuid?.() === 0) {
  console.error("backup: refusing to run as root; run it as the relay's user (65532), as backup.sh does");
  process.exit(2);
}
const keep = Math.max(1, Number.parseInt(keepArg ?? "2", 10) || 1);
const deadlineSec = Math.max(1, Number.parseInt(deadlineArg ?? "600", 10) || 600);
const NAME = /^relay-\d{8}T\d{6}Z\.db$/;

mkdirSync(outDir, { recursive: true, mode: 0o750 });

// Leftovers of an interrupted run.
for (const f of readdirSync(outDir)) if (/^relay-\d{8}T\d{6}Z\.db\.tmp$/.test(f)) rmSync(join(outDir, f), { force: true });

const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
const name = `relay-${stamp}.db`;
const final = join(outDir, name);
const tmp = `${final}.tmp`;

const started = Date.now();
// Tells the relay's checkpoint watchdog that a backup's snapshot, not a stall, holds checkpoints
// back (see the header). Best effort: without it the relay falls back as for any stall.
const marker = `${dbPath}-backup`;
let markerWritten = false;
try {
  writeFileSync(marker, JSON.stringify({ pid: process.pid, started, until: started + deadlineSec * 1000 }), { mode: 0o640 });
  markerWritten = true;
} catch (e) {
  console.error(`backup: no marker for the relay (${e instanceof Error ? e.message : String(e)}); its watchdog may take this backup for a stall`);
}
const dropMarker = () => {
  if (markerWritten) rmSync(marker, { force: true });
  markerWritten = false;
};
// No signal handlers: VACUUM INTO is one synchronous statement, so a handler would only run
// after it, and a kill must stop it at once. A killed run's marker lapses at its deadline.
try {
  const db = new DatabaseSync(dbPath, { readOnly: true });
  try {
    // Waits for a writer's lock instead of failing at once.
    db.exec("PRAGMA busy_timeout = 10000");
    db.prepare("VACUUM INTO ?").run(tmp);
  } finally {
    db.close();
    // The snapshot is released: the relay's worker can catch up from here.
    dropMarker();
  }
  const check = new DatabaseSync(tmp, { readOnly: true });
  try {
    const r = check.prepare("PRAGMA quick_check").get();
    if (r?.quick_check !== "ok") throw new Error(`quick_check on the copy: ${JSON.stringify(r)}`);
  } finally {
    check.close();
  }
  const fd = openSync(tmp, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  chmodSync(tmp, 0o640);
  // The out dir's group (the operator's, added to this process by backup.sh), so the operator
  // can read the copy even where the filesystem ignores the dir's setgid bit.
  try {
    chownSync(tmp, process.getuid?.() ?? -1, statSync(outDir).gid);
  } catch {
    // Not a member of that group (a manual run): the copy stays this user's.
  }
  renameSync(tmp, final);
  const dirFd = openSync(outDir, "r");
  try {
    fsyncSync(dirFd);
  } catch {
    // Not every platform can fsync a directory; the rename is still atomic.
  } finally {
    closeSync(dirFd);
  }
} catch (e) {
  dropMarker();
  rmSync(tmp, { force: true });
  console.error(`backup failed: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
}

const old = readdirSync(outDir)
  .filter((f) => NAME.test(f) && f !== name)
  .sort()
  .reverse()
  .slice(keep - 1);
for (const f of old) rmSync(join(outDir, f), { force: true });

console.error(`backup ok: ${name}, ${statSync(final).size} bytes in ${Date.now() - started} ms; removed ${old.length} older`);
console.log(final);
