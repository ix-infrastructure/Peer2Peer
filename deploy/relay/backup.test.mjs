// Copyright 2026 Ix Infrastructure Inc.
//
// backup.mjs against a relay-sized WAL database that another process keeps
// writing to: the backup must finish (the online backup API never does under
// this load), be a consistent copy, and keep the retention rules.
//
//   node --test deploy/relay/backup.test.mjs      (CI runs it: ci-public.yml)

import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const BACKUP = join(here, "backup.mjs");
const work = mkdtempSync(join(tmpdir(), "p2p-relay-backup-test-"));
const dbPath = join(work, "relay.db");
const out = join(work, "backups");
let writer;

// Writes 4 KiB rows as fast as it can, in small transactions, like a busy relay (and deletes
// as many, so the database keeps its size).
const WRITER = `
const { DatabaseSync } = require("node:sqlite");
const db = new DatabaseSync(process.argv[1]);
db.exec("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 10000; PRAGMA synchronous = NORMAL");
const ins = db.prepare("INSERT INTO envelopes (body) VALUES (?)");
const del = db.prepare("DELETE FROM envelopes WHERE id IN (SELECT id FROM envelopes ORDER BY id LIMIT 20)");
const body = Buffer.alloc(4096, 7);
let n = 0;
for (;;) {
  db.exec("BEGIN");
  for (let i = 0; i < 20; i++) ins.run(body);
  del.run();
  db.exec("COMMIT");
  if (++n % 25 === 0) process.stdout.write("w\\n");
}
`;

function rows(path) {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    return db.prepare("SELECT count(*) AS n FROM envelopes").get().n;
  } finally {
    db.close();
  }
}

/** Runs backup.mjs without blocking this process, so the writer's output keeps being read. */
function runBackup(keep, db = dbPath) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [BACKUP, db, out, String(keep)], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    c.stdout.on("data", (d) => (stdout += d));
    c.stderr.on("data", (d) => (stderr += d));
    const timer = setTimeout(() => c.kill("SIGKILL"), 120_000);
    c.on("close", (status) => {
      clearTimeout(timer);
      resolve({ status, stderr, file: stdout.trim() });
    });
  });
}

before(() => {
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA journal_mode = WAL; CREATE TABLE envelopes (id INTEGER PRIMARY KEY, body BLOB NOT NULL)");
  // About 80 MB, like the review's 85 MB database.
  const ins = db.prepare("INSERT INTO envelopes (body) VALUES (?)");
  const body = Buffer.alloc(4096, 1);
  db.exec("BEGIN");
  for (let i = 0; i < 20_000; i++) ins.run(body);
  db.exec("COMMIT");
  db.close();
});

after(() => {
  writer?.kill("SIGKILL");
  rmSync(work, { recursive: true, force: true });
});

test("finishes under concurrent writes, with a consistent copy", async () => {
  writer = spawn(process.execPath, ["-e", WRITER, dbPath], { stdio: ["ignore", "pipe", "inherit"] });
  let ticks = 0;
  writer.stdout.on("data", (d) => (ticks += String(d).split("\n").filter(Boolean).length));
  // Let the writer get going first.
  while (ticks < 3) await new Promise((r) => setTimeout(r, 50));
  const before = ticks;

  const t0 = Date.now();
  const r = await runBackup(2);
  const ms = Date.now() - t0;
  assert.equal(r.status, 0, `backup failed: ${r.stderr}`);
  assert.ok(ms < 60_000, `took ${ms} ms`);
  assert.ok(ticks > before, "the writer kept writing while the backup ran");

  const copy = new DatabaseSync(r.file, { readOnly: true });
  try {
    assert.equal(copy.prepare("PRAGMA integrity_check").get().integrity_check, "ok");
    assert.equal(copy.prepare("PRAGMA journal_mode").get().journal_mode, "delete");
  } finally {
    copy.close();
  }
  assert.ok(rows(r.file) >= 10_000, "the copy holds the data");
  assert.equal(statSync(r.file).mode & 0o777, 0o640);
  assert.deepEqual(readdirSync(out).filter((f) => f.endsWith(".tmp")), []);
  writer.kill("SIGKILL");
});

test("retention: keeps the newest, and keep=0 never deletes the backup just made", async () => {
  for (let i = 0; i < 3; i++) {
    await new Promise((r) => setTimeout(r, 1100)); // names have one-second resolution
    const r = await runBackup(2);
    assert.equal(r.status, 0, r.stderr);
  }
  assert.equal(readdirSync(out).filter((f) => f.endsWith(".db")).length, 2);
  await new Promise((r) => setTimeout(r, 1100));
  const last = await runBackup(0);
  assert.equal(last.status, 0, last.stderr);
  assert.deepEqual(readdirSync(out), [last.file.split("/").pop()]);
});

test("a leftover .tmp from an interrupted run is removed, and a failed run leaves no file", async () => {
  writeFileSync(join(out, "relay-20000101T000000Z.db.tmp"), "partial");
  await new Promise((r) => setTimeout(r, 1100));
  const ok = await runBackup(1);
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(readdirSync(out).filter((f) => f.endsWith(".tmp")).length, 0);
  const bad = await runBackup(1, join(work, "missing.db"));
  assert.notEqual(bad.status, 0);
  assert.equal(readdirSync(out).filter((f) => f.endsWith(".tmp")).length, 0);
  assert.equal(readdirSync(out).length, 1);
});

test("creates a missing out dir, and leaves no marker for the relay behind (a killed run's is replaced)", async () => {
  const fresh = join(work, "fresh", "backups");
  writeFileSync(`${dbPath}-backup`, JSON.stringify({ pid: 1, started: 0, until: 1 }));
  const r = await new Promise((resolve) => {
    const c = spawn(process.execPath, [BACKUP, dbPath, fresh, "1", "30"], { stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    c.stderr.on("data", (d) => (stderr += d));
    c.on("close", (status) => resolve({ status, stderr }));
  });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(readdirSync(fresh).filter((f) => f.endsWith(".db")).length, 1);
  assert.equal(statSync(fresh).mode & 0o007, 0, "not readable by others");
  assert.throws(() => statSync(`${dbPath}-backup`), /ENOENT/);
});
