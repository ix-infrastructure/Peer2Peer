// Copyright 2026 Ix Infrastructure Inc.
// A backup's read snapshot holds checkpoints back by design. While its marker
// (`<db>-backup`, written by deploy/relay/backup.mjs) is in force, the watchdog
// doesn't take that for a stall: no in-commit checkpoints (which would copy the
// grown WAL on the main thread once the backup ends) and no worker restart. A
// marker past its own deadline, or written too long ago, is ignored.

import { mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { BACKUP_MARKER_MAX_MS, SqliteStore } from "../sqlite-store.js";
import { nextReport, untilReport, virtualClock } from "./checkpoint-clock.js";

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "p2p-relay-backup-marker-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const autocheckpoint = (s: SqliteStore) =>
  Object.values((s as unknown as { db: { prepare(q: string): { get(): Record<string, number> } } }).db.prepare("PRAGMA wal_autocheckpoint").get())[0];

/** A store with a reader pinning its WAL (as VACUUM INTO does), the clock at real time. */
async function pinned(name: string) {
  const path = join(dir, name);
  const warnings: string[] = [];
  const clock = virtualClock(Date.now());
  const s = new SqliteStore(path, { checkpointIntervalMs: 50, checkpointWatchdogMs: 400, now: clock.now, warn: (m) => warnings.push(m) });
  const put = () => s.putEnvelope({ to: "p2p:a", tdid: "d_a", env: "x".repeat(2000), size: 2000, receivedAt: 1, src: "s" }, { maxEnvelopes: 1e9, maxBytes: 1e12 });
  put();
  await untilReport(s.checkpointState().worker!, () => autocheckpoint(s) === 0);
  const reader = new DatabaseSync(path);
  reader.exec("BEGIN");
  reader.prepare("SELECT count(*) AS n FROM meta").get();
  for (let i = 0; i < 20; i++) put();
  /** `n` worker reports, the clock 100 ms further and a watchdog check after each. */
  const run = async (n: number) => {
    for (let i = 0; i < n; i++) {
      // The current worker: a stall restarts it.
      await nextReport(s.checkpointState().worker!);
      clock.advance(100);
      s.checkWatchdog();
    }
  };
  return { path, s, clock, warnings, reader, run, marker: `${path}-backup` };
}

describe("a running backup isn't a checkpoint stall", () => {
  it("while the marker is in force: no fallback, no restart; afterwards the worker catches up off the main thread", async () => {
    const t = await pinned("bk.db");
    const w = t.s.checkpointState().worker;
    writeFileSync(t.marker, JSON.stringify({ until: t.clock.now() + 600_000 }));
    await t.run(30); // 3 s of virtual time against a 400 ms window
    expect(t.warnings.filter((m) => /stalled/.test(m))).toEqual([]);
    expect(t.warnings.some((m) => /held back by a running backup/.test(m))).toBe(true);
    expect(autocheckpoint(t.s)).toBe(0);
    expect(t.s.checkpointState().worker).toBe(w);
    // The backup ends: marker gone, snapshot released. The same worker catches up.
    rmSync(t.marker);
    t.reader.exec("COMMIT");
    t.reader.close();
    await t.run(10);
    expect(t.warnings.filter((m) => /stalled/.test(m))).toEqual([]);
    expect(autocheckpoint(t.s)).toBe(0);
    expect(t.s.checkpointState().worker).toBe(w);
    t.s.close();
  });

  it("a marker past its own deadline is ignored", async () => {
    const t = await pinned("late.db");
    writeFileSync(t.marker, JSON.stringify({ until: t.clock.now() - 1 }));
    await t.run(10);
    expect(t.warnings.some((m) => /stalled/.test(m))).toBe(true);
    expect(autocheckpoint(t.s)).toBe(1000);
    t.reader.exec("COMMIT");
    t.reader.close();
    t.s.close();
  });

  it("a marker written too long ago is ignored, whatever deadline it claims", async () => {
    const t = await pinned("old.db");
    writeFileSync(t.marker, JSON.stringify({ until: t.clock.now() + 10 * BACKUP_MARKER_MAX_MS }));
    const old = (t.clock.now() - BACKUP_MARKER_MAX_MS - 60_000) / 1000;
    utimesSync(t.marker, old, old);
    await t.run(10);
    expect(t.warnings.some((m) => /stalled/.test(m))).toBe(true);
    t.reader.exec("COMMIT");
    t.reader.close();
    t.s.close();
  });

  it("a malformed marker is ignored", async () => {
    const t = await pinned("bad.db");
    writeFileSync(t.marker, "not json");
    await t.run(10);
    expect(t.warnings.some((m) => /stalled/.test(m))).toBe(true);
    t.reader.exec("COMMIT");
    t.reader.close();
    t.s.close();
  });
});
