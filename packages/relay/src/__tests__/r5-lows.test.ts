// Copyright 2026 Ix Infrastructure Inc.
// Follow-ups to a pre-release review: the checkpoint watchdog doesn't flap under sustained
// writes, the invite byte counter survives a rollback, and the per-source
// invite sum reads a covering index.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SqliteStore } from "../sqlite-store.js";
import { stall, virtualClock, type CkptReport } from "./checkpoint-clock.js";

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "p2p-relay-r5lows-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const autocheckpoint = (s: SqliteStore) =>
  Object.values((s as unknown as { db: { prepare(q: string): { get(): Record<string, number> } } }).db.prepare("PRAGMA wal_autocheckpoint").get())[0];
const env = (n: number) => ({ to: "p2p:a", tdid: "d_a", env: "x".repeat(n), size: n, receivedAt: 1, src: "s" });
const roomy = { maxEnvelopes: 1e9, maxBytes: 1e12 };

describe("the checkpoint watchdog counts progress, not only fully caught-up passes", () => {
  // Every test here judges the stall rule on a virtual clock and waits on worker
  // reports, not on wall-clock sleeps: on a loaded machine (the full suite on
  // Node 22) the worker thread can be scheduled late enough to look stalled.
  it("passes that never catch up but keep advancing don't trip it", async () => {
    const warnings: string[] = [];
    const clock = virtualClock();
    const s = new SqliteStore(join(dir, "adv.db"), { checkpointIntervalMs: 50, checkpointWatchdogMs: 400, now: clock.now, warn: (m) => warnings.push(m) });
    const w = s.checkpointState().worker!;
    // The real worker goes quiet; these reports stand in for passes under a
    // steady write load: each copies more, none reaches the end of the log.
    await stall(w);
    let checkpointed = 100;
    for (let i = 0; i < 25; i++) {
      checkpointed += 40;
      w.emit("message", { t: "ckpt", ok: true, busy: 0, log: checkpointed + 25, checkpointed });
      // Every few passes the WAL rewinds (log drops): progress too.
      if (i % 8 === 7) checkpointed = 10;
      clock.advance(50);
      s.checkWatchdog();
    }
    expect(warnings).toEqual([]);
    expect(s.checkpointState().worker).toBe(w);
    expect(autocheckpoint(s)).toBe(0);
    s.close();
  });

  it("passes stuck at the same frame (a pinned reader) still trip it", async () => {
    const warnings: string[] = [];
    const clock = virtualClock();
    const s = new SqliteStore(join(dir, "stuck.db"), { checkpointIntervalMs: 50, checkpointWatchdogMs: 400, now: clock.now, warn: (m) => warnings.push(m) });
    const w = s.checkpointState().worker!;
    await stall(w);
    for (let i = 0; i < 20; i++) {
      w.emit("message", { t: "ckpt", ok: true, busy: 0, log: 500 + i * 10, checkpointed: 300 });
      clock.advance(50);
      s.checkWatchdog();
    }
    expect(warnings.some((m) => /stalled/.test(m))).toBe(true);
    expect(s.checkpointState().worker).not.toBe(w);
    s.close();
  });

  // End to end with the real worker: writes run while it checkpoints, and the
  // clock moves 150 ms per report, so three reports in a row without progress
  // would trip the 400 ms window. Scheduling can only change how many writes
  // land between reports, not the verdict.
  it("sustained real writes don't trip it", async () => {
    const warnings: string[] = [];
    const clock = virtualClock();
    const path = join(dir, "real.db");
    // The WAL limit is set out of reach: this test is about the stall rule alone.
    const s = new SqliteStore(path, { checkpointIntervalMs: 50, checkpointWatchdogMs: 400, walLimitBytes: 8 * 1024 ** 3, now: clock.now, warn: (m) => warnings.push(m) });
    const w = s.checkpointState().worker!;
    let reports = 0;
    w.on("message", (m: CkptReport) => {
      if (m?.t === "ckpt") reports++;
    });
    // 12 reports of 150 virtual ms (1.8 s against a 400 ms window). The pace of real time only
    // changes how many writes land between reports, so the writes are capped per report: under
    // load (pre-release re-review F5) an uncapped loop piled up WAL faster than the starved worker copied
    // it, and the test ran past its timeout.
    for (let round = 0; round < 12; round++) {
      const seen = reports;
      for (let n = 0; reports === seen; n++) {
        if (n < 25) for (let i = 0; i < 5; i++) s.putEnvelope(env(4000), roomy);
        await new Promise((res) => setTimeout(res, n < 25 ? 0 : 10));
      }
      clock.advance(150);
      s.checkWatchdog();
    }
    expect(warnings.filter((m) => /stalled/.test(m))).toEqual([]);
    expect(s.checkpointState().worker).toBe(w);
    s.close();
  }, 30_000);
});

describe("the invite byte counter follows commits only", () => {
  it("a rolled-back transaction leaves inviteBytes() equal to the table", () => {
    const s = new SqliteStore(join(dir, "rb.db"));
    s.putInvite({ lid: "a", iss: "A", blob: "x", size: 10, createdAt: 1, expiresAt: 9e15, src: "s" });
    expect(() =>
      s.transaction(() => {
        s.putInvite({ lid: "b", iss: "A", blob: "x", size: 500, createdAt: 2, expiresAt: 9e15, src: "s" });
        s.takeInvite("a", 0);
        throw new Error("abort");
      }),
    ).toThrow("abort");
    expect(s.inviteBytes()).toBe(10);
    expect(s.inviteBytesOfIss("A")).toBe(10);
    s.transaction(() => s.putInvite({ lid: "c", iss: "B", blob: "x", size: 7, createdAt: 3, expiresAt: 9e15, src: "s" }));
    expect(s.inviteBytes()).toBe(17);
    s.close();
  });
});

describe("inviteBytesOfSrc reads a covering index", () => {
  it("the query plan uses invites_src_size and never the table", () => {
    const path = join(dir, "cov.db");
    const s = new SqliteStore(path);
    s.close();
    const db = new DatabaseSync(path);
    const plan = (db.prepare("EXPLAIN QUERY PLAN SELECT coalesce(sum(size), 0) AS b FROM invites WHERE src = ?").all("s") as { detail: string }[])
      .map((r) => r.detail)
      .join("\n");
    db.close();
    expect(plan).toMatch(/COVERING INDEX invites_src_size/);
  });
});
