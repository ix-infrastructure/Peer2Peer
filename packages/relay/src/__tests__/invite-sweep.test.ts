// Copyright 2026 Ix Infrastructure Inc.
// pre-release follow-up (F-4 for P4 invites): the invite sweep is batched and
// time-boxed like the other sweeps, keeps the per-userId totals row by row,
// and a large expired invite table never holds the event loop.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SqliteStore } from "../sqlite-store.js";
import { MemoryStore, type Store, type StoredInvite } from "../store.js";
import { startRelay, type TestRelay } from "./helpers.js";

let r: TestRelay | undefined;
let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "p2p-relay-invsweep-"));
});
afterEach(async () => {
  await r?.close();
  r = undefined;
  rmSync(dir, { recursive: true, force: true });
});

const inv = (lid: string, iss: string, size: number, expiresAt: number, createdAt = 1): StoredInvite => ({
  lid,
  iss,
  blob: "x".repeat(size),
  size,
  createdAt,
  expiresAt,
  src: "s",
});

describe("invite sweep steps are bounded (both stores)", () => {
  for (const [name, mk] of [
    ["memory", () => new MemoryStore()],
    ["sqlite", () => new SqliteStore(join(dir, "s.db"))],
  ] as [string, () => Store][]) {
    it(`sweepInvites deletes at most \`limit\` invites and tombstones per call and keeps every total (${name})`, () => {
      const s = mk();
      for (let i = 0; i < 25; i++) s.putInvite(inv(`a${i}`, i % 2 ? "A" : "B", 10, 100 + i));
      s.putInvite(inv("live", "A", 7, 10_000));
      // 12 tombstones that expire at 500 (evicted from a second user).
      for (let i = 0; i < 12; i++) s.putInvite(inv(`c${i}`, "C", 1000, 500, 1000 + i));
      expect(s.evictInvites(12_000)).toBe(12_000);
      expect(s.evictedInvitesOf("C", 0)).toHaveLength(12);
      expect(s.inviteBytes()).toBe(257);

      expect(s.sweepInvites(1000, 10)).toEqual({ invites: 10, evicted: 10 });
      expect(s.inviteBytes()).toBe(157);
      expect(s.sweepInvites(1000, 10)).toEqual({ invites: 10, evicted: 2 });
      expect(s.sweepInvites(1000, 10)).toEqual({ invites: 5, evicted: 0 });
      expect(s.sweepInvites(1000, 10)).toEqual({ invites: 0, evicted: 0 });
      expect([s.inviteBytesOfIss("A"), s.inviteBytesOfIss("B"), s.inviteBytes()]).toEqual([7, 0, 7]);
      expect(s.invitesOf("A", 1000)).toEqual(["live"]);
      s.close();
    });

    it(`evictInvites(bytes, now) takes already-expired invites before any live one, with no tombstone (${name})`, () => {
      const s = mk();
      s.putInvite(inv("old1", "A", 50, 100));
      s.putInvite(inv("old2", "A", 50, 200));
      s.putInvite(inv("live", "A", 500, 10_000, 5));
      expect(s.evictInvites(60, 1000)).toBe(100);
      expect(s.invitesOf("A", 1000)).toEqual(["live"]);
      expect(s.evictedInvitesOf("A", 0)).toEqual([]);
      expect([s.inviteBytesOfIss("A"), s.inviteBytes()]).toEqual([500, 500]);
      s.close();
    });
  }

  it("sqlite: init rebuilds the per-userId totals in chunks and the byte counter matches a scan", async () => {
    const path = join(dir, "r.db");
    const a = new SqliteStore(path);
    a.transaction(() => {
      for (let i = 0; i < 5000; i++) a.putInvite(inv(`i${i}`, `U${i % 37}`, 3 + (i % 5), 9e15));
    });
    a.close();
    // Damage the counters, as an interrupted older version might have.
    const raw = new DatabaseSync(path);
    raw.exec("UPDATE invite_iss SET bytes = 1; DELETE FROM invite_iss WHERE iss = 'U3';");
    raw.close();
    const b = new SqliteStore(path);
    await b.init();
    const scan = new DatabaseSync(path);
    const want = scan.prepare("SELECT iss, sum(size) AS b FROM invites GROUP BY iss ORDER BY iss").all() as { iss: string; b: number }[];
    const total = Number((scan.prepare("SELECT sum(size) AS b FROM invites").get() as { b: number }).b);
    scan.close();
    for (const w of want) expect(b.inviteBytesOfIss(w.iss)).toBe(Number(w.b));
    expect(b.inviteBytes()).toBe(total);
    b.close();
  });
});

describe("a large expired invite table doesn't stall the event loop", () => {
  it("relay.sweep() clears 20,000 expired invites (40 MB) in yielding steps, keeping the live ones and their totals", async () => {
    const path = join(dir, "big.db");
    const N = 20_000;
    const seed = new SqliteStore(path, { backgroundCheckpoint: false });
    seed.transaction(() => {
      for (let i = 0; i < N; i++) seed.putInvite(inv(`e${i}`, `U${i % 500}`, 2048, 1000 + i));
      for (let i = 0; i < 50; i++) seed.putInvite(inv(`l${i}`, `U${i}`, 100, 9e15));
    });
    seed.close();

    r = await startRelay({ store: new SqliteStore(path) });
    const st = R().store;
    expect(st.inviteBytes()).toBe(N * 2048 + 50 * 100);

    // Deterministic (pre-release review: this used to time the longest event-loop gap, which fails under
    // load): every step is bounded in rows and followed by a yield, which is what keeps the loop
    // free whatever the machine's speed.
    const rows: number[] = [];
    let yielded = true;
    let alwaysYielded = true;
    const orig = st.sweepInvites.bind(st);
    st.sweepInvites = (now: number, limit: number) => {
      if (!yielded) alwaysYielded = false;
      yielded = false;
      setImmediate(() => {
        yielded = true;
      });
      rows.push(limit);
      return orig(now, limit);
    };
    await R().relay.sweep();
    expect(rows.length).toBeGreaterThanOrEqual(10);
    expect(Math.max(...rows)).toBeLessThanOrEqual(2000);
    expect(alwaysYielded).toBe(true);

    expect(st.inviteBytes()).toBe(50 * 100);
    for (let i = 0; i < 50; i++) expect(st.inviteBytesOfIss(`U${i}`)).toBe(100);
    expect(st.inviteBytesOfIss("U499")).toBe(0);
    const raw = new DatabaseSync(path);
    expect(Number((raw.prepare("SELECT count(*) AS n FROM invites").get() as { n: number }).n)).toBe(50);
    expect(Number((raw.prepare("SELECT count(*) AS n FROM invite_iss").get() as { n: number }).n)).toBe(50);
    raw.close();
  }, 60_000);
});

const R = () => r as TestRelay;
