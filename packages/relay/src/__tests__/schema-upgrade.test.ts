// Copyright 2026 Ix Infrastructure Inc.
// A relay built from main ed8e3d4 is deployed. Its database must open with
// this build and upgrade in place: schema version 1 kept, only additive
// `IF NOT EXISTS` changes, and no data lost.

import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SqliteStore } from "../sqlite-store.js";
import { authed, makeDevice, makeDoc, makeIdentity, startRelay, type TestRelay } from "./helpers.js";

const ED8E3D4_SCHEMA = readFileSync(new URL("testdata/schema-ed8e3d4.sql", import.meta.url), "utf8");

let dir: string;
let r: TestRelay | undefined;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "p2p-relay-upgrade-"));
});
afterEach(async () => {
  await r?.close();
  r = undefined;
  rmSync(dir, { recursive: true, force: true });
});

/** Builds a database exactly as ed8e3d4 would have left it, with data in every table. */
function buildOld(path: string, now: number) {
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL");
  db.exec(ED8E3D4_SCHEMA);
  db.prepare("INSERT INTO meta (k, v) VALUES ('schema', '1')").run();
  const bob = makeDevice(makeIdentity(), Math.floor(now / 1000));
  const iss = bob.identity.userId;
  db.prepare("INSERT INTO devices (did, iss, last_seen, evictable) VALUES (?, ?, ?, 0)").run(bob.did, iss, now);
  const envs: string[] = [];
  for (let i = 0; i < 5; i++) {
    const env = `old-envelope-${i}-${"x".repeat(100)}`;
    envs.push(env);
    // ed8e3d4 tags: a plain keyed hash, no process-generation prefix.
    db.prepare("INSERT INTO envelopes (mbox_to, mbox_did, src, size, received_at, env) VALUES (?, ?, ?, ?, ?, ?)").run(
      iss,
      bob.did,
      i % 2 ? "oldTagA" : "oldTagB",
      env.length,
      now - 1000,
      env,
    );
  }
  db.exec(`
    INSERT INTO totals SELECT 'all', '', coalesce(sum(size), 0), count(*) FROM envelopes;
    INSERT INTO totals SELECT 'mbox', mbox_to || char(10) || mbox_did, sum(size), count(*) FROM envelopes GROUP BY mbox_to, mbox_did;
    INSERT INTO totals SELECT 'rcpt', mbox_to, sum(size), count(*) FROM envelopes GROUP BY mbox_to;
    INSERT INTO totals SELECT 'src', src, sum(size), count(*) FROM envelopes GROUP BY src;
    INSERT INTO totals SELECT 'rsrc', mbox_to || char(10) || src, sum(size), count(*) FROM envelopes GROUP BY mbox_to, src;
    INSERT INTO totals SELECT 'smbox', src || char(10) || mbox_to || char(10) || mbox_did, sum(size), count(*) FROM envelopes GROUP BY src, mbox_to, mbox_did;
  `);
  const doc = makeDoc(bob.identity, Math.floor(now / 1000), { devices: [bob.did] });
  db.prepare(
    "INSERT INTO identity_docs (hash, iss, ver, prev, merge, devices, iat, exp, received_at, jws) VALUES (?, ?, 1, NULL, NULL, ?, ?, ?, ?, ?)",
  ).run(doc.hash, iss, JSON.stringify([bob.did]), Math.floor(now / 1000) - 60, Math.floor(now / 1000) + 86400, now, doc.jws);
  db.prepare("INSERT INTO identity_index (iss, head, head_ver, head_exp, tips, allowed, cap, left_at) VALUES (?, ?, 1, ?, ?, ?, NULL, NULL)").run(
    iss,
    doc.hash,
    Math.floor(now / 1000) + 86400,
    JSON.stringify([doc.hash]),
    JSON.stringify([bob.did]),
  );
  db.prepare("INSERT INTO allowed_devices (did, iss) VALUES (?, ?)").run(bob.did, iss);
  db.prepare("INSERT INTO identity_seen (iss, did, at) VALUES (?, ?, ?)").run(iss, "d_oooooooooooooooooooooooooo", now);
  db.prepare("INSERT INTO caps (key, revoked, uses, updated_at) VALUES ('capkey', 1, 3, ?)").run(now);
  db.close();
  return { bob, envs, doc };
}

function dump(path: string) {
  const db = new DatabaseSync(path);
  try {
    const tables = ["devices", "envelopes", "identity_docs", "identity_index", "allowed_devices", "identity_seen", "caps", "meta"];
    const rows: Record<string, unknown[]> = {};
    for (const t of tables) rows[t] = db.prepare(`SELECT * FROM ${t} ORDER BY 1`).all();
    const indexes = (db.prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_%' ORDER BY name").all() as { name: string }[]).map((x) => x.name);
    const totals = db.prepare("SELECT kind, key, bytes, n FROM totals ORDER BY kind, key").all();
    const recount = db.prepare("SELECT coalesce(sum(size), 0) AS b, count(*) AS n FROM envelopes").get() as { b: number; n: number };
    return { rows, indexes, totals, recount };
  } finally {
    db.close();
  }
}

describe("upgrading a database written by main ed8e3d4", () => {
  it("opens, upgrades additively, keeps every row, and serves the old data", async () => {
    const path = join(dir, "relay.db");
    const now = Date.now();
    const { bob, envs, doc } = buildOld(path, now);
    const before = dump(path);

    // Open with this build (init runs), close, and open again (idempotent).
    for (let i = 0; i < 2; i++) {
      const s = new SqliteStore(path);
      await s.init();
      s.close();
    }
    const after = dump(path);
    // Every pre-existing row is untouched, in every table.
    expect(after.rows).toEqual(before.rows);
    expect((after.rows.meta as { k: string; v: string }[]).find((m) => m.k === "schema")?.v).toBe("1");
    // Only additions to the schema.
    for (const ix of before.indexes) expect(after.indexes).toContain(ix);
    expect(after.indexes).toContain("identity_received");
    // Totals agree with the envelopes.
    const all = (after.totals as { kind: string; bytes: number; n: number }[]).find((t) => t.kind === "all");
    expect(all).toMatchObject({ bytes: Number(after.recount.b), n: Number(after.recount.n) });

    // The relay serves the old data: the head document and the stored mail.
    r = await startRelay({ store: new SqliteStore(path), clock: { t: now, now: () => now, advance: () => {} } });
    expect((await (await fetch(`${r.http}/v3/identity/${bob.identity.userId}`)).json()).doc).toBe(doc.jws);
    const bc = await authed(r, bob);
    const got = (await bc.drainEnvs(300)).map((e) => e.env);
    expect(got).toEqual(envs);
    expect(r.store.capState("capkey")).toEqual({ revoked: true, uses: 3 });
    expect(r.store.seenDevices(bob.identity.userId, 0)).toEqual(["d_oooooooooooooooooooooooooo"]);
  });
});
