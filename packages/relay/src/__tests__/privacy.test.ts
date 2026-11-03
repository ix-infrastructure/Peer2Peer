// Copyright 2026 Ix Infrastructure Inc.
// The privacy promise: the relay stores envelopes as opaque JWS plus routing
// fields, never keeps capabilities, and never logs contents, caps or raw ids.

import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SqliteStore } from "../sqlite-store.js";
import { authed, makeCap, makeDevice, makeEnvelope, makeIdentity, startRelay, TestClient, type TestRelay } from "./helpers.js";

let dir: string;
let r: TestRelay;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "p2p-relay-privacy-"));
});
afterEach(async () => {
  await r?.close();
  rmSync(dir, { recursive: true, force: true });
});

/** Every byte the relay put on disk: the DB, its WAL and any shm/journal. */
function diskBytes(): string {
  return readdirSync(dir)
    .map((f) => readFileSync(join(dir, f)).toString("latin1"))
    .join("\n");
}

describe("no plaintext at rest or in logs", () => {
  it("test payload strings never appear in the DB files or the (debug-level) logs", async () => {
    r = await startRelay({ store: new SqliteStore(join(dir, "relay.db")) });
    const SECRET_TEXT = "SECRET-PLAINTEXT-7f3a9c";
    const SECRET_LABEL = "SECRET-DEVICE-LABEL-b21e";
    const SECRET_LINK = "SECRET-LINK-DATA-55d0";
    const alice = makeDevice(makeIdentity(), r.nowSec(), { label: SECRET_LABEL });
    const bob = makeDevice(makeIdentity(), r.nowSec());
    const ac = await authed(r, alice);
    const bc = await authed(r, bob);
    const cap = makeCap(bob, r.nowSec(), { sub: alice.identity.userId, uses: 5 });

    const envs: string[] = [];
    for (let i = 0; i < 3; i++) {
      const env = makeEnvelope(alice, { userId: bob.identity.userId, did: bob.did }, { plaintext: `${SECRET_TEXT} #${i}` });
      envs.push(env);
      expect(await ac.request({ t: "send", to: bob.identity.userId, tdid: bob.did, env, cap: cap.jws })).toMatchObject({ t: "sent" });
    }
    // Some failures too, so error paths are logged.
    await ac.request({ t: "send", to: bob.identity.userId, tdid: bob.did, env: envs[0], cap: "garbage-cap" });
    await ac.request({ t: "revoke", capid: cap.capid });

    // Link data goes through the relay too.
    const { b32Encode } = await import("../crypto.js");
    const lid = b32Encode(new Uint8Array(20).fill(7)).slice(0, 26);
    await ac.request({ t: "link-open", lid });
    const anon = await TestClient.connect(r.url);
    await anon.request({ t: "link-put", lid, slot: "req", data: SECRET_LINK });

    await bc.drainEnvs();
    await anon.close();
    await r.close();

    const disk = diskBytes();
    const logs = r.logs.join("\n");
    expect(logs.length).toBeGreaterThan(0);
    for (const s of [SECRET_TEXT, SECRET_LABEL, SECRET_LINK]) {
      expect(disk).not.toContain(s);
      expect(logs).not.toContain(s);
    }
    // The capability itself (and its capid) is never stored or logged; nor is
    // any raw identifier logged.
    for (const s of [cap.jws, cap.capid, alice.cert]) {
      expect(disk).not.toContain(s);
      expect(logs).not.toContain(s);
    }
    for (const s of [alice.identity.userId, bob.identity.userId, alice.did, bob.did, "127.0.0.1", lid]) {
      expect(logs).not.toContain(s);
    }
    // Every log line is a JSON object.
    for (const line of r.logs) expect(() => JSON.parse(line)).not.toThrow();
  });

  it("acked envelopes don't linger on disk (secure_delete)", async () => {
    const path = join(dir, "relay.db");
    r = await startRelay({ store: new SqliteStore(path) });
    const alice = makeDevice(makeIdentity(), r.nowSec());
    const bob = makeDevice(makeIdentity(), r.nowSec());
    const ac = await authed(r, alice);
    const bc = await authed(r, bob);
    const cap = makeCap(bob, r.nowSec());
    const env = makeEnvelope(alice, { userId: bob.identity.userId, did: bob.did });
    await ac.request({ t: "send", to: bob.identity.userId, tdid: bob.did, env, cap: cap.jws });
    const got = await bc.next((f) => f.t === "env");
    bc.send({ t: "ack", rids: [got.rid] });
    await new Promise((res) => setTimeout(res, 50));
    await r.close();
    // The envelope's ciphertext segment is gone from the DB and WAL.
    const ctSegment = env.split(".")[1].slice(200, 260);
    expect(diskBytes()).not.toContain(ctSegment);
  });
});
