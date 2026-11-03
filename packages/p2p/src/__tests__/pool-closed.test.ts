// Copyright 2026 Ix Infrastructure Inc.
//
// A closed relay pool never dials again (pre-release review). A handler that outlives its command, still
// sending (a long answer, say), used to re-dial through the closed pool's `ensure`: a connection
// nobody closes, authenticated as this device, that took (and acked) envelopes meant for the next
// command or the running watch.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-pool-closed.test/v3";
let relay: TestRelay;
let u: User;

beforeAll(async () => {
  relay = await startRelay(R);
  u = new User("pc", { [R]: `ws://127.0.0.1:${relay.port}/v3` });
  await u.ok(["init", "--name", "pc", "--relay", R, "--yes"]);
});

afterAll(async () => {
  await relay?.close();
  u?.cleanup();
});

describe("a closed relay pool", () => {
  it("refuses to dial again, so nothing outlives the command it belonged to", async () => {
    const a = await u.app();
    await a.load();
    const pool = await a.connect();
    expect((await pool.ensure(R)).authed).toBe(true);
    await a.close();
    await expect(pool.ensure(R)).rejects.toThrow(/closed its relay connections/);
    // Nothing reconnected behind the closed pool's back.
    await new Promise((r) => setTimeout(r, 300));
    await expect(pool.ensure(R)).rejects.toThrow(/closed its relay connections/);
  });
});
