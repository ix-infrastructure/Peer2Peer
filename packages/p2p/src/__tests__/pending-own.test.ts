// Copyright 2026 Ix Infrastructure Inc.
//
// Review of #65 (M1): a pending head (core #35) narrows trust in an identity's devices while a refresh is
// incomplete, but never this device's view of its own identity. A version only the identity key signed (a
// thief's, at a far-future ver, listing none of the owner's devices) must not stop the owner from editing the
// identity or rotating away from the stolen key.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { b64uDecode, createIdentityDoc, generateDeviceKeysV3, getIdentityView, identityKeyFromSeed, nowSec } from "@peer2peer/core/v3";
import { rotatePlan } from "../rotation.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-pending.test/v3";
let relay: TestRelay;
let ann: User;
let userId = "";

const keysOf = (u: User) => JSON.parse(readFileSync(join(u.home, "cli", "keys.json"), "utf8")) as { userId: string; did: string; ik?: string };

beforeAll(async () => {
  relay = await startRelay(R);
  ann = new User("ann", { [R]: `ws://127.0.0.1:${relay.port}/v3` });
  userId = (await ann.ok(["init", "--name", "ann", "--relay", R, "--yes"])).userId;
  // Plant a pending head the way an incomplete refresh would: signed by ann's identity key, far ahead,
  // listing only a stranger's device.
  const ik = identityKeyFromSeed(b64uDecode(keysOf(ann).ik!, 32));
  const mallory = generateDeviceKeysV3(userId).did;
  const forged = createIdentityDoc(ik, { ver: Number.MAX_SAFE_INTEGER - 1, prev: "A".repeat(43), name: "ann", relays: [R], devices: [mallory], keyholders: [mallory], by: mallory, iat: nowSec() - 5 });
  const app = await ann.app();
  await app.load();
  await app.store.updateIdentity(userId, (cur) => ({ next: { ...cur!, pendingHeads: [forged] }, result: undefined }));
  await app.close();
}, 60_000);

afterAll(async () => {
  await relay?.close();
});

describe("M1: a pending head never narrows the owner's own view", () => {
  it("others' view of the identity is narrowed; the owner's own isn't", async () => {
    const app = await ann.app();
    await app.load();
    try {
      expect((await getIdentityView(app.store, userId))!.devices).toEqual([]);
      expect((await app.ownView()).devices).toEqual([keysOf(ann).did]);
    } finally {
      await app.close();
    }
  });

  it("the owner can still plan a rotation from this key holder", async () => {
    const app = await ann.app();
    await app.load();
    try {
      const plan = await rotatePlan(app);
      expect(plan).toBeDefined();
    } finally {
      await app.close();
    }
  });

  it("the owner can still publish an identity edit (no device_revoked); its complete refresh clears the pending head", async () => {
    const r = await ann.ok(["profile", "set", "--bio", "still mine"]);
    expect(r.profile.bio).toBe("still mine");
    const app = await ann.app();
    await app.load();
    try {
      expect((await app.store.getIdentity(userId))!.pendingHeads).toBeUndefined();
      expect((await getIdentityView(app.store, userId))!.devices).toEqual([keysOf(ann).did]);
    } finally {
      await app.close();
    }
  });
});
