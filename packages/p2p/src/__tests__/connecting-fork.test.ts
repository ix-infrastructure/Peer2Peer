// Copyright 2026 Ix Infrastructure Inc.
//
// #75: someone holding the identity key publishes a version that connects to the owner's history (a
// sibling of the owner's head) and lists none of the owner's devices. The owner's view is then forked, the
// owner's devices fall out of the intersection, and the relays refuse them. Rotation (§2.8) must still
// work from the owner's own branch, and friends follow it. A device listed on no branch (one the owner
// revoked) can't take that path.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { b64uDecode, createIdentityDoc, generateDeviceKeysV3, identityKeyFromSeed, nowSec, peekIdentityDoc } from "@peer2peer/core/v3";
import { linkJoin, linkStart } from "../identity.js";
import { receiving } from "../inbound.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-fork.test/v3";
let relay: TestRelay;
const users: User[] = [];
const ids: Record<string, string> = {};

const keysOf = (u: User) =>
  JSON.parse(readFileSync(join(u.home, "cli", "keys.json"), "utf8")) as {
    userId: string;
    did: string;
    ik?: string;
  };

function user(name: string): User {
  const u = new User(name, { [R]: `ws://127.0.0.1:${relay.port}/v3` });
  users.push(u);
  return u;
}

async function init(u: User): Promise<void> {
  ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
}

async function link(owner: User, dev: User, label: string, keyholder = false): Promise<void> {
  const a = await owner.app();
  await a.load();
  receiving(a);
  const start = await linkStart(a, { keyholder });
  const b = await dev.app();
  const join = await linkJoin(b, start.code, { label });
  await Promise.all([start.wait(async (req) => req.compareCode === join.compareCode), join.wait()]);
  await a.close();
  await b.close();
}

async function befriend(a: User, b: User): Promise<void> {
  const inv = await a.ok(["invite", "--link"]);
  await b.ok(["accept", inv.link]);
  await a.ok(["friends"]);
  await b.ok(["friends"]);
}

async function relayTips(userId: string) {
  const r = (await (await fetch(`http://127.0.0.1:${relay.port}/v3/identity/${encodeURIComponent(userId)}/tips`)).json()) as { tips: string[] };
  return r.tips.map((t) => peekIdentityDoc(t));
}

/**
 * Someone holding `owner`'s identity key publishes a sibling of the owner's head (same ver, same prev) that
 * lists only a device of theirs. It connects to the owner's history, so every refresh takes it.
 */
async function connectingFork(owner: User): Promise<{ hash: string; mallory: string }> {
  const userId = keysOf(owner).userId;
  const [head] = await relayTips(userId);
  expect(head.prev).toBeTruthy();
  const ik = identityKeyFromSeed(b64uDecode(keysOf(owner).ik!, 32));
  const mallory = generateDeviceKeysV3(userId).did;
  const jws = createIdentityDoc(ik, {
    ver: head.ver,
    prev: head.prev!,
    name: head.name,
    relays: [...head.relays],
    devices: [mallory],
    keyholders: [mallory],
    by: mallory,
    iat: nowSec() - 5,
  });
  const app = await owner.app();
  await app.load();
  try {
    const r = await app.publishDoc(jws, [R]);
    expect(r.ok).toEqual([R]);
  } finally {
    await app.close();
  }
  expect((await relayTips(userId)).map((t) => t.hash)).toContain(peekIdentityDoc(jws).hash);
  return { hash: peekIdentityDoc(jws).hash, mallory };
}

beforeAll(async () => {
  relay = await startRelay(R);
}, 60_000);

afterAll(async () => {
  await relay?.close();
  for (const u of users) u.cleanup();
});

describe("#75: a key holder's connecting fork that drops the owner's devices", () => {
  it("the owner still rotates (the final version built from the owner's branch), and a friend follows", async () => {
    const ann = user("ann");
    const ann2 = user("ann2");
    const bob = user("bob");
    for (const u of [ann, bob]) await init(u);
    await link(ann, ann2, "laptop");
    await befriend(ann, bob);
    const own = (await relayTips(ids.ann))[0];
    const fork = await connectingFork(ann);
    // An ordinary edit can't go ahead (a merge would leave this device unlisted), and leaves nothing behind
    // that would hide the owner's branch from the rotation.
    const edit = await ann.run(["profile", "set", "--bio", "still mine"]);
    expect(edit.json.error).toBe("device_revoked");
    // The plan lists the owner's own devices, never the other branch's.
    const plan = await ann.ok(["identity", "rotate", "--plan"]);
    expect(plan.follow.map((d: any) => d.did)).toEqual([keysOf(ann2).did]);
    expect(JSON.stringify(plan)).not.toContain(fork.mallory);
    // bob is invited: the friendship this device made counts, though the forked view can't verify it now.
    expect(plan.friends).toBe(1);
    const res = await ann.run(["identity", "rotate", "--resume", "--yes", "--wait", "1", "--backup-file"]);
    expect(res.code, `${res.out}\n${res.err}`).toBe(0);
    expect(res.json).toMatchObject({ step: "done" });
    // The relays refuse ann's devices, so her old laptop re-links by hand.
    expect(res.json.devices.followed).toEqual([]);
    // The final version lists nobody and carries the statement. It follows a merge of the two branches that
    // also lists nobody, with the owner's name and relays (a restricted connection takes nothing beside a tip).
    const tips = await relayTips(ids.ann);
    expect(tips).toHaveLength(1);
    const [final] = tips;
    expect(final.rotation).toBeDefined();
    expect(final).toMatchObject({
      devices: [],
      keyholders: [],
      relays: own.relays,
      name: own.name,
    });
    const chain = (await (await fetch(`http://127.0.0.1:${relay.port}/v3/identity/${encodeURIComponent(ids.ann)}/chain?to=${final.prev}&n=1`)).json()) as { docs: string[] };
    const merge = peekIdentityDoc(chain.docs[0]);
    expect(merge.hash).toBe(final.prev);
    expect([merge.prev, merge.merge].sort()).toEqual([own.hash, fork.hash].sort());
    expect(merge).toMatchObject({
      devices: [],
      keyholders: [],
      relays: own.relays,
      name: own.name,
    });
    // bob follows: one rotation, carried by ann's own document.
    const items = (await bob.ok(["held"])).held.filter((h: any) => h.type === "rotation");
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({ from: res.json.to, old: ids.ann });
    await bob.ok(["held", "approve", items[0].id]);
    const bf = (await bob.ok(["friends"])).friends.map((f: any) => f.userId);
    expect(bf).toContain(res.json.to);
    expect(bf).not.toContain(ids.ann);
  }, 180_000);

  it("a device listed on no branch (revoked by the owner) can't use that path: nothing is published", async () => {
    const cy = user("cy");
    const cy2 = user("cy2");
    await init(cy);
    await link(cy, cy2, "old phone", true);
    const cy2Did = keysOf(cy2).did;
    // cy revokes the key holder; then a key holder's fork drops cy as well.
    await cy.ok(["devices", "revoke", cy2Did]);
    const before = await relayTips(ids.cy);
    expect(before.every((t) => !t.devices.includes(cy2Did))).toBe(true);
    const fork = await connectingFork(cy);
    const r = await cy2.run(["identity", "rotate", "--yes", "--wait", "1", "--backup-file"]);
    expect(r.code).not.toBe(0);
    expect(r.json.error).toBe("device_revoked");
    const after = await relayTips(ids.cy);
    expect(after.filter((t) => t.rotation !== undefined)).toEqual([]);
    expect(after.map((t) => t.hash).sort()).toEqual([...before.map((t) => t.hash), fork.hash].sort());
  }, 180_000);
});
