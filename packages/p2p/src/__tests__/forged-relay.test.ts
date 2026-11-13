// Copyright 2026 Ix Infrastructure Inc.
//
// #67: someone holding the identity key (a thief) and one of the relays the owner lists serves a forged chain
// of the owner's identity, signed with that key, at a far higher `ver`, that doesn't connect to the owner's
// history. The owner's strict refresh before publishing can't confirm the head over every listed relay. The
// owner must still be able to remove that relay and to rotate; any other edit refuses and names the relay;
// and a forged chain never makes the owner publish below or beside the head the other relays confirm.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { b64uDecode, createIdentityDoc, generateDeviceKeysV3, identityKeyFromSeed, jwsHash, nowSec, peekIdentityDoc } from "@peer2peer/core/v3";
import { startRelay, User, type TestRelay } from "./harness.js";

const R1 = "wss://relay-honest.test/v3";
const R2 = "wss://relay-forged.test/v3";
let r1: TestRelay;
let r2: TestRelay;

const keysOf = (u: User) => JSON.parse(readFileSync(join(u.home, "cli", "keys.json"), "utf8")) as { userId: string; did: string; ik?: string };

/** A chain signed with u's identity key, `count` versions from far above, whose first `prev` no relay holds. */
function forgedChain(u: User, userId: string, count: number): { hash: string; jws: string; prev: string | null }[] {
  const ik = identityKeyFromSeed(b64uDecode(keysOf(u).ik!, 32));
  const mallory = generateDeviceKeysV3(userId).did;
  const out: { hash: string; jws: string; prev: string | null }[] = [];
  let prev = "A".repeat(43);
  for (let v = 5000; v < 5000 + count; v++) {
    const jws = createIdentityDoc(ik, { ver: v, prev, name: u.name, relays: [R1, R2], devices: [mallory], keyholders: [mallory], by: mallory, iat: nowSec() - 5 });
    out.push({ hash: jwsHash(jws), jws, prev });
    prev = jwsHash(jws);
  }
  return out;
}

/**
 * Makes R2 serve `forged` for `userId`'s tips and chain walk over HTTP, as a hostile relay would (its
 * WebSocket side stays the real relay's). Everything else goes through.
 */
function hostileR2(userId: string, forged: { hash: string; jws: string; prev: string | null }[]) {
  const real = globalThis.fetch;
  const base = `http://127.0.0.1:${r2.port}/v3/identity/${encodeURIComponent(userId)}/`;
  const json = (v: unknown) => new Response(JSON.stringify(v), { status: 200, headers: { "content-type": "application/json" } });
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url.startsWith(base)) {
      const u = new URL(url);
      if (u.pathname.endsWith("/tips")) return json({ tips: [forged[forged.length - 1].jws] });
      if (u.pathname.endsWith("/chain")) {
        const byHash = new Map(forged.map((d) => [d.hash, d]));
        const n = Number(u.searchParams.get("n") ?? "64");
        const docs: string[] = [];
        for (let d = byHash.get(u.searchParams.get("to") ?? ""); d && docs.length < n; d = d.prev ? byHash.get(d.prev) : undefined) docs.push(d.jws);
        return json({ docs });
      }
    }
    return real(input, init);
  });
}

/** A user listing R1 and R2, with R2 serving a forged chain of its identity. */
async function victim(name: string) {
  const u = new User(name, { [R1]: `ws://127.0.0.1:${r1.port}/v3`, [R2]: `ws://127.0.0.1:${r2.port}/v3` });
  const userId = (await u.ok(["init", "--name", name, "--relay", R1, "--yes"])).userId as string;
  await u.ok(["relays", "add", R2]);
  const forged = forgedChain(u, userId, 3);
  return { u, userId, forged };
}

async function heldHead(u: User) {
  const app = await u.app();
  await app.load();
  try {
    return (await app.ownView()).head;
  } finally {
    await app.close();
  }
}

beforeAll(async () => {
  r1 = await startRelay(R1);
  r2 = await startRelay(R2);
}, 60_000);

afterEach(() => {
  vi.restoreAllMocks();
});

afterAll(async () => {
  await r1?.close();
  await r2?.close();
});

describe("#67: a listed relay serving a forged chain signed with the identity key", () => {
  it("an ordinary edit refuses and names the relay; removing that relay goes ahead; then edits work again", async () => {
    const { u, userId, forged } = await victim("ann");
    const before = await heldHead(u);
    hostileR2(userId, forged);
    // Any other edit: refused (not publishing on a head it couldn't confirm), naming R2 and the remedy.
    const edit = await u.run(["profile", "set", "--bio", "hello"]);
    expect(edit.code).not.toBe(0);
    expect(edit.json.error).toBe("refresh_failed");
    expect(edit.json.reason).toContain(R2);
    expect(edit.json.reason).toMatch(/rotate/);
    expect((await heldHead(u)).hash).toBe(before.hash);
    // Removing R2: the refresh over the relays kept (R1) is complete, so it goes ahead, with a warning.
    const removed = await u.run(["relays", "remove", R2]);
    expect(removed.code).toBe(0);
    expect(removed.json.relays).toEqual([R1]);
    expect(removed.err).toContain(R2);
    expect(removed.err).toMatch(/someone else holds your identity key/);
    // Published at head.ver + 1 on the head R1 confirmed: never below it, never a fork of it.
    const after = await heldHead(u);
    expect(after.ver).toBe(before.ver + 1);
    expect(after.prev).toBe(before.hash);
    expect(after.relays).toEqual([R1]);
    // R1 holds it as its head.
    const tips = (await (await fetch(`http://127.0.0.1:${r1.port}/v3/identity/${encodeURIComponent(userId)}/tips`)).json()) as { tips: string[] };
    expect(tips.tips.map((t) => peekIdentityDoc(t).hash)).toEqual([after.hash]);
    // R2 is no longer listed, so it is no longer asked: edits work again.
    expect((await u.ok(["profile", "set", "--bio", "still mine"])).profile.bio).toBe("still mine");
  }, 120_000);

  it("removing another relay doesn't set the forged one aside", async () => {
    const { u, userId, forged } = await victim("bea");
    hostileR2(userId, forged);
    // R1 is the one removed; R2 (forged) stays listed, so the kept relays' refresh still can't confirm the head.
    const r = await u.run(["relays", "remove", R1]);
    expect(r.code).not.toBe(0);
    expect(r.json.error).toBe("refresh_failed");
    expect(r.json.reason).toContain(R2);
  }, 120_000);

  it("removing it still builds on the newest version the kept relays serve, not on a stale local head", async () => {
    const { u, userId, forged } = await victim("dee");
    // Another device of ours published v(n+1) (here: published, then dropped from this device's store).
    await u.ok(["profile", "set", "--bio", "from another device"]);
    const newest = await heldHead(u);
    const app = await u.app();
    await app.load();
    await app.store.updateIdentity(userId, (cur) => ({ next: { ...cur!, versions: cur!.versions.filter((j) => peekIdentityDoc(j).hash !== newest.hash) }, result: undefined }));
    await app.close();
    expect((await heldHead(u)).ver).toBe(newest.ver - 1);
    hostileR2(userId, forged);
    const removed = await u.ok(["relays", "remove", R2]);
    expect(removed.relays).toEqual([R1]);
    const after = await heldHead(u);
    expect(after.ver).toBe(newest.ver + 1);
    expect(after.prev).toBe(newest.hash);
    expect(after.profile?.bio).toBe("from another device");
  }, 120_000);

  it("rotation goes ahead (the forged relay set aside), and its final version builds on the confirmed head", async () => {
    const { u, userId, forged } = await victim("cat");
    const before = await heldHead(u);
    hostileR2(userId, forged);
    const r = await u.run(["identity", "rotate", "--yes", "--wait", "1", "--backup-file"]);
    expect(r.code, `${r.out}\n${r.err}`).toBe(0);
    expect(r.err).toContain(R2);
    // The old identity's final version: head.ver + 1 on the head R1 confirmed (or a later one of ours).
    const tips = (await (await fetch(`http://127.0.0.1:${r1.port}/v3/identity/${encodeURIComponent(userId)}/tips`)).json()) as { tips: string[] };
    const final = tips.tips.map((t) => peekIdentityDoc(t));
    expect(final).toHaveLength(1);
    expect(final[0].rotation).toBeDefined();
    expect(final[0].ver).toBeGreaterThan(before.ver);
    expect(final[0].ver).toBeLessThan(5000);
  }, 180_000);
});
