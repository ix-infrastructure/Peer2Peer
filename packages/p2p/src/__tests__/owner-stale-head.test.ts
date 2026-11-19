// Copyright 2026 Ix Infrastructure Inc.
//
// #78: a strict refresh of the owner's own identity skips relays that don't answer. When the up-to-date relay
// times out and a lagging one answers, the owner's edit must not build on the lagging relay's stale head while
// this device already holds the newer version as a pending head an earlier refresh got from the silent relay
// (that would fork the owner's own chain). And no single relay may hold the owner up for good: one that
// answers, one named as serving a forged chain, or one the edit removes never blocks it.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { b64uDecode, createIdentityDoc, generateDeviceKeysV3, IDENTITY_DOC_MAX_TTL_SEC, identityKeyFromSeed, jwsHash, nowSec, peekIdentityDoc } from "@peer2peer/core/v3";
import { maintain } from "../watch.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const RA = "wss://relay-current.test/v3";
const RB = "wss://relay-lagging.test/v3";
const RC = "wss://relay-third.test/v3";
let ra: TestRelay;
let rb: TestRelay;
let rc: TestRelay;

const keysOf = (u: User) => JSON.parse(readFileSync(join(u.home, "cli", "keys.json"), "utf8")) as { userId: string; did: string; ik?: string };
const json = (v: unknown) => new Response(JSON.stringify(v), { status: 200, headers: { "content-type": "application/json" } });

beforeAll(async () => {
  ra = await startRelay(RA);
  rb = await startRelay(RB);
  rc = await startRelay(RC);
}, 60_000);

afterEach(() => {
  vi.restoreAllMocks();
});

afterAll(async () => {
  await ra?.close();
  await rb?.close();
  await rc?.close();
});

async function heldHead(u: User) {
  const app = await u.app();
  await app.load();
  try {
    return (await app.ownView()).head;
  } finally {
    await app.close();
  }
}

/** Rewrites this device's store of its own identity. */
async function storeOwn(u: User, userId: string, f: (cur: Record<string, unknown> & { versions: string[] }) => Record<string, unknown>) {
  const app = await u.app();
  await app.load();
  try {
    await app.store.updateIdentity(userId, (cur) => ({ next: f(cur as never) as never, result: undefined }));
  } finally {
    await app.close();
  }
}

async function realTips(port: number, userId: string) {
  return ((await (await fetch(`http://127.0.0.1:${port}/v3/identity/${encodeURIComponent(userId)}/tips`)).json()) as { tips: string[] }).tips.map((t) => peekIdentityDoc(t));
}

/**
 * Identity fetches: `silent` relays (by port) time out (here: fail), `lagging` ones serve only `stale`
 * (tips: its newest; chain: walked back within it). The rest go through.
 */
function network(userId: string, opts: { silent?: number[]; lagging?: { port: number; stale: string[] }[] }) {
  const real = globalThis.fetch;
  const id = `/v3/identity/${encodeURIComponent(userId)}/`;
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
    if (url.pathname.startsWith(id)) {
      if (opts.silent?.includes(Number(url.port))) throw new Error("connect ETIMEDOUT");
      const lag = opts.lagging?.find((l) => String(l.port) === url.port);
      if (lag) {
        const byHash = new Map(lag.stale.map((j) => [jwsHash(j), j]));
        if (url.pathname.endsWith("/tips")) return json({ tips: [lag.stale.reduce((a, b) => (peekIdentityDoc(b).ver > peekIdentityDoc(a).ver ? b : a))] });
        const docs: string[] = [];
        for (let j = byHash.get(url.searchParams.get("to") ?? ""); j && docs.length < 64; j = byHash.get(String(peekIdentityDoc(j).prev))) docs.push(j);
        return json({ docs });
      }
    }
    return real(input, init);
  });
}

/**
 * A user listing RA and RB (and RC with `three`) whose device holds a stale head, with the newest version
 * stored as a pending head from `from` (or, with `split`, each listed relay's own pending head: the newest
 * from the first, the one before from the second).
 */
async function behind(name: string, from: string[], opts: { three?: boolean; split?: boolean } = {}) {
  const u = new User(name, { [RA]: `ws://127.0.0.1:${ra.port}/v3`, [RB]: `ws://127.0.0.1:${rb.port}/v3`, [RC]: `ws://127.0.0.1:${rc.port}/v3` });
  const userId = (await u.ok(["init", "--name", name, "--relay", RA, "--yes"])).userId as string;
  await u.ok(["relays", "add", RB]);
  if (opts.three) await u.ok(["relays", "add", RC]);
  const stale = await heldHead(u);
  let staleVersions: string[] = [];
  await storeOwn(u, userId, (cur) => {
    staleVersions = [...cur.versions];
    return cur;
  });
  // Another device of ours went on (here: this one, then forgotten), and RA holds it all.
  for (let i = 0; i < 4; i++) await u.ok(["profile", "set", "--bio", `edit ${i}`]);
  const before = await heldHead(u);
  await u.ok(["profile", "set", "--bio", "edit 4"]);
  const newest = await heldHead(u);
  // An earlier, incomplete refresh left the newest version as a pending head, sent by `from`.
  await storeOwn(u, userId, (cur) =>
    opts.split
      ? { ...cur, versions: staleVersions, pendingHeads: [newest.jws, before.jws], pendingHeadRelays: { [newest.hash]: [from[0]], [before.hash]: [from[1]] } }
      : { ...cur, versions: staleVersions, pendingHeads: [newest.jws], pendingHeadRelays: { [newest.hash]: from } },
  );
  expect((await heldHead(u)).hash).toBe(stale.hash);
  return { u, userId, stale, staleVersions, newest };
}

describe("#78: the owner's edit doesn't build on a lagging relay's stale head", () => {
  it("RA (current, its newer version pending here) times out, RB answers the stale head: refused, nothing published", async () => {
    const { u, userId, stale, staleVersions, newest } = await behind("ann", [RA]);
    network(userId, { silent: [ra.port], lagging: [{ port: rb.port, stale: staleVersions }] });
    const edit = await u.run(["profile", "set", "--bio", "on a stale head?"]);
    vi.restoreAllMocks();
    expect(edit.code, `${edit.out}\n${edit.err}`).not.toBe(0);
    expect(edit.json.error).toBe("refresh_failed");
    expect(edit.json.reason).toContain(RA);
    expect(edit.json.reason).toContain(`ver ${newest.ver}`);
    expect(edit.json.reason).toMatch(/try again/i);
    expect(edit.json.reason).toContain("p2p relays remove");
    // Nothing built on the stale head: no fork on either relay, and the held head didn't move.
    expect((await heldHead(u)).hash).toBe(stale.hash);
    for (const port of [ra.port, rb.port]) expect((await realTips(port, userId)).map((t) => t.hash)).toEqual([newest.hash]);

    // RA answers again: the edit goes ahead, on the newest version.
    expect((await u.ok(["profile", "set", "--bio", "on the newest"])).profile.bio).toBe("on the newest");
    const after = await heldHead(u);
    expect(after.ver).toBe(newest.ver + 1);
    expect(after.prev).toBe(newest.hash);
    expect((await realTips(ra.port, userId)).map((t) => t.hash)).toEqual([after.hash]);
  }, 180_000);
});

describe("#78 (T1): a relay can't hold the owner up for good with a pending head", () => {
  /** A version only the identity key signed (a thief's), far above the head, that connects to nothing. */
  function forged(u: User, userId: string) {
    const ik = identityKeyFromSeed(b64uDecode(keysOf(u).ik!, 32));
    const mallory = generateDeviceKeysV3(userId).did;
    return createIdentityDoc(ik, { ver: 9000, prev: "A".repeat(43), name: u.name, relays: [RA, RB], devices: [mallory], keyholders: [mallory], by: mallory, iat: nowSec() - 5 });
  }

  async function withForgedPending(name: string) {
    const u = new User(name, { [RA]: `ws://127.0.0.1:${ra.port}/v3`, [RB]: `ws://127.0.0.1:${rb.port}/v3` });
    const userId = (await u.ok(["init", "--name", name, "--relay", RA, "--yes"])).userId as string;
    await u.ok(["relays", "add", RB]);
    const f = forged(u, userId);
    await storeOwn(u, userId, (cur) => ({ ...cur, pendingHeads: [f], pendingHeadRelays: { [jwsHash(f)]: [RB] } }));
    return { u, userId };
  }

  it("while it stays silent the edit refuses naming it; removing it goes ahead; then edits work again", async () => {
    const { u, userId } = await withForgedPending("bea");
    const before = await heldHead(u);
    network(userId, { silent: [rb.port] });
    const edit = await u.run(["profile", "set", "--bio", "hello"]);
    expect(edit.code).not.toBe(0);
    expect(edit.json.error).toBe("refresh_failed");
    expect(edit.json.reason).toContain(RB);
    expect(edit.json.reason).not.toContain(RA);
    // `p2p relays remove` sets the relay it removes aside: it goes ahead, on the head RA confirms.
    const removed = await u.run(["relays", "remove", RB]);
    expect(removed.code, `${removed.out}\n${removed.err}`).toBe(0);
    expect(removed.json.relays).toEqual([RA]);
    const after = await heldHead(u);
    expect(after.ver).toBe(before.ver + 1);
    expect(after.prev).toBe(before.hash);
    // No longer listed: it holds nothing up any more.
    expect((await u.ok(["profile", "set", "--bio", "still mine"])).profile.bio).toBe("still mine");
  }, 180_000);

  it("once it answers (without the version), it holds nothing up", async () => {
    const { u } = await withForgedPending("cat");
    expect((await u.ok(["profile", "set", "--bio", "hello"])).profile.bio).toBe("hello");
  }, 180_000);

  it("a pending head stored without its senders (an older build), or past its exp, holds nothing up", async () => {
    const u = new User("dee", { [RA]: `ws://127.0.0.1:${ra.port}/v3`, [RB]: `ws://127.0.0.1:${rb.port}/v3` });
    const userId = (await u.ok(["init", "--name", "dee", "--relay", RA, "--yes"])).userId as string;
    await u.ok(["relays", "add", RB]);
    const f = forged(u, userId);
    await storeOwn(u, userId, (cur) => ({ ...cur, pendingHeads: [f] }));
    network(userId, { silent: [rb.port] });
    expect((await u.ok(["profile", "set", "--bio", "legacy"])).profile.bio).toBe("legacy");
    vi.restoreAllMocks();
    // Past its exp: never usable, whoever sent it.
    const ik = identityKeyFromSeed(b64uDecode(keysOf(u).ik!, 32));
    const mallory = generateDeviceKeysV3(userId).did;
    const lapsed = createIdentityDoc(ik, { ver: 9001, prev: "A".repeat(43), name: "dee", relays: [RA, RB], devices: [mallory], keyholders: [mallory], by: mallory, iat: nowSec() - 3 * 86_400, ttlSec: 86_400 });
    await storeOwn(u, userId, (cur) => ({ ...cur, pendingHeads: [lapsed], pendingHeadRelays: { [jwsHash(lapsed)]: [RB] } }));
    network(userId, { silent: [rb.port] });
    expect((await u.ok(["profile", "set", "--bio", "lapsed"])).profile.bio).toBe("lapsed");
  }, 180_000);
});

describe("#78 review: more than one relay, removal, renewal", () => {
  it("three relays: RA silent, RB and RC (a majority) answer the stale head: refused, and the pending head is kept", async () => {
    const { u, userId, stale, staleVersions, newest } = await behind("eli", [RA], { three: true });
    network(userId, { silent: [ra.port], lagging: [{ port: rb.port, stale: staleVersions }, { port: rc.port, stale: staleVersions }] });
    for (let i = 0; i < 2; i++) {
      // Again: the majority's complete refresh didn't clear it, so a retry can't fork either.
      const edit = await u.run(["profile", "set", "--bio", "on a stale head?"]);
      expect(edit.code, `${edit.out}\n${edit.err}`).not.toBe(0);
      expect(edit.json.error).toBe("refresh_failed");
      expect(edit.json.heldBy).toEqual([RA]);
    }
    vi.restoreAllMocks();
    const app = await u.app();
    await app.load();
    try {
      const st = (await app.store.getIdentity(userId))!;
      expect(st.pendingHeads).toEqual([newest.jws]);
      expect(st.pendingHeadRelays).toEqual({ [newest.hash]: [RA] });
    } finally {
      await app.close();
    }
    expect((await heldHead(u)).hash).toBe(stale.hash);
  }, 180_000);

  it("two silent relays that sent the same version: removing one is refused naming the other; both at once go ahead", async () => {
    const { u, userId, staleVersions } = await behind("fay", [RA, RB], { three: true });
    network(userId, { silent: [ra.port, rb.port], lagging: [{ port: rc.port, stale: staleVersions }] });
    const edit = await u.run(["profile", "set", "--bio", "x"]);
    expect(edit.code).not.toBe(0);
    expect(edit.json.heldBy).toEqual([RA, RB]);
    const one = await u.run(["relays", "remove", RA]);
    expect(one.code).not.toBe(0);
    expect(one.json.heldBy).toEqual([RB]);
    const removed = await u.run(["relays", "remove", RA, RB]);
    expect(removed.code, `${removed.out}\n${removed.err}`).toBe(0);
    expect(removed.json.relays).toEqual([RC]);
  }, 180_000);

  it("a relay that replayed the honest relay's version, then withholds it: removing it alone is refused while the honest one is silent", async () => {
    // RA (honest) and RB both sent the newest version; RA is silent now, RB answers the stale head.
    const { u, userId, stale, staleVersions, newest } = await behind("ivy", [RA, RB]);
    network(userId, { silent: [ra.port], lagging: [{ port: rb.port, stale: staleVersions }] });
    const r = await u.run(["relays", "remove", RB]);
    expect(r.code).not.toBe(0);
    expect(r.json.error).toBe("refresh_failed");
    expect(r.json.heldBy).toEqual([RA]);
    vi.restoreAllMocks();
    // Nothing published on the stale head (no fork against the newest).
    expect((await heldHead(u)).hash).toBe(stale.hash);
    for (const port of [ra.port, rb.port]) expect((await realTips(port, userId)).map((t) => t.hash)).toEqual([newest.hash]);
  }, 180_000);

  it("two silent relays that sent different versions: one alone is refused, both at once go ahead", async () => {
    const { u, userId, staleVersions } = await behind("gus", [RA, RB], { three: true, split: true });
    network(userId, { silent: [ra.port, rb.port], lagging: [{ port: rc.port, stale: staleVersions }] });
    const one = await u.run(["relays", "remove", RA]);
    expect(one.code).not.toBe(0);
    expect(one.json.heldBy).toEqual([RB]);
    const both = await u.run(["relays", "remove", RA, RB]);
    expect(both.code, `${both.out}\n${both.err}`).toBe(0);
    expect(both.json.relays).toEqual([RC]);
  }, 180_000);

  it("maintain() doesn't renew silently: a warning every run, and a status-line alert once renewal is due", async () => {
    const { u, userId, staleVersions } = await behind("hal", [RA]);
    network(userId, { silent: [ra.port], lagging: [{ port: rb.port, stale: staleVersions }] });
    const app = await u.app();
    await app.load();
    try {
      await maintain(app);
      expect(app.warnings.some((w) => w.includes("can't renew your identity document") && w.includes(RA) && w.includes("p2p relays remove"))).toBe(true);
      const alerts = async () => ((await app.state.get("events"))?.items ?? []).filter((e) => e.kind === "p2p.alert" && e.data.what === "renewal-held");
      // Not due yet (a fresh document): only the warning.
      expect(await alerts()).toEqual([]);
      // Days before it expires: due, and held up: the alert, with the day count.
      const real = Date.now();
      vi.spyOn(Date, "now").mockReturnValue(real + (IDENTITY_DOC_MAX_TTL_SEC - 3 * 86_400) * 1000);
      await maintain(app);
      const raised = await alerts();
      expect(raised).toHaveLength(1);
      expect(raised[0].data.heldBy).toEqual([RA]);
      expect(raised[0].data.daysLeft).toBeLessThanOrEqual(3);
      // Same day: not raised again.
      await maintain(app);
      expect(await alerts()).toHaveLength(1);
    } finally {
      await app.close();
    }
  }, 180_000);
});
