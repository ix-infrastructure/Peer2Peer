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
import { addIdentityVersion, b64uDecode, createIdentityDoc, generateDeviceKeysV3, IDENTITY_DOC_MAX_TTL_SEC, identityKeyFromSeed, jwsHash, nowSec, peekIdentityDoc } from "@peer2peer/core/v3";
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

describe("#79: a relay a refresh of our own identity was held back for doesn't block rotation", () => {
  it("unanchored own history; RB serves a key holder's newer, non-connecting head and times out on the walk: edits refuse naming it, rotation goes ahead", async () => {
    const u = new User("rex", { [RA]: `ws://127.0.0.1:${ra.port}/v3`, [RB]: `ws://127.0.0.1:${rb.port}/v3`, [RC]: `ws://127.0.0.1:${rc.port}/v3` });
    const userId = (await u.ok(["init", "--name", "rex", "--relay", RA, "--yes"])).userId as string;
    await u.ok(["relays", "add", RB]);
    for (let i = 0; i < 3; i++) await u.ok(["profile", "set", "--bio", `edit ${i}`]);
    const head = await heldHead(u);
    // This device holds only its head (unanchored own history, as after a restore from a later version).
    await storeOwn(u, userId, (cur) => ({ ...cur, versions: [head.jws] }));
    // Someone holding the identity key built a branch off the head's parent that adds a device of theirs.
    const ik = identityKeyFromSeed(b64uDecode(keysOf(u).ik!, 32));
    const mallory = generateDeviceKeysV3(userId).did;
    let prev = head.prev!;
    let top = "";
    for (let v = head.ver; v <= head.ver + 3; v++) {
      top = createIdentityDoc(ik, { ver: v, prev, name: head.name, relays: [...head.relays], devices: [...head.devices, mallory], keyholders: [...head.keyholders], by: head.keyholders[0], iat: nowSec() - 5 });
      prev = jwsHash(top);
    }
    // RB serves that branch's head as its tip, then times out on every chain request.
    const real = globalThis.fetch;
    const id = `/v3/identity/${encodeURIComponent(userId)}/`;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
      if (url.pathname.startsWith(id) && url.port === String(rb.port)) {
        if (url.pathname.endsWith("/tips")) return json({ tips: [top] });
        throw new Error("connect ETIMEDOUT");
      }
      return real(input, init);
    });
    // A plain edit refuses, naming RB (and saying someone else may hold the key).
    const edit = await u.run(["profile", "set", "--bio", "blocked?"]);
    expect(edit.code, `${edit.out}\n${edit.err}`).not.toBe(0);
    expect(edit.json.error).toBe("refresh_failed");
    expect(edit.json.reason).toContain(RB);
    expect(edit.json.reason).toMatch(/someone else holds your identity key/);
    // Rotation sets RB aside (it is the remedy), without removing it first.
    const rot = await u.run(["identity", "rotate", "--yes", "--wait", "1", "--backup-file"]);
    vi.restoreAllMocks();
    expect(rot.code, `${rot.out}\n${rot.err}`).toBe(0);
    expect(`${rot.out}\n${rot.err}`).toContain(RB);
    u.cleanup();
  }, 120_000);

  /**
   * #92 follow-up: as above (RB serves a key holder's newer head off the held head's parent and times out on the
   * walk), but the held head X was published by another device, which this device's publish log doesn't list:
   * `listed`, a version this device published (in its log) lists that device; otherwise no such version does.
   * `dropsMe`: the key holder's head leaves this device out (the #79 case); otherwise it still lists it.
   */
  async function otherDeviceHead(name: string, listed: boolean, dropsMe: boolean) {
    const u = new User(name, { [RA]: `ws://127.0.0.1:${ra.port}/v3`, [RB]: `ws://127.0.0.1:${rb.port}/v3`, [RC]: `ws://127.0.0.1:${rc.port}/v3` });
    const userId = (await u.ok(["init", "--name", name, "--relay", RA, "--yes"])).userId as string;
    await u.ok(["relays", "add", RB]);
    for (let i = 0; i < 2; i++) await u.ok(["profile", "set", "--bio", `edit ${i}`]);
    const ik = identityKeyFromSeed(b64uDecode(keysOf(u).ik!, 32));
    const other = generateDeviceKeysV3(userId).did;
    const app = await u.app();
    await app.load();
    let head = (await app.ownView()).head;
    const docs: string[] = [];
    const next = (by: string, devices: string[], keyholders: string[]) => {
      const jws = createIdentityDoc(ik, { ver: head.ver + 1, prev: head.hash, name: head.name, relays: [...head.relays], devices, keyholders, by, iat: nowSec() - 20 + docs.length });
      docs.push(jws);
      head = peekIdentityDoc(jws) as typeof head;
      return jws;
    };
    try {
      const me = keysOf(u).did;
      if (listed) {
        // This device added the other one (recorded in its publish log); the other then published X.
        const add = next(me, [...head.devices, other], [...head.keyholders, other]);
        await app.store.recordPublished({ hash: jwsHash(add), devices: [other] });
        next(other, [...head.devices], [...head.keyholders]);
      } else {
        // X adds the other device and is published by it: no version in this device's log lists it.
        next(other, [...head.devices, other], [...head.keyholders, other]);
      }
      for (const jws of docs) expect((await app.publishDoc(jws, [RA, RB])).ok.sort()).toEqual([RA, RB].sort());
      for (const jws of docs) await addIdentityVersion(app.store, jws);
    } finally {
      await app.close();
    }
    const x = await heldHead(u);
    expect(x.hash).toBe(head.hash);
    expect(x.by).toBe(other);
    await storeOwn(u, userId, (cur) => ({ ...cur, versions: [x.jws] }));
    const mallory = generateDeviceKeysV3(userId).did;
    let prev = x.prev!;
    let top = "";
    const me = keysOf(u).did;
    for (let v = x.ver; v <= x.ver + 3; v++) {
      top = dropsMe
        ? createIdentityDoc(ik, { ver: v, prev, name: x.name, relays: [...x.relays], devices: [...x.devices.filter((d) => d !== me), mallory], keyholders: [mallory], by: mallory, iat: nowSec() - 5 })
        : createIdentityDoc(ik, { ver: v, prev, name: x.name, relays: [...x.relays], devices: [...x.devices, mallory], keyholders: [...x.keyholders], by: me, iat: nowSec() - 5 });
      prev = jwsHash(top);
    }
    const real = globalThis.fetch;
    const id = `/v3/identity/${encodeURIComponent(userId)}/`;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
      if (url.pathname.startsWith(id) && url.port === String(rb.port)) {
        if (url.pathname.endsWith("/tips")) return json({ tips: [top] });
        throw new Error("connect ETIMEDOUT");
      }
      return real(input, init);
    });
    return { u, userId, x };
  }

  it("#92 follow-up: the left-out head was published by a device no version in this device's publish log lists: RB isn't set aside; rotation refuses; removing RB goes ahead", async () => {
    const { u, userId, x } = await otherDeviceHead("sal", false, false);
    // A plain edit refuses, naming RB as sending newer versions (not as a held-back relay to set aside).
    const edit = await u.run(["profile", "set", "--bio", "blocked?"]);
    expect(edit.code, `${edit.out}\n${edit.err}`).not.toBe(0);
    expect(edit.json.error).toBe("refresh_failed");
    expect(edit.json.reason).toContain(RB);
    expect(edit.json.reason).toContain("p2p relays remove");
    // Rotation doesn't set RB aside: refused, nothing published.
    const rot = await u.run(["identity", "rotate", "--yes", "--wait", "1", "--backup-file"]);
    expect(rot.code, `${rot.out}\n${rot.err}`).not.toBe(0);
    expect(rot.json.error).toBe("refresh_failed");
    expect(rot.json.reason).toContain(RB);
    expect((await realTips(ra.port, userId)).map((t) => t.hash)).toEqual([x.hash]);
    // The user removes RB: that goes ahead on the head RA confirms.
    const removed = await u.run(["relays", "remove", RB]);
    vi.restoreAllMocks();
    expect(removed.code, `${removed.out}\n${removed.err}`).toBe(0);
    expect(removed.json.relays).toEqual([RA]);
    u.cleanup();
  }, 120_000);

  it("#92 follow-up: the left-out head was published by another owner device a version in the publish log lists (not yet in this device's log), and the key holder's head leaves this device out: RB is set aside, rotation goes ahead", async () => {
    const { u } = await otherDeviceHead("tam", true, true);
    const rot = await u.run(["identity", "rotate", "--yes", "--wait", "1", "--backup-file"]);
    vi.restoreAllMocks();
    expect(rot.code, `${rot.out}\n${rot.err}`).toBe(0);
    expect(`${rot.out}\n${rot.err}`).toContain(RB);
    u.cleanup();
  }, 120_000);

  it("#92 follow-up: only our own CURRENT tip counts: an old own version (as a relay could replay) or one not held never does", async () => {
    const u = new User("uma", { [RA]: `ws://127.0.0.1:${ra.port}/v3`, [RB]: `ws://127.0.0.1:${rb.port}/v3` });
    await u.ok(["init", "--name", "uma", "--relay", RA, "--yes"]);
    for (let i = 0; i < 3; i++) await u.ok(["profile", "set", "--bio", `edit ${i}`]);
    const app = await u.app();
    await app.load();
    try {
      const chain = (await app.ownView()).head;
      const log = (await app.store.getPublishLog()).published;
      const old = log.find((h) => h !== chain.hash)!;
      expect(old).toBeDefined();
      type Head = { hash: string; keyholders: string[]; devices?: string[] };
      const heldBack = (by: string[], left: string[], head?: Head) =>
        (app as unknown as { ownHeldBack(by: string[], left: string[], head?: Head): Promise<string[]> }).ownHeldBack(by, left, head);
      // #99: a head that keeps every device our tip lists (a thief's, adding one of its own).
      const thief: Head = { hash: "T".repeat(43), keyholders: [...chain.keyholders], devices: [...chain.devices, generateDeviceKeysV3(chain.iss).did] };
      expect(await heldBack([RB], [chain.hash], thief)).toEqual([RB]);
      expect(await heldBack([RB], [old], thief)).toEqual([]);
      expect(await heldBack([RB], ["A".repeat(43)], thief)).toEqual([]);
      expect(await heldBack([], [chain.hash], thief)).toEqual([]);
      // #99: no head (an older core) or one that didn't say which devices it lists: as if it revoked one.
      expect(await heldBack([RB], [chain.hash])).toEqual([]);
      expect(await heldBack([RB], [chain.hash], { hash: thief.hash, keyholders: thief.keyholders })).toEqual([]);
    } finally {
      await app.close();
    }
    u.cleanup();
  }, 60_000);

  it("#99: our own published tip V never gets the relays serving a head that revoked a device V lists set aside (a long-offline device)", async () => {
    // This device published V listing itself and D. The owner since moved on from another device and revoked D; the
    // history between them is past what the relays keep, so nothing connects V to that head, and a relay replays V.
    const u = new User("wes", { [RA]: `ws://127.0.0.1:${ra.port}/v3`, [RB]: `ws://127.0.0.1:${rb.port}/v3` });
    const userId = (await u.ok(["init", "--name", "wes", "--relay", RA, "--yes"])).userId as string;
    const ik = identityKeyFromSeed(b64uDecode(keysOf(u).ik!, 32));
    const me = keysOf(u).did;
    const d = generateDeviceKeysV3(userId).did;
    const base = await heldHead(u);
    const v = createIdentityDoc(ik, { ver: base.ver + 1, prev: base.hash, name: base.name, relays: [...base.relays], devices: [me, d], keyholders: [me, d], by: me, iat: nowSec() - 30 });
    const app = await u.app();
    await app.load();
    try {
      await addIdentityVersion(app.store, v);
      await app.store.recordPublished({ hash: jwsHash(v), devices: [d] });
      type Head = { hash: string; keyholders: string[]; devices?: string[] };
      const heldBack = (head: Head) =>
        (app as unknown as { ownHeldBack(by: string[], left: string[], head?: Head): Promise<string[]> }).ownHeldBack([RA], [jwsHash(v)], head);
      const x = generateDeviceKeysV3(userId).did;
      const hash = "H".repeat(43);
      // The owner's head: revoked D, still lists this device (and a new one). RA isn't set aside.
      expect(await heldBack({ hash, keyholders: [me, x], devices: [me, x] })).toEqual([]);
      // A head that revoked nothing V lists (a thief adding a device): as before (#79), RA is set aside.
      expect(await heldBack({ hash, keyholders: [me, d], devices: [me, d, x] })).toEqual([RA]);
      // A head that leaves this device out as a key holder (the #79 thief against the owner's devices): unchanged.
      expect(await heldBack({ hash, keyholders: [x], devices: [x] })).toEqual([RA]);
    } finally {
      await app.close();
    }
    u.cleanup();
  }, 60_000);

  it("#99 review: a key holder's head that keeps this device and drops another device our tip lists: RB isn't set aside, and the error names it with what to do", async () => {
    const u = new User("yan", { [RA]: `ws://127.0.0.1:${ra.port}/v3`, [RB]: `ws://127.0.0.1:${rb.port}/v3` });
    const userId = (await u.ok(["init", "--name", "yan", "--relay", RA, "--yes"])).userId as string;
    await u.ok(["relays", "add", RB]);
    await u.ok(["profile", "set", "--bio", "hello"]);
    const ik = identityKeyFromSeed(b64uDecode(keysOf(u).ik!, 32));
    const d = generateDeviceKeysV3(userId).did;
    const base = await heldHead(u);
    // This device published V, adding D (in its publish log).
    const v = createIdentityDoc(ik, { ver: base.ver + 1, prev: base.hash, name: base.name, relays: [...base.relays], devices: [...base.devices, d], keyholders: [...base.keyholders], by: keysOf(u).did, iat: nowSec() - 30 });
    {
      const app = await u.app();
      await app.load();
      try {
        expect((await app.publishDoc(v, [RA, RB])).ok.sort()).toEqual([RA, RB].sort());
        await addIdentityVersion(app.store, v);
        await app.store.recordPublished({ hash: jwsHash(v), devices: [d] });
      } finally {
        await app.close();
      }
    }
    await storeOwn(u, userId, (cur) => ({ ...cur, versions: [v] }));
    // Someone holding the key builds off V's parent: keeps this device (as a key holder too), adds theirs, drops D.
    const mallory = generateDeviceKeysV3(userId).did;
    let prev = base.hash;
    let top = "";
    for (let ver = base.ver + 1; ver <= base.ver + 4; ver++) {
      top = createIdentityDoc(ik, { ver, prev, name: base.name, relays: [...base.relays], devices: [...base.devices, mallory], keyholders: [...base.keyholders], by: base.keyholders[0], iat: nowSec() - 5 });
      prev = jwsHash(top);
    }
    const real = globalThis.fetch;
    const id = `/v3/identity/${encodeURIComponent(userId)}/`;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
      if (url.pathname.startsWith(id) && url.port === String(rb.port)) {
        if (url.pathname.endsWith("/tips")) return json({ tips: [top] });
        throw new Error("connect ETIMEDOUT");
      }
      return real(input, init);
    });
    // Fail closed: RB isn't set aside (that head is indistinguishable from an owner's revocation of D), nothing is
    // published, and the error names RB and says how to remove it.
    const rot = await u.run(["identity", "rotate", "--yes", "--wait", "1", "--backup-file"]);
    expect(rot.code, `${rot.out}\n${rot.err}`).not.toBe(0);
    expect(rot.json.error).toBe("refresh_failed");
    expect(rot.json.reason).toContain(`${RB} serves a newer version of your identity`);
    expect(rot.json.reason).toMatch(/can't tell whether that is a change you made on another device/);
    expect(rot.json.reason).toContain("p2p relays remove <url>");
    expect(rot.err).not.toContain("left out of this check");
    expect((await realTips(ra.port, userId)).map((t) => t.hash)).toEqual([jwsHash(v)]);
    // Following the hint: removing RB goes ahead on what RA confirms.
    const removed = await u.run(["relays", "remove", RB]);
    vi.restoreAllMocks();
    expect(removed.code, `${removed.out}\n${removed.err}`).toBe(0);
    expect(removed.json.relays).toEqual([RA]);
    u.cleanup();
  }, 120_000);

  it("#91 review: a version a revoked device signed, held here, never gets the relay serving the owner's revocation set aside", async () => {
    // A version this device published listed D (later stolen) and B. B revoked D (H, then H2); before that, someone
    // holding the key published T `by` D, listing D and this device but not B, to another relay. This device holds T.
    const u = new User("vic", { [RA]: `ws://127.0.0.1:${ra.port}/v3`, [RB]: `ws://127.0.0.1:${rb.port}/v3` });
    const userId = (await u.ok(["init", "--name", "vic", "--relay", RA, "--yes"])).userId as string;
    await u.ok(["relays", "add", RB]);
    await u.ok(["profile", "set", "--bio", "hello"]);
    const ik = identityKeyFromSeed(b64uDecode(keysOf(u).ik!, 32));
    const me = keysOf(u).did;
    const d = generateDeviceKeysV3(userId).did;
    const b = generateDeviceKeysV3(userId).did;
    const base = await heldHead(u);
    const doc = (ver: number, prev: string, by: string, devices: string[], iat: number) => createIdentityDoc(ik, { ver, prev, name: base.name, relays: [...base.relays], devices, keyholders: devices, by, iat });
    const vA = doc(base.ver + 1, base.hash, me, [me, d, b], nowSec() - 30);
    {
      const app = await u.app();
      await app.load();
      try {
        expect((await app.publishDoc(vA, [RA, RB])).ok.sort()).toEqual([RA, RB].sort());
        await addIdentityVersion(app.store, vA);
        await app.store.recordPublished({ hash: jwsHash(vA), devices: [d, b] });
      } finally {
        await app.close();
      }
    }
    const t = doc(base.ver + 2, jwsHash(vA), d, [me, d], nowSec() - 20);
    const h = doc(base.ver + 2, jwsHash(vA), b, [me, b], nowSec() - 15);
    const h2 = doc(base.ver + 3, jwsHash(h), b, [me, b], nowSec() - 10);
    await storeOwn(u, userId, (cur) => ({ ...cur, versions: [t] }));
    // RA serves the owner's H2 and times out on the walk; RB serves T as its tip (and the history below it).
    const real = globalThis.fetch;
    const id = `/v3/identity/${encodeURIComponent(userId)}/`;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
      if (url.pathname.startsWith(id) && url.port === String(ra.port)) {
        if (url.pathname.endsWith("/tips")) return json({ tips: [h2] });
        throw new Error("connect ETIMEDOUT");
      }
      if (url.pathname.startsWith(id) && url.port === String(rb.port) && url.pathname.endsWith("/tips")) return json({ tips: [t] });
      return real(input, init);
    });
    const rot = await u.run(["identity", "rotate", "--yes", "--wait", "1", "--backup-file"]);
    vi.restoreAllMocks();
    // RA isn't set aside (H2 still lists this device as a key holder, and T isn't in the publish log): refused.
    expect(rot.code, `${rot.out}\n${rot.err}`).not.toBe(0);
    expect(rot.json.error).toBe("refresh_failed");
    expect(rot.err).not.toContain("left out of this check");
    u.cleanup();
  }, 120_000);
});

