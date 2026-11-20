// Copyright 2026 Ix Infrastructure Inc.
//
// #75: someone holding the identity key publishes a version that connects to the owner's history (a
// sibling of the owner's head) and lists none of the owner's devices. The owner's view is then forked, the
// owner's devices fall out of the intersection, and the relays refuse them. Rotation (§2.8) must still
// work from the owner's own branch, and friends follow it:
//  - two relays, two key holders; a failed edit (and the stale merge a 0.1.2 client kept) hides nothing;
//  - a device no branch lists (one the owner revoked) can't take that path;
//  - the own branch is chosen by provenance, never by `ver` or hash: a branch whose newer versions come
//    from a device this one never listed loses; when that can't tell, the user chooses, and the final
//    version never takes the chosen tip's relays beyond the owner's own;
//  - a thief's device on its own branch rotates the same way, and the owner's contest makes it a conflict;
//  - a resume after the merge landed but the final version didn't, with a pinned final version the relays
//    never take, finishes.
// #91 (low follow-ups from #89's review): a branch picked by provenance among others is shown, never silent; a
// re-plan doesn't ignore a new --branch; a thief's rotation out meanwhile points a resume to the contest; what the
// branch summaries print is checked again (relay URLs and device ids only).

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { addIdentityVersion, b64uDecode, createDeviceCert, createIdentityDoc, generateDeviceKeysV3, identityKeyFromSeed, jwsHash, mergePrevTip, nowSec, peekIdentityDoc } from "@peer2peer/core/v3";
import { formatRotationPlan } from "../format.js";
import { linkJoin, linkStart } from "../identity.js";
import { receiving } from "../inbound.js";
import { publishOver, RelayConnection } from "../relay-client.js";
import { branchSummary, readRotationState, rotate } from "../rotation.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R1 = "wss://relay-fork-one.test/v3";
const R2 = "wss://relay-fork-two.test/v3";
/** A relay only versions signed by someone else holding the identity key name. */
const RX = "wss://relay-fork-other.test/v3";
const LIMITS = { identityPublishPerIpPerHour: 100_000, identityPublishPerIssPerHour: 1000, contactPerIpPerHour: 100_000, contactPerSenderPerHour: 1000, linkOpsPerIpPerMinute: 100_000, linkOpenPerIp: 1000, linkOpenPerIpPerHour: 1000, linkOpenPerIssPerHour: 1000, connectsPerIpPerMinute: 100_000, authsPerIpPerMinute: 100_000, authsPerIpv4PerMinute: 100_000, httpPerIpPerMinute: 100_000 };
let r1: TestRelay;
let r2: TestRelay;
let rx: TestRelay;
const users: User[] = [];
const ids: Record<string, string> = {};

const keysOf = (u: User) => JSON.parse(readFileSync(join(u.home, "cli", "keys.json"), "utf8")) as { userId: string; did: string; ik?: string };
const ikOf = (u: User) => identityKeyFromSeed(b64uDecode(keysOf(u).ik!, 32));

function user(name: string): User {
  const u = new User(name, { [R1]: `ws://127.0.0.1:${r1.port}/v3`, [R2]: `ws://127.0.0.1:${r2.port}/v3`, [RX]: `ws://127.0.0.1:${rx.port}/v3` });
  users.push(u);
  return u;
}

async function init(u: User, relays: string[] = [R1]): Promise<void> {
  ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", relays[0], "--yes"])).userId;
  for (const r of relays.slice(1)) await u.ok(["relays", "add", r]);
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

const portOf = (r: string) => (r === R1 ? r1 : r === R2 ? r2 : rx).port;

async function relayTips(userId: string, r = R1) {
  const res = (await (await fetch(`http://127.0.0.1:${portOf(r)}/v3/identity/${encodeURIComponent(userId)}/tips`)).json()) as { tips: string[] };
  return res.tips.map((t) => peekIdentityDoc(t));
}

async function relayDoc(userId: string, hash: string, r = R1) {
  const res = (await (await fetch(`http://127.0.0.1:${portOf(r)}/v3/identity/${encodeURIComponent(userId)}/chain?to=${hash}&n=1`)).json()) as { docs: string[] };
  return peekIdentityDoc(res.docs[0]);
}

/** Publishes versions signed with `owner`'s identity key through `owner`'s connection, as a key holder could. */
async function publishAs(owner: User, docs: string[], relays: string[] = [R1]): Promise<void> {
  const app = await owner.app();
  await app.load();
  try {
    for (const jws of docs) expect((await app.publishDoc(jws, relays)).ok.sort()).toEqual([...relays].sort());
  } finally {
    await app.close();
  }
}

/**
 * Someone holding `owner`'s identity key publishes a sibling of the owner's head (same ver, same prev) that
 * lists only `devices` (a device of theirs by default). It connects to the owner's history.
 */
async function connectingFork(owner: User, opts: { devices?: string[]; relays?: string[] } = {}): Promise<{ hash: string; mallory: string }> {
  const userId = keysOf(owner).userId;
  const relays = opts.relays ?? [R1];
  const [head] = await relayTips(userId, relays[0]);
  expect(head.prev).toBeTruthy();
  const mallory = generateDeviceKeysV3(userId).did;
  const devices = opts.devices ?? [mallory];
  const jws = createIdentityDoc(ikOf(owner), { ver: head.ver, prev: head.prev!, name: head.name, relays: [...head.relays], devices, keyholders: devices, by: devices[0], iat: nowSec() - 5 });
  await publishAs(owner, [jws], relays);
  for (const r of relays) expect((await relayTips(userId, r)).map((t) => t.hash)).toContain(jwsHash(jws));
  return { hash: jwsHash(jws), mallory };
}

beforeAll(async () => {
  r1 = await startRelay(R1, { limits: LIMITS });
  r2 = await startRelay(R2, { limits: LIMITS });
  rx = await startRelay(RX, { limits: LIMITS });
}, 60_000);

afterAll(async () => {
  await r1?.close();
  await r2?.close();
  await rx?.close();
  for (const u of users) u.cleanup();
});

describe("#75: a key holder's connecting fork that drops the owner's devices", () => {
  it("the owner still rotates from its own branch (two relays, two key holders), and a friend follows", async () => {
    const ann = user("ann");
    const ann2 = user("ann2");
    const bob = user("bob");
    await init(ann, [R1, R2]);
    await init(bob);
    await link(ann, ann2, "laptop", true);
    await befriend(ann, bob);
    const own = (await relayTips(ids.ann))[0];
    expect(own.keyholders).toHaveLength(2);
    const fork = await connectingFork(ann, { relays: [R1, R2] });
    // An ordinary edit can't go ahead (a merge would leave this device unlisted), and leaves nothing behind.
    const edit = await ann.run(["profile", "set", "--bio", "still mine"]);
    expect(edit.json.error).toBe("device_revoked");
    {
      // A 0.1.2 client kept that merge (listing nobody of ours): rotation drops it, as no relay serves it.
      const app = await ann.app();
      await app.load();
      const [a, b] = (await app.ownView()).tips;
      const { prev, other } = mergePrevTip(a, b);
      const stale = createIdentityDoc(ikOf(ann), { ver: Math.max(a.ver, b.ver) + 1, prev: prev.hash, merge: other.hash, name: prev.name, relays: [...prev.relays], devices: [], keyholders: [], by: keysOf(ann).did });
      await addIdentityVersion(app.store, stale);
      await app.store.recordPublished({ hash: jwsHash(stale) });
      expect((await app.ownView()).tips.map((t) => t.hash)).toEqual([jwsHash(stale)]);
      await app.close();
    }
    // The plan lists the owner's own devices, never the other branch's, and invites bob: the friendship this
    // device made counts, though the forked view can't verify it now.
    const plan = await ann.ok(["identity", "rotate", "--plan"]);
    expect(plan.follow.map((d: any) => d.did)).toEqual([keysOf(ann2).did]);
    expect(JSON.stringify(plan)).not.toContain(fork.mallory);
    expect(plan.friends).toBe(1);
    const res = await ann.run(["identity", "rotate", "--resume", "--yes", "--wait", "1", "--backup-file"]);
    expect(res.code, `${res.out}\n${res.err}`).toBe(0);
    expect(res.json).toMatchObject({ step: "done" });
    // The relays refuse ann's devices, so her laptop re-links by hand.
    expect(res.json.devices.followed).toEqual([]);
    // On both relays: the final version lists nobody and carries the statement. It follows a merge of the two
    // branches that also lists nobody, with the owner's name and relays.
    for (const r of [R1, R2]) {
      const tips = await relayTips(ids.ann, r);
      expect(tips).toHaveLength(1);
      const [final] = tips;
      expect(final.rotation).toBeDefined();
      expect(final).toMatchObject({ devices: [], keyholders: [], name: own.name });
      expect([...final.relays].sort()).toEqual([R1, R2].sort());
      const merge = await relayDoc(ids.ann, final.prev!, r);
      expect([merge.prev, merge.merge].sort()).toEqual([own.hash, fork.hash].sort());
      expect(merge).toMatchObject({ devices: [], keyholders: [] });
    }
    // bob follows: one rotation, carried by ann's own document.
    const items = (await bob.ok(["held"])).held.filter((h: any) => h.type === "rotation");
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({ from: res.json.to, old: ids.ann });
    await bob.ok(["held", "approve", items[0].id]);
    const bf = (await bob.ok(["friends"])).friends.map((f: any) => f.userId);
    expect(bf).toContain(res.json.to);
    expect(bf).not.toContain(ids.ann);
  }, 240_000);

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
    // The fork gate refused it (no branch lists it), not a later step.
    expect(r.json.error).toBe("device_revoked");
    expect(r.json.reason).toMatch(/no branch of your identity .* lists it as a key holder/);
    expect(await readRotationState(cy2.home)).toBeUndefined();
    const after = await relayTips(ids.cy);
    expect(after.filter((t) => t.rotation !== undefined)).toEqual([]);
    expect(after.map((t) => t.hash).sort()).toEqual([...before.map((t) => t.hash), fork.hash].sort());
  }, 180_000);
});

describe("#75 review: which branch is the owner's", () => {
  /**
   * `u` (A) with key holders B (`u2`) and C (`u3`). B publishes the owner's newest version O, which isn't in
   * A's publish log. Then someone holding the key forks from O's parent: T1 (two versions, the newer at a
   * higher ver than O, still listing A as a key holder, naming RX) `by` `thiefBy`, and T2, which leaves A out.
   */
  async function setup(name: string, thiefBy: (u3: User) => string) {
    const u = user(name);
    const u2 = user(`${name}2`);
    const u3 = user(`${name}3`);
    await init(u);
    await link(u, u2, "laptop", true);
    await link(u, u3, "phone", true);
    await u2.ok(["profile", "set", "--bio", "from the laptop"]);
    const [o] = await relayTips(ids[name]);
    expect(o.by).toBe(keysOf(u2).did);
    const ik = ikOf(u);
    const m = generateDeviceKeysV3(ids[name]).did;
    const by = thiefBy(u3) || m;
    const a = keysOf(u).did;
    const listed = [a, keysOf(u2).did, keysOf(u3).did, ...(by === m ? [m] : [])];
    const t1a = createIdentityDoc(ik, { ver: o.ver, prev: o.prev!, name, relays: [R1, RX], devices: listed, keyholders: [a, by], by, iat: nowSec() - 5 });
    const t1b = createIdentityDoc(ik, { ver: o.ver + 1, prev: jwsHash(t1a), name, relays: [R1, RX], devices: listed, keyholders: [a, by], by, iat: nowSec() - 4 });
    const t2 = createIdentityDoc(ik, { ver: o.ver, prev: o.prev!, name, relays: [R1], devices: [m], keyholders: [m], by: m, iat: nowSec() - 3 });
    // (T2 last: once it is out, the relays refuse A.)
    await publishAs(u, [t1a, t1b, t2]);
    expect((await relayTips(ids[name])).map((t) => t.hash).sort()).toEqual([o.hash, jwsHash(t1b), jwsHash(t2)].sort());
    return { u, o, t1: jwsHash(t1b), m };
  }

  it("a branch whose versions come from a device this one never listed loses, at any ver; the final takes the owner's relays", async () => {
    const { u, o, t1, m } = await setup("gus", () => "");
    const run = await u.run(["identity", "rotate", "--plan"]);
    expect(run.code, run.err).toBe(0);
    const plan = run.json;
    // The plan lists O's devices (B and C), from the branch whose versions came from a listed device: T1,
    // at the higher ver, would have listed the other device too (and named RX).
    expect(plan.follow.map((d: any) => d.label).sort()).toEqual(["laptop", "phone"]);
    expect(JSON.stringify([plan.follow, plan.excluded])).not.toContain(m);
    // #91: never silently: the other branch that still lists this device is warned about and shown in the plan.
    expect(plan.branch).toBe(o.hash);
    expect(plan.otherBranches).toEqual([{ hash: t1, ver: o.ver + 1, by: [m], relays: [R1, RX] }]);
    expect(run.err).toContain(t1);
    expect(run.err).toContain("--plan --branch <hash>");
    const text = formatRotationPlan(plan);
    expect(text).toContain(`builds on the branch ${o.hash}`);
    expect(text).toContain(`${t1} (ver ${o.ver + 1}, published by ${m}; relays ${R1}, ${RX})`);
    const res = await u.run(["identity", "rotate", "--resume", "--yes", "--wait", "1", "--backup-file"]);
    expect(res.code, `${res.out}\n${res.err}`).toBe(0);
    const [final] = await relayTips(ids.gus);
    expect(final.rotation).toBeDefined();
    expect(final.relays).toEqual([R1]);
    expect((await relayDoc(ids.gus, final.prev!)).relays).toEqual([R1]);
  }, 240_000);

  it("when provenance can't tell (a stolen key holder's branch), the user chooses; the chosen tip's other relays are left out", async () => {
    const { u, o, t1 } = await setup("hal", (u3) => keysOf(u3).did);
    const amb = await u.run(["identity", "rotate", "--plan"]);
    expect(amb.json.error).toBe("branch_ambiguous");
    expect(amb.json.branches.map((b: any) => b.hash).sort()).toEqual([o.hash, t1].sort());
    expect(amb.json.branches.find((b: any) => b.hash === t1).relays).toEqual([R1, RX]);
    // #91: what the error echoes from the other branch is relay URLs and device ids only.
    for (const b of amb.json.branches) {
      for (const r of b.relays) expect(r).toMatch(/^wss:\/\/[\x21-\x7e]+$/);
      for (const d of b.by) expect(d).toMatch(/^d_[a-z2-7]{26}$/);
    }
    expect((await u.run(["identity", "rotate", "--plan", "--branch", "nope"])).json.error).toBe("usage");
    // The user picks the thief's branch by mistake: the final version still names only the owner's relays.
    const plan = await u.run(["identity", "rotate", "--plan", "--branch", t1]);
    expect(plan.code, plan.err).toBe(0);
    expect(plan.err).toContain(RX);
    expect(plan.json.branch).toBe(t1);
    // #91: the plan made is reused, so another --branch is refused (drop the plan first), on --plan and --resume.
    for (const args of [
      ["--plan", "--branch", o.hash],
      ["--resume", "--yes", "--branch", o.hash, "--wait", "1"],
    ]) {
      const again = await u.run(["identity", "rotate", ...args]);
      expect(again.json.error, again.err).toBe("usage");
      expect(again.json.reason).toContain(`builds on the branch ${t1}`);
      expect(again.json.reason).toContain("p2p identity rotate --cancel");
    }
    // The same branch again is fine.
    expect((await u.run(["identity", "rotate", "--plan", "--branch", t1])).code).toBe(0);
    const res = await u.run(["identity", "rotate", "--resume", "--yes", "--wait", "1", "--backup-file"]);
    expect(res.code, `${res.out}\n${res.err}`).toBe(0);
    const [final] = await relayTips(ids.hal);
    expect(final.rotation).toBeDefined();
    expect(final.relays).toEqual([R1]);
  }, 240_000);
});

describe("#75 review: the thief's side, and a resume", () => {
  it("a thief's device on its own branch rotates; the owner contests it; a friend applies neither", async () => {
    const eve = user("eve");
    const eve2 = user("eve2");
    const fay = user("fay");
    await init(eve);
    await init(fay);
    await link(eve, eve2, "stolen", true);
    await befriend(eve, fay);
    await eve2.ok(["friends"]);
    const eve2Did = keysOf(eve2).did;
    // eve revokes the stolen key holder; its thief had published a sibling of that revocation that lists it.
    await eve.ok(["devices", "revoke", eve2Did]);
    await connectingFork(eve, { devices: [eve2Did] });
    const thief = await eve2.run(["identity", "rotate", "--yes", "--wait", "1", "--backup-file", "--invite", ids.fay]);
    expect(thief.code, `${thief.out}\n${thief.err}`).toBe(0);
    const [tFinal] = await relayTips(ids.eve);
    expect(tFinal.rotation).toBeDefined();
    // eve answers it from the merge the thief's final version follows.
    const contest = await eve.run(["identity", "rotate", "--contest", "--yes", "--wait", "1", "--backup-file"]);
    expect(contest.code, `${contest.out}\n${contest.err}`).toBe(0);
    expect(contest.json).toMatchObject({ contest: true, step: "done" });
    const items = (await fay.ok(["held"])).held.filter((h: any) => h.type === "rotation");
    expect(items.map((h: any) => h.from).sort()).toEqual([thief.json.to, contest.json.to].sort());
    for (const h of items) expect((await fay.run(["held", "approve", h.id])).json.error).toBe("rotation_conflict");
    const ff = (await fay.ok(["friends"])).friends.map((f: any) => f.userId);
    expect(ff).not.toContain(thief.json.to);
    expect(ff).not.toContain(contest.json.to);
  }, 240_000);

  it("resumes after the merge landed but the final version didn't, past a pinned final version the relays never take", async () => {
    const ida = user("ida");
    const jo = user("jo");
    await init(ida);
    await init(jo);
    await befriend(ida, jo);
    await ida.ok(["profile", "set", "--bio", "before"]);
    const own = (await relayTips(ids.ida))[0];
    const fork = await connectingFork(ida);
    {
      const app = await ida.app();
      await app.load();
      receiving(app);
      await expect(rotate(app, { yes: true, backupFileDefault: true, waitSec: 1, stopAfter: "social" })).rejects.toThrow(/stopped after social/);
      await app.close();
    }
    const st = (await readRotationState(ida.home))!;
    expect(st.ownBranch).toMatchObject({ tip: own.hash, relays: [R1] });
    const ik = ikOf(ida);
    const did = keysOf(ida).did;
    const forkDoc = (await relayTips(ids.ida)).find((t) => t.hash === fork.hash)!;
    const { prev, other } = mergePrevTip(own, forkDoc);
    const merge = createIdentityDoc(ik, { ver: Math.max(own.ver, forkDoc.ver) + 1, prev: prev.hash, merge: other.hash, name: "ida", relays: [R1], devices: [], keyholders: [], by: did });
    // An earlier build's final version on ida's own tip, which no relay takes once the merge is out.
    const pinned = createIdentityDoc(ik, { ver: own.ver + 1, prev: own.hash, name: "ida", relays: [R1], devices: [], keyholders: [], by: did, rotation: st.statement });
    const app = await ida.app();
    await app.load();
    for (const d of [merge, pinned]) {
      await addIdentityVersion(app.store, d);
      await app.store.recordPublished({ hash: jwsHash(d) });
    }
    // The merge landed (over a restricted connection, as rotation sends it); the final version didn't.
    const keys = generateDeviceKeysV3(ik.userId);
    const cert = createDeviceCert(ik, { signingPublicKey: keys.signingPublicKey, agreementPublicKey: keys.agreementPublicKey }, { ttlSec: 600 });
    const conn = new RelayConnection(R1, app.transport(R1), { auth: { cert, signingSecretKey: keys.signingSecretKey }, allowRestricted: true, timeoutMs: 5000 });
    await conn.open();
    expect(await publishOver(conn, merge)).toBe("ok");
    conn.close();
    await app.close();
    expect((await relayTips(ids.ida)).map((t) => t.hash)).toEqual([jwsHash(merge)]);
    const res = await ida.run(["identity", "rotate", "--resume", "--yes", "--wait", "1"]);
    expect(res.code, `${res.out}\n${res.err}`).toBe(0);
    const [final] = await relayTips(ids.ida);
    expect(final.rotation).toBeDefined();
    expect(final.prev).toBe(jwsHash(merge));
    expect(final.hash).not.toBe(jwsHash(pinned));
    const items = (await jo.ok(["held"])).held.filter((h: any) => h.type === "rotation");
    expect(items).toHaveLength(1);
    await jo.ok(["held", "approve", items[0].id]);
    expect((await jo.ok(["friends"])).friends.map((f: any) => f.userId)).toContain(res.json.to);
  }, 240_000);
});

describe("#91: a thief's rotation while the owner's is under way", () => {
  it("--resume points to the contest (not to another --resume); --resume --contest finishes it as a competing one", async () => {
    const kim = user("kim");
    const kim2 = user("kim2");
    const kim3 = user("kim3");
    const lee = user("lee");
    await init(kim);
    await init(lee);
    await link(kim, kim2, "stolen", true);
    // Another key holder of kim's, on her own branch: it gets the rotation to follow.
    await link(kim, kim3, "tablet", true);
    await befriend(kim, lee);
    await kim2.ok(["friends"]);
    const kim2Did = keysOf(kim2).did;
    // kim revokes the stolen key holder; its thief had published a sibling of that revocation that lists it.
    await kim.ok(["devices", "revoke", kim2Did]);
    await connectingFork(kim, { devices: [kim2Did] });
    // kim's rotation from her own branch, interrupted before its final version.
    {
      const app = await kim.app();
      await app.load();
      receiving(app);
      await expect(rotate(app, { yes: true, backupFileDefault: true, waitSec: 1, stopAfter: "social" })).rejects.toThrow(/stopped after social/);
      await app.close();
    }
    const st = (await readRotationState(kim.home))!;
    expect(st.ownBranch).toBeDefined();
    expect(st.devices[keysOf(kim3).did]?.status).not.toBe("excluded");
    // No rotation of kim's to contest yet: --resume --contest is refused.
    const early = await kim.run(["identity", "rotate", "--resume", "--contest", "--yes", "--wait", "1"]);
    expect(early.json.error, early.err).toBe("usage");
    expect(early.json.reason).toMatch(/no rotation of your identity to contest/);
    // The thief's rotation goes out meanwhile.
    const thief = await kim2.run(["identity", "rotate", "--yes", "--wait", "1", "--backup-file"]);
    expect(thief.code, `${thief.out}\n${thief.err}`).toBe(0);
    const res = await kim.run(["identity", "rotate", "--resume", "--yes", "--wait", "1"]);
    expect(res.code).not.toBe(0);
    expect(res.json.error, res.err).toBe("identity_rotated");
    expect(res.json.to).toEqual([thief.json.to]);
    // Named by the device that signed it, so kim can tell it isn't one of hers she still has.
    expect(res.json.by).toEqual([kim2Did]);
    expect(res.json.reason).toContain(kim2Did);
    expect(res.json.reason).toContain("p2p identity rotate --resume --contest");
    expect(res.json.reason).not.toMatch(/run `p2p identity rotate --resume`/);
    const contest = await kim.run(["identity", "rotate", "--resume", "--contest", "--yes", "--wait", "1"]);
    expect(contest.code, `${contest.out}\n${contest.err}`).toBe(0);
    expect(contest.json).toMatchObject({ contest: true, step: "done" });
    // Past the devices step: the key holder that was sent the rotation is named, to revoke on the new identity if lost.
    expect(contest.err).toContain(keysOf(kim3).did);
    expect(contest.err).toMatch(/holds your identity key/);
    // In the fork case the competing final version reaches no relay (the thief's final is terminal, and a restricted
    // connection takes only a version on top of every held tip): the friends' conflict comes from the invites.
    expect(contest.json.finalPublished).toBe(false);
    const tips = await relayTips(ids.kim);
    expect(tips.filter((t) => t.rotation !== undefined)).toHaveLength(1);
    expect(JSON.stringify(tips)).not.toContain(contest.json.to);
    const items = (await lee.ok(["held"])).held.filter((h: any) => h.type === "rotation");
    // lee holds the contest's invite; the old identity's head carries the thief's rotation: a conflict, neither applies.
    expect(items.map((h: any) => h.from)).toContain(contest.json.to);
    for (const h of items) expect((await lee.run(["held", "approve", h.id])).json.error).toBe("rotation_conflict");
  }, 240_000);
});

describe("#91: --resume --contest on a plan not yet accepted", () => {
  it("is refused (the plan never dropped the devices that could have published the rotation): --cancel, then --contest", async () => {
    const mia = user("mia");
    const mia2 = user("mia2");
    await init(mia);
    await link(mia, mia2, "stolen", true);
    const mia2Did = keysOf(mia2).did;
    await mia.ok(["devices", "revoke", mia2Did]);
    await connectingFork(mia, { devices: [mia2Did] });
    const plan = await mia.run(["identity", "rotate", "--plan"]);
    expect(plan.code, plan.err).toBe(0);
    const thief = await mia2.run(["identity", "rotate", "--yes", "--wait", "1", "--backup-file"]);
    expect(thief.code, `${thief.out}\n${thief.err}`).toBe(0);
    {
      // mia's device sees the thief's rotation (a refresh brings it in).
      const app = await mia.app();
      await app.load();
      await app.refreshIdentity(app.userId, app.relays, { force: true, quiet: true });
      await app.close();
    }
    const r = await mia.run(["identity", "rotate", "--resume", "--contest", "--yes", "--wait", "1"]);
    expect(r.json.error, r.err).toBe("usage");
    expect(r.json.reason).toContain("p2p identity rotate --cancel");
    expect(r.json.reason).toContain("p2p identity rotate --contest");
    const st = (await readRotationState(mia.home))!;
    expect([st.step, st.accepted ?? false, st.contest ?? false]).toEqual(["created", false, false]);
    expect((await mia.run(["identity", "rotate", "--cancel"])).json.cancelled).toBe(true);
    const contest = await mia.run(["identity", "rotate", "--contest", "--yes", "--wait", "1", "--backup-file"]);
    expect(contest.code, `${contest.out}\n${contest.err}`).toBe(0);
    expect(contest.json).toMatchObject({ contest: true, step: "done" });
  }, 240_000);
});

describe("#91: branch summaries print relay URLs and device ids only", () => {
  it("core keeps anything else out of a verified version, and the summary checks again", () => {
    const ik = identityKeyFromSeed(new Uint8Array(32).fill(7));
    const d = generateDeviceKeysV3(ik.userId).did;
    const base = { ver: 1, prev: null, name: "x", devices: [d], keyholders: [d], by: d };
    // Core: a relay URL that isn't canonical (control characters, bidi overrides, userinfo) never gets in.
    for (const r of ["wss://r.test/v3\u001b[2J", "wss://r.test/\u202ev3", "wss://user@r.test/v3", "wss://r.test/v3?x=1"]) {
      expect(() => createIdentityDoc(ik, { ...base, relays: [r] })).toThrow();
    }
    expect(() => createIdentityDoc(ik, { ...base, relays: [R1], devices: ["d_\u001b[31m"], keyholders: [], by: "d_\u001b[31m" })).toThrow();
    // The summary: only canonical, printable relay URLs and device ids are kept.
    const s = branchSummary("h", 3, [d, d, "not a did", "d_\u202eaaaaaaaaaaaaaaaaaaaaaaaaa"], [R1, "wss://r.test/v3\u001b[2J", "wss://r.test/\u202ev3", "wss://R.TEST/v3/", RX]);
    expect(s).toEqual({ hash: "h", ver: 3, by: [d], relays: [R1, RX] });
  });
});
