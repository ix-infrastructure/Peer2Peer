// Copyright 2026 Ix Infrastructure Inc.
//
// §2.8 identity rotation end to end, against an in-process relay:
//  - ann rotates from her key-holding device after reviewing the plan (the new
//    fingerprint, the devices that would follow) and dropping a stolen key
//    holder, which is revoked before any code goes out. Two friends (bob,
//    cat), a circle she owns (with cat and bob) and one she is a member of
//    (bob's, where she is an admin) follow; her second device follows only
//    when its user says so there; her third (offline) re-links by hand;
//    relays refuse the old dids afterwards;
//  - friends and owners act only on a rotation the old identity published;
//    competing rotations are held as a conflict; a key holder that sees a
//    rotation it didn't publish alerts, never follows, and contests it;
//  - an interrupted rotation resumes with --resume (and needs a backup of the
//    new key before the final version); circle owners swap a rotated member
//    in by themselves only after the old final version is out, and never past
//    their hold policy; --resend; a follow that died mid-swap finishes.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createRotation, identityKeyFromSeed, b64uDecode, IdentityChain } from "@peer2peer/core/v3";
import { App } from "../app.js";
import { linkJoin, linkStart } from "../identity.js";
import { receiving } from "../inbound.js";
import { generateIdentityKey, loadCircle, verifyRotationSignatures } from "@peer2peer/core/v3";
import { friendVerdict, rotationsFor, noteOwnRotation, readRotationState, recoverInterruptedFollow, relinkRotated, rotate, rotatePlan, type RotateResult, type RotationState } from "../rotation.js";
import { mintInvite } from "../social.js";
import { importSync, sendSync } from "../sync.js";
import { sleep, startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-rotate.test/v3";
const LIMITS = { identityPublishPerIpPerHour: 100_000, identityPublishPerIssPerHour: 1000, contactPerIpPerHour: 100_000, contactPerSenderPerHour: 1000, linkOpsPerIpPerMinute: 100_000, linkOpenPerIp: 1000, linkOpenPerIpPerHour: 1000, linkOpenPerIssPerHour: 1000, connectsPerIpPerMinute: 100_000, authsPerIpPerMinute: 100_000, authsPerIpv4PerMinute: 100_000, httpPerIpPerMinute: 100_000 };
let relay: TestRelay;
const users: User[] = [];
const ids: Record<string, string> = {};

function user(name: string): User {
  const u = new User(name, { [R]: `ws://127.0.0.1:${relay.port}/v3` }, { P2P_FOLLOW_WAIT_MS: "20000" });
  users.push(u);
  return u;
}

const keysOf = (u: User) => JSON.parse(readFileSync(join(u.home, "cli", "keys.json"), "utf8")) as { userId: string; did: string; ik?: string };
const eventsOf = (u: User) => ((JSON.parse(readFileSync(join(u.home, "cli", "events.json"), "utf8")) as { items: any[] }).items ?? []);

async function init(u: User): Promise<string> {
  ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
  return ids[u.name];
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

async function circleWith(owner: User, name: string, members: User[]): Promise<string> {
  const cid = (await owner.ok(["circle", "create", name])).cid as string;
  for (const m of members) {
    await owner.ok(["circle", "invite", cid, ids[m.name]]);
    const item = (await m.ok(["held"])).held.find((h: any) => h.cid === cid);
    expect((await m.ok(["held", "approve", item.id, "--wait", "3", "--yes"])).status).toBe("joined");
    await owner.ok(["circle", "ls"]);
  }
  return cid;
}

/**
 * Runs a rotation on `u` while each of `followers` keeps checking its held
 * items and, as its user would, follows the rotation it finds there.
 */
async function rotateWith(u: User, followers: User[], opts: Parameters<typeof rotate>[1]): Promise<{ res: RotateResult; seen: any[] }> {
  const app = await u.app();
  await app.load();
  receiving(app);
  let done = false;
  const p = rotate(app, opts).finally(() => {
    done = true;
  });
  const old = keysOf(u).userId;
  const seen: any[] = [];
  await Promise.all(
    followers.map(async (f) => {
      while (!done && keysOf(f).userId === old) {
        const item = ((await f.run(["held"])).json?.held ?? []).find((h: any) => h.type === "rotation-follow");
        if (!item) {
          await sleep(200);
          continue;
        }
        seen.push(item);
        // Draining again never follows by itself (pre-release review H2): only the user's command does.
        await f.run(["friends"]);
        expect(keysOf(f).userId).toBe(old);
        await f.run(["identity", "follow", item.id]);
      }
    }),
  );
  try {
    return { res: await p, seen };
  } finally {
    await app.close();
  }
}

beforeAll(async () => {
  relay = await startRelay(R, { limits: LIMITS });
});

afterAll(async () => {
  await relay?.close();
  for (const u of users) u.cleanup();
});

describe("§2.8 identity rotation", () => {
  let ann: User, ann2: User, ann3: User, ann4: User, bob: User, cat: User;
  let owned = "";
  let bobs = "";
  let res: RotateResult;

  beforeAll(async () => {
    ann = user("ann");
    ann2 = user("ann2");
    ann3 = user("ann3");
    ann4 = user("ann4");
    bob = user("bob");
    cat = user("cat");
    for (const u of [ann, bob, cat]) await init(u);
    await link(ann, ann2, "laptop");
    await link(ann, ann3, "tablet");
    await link(ann, ann4, "stolen", true);
    await befriend(ann, bob);
    await befriend(ann, cat);
    owned = await circleWith(ann, "anns", [cat, bob]);
    bobs = await circleWith(bob, "bobs", [ann]);
    await bob.ok(["circle", "propose", bobs, "promote", ids.ann]);
    // ann's second device learns the circles and friends.
    await ann2.ok(["circle", "ls"]);
  }, 120_000);

  it("shows the plan first (new fingerprint, who would follow); nothing runs before it is accepted", async () => {
    const app = await ann.app();
    await app.load();
    receiving(app);
    const plan = await rotatePlan(app, { backupFileDefault: true });
    await app.close();
    expect(plan.follow.map((d) => d.label).sort()).toEqual(["laptop", "stolen", "tablet"]);
    expect(plan.follow.find((d) => d.label === "stolen")?.keyholder).toBe(true);
    expect(plan.newFingerprint).toMatch(/^[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}$/);
    expect(plan.backup?.file).toMatch(/backup-phrase-[a-z2-7]{16}\.txt$/);
    // Without an acceptance nothing is published (no terminal, no --yes).
    const r = await ann.run(["identity", "rotate", "--resume"]);
    expect(r.json.error).toBe("needs_confirmation");
    expect((await readRotationState(ann.home))?.step).toBe("created");
    ids.annPlanned = plan.to;
  }, 60_000);

  it("rotates: the stolen device is revoked first, the online device follows when told to, the offline one doesn't", async () => {
    const stolen = keysOf(ann4).did;
    const r = await rotateWith(ann, [ann2], { resume: true, yes: true, exclude: [stolen], waitSec: 8 });
    res = r.res;
    expect(res.from).toBe(ids.ann);
    expect(res.to).toBe(ids.annPlanned);
    expect(res.step).toBe("done");
    expect(res.devices.followed.map((d) => d.label)).toEqual(["laptop"]);
    expect(res.devices.offline.map((d) => d.label)).toEqual(["tablet"]);
    expect(res.devices.excluded.map((d) => d.label)).toEqual(["stolen"]);
    expect(res.friends.invited).toBe(2);
    expect(res.circles.map((c) => [c.cid, c.role, c.status]).sort()).toEqual([[owned, "owner", "done"], [bobs, "member", "done"]].sort());
    // The follower's held item named the new fingerprint and the device that sent it.
    expect(r.seen[0]).toMatchObject({ type: "rotation-follow", newFingerprint: res.fingerprint, deviceLabel: expect.any(String) });
    expect(JSON.stringify(r.seen)).not.toMatch(/p2p-link:/);
    // No link code (a secret) anywhere in the result.
    expect(JSON.stringify(res)).not.toMatch(/p2p-link:/);
    // This home is now the new identity; this device has a new did.
    const who = await ann.ok(["whoami"]);
    expect(who.userId).toBe(res.to);
    expect(who.devices.map((d: any) => d.did)).toContain(keysOf(ann2).did);
    expect(keysOf(ann2).userId).toBe(res.to);
    expect(keysOf(ann3).userId).toBe(ids.ann);
    // H1: the version before the final one no longer lists the stolen device (revoked before any code).
    const old = new App({ env: { ...ann.env, P2P_HOME: res.archive! }, io: { out: () => {}, err: () => {} } });
    await old.load();
    const chain = IdentityChain.fromStored((await old.store.getIdentity(ids.ann))!);
    const fin = chain.tips().find((t) => t.rotation)!;
    expect(chain.get(fin.prev!)!.devices).not.toContain(stolen);
    await old.close();
  }, 120_000);

  it("the old identity's final version lists no devices and carries the statement; the relay refuses old dids", async () => {
    const app = await bob.app();
    await app.load();
    const v = await app.refreshIdentity(ids.ann, [R], { force: true });
    expect(v?.devices).toEqual([]);
    expect(v?.rotations).toHaveLength(1);
    await app.close();
    // The offline device: every relay refuses it, and it is told where its identity went.
    const a3 = await ann3.app();
    await a3.load();
    await expect(a3.connect()).rejects.toMatchObject({ code: "identity_rotated" });
    await a3.close();
    // The archived old home (the rotating device's old keys) and the stolen device are refused too.
    for (const env of [{ ...ann.env, P2P_HOME: res.archive! }, ann4.env]) {
      const old = new App({ env, io: { out: () => {}, err: () => {} } });
      await old.load();
      await expect(old.connect()).rejects.toMatchObject({ code: expect.stringMatching(/identity_rotated|device_revoked/) });
      await old.close();
    }
  }, 60_000);

  it("bob holds \"ann moved to a new key\"; approving makes friends with the new id and ends the old friendship", async () => {
    const held = (await bob.ok(["held"])).held;
    const item = held.find((h: any) => h.type === "rotation");
    expect(item).toMatchObject({ from: res.to, old: ids.ann, confirmedByDocument: true });
    expect(item.summary).toMatch(/moved to a new key/);
    const ok = await bob.ok(["held", "approve", item.id]);
    expect(ok).toMatchObject({ type: "rotation", from: ids.ann, to: res.to });
    await ann.ok(["friends"]);
    const bf = (await bob.ok(["friends"])).friends.map((f: any) => f.userId);
    expect(bf).toContain(res.to);
    expect(bf).not.toContain(ids.ann);
    expect((await ann.ok(["friends"])).friends.map((f: any) => f.userId)).toContain(ids.bob);
  }, 60_000);

  it("bob, owner of a circle ann was an admin of, swapped her in as a member; the admin rights wait for his approval", async () => {
    const m = await bob.ok(["circle", "members", bobs]);
    const row = m.members.find((x: any) => x.userId === res.to);
    expect(row).toBeDefined();
    expect(row.admin).toBe(false);
    expect(m.members.map((x: any) => x.userId)).not.toContain(ids.ann);
    const admin = (await bob.ok(["held"])).held.find((h: any) => h.type === "rotation-join" && h.cid === bobs);
    expect(admin).toMatchObject({ reason: "admin" });
    expect(admin.summary).toMatch(/approve to make the new key an admin/);
    await bob.ok(["held", "approve", admin.id]);
    expect((await bob.ok(["circle", "members", bobs])).members.find((x: any) => x.userId === res.to).admin).toBe(true);
    // ann's new identity stands there once it has the new version.
    await ann.ok(["circle", "ls"]);
    const mine = (await ann.ok(["circle", "members", bobs])).members.find((x: any) => x.userId === res.to);
    expect(mine?.stands).toBe(true);
  }, 60_000);

  it("cat approves too; the circle ann owned now belongs to the new identity, the old one gone", async () => {
    const item = (await cat.ok(["held"])).held.find((h: any) => h.type === "rotation");
    await cat.ok(["held", "approve", item.id]);
    const c = (await cat.ok(["circle", "ls"])).circles.find((x: any) => x.cid === owned);
    expect(c.owner).toBe(res.to);
    const members = (await cat.ok(["circle", "members", owned])).members.map((x: any) => x.userId);
    expect(members).toContain(res.to);
    expect(members).not.toContain(ids.ann);
    expect((await ann.ok(["circle", "ls"])).circles.find((x: any) => x.cid === owned)).toMatchObject({ role: "owner", owner: res.to });
    // The follower got the new identity's circles by sync.
    expect((await ann2.ok(["circle", "ls"])).circles.find((x: any) => x.cid === owned)).toMatchObject({ owner: res.to, joined: true });
  }, 60_000);

  it("the offline device re-links by hand with --rotated (and only into the identity a rotation names)", async () => {
    const a = await ann.app();
    await a.load();
    receiving(a);
    const start = await linkStart(a, {});
    const b = await ann3.app();
    const join = await relinkRotated(b, start.code, { label: "tablet" });
    const [, joined] = await Promise.all([start.wait(async (req) => req.compareCode === join.compareCode), join.wait()]);
    await a.close();
    await b.close();
    expect(joined).toMatchObject({ userId: res.to, from: ids.ann });
    expect(keysOf(ann3).userId).toBe(res.to);
    // A device that wasn't rotated can't use --rotated.
    const c = await bob.app();
    await expect(relinkRotated(c, "p2p-link:aaaaaaaaaaaaaaaaaaaaaaaaaa@relay-rotate.test/v3")).rejects.toMatchObject({ code: "not_rotated" });
    await c.close();
  }, 60_000);

  it("a rotated identity can't rotate again from the old keys", async () => {
    const old = new App({ env: { ...ann.env, P2P_HOME: res.archive! }, io: { out: () => {}, err: () => {} } });
    await old.load();
    await expect(rotate(old, { yes: true })).rejects.toBeTruthy();
    await old.close();
  });
});

describe("§2.8 competing rotations", () => {
  it("a statement the old identity never published can't be approved; two rotations are a conflict, neither applied", async () => {
    const dan = user("dan");
    const eve = user("eve");
    const thief = user("thief");
    for (const u of [dan, eve, thief]) await init(u);
    await befriend(dan, eve);
    // A thief with dan's identity key signs its own rotation and re-invites dan's friend.
    const danIk = identityKeyFromSeed(b64uDecode(keysOf(dan).ik!, 32));
    const tIk = identityKeyFromSeed(b64uDecode(keysOf(thief).ik!, 32));
    const statement = createRotation(danIk, tIk);
    const t = await thief.app();
    await t.load();
    receiving(t);
    await t.connect();
    await t.refreshIdentity(ids.eve, [R], { force: true });
    const m = await mintInvite(t, { aud: ids.eve, uses: 3, ttlSec: 3600 });
    expect((await t.deliver(ids.eve, "contact", { own: ids.thief, sid: "~contact" }, { rotation: statement, invite: m.jws })).relays).toEqual([R]);
    await t.close();
    const first = (await eve.ok(["held"])).held.filter((h: any) => h.type === "rotation");
    expect(first).toHaveLength(1);
    expect(first[0]).toMatchObject({ from: ids.thief, old: ids.dan, confirmedByDocument: false });
    // H2: dan's own document never carried it, so it can't split dan from eve.
    expect((await eve.run(["held", "approve", first[0].id])).json.error).toBe("not_published");
    // The real dan rotates.
    const real = await dan.ok(["identity", "rotate", "--yes", "--wait", "1", "--backup-file"]);
    const both = (await eve.ok(["held"])).held.filter((h: any) => h.type === "rotation");
    expect(both.map((h: any) => h.from).sort()).toEqual([ids.thief, real.to].sort());
    expect(both.every((h: any) => h.reason === "conflict")).toBe(true);
    for (const h of both) {
      const r = await eve.run(["held", "approve", h.id]);
      expect(r.json.error).toBe("rotation_conflict");
    }
    // Neither was applied: eve is friends with neither new identity.
    const ef = (await eve.ok(["friends"])).friends.map((f: any) => f.userId);
    expect(ef).not.toContain(real.to);
    expect(ef).not.toContain(ids.thief);
  }, 120_000);

  it("a key holder that sees a rotation it didn't publish alerts, never follows, and contests it into a conflict", async () => {
    const kim = user("kim");
    const kim2 = user("kim2");
    const lou = user("lou");
    for (const u of [kim, lou]) await init(u);
    await link(kim, kim2, "stolen", true);
    const kim2Did = keysOf(kim2).did;
    await befriend(kim, lou);
    await kim2.ok(["friends"]);
    // The thief, on the stolen key holder, rotates all the way.
    // (It opts lou in: a friendship kim's own device made is one the stolen device can't vouch for, pre-release re-review M1.)
    const thief = await kim2.ok(["identity", "rotate", "--yes", "--wait", "1", "--backup-file", "--invite", ids.lou]);
    // kim's own key holder: an alert, no held rotation to follow, and a plain rotate refuses.
    await kim.run(["held"]);
    expect((await kim.ok(["held"])).held.filter((h: any) => h.type === "rotation-follow")).toEqual([]);
    expect(eventsOf(kim).some((e) => e.kind === "p2p.alert" && e.data?.to === thief.to)).toBe(true);
    const plain = await kim.run(["identity", "rotate", "--yes"]);
    expect(plain.json.error).toBe("identity_rotated");
    expect(plain.json.reason).toMatch(/--contest/);
    const contest = await kim.ok(["identity", "rotate", "--contest", "--yes", "--wait", "1", "--backup-file"]);
    expect(contest).toMatchObject({ contest: true, step: "done" });
    // pre-release re-review M4: the key holder that signed the other rotation got no code (dropped by default).
    expect(contest.devices.excluded.map((d: any) => d.did)).toEqual([kim2Did]);
    expect(contest.devices.followed).toEqual([]);
    // lou holds both, as a conflict, and applies neither.
    const items = (await lou.ok(["held"])).held.filter((h: any) => h.type === "rotation");
    expect(items.map((h: any) => h.from).sort()).toEqual([thief.to, contest.to].sort());
    for (const h of items) expect((await lou.run(["held", "approve", h.id])).json.error).toBe("rotation_conflict");
  }, 120_000);

  it("the thief race end to end: a friend and an owner who approved the thief are suspended when the contest arrives; the contest never trusts the thief's devices", async () => {
    const may = user("may");
    const may2 = user("may2");
    const may3 = user("may3");
    const ned = user("ned");
    const ned2 = user("ned2");
    const mal = user("mal");
    const pat = user("pat");
    for (const u of [may, ned, mal, pat]) await init(u);
    const mayIk = identityKeyFromSeed(b64uDecode(keysOf(may).ik!, 32));
    await link(may, may2, "stolen", true);
    await link(ned, ned2, "phone");
    const may2Did = keysOf(may2).did;
    await befriend(may, ned);
    await may2.ok(["friends"]);
    await ned2.ok(["friends"]);
    const neds = await circleWith(ned, "neds", [may]);
    await may2.ok(["circle", "ls"]);
    // Before the theft is noticed, the stolen key holder links a device of the thief's...
    await link(may2, may3, "my tablet");
    const may3Did = keysOf(may3).did;
    {
      // (may's device learns the version that lists the tablet, as its periodic refresh would.)
      const a = await may.app();
      await a.load();
      await a.refreshIdentity(ids.may, [R], { force: true });
      await a.close();
    }
    // ...which plants an accomplice: its friendship reaches may's own device by sync (pre-release re-review M1).
    await befriend(mal, may3);
    await may.ok(["friends"]);
    expect((await may.ok(["friends"])).friends.map((f: any) => f.userId)).toContain(ids.mal);
    // L1: even a plain rotation drops, by default, a device this device didn't list itself.
    const plain = await may.ok(["identity", "rotate", "--plan"]);
    expect(plain.excluded).toEqual([expect.objectContaining({ did: may3Did, why: "added by a version you didn't publish", labelTrusted: false })]);
    expect(plain.follow.map((d: any) => d.did)).toEqual([may2Did]);
    // M1: and the accomplice that device befriended isn't invited by default; the count says so (L2).
    expect(plain.friends).toBe(1);
    expect(plain.friendsOptIn).toEqual([expect.objectContaining({ userId: ids.mal, invited: false, why: expect.stringMatching(/^made by a device the plan drops/) })]);
    const opted = await may.ok(["identity", "rotate", "--plan", "--invite", ids.mal]);
    expect(opted.friends).toBe(2);
    expect(opted.friendsOptIn).toEqual([expect.objectContaining({ userId: ids.mal, invited: true })]);
    // L1 (imports): while the rotation is under way, a friendship the thief's tablet makes isn't taken from its sync.
    await befriend(pat, may3);
    await may.ok(["friends"]);
    expect((await may.ok(["friends"])).friends.map((f: any) => f.userId)).not.toContain(ids.pat);
    await may.ok(["identity", "rotate", "--cancel"]);
    // The thief rotates all the way.
    const thief = await may2.ok(["identity", "rotate", "--yes", "--wait", "1", "--backup-file"]);
    // ned approves the thief (its final version is out, nothing conflicts yet), and his circle swaps it in.
    const tItem = (await ned.ok(["held"])).held.find((h: any) => h.type === "rotation");
    await ned.ok(["held", "approve", tItem.id]);
    expect((await ned.ok(["friends"])).friends.map((f: any) => f.userId)).toContain(thief.to);
    expect((await ned.ok(["circle", "members", neds])).members.find((m: any) => m.userId === thief.to)?.stands).toBe(true);
    // M2: ned's phone learns the approvals.
    await ned2.ok(["friends"]);
    // may notices (an alert) and contests. N2: the thief's tablet is dropped by default, its label untrusted;
    // M4: so is the key holder that signed the other rotation's final version.
    await may.run(["held"]);
    const plan = await may.ok(["identity", "rotate", "--plan", "--contest", "--backup-file"]);
    expect(plan.contest).toBe(true);
    expect(plan.excluded).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ did: may3Did, why: "added by a version you didn't publish", labelTrusted: false }),
        expect.objectContaining({ did: may2Did, keyholder: true, why: "signed the rotation you are contesting" }),
      ]),
    );
    expect(plan.follow).toEqual([]);
    // M1: contesting, the stored friendships count, but never the accomplice's.
    expect(plan.friends).toBe(1);
    expect(plan.friendsOptIn.map((f: any) => f.userId)).toEqual([ids.mal]);
    const contest = await may.ok(["identity", "rotate", "--resume", "--yes", "--wait", "1"]);
    expect(contest).toMatchObject({ contest: true, step: "done" });
    expect(contest.devices.excluded.map((d: any) => d.did)).toEqual(expect.arrayContaining([may3Did, may2Did]));
    expect(contest.friends.invited).toBe(1);
    expect((await mal.ok(["held"])).held.filter((h: any) => h.from === contest.to)).toEqual([]);
    // N1: the contest reaches ned. The thief he approved is suspended at once, everywhere.
    await ned.ok(["held"]);
    const held = (await ned.ok(["held"])).held;
    const dispute = held.find((h: any) => h.type === "rotation-dispute");
    expect(dispute).toMatchObject({ old: ids.may, candidates: [thief.to, contest.to].sort() });
    expect(dispute.summary).toMatch(/CONTESTED/);
    expect(eventsOf(ned).some((e) => e.kind === "p2p.alert" && e.data?.what === "rotation-dispute")).toBe(true);
    expect((await ned.ok(["friends"])).blocked.map((b: any) => b.userId)).toContain(thief.to);
    // M3: ned's key holder took the thief out of the circle he owns at once.
    expect((await ned.ok(["circle", "members", neds])).members.map((m: any) => m.userId)).not.toContain(thief.to);
    const nedApp = await ned.app();
    await nedApp.load();
    expect((await nedApp.store.listCapsIssued()).filter((c) => c.sub === thief.to)).toEqual([]);
    await nedApp.close();
    // M2: ned's phone suspends it too and holds the same dispute...
    await ned2.ok(["held"]);
    const d2 = (await ned2.ok(["held"])).held.find((h: any) => h.type === "rotation-dispute");
    expect(d2).toMatchObject({ old: ids.may, candidates: [thief.to, contest.to].sort() });
    expect((await ned2.ok(["friends"])).blocked.map((b: any) => b.userId)).toContain(thief.to);
    // ...but can't settle it (M3): only a key holder does, and it says so.
    const there = await ned2.run(["identity", "dispute", d2.id, "--keep", contest.to]);
    expect(there.json.error).toBe("needs_keyholder");
    // A choice is required: approve won't do.
    expect((await ned.run(["held", "approve", dispute.id])).json.error).toBe("usage");
    // ned confirms out of band and keeps the contest: friends with it, the thief out of his friends and circle.
    const settled = await ned.ok(["identity", "dispute", dispute.id, "--keep", contest.to]);
    expect(settled).toMatchObject({ keep: contest.to, rejected: [thief.to] });
    await may.ok(["friends"]);
    const nf = (await ned.ok(["friends"])).friends.map((f: any) => f.userId);
    expect(nf).toContain(contest.to);
    expect(nf).not.toContain(thief.to);
    const members = (await ned.ok(["circle", "members", neds])).members.map((m: any) => m.userId);
    expect(members).toContain(contest.to);
    expect(members).not.toContain(thief.to);
    expect((await ned.ok(["held"])).held.filter((h: any) => h.type.startsWith("rotation"))).toEqual([]);
    // M2: the settlement reaches the phone: the dispute is gone there, the thief still blocked.
    await ned2.ok(["held"]);
    expect((await ned2.ok(["held"])).held.filter((h: any) => h.type === "rotation-dispute")).toEqual([]);
    expect((await ned2.ok(["friends"])).blocked.map((b: any) => b.userId)).toContain(thief.to);
    // M5: a later rotation from may's old id (the thief still has that key) is held as a new dispute,
    // and the identity ned kept after checking out of band isn't suspended again.
    const t3 = user("t3");
    await init(t3);
    const statement = createRotation(mayIk, identityKeyFromSeed(b64uDecode(keysOf(t3).ik!, 32)));
    const t = await t3.app();
    await t.load();
    receiving(t);
    await t.connect();
    await t.refreshIdentity(ids.ned, [R], { force: true });
    const m = await mintInvite(t, { aud: ids.ned, uses: 3, ttlSec: 3600 });
    expect((await t.deliver(ids.ned, "contact", { own: ids.t3, sid: "~contact" }, { rotation: statement, invite: m.jws })).relays).toEqual([R]);
    await t.close();
    await ned.ok(["held"]);
    const again = (await ned.ok(["held"])).held.find((h: any) => h.type === "rotation-dispute");
    expect(again).toMatchObject({ old: ids.may, candidates: [contest.to, ids.t3].sort() });
    const after = await ned.ok(["friends"]);
    expect(after.blocked.map((b: any) => b.userId)).not.toContain(contest.to);
    expect(after.friends.map((f: any) => f.userId)).toContain(contest.to);
    expect((await ned.ok(["circle", "members", neds])).members.find((x: any) => x.userId === contest.to)?.stands).toBe(true);
  }, 300_000);
});

describe("§2.8 following: only a key holder's sync counts, and it is held", () => {
  it("ignored from an ordinary device; held on an ordinary device (no secret listed); an alert on a key holder", async () => {
    const hal = user("hal");
    const hal2 = user("hal2");
    const hal3 = user("hal3");
    await init(hal);
    await link(hal, hal2, "phone", true);
    await link(hal, hal3, "desk");
    const halIk = identityKeyFromSeed(b64uDecode(keysOf(hal).ik!, 32));
    const other = identityKeyFromSeed(new Uint8Array(32).fill(7));
    const statement = createRotation(halIk, other);
    const body = { statement, link: "p2p-link:aaaaaaaaaaaaaaaaaaaaaaaaaa@relay-rotate.test/v3" };
    const a = await hal3.app();
    await a.load();
    await a.refreshIdentity(ids.hal, [R], { force: true });
    await noteOwnRotation(a, body, keysOf(hal3).did);
    expect((await a.state.get("held")) ?? []).toEqual([]);
    await noteOwnRotation(a, body, keysOf(hal).did);
    const held = (await a.state.get("held")) ?? [];
    expect(held).toMatchObject([{ type: "rotation-follow", device: keysOf(hal).did }]);
    expect(Object.values((await a.state.get("follows")) ?? {})[0]?.link).toBe(body.link);
    await a.close();
    const listed = await hal3.ok(["held"]);
    expect(JSON.stringify(listed)).not.toMatch(/p2p-link:/);
    expect(listed.held[0].summary).toMatch(/follow it with `p2p identity follow/);
    // Declining drops the secret with it.
    await hal3.ok(["held", "decline", listed.held[0].id]);
    const b = await hal3.app();
    await b.load();
    expect((await b.state.get("follows")) ?? {}).toEqual({});
    await b.close();
    // On a key holder: never held, an alert instead; and `identity follow` refuses there.
    const k = await hal2.app();
    await k.load();
    await k.refreshIdentity(ids.hal, [R], { force: true });
    await noteOwnRotation(k, body, keysOf(hal).did);
    expect((await k.state.get("held")) ?? []).toEqual([]);
    expect(((await k.state.get("events"))?.items ?? []).some((e) => e.kind === "p2p.alert")).toBe(true);
    await k.close();
  }, 60_000);

  it("a follow that died mid-swap finishes on the next run", async () => {
    const home = join(users[0].home, "..", `p2p-recover-${Date.now()}`);
    mkdirSync(join(home, "cli"), { recursive: true });
    writeFileSync(join(home, "cli", "keys.json"), '{"old":true}');
    mkdirSync(join(home, "rotation", "follow", "cli"), { recursive: true });
    mkdirSync(join(home, "rotation", "follow", "v3"), { recursive: true });
    writeFileSync(join(home, "rotation", "follow", "cli", "keys.json"), '{"new":true}');
    writeFileSync(join(home, "rotation", "follow", "linked.json"), JSON.stringify({ to: "p2p:x", tag: "oldfp-1" }));
    expect(await recoverInterruptedFollow(home)).toBe(true);
    expect(readFileSync(join(home, "cli", "keys.json"), "utf8")).toBe('{"new":true}');
    expect(readFileSync(join(home, "rotated", "oldfp-1", "cli", "keys.json"), "utf8")).toBe('{"old":true}');
    expect(existsSync(join(home, "rotation", "follow"))).toBe(false);
    expect(await recoverInterruptedFollow(home)).toBe(false);
  });
});

describe("§2.8 an interrupted rotation", () => {
  it("resumes; needs a backup before the final version; owners wait for it (and their hold policy); --resend", async () => {
    const fay = user("fay");
    const gil = user("gil");
    for (const u of [fay, gil]) await init(u);
    await befriend(fay, gil);
    const cid = await circleWith(fay, "fays", [gil]);
    const gils = await circleWith(gil, "gils", [fay]);
    const held = await circleWith(gil, "gilsheld", [fay]);
    await gil.ok(["circle", "hold", held, "on"]);
    const app = await fay.app();
    await app.load();
    receiving(app);
    await expect(rotate(app, { yes: true, waitSec: 1, stopAfter: "social" })).rejects.toMatchObject({ code: "interrupted" });
    await app.close();
    const st = await readRotationState(fay.home);
    expect(st?.step).toBe("social");
    // Still the old identity here: the final version isn't out.
    expect((await fay.ok(["whoami"])).userId).toBe(ids.fay);
    // M1: gil's client won't swap fay in before her old identity's final version is out, nor past his hold.
    const waiting = (await gil.ok(["held"])).held.filter((h: any) => h.type === "rotation-join");
    expect(Object.fromEntries(waiting.map((h: any) => [h.cid, h.reason]))).toEqual({ [gils]: "not-final-yet", [held]: "held-by-policy" });
    expect((await gil.ok(["circle", "members", gils])).members.map((x: any) => x.userId)).toContain(ids.fay);
    // Nor will he approve the friendship yet.
    const early = (await gil.ok(["held"])).held.find((h: any) => h.type === "rotation");
    expect((await gil.run(["held", "approve", early.id])).json.error).toBe("not_published");
    const again = await fay.run(["identity", "rotate", "--yes"]);
    expect(again.json.error).toBe("rotation_in_progress");
    // L3: the new key would live on this device only: a backup first.
    expect((await fay.run(["identity", "rotate", "--resume"])).json.error).toBe("needs_backup");
    const r = await fay.ok(["identity", "rotate", "--resume", "--backup-file"]);
    expect(r).toMatchObject({ from: ids.fay, to: st!.to, step: "done", backup: { file: expect.stringMatching(/backup-phrase/) } });
    expect((await fay.ok(["whoami"])).userId).toBe(st!.to);
    // Now the final version is out: gil's client swaps her in by itself; the held circle waits.
    await gil.ok(["held"]);
    expect((await gil.ok(["circle", "members", gils])).members.map((x: any) => x.userId)).toEqual(expect.arrayContaining([st!.to]));
    expect((await gil.ok(["circle", "members", gils])).members.map((x: any) => x.userId)).not.toContain(ids.fay);
    const policy = (await gil.ok(["held"])).held.find((h: any) => h.type === "rotation-join" && h.cid === held);
    await gil.ok(["held", "approve", policy.id]);
    expect((await gil.ok(["circle", "members", held])).members.map((x: any) => x.userId)).toContain(st!.to);
    // gil follows the circle and the friendship over.
    const item = (await gil.ok(["held"])).held.find((h: any) => h.type === "rotation");
    await gil.ok(["held", "approve", item.id]);
    expect((await gil.ok(["circle", "ls"])).circles.find((x: any) => x.cid === cid).owner).toBe(st!.to);
    expect((await fay.run(["identity", "rotate", "--resume"])).json.error).toBe("no_rotation");
    // L2: a friend the invite didn't reach gets it again with --resend.
    const path = join(fay.home, "rotation", "state.json");
    const s = JSON.parse(readFileSync(path, "utf8"));
    s.friends[ids.gil] = "failed";
    writeFileSync(path, JSON.stringify(s));
    const resent = await fay.ok(["identity", "rotate", "--resend"]);
    expect(resent).toMatchObject({ sent: 1, failed: [], throttled: false });
  }, 180_000);
});

describe("§2.8 disputes and trust that a device of the user can't forge (pre-release third review)", () => {
  it("M-A: a forged dispute synced from an ordinary device blocks no one, publishes nothing, holds nothing", async () => {
    const ola = user("ola");
    const ola2 = user("ola2");
    const fay = user("fayf");
    const xen = user("xen");
    for (const u of [ola, fay, xen]) await init(u);
    await link(ola, ola2, "laptop");
    await befriend(ola, fay);
    await ola2.ok(["friends"]);
    const cid = await circleWith(ola, "olas", [fay]);
    await ola2.ok(["circle", "ls"]);
    const verOf = async () => {
      const a = await ola.app();
      await a.load();
      const v = (await loadCircle(a.store, cid))!.chain.head.ver;
      await a.close();
      return v;
    };
    const ver0 = await verOf();
    // The compromised ordinary device claims fay is a contested rotation's carried-over identity.
    const o2 = await ola2.app();
    await o2.load();
    receiving(o2);
    await o2.connect();
    expect(await sendSync(o2, { rotationDispute: { old: ids.xen, candidates: [ids.fayf, `p2p:${"a".repeat(52)}`], suspended: [ids.fayf], statements: [] } })).toBe(1);
    await o2.close();
    const r = await ola.run(["held"]);
    expect(r.err).toMatch(/can't verify it yet \(nothing was changed\)/);
    expect((r.json.held ?? []).filter((h: any) => h.type === "rotation-dispute")).toEqual([]);
    const f = await ola.ok(["friends"]);
    expect(f.blocked.map((b: any) => b.userId)).not.toContain(ids.fayf);
    expect(f.friends.map((x: any) => x.userId)).toContain(ids.fayf);
    expect((await ola.ok(["circle", "members", cid])).members.find((m: any) => m.userId === ids.fayf)?.stands).toBe(true);
    expect(await verOf()).toBe(ver0);
    expect(eventsOf(ola).some((e) => e.kind === "p2p.alert" && e.data?.what === "rotation-dispute")).toBe(false);
    expect((await ola.ok(["held"])).held.some((h: any) => /CONTESTED/.test(h.summary ?? ""))).toBe(false);
  }, 120_000);

  it("L-C: junk synced disputes about strangers never push a real recorded rotation out of the bounded list", async () => {
    const pia = user("pia");
    const gus = user("gus");
    const gus2 = user("gus2");
    for (const u of [pia, gus, gus2]) await init(u);
    await befriend(pia, gus);
    // A real rotation of gus's (whoever signed it) reaches pia and is recorded.
    const gusIk = identityKeyFromSeed(b64uDecode(keysOf(gus).ik!, 32));
    const statement = createRotation(gusIk, identityKeyFromSeed(b64uDecode(keysOf(gus2).ik!, 32)));
    const g = await gus2.app();
    await g.load();
    receiving(g);
    await g.connect();
    await g.refreshIdentity(ids.pia, [R], { force: true });
    const m = await mintInvite(g, { aud: ids.pia, uses: 3, ttlSec: 3600 });
    await g.deliver(ids.pia, "contact", { own: ids.gus2, sid: "~contact" }, { rotation: statement, invite: m.jws });
    await g.close();
    await pia.ok(["held"]);
    const a = await pia.app();
    await a.load();
    expect((await rotationsFor(a, ids.gus)).map((r) => r.to)).toEqual([ids.gus2]);
    // 256 synced disputes, each about a stranger with two genuinely signed, conflicting statements.
    for (let i = 0; i < 256; i++) {
      const fake = generateIdentityKey();
      const s1 = createRotation(fake, generateIdentityKey());
      const s2 = createRotation(fake, generateIdentityKey());
      const to = [s1, s2].map((s) => verifyRotationSignatures(s).to);
      await importSync(a, { rotationDispute: { old: fake.userId, candidates: to, suspended: [to[0]], statements: [s1, s2] } }, { fdid: "d_other" });
    }
    expect((await rotationsFor(a, ids.gus)).map((r) => r.to)).toEqual([ids.gus2]);
    expect(Object.keys((await a.state.get("rotations")) ?? {})).toEqual([ids.gus]);
    expect(((await a.state.get("held")) ?? []).filter((h) => h.type === "rotation-dispute")).toEqual([]);
    await a.close();
  }, 180_000);

  it("L-B: a follower whose link aborted (another device answered its code) doesn't vouch for a friendship", () => {
    const st = {
      v: 1,
      from: "p2p:old",
      to: "p2p:new",
      startedAt: 0,
      step: "social",
      keepKeyholders: false,
      selfDid: "d_self",
      devices: {
        d_ab: { label: "phone", keyholder: false, status: "aborted" },
        d_ok: { label: "laptop", keyholder: false, status: "followed" },
      },
      friendSigners: { "p2p:a": [{ did: "d_ab", live: true }], "p2p:b": [{ did: "d_ok", live: true }] },
      plan: { friends: 0, owned: 0, memberOf: 0 },
      friends: {},
      circles: {},
    } as unknown as RotationState;
    expect(friendVerdict(st, "p2p:a")).toMatchObject({ invite: false });
    expect(friendVerdict(st, "p2p:a").why).toBeDefined();
    expect(friendVerdict(st, "p2p:b")).toEqual({ invite: true });
    expect(friendVerdict({ ...st, inviteOptIn: ["p2p:a"] }, "p2p:a").invite).toBe(true);
  });
});
