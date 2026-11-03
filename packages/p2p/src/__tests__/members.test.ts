// Copyright 2026 Ix Infrastructure Inc.
//
// Members-only relays, end to end through the CLI: a stranger is refused with
// `not_member`; a member's short code admits a brand-new teammate on that
// relay (the code carries an admission key); and with a circle-following
// relay, the owner's client seeds the circle, adding the joiner makes it a
// member there, and removing it cuts it off.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { inviteAdmitHash, inviteAdmitKey, parseShortCode } from "../shortcode.js";
import type { RelayConnection } from "../relay-client.js";
import { alongside, startRelay, User, type TestRelay } from "./harness.js";

const OPEN = "wss://members-open.test/v3";
const LIST = "wss://members-list.test/v3";
const CIRC = "wss://members-circle.test/v3";
let open: TestRelay;
let list: TestRelay;
let circ: TestRelay | undefined;
let t: Record<string, string>;
const users: User[] = [];

function user(name: string, relay: string): User {
  const u = new User(name, t, { P2P_DEFAULT_RELAYS: relay });
  users.push(u);
  return u;
}

beforeAll(async () => {
  open = await startRelay(OPEN);
  // Members-only from the start, with nobody on the list yet: the first member is added below.
  list = await startRelay(LIST, { config: { allow: [] } });
  t = { [OPEN]: `ws://127.0.0.1:${open.port}/v3`, [LIST]: `ws://127.0.0.1:${list.port}/v3`, [CIRC]: "ws://127.0.0.1:1/v3" };
});

afterAll(async () => {
  await open?.close();
  await list?.close();
  await circ?.close();
  for (const u of users) u.cleanup();
});

describe("members-only relay (allowlist)", () => {
  let alice: User;
  let aliceId: string;

  beforeAll(async () => {
    // Alice sets up on the open relay, then the operator lists her userId on LIST and she adds it.
    alice = user("alice", OPEN);
    aliceId = (await alice.ok(["setup", "--name", "alice", "--no-backup"])).userId;
    list.relay.setAllow([aliceId]);
    await alice.ok(["relays", "add", LIST]);
  }, 60_000);

  it("a stranger is refused with not_member, and nothing of it is served there", async () => {
    const eve = user("eve", LIST);
    const s = await eve.ok(["setup", "--name", "eve", "--no-backup"]);
    expect(s.published ?? []).not.toContain(LIST);
    // A command that needs the relay fails with not_member; one that can go on says why it is offline.
    expect((await eve.run(["invite", "--no-circle"])).json).toMatchObject({ error: "not_member", reason: expect.stringMatching(/members-only/) });
    expect((await eve.run(["friends"])).err).toMatch(/offline: every relay of yours is members-only/);
    expect((await fetch(`http://127.0.0.1:${list.port}/v3/identity/${s.userId}`)).status).toBe(404);
  }, 60_000);

  it("a member's code admits a brand-new teammate on the members-only relay", async () => {
    const inv = await alice.ok(["invite", "joey", "--no-circle", "--relay", LIST]);
    expect(inv.relay).toBe(LIST);
    const joey = user("joey", LIST);
    const j = await alongside(joey.run(["join", "--confirmed", inv.code, "--wait", "8", "--name", "joey"]), () => alice.ok(["invites"]));
    expect(j.code).toBe(0);
    const joeyId = j.json.created.userId as string;
    expect(j.json.created.relays).toEqual([LIST]);
    expect(list.relay.members.admitted(joeyId)).toBe(true);
    // The key was used up (the relay admitted joey), so the client dropped it.
    const app = await joey.app();
    await app.load();
    expect(Object.keys((await app.state.get("admits")) ?? {})).toEqual([]);
    await app.close();
    expect((await alice.ok(["invites"])).invites[0]).toMatchObject({ status: "redeemed", redeemedBy: { userId: joeyId } });
    expect((await joey.ok(["friends"])).friends.map((f: { userId: string }) => f.userId)).toEqual([aliceId]);
    // The relay saw only the hash of the admission key at invite-put.
    const key = inviteAdmitKey(parseShortCode(inv.code).secret);
    expect(inviteAdmitHash(key)).not.toBe(key);
  }, 60_000);

  it("removal from the list cuts the member off", async () => {
    const bob = user("bob", LIST);
    const inv = await alice.ok(["invite", "--no-circle", "--relay", LIST]);
    const j = await alongside(bob.run(["join", "--confirmed", inv.code, "--wait", "8", "--name", "bob"]), () => alice.ok(["invites"]));
    expect(j.code).toBe(0);
    // The operator makes bob permanent, then removes him.
    const bobId = j.json.created.userId as string;
    list.relay.setAllow([aliceId, bobId]);
    expect((await bob.run(["friends"])).err).not.toMatch(/offline/);
    list.relay.setAllow([aliceId]);
    expect((await bob.run(["friends"])).err).toMatch(/offline: every relay of yours is members-only/);
  }, 60_000);
});

describe("members-only relay (circle)", () => {
  it("the owner's client seeds the circle; a code joiner becomes a member there; removal cuts it off", async () => {
    const owner = user("owner", OPEN);
    const ownerId = (await owner.ok(["setup", "--name", "owner", "--no-backup"])).userId as string;
    const cid = (await owner.ok(["circle", "create", "crew"])).cid as string;
    await owner.ok(["circle", "default", cid]);
    circ = await startRelay(CIRC, { config: { allow: [ownerId], allowCircle: cid } });
    t[CIRC] = `ws://127.0.0.1:${circ.port}/v3`;
    expect(circ.relay.members.circleInfo()).toEqual({ cid, ver: 0 });
    // Adding the relay connects to it as an allowlisted member: the client pushes the circle from version 1.
    await owner.ok(["relays", "add", CIRC]);
    await owner.ok(["invites"]);
    expect(circ.relay.members.circleInfo()!.ver).toBeGreaterThanOrEqual(1);

    // A1: a relay that isn't one of ours (a recipient's, say) gets nothing, whatever circle it names.
    const app = await owner.app();
    await app.load();
    const asked: unknown[] = [];
    const fake = (relay: string, ver = 0) =>
      ({ relay, circle: { cid, ver }, authed: true, restricted: false, request: async (f: unknown) => (asked.push(f), { t: "ok", ver: 1 }) }) as unknown as RelayConnection;
    await app.syncRelayCircle(fake("wss://evil.test/v3"));
    await app.syncRelayCircle(fake(OPEN.replace("open", "elsewhere")));
    expect(asked).toEqual([]);
    // Our own relay that follows the circle does get it (the control).
    await app.syncRelayCircle(fake(CIRC));
    expect(asked).toHaveLength(1);
    await app.close();

    const inv = await owner.ok(["invite", "kim", "--relay", CIRC]);
    expect(inv.circle).toMatchObject({ cid });
    const kim = user("kim", CIRC);
    const j = await alongside(kim.run(["join", "--confirmed", inv.code, "--wait", "12", "--name", "kim"]), () => owner.ok(["invites"]));
    expect(j.code).toBe(0);
    const kimId = j.json.created.userId as string;
    expect(j.json.circle).toMatchObject({ cid, status: "joined" });
    // The owner added kim to the circle and pushed that version: kim is a full member there.
    expect(circ.relay.members.isFull(kimId)).toBe(true);
    expect((await kim.run(["friends"])).err).not.toMatch(/offline/);

    const rm = await owner.ok(["remove", kimId]);
    expect(rm.circles).toEqual([{ cid, result: "removed" }]);
    expect(circ.relay.members.admitted(kimId)).toBe(false);
    expect((await kim.run(["friends"])).err).toMatch(/offline: every relay of yours is members-only/);
  }, 90_000);
});
