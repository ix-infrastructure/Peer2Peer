// Copyright 2026 Ix Infrastructure Inc.
//
// The full social flow over two real in-process relays, with three users
// (alice, bob, carol) in separate temp homes, driven through the CLI:
//   1 init · 2 invite/accept · 3 two-way messaging · 4 status in ls ·
//   5 circle create + open-link join, members see each other ·
//   6 proposal applied by the owner · 7 leave · 9 device link + revoke ·
//   10 one relay killed, delivery continues · 8 unfriend + block stop
//   delivery · 11 backup restore.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { linkJoin, linkStart } from "../identity.js";
import { receiving } from "../inbound.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R1 = "wss://relay-one.test/v3";
const R2 = "wss://relay-two.test/v3";

let r1: TestRelay;
let r2: TestRelay;
let alice: User;
let bob: User;
let carol: User;
let alice2: User;
const ids: Record<string, string> = {};
let cid = "";
let circleLinkStr = "";

describe("p2p end to end", () => {
  beforeAll(async () => {
    r1 = await startRelay(R1);
    r2 = await startRelay(R2);
    const transport = { [R1]: `ws://127.0.0.1:${r1.port}/v3`, [R2]: `ws://127.0.0.1:${r2.port}/v3` };
    alice = new User("alice", transport);
    bob = new User("bob", transport);
    carol = new User("carol", transport);
    alice2 = new User("alice2", transport);
  });

  afterAll(async () => {
    await r1?.close().catch(() => {});
    await r2?.close().catch(() => {});
    for (const u of [alice, bob, carol, alice2]) u?.cleanup();
  });

  it("1. init: identity key, first device, document v1 on both relays", async () => {
    for (const u of [alice, bob, carol]) {
      const r = await u.ok(["init", "--name", u.name, "--relay", R1, "--relay", R2, "--yes"]);
      expect(r.published.sort()).toEqual([R1, R2]);
      expect(r.address).toMatch(new RegExp(`^${u.name}@[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}$`));
      ids[u.name] = r.userId;
    }
    const w = await alice.ok(["whoami"]);
    expect(w.userId).toBe(ids.alice);
    expect(w.devices).toHaveLength(1);
    expect(w.keyholder).toBe(true);
    expect(w.doc.ver).toBe(1);
    // Without relays configured, init explains how to set them.
    const none = new User("none", {});
    const r = await none.run(["init", "--yes"]);
    expect(r.code).toBe(1);
    expect(r.json.error).toBe("no_relays");
    none.cleanup();
  });

  it("2. invite and accept: friends both ways, caps exchanged", async () => {
    const inv = await alice.ok(["invite", "--link"]);
    expect(inv.link).toMatch(/^p2p:\/\/invite\//);
    expect(inv.web).toMatch(/^https:\/\/ix-infra\.com\/p2p\/i#/);
    const acc = await bob.ok(["accept", inv.link]);
    expect(acc.friend.userId).toBe(ids.alice);
    expect(acc.delivered.relays.length).toBeGreaterThan(0);
    // alice handles the accept and grants her cap back.
    const af = await alice.ok(["friends"]);
    expect(af.friends.map((f: any) => f.userId)).toEqual([ids.bob]);
    const bf = await bob.ok(["friends"]);
    expect(bf.friends[0].userId).toBe(ids.alice);
    expect(bf.friends[0].canMessage).toBe(true);
    // bob and carol become friends too (used for unfriend later).
    const inv2 = await carol.ok(["invite", "--link", "--uses", "2"]);
    await bob.ok(["accept", inv2.web]);
    await carol.ok(["friends"]);
    expect((await bob.ok(["friends"])).friends).toHaveLength(2);
    await alice.ok(["petname", ids.bob, "bobby"]);
    expect((await alice.ok(["friends"])).friends[0].address).toMatch(/^bobby@/);
  });

  it("3+4. status shows up in ls; two-way messaging", async () => {
    await bob.ok(["session", "roster", "bs1", "--add", ids.alice]);
    const st = await bob.ok(["status", "--session", "bs1", "--state", "busy", "--summary", "fixing auth <b>", "--file", "src/auth.ts", "--label", "api"]);
    expect(st.delivered.map((d: any) => d.userId)).toEqual([ids.alice]);
    const ls = await alice.ok(["ls"]);
    const row = ls.peers.find((p: any) => p.own === ids.bob);
    expect(row).toMatchObject({ sid: "bs1", state: "busy", label: "api", summary: "fixing auth b", files: ["src/auth.ts"], live: true });
    // alice → bob's live session (alice's project is shared with him: projects.ts).
    await alice.share(ids.bob);
    const sent = await alice.ok(["send", "--from-session", "as1", "--to", "bobby", "hello", "bob"]);
    expect(sent.delivered).toBe(true);
    expect(sent.relays).toBe(2);
    expect(sent.to.sid).toBe("bs1");
    const bl = await bob.watch("bs1", 1500);
    const msg = bl.find((e) => e.kind === "p2p.message");
    expect(msg).toMatchObject({ text: "hello bob", own: ids.bob, sid: "bs1", toSession: "bs1" });
    expect(msg.from.userId).toBe(ids.alice);
    // bob → alice: she has no live session, so into bob's session (alice is on its roster).
    const back = await bob.ok(["send", "--from-session", "bs1", "--to", ids.alice], { stdin: "hi alice\n" });
    expect(back.to.own).toBe(ids.bob);
    const al = await alice.watch("as1", 1500);
    expect(al.find((e) => e.kind === "p2p.message")).toMatchObject({ text: "hi alice", own: ids.bob, sid: "bs1" });
    // A new status reaches alice's (now running) stream; idle is shown by ts.
    await bob.ok(["status", "--session", "bs1", "--state", "idle", "--label", "api"]);
    const al2 = await alice.watch("as1", 1500);
    expect(al2.find((e) => e.kind === "p2p.status" && e.own === ids.bob)?.status.state).toBe("idle");
    // A peer the session isn't shared with is refused, with a hint.
    const ref = await carol.run(["send", "--from-session", "cs1", "--to", ids.alice, "yo"]);
    expect(ref.code).toBe(1);
  });

  it("5. circle: create open, join through the link (confirm first), members see each other", async () => {
    const c = await alice.ok(["circle", "create", "team", "--open"]);
    cid = c.cid;
    expect(c.policy).toBe("open");
    expect(c.link).toMatch(/^p2p:\/\/circle\/[A-Za-z0-9_-]+~[A-Za-z0-9_-]+$/);
    circleLinkStr = (await alice.ok(["circle", "invite", cid, "--link"])).link;
    // carol, a stranger to alice: asks the owner for the history first.
    const w = await carol.ok(["circle", "join", circleLinkStr, "--wait", "0"]);
    expect(w.status).toBe("waiting");
    await alice.ok(["circle", "ls"]); // alice is online: answers the request
    const j = await carol.ok(["circle", "join", circleLinkStr, "--wait", "3"]);
    expect(j).toMatchObject({ status: "joined", confirmation: "owner-only", cid });
    // alice's client admits carol automatically (open policy) and distributes the new version.
    const am = await alice.ok(["circle", "members", cid]);
    expect(am.members.map((m: any) => m.userId).sort()).toEqual([ids.alice, ids.carol].sort());
    // bob joins with a fresh link whose head lists carol: she is a second member to confirm
    // with, but bob can't reach her yet, so the join is unconfirmed without --yes.
    circleLinkStr = (await alice.ok(["circle", "invite", cid, "--link"])).link;
    await bob.ok(["circle", "join", circleLinkStr, "--wait", "0"]);
    await alice.ok(["circle", "ls"]);
    const unconf = await bob.run(["circle", "join", circleLinkStr, "--wait", "2"]);
    expect(unconf.json.status).toBe("unconfirmed");
    expect(unconf.code).toBe(1);
    expect((await bob.ok(["circle", "join", circleLinkStr, "--wait", "2", "--yes"])).status).toBe("joined");
    await alice.ok(["circle", "ls"]);
    // everyone sees everyone standing.
    for (const u of [alice, bob, carol]) {
      const m = await u.ok(["circle", "members", cid]);
      expect(m.members).toHaveLength(3);
      expect(m.members.every((x: any) => x.stands)).toBe(true);
    }
    // a circle-wide session: carol's status reaches both co-members.
    await carol.ok(["circle", "default", cid]);
    const st = await carol.ok(["status", "--session", "cs2", "--state", "busy", "--summary", "circle work"]);
    expect(st.roster.vis).toBe("circle");
    expect(st.delivered.map((d: any) => d.userId).sort()).toEqual([ids.alice, ids.bob].sort());
    expect((await alice.ok(["ls"])).peers.some((p: any) => p.own === ids.carol && p.summary === "circle work")).toBe(true);
    expect((await bob.ok(["ls"])).peers.some((p: any) => p.own === ids.carol)).toBe(true);
  });

  it("6. proposal: an admin proposes, the owner's client applies it", async () => {
    const pr = await alice.ok(["circle", "propose", cid, "promote", ids.bob]);
    expect(pr.applied).toBe(true);
    await bob.ok(["circle", "ls"]);
    const p = await bob.ok(["circle", "propose", cid, "rename", "core-team"]);
    expect(p.applied).toBe(false);
    expect(p.sentTo).toBe(ids.alice);
    await alice.ok(["circle", "ls"]); // the owner applies and publishes
    const cl = (await carol.ok(["circle", "ls"])).circles.find((x: any) => x.cid === cid);
    expect(cl.name).toBe("core-team");
    expect((await bob.ok(["circle", "members", cid])).members.find((m: any) => m.userId === ids.bob).admin).toBe(true);
  });

  it("7. leave: members honour it, the owner drops the member", async () => {
    const l = await carol.ok(["circle", "leave", cid]);
    expect(l.told).toBe(2);
    await alice.ok(["circle", "ls"]);
    const bm = await bob.ok(["circle", "members", cid]);
    expect(bm.members.map((m: any) => m.userId).sort()).toEqual([ids.alice, ids.bob].sort());
    const cl = (await carol.ok(["circle", "ls"])).circles.find((x: any) => x.cid === cid);
    expect(cl.joined).toBe(false);
  });

  it("9. device link between two homes of one user, then revoke", async () => {
    const a = await alice.app();
    await a.load();
    receiving(a);
    const start = await linkStart(a, {});
    expect(start.code).toMatch(/^p2p-link:[a-z2-7]{26}@relay-one\.test\/v3$/);
    const b = await alice2.app();
    const join = await linkJoin(b, start.code, { label: "laptop" });
    let shown = "";
    const [linked, joined] = await Promise.all([
      start.wait(async (req) => {
        shown = req.compareCode;
        return req.compareCode === join.compareCode && req.label === "laptop";
      }),
      join.wait(),
    ]);
    await a.close();
    await b.close();
    expect(shown).toBe(join.compareCode);
    expect(joined.userId).toBe(ids.alice);
    expect(joined.keyholder).toBe(false);
    expect(linked.did).toBe(joined.did);
    const w = await alice.ok(["whoami"]);
    expect(w.devices).toHaveLength(2);
    // The new device got alice's friends by sync, and sees bob as a friend.
    expect((await alice2.ok(["friends"])).friends.map((f: any) => f.userId)).toContain(ids.bob);
    // alice posts a status from her first device; bob messages her session: both devices get it.
    await alice.ok(["session", "roster", "as1", "--add", "bobby"]);
    await alice.ok(["status", "--session", "as1", "--state", "busy", "--summary", "two devices"]);
    const sent = await bob.ok(["send", "--from-session", "bs1", "--to", ids.alice, "to both"]);
    expect(sent.devices).toBe(2);
    expect((await alice2.watch("as1", 1200)).find((e) => e.kind === "p2p.message")?.text).toBe("to both");
    expect((await alice.watch("as1", 1200)).find((e) => e.kind === "p2p.message")?.text).toBe("to both");
    // Revoke the second device: the next message goes to one device, and the relays refuse the revoked one.
    const rv = await alice.ok(["devices", "revoke", joined.did]);
    expect(rv.revoked).toBe(joined.did);
    const sent2 = await bob.ok(["send", "--from-session", "bs1", "--to", ids.alice, "only one"]);
    expect(sent2.devices).toBe(1);
    const gone = await alice2.run(["send", "--from-session", "x1", "--to", ids.bob, "hi"]);
    expect(gone.code).toBe(1);
    expect(gone.json.error).toBe("device_revoked");
  });

  it("10. two relays, one killed: delivery continues via the other", async () => {
    await r1.close();
    await bob.ok(["status", "--session", "bs1", "--state", "busy", "--label", "api"]);
    const s = await alice.ok(["send", "--from-session", "as1", "--to", "bobby", "still", "here"]);
    expect(s.delivered).toBe(true);
    expect(s.relays).toBe(1);
    const lines = await bob.watch("bs1", 1500);
    expect(lines.find((e) => e.kind === "p2p.message")?.text).toBe("still here");
    // Zero relays is an error, not a silent success.
    const lone = await carol.run(["send", "--from-session", "cs9", "--to", ids.bob, "x"]);
    expect(lone.code).toBe(1);
  });

  it("8. unfriend and block stop delivery", async () => {
    // carol shares a session with bob; bob can see and message it while they're friends.
    await carol.ok(["session", "roster", "cs3", "--add", ids.bob]);
    await carol.ok(["status", "--session", "cs3", "--state", "busy"]);
    await bob.share(ids.carol);
    const ok1 = await bob.ok(["send", "--from-session", "bs1", "--to", `${ids.carol}/cs3`, "before"]);
    expect(ok1.relays).toBe(1);
    const uf = await carol.ok(["unfriend", ids.bob]);
    expect(uf.revoked).toBeGreaterThan(0);
    const after = await bob.run(["send", "--from-session", "bs1", "--to", `${ids.carol}/cs3`, "after"]);
    expect(after.code).toBe(1);
    expect(after.json.error).toBe("undelivered");
    expect((await carol.watch("cs3", 1200)).filter((e) => e.kind === "p2p.message").map((e) => e.text)).toEqual(["before"]);
    // alice blocks bob (still a co-member: the relay may accept, alice's client rejects).
    const bl = await alice.ok(["block", "bobby"]);
    expect(bl.blocked).toBe(ids.bob);
    await alice.watch("as1", 600); // print what arrived before the block
    await bob.run(["send", "--from-session", "bs1", "--to", ids.alice, "blocked?"]);
    await bob.ok(["status", "--session", "bs1", "--state", "busy", "--summary", "after block"]);
    expect((await alice.watch("as1", 1200)).some((e) => e.from?.userId === ids.bob)).toBe(false);
    expect((await alice.ok(["ls", "--all"])).peers.some((p: any) => p.own === ids.bob)).toBe(false);
    await alice.ok(["unblock", "bobby"]);
  });

  it("11. backup restore: same identity on a fresh home, lost devices revoked", async () => {
    const phrase = (await alice.ok(["backup", "show"])).phrase as string;
    expect(phrase.split(" ")).toHaveLength(24);
    const restored = new User("alice3", { [R2]: `ws://127.0.0.1:${r2.port}/v3` });
    try {
      // Relay one was killed in step 10: the restore commits, but reports it (exit 2, restore_incomplete).
      const res = await restored.run(["backup", "restore", "--relay", R2], { stdin: phrase });
      expect(res.code).toBe(2);
      const r = res.json;
      expect(r.error).toBe("restore_incomplete");
      expect(r.failed.map((f: { relay: string }) => f.relay)).toEqual([R1]);
      expect(r.userId).toBe(ids.alice);
      expect(r.revoked).toHaveLength(1);
      const w = await restored.ok(["whoami"]);
      expect(w.userId).toBe(ids.alice);
      expect(w.keyholder).toBe(true);
      expect(w.devices).toHaveLength(1);
      expect(w.doc.ver).toBeGreaterThan(3);
      // The lost device is cut off.
      const old = await alice.run(["send", "--from-session", "as1", "--to", "bobby", "x"]);
      expect(old.json?.error, old.out + old.err).toBe("device_revoked");
      const bad = await new User("x", { [R2]: `ws://127.0.0.1:${r2.port}/v3` }).run(["backup", "restore", "--relay", R2], { stdin: "not a phrase" });
      expect(bad.json.error).toBe("bad_phrase");
    } finally {
      restored.cleanup();
    }
  });
});
