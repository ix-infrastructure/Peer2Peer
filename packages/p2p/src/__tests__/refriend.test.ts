// Copyright 2026 Ix Infrastructure Inc.
//
// Re-friending after an unfriend, over one in-process relay. An unfriend ends
// every friendship of the pair whose invite was issued at or before it (core
// unfriendApplies, whole seconds). A re-invite in the unfriend's own second,
// or with the unfriender's clock ahead, used to be refused after the code or
// link was spent. Clocks are moved with a Date.now offset (the relay runs in
// this process, so it moves too, exactly like a skewed peer).

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { decodeTyped, inviteLink, TYP3 } from "@peer2peer/core/v3";
import { mintInvite } from "../social.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-refriend.test/v3";
let relay: TestRelay;
let t: Record<string, string>;
const users: User[] = [];
const ids: Record<string, string> = {};
const realNow = Date.now.bind(Date);

/** Runs `fn` with this process's clock moved by `offsetMs` (a peer whose clock is off). */
async function withClock<T>(offsetMs: number, fn: () => Promise<T>): Promise<T> {
  const spy = vi.spyOn(Date, "now").mockImplementation(() => realNow() + offsetMs);
  try {
    return await fn();
  } finally {
    spy.mockRestore();
  }
}

async function pair(a: string, b: string): Promise<[User, User]> {
  const out: User[] = [];
  for (const n of [a, b]) {
    const u = new User(n, t);
    users.push(u);
    ids[n] = (await u.ok(["init", "--name", n, "--relay", R, "--yes"])).userId;
    out.push(u);
  }
  return out as [User, User];
}

async function befriend(a: User, b: User): Promise<void> {
  const inv = await a.ok(["invite", "--link"]);
  await b.ok(["accept", inv.link]);
  await a.ok(["friends"]);
}

const friendIds = async (u: User): Promise<string[]> => (await u.ok(["friends"])).friends.map((f: { userId: string }) => f.userId);

async function unfriendIat(u: User, peer: string): Promise<number> {
  const app = await u.app();
  await app.load();
  const list = (await app.store.listUnfriends()).filter((x) => x.iss === app.userId && x.peer === peer);
  return Math.max(...list.map((x) => x.iat));
}

const inviteIat = (link: string): number => {
  const jws = Buffer.from(link.slice("p2p://invite/".length), "base64url").toString("utf8");
  return decodeTyped(jws, TYP3.invite).payload.iat as number;
};

beforeAll(async () => {
  relay = await startRelay(R);
  t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
});

afterEach(() => vi.restoreAllMocks());

afterAll(async () => {
  await relay?.close();
  for (const u of users) u.cleanup();
});

describe("re-friending after an unfriend", () => {
  it("in the same second as the unfriend: the new invite is dated after it, and works", async () => {
    const [p, q] = await pair("sp", "sq");
    await befriend(p, q);
    await q.ok(["unfriend", ids.sp]);
    const u = await unfriendIat(q, ids.sp);
    // p's clock starts exactly at the unfriend's second: without the fix its invite carries that
    // same second and the new friendship is ended by the unfriend it follows.
    const link = await withClock(u * 1000 - realNow(), async () => (await p.ok(["invite", "--link"])).link as string);
    expect(inviteIat(link)).toBeGreaterThan(u);
    await q.ok(["accept", link]);
    expect(await friendIds(p)).toContain(ids.sq);
    expect(await friendIds(q)).toContain(ids.sp);
  }, 30_000);

  it("the unfriender's clock 120 s ahead, and the inviter holds the unfriend: works", async () => {
    const [p, q] = await pair("kp", "kq");
    await befriend(p, q);
    const AHEAD = 120_000;
    await withClock(AHEAD, () => q.ok(["unfriend", ids.kp]));
    const u = await unfriendIat(q, ids.kp);
    expect(u).toBeGreaterThan(Math.floor(realNow() / 1000) + 100);
    // p (correct clock) drains the unfriend before dating the invite.
    const link = (await p.ok(["invite", "--link"])).link as string;
    expect(inviteIat(link)).toBe(u + 1);
    await withClock(AHEAD, () => q.ok(["accept", link]));
    expect(await friendIds(p)).toContain(ids.kq);
    expect(await withClock(AHEAD, () => friendIds(q))).toContain(ids.kp);
  }, 30_000);

  it("skew the inviter can't know about: the accepter refuses clearly before accepting anything, and a later invite works", async () => {
    const [p, q] = await pair("up", "uq");
    await befriend(p, q);
    const AHEAD = 120_000;
    await withClock(AHEAD, () => q.ok(["unfriend", ids.up]));
    // p mints without having received the unfriend (it is still queued at the relay).
    const a = await p.app();
    await a.load();
    const m = await mintInvite(a, { aud: "*", uses: 1, ttlSec: 3600 });
    await a.close();
    const r = await withClock(AHEAD, () => q.run(["accept", inviteLink(m.jws)]));
    expect(r.code).toBe(1);
    expect(r.json).toMatchObject({ error: "invite_predates_unfriend", inviter: ids.up });
    expect(r.json.reason).toMatch(/s before the unfriend between you.*Nothing was accepted: ask .* for a new invite/);
    // Nothing was recorded or sent.
    expect(await withClock(AHEAD, () => friendIds(q))).not.toContain(ids.up);
    expect(await friendIds(p)).not.toContain(ids.uq);
    // Once p holds the unfriend, its next invite is dated after it.
    const link = (await p.ok(["invite", "--link"])).link as string;
    await withClock(AHEAD, () => q.ok(["accept", link]));
    expect(await friendIds(p)).toContain(ids.uq);
  }, 30_000);

  it("an invite issued before the unfriend still never re-friends (the rule's purpose)", async () => {
    const [p, q] = await pair("op", "oq");
    await befriend(p, q);
    const stale = (await p.ok(["invite", "--link"])).link as string;
    await q.ok(["unfriend", ids.op]);
    const r = await q.run(["accept", stale]);
    expect(r.code).toBe(1);
    expect(r.json.error).toBe("invite_predates_unfriend");
    expect(await friendIds(q)).not.toContain(ids.op);
    expect(await friendIds(p)).not.toContain(ids.oq);
  }, 30_000);

  it("issue #3: an unfriend that arrives after the re-friend leaves the new friendship's caps alone", async () => {
    const [p, q] = await pair("lp", "lq");
    await befriend(p, q);
    await q.ok(["unfriend", ids.lp]);
    await befriend(p, q);
    const canMessage = async (u: User, other: string) => ((await u.ok(["friends"])).friends as { userId: string; canMessage: boolean }[]).find((f) => f.userId === other)?.canMessage;
    expect(await canMessage(p, ids.lq)).toBe(true);
    const issuedTo = async (u: User, other: string) => {
      const a = await u.app();
      await a.load();
      return (await a.store.listCapsIssued()).filter((c) => c.sub === other).length;
    };
    const issued = await issuedTo(p, ids.lq);
    expect(issued).toBeGreaterThan(0);
    // A late copy of the old unfriend (another device's, one a relay held back): it ends the old
    // friendship only, which is over already.
    const a = await q.app();
    await a.load();
    const old = (await a.store.listUnfriends()).find((u) => u.iss === ids.lq && u.peer === ids.lp);
    try {
      await a.deliver(ids.lp, "contact", { own: ids.lq, sid: "~contact" }, { text: old!.jws });
    } finally {
      await a.close();
    }
    await p.ok(["friends"]);
    expect(await friendIds(p)).toContain(ids.lq);
    // Without the fix, p dropped the caps q gave it and revoked the ones it gave q.
    expect(await canMessage(p, ids.lq)).toBe(true);
    expect(await issuedTo(p, ids.lq)).toBe(issued);
    await q.ok(["session", "roster", "s-q", "--add", ids.lp]);
    await q.ok(["status", "--session", "s-q", "--state", "idle", "--label", "q"]);
    await p.ok(["session", "roster", "s-p", "--add", ids.lq]);
    await p.ok(["ls"]);
    const sent = await p.ok(["send", "--from-session", "s-p", "--to", `${ids.lq}/s-q`, "--stdin"], { stdin: "still friends" });
    expect(sent).toMatchObject({ delivered: true });
  }, 60_000);
});
