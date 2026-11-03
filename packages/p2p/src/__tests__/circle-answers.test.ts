// Copyright 2026 Ix Infrastructure Inc.
//
// Chunked answers to a stranger's `want` (§3.3, draft 3 amendment), end to end
// over an in-process relay: a 45-version open circle, an answer in many parts,
// and one part lost on the way. The join must wait for the whole answer (never
// count its first part, never call a gap a conflict, never drop the pending
// join), then resume from what is missing.

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { applyCircleBundle, CircleChain, createNextCircleVersion, freshnessLookup, generateIdentityKey, loadCircle } from "@peer2peer/core/v3";
import { App } from "../app.js";
import { ANSWER_ATTEMPT_MIN_BYTES, encodeCircleLink, JOIN_REASK_MS, parseCircleLink } from "../circle-ops.js";
import { readAnswer } from "../join-answers.js";
import { alongside, startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-circle-answers.test/v3";
let relay: TestRelay;
let t: Record<string, string>;
const users: User[] = [];
const ids: Record<string, string> = {};
let owner: User;
let cid = "";
let link = "";
const VERSIONS = 45;

async function user(name: string, env: Record<string, string> = {}): Promise<User> {
  const u = new User(name, t, env);
  users.push(u);
  ids[name] = (await u.ok(["init", "--name", name, "--relay", R, "--yes"])).userId;
  return u;
}

async function ownerApp(): Promise<App> {
  const a = await owner.app();
  await a.load();
  return a;
}

const pendingOf = async (u: User) => {
  const a = await u.app();
  await a.load();
  const p = (await a.state.get("joins"))?.[cid];
  await a.close();
  return p;
};

/** As if the re-ask interval had passed for `u`'s pending join of `c` (without moving any clock). */
async function ageAsk(u: User, c: string): Promise<void> {
  const j = await u.app();
  await j.load();
  await j.state.update("joins", (cur = {}) => {
    const p = cur[c];
    if (!p) return { result: undefined };
    const back = JOIN_REASK_MS + 1000;
    return { next: { ...cur, [c]: { ...p, askedAt: p.askedAt - back, askedAtBy: Object.fromEntries(Object.entries(p.askedAtBy ?? {}).map(([k, x]) => [k, x - back])) } }, result: undefined };
  });
  await j.close();
}

/** What the joiner holds of the owner's answer, and what the owner recorded: for failure messages. */
async function explain(joiner: User, c: string): Promise<string> {
  const a = await joiner.app();
  await a.load();
  const d = await readAnswer(a, c, ids.aown);
  const p = (await a.state.get("joins"))?.[c];
  const jid = a.userId;
  await a.close();
  const o = await owner.app();
  await o.load();
  const w = await o.state.get("wantAnswers");
  await o.close();
  const vers = (d?.versions ?? []).map((v) => JSON.parse(Buffer.from(v.split(".")[1], "base64url").toString()).ver as number).sort((x, y) => x - y);
  return JSON.stringify({
    vers: vers.join(","),
    parts: d?.parts,
    askedAtBy: p?.askedAtBy,
    owner: { by: w?.by?.[jid], bytes: w?.bytes?.[jid], last: w?.last?.[`${jid}|${c}`], refused: w?.refused?.[`${jid}|${c}`] },
    ownerWatchErr: owner.watchErr.slice(-12),
  });
}

/**
 * Joins (asking again for what is missing, as a joiner would) until joined, at most `rounds`
 * times, while the owner runs as a client does (`serve`, a `watch`): it handles a want for as
 * long as its slow, many-part answer takes, where a short command would cut it short on its way
 * out (its handlers get a bounded grace).
 */
async function joinUntil(u: User, l: string, rounds = 3): Promise<Awaited<ReturnType<User["run"]>>> {
  let r = await u.run(["circle", "join", l, "--wait", "20", "--yes"]);
  for (let i = 1; i < rounds && r.code === 0 && r.json?.status === "waiting"; i++) {
    await ageAsk(u, r.json.cid as string);
    r = await u.run(["circle", "join", l, "--wait", "20", "--yes"]);
  }
  return r;
}

/** Waits until `ok()` (polling every 300 ms, at most `ms`). */
async function until(ok: () => boolean | Promise<boolean>, ms: number): Promise<void> {
  for (const end = Date.now() + ms; Date.now() < end && !(await ok()); ) await new Promise((r) => setTimeout(r, 300));
}

beforeAll(async () => {
  // Every test user (and every retry) comes from 127.0.0.1: per-IP relay limits would bite first.
  relay = await startRelay(R, { limits: { httpPerIpPerMinute: 100_000, connectsPerIpPerMinute: 100_000, authsPerIpPerMinute: 100_000, authsPerIpv4PerMinute: 100_000, identityPublishPerIpPerHour: 100_000, newDevicesPerIpPerDay: 100_000, newDevicesPerIpv4PerDay: 100_000 } });
  t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
  // The owner answers from short commands here, where one envelope gets 8 s before the command
  // goes on without it (and, on its way out, cuts a long answer short). A member normally answers
  // from its running `watch`; give these commands that patience on a loaded machine.
  owner = await user("aown", { P2P_ENVELOPE_TIMEOUT_MS: "60000" });
  cid = (await owner.ok(["circle", "create", "long", "--open"])).cid;
  const a = await ownerApp();
  const ik = a.requireKeyholder("test");
  const opts = { ...a.signerCtx(), self: a.userId, identityFreshness: await freshnessLookup(a.store) };
  for (let i = 2; i <= VERSIONS; i++) {
    const head = (await loadCircle(a.store, cid))!.chain.head;
    const add = Array.from({ length: i === 2 ? 40 : 1 }, () => generateIdentityKey().userId);
    const v = createNextCircleVersion(ik, head, { members: [...head.members, ...add] });
    expect((await applyCircleBundle(a.store, { circles: [v], joins: [], ops: [] }, opts)).versions[cid]?.[0]?.status).toBe("accepted");
  }
  await a.close();
  link = (await owner.ok(["circle", "invite", cid, "--link"])).link;
}, 120_000);

afterEach(() => vi.restoreAllMocks());

afterAll(async () => {
  await relay?.close();
  for (const u of users) u.cleanup();
});

describe("a chunked answer is whole before it counts", () => {
  it(`a ${VERSIONS}-version chain in many parts: joined end to end`, async () => {
    const s = await user("ajoin");
    const sent: number[] = [];
    let count = 0;
    const deliver = App.prototype.deliver;
    // The member's parts arrive slowly (a busy relay, a slow link): the joiner sees the first part,
    // a prefix of the chain, well before the rest. It must not count it as the answer.
    vi.spyOn(App.prototype, "deliver").mockImplementation(async function (this: App, ...args: Parameters<App["deliver"]>) {
      const pt = args[3] as { part?: { n: number }; circles?: string[] };
      if (args[1] === "circle" && args[0] === ids.ajoin && pt.circles) {
        if (pt.part) sent.push(pt.part.n);
        if (count++ > 0) await new Promise((r) => setTimeout(r, 400));
      }
      return deliver.apply(this, args);
    });
    const srv = owner.serve("answers");
    try {
      // The join's wait ends while parts are still on their way: it waits (no conflict, pending kept)...
      const r1 = await s.run(["circle", "join", link, "--wait", "2", "--yes"]);
      expect(r1.code, r1.err).toBe(0);
      expect(r1.json).toMatchObject({ cid, status: "waiting" });
      expect(await pendingOf(s)).toBeDefined();
      // ...and joins once the rest is in (asking again for anything missing, as a joiner would).
      await ageAsk(s, cid);
      const r = await joinUntil(s, link);
      expect(r.code, r.err).toBe(0);
      expect(r.json, await explain(s, cid)).toMatchObject({ cid, status: "joined" });
    } finally {
      await srv.stop();
    }
    // It really was several parts.
    expect(Math.max(...sent)).toBeGreaterThanOrEqual(4);
  }, 180_000);

  it("a part lost in the middle: the join waits (no conflict, pending kept), then resumes from the gap and joins", async () => {
    const s = await user("alost");
    const deliver = App.prototype.deliver;
    let dropped = 0;
    const spy = vi.spyOn(App.prototype, "deliver").mockImplementation(async function (this: App, ...args: Parameters<App["deliver"]>) {
      const pt = args[3] as { part?: { i: number; n: number } };
      if (args[1] === "circle" && args[0] === ids.alost && pt.part && pt.part.n >= 3 && pt.part.i === 2 && dropped === 0) {
        dropped++;
        return { userId: args[0], devices: 1, relays: [] };
      }
      return deliver.apply(this, args);
    });
    const srv = owner.serve("answers");
    try {
      const r1 = await s.run(["circle", "join", link, "--wait", "6", "--yes"]);
      expect(r1.code, r1.err).toBe(0);
      // Never a conflict, never joined without the lost part.
      expect(r1.json, await explain(s, cid)).toMatchObject({ cid, status: "waiting" });
      // The owner's answer (with part 2 lost) goes out, and the joiner takes in what came.
      await until(() => dropped === 1, 30_000);
      expect(dropped, await explain(s, cid)).toBe(1);
      const held = async () => {
        await s.run(["circle", "ls"]);
        const a = await s.app();
        await a.load();
        const d = await readAnswer(a, cid, ids.aown);
        await a.close();
        return d;
      };
      await until(async () => Object.values((await held())?.parts ?? {}).some((r) => r.got.length >= r.n - 1), 30_000);
      const p = await pendingOf(s);
      expect(p).toBeDefined();
      // Some versions arrived, not all.
      const got = await held();
      expect(got!.versions.length, await explain(s, cid)).toBeGreaterThan(0);
      expect(got!.versions.length, await explain(s, cid)).toBeLessThan(VERSIONS);
      spy.mockRestore();
      // Later (past the re-ask interval) the join asks again for what is missing, and joins.
      await ageAsk(s, cid);
      const r2 = await joinUntil(s, link);
      expect(r2.code, r2.err).toBe(0);
      expect(r2.json, await explain(s, cid)).toMatchObject({ cid, status: "joined" });
    } finally {
      await srv.stop();
    }
  }, 180_000);
});

describe("an answer bigger than one hour's budget (review M2)", () => {
  it("is sent in whole-version slices over several hours, and the join completes", async () => {
    // An owner whose per-asker budget is far smaller than the chain.
    const small = new User("bown", t, { P2P_ANSWER_BYTES_PER_ASKER_PER_HOUR: "120000" });
    users.push(small);
    ids.bown = (await small.ok(["init", "--name", "bown", "--relay", R, "--yes"])).userId;
    const c2 = (await small.ok(["circle", "create", "slow", "--open"])).cid as string;
    const a = await small.app();
    await a.load();
    const ik = a.requireKeyholder("test");
    const opts = { ...a.signerCtx(), self: a.userId, identityFreshness: await freshnessLookup(a.store) };
    for (let i = 2; i <= 30; i++) {
      const head = (await loadCircle(a.store, c2))!.chain.head;
      const v = createNextCircleVersion(ik, head, { members: [...head.members, ...Array.from({ length: i === 2 ? 40 : 1 }, () => generateIdentityKey().userId)] });
      await applyCircleBundle(a.store, { circles: [v], joins: [], ops: [] }, opts);
    }
    await a.close();
    const l2 = (await small.ok(["circle", "invite", c2, "--link"])).link as string;
    const s = await user("bjoin");
    // An hour passing, without moving the clock (the relay's clock would then refuse the joiner's
    // fresh caps): the owner's budget entries and the joiner's last ask age by an hour.
    const anHourLater = async () => {
      const o = await small.app();
      await o.load();
      await o.state.update("wantAnswers", (cur) => {
        if (!cur) return { result: undefined };
        const back = <T extends { at: number }>(x: T) => ({ ...x, at: x.at - 3_700_000 });
        return {
          next: {
            by: Object.fromEntries(Object.entries(cur.by).map(([k, ts]) => [k, ts.map((x) => x - 3_700_000)])),
            bytes: Object.fromEntries(Object.entries(cur.bytes).map(([k, xs]) => [k, xs.map(back)])),
            sent: cur.sent.map(back),
            last: Object.fromEntries(Object.entries(cur.last).map(([k, x]) => [k, back(x)])),
          },
          result: undefined,
        };
      });
      await o.close();
      const j = await s.app();
      await j.load();
      await j.state.update("joins", (cur = {}) => {
        const p = cur[c2];
        if (!p) return { result: undefined };
        return { next: { ...cur, [c2]: { ...p, askedAt: p.askedAt - 3_700_000, askedAtBy: Object.fromEntries(Object.entries(p.askedAtBy ?? {}).map(([k, x]) => [k, x - 3_700_000])) } }, result: undefined };
      });
      await j.close();
    };
    let status = "";
    let hours = 0;
    for (; hours < 8 && status !== "joined"; hours++) {
      if (hours > 0) await anHourLater();
      const r = await alongside(s.run(["circle", "join", l2, "--wait", "6", "--yes"]), () => small.run(["invites"]));
      expect(r.code, r.err).toBe(0);
      status = r.json.status;
    }
    expect(status).toBe("joined");
    // It took more than one hour's budget.
    expect(hours).toBeGreaterThan(1);
  }, 240_000);
});

describe("an offered head that isn't on the chain (re-review N4)", () => {
  it("is a conflict once every version up to its ver has arrived, not an endless wait", async () => {
    const o = new User("fown", t);
    users.push(o);
    ids.fown = (await o.ok(["init", "--name", "fown", "--relay", R, "--yes"])).userId;
    const c3 = (await o.ok(["circle", "create", "forky", "--open"])).cid as string;
    const a = await o.app();
    await a.load();
    const ik = a.requireKeyholder("test");
    const opts = { ...a.signerCtx(), self: a.userId, identityFreshness: await freshnessLookup(a.store) };
    for (let i = 0; i < 2; i++) {
      const head = (await loadCircle(a.store, c3))!.chain.head;
      await applyCircleBundle(a.store, { circles: [createNextCircleVersion(ik, head, { name: `v${i + 2}` })], joins: [], ops: [] }, opts);
    }
    // A sibling of the held head (same ver, never published): the link offers that.
    const chain = (await loadCircle(a.store, c3))!.chain;
    const v2 = chain.versionsFrom(1)[1];
    const fork = createNextCircleVersion(ik, CircleChain.bootstrap(chain.versionsFrom(1).slice(0, 2), { head: v2 }).head, { name: "fork" });
    await a.close();
    const { hint } = parseCircleLink((await o.ok(["circle", "invite", c3, "--link"])).link);
    const forkLink = encodeCircleLink(fork, hint);
    const s = await user("fjoin");
    const r = await alongside(s.run(["circle", "join", forkLink, "--wait", "10", "--yes"]), () => o.run(["invites"]));
    expect(r.code).toBe(1);
    expect(r.json).toMatchObject({ error: "join_conflict" });
    // Not left pending.
    const sa = await s.app();
    await sa.load();
    expect((await sa.state.get("joins"))?.[c3]).toBeUndefined();
    await sa.close();
  }, 90_000);
});

describe("an answer that arrives before the join has noted whom it asked (pre-release soak)", () => {
  it("still counts: the ask is recorded before the want goes out", async () => {
    const o = new User("rown", t);
    users.push(o);
    ids.rown = (await o.ok(["init", "--name", "rown", "--relay", R, "--yes"])).userId;
    const c4 = (await o.ok(["circle", "create", "quick", "--open"])).cid as string;
    const l4 = (await o.ok(["circle", "invite", c4, "--link"])).link as string;
    const s = await user("rjoin");
    // The owner answers at once, and another process of the joiner's (its watch) takes the answer,
    // all before the join command is back from sending its want.
    const deliver = App.prototype.deliver;
    let raced = false;
    vi.spyOn(App.prototype, "deliver").mockImplementation(async function (this: App, ...args: Parameters<App["deliver"]>) {
      const r = await deliver.apply(this, args);
      const pt = args[3] as { want?: unknown };
      if (!raced && this.userId === ids.rjoin && args[0] === ids.rown && args[1] === "circle" && pt.want) {
        raced = true;
        await o.run(["invites"]);
        await s.run(["circle", "ls"]);
      }
      return r;
    });
    const r = await alongside(s.run(["circle", "join", l4, "--wait", "5", "--yes"]), () => o.run(["invites"]));
    expect(raced).toBe(true);
    expect(r.code, r.err).toBe(0);
    expect(r.json).toMatchObject({ cid: c4, status: "joined" });
  }, 90_000);
});

describe("an answer that didn't go out (pre-release soak)", () => {
  it("is refunded: the asker's next want is answered, not refused as a resend", async () => {
    const o = new User("xown", t);
    users.push(o);
    ids.xown = (await o.ok(["init", "--name", "xown", "--relay", R, "--yes"])).userId;
    const c5 = (await o.ok(["circle", "create", "flaky", "--open"])).cid as string;
    const l5 = (await o.ok(["circle", "invite", c5, "--link"])).link as string;
    const s = await user("xjoin");
    // The owner's first two answers die on the way (its relay connections closing, a relay down).
    const deliver = App.prototype.deliver;
    let failed = 0;
    vi.spyOn(App.prototype, "deliver").mockImplementation(async function (this: App, ...args: Parameters<App["deliver"]>) {
      const pt = args[3] as { part?: unknown };
      if (this.userId === ids.xown && args[0] === ids.xjoin && args[1] === "circle" && pt.part && failed < 2) {
        failed++;
        throw new Error("this command closed its relay connections");
      }
      return deliver.apply(this, args);
    });
    let r = await alongside(s.run(["circle", "join", l5, "--wait", "4", "--yes"]), () => o.run(["invites"]));
    for (let i = 0; i < 3 && r.json?.status === "waiting"; i++) {
      await ageAsk(s, c5);
      r = await alongside(s.run(["circle", "join", l5, "--wait", "4", "--yes"]), () => o.run(["invites"]));
    }
    expect(failed).toBe(2);
    expect(r.code, r.err).toBe(0);
    expect(r.json).toMatchObject({ cid: c5, status: "joined" });
    // The failed attempts sent nothing: each stays charged only the minimum for an attempt (review
    // N-A), and the answer that went out in full is charged in full.
    const a = await o.app();
    await a.load();
    const w = (await a.state.get("wantAnswers"))!;
    await a.close();
    const charges = (w.bytes[ids.xjoin] ?? []).map((x) => x.bytes);
    expect(charges.length).toBe(3);
    expect(charges.slice(0, 2)).toEqual([ANSWER_ATTEMPT_MIN_BYTES, ANSWER_ATTEMPT_MIN_BYTES]);
    expect(charges[2]).toBeGreaterThan(ANSWER_ATTEMPT_MIN_BYTES);
  }, 120_000);
});
