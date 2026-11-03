// Copyright 2026 Ix Infrastructure Inc.
//
// Every device of a member gets a `want`. Review M3: the first in line (the
// lowest key holder) answers, so an answer isn't sent and charged once per
// device. Re-review N6: that election mustn't stall for good, so the next
// device in line answers after a delay if nobody did, and an answer by one
// device (synced) keeps the others quiet.

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { createCap, loadCircle } from "@peer2peer/core/v3";
import { App, joinCapOf } from "../app.js";
import { answerDeferredWants, answeringDevice, answeringRank, DEFERRED_WANT_MAX_AGE_MS, importWantAnswered, MAX_DEFERRED_PER_ASKER, parseCircleLink } from "../circle-ops.js";
import { linkJoin, linkStart } from "../identity.js";
import { receiving } from "../inbound.js";
import { sleep, startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-circle-devices.test/v3";
let relay: TestRelay;
let t: Record<string, string>;
const users: User[] = [];

beforeAll(async () => {
  // Every test user (and every retry) comes from 127.0.0.1: per-IP relay limits would bite first.
  relay = await startRelay(R, { limits: { httpPerIpPerMinute: 100_000, connectsPerIpPerMinute: 100_000, authsPerIpPerMinute: 100_000, authsPerIpv4PerMinute: 100_000, identityPublishPerIpPerHour: 100_000, newDevicesPerIpPerDay: 100_000, newDevicesPerIpv4PerDay: 100_000 } });
  t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
});

afterEach(() => vi.restoreAllMocks());

afterAll(async () => {
  await relay?.close();
  for (const u of users) u.cleanup();
});

const mk = (name: string, env: Record<string, string> = {}) => {
  const u = new User(name, t, env);
  users.push(u);
  return u;
};

/** An owner with a key holder (o1) and a linked non-key-holder (o2), both holding an open circle. */
async function twoDevices(tag: string, env2: Record<string, string> = {}) {
  const o1 = mk(`${tag}1`);
  const owner = (await o1.ok(["init", "--name", `${tag}1`, "--relay", R, "--yes"])).userId as string;
  const o2 = mk(`${tag}2`, env2);
  const a = await o1.app();
  await a.load();
  receiving(a);
  const st = await linkStart(a, { keyholder: false });
  const b = await o2.app();
  const j = await linkJoin(b, st.code);
  const [, joined] = await Promise.all([st.wait(async (req) => req.compareCode === j.compareCode), j.wait()]);
  const did1 = a.did!;
  await a.close();
  await b.close();
  const cid = (await o1.ok(["circle", "create", "two", "--open"])).cid as string;
  const link = (await o1.ok(["circle", "invite", cid, "--link"])).link as string;
  await o2.ok(["circle", "ls"]);
  const d2 = await o2.app();
  await d2.load();
  expect(await loadCircle(d2.store, cid)).toBeDefined();
  await d2.close();
  return { o1, o2, owner, cid, link, did1, did2: joined.did as string };
}

/** A stranger's want to the owner (both devices get it). */
async function ask(tag: string, owner: string, cid: string, link: string, times = 1, before?: (id: string) => Promise<unknown>): Promise<string> {
  const s = mk(tag);
  const sid = (await s.ok(["init", "--name", tag, "--relay", R, "--yes"])).userId as string;
  if (before) await before(sid);
  const sa = await s.app();
  await sa.load();
  const { hint } = parseCircleLink(link);
  await sa.refreshIdentity(owner, App.relaysOf(hint!.doc!), { force: true });
  const cap = createCap(sa.device!, sa.keys!.cert, { purpose: "answer", sub: owner, relays: sa.relays, ttlSec: 3600 });
  for (let i = 0; i < times; i++) {
    const d = await sa.deliver(owner, "circle", { own: sa.userId, sid: "~circle" }, { want: { cid, fromVer: 1 }, cap }, { extraCaps: [joinCapOf(hint!.join!)!] });
    expect(d.devices).toBe(2);
  }
  const id = sa.userId;
  await sa.close();
  return id;
}

/** Circle deliveries each device makes to `to`. */
function watchAnswers(to: () => string) {
  const byDid: Record<string, number> = {};
  const deliver = App.prototype.deliver;
  vi.spyOn(App.prototype, "deliver").mockImplementation(function (this: App, ...args: Parameters<App["deliver"]>) {
    if (args[1] === "circle" && args[0] === to()) byDid[this.did!] = (byDid[this.did!] ?? 0) + 1;
    return deliver.apply(this, args);
  });
  return byDid;
}

describe("one device answers a want (M3, N6)", () => {
  it("the order: key holders first, then the other devices, lowest first", () => {
    expect(answeringDevice({ devices: ["d_c", "d_a", "d_b"], keyholders: ["d_c", "d_b"] })).toBe("d_b");
    expect(answeringDevice({ devices: ["d_c", "d_a"], keyholders: [] })).toBe("d_a");
    expect(answeringDevice({ devices: ["d_c", "d_d"], keyholders: ["d_a", "d_d"] })).toBe("d_d");
    const v = { devices: ["d_c", "d_a", "d_b", "d_e"], keyholders: ["d_c", "d_b"] };
    expect(["d_b", "d_c", "d_a", "d_e", "d_x"].map((d) => answeringRank(v, d))).toEqual([0, 1, 2, 3, undefined]);
  });

  it("the key holder answers at once; the other device waits, sees the synced answer, and stays quiet", async () => {
    const { o1, o2, owner, cid, link, did2 } = await twoDevices("dq", { P2P_WANT_FALLBACK_SEC: "1" });
    let stranger = "";
    const byDid = watchAnswers(() => stranger);
    stranger = await ask("dqs", owner, cid, link);
    await o1.ok(["circle", "ls"]);
    await o2.ok(["circle", "ls"]);
    await sleep(1200);
    await o2.ok(["circle", "ls"]);
    expect(Object.keys(byDid).length).toBe(1);
    expect(byDid[did2]).toBeUndefined();
    const x = await o2.app();
    await x.load();
    expect(await x.state.get("deferredWants")).toEqual([]);
    expect((await x.state.get("wantAnswers"))?.last[`${stranger}|${cid}`]).toBeDefined();
    await x.close();
  }, 90_000);

  it("N6: the key holder never answers (offline): the next device answers after its delay", async () => {
    const { o2, owner, cid, link, did2 } = await twoDevices("dn", { P2P_WANT_FALLBACK_SEC: "1" });
    let stranger = "";
    const byDid = watchAnswers(() => stranger);
    stranger = await ask("dns", owner, cid, link);
    // Only the second device runs.
    await o2.ok(["circle", "ls"]);
    expect(byDid[did2]).toBeUndefined();
    await sleep(1200);
    await o2.ok(["circle", "ls"]);
    expect(byDid[did2]).toBeGreaterThan(0);
  }, 90_000);

  it("F2: an answer that reached no relay doesn't count; the next device answers", async () => {
    const { o1, o2, owner, cid, link, did1, did2 } = await twoDevices("dz", { P2P_WANT_FALLBACK_SEC: "1" });
    let stranger = "";
    const counted: Record<string, number> = {};
    const deliver = App.prototype.deliver;
    vi.spyOn(App.prototype, "deliver").mockImplementation(async function (this: App, ...args: Parameters<App["deliver"]>) {
      if (args[1] === "circle" && args[0] === stranger && this.did === did1) return { userId: args[0], devices: 1, relays: [] };
      const r = await deliver.apply(this, args);
      if (args[1] === "circle" && args[0] === stranger) counted[this.did!] = (counted[this.did!] ?? 0) + 1;
      return r;
    });
    stranger = await ask("dzs", owner, cid, link);
    await o1.ok(["circle", "ls"]);
    await o2.ok(["circle", "ls"]);
    await sleep(1200);
    await o2.ok(["circle", "ls"]);
    expect(counted[did2]).toBeGreaterThan(0);
  }, 90_000);

  it("F2: what the first device refused, the others don't answer; pools and proofs are merged", async () => {
    const { o2, cid } = await twoDevices("dr", { P2P_WANT_FALLBACK_SEC: "1" });
    const x = await o2.app();
    await x.load();
    const now = Date.now();
    await importWantAnswered(x, [
      { asker: "p2p:refusedasker", cid, at: now, refused: true },
      { asker: "p2p:a1", cid, at: now, ver: 3, bytes: 500, pool: "reserve", pow: "f".repeat(64) },
      { asker: "p2p:a2", cid, at: now, ver: 3, bytes: 300, pool: "member" },
      { asker: "p2p:a3", cid, at: now, ver: 3, bytes: 200, pool: "open" },
      { asker: "p2p:bad", cid, at: "x" },
    ]);
    const doc = (await x.state.get("wantAnswers"))!;
    expect(doc.refused?.[`p2p:refusedasker|${cid}`]).toBe(now);
    expect(doc.sent.map((e) => [e.pool, e.bytes])).toEqual([
      ["reserve", 500],
      ["open", 200],
    ]);
    expect(doc.members?.[cid]).toEqual([{ at: now, bytes: 300 }]);
    expect(doc.pows?.map((p) => p.id)).toEqual(["f".repeat(64)]);
    expect(doc.by["p2p:bad"]).toBeUndefined();
    // Deferred wants: one refused by the first device, one too old, one due: only the last is tried.
    const w = (from: string, at: number) => ({ from, fdid: "d_x", want: { cid, fromVer: 1 }, relay: R, at, due: at });
    await x.state.put("deferredWants", [w("p2p:refusedasker", now), w("p2p:old", now - DEFERRED_WANT_MAX_AGE_MS - 1000), w("p2p:fresh", now - 2000)]);
    expect(await answerDeferredWants(x)).toBe(1);
    expect(await x.state.get("deferredWants")).toEqual([]);
    await x.close();
  }, 90_000);

  it("F3: a later device queues only wants that pass the cheap checks, at most 4 per asker", async () => {
    const { o2, owner, cid, link } = await twoDevices("dc", { P2P_WANT_FALLBACK_SEC: "600" });
    await ask("dcs", owner, cid, link, 6);
    await o2.ok(["circle", "ls"]);
    const x = await o2.app();
    await x.load();
    expect((await x.state.get("deferredWants"))?.length).toBe(MAX_DEFERRED_PER_ASKER);
    await x.close();
    // A blocked asker's wants aren't queued at all.
    const blocked = await ask("dcb", owner, cid, link, 1, (id) => o2.ok(["block", id]));
    await o2.ok(["circle", "ls"]);
    const y = await o2.app();
    await y.load();
    expect((await y.state.get("deferredWants"))?.filter((d) => d.from === blocked)).toEqual([]);
    await y.close();
  }, 90_000);
});

