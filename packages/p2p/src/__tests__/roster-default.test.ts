// Copyright 2026 Ix Infrastructure Inc.
//
// A session nobody shared explicitly follows the default circle (§6). The
// live bug: a session started before its user joined the circle (or before
// the default was set, or the join approved) kept the private roster it was
// made with, so its statuses reached only its owner: the circle's members
// saw nothing, though friendship, caps and relays were all fine.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { docFromStored, isAutoRoster } from "../sessions.js";
import { CliError } from "../errors.js";
import type { SessionDoc } from "../state.js";
import { alongside, startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-roster.test/v3";
let relay: TestRelay;
let ann: User;
let ben: User;
let cid: string;
const ids: Record<string, string> = {};

describe("isAutoRoster", () => {
  const doc = (d: Partial<SessionDoc>): SessionDoc => ({ sid: "s", ver: 1, vis: "private", parts: [], jws: "x", ...d });
  it("a doc says so; one from before the field counts only as the untouched first version", () => {
    expect(isAutoRoster(doc({ auto: true, ver: 4 }))).toBe(true);
    expect(isAutoRoster(doc({ auto: false }))).toBe(false);
    expect(isAutoRoster(doc({}))).toBe(true);
    expect(isAutoRoster(doc({ vis: "circle", circle: "c_x" }))).toBe(true);
    expect(isAutoRoster(doc({ ver: 2 }))).toBe(false); // an explicit `session roster` change
    expect(isAutoRoster(doc({ parts: ["p2p:someone"] }))).toBe(false);
  });
});

describe("docFromStored (pre-release review lows)", () => {
  const jws = (p: Record<string, unknown>) => `e30.${Buffer.from(JSON.stringify(p)).toString("base64url")}.sig`;
  const mine = { sid: "s", ver: 3, vis: "circle", circle: "c_team", parts: [], did: "d_me" };
  it("adopts only a roster this device signed; anything else fails closed with a clear error", () => {
    expect(docFromStored("s", { ver: 3, jws: jws(mine) }, "d_me")).toMatchObject({ ver: 3, vis: "circle", circle: "c_team", auto: false });
    const other = () => docFromStored("s", { ver: 3, jws: jws({ ...mine, did: "d_other" }) }, "d_me");
    expect(other).toThrow(CliError);
    expect(other).toThrow(/signed by another device \(d_other\), not this one \(d_me\)/);
    for (const bad of [jws({ ...mine, ver: 4 }), jws({ ...mine, sid: "t" }), jws({ ...mine, vis: "open" }), jws({ ...mine, parts: "x" }), "not.a-jws", ""]) {
      expect(() => docFromStored("s", { ver: 3, jws: bad }, "d_me")).toThrow(/can't read; it is not adopted/);
    }
  });
  it("keeps auto: true only when it is exactly the default roster this device would sign", () => {
    expect(docFromStored("s", { ver: 3, jws: jws(mine) }, "d_me", { vis: "circle", circle: "c_team" }).auto).toBe(true);
    expect(docFromStored("s", { ver: 3, jws: jws({ ...mine, circle: undefined, vis: "private" }) }, "d_me", { vis: "private" }).auto).toBe(true);
    expect(docFromStored("s", { ver: 3, jws: jws(mine) }, "d_me", { vis: "circle", circle: "c_other" }).auto).toBe(false);
    expect(docFromStored("s", { ver: 3, jws: jws(mine) }, "d_me", { vis: "private" }).auto).toBe(false);
    expect(docFromStored("s", { ver: 3, jws: jws({ ...mine, parts: ["p2p:x"] }) }, "d_me", { vis: "circle", circle: "c_team" }).auto).toBe(false);
  });
});

describe("a default roster follows the default circle", () => {
  beforeAll(async () => {
    relay = await startRelay(R);
    const t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    ann = new User("ann", t);
    ben = new User("ben", t);
    for (const u of [ann, ben]) ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
    cid = (await ann.ok(["circle", "create", "ix-team"])).cid;
    await ann.ok(["circle", "default", cid]);
    await ann.ok(["session", "roster", "as1"]);
  }, 60_000);

  afterAll(async () => {
    await relay?.close().catch(() => {});
    ann?.cleanup();
    ben?.cleanup();
  });

  it("ben's session, started before his code join, stays as it was; he moves it (or sets the default) himself", async () => {
    // His session starts first: no default circle yet, so private.
    const before = await ben.ok(["status", "--session", "bs1", "--state", "busy", "--label", "web"]);
    expect(before.roster).toMatchObject({ vis: "private", ver: 1 });
    // Then he joins ann's circle with her code (which makes it his default).
    const inv = await ann.ok(["invite", "ben"]);
    const j = await alongside(ben.run(["join", "--confirmed", inv.code, "--wait", "12"]), () => ann.ok(["invites"]));
    expect(j.code).toBe(0);
    // An existing identity's join may still be finishing when `join` returns ("pending"): the
    // circle arrives in a later drain, as the live case's did. The same session's next status
    // (which drains first) goes to the circle all the same.
    expect(j.json.circle).toMatchObject({ cid });
    expect(["joined", "pending"]).toContain(j.json.circle.status);
    for (let i = 0; i < 10; i++) {
      await ann.ok(["invites"]);
      if ((await ben.ok(["circle", "ls"])).circles.some((c: { cid: string; joined?: boolean }) => c.cid === cid && c.joined)) break;
    }
    const app = await ben.app();
    await app.load();
    expect(app.self?.defaultCircle).toBe(cid);
    expect(app.self?.defaultFromJoin).toBe(cid);
    await app.close();
    // A code join made the circle his default: a session already running doesn't move into it.
    const held = await ben.ok(["status", "--session", "bs1", "--state", "busy", "--label", "web", "--summary", "Fixing login."]);
    expect(held.roster).toMatchObject({ vis: "private", ver: 1 });
    // A new session starts in it.
    const fresh = await ben.ok(["status", "--session", "bs0", "--state", "busy", "--label", "web"]);
    expect(fresh.roster).toMatchObject({ vis: "circle", circle: cid });
    // The live bug stays fixed: once ben sets the default himself, the untouched session follows it.
    await ben.ok(["circle", "default", cid]);
    let after: any;
    for (let i = 0; i < 5; i++) {
      after = await ben.ok(["status", "--session", "bs1", "--state", "busy", "--label", "web", "--summary", "Fixing login."]);
      if (after.roster.vis === "circle") break;
    }
    expect(after.roster).toMatchObject({ vis: "circle", circle: cid, ver: 2 });
    expect(after.delivered.map((d: { userId: string }) => d.userId)).toContain(ids.ann);
    const row = (await ann.ok(["ls"])).peers.find((p: { own: string; sid: string }) => p.own === ids.ben && p.sid === "bs1");
    expect(row).toMatchObject({ label: "web", summary: "Fixing login.", state: "busy" });
  });

  it("an explicitly shared session keeps what its user chose", async () => {
    await ben.ok(["session", "roster", "bs2", "--private"]);
    const st = await ben.ok(["status", "--session", "bs2", "--state", "busy", "--label", "web"]);
    expect(st.roster).toMatchObject({ vis: "private" });
  });

  it("no default any more: back to private (never wider than the user's setting)", async () => {
    await ben.ok(["circle", "default", "--none"]);
    const st = await ben.ok(["status", "--session", "bs1", "--state", "idle", "--label", "web"]);
    expect(st.roster).toMatchObject({ vis: "private", ver: 3 });
    await ben.ok(["circle", "default", cid]);
    const again = await ben.ok(["status", "--session", "bs1", "--state", "idle", "--label", "web"]);
    expect(again.roster).toMatchObject({ vis: "circle", circle: cid, ver: 4 });
    // Unchanged default: no new version.
    const same = await ben.ok(["status", "--session", "bs1", "--state", "idle", "--label", "web"]);
    expect(same.roster.ver).toBe(4);
  });

  it("review M1: a status post racing `session roster --private` never undoes it; versions only go up", async () => {
    await ben.ok(["circle", "default", cid]);
    for (let i = 0; i < 6; i++) {
      const sid = `race${i}`;
      await ben.ok(["session", "roster", sid]); // made under the default: the circle, auto
      const [a, b] = await Promise.all([
        ben.run(["status", "--session", sid, "--state", "busy", "--label", "web"]),
        ben.run(["session", "roster", sid, "--private"]),
      ]);
      expect([a.code, b.code]).toEqual([0, 0]);
      // Whatever the order, the explicit --private stands afterwards.
      const after = await ben.ok(["status", "--session", sid, "--state", "idle", "--label", "web"]);
      expect(after.roster.vis).toBe("private");
      const app = await ben.app();
      await app.load();
      const doc = (await app.state.get("sessions"))?.[sid];
      const held = await app.store.getRoster(app.userId, sid);
      await app.close();
      expect(doc?.auto).toBe(false);
      expect(held?.ver).toBe(doc?.ver);
      expect(held?.jws).toBe(doc?.jws);
    }
  });

  it("review M-new: a trust store ahead of state (ver 3 circle vs ver 2 private) no longer locks the roster", async () => {
    const sid = "ahead1";
    await ben.ok(["session", "roster", sid, "--private"]); // state and store at ver 2, private
    const app = await ben.app();
    await app.load();
    try {
      const { createRosterV3 } = await import("@peer2peer/core/v3");
      // Version 3 reached the trust store but not state (an older client, a crash between the two writes).
      await app.store.putRoster({ iss: app.userId, sid, ver: 3, jws: createRosterV3(app.signer(), { sid, ver: 3, vis: "circle", circle: cid, parts: [] }) });
      expect((await app.state.get("sessions"))?.[sid]?.ver).toBe(2);
    } finally {
      await app.close();
    }
    // Was: "roster version 3 is conflict", for good. Now: the store's v3 is adopted, and --private is v4.
    const r = await ben.ok(["session", "roster", sid, "--private"]);
    expect(r.roster).toMatchObject({ vis: "private", ver: 4 });
    const check = await ben.app();
    await check.load();
    try {
      const doc = (await check.state.get("sessions"))?.[sid];
      const held = await check.store.getRoster(check.userId, sid);
      expect(doc).toMatchObject({ ver: 4, vis: "private", auto: false });
      expect(held?.ver).toBe(4);
      expect(held?.jws).toBe(doc?.jws);
    } finally {
      await check.close();
    }
  });

  it("review M-new: a status repairs state from a store that is ahead, keeping the store's roster", async () => {
    const sid = "ahead2";
    await ben.ok(["session", "roster", sid, "--private"]);
    const app = await ben.app();
    await app.load();
    try {
      const { createRosterV3 } = await import("@peer2peer/core/v3");
      await app.store.putRoster({ iss: app.userId, sid, ver: 7, jws: createRosterV3(app.signer(), { sid, ver: 7, vis: "circle", circle: cid, parts: [] }) });
    } finally {
      await app.close();
    }
    const st = await ben.ok(["status", "--session", sid, "--state", "busy", "--label", "web"]);
    expect(st.roster).toMatchObject({ vis: "circle", circle: cid, ver: 7 });
    // Pre-release review low: it is exactly the default roster this device would sign (ben's default circle, nobody
    // added), so it keeps following the default.
    const check = await ben.app();
    await check.load();
    try {
      expect((await check.state.get("sessions"))?.[sid]).toMatchObject({ ver: 7, auto: true });
    } finally {
      await check.close();
    }
  });

  it("review M2: a running session doesn't move into an open default circle by itself, and says why", async () => {
    const open = (await ben.ok(["circle", "create", "community", "--open"])).cid as string;
    await ben.ok(["circle", "default", "--none"]);
    await ben.ok(["status", "--session", "op1", "--state", "busy", "--label", "web"]);
    await ben.ok(["circle", "default", open]);
    const st = await ben.ok(["status", "--session", "op1", "--state", "busy", "--label", "web"]);
    expect(st.roster.vis).toBe("private");
    expect(st.warnings.join("\n")).toMatch(/kept private: your default circle is open/);
    // A session started now, under that default, is the circle's (as before).
    const fresh = await ben.ok(["status", "--session", "op2", "--state", "busy", "--label", "web"]);
    expect(fresh.roster).toMatchObject({ vis: "circle", circle: open });
    // And one following the old (closed) default leaves it for private rather than going open.
    await ben.ok(["circle", "default", cid]);
    await ben.ok(["status", "--session", "op3", "--state", "busy", "--label", "web"]);
    await ben.ok(["circle", "default", open]);
    const moved = await ben.ok(["status", "--session", "op3", "--state", "busy", "--label", "web"]);
    expect(moved.roster.vis).toBe("private");
  });

  it("review L1: summaryAt stays put while the line is the same, (+N agents) or not", async () => {
    await ben.ok(["circle", "default", "--none"]);
    const off = { ...ben.env, P2P_STATUS_CAPS: "0" };
    const u = Object.create(ben) as User;
    Object.defineProperty(u, "env", { get: () => off });
    const agents = JSON.stringify([{ id: "a1", type: "Explore", task: "t", state: "running", at: 1 }]);
    const first = await u.ok(["status", "--session", "sa1", "--state", "busy", "--label", "web", "--summary", "Fixing login.", "--agents-json", agents]);
    expect(first.status.summary).toBe("Fixing login. (+1 agent)");
    await new Promise((r) => setTimeout(r, 20));
    const second = await u.ok(["status", "--session", "sa1", "--state", "busy", "--label", "web", "--summary", "Fixing login.", "--agents-json", agents]);
    expect(second.status.summaryAt).toBe(first.status.summaryAt);
  });

  it("review L-c: a session in a circle whose policy became open is warned about once", async () => {
    const team = (await ben.ok(["circle", "create", "later-open"])).cid as string;
    await ben.ok(["session", "roster", "lc1", "--circle", team]);
    const before = await ben.ok(["status", "--session", "lc1", "--state", "busy", "--label", "web"]);
    expect(before.warnings ?? []).toEqual([]);
    await ben.ok(["circle", "policy", team, "open"]);
    const now = await ben.ok(["status", "--session", "lc1", "--state", "busy", "--label", "web"]);
    expect((now.warnings ?? []).filter((w: string) => /open circle/.test(w))).toHaveLength(1);
    const again = await ben.ok(["status", "--session", "lc1", "--state", "busy", "--label", "web"]);
    expect((again.warnings ?? []).filter((w: string) => /open circle/.test(w))).toHaveLength(0);
  });
});

