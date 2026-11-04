// Copyright 2026 Ix Infrastructure Inc.
//
// Regressions found by the soak harness (scripts/soak): leaving an open
// circle right after joining it, and joining it again.
//
//   - `circle leave` read the circle before handling what was queued, so a
//     member who had just joined (no co-member caps yet, no friendships) told
//     nobody: the owner kept listing it.
//   - The owner's client decided an open-circle join after the store already
//     held it, so the leave before it was invisible and a voluntary leaver's
//     re-join was held as "previously-removed".
//   - A former member still holds the circle, so the owner's answer to its
//     re-join (sent as a circle bundle when they are friends) was applied as an
//     update and never counted as the answer: the join waited for good.
//
// A long circle chain (many joins and leaves) is answered in chunks that each fit an envelope.
//
// And a message lost after a crash: envelope seqs jumped to the clock on every
// send, so an envelope applied after a later one (its first attempt died) was
// more than the 512-seq window behind and dropped as seq-too-old.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { processEnvelope, receiving } from "../inbound.js";
import { exportCircle, importSync, splitCircle } from "../sync.js";
import { linkJoin, linkStart } from "../identity.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-soak-findings.test/v3";
let relay: TestRelay;
let owen: User;
let bea: User;
let cy: User;
const ids: Record<string, string> = {};
let cid = "";

async function joinOpen(u: User): Promise<void> {
  const link = (await owen.ok(["circle", "invite", cid, "--link"])).link;
  await u.ok(["circle", "join", link, "--wait", "0"]);
  await owen.ok(["circle", "ls"]); // answers the request for the history
  const j = await u.run(["circle", "join", link, "--wait", "3", "--yes"]);
  expect(j.json.status).toBe("joined");
  await owen.ok(["circle", "ls"]); // admits it (open policy) and distributes the next version
}

/** A former member's join is held for the owner (review H1): the owner approves it. */
async function approveHeldJoin(u: User): Promise<void> {
  const held = (await owen.ok(["held"])).held.filter((h: any) => h.type === "circle-join" && h.from === ids[u.name]);
  expect(held).toEqual([expect.objectContaining({ reason: "previously-removed" })]);
  await owen.ok(["held", "approve", held[0].id]);
  expect((await owen.ok(["held"])).held).toEqual([]);
}

describe("soak findings: leave and re-join an open circle", () => {
  beforeAll(async () => {
    relay = await startRelay(R);
    const t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    owen = new User("owen", t);
    bea = new User("bea", t);
    cy = new User("cy", t);
    for (const u of [owen, bea, cy]) ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
    cid = (await owen.ok(["circle", "create", "team", "--open"])).cid;
    await joinOpen(bea);
    await joinOpen(cy);
  }, 120_000);

  afterAll(async () => {
    await relay?.close().catch(() => {});
    for (const u of [owen, bea, cy]) u?.cleanup();
  });

  it("a member who just joined (nothing handled since) tells every member it left", async () => {
    // Nothing between the join and the leave: what the owner distributed is still queued for bea.
    const l = await bea.ok(["circle", "leave", cid]);
    expect(l.told).toBe(2);
    await owen.ok(["circle", "ls"]);
    const m = await owen.ok(["circle", "members", cid]);
    expect(m.members.map((x: any) => x.userId).sort()).toEqual([ids.owen, ids.cy].sort());
  }, 60_000);

  it("the member who left joins again: held for the owner (as on main), who approves it", async () => {
    await joinOpen(bea);
    await approveHeldJoin(bea);
    await bea.ok(["circle", "ls"]);
    const m = await owen.ok(["circle", "members", cid]);
    expect(m.members.map((x: any) => x.userId).sort()).toEqual([ids.owen, ids.bea, ids.cy].sort());
    expect(m.members.every((x: any) => x.stands)).toBe(true);
  }, 60_000);

  it("a member who is the owner's friend leaves and joins again (the answer comes for a circle it still holds)", async () => {
    const inv = await owen.ok(["invite", "--link", "--no-circle"]);
    await cy.ok(["accept", inv.link]);
    await owen.ok(["friends"]);
    expect((await cy.ok(["circle", "leave", cid])).told).toBe(2);
    await owen.ok(["circle", "ls"]);
    expect((await owen.ok(["circle", "members", cid])).members.map((x: any) => x.userId)).not.toContain(ids.cy);
    await joinOpen(cy);
    // The join completes on cy's side (the answer counted), and waits for the owner's approval.
    await approveHeldJoin(cy);
    const m = await owen.ok(["circle", "members", cid]);
    expect(m.members.map((x: any) => x.userId).sort()).toEqual([ids.owen, ids.bea, ids.cy].sort());
  }, 60_000);

  it("review H1: a removed member's leave-then-join is held even where the store lost its removal record", async () => {
    await owen.ok(["circle", "propose", cid, "remove", ids.bea]);
    await bea.ok(["circle", "ls"]);
    // An owner store that didn't watch the removal: a second key holder that got the circle by sync
    // before the record travelled with it, a later owner, a rotation import, a pre-record store.
    const app = await owen.app();
    await app.load();
    await app.store.updateCircle(cid, (cur) => ({ next: { ...cur!, removed: undefined }, result: undefined }));
    // bea signs a leave (n+1), then a join (n+2), through an ordinary link.
    await bea.run(["circle", "leave", cid]);
    const link = (await owen.ok(["circle", "invite", cid, "--link"])).link;
    await bea.ok(["circle", "join", link, "--wait", "0"]);
    await owen.ok(["circle", "ls"]);
    await bea.run(["circle", "join", link, "--wait", "3", "--yes"]);
    await owen.ok(["circle", "ls"]);
    expect((await owen.ok(["held"])).held).toEqual([expect.objectContaining({ type: "circle-join", from: ids.bea, reason: "previously-removed" })]);
    expect((await owen.ok(["circle", "members", cid])).members.map((x: any) => x.userId)).not.toContain(ids.bea);
  }, 60_000);

  it("the removal record travels by sync (it can only add holds)", async () => {
    const a = await owen.app();
    await a.load();
    // What owen's store would hold had it watched bea's removal (the test above blanked it).
    await a.store.updateCircle(cid, (cur) => ({ next: { ...cur!, removed: [ids.bea] }, result: undefined }));
    const exp = await exportCircle(a, cid);
    expect(exp).toMatchObject({ removed: [ids.bea] });
    const other = new User("owen-laptop", { [R]: `ws://127.0.0.1:${relay.port}/v3` });
    try {
      await other.ok(["init", "--name", "other", "--relay", R, "--yes"]);
      const b = await other.app();
      await b.load();
      await importSync(b, { circles: [exp] });
      const rec = await b.store.getCircle(cid);
      expect(rec?.chain.versions.length).toBe(exp!.versions.length);
      expect(rec?.removed).toEqual([ids.bea]);
    } finally {
      other.cleanup();
    }
  }, 60_000);
});

describe("soak findings: an envelope applied after a later one from the same session", () => {
  let r2: TestRelay;
  let ann: User;
  let ben: User;
  afterAll(async () => {
    await r2?.close().catch(() => {});
    for (const u of [ann, ben]) u?.cleanup();
  });

  it("is applied, not dropped as seq-too-old, though the sends were a second apart", async () => {
    const R2 = "wss://relay-soak-seq.test/v3";
    r2 = await startRelay(R2);
    const t = { [R2]: `ws://127.0.0.1:${r2.port}/v3` };
    ann = new User("ann", t);
    ben = new User("ben", t);
    const id: Record<string, string> = {};
    for (const u of [ann, ben]) id[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R2, "--yes"])).userId;
    await ben.ok(["accept", (await ann.ok(["invite", "--link"])).link]);
    await ann.ok(["friends"]);
    await ann.ok(["session", "roster", "as1", "--add", id.ben]);
    await ben.share(id.ann);
    await ann.ok(["status", "--session", "as1", "--state", "busy"]);
    await ben.ok(["ls"]);
    await ben.ok(["send", "--from-session", "bs1", "--to", `${id.ann}/as1`, "first"]);
    await new Promise((res) => setTimeout(res, 1100));
    await ben.ok(["send", "--from-session", "bs1", "--to", `${id.ann}/as1`, "second"]);
    // Ann's device takes both off the relay without applying them (as a process killed mid-apply would).
    const got: { env: string; relay: string }[] = [];
    const a1 = await ann.app();
    await a1.load();
    a1.onEnvelope = async (env, relay) => {
      got.push({ env, relay });
      return "keep";
    };
    await a1.connectAndDrain();
    await a1.close();
    expect(got).toHaveLength(2);
    // The later one is applied first (another process, another relay's copy), then the earlier one.
    const a2 = await ann.app();
    await a2.load();
    receiving(a2);
    a2.onEnvelope = async () => "keep";
    await a2.connect();
    expect(await processEnvelope(a2, got[1].env, got[1].relay)).toBe("ack");
    expect(await processEnvelope(a2, got[0].env, got[0].relay)).toBe("ack");
    await a2.close();
    const texts = ((await (await ann.app()).state.get("events"))?.items ?? []).filter((e) => e.kind === "p2p.message").map((e) => e.data.text);
    expect(texts.sort()).toEqual(["first", "second"]);
  }, 60_000);

  // Ann's session as1 as ben's sends see it.
  const seqKey = () => Object.keys(JSON.parse(readFileSync(join(ben.home, "cli", "seq.json"), "utf8"))).find((k) => k.endsWith("|as1"))!;
  const texts = async () => ((await (await ann.app()).state.get("events"))?.items ?? []).filter((e) => e.kind === "p2p.message").map((e) => e.data.text);

  it("review M1: a lost seq key starts from the clock again, above the receiver's window, so the next message is delivered", async () => {
    const seqPath = join(ben.home, "cli", "seq.json");
    const id = (await ann.ok(["whoami"])).userId;
    await ann.ok(["ls"]);
    // The receiver's window for this session is at the clock's scale (ms): a send from a counter there.
    const doc = JSON.parse(readFileSync(seqPath, "utf8")) as Record<string, number>;
    doc[seqKey()] = Date.now();
    writeFileSync(seqPath, JSON.stringify(doc));
    await ben.ok(["send", "--from-session", "bs1", "--to", `${id}/as1`, "before-loss"]);
    await ann.ok(["ls"]);
    expect(await texts()).toContain("before-loss");
    // seq.json loses the key (deleted, a clone, a backup from before the session's first send).
    const k = seqKey();
    const lost = JSON.parse(readFileSync(seqPath, "utf8")) as Record<string, number>;
    delete lost[k];
    writeFileSync(seqPath, JSON.stringify(lost));
    await new Promise((res) => setTimeout(res, 5));
    await ben.ok(["send", "--from-session", "bs1", "--to", `${id}/as1`, "after-loss"]);
    await ann.ok(["ls"]);
    expect(await texts()).toContain("after-loss");
  }, 60_000);

  it("review M1: an envelope 300 seqs behind a later one (still inside the 512 window) is applied after it", async () => {
    const seqPath = join(ben.home, "cli", "seq.json");
    const id = (await ann.ok(["whoami"])).userId;
    await ann.ok(["ls"]); // acks what earlier tests left on the relay
    await ben.ok(["send", "--from-session", "bs1", "--to", `${id}/as1`, "before-idle"]);
    // 299 envelopes of this session went to other devices in between (a large status fan-out).
    const doc = JSON.parse(readFileSync(seqPath, "utf8")) as Record<string, number>;
    doc[seqKey()] += 299;
    writeFileSync(seqPath, JSON.stringify(doc));
    await ben.ok(["send", "--from-session", "bs1", "--to", `${id}/as1`, "after-idle"]);
    const got: { env: string; relay: string }[] = [];
    const a1 = await ann.app();
    await a1.load();
    a1.onEnvelope = async (env, relay) => {
      got.push({ env, relay });
      return "keep";
    };
    await a1.connectAndDrain();
    await a1.close();
    expect(got).toHaveLength(2);
    const a2 = await ann.app();
    await a2.load();
    receiving(a2);
    a2.onEnvelope = async () => "keep";
    await a2.connect();
    await processEnvelope(a2, got[1].env, got[1].relay);
    await processEnvelope(a2, got[0].env, got[0].relay);
    await a2.close();
    expect(await texts()).toEqual(expect.arrayContaining(["before-idle", "after-idle"]));
  }, 60_000);

  it("review M1: an envelope behind the window is acked but counted, and doctor says so (without its content)", async () => {
    const seqPath = join(ben.home, "cli", "seq.json");
    const id = (await ann.ok(["whoami"])).userId;
    await ann.ok(["ls"]);
    await ben.ok(["send", "--from-session", "bs1", "--to", `${id}/as1`, "late-one"]);
    const got: { env: string; relay: string }[] = [];
    const a1 = await ann.app();
    await a1.load();
    a1.onEnvelope = async (env, relay) => {
      got.push({ env, relay });
      return "keep";
    };
    await a1.connectAndDrain();
    await a1.close();
    // 600 later envelopes from the session were applied first.
    const doc = JSON.parse(readFileSync(seqPath, "utf8")) as Record<string, number>;
    doc[seqKey()] += 600;
    writeFileSync(seqPath, JSON.stringify(doc));
    await ben.ok(["send", "--from-session", "bs1", "--to", `${id}/as1`, "much-later"]);
    const a2 = await ann.app();
    await a2.load();
    receiving(a2);
    const later: { env: string; relay: string }[] = [];
    a2.onEnvelope = async (env, relay) => {
      if (!got.some((g) => g.env === env)) later.push({ env, relay });
      return "keep";
    };
    await a2.connectAndDrain();
    expect(later).toHaveLength(1);
    expect(await processEnvelope(a2, later[0].env, later[0].relay)).toBe("ack");
    expect(await processEnvelope(a2, got[0].env, got[0].relay)).toBe("ack");
    await a2.close();
    expect(await texts()).not.toContain("late-one");
    expect((await (await ann.app()).state.get("inbound"))?.tooOld).toBe(1);
    const doctor = JSON.stringify((await ann.run(["doctor"])).json);
    expect(doctor).toMatch(/arrived behind the replay window/);
    expect(doctor).not.toContain("late-one");
  }, 60_000);
});

describe("soak findings: a long circle chain still reaches a joiner", () => {
  const R3 = "wss://relay-soak-chain.test/v3";
  let r3: TestRelay;
  let owner: User;
  let joiner: User;
  afterAll(async () => {
    await r3?.close().catch(() => {});
    for (const u of [owner, joiner]) u?.cleanup();
  });

  it("the owner's answer to a friend is split into envelopes under the 64 KiB cap", async () => {
    r3 = await startRelay(R3);
    const t = { [R3]: `ws://127.0.0.1:${r3.port}/v3` };
    owner = new User("olga", t);
    joiner = new User("jo", t);
    for (const u of [owner, joiner]) await u.ok(["init", "--name", u.name, "--relay", R3, "--yes"]);
    // Friends: the owner answers with chunked circle bundles (a stranger gets one contact envelope).
    await joiner.ok(["accept", (await owner.ok(["invite", "--link", "--no-circle"])).link]);
    await owner.ok(["friends"]);
    const c = await owner.ok(["circle", "create", "long", "--open"]);
    // About 1.5 KiB a version: 40 of them are well past one envelope.
    for (let i = 0; i < 40; i++) await owner.ok(["circle", "propose", c.cid, "rename", `${"long-chain-".repeat(11)}${i}`]);
    const link = (await owner.ok(["circle", "invite", c.cid, "--link"])).link;
    await joiner.ok(["circle", "join", link, "--wait", "0"]);
    const ls = await owner.run(["circle", "ls"]);
    expect(ls.err).not.toMatch(/couldn.t answer/);
    const j = await joiner.run(["circle", "join", link, "--wait", "5", "--yes"]);
    expect(j.json.status).toBe("joined");
  }, 120_000);

  it("review M2: slices that arrive in reverse are held until they line up, then applied once", async () => {
    const a = await owner.app();
    await a.load();
    const cid = (await owner.ok(["circle", "ls"])).circles[0].cid;
    const parts = splitCircle((await exportCircle(a, cid))!);
    expect(parts.length).toBeGreaterThan(1);
    // A version that doesn't parse is dropped, not left to stall the rest.
    parts[parts.length - 1] = { ...parts[parts.length - 1], versions: [...parts[parts.length - 1].versions, "not.a.version"] };
    const other = new User("olga-backup", { [R3]: `ws://127.0.0.1:${r3.port}/v3` });
    try {
      await other.ok(["init", "--name", "olgab", "--relay", R3, "--yes"]);
      const b = await other.app();
      await b.load();
      for (const p of [...parts].reverse().slice(0, -1)) {
        await importSync(b, { circles: [p] });
        expect(await b.store.getCircle(cid)).toBeUndefined();
      }
      await importSync(b, { circles: [parts[0]] });
      const rec = await b.store.getCircle(cid);
      expect(rec?.chain.versions.length).toBe(parts.flatMap((p) => p.versions).length - 1);
      expect((await b.state.get("syncCircles"))?.[cid]).toBeUndefined();
    } finally {
      other.cleanup();
    }
  }, 60_000);

  it("review M2: a device linked afterwards gets the long-chain circle by sync, in slices", async () => {
    const laptop = new User("olga-laptop", { [R3]: `ws://127.0.0.1:${r3.port}/v3` });
    try {
      const a = await owner.app();
      await a.load();
      receiving(a);
      const start = await linkStart(a, {});
      const b = await laptop.app();
      const join = await linkJoin(b, start.code, { label: "laptop" });
      await Promise.all([start.wait(async (req) => req.compareCode === join.compareCode), join.wait()]);
      await a.close();
      await b.close();
      const want = (await owner.ok(["circle", "ls"])).circles[0];
      for (let i = 0; i < 3; i++) await laptop.ok(["circle", "ls"]);
      const got = (await laptop.ok(["circle", "ls"])).circles.find((c: any) => c.cid === want.cid);
      expect(got).toMatchObject({ cid: want.cid, ver: want.ver });
    } finally {
      laptop.cleanup();
    }
  }, 120_000);
});

describe("review low: the second confirmer's ask is timed too", () => {
  let r4: TestRelay;
  const us: User[] = [];
  afterAll(async () => {
    await r4?.close().catch(() => {});
    for (const u of us) u.cleanup();
  });

  it("a confirmer first named by the answered chain gets an askedAtBy entry", async () => {
    const R4 = "wss://relay-soak-confirm.test/v3";
    r4 = await startRelay(R4);
    const t = { [R4]: `ws://127.0.0.1:${r4.port}/v3` };
    const [o, m, j] = ["oona", "milo", "jade"].map((n) => new User(n, t));
    us.push(o, m, j);
    const id: Record<string, string> = {};
    for (const u of [o, m, j]) id[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R4, "--yes"])).userId;
    // jade can reach milo (friends), so asking him works.
    await j.ok(["accept", (await m.ok(["invite", "--link", "--no-circle"])).link]);
    await m.ok(["friends"]);
    const cid = (await o.ok(["circle", "create", "c", "--open"])).cid;
    // A link made while the owner was alone: its head names no other member to confirm with.
    const oldLink = (await o.ok(["circle", "invite", cid, "--link"])).link;
    const fresh = (await o.ok(["circle", "invite", cid, "--link"])).link;
    await m.ok(["circle", "join", fresh, "--wait", "0"]);
    await o.ok(["circle", "ls"]);
    expect((await m.run(["circle", "join", fresh, "--wait", "3", "--yes"])).json.status).toBe("joined");
    await o.ok(["circle", "ls"]);
    // jade joins with the old link: the owner's answer names milo, the second confirmer.
    await j.ok(["circle", "join", oldLink, "--wait", "0"]);
    await o.ok(["circle", "ls"]);
    await j.run(["circle", "join", oldLink, "--wait", "2"]);
    const pending = (await (await j.app()).state.get("joins"))?.[cid];
    expect(pending?.asked).toContain(id.milo);
    expect(pending?.askedAtBy?.[id.milo]).toBeGreaterThan(0);
  }, 120_000);
});
