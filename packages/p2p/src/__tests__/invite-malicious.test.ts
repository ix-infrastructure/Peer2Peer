// Copyright 2026 Ix Infrastructure Inc.
//
// A malicious inviter's code (docs/protocol.md P4, review M1 of invite links). The code's circle versions are
// whatever its maker put there: the preview checks each one's signature and shows what is verified,
// and the redeemer joins a circle from the code only when the circle that actually arrives verifies
// from version 1, isn't open, is run (owned or administered) by the inviter, and is the one the
// person said yes to. Anything else stays a held circle invite to approve on its own, and never
// becomes the default circle.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { signJws } from "@peer2peer/core";
import { b64uEncode, circlePolicy, IK_KID, jwsHash, loadCircle, parseCircleVersion, storeOfferedCircle, TYP3 } from "@peer2peer/core/v3";
import { deliverCircle, joinCircle } from "../circle-ops.js";
import { invitePut } from "../relay-client.js";
import { formatShortCode, inviteAdmitHash, inviteAdmitKey, inviteLid, newCodeSecret, sealInviteBundle, groupCode, encodeCodeChars, type InviteBundle } from "../shortcode.js";
import { mintInvite } from "../social.js";
import type { CodeRecord } from "../state.js";
import { alongside, startRelay, User, type TestRelay } from "./harness.js";

const R1 = "wss://invite-malicious.test/v3";
let r1: TestRelay;
let t: Record<string, string>;
const users: User[] = [];

async function setUp(name: string): Promise<User> {
  const u = new User(name, t, { P2P_DEFAULT_RELAYS: R1 });
  users.push(u);
  await u.ok(["setup", "--name", name, "--no-backup"]);
  return u;
}

/**
 * A code as a malicious client makes it: any circle versions in the bundle. `addTo` is recorded like
 * a real code's circles, so this client still adds the redeemer to those on the accept.
 */
async function craftCode(u: User, heads: string[], addTo: string[] = []): Promise<string> {
  const app = await u.app();
  await app.load();
  try {
    const pool = await app.connectAndDrain();
    const m = await mintInvite(app, { aud: "*", uses: 3, ttlSec: 3600 });
    const s = newCodeSecret();
    const lid = inviteLid(s);
    const [first, ...rest] = heads;
    const bundle: InviteBundle = { v: 1, invite: m.jws, circle: { head: first }, ...(rest.length ? { circles: rest.map((head) => ({ head })) } : {}) };
    const exp = await invitePut(await pool.ensure(R1), lid, sealInviteBundle(s, bundle), 3600, inviteAdmitHash(inviteAdmitKey(s)));
    const rec: CodeRecord = {
      lid,
      code: groupCode(encodeCodeChars(s)),
      short: formatShortCode(R1, s),
      relay: R1,
      inv: m.inv,
      aud: "*",
      ...(addTo.length ? { cid: addTo[0], cids: addTo } : {}),
      createdAt: Math.floor(Date.now() / 1000),
      exp,
      status: "open",
    };
    await app.state.update("codes", (cur = {}) => ({ next: { ...cur, [lid]: rec }, result: undefined }));
    return rec.short;
  } finally {
    await app.close();
  }
}

/** A version of `cid` that `signer` signs as its "owner", saying whatever it likes (name, members). */
async function forgeHead(signer: User, realHead: string, name: string): Promise<string> {
  const app = await signer.app();
  await app.load();
  try {
    const real = parseCircleVersion(realHead);
    const me = app.userId;
    const payload = {
      cid: real.cid,
      founder: real.founder,
      nonce: real.nonce,
      ver: real.ver + 1,
      prev: jwsHash(realHead),
      owner: me,
      ik: b64uEncode(app.ik!.publicKey),
      name,
      admins: [],
      members: [me, ...real.members.filter((m) => m !== me)].slice(0, 3),
      iat: Math.floor(Date.now() / 1000),
    };
    return signJws(TYP3.circle, IK_KID, payload, app.ik!.secretKey);
  } finally {
    await app.close();
  }
}

/** `from` sends `to` the circle's real chain, as a circle invite (what any member's client can do). */
async function sendRealChain(from: User, to: string, cid: string): Promise<void> {
  // Friends first: the redeemer's accept reaches the inviter's client.
  for (let i = 0; i < 20; i++) {
    if ((await from.ok(["friends"])).friends.some((f: { userId: string }) => f.userId === to)) break;
    await new Promise((r) => setTimeout(r, 300));
  }
  const app = await from.app();
  await app.load();
  try {
    // Handles the redeemer's accept first (friends then), as the inviter's client would.
    await app.connectAndDrain();
    const c = await loadCircle(app.store, cid);
    await deliverCircle(app, to, { circles: c!.chain.versionsFrom(1), joins: [] });
  } finally {
    await app.close();
  }
}

async function headOf(u: User, cid: string): Promise<string> {
  const app = await u.app();
  await app.load();
  try {
    return (await loadCircle(app.store, cid))!.chain.head.jws;
  } finally {
    await app.close();
  }
}

async function notJoined(v: User, cid: string): Promise<void> {
  // A few commands: whatever arrives is handled (finishCodeJoins runs after each drain).
  for (let i = 0; i < 3; i++) await v.ok(["held"]);
  const mine = (await v.ok(["circle", "ls"])).circles.find((c: { cid: string }) => c.cid === cid);
  expect(mine?.joined ?? false).toBe(false);
  expect((await v.ok(["whoami"])).defaultCircle ?? null).toBeNull();
  // Nothing left waiting to auto-join it: the code's claim on this circle was refused, not just slow.
  const app = await v.app();
  await app.load();
  try {
    expect((await app.state.get("codeJoins"))?.[cid]).toBeUndefined();
  } finally {
    await app.close();
  }
}

async function heldInvite(v: User, cid: string): Promise<number> {
  return (await v.ok(["held"])).held.filter((h: { type: string; cid?: string }) => h.type === "circle-invite" && h.cid === cid).length;
}

let carol: User;
let mallory: User;
let carolTeam: string;

beforeAll(async () => {
  r1 = await startRelay(R1);
  t = { [R1]: `ws://127.0.0.1:${r1.port}/v3` };
  // carol owns an invite-only circle; mallory is a plain member of it.
  carol = await setUp("carol");
  mallory = await setUp("mallory");
  carolTeam = (await carol.ok(["circle", "create", "carol-team"])).cid;
  const inv = await carol.ok(["invite", "--circle", carolTeam]);
  await alongside(mallory.run(["join", "--yes", inv.code, "--wait", "12"]), () => carol.ok(["invites"]));
  expect((await mallory.ok(["circle", "ls"])).circles.find((c: { cid: string }) => c.cid === carolTeam)).toMatchObject({ joined: true, role: "member" });
}, 120_000);

afterAll(async () => {
  await r1?.close();
  for (const u of users) u.cleanup();
});

describe("a malicious inviter's code never auto-joins", () => {
  it("a forged head (signed by someone else than the circle's owner): shown as theirs, never joined when the real circle comes", async () => {
    const forged = await forgeHead(mallory, await headOf(mallory, carolTeam), "Book club");
    const code = await craftCode(mallory, [forged]);
    const victim = await setUp("victim1");
    const pv = (await victim.ok(["join", "--preview", code])).preview;
    // Signed by the owner it names (mallory), so "verified": but it says mallory owns it, which the real circle won't.
    expect(pv.circles[0]).toMatchObject({ cid: carolTeam, name: "Book club", owner: (await mallory.ok(["whoami"])).userId });
    const j = await victim.ok(["join", "--confirmed", code, "--wait", "1"]);
    expect(j.circles[0]).toMatchObject({ cid: carolTeam });
    // mallory's client sends the real circle; it isn't what was shown (owner, name), and mallory doesn't run it.
    await sendRealChain(mallory, (await victim.ok(["whoami"])).userId, carolTeam);
    await notJoined(victim, carolTeam);
    const held = (await victim.ok(["held"])).held.filter((h: { type: string; cid?: string }) => h.type === "circle-invite" && h.cid === carolTeam);
    expect(held).toHaveLength(1);
  }, 90_000);

  it("the attack: a plain member of an open circle forges an invite-only \"Book club\"; the victim's yes never puts them in the open circle", async () => {
    const town = (await carol.ok(["circle", "create", "town", "--open"])).cid;
    const link = (await carol.ok(["circle", "invite", town, "--link"])).link as string;
    // The owner's client runs throughout: an open circle admits whoever asks.
    const srv = carol.serve("answers");
    try {
      const mj = await mallory.run(["circle", "join", link, "--wait", "15", "--yes"]);
      expect(mj.json, mj.err).toMatchObject({ cid: town, status: "joined" });
      const forged = await forgeHead(mallory, await headOf(mallory, town), "Book club");
      const code = await craftCode(mallory, [forged]);
      const victim = await setUp("victim0");
      const pv = (await victim.ok(["join", "--preview", code])).preview;
      expect(pv.circles[0]).toMatchObject({ cid: town, name: "Book club", policy: "invite" });
      await victim.ok(["join", "--confirmed", code, "--wait", "1"]);
      await sendRealChain(mallory, (await victim.ok(["whoami"])).userId, town);
      await notJoined(victim, town);
      expect(await heldInvite(victim, town)).toBe(1);
    } finally {
      await srv.stop();
    }
  }, 120_000);

  it("a head with a bad signature: shown as unverified, and not joined", async () => {
    const real = await headOf(mallory, carolTeam);
    const [h, p] = real.split(".");
    const bad = `${h}.${p}.${(await forgeHead(mallory, real, "x")).split(".")[2]}`;
    const code = await craftCode(mallory, [bad]);
    const victim = await setUp("victim2");
    const no = await victim.run(["join", code]);
    expect(no.json.reason).toMatch(/"carol-team" \(unverified: not joined from this code/);
    const j = await victim.ok(["join", "--confirmed", code, "--wait", "1"]);
    expect(j.circles[0]).toMatchObject({ cid: carolTeam, status: "held", reason: expect.stringMatching(/isn't signed by the owner it names/) });
    await sendRealChain(mallory, (await victim.ok(["whoami"])).userId, carolTeam);
    await notJoined(victim, carolTeam);
    expect(await heldInvite(victim, carolTeam)).toBe(1);
  }, 90_000);

  it("an inviter who is a plain member (not owner or admin): not joined", async () => {
    const code = await craftCode(mallory, [await headOf(mallory, carolTeam)]);
    const victim = await setUp("victim3");
    const pv = (await victim.ok(["join", "--preview", code])).preview;
    expect(pv.circles[0]).toMatchObject({ cid: carolTeam, verified: true, auto: false, note: "not-admin" });
    const j = await victim.ok(["join", "--confirmed", code, "--wait", "1"]);
    expect(j.circles[0]).toMatchObject({ status: "held" });
    await sendRealChain(mallory, (await victim.ok(["whoami"])).userId, carolTeam);
    await notJoined(victim, carolTeam);
    expect(await heldInvite(victim, carolTeam)).toBe(1);
  }, 90_000);

  it("an open circle (its owner's own code): not joined from the code, and never the default", async () => {
    const lobby = (await carol.ok(["circle", "create", "lobby", "--open"])).cid;
    // carol's client adds the redeemer to it on the accept, as a real code's circle.
    const code = await craftCode(carol, [await headOf(carol, lobby)], [lobby]);
    const victim = await setUp("victim4");
    const pv = (await victim.ok(["join", "--preview", code])).preview;
    expect(pv.circles[0]).toMatchObject({ cid: lobby, policy: "open", auto: false, note: "open" });
    const j = await alongside(victim.run(["join", "--confirmed", code, "--wait", "3"]), () => carol.ok(["invites"]));
    expect(j.json.circles[0]).toMatchObject({ cid: lobby, status: "held", default: false });
    await carol.ok(["invites"]);
    await notJoined(victim, lobby);
  }, 90_000);

  it("invite-only in the code and in the admin's add, open in the owner's answer: the join refuses the head it would commit to", async () => {
    // carol owns the circle; dave administers it and makes the code.
    const c = (await carol.ok(["circle", "create", "admin-run"])).cid;
    const dave = await setUp("dave");
    const daveId = (await dave.ok(["whoami"])).userId as string;
    const forDave = await carol.ok(["invite", "--circle", c]);
    await alongside(dave.run(["join", "--yes", forDave.code, "--wait", "12"]), () => carol.ok(["invites"]));
    await carol.ok(["circle", "propose", c, "promote", daveId]);
    for (let i = 0; i < 10; i++) {
      if ((await dave.ok(["circle", "ls"])).circles.find((x: { cid: string; role?: string }) => x.cid === c)?.role === "admin") break;
      await carol.ok(["invites"]);
    }
    const inv = await dave.ok(["invite", "--circle", c]);
    const victim = await setUp("victim-later-open");
    // The victim already knows carol (so her client can be asked for the circle's history).
    const hello = await carol.ok(["invite", "--no-circle"]);
    await alongside(victim.run(["join", "--yes", hello.code, "--wait", "5"]), () => carol.ok(["invites"]));
    const pv = (await victim.ok(["join", "--preview", inv.web])).preview;
    expect(pv.circles[0]).toMatchObject({ cid: c, policy: "invite", auto: true });
    await victim.ok(["join", "--confirmed", inv.web, "--wait", "0"]);
    // dave's client takes the accept: it proposes the add to carol and sends the victim the invite-only chain.
    await dave.ok(["invites"]);
    // Then the circle turns open. The victim's join asks carol (the owner) for the history; her answer is the open chain.
    await carol.ok(["circle", "policy", c, "open"]);
    const srv = carol.serve("answers");
    let r;
    try {
      r = await victim.run(["held"]);
    } finally {
      await srv.stop();
    }
    expect(r.code, r.err).toBe(0);
    expect(r.err).toMatch(/wasn't joined from your code \(it is open\)/);
    await notJoined(victim, c);
    expect(await heldInvite(victim, c)).toBeGreaterThanOrEqual(1);
  }, 120_000);

  it("a circle already stored here, ahead of the chain the join chose: the rules see the stored head before anything is signed", async () => {
    const c = (await carol.ok(["circle", "create", "stored-ahead"])).cid;
    const carolId = (await carol.ok(["whoami"])).userId as string;
    const victim = await setUp("victim-stored");
    const vid = (await victim.ok(["whoami"])).userId as string;
    const chainOf = async () => {
      const a = await carol.app();
      await a.load();
      try {
        return (await loadCircle(a.store, c))!.chain.versionsFrom(1);
      } finally {
        await a.close();
      }
    };
    await carol.ok(["circle", "propose", c, "add", vid]);
    const offered = await chainOf(); // invite-only, lists the victim
    await carol.ok(["circle", "policy", c, "open"]);
    const newer = await chainOf(); // open
    const app = await victim.app();
    await app.load();
    try {
      // Held here already (seen before, never joined), at the newer, open version.
      await storeOfferedCircle(app.store, newer);
      const seen: string[] = [];
      const r = await joinCircle(
        app,
        { head: offered.at(-1)!, chain: offered, inviter: carolId, accept: (h) => (seen.push(circlePolicy(h)), circlePolicy(h) === "open" ? "it is open" : undefined) },
        { waitSec: 0, yes: true },
      );
      expect(r).toMatchObject({ status: "refused", refused: "it is open", policy: "open" });
      // The chain the join chose passed; the stored head it would have signed onto did not.
      expect(seen).toEqual(["invite", "open"]);
      expect((await app.store.getCircle(c))?.joinedByMe ?? false).toBe(false);
    } finally {
      await app.close();
    }
  }, 90_000);

  it("a circle renamed, or made open, after the preview: not the one said yes to, so not joined", async () => {
    for (const change of [["propose", "rename", "Something else"], ["policy", "open"]] as const) {
      const c = (await carol.ok(["circle", "create", `swap-${change[0]}`])).cid;
      const inv = await carol.ok(["invite", "--circle", c]);
      const victim = await setUp(`victim-${change[0]}`);
      const pv = (await victim.ok(["join", "--preview", inv.web])).preview;
      expect(pv.circles[0]).toMatchObject({ cid: c, auto: true });
      // The swap, between the preview and the yes: carol's client then adds the victim to the changed circle.
      if (change[0] === "propose") await carol.ok(["circle", "propose", c, "rename", change[2]]);
      else await carol.ok(["circle", "policy", c, change[1]]);
      const j = await alongside(victim.run(["join", "--confirmed", inv.web, "--wait", "12"]), () => carol.ok(["invites"]));
      expect(j.code).toBe(0);
      await carol.ok(["invites"]);
      await notJoined(victim, c);
      const held = (await victim.ok(["held"])).held.filter((h: { type: string; cid?: string }) => h.type === "circle-invite" && h.cid === c);
      expect(held).toHaveLength(1);
    }
  }, 180_000);
});
