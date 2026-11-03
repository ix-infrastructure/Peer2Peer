// Copyright 2026 Ix Infrastructure Inc.
//
// P4 short-code invites: `p2p invite` / `p2p join` / `p2p invites` /
// `p2p remove` / `p2p setup`, over real in-process relays, plus the sealing
// and code format on their own.

import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { b64uEncode } from "@peer2peer/core/v3";
import { accept } from "../social.js";
import { onCodeRedeemed } from "../codes.js";
import { capPeek, joinCapOf } from "../app.js";
import { receiving } from "../inbound.js";
import { inviteGet, openLinkConnection } from "../relay-client.js";
import {
  codeRelayPart,
  decodeCodeChars,
  encodeCodeChars,
  formatShortCode,
  inviteLid,
  newCodeSecret,
  openInviteBundle,
  parseInviteBundle,
  parseShortCode,
  sealInviteBundle,
} from "../shortcode.js";
import { main } from "../cli.js";
import { alongside, startRelay, User, type TestRelay } from "./harness.js";

const R1 = "wss://codes-one.test/v3";
const R2 = "wss://codes-two.test/v3";
let r1: TestRelay;
let r2: TestRelay;
const clock = { offset: 0 };
let t: Record<string, string>;
const users: User[] = [];
const dirs: string[] = [];
/** Every frame relay 1 received, as text (to show the code secret never reaches it). */
const seen: string[] = [];

function user(name: string, extra: Record<string, string> = {}): User {
  const u = new User(name, t, { P2P_DEFAULT_RELAYS: R1, ...extra });
  users.push(u);
  return u;
}

async function setUp(name: string): Promise<User> {
  const u = user(name);
  await u.ok(["setup", "--name", name, "--no-backup"]);
  return u;
}

beforeAll(async () => {
  r1 = await startRelay(R1, { now: () => Date.now() + clock.offset });
  r2 = await startRelay(R2);
  t = { [R1]: `ws://127.0.0.1:${r1.port}/v3`, [R2]: `ws://127.0.0.1:${r2.port}/v3` };
  const relay = r1.relay as unknown as { onFrame: (c: unknown, d: unknown, b: boolean) => void };
  const orig = relay.onFrame.bind(relay);
  relay.onFrame = (c, d, b) => {
    seen.push(Buffer.isBuffer(d) ? d.toString("utf8") : Array.isArray(d) ? Buffer.concat(d as Buffer[]).toString("utf8") : Buffer.from(d as ArrayBuffer).toString("utf8"));
    orig(c, d, b);
  };
});

afterAll(async () => {
  await r1?.close();
  await r2?.close();
  for (const u of users) u.cleanup();
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

describe("the code and its sealing", () => {
  it("100 bits as 20 Crockford characters, grouped; forgiving on input", () => {
    for (let i = 0; i < 50; i++) {
      const s = newCodeSecret();
      expect(s.length).toBe(13);
      expect(s[0]).toBeLessThan(16);
      const c = encodeCodeChars(s);
      expect(c).toMatch(/^[0-9A-HJKMNP-TV-Z]{20}$/);
      expect(decodeCodeChars(c)).toEqual(s);
    }
    const s = newCodeSecret();
    const grouped = formatShortCode(R1, s).split("/")[1];
    expect(grouped).toMatch(/^.{4}-.{4}-.{4}-.{4}-.{4}$/);
    expect(decodeCodeChars(grouped.toLowerCase().replace(/0/g, "o").replace(/1/g, "l"))).toEqual(s);
    expect(decodeCodeChars("ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ")).toEqual(new Uint8Array([15, ...new Array(12).fill(255)]));
    expect(decodeCodeChars("K7QM-3XPD-9TWA-HF2N")).toBeUndefined();
    expect(decodeCodeChars("U7QM-3XPD-9TWA-HF2N-6RJC")).toBeUndefined();
    expect(() => encodeCodeChars(new Uint8Array(13).fill(255))).toThrow(/100 bits/);
  });

  it("the relay part drops wss:// and a bare /v3, and parses back", () => {
    const s = newCodeSecret();
    expect(codeRelayPart("wss://relay.example/v3")).toBe("relay.example");
    expect(codeRelayPart("wss://relay.example:8443/v3")).toBe("relay.example:8443");
    expect(codeRelayPart("wss://relay.example/x/v3")).toBe("relay.example/x/v3");
    for (const relay of ["wss://relay.example/v3", "wss://relay.example:8443/v3", "wss://relay.example/x/v3", "wss://relay.example/custom"]) {
      const p = parseShortCode(formatShortCode(relay, s));
      expect(p.relay).toBe(relay);
      expect(p.secret).toEqual(s);
    }
    expect(parseShortCode(`p2p join ${formatShortCode(R1, s)}`).relay).toBe(R1);
    expect(parseShortCode(encodeCodeChars(s)).relay).toBeUndefined();
    expect(() => parseShortCode("relay.example/not-a-code")).toThrow(/not an invite code/);
  });

  it("opens only under the same code; a swapped or altered blob fails", () => {
    const s = newCodeSecret();
    const other = newCodeSecret();
    const blob = sealInviteBundle(s, { v: 1, invite: "a.b.c" });
    expect(parseInviteBundle(openInviteBundle(s, blob))).toEqual({ v: 1, invite: "a.b.c" });
    expect(() => openInviteBundle(other, blob)).toThrow(/altered or swapped/);
    expect(() => openInviteBundle(s, sealInviteBundle(other, { v: 1, invite: "evil" }))).toThrow(/altered or swapped/);
    const raw = Buffer.from(blob, "base64url");
    raw[20] ^= 1;
    expect(() => openInviteBundle(s, raw.toString("base64url"))).toThrow(/altered or swapped/);
    expect(inviteLid(s)).toMatch(/^[a-z2-7]{26}$/);
    expect(inviteLid(s)).not.toBe(inviteLid(other));
  });
});

describe("one-step invites", () => {
  let alice: User;
  let cid: string;

  beforeAll(async () => {
    alice = await setUp("alice");
    cid = (await alice.ok(["circle", "create", "team"])).cid;
    await alice.ok(["circle", "default", cid]);
  });

  it("join = friends + circle + default circle, in one command, with no identity beforehand; the inviter is told", async () => {
    const before = seen.length;
    const inv = await alice.ok(["invite", "grace"]);
    expect(inv).toMatchObject({ label: "grace", uses: 1, relay: R1, circle: { cid, name: "team" }, to: null });
    expect(inv.lid).toMatch(/^[a-z2-7]{26}$/);
    expect(inv.code).toMatch(/^codes-one\.test\/[0-9A-Z]{4}(-[0-9A-Z]{4}){4}$/);
    expect(inv.line).toBe(`Join me on Peer2Peer: https://ix-infra.com/p2p/invite#${inv.code} (or: p2p join ${inv.code})`);
    expect(inv.expiresAt).toBeGreaterThan(Date.now() / 1000 + 6.9 * 86_400);

    const grace = user("grace");
    // The inviter's client handles the accept while the joiner waits (e.g. a running mod).
    const j = await alongside(grace.run(["join", "--confirmed", inv.code, "--wait", "12", "--name", "grace"]), () => alice.ok(["invites"]));
    expect(j.code).toBe(0);
    expect(j.json).toMatchObject({ friend: { address: expect.stringMatching(/^alice@/) }, circle: { cid, name: "team", status: "joined", default: true }, defaultCircle: cid });
    expect(j.json.created).toMatchObject({ relays: [R1] });
    expect(j.json.from.fingerprint).toMatch(/^[a-z2-7]{4}-/);
    const graceId = j.json.created.userId as string;

    const list = (await alice.ok(["invites"])).invites;
    expect(list[0]).toMatchObject({ code: inv.code, label: "grace", status: "redeemed", redeemedBy: { userId: graceId } });
    expect((await alice.ok(["circle", "members", cid])).members.map((m: { userId: string }) => m.userId)).toContain(graceId);
    expect((await grace.ok(["friends"])).friends.map((f: { userId: string }) => f.userId)).toEqual([j.json.friend.userId]);
    expect((await grace.ok(["whoami"])).defaultCircle).toBe(cid);

    // The relay never saw the code secret, in any spelling.
    const s = parseShortCode(inv.code).secret;
    const chars = encodeCodeChars(s);
    const spellings = [chars, chars.toLowerCase(), inv.code.split("/")[1], b64uEncode(s), Buffer.from(s).toString("hex"), Buffer.from(s).toString("base64")];
    const frames = seen.slice(before).join("\n");
    expect(frames).toContain(inviteLid(s));
    for (const sp of spellings) expect(frames).not.toContain(sp);
  }, 60_000);

  it("with the inviter offline, the circle join finishes on the joiner's next command", async () => {
    // A circle of the owner alone: the owner's answer confirms it (§3.3).
    const solo = (await alice.ok(["circle", "create", "solo"])).cid as string;
    const inv = await alice.ok(["invite", "zed", "--circle", solo]);
    const zed = user("zed");
    const j = await zed.ok(["join", "--confirmed", inv.code, "--wait", "0"]);
    expect(j.circle).toMatchObject({ cid: solo, status: "pending", default: false });
    expect(j.defaultCircle).toBeNull();
    await alice.ok(["invites"]); // the inviter's client runs: zed is added
    const later = await zed.run(["circle", "ls"]);
    expect(later.err).toMatch(/joined "solo" \(from your code join\); it is your default circle/);
    expect(later.json.circles.find((c: { cid: string }) => c.cid === solo)).toMatchObject({ joined: true });
    expect((await zed.ok(["whoami"])).defaultCircle).toBe(solo);
  }, 60_000);

  it("a circle with other members keeps §3.3: unconfirmed needs the user's say (--yes, or held approve)", async () => {
    // "team" now lists alice and grace; grace is offline, so nobody but the owner can confirm it.
    const both = async (who: User, args: string[]) => {
      const r = await alongside(who.run(args), () => alice.ok(["invites"]));
      return r;
    };
    const pat = user("pat");
    const p = await both(pat, ["join", "--confirmed", (await alice.ok(["invite", "pat"])).code, "--wait", "8"]);
    expect(p.json.circle).toMatchObject({ cid, status: "needs-approval", default: false });
    expect(p.json.circle.held).toMatch(/^c/);
    const quinn = user("quinn");
    const q = await both(quinn, ["join", "--confirmed", (await alice.ok(["invite", "quinn"])).code, "--wait", "8", "--yes"]);
    expect(q.json.circle).toMatchObject({ cid, status: "joined", default: true });
  }, 60_000);

  it("a code works once; the redeemer can retry from what it fetched", async () => {
    const inv = await alice.ok(["invite", "--no-circle"]);
    expect(inv.circle).toBeNull();
    const bob = await setUp("bob");
    const first = await bob.ok(["join", "--confirmed", inv.code, "--wait", "0"]);
    expect(first.circle).toBeNull();
    // A retry by the same user is idempotent (no relay needed).
    expect((await bob.ok(["join", "--confirmed", inv.code, "--wait", "0"])).friend.userId).toBe(first.friend.userId);
    const carol = await setUp("carol");
    const r = await carol.run(["join", "--confirmed", inv.code]);
    expect(r.code).toBe(1);
    expect(r.json).toMatchObject({ error: "code_not_found" });
  }, 60_000);

  it("a wrong code finds nothing (and costs the guesser its miss budget)", async () => {
    const dave = await setUp("dave");
    const s = newCodeSecret();
    const r = await dave.run(["join", "--confirmed", formatShortCode(R1, s)]);
    expect(r.json).toMatchObject({ error: "code_not_found" });
    expect((await dave.ok(["friends"])).friends).toEqual([]);
  }, 30_000);

  it("a swapped blob is rejected and nothing is accepted", async () => {
    const a = await alice.ok(["invite", "--no-circle"]);
    const b = await alice.ok(["invite", "--no-circle"]);
    const store = r1.relay.store as unknown as { invites: Map<string, { blob: string }> };
    const la = inviteLid(parseShortCode(a.code).secret);
    const lb = inviteLid(parseShortCode(b.code).secret);
    const swap = store.invites.get(la)!.blob;
    store.invites.get(la)!.blob = store.invites.get(lb)!.blob;
    store.invites.get(lb)!.blob = swap;
    const erin = await setUp("erin");
    const r = await erin.run(["join", "--confirmed", a.code]);
    expect(r.json).toMatchObject({ error: "code_invalid" });
    expect((await erin.ok(["friends"])).friends).toEqual([]);
  }, 30_000);

  it("an expired code is gone", async () => {
    const inv = await alice.ok(["invite", "--no-circle", "--ttl-days", "1"]);
    clock.offset = 2 * 86_400_000;
    try {
      const f = await setUp("frank");
      expect((await f.run(["join", "--confirmed", inv.code])).json).toMatchObject({ error: "code_not_found" });
    } finally {
      clock.offset = 0;
    }
    expect((await alice.ok(["invite", "--ttl-days", "8"]).catch((e: Error) => e.message))).toMatch(/1\.\.7/);
  }, 30_000);

  it("--to binds the code: anyone else is refused, and the inviter sees it was taken", async () => {
    const gus = await setUp("gus");
    const gusId = (await gus.ok(["whoami"])).userId as string;
    const hal = await setUp("hal");
    const inv = await alice.ok(["invite", "for-gus", "--to", gusId, "--no-circle"]);
    expect(inv.to).toMatchObject({ userId: gusId });
    const r = await hal.run(["join", "--confirmed", inv.code]);
    expect(r.json).toMatchObject({ error: "not_for_you" });
    expect((await hal.ok(["friends"])).friends).toEqual([]);
    const row = (await alice.ok(["invites"])).invites.find((x: { code: string }) => x.code === inv.code);
    expect(row.status).toBe("taken");
  }, 30_000);

  it("an intercepted code: the inviter is told who joined, and `p2p remove` undoes it", async () => {
    const inv = await alice.ok(["invite", "ivan"]);
    const mallory = await setUp("mallory");
    const m = await mallory.ok(["join", "--confirmed", inv.code, "--wait", "0"]);
    const malloryId = (await mallory.ok(["whoami"])).userId as string;
    expect(m.circle).toMatchObject({ cid, status: "pending" });
    const seenBy = await alice.run(["invites"]);
    expect(seenBy.err).toMatch(/mallory@.* joined via your code .{4}… \("ivan"\) and was added to "team"\. Not who you meant\? p2p remove p2p:/);
    expect(seenBy.json.invites.find((x: { code: string }) => x.code === inv.code)).toMatchObject({ status: "redeemed", redeemedBy: { userId: malloryId } });
    // The event the mod shows.
    const app = await alice.app();
    await app.load();
    const ev = ((await app.state.get("events"))?.items ?? []).find((e) => e.kind === "p2p.joined" && (e.data.from as { userId: string }).userId === malloryId);
    expect(ev?.data).toMatchObject({ label: "ivan", cid, circleName: "team", remove: `p2p remove ${malloryId}` });
    // The exact, non-secret code id: the same lid `p2p invite --json` printed, derived from the code.
    expect(inv.lid).toBe(inviteLid(parseShortCode(inv.code).secret));
    expect(ev?.data.lid).toBe(inv.lid);
    expect(JSON.stringify(ev?.data)).not.toContain(inv.code.split("/")[1]);

    const rm = await alice.ok(["remove", malloryId]);
    expect(rm).toMatchObject({ removed: malloryId, unfriended: true, circles: [{ cid, result: "removed" }] });
    expect((await alice.ok(["circle", "members", cid])).members.map((x: { userId: string }) => x.userId)).not.toContain(malloryId);
    expect((await alice.ok(["friends"])).friends.map((f: { userId: string }) => f.userId)).not.toContain(malloryId);
    // Ivan, too late:
    const ivan = await setUp("ivan");
    expect((await ivan.run(["join", "--confirmed", inv.code])).json).toMatchObject({ error: "code_not_found" });
  }, 60_000);

  it("a revoked code is gone from the relay, and a copy taken before the revoke is refused", async () => {
    const open = await alice.ok(["invite", "--no-circle"]);
    const rv = await alice.ok(["invites", "revoke", open.code]);
    expect(rv).toMatchObject({ revoked: true, wasOpen: true });
    const judy = await setUp("judy");
    expect((await judy.run(["join", "--confirmed", open.code])).json).toMatchObject({ error: "code_not_found" });

    // An interceptor fetches the bundle, waits for the revoke, then accepts.
    const taken = await alice.ok(["invite", "--no-circle"]);
    const { secret } = parseShortCode(taken.code);
    const conn = await openLinkConnection(R1, (await judy.app()).transport, 3000);
    const blob = (await inviteGet(conn, inviteLid(secret)))!;
    conn.close();
    const bundle = parseInviteBundle(openInviteBundle(secret, blob));
    expect((await alice.ok(["invites", "revoke", taken.code.split("/")[1].slice(0, 4)])).wasOpen).toBe(false);
    const mapp = await judy.app();
    await mapp.load();
    receiving(mapp);
    try {
      await accept(mapp, bundle.invite).catch(() => undefined);
    } finally {
      await mapp.close();
    }
    const judyId = (await judy.ok(["whoami"])).userId;
    const after = await alice.run(["friends"]);
    expect(after.json.friends.map((f: { userId: string }) => f.userId)).not.toContain(judyId);
  }, 60_000);

  it("per-IP limits on invite-get stop guessing", async () => {
    const lim = await startRelay("wss://codes-limit.test/v3", { limits: { inviteMissesPerIpPerHour: 3 } });
    try {
      const k = new User("guesser", { ...t, "wss://codes-limit.test/v3": `ws://127.0.0.1:${lim.port}/v3` }, { P2P_DEFAULT_RELAYS: R1 });
      users.push(k);
      await k.ok(["setup", "--no-backup"]);
      const codes: string[] = [];
      for (let i = 0; i < 4; i++) codes.push(formatShortCode("wss://codes-limit.test/v3", newCodeSecret()));
      for (let i = 0; i < 3; i++) expect((await k.run(["join", "--confirmed", codes[i]])).json).toMatchObject({ error: "code_not_found" });
      expect((await k.run(["join", "--confirmed", codes[3]])).json).toMatchObject({ error: "rate_limited" });
    } finally {
      await lim.close();
    }
  }, 30_000);
});

describe("pre-release review", () => {
  it("M1: with no default relays, the code's relay is the only one, with a loud warning; `relays add|remove` fix it", async () => {
    const nd = user("nodefaults", { P2P_DEFAULT_RELAYS: "", P2P_DEFAULTS_FILE: join(tmpdir(), "p2p-no-such-defaults.json") });
    const inviter = await setUp("m1-inviter");
    const inv = await inviter.ok(["invite", "--no-circle"]);
    const j = await nd.run(["join", "--confirmed", inv.code, "--wait", "0"]);
    expect(j.code).toBe(0);
    expect(j.json.created.relays).toEqual([R1]);
    expect(j.json.relayWarning).toBe("codes-one.test");
    expect(j.err).toMatch(/Your only relay is codes-one\.test, chosen by whoever gave you this code.*p2p relays add/);
    expect((await nd.ok(["relays"])).relays).toEqual([R1]);
    await inviter.ok(["friends"]); // the inviter handles the accept: it now holds nd's friend cap (for R1)
    const ndc = (await nd.ok(["circle", "create", "ndc"])).cid as string;
    const added = await nd.ok(["relays", "add", R2]);
    expect(added).toMatchObject({ relays: [R1, R2], ver: 2, capsReissued: 1, rejoined: [ndc] });
    expect(added.published.sort()).toEqual([R1, R2]);
    // pre-release follow-up L5: after dropping R1, friends hold a cap for R2, and our join names R2.
    const removed = await nd.ok(["relays", "remove", R1]);
    expect(removed).toMatchObject({ relays: [R2], ver: 3, capsReissued: 1, rejoined: [ndc] });
    expect((await nd.run(["relays", "remove", R2])).json).toMatchObject({ error: "usage" });
    expect((await nd.ok(["whoami"])).relays).toEqual([R2]);
    const ndId = j.json.created.userId as string;
    await inviter.ok(["friends"]);
    const iapp = await inviter.app();
    await iapp.load();
    expect((await iapp.store.listCapsHeld(ndId)).map((c) => c.relays)).toContainEqual([R2]);
    expect([...(await iapp.capsFor(ndId, "msg")).keys()]).toContain(R2);
    await iapp.close();
    const napp = await nd.app();
    await napp.load();
    const mine = (await napp.store.getCircle(ndc))!.statements[ndId];
    expect(capPeek(joinCapOf(mine.jws)!)!.relays).toEqual([R2]);
    // review L2: every old cap naming R1 (friend and join caps) was revoked at R1 only; R2 still honours them.
    const old = (await napp.store.listCapsIssued()).filter((c) => c.relays.includes(R1));
    expect(old.length).toBeGreaterThanOrEqual(3);
    expect(removed.revokedAtRemoved).toBe(old.length);
    const revokedAt = (t: TestRelay, capid: string) => {
      const relay = t.relay as unknown as { capKey: (iss: string, capid: string) => string };
      return t.relay.store.capState(relay.capKey(ndId, capid)).revoked;
    };
    for (const c of old) {
      expect(revokedAt(r1, c.capid)).toBe(true);
      if (c.relays.includes(R2)) expect(revokedAt(r2, c.capid)).toBe(false);
    }
    await napp.close();
  }, 60_000);

  it("M1/L1: with default relays, only the defaults are used (no warning); the inviter is still reachable", async () => {
    const wd = user("withdefaults", { P2P_DEFAULT_RELAYS: R2 });
    const inviter = await setUp("m1-inviter2");
    const j = await wd.run(["join", "--confirmed", (await inviter.ok(["invite", "--no-circle"])).code, "--wait", "0"]);
    expect(j.json.created.relays).toEqual([R2]);
    expect(j.json.relayWarning).toBeUndefined();
    expect(j.err).not.toMatch(/Your only relay/);
    expect(j.json.delivered.relays).toEqual([R1]);
    const list = (await inviter.ok(["invites"])).invites;
    expect(list[0]).toMatchObject({ status: "redeemed" });
  }, 60_000);

  it("review L1: re-signing joins after a relay change never reaches a blocked member", async () => {
    const o = await setUp("blk-owner");
    const solo = (await o.ok(["circle", "create", "blk"])).cid as string;
    const inv = await o.ok(["invite", "--circle", solo]);
    const m = user("blk-member");
    const j = await alongside(m.run(["join", "--confirmed", inv.code, "--wait", "12", "--name", "blkm"]), () => o.ok(["invites"]));
    expect(j.json.circle).toMatchObject({ cid: solo, status: "joined" });
    const oId = j.json.friend.userId as string;
    const mId = j.json.created.userId as string;
    await o.ok(["circle", "members", solo]);
    await o.ok(["block", mId]);
    const nOf = async () => {
      await m.ok(["circle", "ls"]);
      const a = await m.app();
      await a.load();
      const st = (await a.store.getCircle(solo))!.statements[oId];
      await a.close();
      return st ? st.n : -1;
    };
    const before = await nOf();
    const added = await o.ok(["relays", "add", R2]);
    expect(added.rejoined).toEqual([solo]);
    // The owner re-signed (n went up on its side), but the blocked member never received it.
    const oa = await o.app();
    await oa.load();
    expect((await oa.store.getCircle(solo))!.statements[oId].n).toBeGreaterThan(before);
    await oa.close();
    expect(await nOf()).toBe(before);
  }, 60_000);

  it("follow-up L2: a code the relay evicted (full store) shows as evicted, not taken", async () => {
    const LR = "wss://codes-evict.test/v3";
    const lr = await startRelay(LR, { limits: { inviteYoungIdentitySec: 0, inviteBytesPerIp: 10_000_000 } });
    try {
      const ev = new User("evictee", { ...t, [LR]: `ws://127.0.0.1:${lr.port}/v3` }, { P2P_DEFAULT_RELAYS: LR });
      users.push(ev);
      await ev.ok(["setup", "--no-backup"]);
      const a = await ev.ok(["invite", "--no-circle", "first"]);
      const size = lr.relay.store.inviteBytes();
      // Room for one and a half codes: the second put evicts the biggest holder's newest (the first).
      (lr.relay.config.limits as { inviteTotalBytes: number }).inviteTotalBytes = Math.floor(size * 1.5);
      const b = await ev.ok(["invite", "--no-circle", "second"]);
      const rows = (await ev.ok(["invites"])).invites;
      expect(rows.find((x: { code: string }) => x.code === a.code)).toMatchObject({ status: "evicted" });
      expect(rows.find((x: { code: string }) => x.code === b.code)).toMatchObject({ status: "open" });
    } finally {
      await lr.close();
    }
  }, 30_000);

  it("L2: the open -> redeemed flip is a compare-and-set: concurrent handlers act once", async () => {
    const owner = await setUp("cas");
    const app = await owner.app();
    await app.load();
    const rec = { lid: "a".repeat(26), code: "AAAA-AAAA-AAAA-AAAA-AAAA", short: "x/AAAA", relay: R1, inv: "inv", aud: "*", createdAt: 1, exp: 2e9, status: "open" as const };
    await app.state.put("codes", { [rec.lid]: rec });
    const from = { userId: "p2p:x", did: "d", address: "x@y", self: false };
    const lines: string[] = [];
    (app.io as { err: (s: string) => void }).err = (s) => lines.push(s);
    const [a, b] = await Promise.all([onCodeRedeemed(app, "env1", 1, from, rec, "p2p:x"), onCodeRedeemed(app, "env2", 1, from, rec, "p2p:x")]);
    expect([a.length, b.length].sort()).toEqual([0, 1]);
    expect(lines.filter((l) => l.includes("joined via your code"))).toHaveLength(1);
    expect((await app.state.get("codes"))![rec.lid]).toMatchObject({ status: "redeemed", redeemedBy: "p2p:x" });
    await app.close();
  }, 30_000);
});

describe("setup", () => {
  it("is idempotent, takes the shipped defaults.json, and saves the phrase 0600 only when asked", async () => {
    const dir = mkdtempSync(join(tmpdir(), "p2p-defaults-"));
    dirs.push(dir);
    writeFileSync(join(dir, "defaults.json"), JSON.stringify({ defaultRelays: [R2] }));
    const u = new User("setup", t, { P2P_DEFAULTS_FILE: join(dir, "defaults.json") });
    users.push(u);
    const first = await u.ok(["setup", "--name", "Kim!", "--no-backup"]).catch((e: Error) => e.message);
    expect(first).toMatch(/--name/);
    const withErr = await u.run(["setup", "--backup-file"]);
    expect(withErr.err).toMatch(/backup file is on this same device.*password manager/);
    const r = withErr.json;
    expect(r).toMatchObject({ created: true, relays: [R2] });
    expect(r.address).toMatch(/@/);
    expect(r.backup.phrase).toBeUndefined();
    expect(statSync(r.backup.file).mode & 0o777).toBe(0o600);
    expect(readFileSync(r.backup.file, "utf8").trim().split(/\s+/)).toHaveLength(24);
    const again = await u.ok(["setup"]);
    expect(again).toMatchObject({ created: false, userId: r.userId });
    expect(again.backup).toBeUndefined();
    // Never overwrites a phrase file.
    expect((await u.run(["setup", "--backup-file"])).json).toMatchObject({ error: "exists" });
    const printed = await u.ok(["setup", "--print-backup"]);
    expect(printed.backup.phrase.split(" ")).toHaveLength(24);
  }, 30_000);

  it("positional arguments after `--`, and --version", async () => {
    const u = await setUp("dash");
    const lines = { out: [] as string[], err: [] as string[] };
    const code = await main(["invite", "--json", "--no-circle", "--", "--odd-label"], { env: u.env, io: u.io(lines) });
    expect(code).toBe(0);
    expect(JSON.parse(lines.out.at(-1)!)).toMatchObject({ label: "--odd-label" });
    expect(await main(["--version"], { env: u.env, io: u.io({ out: [], err: [] }) })).toBe(0);
  }, 30_000);
});
