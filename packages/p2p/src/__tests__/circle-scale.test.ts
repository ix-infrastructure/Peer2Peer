// Copyright 2026 Ix Infrastructure Inc.
//
// A stranger joining an open circle with a long history (100+ members, 10+
// versions), end to end over an in-process relay, and the abuse limits on
// answering strangers.
//
// The chain is far over the 64 KiB envelope cap. The old answer, one `contact`
// envelope carrying the whole chain, could never be sent, so the join waited
// for good. The stranger's `want` now carries an answer cap for the owner
// (§3.3, draft 3 amendment), and the answer comes as ordinary chunked `circle`
// bundles.

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  applyCircleBundle,
  createCap,
  createNextCircleVersion,
  freshnessLookup,
  generateIdentityKey,
  jwsHash,
  loadCircle,
  nowSec,
} from "@peer2peer/core/v3";
import { App, joinCapOf } from "../app.js";
import { ANSWERS_PER_ASKER_PER_HOUR, answerComplete, answerParts, chargeAnswer, contiguousTop, MAX_ANSWER_ASKERS, MAX_POOL_ENTRIES, noteRefused, parseCircleLink } from "../circle-ops.js";
import { SYNC_CHUNK_BYTES } from "../sync.js";
import { RelayConnection } from "../relay-client.js";
import { checkWantPow, solveWantPow, WANT_POW_WINDOW_SEC } from "../want-pow.js";
import { alongside, startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-circle-scale.test/v3";
let relay: TestRelay;
let t: Record<string, string>;
const users: User[] = [];
const ids: Record<string, string> = {};
let owner: User;
let cid = "";
let link = "";
let chainBytes = 0;
let joined: User | undefined;

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

/** Publishes `n` more versions on the owner's device, each listing `per` more (made-up) members. */
async function grow(n: number, first: number, per: number): Promise<void> {
  const a = await ownerApp();
  const ik = a.requireKeyholder("test");
  const opts = { ...a.signerCtx(), self: a.userId, identityFreshness: await freshnessLookup(a.store) };
  for (let i = 0; i < n; i++) {
    const c = (await loadCircle(a.store, cid))!;
    const add = Array.from({ length: i === 0 ? first : per }, () => generateIdentityKey().userId);
    const v = createNextCircleVersion(ik, c.chain.head, { members: [...c.chain.head.members, ...add] });
    const res = await applyCircleBundle(a.store, { circles: [v], joins: [], ops: [] }, opts);
    expect(res.versions[cid]?.[0]?.status).toBe("accepted");
  }
  await a.close();
}

/** Sends the owner `want`s for the circle from `who`, the way an asker's client does (programmatically, to count). */
type Extra = { link?: string; pow?: (a: App) => { at: number; nonce: string } | undefined };
async function sendWants(who: User, n: number, cap: (a: App, ownerId: string) => string | undefined, extra: Extra = {}): Promise<string> {
  const a = await who.app();
  await a.load();
  const { hint } = parseCircleLink(link);
  await a.refreshIdentity(ids.own, App.relaysOf(hint!.doc!), { force: true });
  const extraCaps = [joinCapOf(hint!.join!)!];
  for (let i = 0; i < n; i++) {
    const c = cap(a, ids.own);
    const d = await a.deliver(ids.own, "circle", { own: a.userId, sid: "~circle" }, { want: { cid, fromVer: 1 }, ...(c ? { cap: c } : {}), ...(extra.link ? { link: extra.link } : {}), ...(extra.pow?.(a) ? { pow: extra.pow(a) } : {}) }, { extraCaps });
    expect(d.relays.length).toBeGreaterThan(0);
  }
  const did = a.did!;
  await a.close();
  return did;
}

const answerCap = (a: App, sub: string) => createCap(a.device!, a.keys!.cert, { purpose: "answer", sub, relays: a.relays, ttlSec: 3600 });

beforeAll(async () => {
  // Every test user shares 127.0.0.1, and the owner looks up each made-up member when it
  // distributes a version: more document fetches from one IP than a relay allows by default.
  relay = await startRelay(R, { limits: { httpPerIpPerMinute: 100_000, connectsPerIpPerMinute: 100_000, authsPerIpPerMinute: 100_000, authsPerIpv4PerMinute: 100_000, identityPublishPerIpPerHour: 100_000, newDevicesPerIpPerDay: 100_000, newDevicesPerIpv4PerDay: 100_000 } });
  t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
  owner = await user("own");
  cid = (await owner.ok(["circle", "create", "big", "--open"])).cid;
  // 11 more versions: 100 members, then 2 more each time (12 versions, 121 members at the head).
  await grow(11, 100, 2);
  link = (await owner.ok(["circle", "invite", cid, "--link"])).link;
  const a = await ownerApp();
  const c = (await loadCircle(a.store, cid))!;
  expect(c.chain.head.ver).toBe(12);
  expect(c.chain.head.members.length).toBe(121);
  chainBytes = c.chain.versionsFrom(1).reduce((n, v) => n + v.length, 0);
  await a.close();
}, 60_000);

afterEach(() => vi.restoreAllMocks());

afterAll(async () => {
  await relay?.close();
  for (const u of users) u.cleanup();
});

describe("a stranger joins an open circle with a long history", () => {
  it("121 members, 12 versions: far over one envelope, joined end to end", async () => {
    // Well past the 64 KiB envelope cap, several 30 KiB chunks.
    expect(chainBytes).toBeGreaterThan(3 * SYNC_CHUNK_BYTES);
    const s = await user("stranger");
    joined = s;
    // The owner's client keeps handling deliveries while the stranger joins (as `watch` would).
    const revoked: string[] = [];
    const rv = App.prototype.revokeCaps;
    vi.spyOn(App.prototype, "revokeCaps").mockImplementation(function (this: App, caps) {
      if (this.userId === ids.stranger) revoked.push(...caps.map((c) => c.capid));
      return rv.call(this, caps);
    });
    const r = await alongside(s.run(["circle", "join", link, "--wait", "6", "--yes"]), () => owner.run(["invites"]));
    expect(r.code, r.err).toBe(0);
    expect(r.json).toMatchObject({ cid, status: "joined" });
    // L1: the answer cap it gave the owner is revoked once the join is done, and no longer kept.
    expect(revoked.length).toBeGreaterThan(0);
    const sa0 = await s.app();
    await sa0.load();
    const left = (await sa0.store.listCapsIssued()).filter((c) => revoked.includes(c.capid));
    await sa0.close();
    expect(left).toEqual([]);
    vi.restoreAllMocks();
    // The owner auto-accepted the join (open policy) and published the version that lists them.
    const a = await ownerApp();
    for (let i = 0; i < 20 && !(await loadCircle(a.store, cid))!.chain.head.members.includes(ids.stranger); i++) await owner.run(["invites"]);
    const head = (await loadCircle(a.store, cid))!.chain.head;
    await a.close();
    expect(head.members).toContain(ids.stranger);
    expect(head.ver).toBe(13);
    // The stranger holds the whole chain.
    const sa = await s.app();
    await sa.load();
    const mine = await loadCircle(sa.store, cid);
    await sa.close();
    expect(mine?.chain.versionsFrom(1).length).toBeGreaterThanOrEqual(12);
  }, 60_000);
});

describe("answering strangers is bounded", () => {
  it("one stranger asking over and over: one answer and one resend an hour, then nothing", async () => {
    const s = await user("pest");
    await sendWants(s, 5, (a, o) => answerCap(a, o));
    const r = await owner.run(["invites"]);
    expect(r.code).toBe(0);
    // (The head is 13 once the stranger above joined.)
    const refusals = r.err.split("\n").filter((l) => /already sent them this circle up to version 1[23] this hour/.test(l));
    expect(refusals.length).toBe(3);
    const a = await ownerApp();
    const doc = await a.state.get("wantAnswers");
    expect(doc?.by[ids.pest]?.length).toBe(2);
    expect(doc?.last[`${ids.pest}|${cid}`]).toMatchObject({ ver: expect.any(Number), resent: true });
    expect(doc!.last[`${ids.pest}|${cid}`].ver).toBeGreaterThanOrEqual(12);
    await a.close();
  }, 60_000);

  it("M1: a member (one who joined a moment ago) is limited exactly like a stranger", async () => {
    expect(joined).toBeDefined();
    await sendWants(joined!, 5, (a, o) => answerCap(a, o));
    const r = await owner.run(["invites"]);
    // Whatever it was sent when it joined, five more asks for the same head get one answer and one
    // resend at most, and the rest are refused (as for a stranger).
    const refusals = r.err.split("\n").filter((l) => /not answering .*(already answered them \d+ times|already sent them this circle up to version)/.test(l));
    expect(refusals.length).toBeGreaterThanOrEqual(2);
    const a = await ownerApp();
    expect((await a.state.get("wantAnswers"))?.by[ids.stranger]?.length).toBeLessThanOrEqual(3);
    await a.close();
  }, 60_000);

  it("a want without a usable answer cap gets no oversized first-contact answer", async () => {
    const s = await user("oldclient");
    // No cap (an older client), and a cap that isn't for the owner (someone else's).
    await sendWants(s, 1, () => undefined);
    await sendWants(s, 1, (a) => answerCap(a, generateIdentityKey().userId));
    const r = await owner.run(["invites"]);
    const lines = r.err.split("\n").filter((l) => l.includes("too long for one first-contact envelope"));
    expect(lines.length).toBe(2);
    const a = await ownerApp();
    // Refused before anything was counted or sent.
    expect((await a.state.get("wantAnswers"))?.by[ids.oldclient]).toBeUndefined();
    await a.close();
  }, 60_000);

  it("per-asker count and bytes for everyone, a shared pool for non-members; an hour later it is back", async () => {
    const a = new App({ env: { ...owner.env, P2P_STRANGER_ANSWER_BYTES_PER_HOUR: "1000", P2P_ANSWER_BYTES_PER_ASKER_PER_HOUR: "700" }, io: { out: () => {}, err: () => {} } });
    await a.load();
    await a.state.update("wantAnswers", () => ({ next: { by: {}, bytes: {}, sent: [], last: {} }, result: undefined }));
    expect(await chargeAnswer(a, "p2p:a", "reserve", 600)).toMatchObject({ ok: true });
    // The non-member pool has 400 left; b may send up to that.
    expect(await chargeAnswer(a, "p2p:b", "reserve", 500)).toMatchObject({ ok: false, why: expect.stringContaining("over what is left") });
    expect(await chargeAnswer(a, "p2p:b", "reserve", 400)).toMatchObject({ ok: true });
    expect(await chargeAnswer(a, "p2p:c", "reserve", 1)).toMatchObject({ ok: false, why: expect.stringContaining("non-members (1000 bytes) is spent") });
    // A member isn't in the pool, but has its own byte budget and count.
    expect(await chargeAnswer(a, "p2p:m", "member", 700)).toMatchObject({ ok: true });
    expect(await chargeAnswer(a, "p2p:m", "member", 1)).toMatchObject({ ok: false, why: expect.stringContaining("answering them (700 bytes)") });
    const real = Date.now.bind(Date);
    vi.spyOn(Date, "now").mockImplementation(() => real() + 3_600_001);
    for (let i = 0; i < ANSWERS_PER_ASKER_PER_HOUR; i++) expect(await chargeAnswer(a, "p2p:m", "member", 1)).toMatchObject({ ok: true });
    expect(await chargeAnswer(a, "p2p:m", "member", 1)).toMatchObject({ ok: false, why: expect.stringContaining(`${ANSWERS_PER_ASKER_PER_HOUR} times this hour`) });
    await a.close();
  });

  it("N2: all of a circle's members together share one hourly pool", async () => {
    const a = new App({ env: { ...owner.env, P2P_MEMBER_ANSWER_BYTES_PER_CIRCLE_PER_HOUR: "1000" }, io: { out: () => {}, err: () => {} } });
    await a.load();
    await a.state.update("wantAnswers", () => ({ next: { by: {}, bytes: {}, sent: [], last: {} }, result: undefined }));
    const m = (i: number, c = "c_one") => chargeAnswer(a, `p2p:member${i}`, "member", 400, { cid: c, ver: 1, resent: false });
    expect(await m(1)).toMatchObject({ ok: true });
    expect(await m(2)).toMatchObject({ ok: true });
    // Twenty fresh members can't each take their own budget: the circle's pool is spent.
    expect(await m(3)).toMatchObject({ ok: false, why: expect.stringContaining("over what is left") });
    expect(await chargeAnswer(a, "p2p:member3", "member", 200, { cid: "c_one", ver: 1, resent: false })).toMatchObject({ ok: true });
    expect(await m(4)).toMatchObject({ ok: false, why: expect.stringContaining("this circle's members (1000 bytes) is spent") });
    // Another circle's members have their own.
    expect(await m(5, "c_two")).toMatchObject({ ok: true });
    await a.close();
  });

  it("a member who leaves and joins again four times in an hour is answered each time (pre-release soak, seed 21)", async () => {
    const a = new App({ env: owner.env, io: { out: () => {}, err: () => {} } });
    await a.load();
    await a.state.update("wantAnswers", () => ({ next: { by: {}, bytes: {}, sent: [], last: {} }, result: undefined }));
    // Each join needs an answer, each for a newer head (the version that dropped or re-added it).
    for (let i = 0; i < 4; i++) expect(await chargeAnswer(a, "p2p:rejoiner", "member", 1000, { cid: "c_x", ver: 5 + i, resent: false })).toMatchObject({ ok: true });
    await a.close();
  });

  it("M2: the reserve and a small pool of its own for non-members without proof of work", async () => {
    const a = new App({ env: { ...owner.env, P2P_STRANGER_ANSWER_BYTES_PER_HOUR: "1000", P2P_UNLINKED_ANSWER_BYTES_PER_HOUR: "300" }, io: { out: () => {}, err: () => {} } });
    await a.load();
    await a.state.update("wantAnswers", () => ({ next: { by: {}, bytes: {}, sent: [], last: {} }, result: undefined }));
    // Identities that know only the circle id spend their own pool...
    expect(await chargeAnswer(a, "p2p:x1", "open", 300)).toMatchObject({ ok: true });
    expect(await chargeAnswer(a, "p2p:x2", "open", 1)).toMatchObject({ ok: false, why: expect.stringContaining("whose want carries no proof of work (300 bytes)") });
    // ...and the link-holders' reserve is untouched.
    expect(await chargeAnswer(a, "p2p:l1", "reserve", 1000)).toMatchObject({ ok: true });
    await a.close();
  });

  it("M2 + L2: the answer goes to the asking device only, charged once at its sealed size per relay", async () => {
    const s = await user("onedev");
    const deliver = App.prototype.deliver;
    const seen: { to: string; only?: readonly string[] }[] = [];
    vi.spyOn(App.prototype, "deliver").mockImplementation(function (this: App, ...args: Parameters<App["deliver"]>) {
      if (args[1] === "circle" && args[0] === ids.onedev) seen.push({ to: args[0], only: args[4]?.onlyDevices });
      return deliver.apply(this, args);
    });
    const did = await sendWants(s, 1, (a, o) => answerCap(a, o), { pow: (a) => solveWantPow(a.userId, ids.own, cid, 1, nowSec()) });
    await owner.run(["invites"]);
    expect(seen.length).toBeGreaterThan(1);
    for (const x of seen) expect(x.only).toEqual([did]);
    const a = await ownerApp();
    const doc = await a.state.get("wantAnswers");
    await a.close();
    const charged = doc!.bytes[ids.onedev].reduce((n, x) => n + x.bytes, 0);
    // Sealed: about 16/9 of the plaintext plus ~3 KiB an envelope (one relay here).
    expect(charged).toBeGreaterThan((chainBytes * 16) / 9);
    expect(doc!.sent.at(-1)).toMatchObject({ pool: "reserve", bytes: charged });
  }, 60_000);

  it("N3: a public ancestor hash buys nothing; a fresh proof of work does, once", async () => {
    const s = await user("powless");
    const { head } = parseCircleLink(link);
    // `link` (any hash on the chain: `prev`, join statements' `at`) is public: the small pool.
    await sendWants(s, 1, (a, o) => answerCap(a, o), { link: jwsHash(head) });
    await owner.run(["invites"]);
    let a = await ownerApp();
    expect((await a.state.get("wantAnswers"))!.sent.at(-1)).toMatchObject({ pool: "open" });
    await a.close();
    // A valid proof: the reserve. The same proof again (a replay, from anyone): the small pool.
    const p = await user("powful");
    const proofAt = nowSec();
    let proof: { at: number; nonce: string } | undefined;
    await sendWants(p, 2, (x, o) => answerCap(x, o), { pow: (x) => (proof ??= solveWantPow(x.userId, ids.own, cid, 1, proofAt)) });
    await owner.run(["invites"]);
    a = await ownerApp();
    const doc = (await a.state.get("wantAnswers"))!;
    await a.close();
    // Whichever of the two wants is handled first (their arrival order varies) gets the reserve.
    const mine = doc.sent.slice(-2).map((x) => x.pool).sort();
    expect(mine).toEqual(["open", "reserve"]);
    // Stale or wrong proofs don't count.
    expect(checkWantPow(proof, ids.powful, ids.own, cid, 1, proofAt + WANT_POW_WINDOW_SEC + 1)).toBeUndefined();
    expect(checkWantPow(proof, ids.powful, ids.own, cid, 2, proofAt)).toBeUndefined();
    expect(checkWantPow(proof, ids.powless, ids.own, cid, 1, proofAt)).toBeUndefined();
    // F1: bound to the member asked: the same proof is worth nothing at another member.
    expect(checkWantPow(proof, ids.powful, ids.stranger, cid, 1, proofAt)).toBeUndefined();
    expect(checkWantPow(proof, ids.powful, ids.own, cid, 1, proofAt)).toMatch(/^[0-9a-f]{64}$/);
  }, 60_000);

  it("N-A: an answer whose last part a relay drops is charged for what went out, not refunded", async () => {
    const s = await user("dropper");
    const deliver = App.prototype.deliver;
    let parts = 0;
    vi.spyOn(App.prototype, "deliver").mockImplementation(async function (this: App, ...args: Parameters<App["deliver"]>) {
      const pt = args[3] as { part?: { i: number; n: number } };
      if (args[1] === "circle" && args[0] === ids.dropper && pt.part) {
        parts = pt.part.n;
        // The asker's own relay takes every part but the last.
        if (pt.part.i === pt.part.n) return { userId: args[0], devices: 1, relays: [] };
      }
      return deliver.apply(this, args);
    });
    await sendWants(s, 1, (a, o) => answerCap(a, o));
    await owner.run(["invites"]);
    expect(parts).toBeGreaterThan(2);
    const a = await ownerApp();
    const doc = (await a.state.get("wantAnswers"))!;
    await a.close();
    const charged = (doc.bytes[ids.dropper] ?? []).reduce((n, x) => n + x.bytes, 0);
    // Most of the chain went out: most of it stays charged (sealed, one relay here), and the pool
    // the asker drew on is spent by the same amount.
    expect(charged).toBeGreaterThan(((chainBytes * 16) / 9) * ((parts - 2) / parts));
    expect(doc.sent.at(-1)?.bytes).toBe(charged);
    // Not marked as sent: the asker may ask for the rest.
    expect(doc.last[`${ids.dropper}|${cid}`]).toBeUndefined();
  }, 60_000);

  it("P1: a relay that stores every part but answers an error still leaves the asker charged", async () => {
    const s = await user("liar");
    const request = RelayConnection.prototype.request;
    let lied = 0;
    vi.spyOn(RelayConnection.prototype, "request").mockImplementation(async function (this: RelayConnection, frame, ms) {
      const r = await request.call(this, frame, ms);
      // The asker's relay keeps the part (the real reply was `sent`) and says it didn't.
      if (frame.t === "send" && frame.to === ids.liar && r.t === "sent") {
        lied++;
        return { t: "error", id: r.id, code: "undeliverable" };
      }
      return r;
    });
    await sendWants(s, 1, (a, o) => answerCap(a, o));
    await owner.run(["invites"]);
    expect(lied).toBeGreaterThan(2);
    const a = await ownerApp();
    const doc = (await a.state.get("wantAnswers"))!;
    await a.close();
    const charged = (doc.bytes[ids.liar] ?? []).reduce((n, x) => n + x.bytes, 0);
    // Every part went out on the wire: the whole answer stays charged (sealed, one relay here).
    expect(charged).toBeGreaterThan((chainBytes * 16) / 9);
    expect(doc.sent.at(-1)?.bytes).toBe(charged);
  }, 60_000);

  it("N-B: the answer records stay bounded (newest kept, pools folded, not freed); a repeat refusal rewrites nothing", async () => {
    const a = new App({ env: owner.env, io: { out: () => {}, err: () => {} } });
    await a.load();
    const now = Date.now();
    const n = MAX_ANSWER_ASKERS + 100;
    const by: Record<string, number[]> = {};
    const bytes: Record<string, { at: number; bytes: number }[]> = {};
    const last: Record<string, { ver: number; at: number }> = {};
    const refused: Record<string, number> = {};
    const sent: { at: number; bytes: number; pool: "open" }[] = [];
    for (let i = 0; i < n; i++) {
      const at = now - 1_000_000 + i;
      by[`p2p:a${i}`] = [at];
      bytes[`p2p:a${i}`] = [{ at, bytes: 1 }];
      last[`p2p:a${i}|c_x`] = { ver: 1, at };
      refused[`p2p:a${i}|c_x`] = at;
    }
    for (let i = 0; i < MAX_POOL_ENTRIES + 50; i++) sent.push({ at: now - 1_000_000 + i, bytes: 2, pool: "open" });
    await a.state.update("wantAnswers", () => ({ next: { by, bytes, sent, last, refused }, result: undefined }));
    // Any update rewrites the document pruned.
    expect(await chargeAnswer(a, "p2p:newest", "member", 1, { cid: "c_y", ver: 1, resent: false })).toMatchObject({ ok: true });
    const doc = (await a.state.get("wantAnswers"))!;
    expect(Object.keys(doc.by).length).toBeLessThanOrEqual(MAX_ANSWER_ASKERS);
    expect(doc.by["p2p:newest"]).toBeDefined();
    expect(doc.by[`p2p:a${n - 1}`]).toBeDefined();
    expect(doc.by["p2p:a0"]).toBeUndefined();
    expect(Object.keys(doc.last).length).toBeLessThanOrEqual(MAX_ANSWER_ASKERS);
    expect(Object.keys(doc.refused ?? {}).length).toBeLessThanOrEqual(MAX_ANSWER_ASKERS);
    expect(doc.sent.length).toBeLessThanOrEqual(MAX_POOL_ENTRIES);
    // Folding never frees pool budget.
    expect(doc.sent.reduce((t, x) => t + x.bytes, 0)).toBe((MAX_POOL_ENTRIES + 50) * 2);
    // A refusal repeated within 10 minutes writes nothing.
    await noteRefused(a, "p2p:pest", "c_x");
    const writes: string[] = [];
    const orig = a.state.backend.write.bind(a.state.backend);
    vi.spyOn(a.state.backend, "write").mockImplementation(async (name: string, v: unknown) => {
      writes.push(name);
      return orig(name, v);
    });
    await noteRefused(a, "p2p:pest", "c_x");
    expect(writes.filter((w) => w === "wantAnswers")).toEqual([]);
    await a.close();
  });

  it("P3: a spent proof still inside its window is never evicted, however many proofs there are", async () => {
    const a = new App({ env: owner.env, io: { out: () => {}, err: () => {} } });
    await a.load();
    const now = Date.now();
    // More live proofs than the cap, all spent in the last few minutes, plus older ones.
    const pows = [
      ...Array.from({ length: 100 }, (_, i) => ({ id: `old${i}`, at: now - 30 * 60_000 })),
      ...Array.from({ length: MAX_POOL_ENTRIES + 10 }, (_, i) => ({ id: `live${i}`, at: now - 60_000 })),
    ];
    await a.state.update("wantAnswers", () => ({ next: { by: {}, bytes: {}, sent: [], last: {}, pows }, result: undefined }));
    expect(await chargeAnswer(a, "p2p:x", "member", 1, { cid: "c_z", ver: 1, resent: false })).toMatchObject({ ok: true });
    const kept = new Set(((await a.state.get("wantAnswers"))!.pows ?? []).map((p) => p.id));
    for (let i = 0; i < MAX_POOL_ENTRIES + 10; i++) expect(kept.has(`live${i}`)).toBe(true);
    expect(kept.has("old0")).toBe(false);
    await a.close();
  });

  it("an answer bigger than the budget is cut to whole versions, statements only when all fits", () => {
    const vs = ["a".repeat(1000), "b".repeat(1000), "c".repeat(1000)];
    const js = ["s".repeat(500)];
    const id = (n: number) => n;
    expect(answerParts(vs, js, 100_000, id).sentVersions).toBe(3);
    expect(answerParts(vs, js, 100_000, id).parts.flatMap((p) => p.joins)).toEqual(js);
    const cut = answerParts(vs, js, 2100, id);
    expect(cut.sentVersions).toBe(2);
    expect(cut.parts.flatMap((p) => p.joins)).toEqual([]);
    expect(cut.bytes).toBeLessThanOrEqual(2100);
    expect(answerParts(vs, js, 10, id)).toEqual({ parts: [], bytes: 0, sentVersions: 0 });
    // N7: room for every version but not the statements: stop short of the head, so the answer
    // that reaches it (and counts as whole) brings the statements.
    const all = answerParts(vs, [], 100_000, id).bytes;
    const short = answerParts(vs, js, all + 10, id);
    expect(short.sentVersions).toBe(2);
    expect(short.parts.flatMap((p) => p.joins)).toEqual([]);
    // Without statements to send, all versions go.
    expect(answerParts(vs, [], all, id).sentVersions).toBe(3);
  });

  it("an answer counts only once it reaches the offered head, every part of it included", async () => {
    const a = await ownerApp();
    const vs = (await loadCircle(a.store, cid))!.chain.versionsFrom(1);
    await a.close();
    const top = vs.length;
    expect(contiguousTop(vs)).toBe(top);
    expect(contiguousTop([...vs.slice(0, 4), ...vs.slice(5)])).toBe(4);
    expect(contiguousTop(undefined)).toBe(0);
    // A prefix (the first chunk: versions go out in order) is not an answer, whoever sent it.
    expect(answerComplete(vs.slice(0, 5), undefined, top)).toBe(false);
    expect(answerComplete(vs, undefined, top)).toBe(true);
    expect(answerComplete([...vs].reverse(), undefined, top)).toBe(true);
    expect(answerComplete(vs.slice(1), undefined, top)).toBe(false);
    // Marked parts: every part of one answer that reached the head (its statements are in its last parts).
    expect(answerComplete(vs, { a: { n: 4, got: [1, 2, 4], top } }, top)).toBe(false);
    expect(answerComplete(vs, { a: { n: 4, got: [1, 2, 4, 3], top } }, top)).toBe(true);
    // A whole earlier answer that stopped short (a budget) doesn't stand in for the rest.
    expect(answerComplete(vs, { a: { n: 2, got: [1, 2], top: 5 }, b: { n: 3, got: [1, 2], top } }, top)).toBe(false);
    expect(answerComplete(vs, { a: { n: 2, got: [1, 2], top: 5 }, b: { n: 3, got: [1, 2, 3], top } }, top)).toBe(true);
    // Every version held, the answer that carried the head lost its last part (the statements), and
    // the re-asked answer from past the head carries only the statements: whole.
    expect(answerComplete(vs, { a: { n: 10, got: [1, 2, 3, 4, 5, 6, 7, 8, 9], top }, b: { n: 1, got: [1], top: 0 } }, top)).toBe(true);
    expect(answerComplete(vs.slice(0, -1), { b: { n: 1, got: [1], top: 0 } }, top)).toBe(false);
  });
});
