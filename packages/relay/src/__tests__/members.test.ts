// Copyright 2026 Ix Infrastructure Inc.
// Members-only relays (docs/run-a-relay.md "Members-only relays"): an
// allowlist, circle admission, removal of live connections, the invite
// admission and what an unauthenticated client can still reach.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { b64uEncode, randomBytes, sha256 } from "@peer2peer/core";
import { CircleChain, createCircle, createNextCircleVersion, type IdentityKey } from "@peer2peer/core/v3";
import { loadConfig, parseAllowFile, DEFAULT_INVITE_ADMIT_SEC } from "../config.js";
import { b32Encode } from "../crypto.js";
import { SqliteStore } from "../sqlite-store.js";
import { MemoryStore } from "../store.js";
import {
  authed,
  authSig,
  crypto,
  makeClock,
  makeDevice,
  makeDoc,
  makeEnvelope,
  makeIdentity,
  startRelay,
  TestClient,
  type Identity,
  type StartOptions,
  type TestRelay,
} from "./helpers.js";

let r: TestRelay | undefined;
const clients: TestClient[] = [];
const dirs: string[] = [];

afterEach(async () => {
  for (const c of clients.splice(0)) await c.close().catch(() => 0);
  await r?.close();
  r = undefined;
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const newLid = () => b32Encode(randomBytes(20)).slice(0, 26);
const newAdmitKey = () => b64uEncode(randomBytes(32));
const hashKey = (k: string) => b64uEncode(sha256(Buffer.from(k, "base64url")));
const ikOf = (id: Identity): IdentityKey => ({ userId: id.userId, secretKey: id.ikSecret, publicKey: id.ik });

async function start(o: StartOptions = {}): Promise<TestRelay> {
  r = await startRelay(o);
  return r;
}

async function connect(rr: TestRelay): Promise<TestClient> {
  const c = await TestClient.connect(rr.url);
  clients.push(c);
  return c;
}

/** Authenticates a fresh device of `id`; resolves with the client and the auth reply. */
async function tryAuth(rr: TestRelay, id: Identity, extra: Record<string, unknown> = {}) {
  const c = await connect(rr);
  const device = makeDevice(id, rr.nowSec());
  const reply = c.next((f) => f.t === "ok" || f.t === "error");
  c.send({ t: "auth", cert: device.cert, sig: authSig(device, c.hello.relay as string, c.hello.nonce as string), ...extra });
  return { c, device, reply: await reply };
}

async function expectRefused(rr: TestRelay, id: Identity, extra: Record<string, unknown> = {}) {
  const { c, device, reply } = await tryAuth(rr, id, extra);
  expect(reply).toMatchObject({ t: "error", code: "not-member" });
  expect(await c.closed).toBe(4001);
  // Refused before anything was stored for the device.
  expect(rr.store.deviceIssuer(device.did)).toBeUndefined();
}

async function identityStatus(rr: TestRelay, userId: string): Promise<number> {
  return (await fetch(`${rr.http}/v3/identity/${userId}`)).status;
}

describe("members-only relay: allowlist", () => {
  it("unset: the relay stays open", async () => {
    const rr = await start();
    expect((await tryAuth(rr, makeIdentity())).reply).toMatchObject({ t: "ok" });
    const info = (await (await fetch(`${rr.http}/.well-known/p2p-relay.json`)).json()) as Record<string, unknown>;
    expect(info.access).toBe("open");
  });

  it("an allowed member authenticates; a stranger is refused at auth with not-member and 4001", async () => {
    const alice = makeIdentity();
    const rr = await start({ config: { allow: [alice.userId] } });
    const ok = await tryAuth(rr, alice);
    expect(ok.reply).toEqual({ t: "ok" });
    await expectRefused(rr, makeIdentity());
    const info = (await (await fetch(`${rr.http}/.well-known/p2p-relay.json`)).json()) as Record<string, unknown>;
    expect(info.access).toBe("members");
    expect(JSON.stringify(info)).not.toContain(alice.userId);
  });

  it("a stranger can't reach the authenticated frames on its unauthenticated socket", async () => {
    const alice = makeIdentity();
    const rr = await start({ config: { allow: [alice.userId] } });
    const anon = await connect(rr);
    for (const t of ["send", "identity", "invite-put", "link-open", "circle-put"]) {
      expect(await anon.request({ t })).toMatchObject({ code: "auth-required" });
    }
  });

  it("removal mid-connection: live connections close with not-member, new auths are refused", async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const rr = await start({ config: { allow: [alice.userId, bob.userId] } });
    const a = await tryAuth(rr, alice);
    const b1 = await tryAuth(rr, bob);
    const b2 = await tryAuth(rr, bob);
    expect(b1.reply.t).toBe("ok");
    rr.relay.setAllow([alice.userId]);
    for (const b of [b1.c, b2.c]) {
      expect(await b.next((f) => f.t === "error")).toMatchObject({ code: "not-member" });
      expect(await b.closed).toBe(4001);
    }
    await expectRefused(rr, bob);
    // Alice is untouched.
    expect(await a.c.request({ t: "invite-list" })).toMatchObject({ t: "invites" });
    // Re-adding lets Bob back in.
    rr.relay.setAllow([alice.userId, bob.userId]);
    expect((await tryAuth(rr, bob)).reply.t).toBe("ok");
  });

  it("a restricted (unlisted-device) connection of a removed member is closed too", async () => {
    const alice = makeIdentity();
    const rr = await start({ config: { allow: [alice.userId] } });
    const listed = makeDevice(alice, rr.nowSec());
    const a = await authed(rr, listed);
    clients.push(a);
    expect(await a.request({ t: "identity", doc: makeDoc(alice, rr.nowSec(), { devices: [listed.did] }).jws })).toMatchObject({ t: "ok" });
    const restricted = await tryAuth(rr, alice);
    expect(restricted.reply).toMatchObject({ t: "ok", restricted: true });
    rr.relay.setAllow([]);
    expect(await restricted.c.closed).toBe(4001);
    expect(await a.closed).toBe(4001);
  });

  it("nothing is stored for a non-member, and only members' identity documents are served", async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const rr = await start({ config: { allow: [alice.userId, bob.userId] } });
    const ad = makeDevice(alice, rr.nowSec());
    const a = await authed(rr, ad);
    clients.push(a);
    expect(await a.request({ t: "identity", doc: makeDoc(alice, rr.nowSec(), { devices: [ad.did] }).jws })).toMatchObject({ t: "ok" });
    expect(await identityStatus(rr, alice.userId)).toBe(200);
    const stranger = makeIdentity();
    const sd = makeDevice(stranger, rr.nowSec());
    const env = makeEnvelope(ad, { userId: stranger.userId, did: sd.did }, { kind: "contact" });
    expect(await a.request({ t: "send", to: stranger.userId, tdid: sd.did, env })).toMatchObject({ code: "undeliverable" });
    // Removed: the stored document is no longer served (a non-member looks unknown).
    rr.relay.setAllow([bob.userId]);
    expect(await identityStatus(rr, alice.userId)).toBe(404);
    expect(await identityStatus(rr, stranger.userId)).toBe(404);
  });
});

describe("members-only relay: config", () => {
  const base = { RELAY_URL: "wss://relay.test/v3" };
  it("parses RELAY_ALLOW, the allow file and RELAY_ALLOW_CIRCLE; refuses anything that isn't a full userId", () => {
    const a = makeIdentity().userId;
    const b = makeIdentity().userId;
    const c = makeIdentity().userId;
    const files: Record<string, string> = { "/allow.txt": `# team\n${b}\n\n${c}  # carol\n` };
    const cfg = loadConfig(crypto, {
      env: { ...base, RELAY_ALLOW: `${a}, ${b}`, RELAY_ALLOW_FILE: "/allow.txt", RELAY_ALLOW_CIRCLE: "c_abcdefghijklmnopqrstuvwxyz" },
      readFile: (p) => files[p],
    });
    expect(new Set(cfg.allow)).toEqual(new Set([a, b, c]));
    expect(cfg.allowCircle).toBe("c_abcdefghijklmnopqrstuvwxyz");
    expect(cfg.inviteAdmitSec).toBe(DEFAULT_INVITE_ADMIT_SEC);
    expect(loadConfig(crypto, { env: base }).allow).toBeUndefined();
    expect(() => loadConfig(crypto, { env: { ...base, RELAY_ALLOW: a.slice(0, 20) } })).toThrow(/not a full userId/);
    expect(() => loadConfig(crypto, { env: { ...base, RELAY_ALLOW_CIRCLE: "nope" } })).toThrow(/circle id/);
    expect(loadConfig(crypto, { env: { ...base, RELAY_INVITE_ADMIT_SEC: "0" } }).inviteAdmitSec).toBe(0);
    // The JSON file's list.
    const viaFile = loadConfig(crypto, { env: { ...base, RELAY_CONFIG: "/c.json" }, readFile: () => JSON.stringify({ allow: [a] }) });
    expect(viaFile.allow).toEqual([a]);
    // An empty list is members-only with nobody on it (fail closed), not an open relay.
    expect(loadConfig(crypto, { env: { ...base, RELAY_ALLOW: " " } }).allow).toEqual([]);
    expect(parseAllowFile("x # y\n#z\n!w\n")).toEqual({ allow: ["x"], deny: ["w"] });
    // Deny: RELAY_DENY, and `!` lines of the allow file.
    const d = makeIdentity().userId;
    const withDeny = loadConfig(crypto, { env: { ...base, RELAY_DENY: a, RELAY_ALLOW_FILE: "/f" }, readFile: () => `${b}\n!${d}\n` });
    expect(withDeny.allow).toEqual([b]);
    expect(new Set(withDeny.deny)).toEqual(new Set([a, d]));
    // A file with one bad line fails as a whole (a reload then keeps the current list).
    expect(() => loadConfig(crypto, { env: { ...base, RELAY_ALLOW_FILE: "/f" }, readFile: () => `${b}\n${c.slice(0, 30)}\n` })).toThrow(/not a full userId/);
  });
});

describe("members-only relay: circle admission", () => {
  async function circleRelay(o: { store?: MemoryStore | SqliteStore; extraAllow?: string[] } = {}) {
    const owner = makeIdentity();
    const bob = makeIdentity();
    const clock = makeClock();
    const now = Math.floor(clock.t / 1000);
    const v1 = createCircle(ikOf(owner), { name: "team", members: [bob.userId], iat: now });
    const chain = CircleChain.bootstrap([v1], { now });
    const rr = await start({ clock, config: { allow: [owner.userId, ...(o.extraAllow ?? [])], allowCircle: chain.cid }, ...(o.store ? { store: o.store } : {}) });
    return { rr, owner, bob, v1, chain, now };
  }

  it("the allowlisted owner seeds the circle; then its members are admitted and told which circle to keep current", async () => {
    const { rr, owner, bob, v1, chain } = await circleRelay();
    await expectRefused(rr, bob);
    const o = await tryAuth(rr, owner);
    expect(o.reply).toEqual({ t: "ok", circle: { cid: chain.cid, ver: 0 } });
    expect(await o.c.request({ t: "circle-put", versions: [v1] })).toMatchObject({ t: "ok", ver: 1, status: "seeded" });
    const b = await tryAuth(rr, bob);
    expect(b.reply).toEqual({ t: "ok", circle: { cid: chain.cid, ver: 1 } });
    // Re-sending is harmless.
    expect(await b.c.request({ t: "circle-put", versions: [v1] })).toMatchObject({ t: "ok", ver: 1, status: "duplicate" });
    await expectRefused(rr, makeIdentity());
  });

  it("only an allowlisted userId may seed; another circle, or a version not signed by the owner, changes nothing", async () => {
    const helper = makeIdentity();
    const { rr, owner, bob, v1, chain, now } = await circleRelay({ extraAllow: [helper.userId] });
    // A circle of the helper's own, with the same members, is not the configured one.
    const other = createCircle(ikOf(helper), { name: "fake", members: [bob.userId], iat: now });
    const h = await tryAuth(rr, helper);
    expect(await h.c.request({ t: "circle-put", versions: [other] })).toMatchObject({ code: "bad-request" });
    expect(await h.c.request({ t: "circle-put", versions: "nope" })).toMatchObject({ code: "bad-request" });
    // An allowlisted non-owner may seed the genuine chain: it is self-certifying from the cid.
    expect(await h.c.request({ t: "circle-put", versions: [v1] })).toMatchObject({ t: "ok", ver: 1 });
    // Bob, a member, forges version 2 adding a friend: not signed by the owner's identity key.
    const mallory = makeIdentity();
    const forged = createNextCircleVersion({ ...ikOf(bob), userId: owner.userId }, chain.head, { members: [...chain.head.members, mallory.userId], iat: now });
    const b = await tryAuth(rr, bob);
    expect(await b.c.request({ t: "circle-put", versions: [forged] })).toMatchObject({ t: "ok", ver: 1, status: "rejected" });
    await expectRefused(rr, mallory);
  });

  it("only an allowlisted userId seeds: a provisional member can't, even with the genuine chain", async () => {
    const { rr, owner, bob, v1 } = await circleRelay();
    const o = await tryAuth(rr, owner);
    const key = newAdmitKey();
    await o.c.request({ t: "invite-put", lid: newLid(), blob: "b", ttl: 600, admit: hashKey(key) });
    const b = await tryAuth(rr, bob, { admit: key });
    expect(b.reply).toMatchObject({ t: "ok", admitted: "invite", circle: { ver: 0 } });
    expect(await b.c.request({ t: "circle-put", versions: [v1] })).toMatchObject({ code: "forbidden" });
    expect(await o.c.request({ t: "circle-put", versions: [v1] })).toMatchObject({ t: "ok", status: "seeded" });
  });

  it("removal from the circle cuts off live connections and refuses new auths; additions take effect at once", async () => {
    const { rr, owner, bob, v1, chain, now } = await circleRelay();
    const o = await tryAuth(rr, owner);
    await o.c.request({ t: "circle-put", versions: [v1] });
    const b = await tryAuth(rr, bob);
    expect(b.reply.t).toBe("ok");
    const carol = makeIdentity();
    await expectRefused(rr, carol);
    const v2 = createNextCircleVersion(ikOf(owner), chain.head, { members: [owner.userId, carol.userId], iat: now + 1 });
    expect(await o.c.request({ t: "circle-put", versions: [v2] })).toMatchObject({ t: "ok", ver: 2, status: "accepted" });
    expect(await b.c.next((f) => f.t === "error")).toMatchObject({ code: "not-member" });
    expect(await b.c.closed).toBe(4001);
    await expectRefused(rr, bob);
    expect((await tryAuth(rr, carol)).reply).toMatchObject({ t: "ok", circle: { ver: 2 } });
  });

  it("the verified chain survives a restart", async () => {
    const dir = mkdtempSync(join(tmpdir(), "p2p-members-"));
    dirs.push(dir);
    const store = new SqliteStore(join(dir, "relay.db"));
    const { rr, owner, bob, v1, chain } = await circleRelay({ store });
    const o = await tryAuth(rr, owner);
    await o.c.request({ t: "circle-put", versions: [v1] });
    for (const c of clients.splice(0)) await c.close().catch(() => 0);
    await rr.close();
    r = await startRelay({ clock: rr.clock, config: { allow: [owner.userId], allowCircle: chain.cid }, store: new SqliteStore(join(dir, "relay.db")) });
    expect((await tryAuth(r, bob)).reply).toEqual({ t: "ok", circle: { cid: chain.cid, ver: 1 } });
  });
});

describe("members-only relay: open circles fail closed", () => {
  it("an open circle can't be seeded", async () => {
    const owner = makeIdentity();
    const clock = makeClock();
    const now = Math.floor(clock.t / 1000);
    const v1 = createCircle(ikOf(owner), { name: "anyone", policy: "open", iat: now });
    const cid = CircleChain.bootstrap([v1], { now }).cid;
    const rr = await start({ clock, config: { allow: [owner.userId], allowCircle: cid } });
    const o = await tryAuth(rr, owner);
    expect(await o.c.request({ t: "circle-put", versions: [v1] })).toMatchObject({ code: "bad-request" });
    expect(rr.relay.members.circleInfo()).toEqual({ cid, ver: 0 });
  });

  it("a head that turns open admits nobody through the circle (allowlist only), flags attention, and recovers", async () => {
    const owner = makeIdentity();
    const bob = makeIdentity();
    const clock = makeClock();
    const now = Math.floor(clock.t / 1000);
    const v1 = createCircle(ikOf(owner), { name: "team", members: [bob.userId], iat: now });
    const chain = CircleChain.bootstrap([v1], { now });
    const rr = await start({ clock, config: { allow: [owner.userId], allowCircle: chain.cid } });
    const info = async () => (await (await fetch(`${rr.http}/.well-known/p2p-relay.json`)).json()) as Record<string, unknown>;
    const o = await tryAuth(rr, owner);
    await o.c.request({ t: "circle-put", versions: [v1] });
    const b = await tryAuth(rr, bob);
    expect(b.reply.t).toBe("ok");
    expect((await info()).attention).toBeUndefined();
    const v2 = createNextCircleVersion(ikOf(owner), chain.head, { policy: "open", iat: now + 1 });
    chain.receive(v2, { now: now + 1 });
    expect(await o.c.request({ t: "circle-put", versions: [v2] })).toMatchObject({ t: "ok", ver: 2 });
    // Bob is cut off; the allowlisted owner is not.
    expect(await b.c.closed).toBe(4001);
    await expectRefused(rr, bob);
    expect(rr.logs.some((l) => l.includes('"level":"error"') && l.includes("OPEN"))).toBe(true);
    const i = await info();
    expect(i).toMatchObject({ access: "members", attention: true });
    expect(JSON.stringify(i)).not.toContain(chain.cid);
    expect(await o.c.request({ t: "invite-list" })).toMatchObject({ t: "invites" });
    // Invite-only again: the circle admits its members again.
    const v3 = createNextCircleVersion(ikOf(owner), chain.head, { policy: "invite", iat: now + 2 });
    expect(await o.c.request({ t: "circle-put", versions: [v3] })).toMatchObject({ ver: 3 });
    expect((await tryAuth(rr, bob)).reply.t).toBe("ok");
    expect((await info()).attention).toBeUndefined();
  });
});

describe("members-only relay: invite admission", () => {
  async function inviteRelay(config: StartOptions["config"] = {}) {
    const alice = makeIdentity();
    const rr = await start({ config: { allow: [alice.userId], ...config }, limits: { inviteGetsPerIpPerMinute: 1000, inviteMissesPerIpPerHour: 1000 } });
    const a = await tryAuth(rr, alice);
    return { rr, alice, a: a.c };
  }

  it("a member's code admits its redeemer: take the blob unauthenticated, then authenticate with the key", async () => {
    const { rr, a } = await inviteRelay();
    const lid = newLid();
    const key = newAdmitKey();
    expect(await a.request({ t: "invite-put", lid, blob: "sealed", ttl: 3600, admit: hashKey(key) })).toMatchObject({ t: "ok", admits: true });
    const joiner = makeIdentity();
    // The take needs no auth (the joiner is nobody here yet).
    const anon = await connect(rr);
    expect(await anon.request({ t: "invite-get", lid })).toMatchObject({ t: "invite", blob: "sealed" });
    // Without the key, or with the wrong one: refused.
    await expectRefused(rr, joiner);
    await expectRefused(rr, joiner, { admit: newAdmitKey() });
    await expectRefused(rr, joiner, { admit: "short" });
    const j = await tryAuth(rr, joiner, { admit: key });
    expect(j.reply).toEqual({ t: "ok", admitted: "invite" });
    // Admitted from now on, without the key; it can publish its document and get mail.
    const j2 = await tryAuth(rr, joiner);
    expect(j2.reply).toEqual({ t: "ok" });
    expect(await j2.c.request({ t: "identity", doc: makeDoc(joiner, rr.nowSec(), { devices: [j2.device.did] }).jws })).toMatchObject({ t: "ok" });
    expect(await identityStatus(rr, joiner.userId)).toBe(200);
    // The grant was single-use.
    await expectRefused(rr, makeIdentity(), { admit: key });
  });

  it("the admission lapses after inviteAdmitSec unless the list adds the joiner", async () => {
    const { rr, alice, a } = await inviteRelay({ inviteAdmitSec: 3600 });
    const keys = [newAdmitKey(), newAdmitKey()];
    for (const k of keys) await a.request({ t: "invite-put", lid: newLid(), blob: "b", ttl: 600, admit: hashKey(k) });
    const [j1, j2] = [makeIdentity(), makeIdentity()];
    const c1 = await tryAuth(rr, j1, { admit: keys[0] });
    const c2 = await tryAuth(rr, j2, { admit: keys[1] });
    expect(c1.reply.t).toBe("ok");
    // The operator lists j2 for good; j1 stays provisional.
    rr.relay.setAllow([alice.userId, j2.userId]);
    rr.clock.advance(3601 * 1000);
    await rr.relay.sweep();
    expect(await c1.c.closed).toBe(4001);
    await expectRefused(rr, j1);
    expect((await tryAuth(rr, j2)).reply.t).toBe("ok");
    // ...and removing j2 from the list now cuts it off (it isn't provisional any more).
    rr.relay.setAllow([alice.userId]);
    expect(await c2.c.closed).toBe(4001);
    await expectRefused(rr, j2);
  });

  it("revoking the code (invite-del) voids its admission even after the blob was taken; an expired code admits nobody", async () => {
    const { rr, a } = await inviteRelay();
    const lid = newLid();
    const key = newAdmitKey();
    await a.request({ t: "invite-put", lid, blob: "b", ttl: 600, admit: hashKey(key) });
    const anon = await connect(rr);
    await anon.request({ t: "invite-get", lid });
    // The invite was taken, so the relay says not-found; the grant goes all the same.
    expect(await a.request({ t: "invite-del", lid })).toMatchObject({ code: "not-found" });
    await expectRefused(rr, makeIdentity(), { admit: key });
    const late = newAdmitKey();
    await a.request({ t: "invite-put", lid: newLid(), blob: "b", ttl: 600, admit: hashKey(late) });
    rr.clock.advance(601 * 1000);
    await expectRefused(rr, makeIdentity(), { admit: late });
  });

  it("only a full member's code admits: a provisional member can't sponsor, and a removed sponsor's joiners go with it", async () => {
    const { rr, a } = await inviteRelay();
    const key = newAdmitKey();
    await a.request({ t: "invite-put", lid: newLid(), blob: "b", ttl: 600, admit: hashKey(key) });
    const joiner = makeIdentity();
    const j = await tryAuth(rr, joiner, { admit: key });
    expect(j.reply.t).toBe("ok");
    expect(await j.c.request({ t: "invite-put", lid: newLid(), blob: "b", ttl: 600, admit: hashKey(newAdmitKey()) })).toMatchObject({ code: "forbidden" });
    // A plain invite (no admission) is still fine for a provisional member.
    expect(await j.c.request({ t: "invite-put", lid: newLid(), blob: "b", ttl: 600 })).toMatchObject({ t: "ok" });
    const other = makeIdentity();
    rr.relay.setAllow([other.userId]);
    expect(await j.c.closed).toBe(4001);
    expect(await a.closed).toBe(4001);
    await expectRefused(rr, joiner);
  });

  it("with RELAY_INVITE_ADMIT_SEC=0 a code admits nobody", async () => {
    const { rr, a } = await inviteRelay({ inviteAdmitSec: 0 });
    const key = newAdmitKey();
    const put = await a.request({ t: "invite-put", lid: newLid(), blob: "b", ttl: 600, admit: hashKey(key) });
    expect(put).toMatchObject({ t: "ok" });
    expect(put.admits).toBeUndefined();
    await expectRefused(rr, makeIdentity(), { admit: key });
  });

  it("circle mode: the inviter adding the joiner makes it a circle member; removing it later cuts it off at once", async () => {
    const owner = makeIdentity();
    const clock = makeClock();
    const now = Math.floor(clock.t / 1000);
    const v1 = createCircle(ikOf(owner), { name: "team", iat: now });
    const chain = CircleChain.bootstrap([v1], { now });
    const rr = await start({ clock, config: { allow: [owner.userId], allowCircle: chain.cid } });
    const o = await tryAuth(rr, owner);
    await o.c.request({ t: "circle-put", versions: [v1] });
    const key = newAdmitKey();
    await o.c.request({ t: "invite-put", lid: newLid(), blob: "b", ttl: 600, admit: hashKey(key) });
    const joiner = makeIdentity();
    const j = await tryAuth(rr, joiner, { admit: key });
    expect(j.reply).toMatchObject({ t: "ok", admitted: "invite", circle: { cid: chain.cid, ver: 1 } });
    const v2 = createNextCircleVersion(ikOf(owner), chain.head, { members: [owner.userId, joiner.userId], iat: now + 1 });
    chain.receive(v2, { now: now + 1 });
    expect(await o.c.request({ t: "circle-put", versions: [v2] })).toMatchObject({ ver: 2 });
    const v3 = createNextCircleVersion(ikOf(owner), chain.head, { members: [owner.userId], iat: now + 2 });
    expect(await o.c.request({ t: "circle-put", versions: [v3] })).toMatchObject({ ver: 3 });
    expect(await j.c.closed).toBe(4001);
    await expectRefused(rr, joiner);
  });

  it("a fresh relay of the same store keeps provisional members and grants", async () => {
    const store = new MemoryStore();
    const alice = makeIdentity();
    const clock = makeClock();
    r = await startRelay({ clock, store, config: { allow: [alice.userId] } });
    const a = await tryAuth(r, alice);
    const k1 = newAdmitKey();
    const k2 = newAdmitKey();
    await a.c.request({ t: "invite-put", lid: newLid(), blob: "b", ttl: 600, admit: hashKey(k1) });
    await a.c.request({ t: "invite-put", lid: newLid(), blob: "b", ttl: 600, admit: hashKey(k2) });
    const j1 = makeIdentity();
    expect((await tryAuth(r, j1, { admit: k1 })).reply.t).toBe("ok");
    for (const c of clients.splice(0)) await c.close().catch(() => 0);
    await r.close();
    r = await startRelay({ clock, store, config: { allow: [alice.userId] } });
    expect((await tryAuth(r, j1)).reply.t).toBe("ok");
    expect((await tryAuth(r, makeIdentity(), { admit: k2 })).reply.t).toBe("ok");
  });
});

describe("members-only relay: removing one provisional member", () => {
  it("revoking the invite (invite-del) removes the member it admitted, and only that one", async () => {
    const alice = makeIdentity();
    const rr = await start({ config: { allow: [alice.userId] } });
    const a = await tryAuth(rr, alice);
    const [l1, l2] = [newLid(), newLid()];
    const [k1, k2] = [newAdmitKey(), newAdmitKey()];
    await a.c.request({ t: "invite-put", lid: l1, blob: "b", ttl: 600, admit: hashKey(k1) });
    await a.c.request({ t: "invite-put", lid: l2, blob: "b", ttl: 600, admit: hashKey(k2) });
    const [j1, j2] = [makeIdentity(), makeIdentity()];
    const c1 = await tryAuth(rr, j1, { admit: k1 });
    const c2 = await tryAuth(rr, j2, { admit: k2 });
    expect(c1.reply.t).toBe("ok");
    // Someone else's invite-del of the same lid does nothing.
    const mallory = await tryAuth(rr, j2);
    await mallory.c.request({ t: "invite-del", lid: l1 });
    expect(rr.relay.members.admitted(j1.userId)).toBe(true);
    await a.c.request({ t: "invite-del", lid: l1 });
    expect(await c1.c.closed).toBe(4001);
    await expectRefused(rr, j1);
    expect((await c2.c.request({ t: "invite-list" })).t).toBe("invites");
  });

  it("the operator's deny list removes a provisional member (or anyone) at once and wins over everything", async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const rr = await start({ config: { allow: [alice.userId, bob.userId] } });
    const a = await tryAuth(rr, alice);
    const k = newAdmitKey();
    await a.c.request({ t: "invite-put", lid: newLid(), blob: "b", ttl: 600, admit: hashKey(k) });
    const j = makeIdentity();
    const cj = await tryAuth(rr, j, { admit: k });
    const cb = await tryAuth(rr, bob);
    rr.relay.setAllow([alice.userId, bob.userId], [j.userId, bob.userId]);
    expect(await cj.c.closed).toBe(4001);
    expect(await cb.c.closed).toBe(4001);
    await expectRefused(rr, j);
    await expectRefused(rr, bob);
    // A denied userId's invites admit nobody either, and lifting the deny restores bob.
    rr.relay.setAllow([alice.userId, bob.userId], []);
    expect((await tryAuth(rr, bob)).reply.t).toBe("ok");
    // ...but the provisional admission the deny ended doesn't come back.
    await expectRefused(rr, j);
  });

  it("a denied userId can't get in with a fresh, valid code, and the code stays unspent", async () => {
    const alice = makeIdentity();
    const eve = makeIdentity();
    const rr = await start({ config: { allow: [alice.userId], deny: [eve.userId] } });
    const a = await tryAuth(rr, alice);
    const key = newAdmitKey();
    expect(await a.c.request({ t: "invite-put", lid: newLid(), blob: "b", ttl: 600, admit: hashKey(key) })).toMatchObject({ admits: true });
    await expectRefused(rr, eve, { admit: key });
    expect(rr.relay.members.admitted(eve.userId)).toBe(false);
    // Not consumed: the grant still admits someone who isn't denied.
    expect((await tryAuth(rr, makeIdentity(), { admit: key })).reply).toMatchObject({ t: "ok", admitted: "invite" });
    expect((await a.c.request({ t: "invite-list" })).t).toBe("invites");
  });
});
