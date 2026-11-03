// Copyright 2026 Ix Infrastructure Inc.
//
// Regression tests for the pre-release security review, over one in-process relay
// (the relay-side halves of H1, H2 and M1 are in packages/relay
// restricted.test.ts).

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { b64uEncode, createCap, createCircle } from "@peer2peer/core/v3";
import { encodeCircleLink, joinFromLink, recordJoinAnswer } from "../circle-ops.js";
import { main } from "../cli.js";
import { CliError } from "../errors.js";
import { safeJson, safeTerminal } from "../format.js";
import { backupRestore, linkJoin, linkStart } from "../identity.js";
import { processEnvelope, receiving } from "../inbound.js";
import { readCapped, relayCode } from "../relay-client.js";
import { importSync } from "../sync.js";
import { maintain } from "../watch.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-review.test/v3";
const DEAD = "wss://relay-dead.test/v3";
const ESC = "\u001b";
const OSC = `${ESC}]0;pwned\u0007`;
let relay: TestRelay;
let t: Record<string, string>;
const users: User[] = [];
const ids: Record<string, string> = {};

function user(name: string): User {
  const u = new User(name, t);
  users.push(u);
  return u;
}

async function init(u: User): Promise<string> {
  ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
  return ids[u.name];
}

async function befriend(a: User, b: User): Promise<void> {
  const inv = await a.ok(["invite", "--link"]);
  await b.ok(["accept", inv.link]);
  await a.ok(["friends"]);
  await b.ok(["friends"]);
}

/** Links a new home to `owner` (optionally as a key holder). */
async function link(owner: User, home: User, keyholder = false): Promise<string> {
  const a = await owner.app();
  await a.load();
  receiving(a);
  const s = await linkStart(a, { keyholder });
  const b = await home.app();
  const j = await linkJoin(b, s.code);
  const [, joined] = await Promise.all([s.wait(async (req) => req.compareCode === j.compareCode), j.wait()]);
  await a.close();
  await b.close();
  return joined.did;
}

beforeAll(async () => {
  relay = await startRelay(R);
  t = { [R]: `ws://127.0.0.1:${relay.port}/v3`, [DEAD]: "ws://127.0.0.1:9/v3" };
});

afterAll(async () => {
  await relay?.close();
  for (const u of users) u.cleanup();
});

describe("pre-release review regressions", () => {
  it("M2: terminal escapes are stripped from every printer, and escaped in JSON", async () => {
    expect(safeTerminal(`ok${OSC}\u009b31m\u202edone\nnext\tline`)).toBe("ok]0;pwned31mdone\nnext\tline");
    expect(safeJson({ r: `a${OSC}\u009b\u202e` })).not.toMatch(/[\u001b\u0007\u009b\u202e]/);
    expect(JSON.parse(safeJson({ r: `a${OSC}\u009b\u202e` })).r).toBe(`a${OSC}\u009b\u202e`);
    expect(relayCode("rate-limited")).toBe("rate-limited");
    expect(relayCode(`x${ESC}[31m`)).toBe("relay-error");
    expect(relayCode("a".repeat(40))).toBe("relay-error");
    // Through the CLI: a failure whose reason carries an OSC payload.
    const out: string[] = [];
    const err: string[] = [];
    const accept = async () => {
      throw new CliError("x", `relay said ${OSC} bye`);
    };
    const io = { out: (s: string) => out.push(s), err: (s: string) => err.push(s) };
    await main(["accept", "p2p://invite/x"], { env: {}, io, ops: { accept } as never, makeApp: () => ({ load: async () => true, close: async () => {} }) as never });
    await main(["accept", "p2p://invite/x", "--json"], { env: {}, io, ops: { accept } as never, makeApp: () => ({ load: async () => true, close: async () => {} }) as never });
    process.exitCode = 0;
    expect(err.join("")).not.toMatch(/[\u001b\u0007]/);
    expect(out.join("")).not.toMatch(/[\u001b\u0007]/);
    expect(JSON.parse(out.at(-1)!).reason).toContain(OSC);
    // A rejected envelope whose quoted fields carry escapes is logged sanitized.
    const x = user("esc");
    await init(x);
    const app = await x.app();
    const lines: string[] = [];
    (app as unknown as { io: { err: (s: string) => void } }).io.err = (s) => lines.push(s);
    await app.load();
    const header = b64uEncode(new TextEncoder().encode(JSON.stringify({ alg: "EdDSA", typ: `p2p-msg+jws${OSC}`, kid: "d" })));
    await processEnvelope(app, `${header}.e30.c2ln`, `wss://r${ESC}[2J.test/v3`);
    expect(lines.length).toBeGreaterThan(0);
    expect(lines.join("")).not.toMatch(/[\u001b\u0007]/);
  });

  it("L6: relay HTTP bodies are size-capped", async () => {
    const big = new Response("x".repeat(5000));
    await expect(readCapped(big, 1000)).rejects.toMatchObject({ code: "network" });
    expect(await readCapped(new Response('{"a":1}'), 1000)).toBe('{"a":1}');
  });

  it("M4: restore distinguishes unreachable relays from 'no document'; v1 only with --new-chain", async () => {
    const owner = user("phr");
    await init(owner);
    const phrase = (await owner.ok(["backup", "show"])).phrase as string;
    const r1 = await user("rs1").run(["backup", "restore", "--relay", DEAD], { stdin: phrase });
    expect(r1.json.error).toBe("unreachable");
    expect(r1.code).toBe(1);
    // A fresh identity nobody published: reachable relay, no document.
    const lone = user("lone");
    const ik = (await import("@peer2peer/core/v3")).generateIdentityKey();
    const lonePhrase = (await import("@peer2peer/core/v3")).backupPhraseFromSeed(ik.secretKey);
    const r2 = await lone.run(["backup", "restore", "--relay", R], { stdin: lonePhrase });
    expect(r2.json.error).toBe("no_document");
    const r3 = await lone.ok(["backup", "restore", "--relay", R, "--new-chain"], { stdin: lonePhrase });
    expect(r3.ver).toBe(1);
    // L4: the phrase is never an argument.
    const r4 = await user("rs4").run(["backup", "restore", "--relay", R, "--phrase", phrase]);
    expect(r4.code).toBe(1);
  });

  it("H2/L5: publishing fails closed on an unconfirmed head; revoking a key holder warns; a revoked key holder never republishes", async () => {
    const a = user("kh");
    await init(a);
    const a2 = user("kh2");
    const did2 = await link(a, a2, true);
    // The second key holder is revoked; it still holds ik but must not publish (maintain or explicit).
    const rv = await a.ok(["devices", "revoke", did2]);
    expect(rv.warnings.join(" ")).toMatch(/still hold.*identity key.*rotation/);
    const before = (await a.ok(["whoami"])).doc.ver;
    const stale = await a2.app();
    await stale.load();
    await maintain(stale);
    await stale.close();
    const prof = await a2.run(["profile", "set", "--bio", "from the revoked key holder"]);
    expect(prof.code).toBe(1);
    expect(["device_revoked", "refresh_failed", "no_relay"]).toContain(prof.json.error);
    expect((await a.ok(["whoami"])).doc.ver).toBe(before);
    // Relays unreachable: no blind publish on a possibly stale head.
    const off = new User("kh-off", { [R]: "ws://127.0.0.1:9/v3" }, { P2P_HOME: a.home });
    const r = await off.run(["profile", "set", "--bio", "offline"]);
    expect(r.code).toBe(1);
    expect(["refresh_failed", "no_relay"]).toContain(r.json.error);
    expect((await a.ok(["whoami"])).doc.ver).toBe(before);
  });

  it("M5: caps-issued records from sync are rebuilt from the verified JWS", async () => {
    const c = user("capsync");
    await init(c);
    const peer = user("capsync-peer");
    await init(peer);
    const app = await c.app();
    await app.load();
    const real = createCap(app.device!, app.keys!.cert, { purpose: "friend", sub: ids["capsync-peer"], relays: [R] });
    const theirs = createCap((await peer.app().then(async (p) => (await p.load(), p))).device!, (await peer.app().then(async (p) => (await p.load(), p))).keys!.cert, { purpose: "contact", relays: [R] });
    await importSync(app, {
      capsIssued: [
        { capid: "forged", iss: ids.capsync, sub: "*", relays: ["wss://evil.test/v3"], kinds: ["*"], exp: 9e9, jws: real },
        { capid: "x", iss: ids.capsync, sub: "*", relays: [R], kinds: ["*"], exp: 9e9, jws: theirs },
        { capid: "y", iss: ids.capsync, sub: "*", relays: [R], kinds: ["*"], exp: 9e9, jws: "not.a.cap" },
      ],
    });
    const stored = await app.store.listCapsIssued();
    expect(stored).toHaveLength(1);
    expect(stored[0]).toMatchObject({ sub: ids["capsync-peer"], relays: [R], kinds: ["*"] });
    expect(stored[0].capid).not.toBe("forged");
    await app.close();
  });

  it("L1: a join answer nobody asked for is ignored", async () => {
    const j = user("joiner");
    await init(j);
    const app = await j.app();
    await app.load();
    const ik = (await import("@peer2peer/core/v3")).generateIdentityKey();
    const head = createCircle(ik, { name: "c", policy: "open" });
    const cid = JSON.parse(Buffer.from(head.split(".")[1], "base64url").toString()).cid as string;
    await app.state.put("joins", { [cid]: { cid, head, answers: {}, joins: [], asked: [ik.userId], askedAt: Date.now() } });
    // Someone nobody asked: made here, not borrowed from another test (which may not have run).
    const stranger = (await import("@peer2peer/core/v3")).generateIdentityKey().userId;
    expect(await recordJoinAnswer(app, stranger, [head], [])).toBe(false);
    expect(await recordJoinAnswer(app, ik.userId, [head], [])).toBe(true);
    expect((await app.state.get("joins"))![cid].answerFrom).toEqual([ik.userId]);
    await app.close();
  });

  it("forged circle-link hint: the hint's document is never stored, and a stranger's cap isn't used", async () => {
    const owner = user("hintowner");
    await init(owner);
    const forger = user("forger");
    await init(forger);
    const victim = user("victim");
    await init(victim);
    const c = await owner.ok(["circle", "create", "real", "--open"]);
    const realLink = (await owner.ok(["circle", "invite", c.cid, "--link"])).link as string;
    const headJws = new TextDecoder().decode(Buffer.from(realLink.slice("p2p://circle/".length).split("~")[0], "base64url"));
    // The forger's own document and join cap in place of the owner's.
    const fApp = await forger.app();
    await fApp.load();
    const fDoc = (await fApp.ownView()).head.jws;
    await fApp.close();
    const forged = encodeCircleLink(headJws, { doc: fDoc });
    const app = await victim.app();
    await app.load();
    receiving(app);
    const r = await joinFromLink(app, forged, { waitSec: 1 });
    expect(r.status).not.toBe("joined");
    expect(await app.view(ids.forger)).toBeUndefined();
    await app.close();
  });

  it("M3 + L2: confirmation follows the head actually joined; friends who aren't members get no roster", async () => {
    const o = user("m3owner");
    await init(o);
    const m = user("m3member");
    await init(m);
    const late = user("m3late");
    await init(late);
    const c = await o.ok(["circle", "create", "grow", "--open"]);
    const oldLink = (await o.ok(["circle", "invite", c.cid, "--link"])).link as string;
    await m.ok(["circle", "join", oldLink, "--wait", "0"]);
    await o.ok(["circle", "ls"]);
    expect((await m.ok(["circle", "join", oldLink, "--wait", "3"])).status).toBe("joined");
    await o.ok(["circle", "ls"]);
    // The old link's head lists only the owner, but the owner answers with a head that lists
    // m3member: that's what late would join, so owner-only isn't enough.
    await late.ok(["circle", "join", oldLink, "--wait", "0"]);
    await o.ok(["circle", "ls"]);
    const res = await late.run(["circle", "join", oldLink, "--wait", "2"]);
    expect(res.json.status).toBe("unconfirmed");
    // L2: an invite-only circle's roster isn't sent to a friend who isn't a member.
    const priv = await o.ok(["circle", "create", "private-one"]);
    await befriend(o, late);
    const plain = (await o.ok(["circle", "invite", priv.cid, "--link"])).link as string;
    await late.ok(["circle", "join", plain, "--wait", "0"]);
    await o.ok(["circle", "ls"]);
    const w = await late.ok(["circle", "join", plain, "--wait", "2"]);
    expect(w.status).toBe("waiting");
    expect(w.answered).toEqual([]);
  });

  it("L3: a sync from a device revoked elsewhere is ignored once the own document is refreshed", async () => {
    const a1 = user("s1");
    await init(a1);
    const a2 = user("s2");
    await link(a1, a2, true);
    const a3 = user("s3");
    const did3 = await link(a1, a3, false);
    const friend = user("sfriend");
    const fid = await init(friend);
    // a3 learns of the friend's identity, then syncs a petname to its other devices (queued for a1).
    const a3app = await a3.app();
    await a3app.load();
    await a3app.connect();
    await a3app.refreshIdentity(fid, [R], { force: true });
    await a3app.close();
    await a3.ok(["petname", fid, "from-revoked"]);
    // a2 (a key holder) revokes a3; a1 doesn't know yet (its copy of the document is stale).
    await a2.ok(["devices", "revoke", did3]);
    await a1.ok(["ls"]);
    const pets = await (await a1.app().then(async (x) => (await x.load(), x))).store.listPetnames();
    expect(pets[fid]).toBeUndefined();
  });

  it("unfriend and block, in both directions", async () => {
    const p = user("bp");
    await init(p);
    const q = user("bq");
    await init(q);
    await befriend(p, q);
    await p.ok(["session", "roster", "ps", "--add", ids.bq]);
    await q.ok(["session", "roster", "qs", "--add", ids.bp]);
    await p.ok(["status", "--session", "ps", "--state", "busy"]);
    await q.ok(["status", "--session", "qs", "--state", "busy"]);
    expect((await q.ok(["send", "--from-session", "qs", "--to", `${ids.bp}/ps`, "hi"])).delivered).toBe(true);
    // q unfriends p: neither direction delivers any more.
    await q.ok(["unfriend", ids.bp]);
    expect((await p.run(["send", "--from-session", "ps", "--to", `${ids.bq}/qs`, "x"])).code).toBe(1);
    expect((await q.run(["send", "--from-session", "qs", "--to", `${ids.bp}/ps`, "x"])).code).toBe(1);
    // Block, both ways: a blocked user's sends are refused locally and their caps revoked.
    // Re-friending right after the unfriend (same second) works: the invite is dated after it.
    await befriend(p, q);
    await p.ok(["block", ids.bq]);
    await p.watch("ps", 600); // what arrived before the block
    expect((await p.run(["send", "--from-session", "ps", "--to", `${ids.bq}/qs`, "x"])).json.error).toBe("blocked");
    const fromQ = await q.run(["send", "--from-session", "qs", "--to", `${ids.bp}/ps`, "blocked?"]);
    expect(fromQ.code).toBe(1);
    expect((await p.watch("ps", 800)).some((e) => e.from?.userId === ids.bq && e.kind === "p2p.message")).toBe(false);
  });

  it("restore over unreachable relays changes nothing", async () => {
    const r = await backupRestore(await user("noop").app(), "a ".repeat(24), { relays: [DEAD] }).catch((e) => e);
    expect(r).toBeInstanceOf(CliError);
  });
});
