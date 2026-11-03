// Copyright 2026 Ix Infrastructure Inc.
//
// Relays on loopback, link-local or private addresses, named by something someone else gave the
// user (a code, a long invite link, a circle link): refused before anything connects there, and a
// name is checked where it resolves, on the WebSocket and on the HTTP document fetches from a
// code's relay. Opt-in: --allow-private-relay or P2P_ALLOW_PRIVATE_RELAY=1 (docs/protocol.md P4).

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fetchTips } from "../relay-client.js";
import { invite } from "../social.js";
import { init } from "../identity.js";
import { isPrivateAddress, privateGuardLookup } from "../shortcode.js";
import { startRelay, User, type TestRelay } from "./harness.js";

describe("more special-purpose IPv6 forms", () => {
  it("IPv4-translated (::ffff:0:0/96) by its embedded address; Teredo (2001::/32) whole", () => {
    for (const ip of ["::ffff:0:10.0.0.1", "::ffff:0:a00:1", "::ffff:0:127.0.0.1", "0:0:0:0:ffff:0:c0a8:101", "2001::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2"]) {
      expect(isPrivateAddress(ip), ip).toBe(true);
    }
    for (const ip of ["::ffff:0:8.8.8.8", "2001:db8::1", "2001:4860:4860::8888", "2001:1::1"]) expect(isPrivateAddress(ip), ip).toBe(false);
  });
});

describe("a code's relay over HTTP: the document fetch is checked where the name resolves", () => {
  let srv: Server;
  let port: number;
  beforeAll(async () => {
    srv = createServer((req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(req.url?.endsWith("/tips") ? { tips: ["t1"] } : {}));
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
    port = (srv.address() as AddressInfo).port;
  });
  afterAll(() => new Promise<void>((r) => srv.close(() => r())));

  it("one overall deadline: a relay that trickles its answer can't hold the command", async () => {
    const slow = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.write("{");
      const t = setInterval(() => res.write(" "), 100);
      res.on("close", () => clearInterval(t));
    });
    await new Promise<void>((r) => slow.listen(0, "127.0.0.1", () => r()));
    const p = (slow.address() as AddressInfo).port;
    const lookup = ((_h: string, o: { all?: boolean }, cb: (e: Error | null, a: unknown, f?: number) => void) =>
      o?.all ? cb(null, [{ address: "127.0.0.1", family: 4 }]) : cb(null, "127.0.0.1", 4)) as unknown as import("node:net").LookupFunction;
    const t0 = Date.now();
    try {
      await expect(fetchTips({ ws: `ws://relay.example:${p}/v3`, http: `http://relay.example:${p}` }, "p2p:x", 800, undefined, lookup)).rejects.toMatchObject({ code: "timeout" });
      expect(Date.now() - t0).toBeLessThan(5000);
    } finally {
      slow.closeAllConnections();
      await new Promise<void>((r) => slow.close(() => r()));
    }
  });

  it("the lookup given is what the request dials (resolved once); the guard refuses a name that resolves to loopback", async () => {
    const t = { ws: `ws://relay.example:${port}/v3`, http: `http://relay.example:${port}` };
    // relay.example doesn't resolve on its own: this answer comes from the lookup the fetch was given.
    const mapped = ((host: string, o: { all?: boolean }, cb: (e: Error | null, a: unknown, f?: number) => void) => {
      if (host !== "relay.example") return cb(new Error("ENOTFOUND"), "", 0);
      return o?.all ? cb(null, [{ address: "127.0.0.1", family: 4 }]) : cb(null, "127.0.0.1", 4);
    }) as unknown as import("node:net").LookupFunction;
    expect(await fetchTips(t, "p2p:x", 5000, undefined, mapped)).toEqual(["t1"]);
    const guard = privateGuardLookup((host, _o, cb) => cb(null, host === "relay.example" ? [{ address: "127.0.0.1", family: 4 }] : []));
    await expect(fetchTips(t, "p2p:x", 5000, undefined, guard)).rejects.toMatchObject({ code: "private_relay" });
  });
});

describe("relays named by links and codes", () => {
  const RP = "wss://10.0.0.5:8443/v3";
  const RD = "wss://dns-guard.test/v3";
  let rp: TestRelay;
  let rd: TestRelay;
  const users: User[] = [];
  const user = (name: string, relay: string, transport: Record<string, string>, extra: Record<string, string> = {}) => {
    const u = new User(name, transport, { P2P_DEFAULT_RELAYS: relay, ...extra });
    users.push(u);
    return u;
  };
  beforeAll(async () => {
    rp = await startRelay(RP);
    rd = await startRelay(RD);
  });
  afterAll(async () => {
    await rp?.close();
    await rd?.close();
    for (const u of users) u.cleanup();
  });

  it("a long invite link and a circle link naming a private relay are refused unless opted in", async () => {
    const t = { [RP]: `ws://127.0.0.1:${rp.port}/v3`, [RD]: `ws://127.0.0.1:${rd.port}/v3` };
    const ann = user("ann", RP, t);
    await ann.ok(["setup", "--name", "ann", "--no-backup"]);
    // ben's own relay is another one: ann's private relay is someone else's to him.
    const ben = user("ben", RD, t);
    await ben.ok(["setup", "--name", "ben", "--no-backup"]);
    const link = (await ann.ok(["invite", "--link"])).link as string;
    const no = await ben.run(["accept", link]);
    expect(no.json).toMatchObject({ error: "private_relay" });
    expect(no.json.reason).toMatch(/the invite's relay 10\.0\.0\.5 is on a private network \(for example Tailscale or a LAN\)\. If you trust the person who sent it, run the same command again with --allow-private-relay/);
    expect((await ben.run(["accept", "--allow-private-relay", link])).code).toBe(0);

    const cid = (await ann.ok(["circle", "create", "lan"])).cid;
    const clink = (await ann.ok(["circle", "invite", cid, "--link"])).link as string;
    const cno = await ben.run(["circle", "join", clink, "--wait", "1"]);
    expect(cno.json).toMatchObject({ error: "private_relay" });
    const cyes = await ben.run(["circle", "join", clink, "--wait", "1", "--allow-private-relay"]);
    expect(cyes.json?.error).not.toBe("private_relay");
    // The env opt-in works the same.
    const envBen = user("ben2", RD, t, { P2P_ALLOW_PRIVATE_RELAY: "1" });
    await envBen.ok(["setup", "--name", "ben2", "--no-backup"]);
    expect((await envBen.run(["accept", (await ann.ok(["invite", "--link"])).link])).code).toBe(0);
  }, 90_000);

  it("a code join whose inviter's relays are private: refused before anything is accepted, joined with the opt-in (the same code)", async () => {
    const t = { [RD]: `ws://127.0.0.1:${rd.port}/v3`, [RP]: `ws://127.0.0.1:${rp.port}/v3` };
    const ann = user("ann-lan", `${RD},${RP}`, t);
    await ann.ok(["setup", "--name", "ann", "--no-backup"]);
    const code = (await ann.ok(["invite", "--no-circle", "--relay", RD])).code as string;
    const ben = user("ben-lan", RD, t);
    await ben.ok(["setup", "--name", "ben", "--no-backup"]);
    const no = await ben.run(["join", "--yes", code]);
    expect(no.json).toMatchObject({ error: "private_relay" });
    expect(no.json.reason).toMatch(/the inviter's relay 10\.0\.0\.5 is on a private network.*\/peers join --allow-private-relay <code>/);
    expect((await ben.ok(["friends"])).friends).toEqual([]);
    const yes = await ben.run(["join", "--yes", "--allow-private-relay", code]);
    expect(yes.code, yes.err).toBe(0);
    expect(yes.json.friend.userId).toBe((await ann.ok(["whoami"])).userId);
  }, 90_000);

  it("invites that arrived otherwise are accepted as before: held approve and a rotation, from a friend on a private relay", async () => {
    const t = { [RP]: `ws://127.0.0.1:${rp.port}/v3` };
    const ann = user("ann-held", RP, t);
    const ben = user("ben-held", RP, t);
    for (const [u, n] of [[ann, "ann"], [ben, "ben"]] as const) await u.ok(["setup", "--name", n, "--no-backup"]);
    const benId = (await ben.ok(["whoami"])).userId as string;
    const app = await ann.app();
    await app.load();
    try {
      await app.connect();
      await app.refreshIdentity(benId, [RP], { force: true });
      await invite(app, { to: benId });
    } finally {
      await app.close();
    }
    const held = (await ben.ok(["held"])).held.find((h: { type: string }) => h.type === "invite");
    expect(held).toBeDefined();
    const ok = await ben.run(["held", "approve", held.id]);
    expect(ok.code, ok.err).toBe(0);
    expect(ok.json.friend.userId).toBe((await ann.ok(["whoami"])).userId);
    await ann.ok(["friends"]);

    // ann moves to a new key; ben approves "ann moved to a new key" (its invite names ann's private relay).
    const rot = await ann.run(["identity", "rotate", "--yes", "--wait", "1", "--backup-file"]);
    expect(rot.code, rot.err).toBe(0);
    let item: { id: string; type: string } | undefined;
    for (let i = 0; i < 10 && !item; i++) item = (await ben.ok(["held"])).held.find((h: { type: string }) => h.type === "rotation");
    expect(item).toBeDefined();
    const r = await ben.run(["held", "approve", item!.id]);
    expect(r.code, r.err).toBe(0);
    expect(r.json).toMatchObject({ type: "rotation" });
  }, 120_000);

  it("a pasted link whose relay's name resolves to a private address is refused (resolved where it is dialed), unless opted in", async () => {
    const ann = user("ann-dns", RD, { [RD]: `ws://127.0.0.1:${rd.port}/v3` });
    await ann.ok(["setup", "--name", "ann", "--no-backup"]);
    const link = (await ann.ok(["invite", "--link"])).link as string;
    // ben (whose own relay is another) dials the link's relay through a name that resolves to loopback.
    const ben = user("ben-dns", RP, { [RD]: `ws://localhost:${rd.port}/v3`, [RP]: `ws://127.0.0.1:${rp.port}/v3` });
    await ben.ok(["setup", "--name", "ben", "--no-backup"]);
    const no = await ben.run(["accept", link]);
    expect(no.json).toMatchObject({ error: "private_relay" });
    expect(no.json.reason).toMatch(/the invite's relay dns-guard\.test \(it resolves to [^)]+\) is on a private network/);
  }, 60_000);

  it("an invite's message: the web link, how to install, how to join; on a private relay with --allow-private-relay and a note", async () => {
    const pub = user("ann-msg", RD, { [RD]: `ws://127.0.0.1:${rd.port}/v3` });
    await pub.ok(["setup", "--name", "ann", "--no-backup"]);
    const r = await pub.ok(["invite", "--no-circle"]);
    expect(r.privateRelay).toBe(false);
    expect(r.message.split("\n")).toEqual([
      `Join me on Peer2Peer: ${r.web}`,
      "New to it? In Claude Code run:",
      "  /plugin marketplace add ix-infrastructure/Peer2Peer",
      "  /plugin install peer2peer@peer2peer",
      "  /reload-plugins",
      `then: /peers join ${r.web}`,
      "Using Codex? See https://github.com/ix-infrastructure/Peer2Peer/blob/main/packages/codex-bridge/README.md#install",
      `(Already have the p2p command? p2p join '${r.web}')`,
    ]);
    // The existing fields are as they were.
    expect(r.line).toBe(`Join me on Peer2Peer: ${r.web} (or: p2p join ${r.code})`);
    const plain = await pub.run(["invite", "--no-circle"], { json: false });
    expect(plain.out).toMatch(/or the code: \S+ {2}\(p2p join 'https:\/\/ix-infra\.com\/p2p\/invite#[^']+'\)/);
    expect(plain.out).toContain("Send them this message");

    const lan = user("ann-lan-msg", RP, { [RP]: `ws://127.0.0.1:${rp.port}/v3` });
    await lan.ok(["setup", "--name", "ann", "--no-backup"]);
    const l = await lan.ok(["invite", "--no-circle"]);
    expect(l.privateRelay).toBe(true);
    expect(l.message).toContain("You need to be on the same private network as me (e.g. Tailscale)");
    expect(l.message).toContain(`then: /peers join --allow-private-relay ${l.web}`);
    expect(l.message).toContain(`p2p join --allow-private-relay '${l.web}'`);
    const lplain = await lan.run(["invite", "--no-circle"], { json: false });
    expect(lplain.out).toMatch(/\(p2p join --allow-private-relay 'https:/);
  }, 60_000);

  it("a team on its own private relay (Tailscale, a LAN): codes and links between members need no opt-in", async () => {
    // A literal private address as the team relay...
    const t = { [RP]: `ws://127.0.0.1:${rp.port}/v3` };
    const ann = user("ann-team", RP, t);
    const ben = user("ben-team", RP, t);
    for (const [u, n] of [[ann, "ann"], [ben, "ben"]] as const) await u.ok(["setup", "--name", n, "--no-backup"]);
    const code = (await ann.ok(["invite", "--no-circle"])).code as string;
    expect(code.startsWith("10.0.0.5:8443/")).toBe(true);
    const j = await ben.run(["join", "--yes", code]);
    expect(j.code, j.err).toBe(0);
    const cy = user("cy-team", RP, t);
    await cy.ok(["setup", "--name", "cy", "--no-backup"]);
    const a = await cy.run(["accept", (await ann.ok(["invite", "--link"])).link]);
    expect(a.code, a.err).toBe(0);
    // ...and a name that resolves to one (as a MagicDNS name resolves to 100.64/10): dialed through localhost here.
    const dt = { [RD]: `ws://localhost:${rd.port}/v3` };
    const dee = user("dee-team", RD, { [RD]: `ws://127.0.0.1:${rd.port}/v3` });
    const eve = user("eve-team", RD, dt);
    for (const [u, n] of [[dee, "dee"], [eve, "eve"]] as const) await u.ok(["setup", "--name", n, "--no-backup"]);
    const dcode = (await dee.ok(["invite", "--no-circle"])).code as string;
    const dj = await eve.run(["join", "--yes", dcode]);
    expect(dj.code, dj.err).toBe(0);
  }, 120_000);

  it("a relay guarded at the start of a command stays guarded when it becomes the user's own meanwhile; one already theirs is never guarded", async () => {
    const fresh = user("fresh", "", { [RD]: `ws://127.0.0.1:${rd.port}/v3` });
    const app = await fresh.app();
    try {
      expect(await app.load(false)).toBe(false);
      app.guardRelays([RD]);
      // As a code join does with no identity and no default relays: the code's relay becomes the only one.
      await init(app, { name: "fresh", relays: [RD] });
      expect(app.self?.relays).toEqual([RD]);
      expect((app as unknown as { guardedLookup(r: string): unknown }).guardedLookup(RD)).toBeTypeOf("function");
    } finally {
      await app.close();
    }
    const later = await fresh.app();
    try {
      await later.load();
      later.guardRelays([RD]);
      expect((later as unknown as { guardedLookup(r: string): unknown }).guardedLookup(RD)).toBeUndefined();
    } finally {
      await later.close();
    }
  }, 60_000);

  it("a code's relay: the inviter's document is fetched over HTTP only through the resolve-time check", async () => {
    const alice = user("alice", RD, { [RD]: `ws://127.0.0.1:${rd.port}/v3` });
    await alice.ok(["setup", "--name", "alice", "--no-backup"]);
    const aliceId = (await alice.ok(["whoami"])).userId as string;
    // A redeemer whose route to the code's relay is a name that resolves to loopback.
    const viaName = user("dns", RD, { [RD]: `ws://localhost:${rd.port}/v3` });
    for (const guarded of [true, false]) {
      const app = await viaName.app();
      try {
        if (guarded) app.guardRelays([RD]);
        const v = await app.refreshIdentity(aliceId, [RD], { force: true, quiet: true });
        if (guarded) expect(v).toBeUndefined();
        else expect(v?.iss ?? (v as { userId?: string } | undefined)?.userId ?? v).toBeTruthy();
      } finally {
        await app.close();
      }
    }
  }, 60_000);
});
