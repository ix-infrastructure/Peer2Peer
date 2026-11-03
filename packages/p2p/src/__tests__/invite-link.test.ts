// Copyright 2026 Ix Infrastructure Inc.
//
// One invite link (https://ix-infra.com/p2p/invite#<relay>/<CODE>) that makes the person a friend and
// joins them to the circles the inviter chose (docs/protocol.md P4): the strict link parser, several
// circles in one code, what fails rather than silently joining less, the redeemer's one yes before
// anything is accepted, and what a join must not change (running sessions, an existing default).

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseCircleInviteLink, parseInviteLink } from "@peer2peer/core/v3";
import {
  canonicalShortCode,
  codeFromWebLink,
  codeWebLink,
  encodeCodeChars,
  formatShortCode,
  groupCode,
  isPrivateAddress,
  isPrivateRelayHost,
  newCodeSecret,
  parseInviteBundle,
  parseShortCode,
  privateGuardLookup,
} from "../shortcode.js";
import { alongside, startRelay, User, type TestRelay } from "./harness.js";

const R1 = "wss://invite-link.test/v3";
let r1: TestRelay;
let t: Record<string, string>;
const users: User[] = [];

function user(name: string, extra: Record<string, string> = {}): User {
  const u = new User(name, t, { P2P_DEFAULT_RELAYS: R1, ...extra });
  users.push(u);
  return u;
}

async function setUp(name: string, extra: Record<string, string> = {}): Promise<User> {
  const u = user(name, extra);
  await u.ok(["setup", "--name", name, "--no-backup"]);
  return u;
}

beforeAll(async () => {
  r1 = await startRelay(R1);
  t = { [R1]: `ws://127.0.0.1:${r1.port}/v3` };
});

afterAll(async () => {
  await r1?.close();
  for (const u of users) u.cleanup();
});

describe("the join line's quoting", () => {
  it("a web link goes in single quotes as it is; anything else is quoted so a ' can't break out", async () => {
    const { joinCommandFor, shellQuote } = await import("../codes.js");
    const web = "https://ix-infra.com/p2p/invite#relay.example:8443/x/K7QM-3XPD-9TWA-HF2N-6RJC";
    expect(joinCommandFor(web, false)).toBe(`p2p join '${web}'`);
    expect(joinCommandFor(web, true)).toBe(`p2p join --allow-private-relay '${web}'`);
    expect(joinCommandFor("https://ix-infra.com/p2p/invite#[2001:db8::1]:8443/K7QM-3XPD-9TWA-HF2N-6RJC", false)).toContain("'https://ix-infra.com/p2p/invite#[2001:db8::1]:8443/");
    const evil = "https://ix-infra.com/p2p/invite#x'; rm -rf ~; echo '";
    expect(joinCommandFor(evil, false)).toBe(`p2p join ${shellQuote(evil)}`);
    const { execFileSync: run } = await import("node:child_process");
    // The whole line, as a shell reads it: `p2p join` and then exactly the one argument.
    expect(run("/bin/sh", ["-c", `p2p() { printf '%s|' "$@"; }; ${joinCommandFor(evil, false)}`]).toString()).toBe(`join|${evil}|`);
    // A POSIX shell reads it back as the one argument it was.
    const { execFileSync } = await import("node:child_process");
    for (const s of [evil, "a'b", "'", "''", "x\\'y", "$(id) `id` \"q\""]) {
      expect(execFileSync("/bin/sh", ["-c", `printf %s ${shellQuote(s)}`]).toString()).toBe(s);
    }
  });
});

describe("the web link", () => {
  const s = newCodeSecret();
  const chars = encodeCodeChars(s);
  const grouped = groupCode(chars);

  it("wraps the same code; the relay part may be a DNS name or [IPv6], with a port and a path", () => {
    for (const relay of ["wss://relay.example/v3", "wss://relay.example:8443/v3", "wss://relay.example:8443/team/v3", "wss://[2001:db8::1]:8443/v3", "wss://[2001:db8::7]/custom"]) {
      const short = formatShortCode(relay, s);
      const link = codeWebLink(short);
      expect(link).toBe(`https://ix-infra.com/p2p/invite#${short}`);
      const p = parseShortCode(link);
      expect(p.secret).toEqual(s);
      expect(p.relay).toBe(relay);
      // Messages name the code as parsed, never the raw input.
      expect(canonicalShortCode(p)).toBe(short);
    }
  });

  it("knows the special-purpose ranges, including IPv6 forms that carry a private IPv4 address", () => {
    const priv = [
      "0.1.2.3", "10.0.0.1", "100.64.0.1", "100.127.255.255", "127.0.0.1", "169.254.169.254", "172.16.0.1", "172.31.0.1", "192.168.0.1",
      "198.18.0.1", "198.19.255.255", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
      "::", "::1", "::10.0.0.1", "::a00:1", "::8.8.8.8", "::ffff:127.0.0.1", "::ffff:7f00:1", "0:0:0:0:0:ffff:192.168.1.1",
      "64:ff9b::10.0.0.1", "64:ff9b::a00:1", "64:ff9b::7f00:1", "64:ff9b:1::8.8.8.8", "2002:a00:1::", "2002:7f00:1::1", "2002:c0a8:101::",
      "fc00::1", "fdff::1", "fe80::1", "febf::1", "fec0::1", "feff::1", "ff02::1", "ff0e::1", "fe80::1%eth0",
    ];
    for (const ip of priv) expect(isPrivateAddress(ip), ip).toBe(true);
    const pub = ["8.8.8.8", "1.1.1.1", "100.63.255.255", "100.128.0.1", "172.15.0.1", "172.32.0.1", "192.169.0.1", "198.17.0.1", "198.20.0.1", "223.255.255.255", "2001:db8::1", "2606:4700::1111", "64:ff9b::8.8.8.8", "2002:808:808::", "::ffff:8.8.8.8", "fbff::1"];
    for (const ip of pub) expect(isPrivateAddress(ip), ip).toBe(false);
    // And as a code's relay host, in brackets.
    for (const h of ["[::a00:1]", "[64:ff9b::a00:1]", "[2002:c0a8:101::1]", "[fec0::1]", "[ff02::1]", "224.0.0.1", "198.18.0.1", "240.0.0.1", "255.255.255.255"]) {
      expect(() => parseShortCode(`${h}/${grouped}`), h).toThrow(/private network/);
    }
  });

  it("a name that resolves to a private address is refused when the code's relay is dialed (resolved once, never again)", async () => {
    const answers: Record<string, string[]> = { "127.0.0.1.nip.io": ["127.0.0.1"], "localtest.me": ["::1", "127.0.0.1"], "mixed.example": ["93.184.216.34", "10.0.0.5"], "relay.example": ["93.184.216.34", "2606:4700::1111"] };
    const calls: string[] = [];
    const lookup = privateGuardLookup((host, _o, cb) => {
      calls.push(host);
      const a = answers[host];
      if (!a) return cb(Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" }), []);
      cb(null, a.map((address) => ({ address, family: address.includes(":") ? 6 : 4 })));
    });
    const ask = (host: string, all = false) =>
      new Promise<{ err?: Error; address?: unknown; family?: number }>((res) => (lookup as (h: string, o: object, cb: (e: Error | null, a?: unknown, f?: number) => void) => void)(host, { all }, (err, address, family) => res({ err: err ?? undefined, address, family })));
    for (const h of ["127.0.0.1.nip.io", "localtest.me", "mixed.example"]) {
      const r = await ask(h);
      expect(r.err?.message, h).toMatch(/resolves to a loopback, link-local or private address/);
    }
    // A public name: the first address, which the socket then dials as is.
    expect(await ask("relay.example")).toMatchObject({ address: "93.184.216.34", family: 4 });
    expect((await ask("relay.example", true)).address).toEqual([{ address: "93.184.216.34", family: 4 }, { address: "2606:4700::1111", family: 6 }]);
    expect((await ask("nowhere.example")).err).toBeDefined();
    expect(calls.filter((h) => h === "relay.example")).toHaveLength(2);
  });

  it("refuses a relay on a loopback, link-local or private host (in the link and in a bare code) unless opted in", () => {
    const priv = ["localhost", "relay.localhost", "printer.local", "127.0.0.1", "127.8.9.1:8443", "10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.1.10:9000/team", "169.254.169.254", "0.0.0.0", "100.64.0.1", "[::1]", "[::]", "[fd00::1]", "[fc12:3456::1]:8443", "[fe80::1]", "[::ffff:10.0.0.1]", "[::ffff:127.0.0.1]"];
    for (const host of priv) {
      for (const input of [`${host}/${grouped}`, `https://ix-infra.com/p2p/invite#${host}/${grouped}`, `wss://${host}/${grouped}`]) {
        expect(() => parseShortCode(input), input).toThrow(/is on a private network \(for example Tailscale or a LAN\)\. If you trust the person who sent it, run the same command again with --allow-private-relay \(in Claude Code: \/peers join --allow-private-relay <code>\)/);
        // The user's own relay is never refused, whatever its address.
        expect(parseShortCode(input, { own: [parseShortCode(input, { allowPrivate: true }).relay!] }).secret, input).toEqual(s);
        expect(parseShortCode(input, { allowPrivate: true }).secret, input).toEqual(s);
      }
    }
    for (const host of ["relay.example", "8.8.8.8", "172.32.0.1", "172.15.0.1", "192.169.0.1", "[2001:db8::1]", "[2606:4700::1111]", "local.example.com"]) {
      expect(parseShortCode(`${host}/${grouped}`).secret, host).toEqual(s);
    }
    expect(isPrivateRelayHost("[FE80::abcd]")).toBe(true);
    expect(isPrivateRelayHost("127.0.0.1.nip.io")).toBe(false); // a name: caught when it is resolved (below)
    expect(isPrivateRelayHost("example.local.")).toBe(true);
    // A bare code names no relay: it is looked up on your own relays.
    expect(parseShortCode(grouped).relay).toBeUndefined();
  });

  it("accepts the code in any spelling the page allows, and the command as the page copies it", () => {
    const base = "https://ix-infra.com/p2p/invite#relay.example:8443/x/";
    const forms = [grouped, chars, chars.toLowerCase(), grouped.toLowerCase().replace(/0/g, "o").replace(/1/g, "l")];
    for (const f of forms) expect(parseShortCode(base + f).secret).toEqual(s);
    // `p2p join 'https://…'` pasted whole (into /peers join), or with double quotes.
    expect(parseShortCode(`p2p join '${base}${grouped}'`).relay).toBe("wss://relay.example:8443/x");
    expect(parseShortCode(`"${base}${grouped}"`).secret).toEqual(s);
    expect(parseShortCode(`  ${base}${grouped}  `).secret).toEqual(s);
  });

  it("is strict: https only, host exactly ix-infra.com, path exactly /p2p/invite, no query, a code in the fragment", () => {
    const frag = `relay.example/${grouped}`;
    const bad = [
      `http://ix-infra.com/p2p/invite#${frag}`,
      `https://evil.example/p2p/invite#${frag}`,
      `https://ix-infra.com.evil.example/p2p/invite#${frag}`,
      `https://www.ix-infra.com/p2p/invite#${frag}`,
      `https://ix-infra.com:8443/p2p/invite#${frag}`,
      `https://user@ix-infra.com/p2p/invite#${frag}`,
      `https://ix-infra.com/p2p/invite/#${frag}`,
      `https://ix-infra.com/p2p/invitex#${frag}`,
      `https://ix-infra.com/p2p/Invite#${frag}`,
      `https://ix-infra.com/p2p/invite?x=1#${frag}`,
      "https://ix-infra.com/p2p/invite",
      "https://ix-infra.com/p2p/invite#",
      `https://ix-infra.com/p2p/invite#relay.example/${chars.slice(1)}`,
      `https://ix-infra.com/p2p/invite#relay.example/${chars}X`,
      `https://ix-infra.com/p2p/invite#relay example/${grouped}`,
      `https://ix-infra.com/p2p/invite#relay.example/${grouped}?x`,
      `ftp://ix-infra.com/p2p/invite#${frag}`,
      `javascript:alert(1)//ix-infra.com/p2p/invite#${frag}`,
      // Dot segments, an empty query, encoded characters: refused, never normalised into the accepted path.
      `https://ix-infra.com/p2p/./invite#${frag}`,
      `https://ix-infra.com/p2p/x/../invite#${frag}`,
      `https://ix-infra.com/x/../p2p/invite#${frag}`,
      `https://ix-infra.com/p2p/%69nvite#${frag}`,
      `https://ix-infra.com/p2p/invite?#${frag}`,
      `https://ix-infra.com./p2p/invite#${frag}`,
      // Whitespace or control characters anywhere inside.
      `https://ix-infra.com/p2p/invite#relay.example/${grouped.slice(0, 4)} ${grouped.slice(4)}`,
      `https://ix-infra.com/p2p/in\tvite#${frag}`,
      `https://ix-infra.com/p2p/invite#${frag}\u0000`,
      `https://ix-infra.com/p2p/invite\n#${frag}`,
      `https://ix-infra.com/p2p/invite#relay.example/\u007f${grouped}`,
    ];
    for (const b of bad) expect(() => parseShortCode(b), JSON.stringify(b)).toThrow(/not .*invite|isn't an invite code|not a relay host|not an invite code|spaces or control characters/);
  });

  it("the other links keep their own parsers, and join says which command takes them", () => {
    const jws = "eyJhbGciOiJFZERTQSJ9.eyJ4IjoxfQ.c2ln";
    const b64 = Buffer.from(jws).toString("base64url");
    for (const l of [`https://ix-infra.com/p2p/i#${b64}`, `https://peer2peer.dev/i#${b64}`, `p2p://invite/${b64}`]) {
      // Each prefix is still recognised (what's after it is checked further, as before).
      expect(() => parseInviteLink(l)).not.toThrow(/not an invite link/);
      expect(() => parseShortCode(l)).toThrow(/long invite link: use `p2p accept/);
    }
    for (const l of [`https://ix-infra.com/p2p/c#${b64}`, `https://peer2peer.dev/c#${b64}`, `p2p://circle/${b64}`]) {
      expect(() => parseCircleInviteLink(l)).not.toThrow(/not a circle link/);
      expect(() => parseShortCode(l)).toThrow(/circle link: use `p2p circle join/);
    }
    expect(codeFromWebLink(`relay.example:8443/${grouped}`)).toBeUndefined();
  });

  it("the bundle's `circles` (heads only, at most 4 beside `circle`) is read only beside a `circle`", () => {
    expect(parseInviteBundle({ v: 1, invite: "a.b.c", circle: { head: "h1" }, circles: [{ head: "h2" }, { head: "h3" }] })).toEqual({ v: 1, invite: "a.b.c", circle: { head: "h1" }, circles: [{ head: "h2" }, { head: "h3" }] });
    expect(() => parseInviteBundle({ v: 1, invite: "a.b.c", circles: [{ head: "h2" }] })).toThrow(/malformed/);
    expect(() => parseInviteBundle({ v: 1, invite: "a.b.c", circle: { head: "h1" }, circles: Array.from({ length: 5 }, () => ({ head: "h" })) })).toThrow(/malformed/);
    // A field this version doesn't know is ignored, as a client before `circles` ignores `circles`.
    expect(parseInviteBundle({ v: 1, invite: "a.b.c", circle: { head: "h1" }, later: 1 })).toEqual({ v: 1, invite: "a.b.c", circle: { head: "h1" } });
  });
});

describe("one code, several circles", () => {
  let alice: User;
  let team: string;
  let ops: string;

  beforeAll(async () => {
    alice = await setUp("alice");
    team = (await alice.ok(["circle", "create", "team"])).cid;
    ops = (await alice.ok(["circle", "create", "ops"])).cid;
    await alice.ok(["circle", "default", team]);
  }, 60_000);

  it("the redeemer sees who and what, says yes once, and is in every circle; the inviter is told each outcome", async () => {
    const inv = await alice.ok(["invite", "bob", "--circle", team, "--circle", ops]);
    expect(inv.circles.map((c: { cid: string }) => c.cid)).toEqual([team, ops]);
    expect(inv.web).toBe(`https://ix-infra.com/p2p/invite#${inv.code}`);
    const bob = await setUp("bob");
    // A running session of Bob's, private (no default circle yet): a join must not move it.
    await bob.ok(["session", "roster", "running"]);

    // Nothing accepted without the yes; the preview names the inviter (fingerprint) and every circle.
    const no = await bob.run(["join", inv.web]);
    expect(no.json).toMatchObject({ error: "confirm_required" });
    expect(no.json.reason).toMatch(/^alice@[a-z2-7-]+ \(fingerprint [a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}\) invites you to be friends, and to join "team" \(1 member, invite-only, theirs\), "ops" \(1 member, invite-only, theirs\)\. Join with --yes/);
    expect((await bob.ok(["friends"])).friends).toEqual([]);
    const pv = await bob.ok(["join", "--preview", inv.web]);
    const aliceId = (await alice.ok(["whoami"])).userId;
    expect(pv.preview.circles).toMatchObject([
      { cid: team, name: "team", members: 1, policy: "invite", owner: aliceId, verified: true, auto: true },
      { cid: ops, name: "ops", members: 1, policy: "invite", owner: aliceId, verified: true, auto: true },
    ]);

    const j = await alongside(bob.run(["join", "--confirmed", inv.web, "--wait", "12"]), () => alice.ok(["invites"]));
    expect(j.code).toBe(0);
    expect(j.json.circles.map((c: { cid: string; status: string }) => [c.cid, c.status])).toEqual([
      [team, "joined"],
      [ops, "joined"],
    ]);
    // Only the code's first circle may become the default, and only because there was none.
    expect(j.json.defaultCircle).toBe(team);
    const told = await alice.run(["invites"]);
    expect(told.json.invites[0]).toMatchObject({ status: "redeemed", circles: [{ cid: team }, { cid: ops }] });
    const bobId = (await bob.ok(["whoami"])).userId as string;
    for (const cid of [team, ops]) expect((await alice.ok(["circle", "members", cid])).members.map((m: { userId: string }) => m.userId)).toContain(bobId);

    // The running session stayed private; a new one starts in the default circle.
    expect((await bob.ok(["session", "roster", "running"])).roster).toMatchObject({ vis: "private" });
    expect((await bob.ok(["session", "roster", "fresh"])).roster).toMatchObject({ vis: "circle", circle: team });

    // `p2p remove` undoes it: unfriended, and out of both circles.
    const rm = await alice.ok(["remove", bobId]);
    expect(rm.circles.map((c: { cid: string; result: string }) => [c.cid, c.result]).sort()).toEqual([
      [ops, "removed"],
      [team, "removed"],
    ].sort());
  }, 90_000);

  it("p2p remove takes them out only of the circles the code put them in, never one they were in already", async () => {
    const erin = await setUp("erin");
    const erinId = (await erin.ok(["whoami"])).userId as string;
    const extra = (await alice.ok(["circle", "create", "extra"])).cid;
    // erin is in "ops" before any code (alice added her).
    await alice.ok(["circle", "propose", ops, "add", erinId]);
    const inv = await alice.ok(["invite", "--circle", extra, "--circle", ops]);
    await alongside(erin.run(["join", "--yes", inv.code, "--wait", "12"]), () => alice.ok(["invites"]));
    const rec = Object.values((await (async () => {
      const app = await alice.app();
      await app.load();
      try {
        return (await app.state.get("codes")) ?? {};
      } finally {
        await app.close();
      }
    })()) as Record<string, { lid: string; redeemedBy?: string; added?: string[] }>).find((c) => c.redeemedBy === erinId);
    expect(rec?.added).toEqual([extra]);
    const rm = await alice.ok(["remove", erinId]);
    expect(rm.circles).toEqual([{ cid: extra, result: "removed" }]);
    expect((await alice.ok(["circle", "members", ops])).members.map((m: { userId: string }) => m.userId)).toContain(erinId);
    expect((await alice.ok(["circle", "members", extra])).members.map((m: { userId: string }) => m.userId)).not.toContain(erinId);
  }, 90_000);

  it("a code for one person says so; with no identity here yet, it is refused before one is made", async () => {
    const hal = await setUp("hal");
    const halId = (await hal.ok(["whoami"])).userId as string;
    const inv = await alice.ok(["invite", "--to", halId, "--no-circle"]);
    const asked = await hal.run(["join", inv.web]);
    expect(asked.json).toMatchObject({ error: "confirm_required", preview: { to: halId, toAddress: expect.stringMatching(/^hal@/) } });
    expect(asked.json.reason).toMatch(/This code is for hal@[a-z2-7-]+\./);
    const other = await alice.ok(["invite", "--to", halId, "--no-circle"]);
    const fresh = user("nobody-yet");
    const r = await fresh.run(["join", "--yes", other.web, "--name", "nobody"]);
    expect(r.json).toMatchObject({ error: "not_for_you" });
    expect(r.json.reason).toMatch(/this code is for \S+@[a-z2-7-]+, and there is no identity here yet/);
    // Nothing was made: still no identity here.
    expect((await fresh.run(["whoami"])).code).not.toBe(0);
  }, 90_000);

  it("an existing default circle is never changed by a join", async () => {
    const own = await setUp("dora");
    const mine = (await own.ok(["circle", "create", "mine"])).cid;
    await own.ok(["circle", "default", mine]);
    const inv = await alice.ok(["invite", "--circle", ops]);
    const j = await alongside(own.run(["join", "--yes", inv.code, "--wait", "12"]), () => alice.ok(["invites"]));
    expect(j.json.circles[0]).toMatchObject({ cid: ops, status: "joined", default: false });
    expect((await own.ok(["whoami"])).defaultCircle).toBe(mine);
  }, 90_000);

  it("a named circle this user can't add people to fails the whole code, naming it: no code is made", async () => {
    const carol = await setUp("carol");
    const theirs = (await carol.ok(["circle", "create", "theirs"])).cid;
    const c = await carol.ok(["invite", "--circle", theirs]);
    await alongside(alice.run(["join", "--confirmed", c.code, "--wait", "12"]), () => carol.ok(["invites"]));
    expect((await alice.ok(["circle", "ls"])).circles.find((x: { cid: string }) => x.cid === theirs)).toMatchObject({ joined: true, role: "member" });
    const before = (await alice.ok(["invites"])).invites.length;
    const r = await alice.run(["invite", "--circle", team, "--circle", theirs]);
    expect(r.json).toMatchObject({ error: "not_admin" });
    expect(r.json.reason).toContain(`"theirs" (${theirs}): only its owner or an admin can add people`);
    expect((await alice.ok(["invites"])).invites.length).toBe(before);
    // More than five: refused too.
    const six = await alice.run(["invite", ...Array.from({ length: 6 }, () => ["--circle", team]).flat()]);
    expect(six.json.error).toBe("usage");
  }, 90_000);

  it("an open circle is refused (it has its own link)", async () => {
    const open = (await alice.ok(["circle", "create", "lobby", "--open"])).cid;
    const r = await alice.run(["invite", "--circle", open]);
    expect(r.json).toMatchObject({ error: "not_admin" });
    expect(r.json.reason).toMatch(/it is open/);
  }, 60_000);

  it("a bundle that won't fit fails with a clear message, never dropping a circle", async () => {
    const small = user("alice", { P2P_INVITE_BLOB_MAX: "2000" });
    Object.defineProperty(small, "home", { value: alice.home });
    const r = await small.run(["invite", "--circle", team, "--circle", ops]);
    expect(r.json).toMatchObject({ error: "too_large" });
    expect(r.json.reason).toMatch(/joining these 2 circles doesn't fit in a code .*name fewer circles/);
  }, 60_000);

  it("a code's relay whose name resolves to a private address is refused at connect time, unless opted in", async () => {
    const inv = await alice.ok(["invite", "--no-circle"]);
    // This redeemer reaches the code's relay through a name that resolves to loopback (as 127.0.0.1.nip.io would).
    const via = (extra: Record<string, string> = {}) => {
      const u = new User("dns", { [R1]: `ws://localhost:${r1.port}/v3` }, { P2P_DEFAULT_RELAYS: R1, ...extra });
      users.push(u);
      return u;
    };
    const r = await via().run(["join", "--preview", inv.web]);
    expect(r.json).toMatchObject({ error: "private_relay" });
    expect(r.json.reason).toMatch(/\(it resolves to [^)]+\) is on a private network.*--allow-private-relay \(in Claude Code: \/peers join --allow-private-relay <code>\)/);
    // Opted in: the same code opens (refused before the take, so it is still there).
    const ok = await via().run(["join", "--preview", "--allow-private-relay", inv.web]);
    expect(ok.json?.preview?.from?.userId, ok.err).toBe((await alice.ok(["whoami"])).userId);
  }, 60_000);

  it("revoked after it was sent: the link no longer works", async () => {
    const inv = await alice.ok(["invite", "--circle", team]);
    expect(await alice.ok(["invites", "revoke", inv.code])).toMatchObject({ revoked: true, wasOpen: true });
    const late = await setUp("late");
    expect((await late.run(["join", "--confirmed", inv.web])).json).toMatchObject({ error: "code_not_found" });
  }, 60_000);
});
