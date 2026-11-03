// Copyright 2026 Ix Infrastructure Inc.
//
// Regression tests for the pre-release re-review and the Claude mod findings,
// over in-process relays.

import { createServer, type Server } from "node:net";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createIdentityDoc, peekIdentityDoc } from "@peer2peer/core/v3";
import type { App } from "../app.js";
import { main } from "../cli.js";
import { linkJoin, linkStart } from "../identity.js";
import { receiving } from "../inbound.js";
import { RelayPool } from "../relay-client.js";
import { getHeld, withHeldId } from "../social.js";
import { importSync } from "../sync.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-rr.test/v3";
const RX = "wss://relay-refuse.test/v3";
let relay: TestRelay;
let refusing: TestRelay;
let t: Record<string, string>;
const users: User[] = [];
const ids: Record<string, string> = {};

function user(name: string, relayUrl = R): User {
  const u = new User(name, t);
  void relayUrl;
  users.push(u);
  return u;
}

async function init(u: User, relayUrl = R): Promise<string> {
  ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", relayUrl, "--yes"])).userId;
  return ids[u.name];
}

async function opened(u: User): Promise<App> {
  const a = await u.app();
  await a.load();
  receiving(a);
  return a;
}

async function link(owner: User, home: User, keyholder = false): Promise<string> {
  const a = await opened(owner);
  const s = await linkStart(a, { keyholder });
  const b = await home.app();
  const j = await linkJoin(b, s.code);
  const [, joined] = await Promise.all([s.wait(async (req) => req.compareCode === j.compareCode), j.wait()]);
  await a.close();
  await b.close();
  return joined.did;
}

/**
 * A second key holder publishes a sibling of `base` (the race of §2.5: it
 * hadn't seen the other key holder's version), building it by hand.
 */
async function racingSibling(k2: User, baseDoc: string, name: string): Promise<string> {
  const a = await opened(k2);
  const base = peekIdentityDoc(baseDoc);
  const doc = createIdentityDoc(a.ik!, {
    ver: base.ver + 1,
    prev: base.hash,
    name,
    relays: base.relays,
    devices: base.devices,
    keyholders: base.keyholders,
    by: a.did,
    certs: base.certs,
  });
  await a.connect();
  const r = await a.publishDoc(doc, base.relays);
  await a.close();
  expect(r.ok.length).toBeGreaterThan(0);
  return doc;
}

async function headOf(u: User): Promise<string> {
  const a = await opened(u);
  const v = await a.ownView();
  await a.close();
  return v.head.jws;
}

beforeAll(async () => {
  relay = await startRelay(R);
  // A relay that accepts no restricted (restoring) publish at all.
  refusing = await startRelay(RX, { limits: { restrictedIdentityPerIssPerHour: 0 } });
  t = { [R]: `ws://127.0.0.1:${relay.port}/v3`, [RX]: `ws://127.0.0.1:${refusing.port}/v3` };
});

afterAll(async () => {
  await relay?.close();
  await refusing?.close();
  for (const u of users) u.cleanup();
});

describe("pre-release re-review N-H1: forks are merged, never turned into lost devices", () => {
  it("a device linked during a concurrent renewal is kept (merge, then re-added), not retired", async () => {
    const k1 = user("fk1");
    await init(k1);
    const k2 = user("fk2");
    await link(k1, k2, true);
    const base = await headOf(k1);
    // K1 links N while K2, not having seen it, publishes a sibling (e.g. a renewal).
    const n = user("fkn");
    const nDid = await link(k1, n);
    await racingSibling(k2, base, "fk1");
    // K1's next publish sees two tips: it merges, then re-adds N (dropped by the merge only).
    const r = await k1.ok(["profile", "set", "--bio", "after the fork"]);
    expect(r.ver).toBeGreaterThan(peekIdentityDoc(base).ver + 2);
    const w = await k1.ok(["whoami"]);
    expect(w.doc.forked).toBe(false);
    expect(w.devices.map((d: { did: string }) => d.did)).toContain(nDid);
    // N is still a working device: the relay lets it in (not retired), and it can act.
    expect((await n.run(["friends"])).code).toBe(0);
    expect(relay.relay.identity.revoked(ids.fk1).has(nDid)).toBe(false);
    expect(relay.relay.identity.allowedDevices(ids.fk1)?.has(nDid)).toBe(true);
  });

  it("three tips are merged pairwise, then extended", async () => {
    const k1 = user("tk1");
    await init(k1);
    const k2 = user("tk2");
    await link(k1, k2, true);
    const base = await headOf(k1);
    await racingSibling(k2, base, "tk1-a");
    await racingSibling(k2, base, "tk1-b");
    await racingSibling(k2, base, "tk1-c");
    const r = await k1.ok(["profile", "set", "--bio", "three tips"]);
    const w = await k1.ok(["whoami"]);
    expect(w.doc.forked).toBe(false);
    // Three siblings at ver b+1, two merges (b+2, b+3), then the extension at b+4.
    expect(r.ver).toBe(peekIdentityDoc(base).ver + 4);
  });

  it("a restore succeeds during a two-tip fork (merge by a common key holder, then the extension)", async () => {
    const k1 = user("rk1");
    await init(k1);
    const k2 = user("rk2");
    await link(k1, k2, true);
    const base = await headOf(k1);
    await racingSibling(k2, base, "rk1-x");
    await racingSibling(k2, base, "rk1-y");
    const phrase = (await k1.ok(["backup", "show"])).phrase as string;
    const fresh = user("rk-restored");
    const r = await fresh.ok(["backup", "restore", "--relay", R], { stdin: phrase });
    expect(r.userId).toBe(ids.rk1);
    expect(r.merged).toBe(1);
    expect((await fresh.ok(["whoami"])).doc.forked).toBe(false);
  });

  it("a restore no relay accepts exits non-zero and commits nothing", async () => {
    const owner = user("refowner", RX);
    await init(owner, RX);
    const phrase = (await owner.ok(["backup", "show"])).phrase as string;
    const fresh = user("refused");
    const r = await fresh.run(["backup", "restore", "--relay", RX], { stdin: phrase });
    expect(r.code).toBe(1);
    expect(r.json.error).toBe("not_published");
    expect(existsSync(join(fresh.home, "cli", "keys.json"))).toBe(false);
    expect((await fresh.run(["whoami"])).json.error).toBe("no_identity");
  });
});

describe("block re-keys circle join caps", () => {
  it("the blocked user's copy of our join cap stops reaching us; other members get the new one", async () => {
    const a = user("ba");
    await init(a);
    const b = user("bb");
    await init(b);
    const c = user("bc");
    await init(c);
    const circle = await a.ok(["circle", "create", "rekey", "--open"]);
    const lnk = (await a.ok(["circle", "invite", circle.cid, "--link"])).link as string;
    for (const u of [b, c]) {
      await u.ok(["circle", "join", lnk, "--wait", "0"]);
      await a.ok(["circle", "ls"]);
      await u.ok(["circle", "join", lnk, "--wait", "3", "--yes"]);
      await a.ok(["circle", "ls"]);
    }
    for (const u of [b, c]) await u.ok(["circle", "ls"]);
    for (const u of [a, b, c]) await u.ok(["circle", "default", circle.cid]);
    await a.ok(["status", "--session", "as", "--state", "busy"]);
    // Before: b reaches a.
    expect((await b.ok(["send", "--from-session", "bs", "--to", `${ids.ba}/as`, "before"])).delivered).toBe(true);
    const bl = await a.ok(["block", ids.bb]);
    expect(bl.rekeyedCircles).toEqual([circle.cid]);
    // After: b's held join cap of a's is revoked at the relay: delivered via 0.
    const after = await b.run(["send", "--from-session", "bs", "--to", `${ids.ba}/as`, "after"]);
    expect(after.code).toBe(1);
    expect(after.json.error).toBe("undelivered");
    // c got a's new statement (and cap) and still reaches a.
    expect((await c.ok(["send", "--from-session", "cs", "--to", `${ids.ba}/as`, "still here"])).delivered).toBe(true);
  });
});

describe("Claude mod review items", () => {
  it("reconnects back off (one timer per relay, 1 s, 2 s, ...) and re-read the device auth on every dial", async () => {
    let accepts = 0;
    const srv: Server = createServer((s) => {
      accepts++;
      s.destroy();
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
    const port = (srv.address() as { port: number }).port;
    const dead = "wss://flaky.test/v3";
    const authCalls = vi.fn(() => ({ cert: "c", signingSecretKey: new Uint8Array(32) }));
    const pool = new RelayPool({ relays: [dead], transport: () => ({ ws: `ws://127.0.0.1:${port}/v3`, http: "" }), auth: authCalls, timeoutMs: 1000, reconnect: true });
    await pool.connect();
    // After each failure exactly one reconnect is pending (the old code scheduled two per failure).
    const pendingTimers = () => (pool as unknown as { timers: Set<unknown> }).timers.size;
    for (const at of [300, 1500, 2600]) {
      await new Promise((r) => setTimeout(r, at - (at === 300 ? 0 : at === 1500 ? 300 : 1500)));
      expect(pendingTimers()).toBe(1);
    }
    await new Promise((r) => setTimeout(r, 1000));
    pool.close();
    srv.close();
    // Initial dial, then at +1 s and +3 s: never the doubling of a timer per failure.
    expect(pool.dials.get(dead)).toBeLessThanOrEqual(3);
    expect(accepts).toBeLessThanOrEqual(3);
    expect(authCalls).toHaveBeenCalledTimes(pool.dials.get(dead)!);
  });

  it("a failed identity lookup is retried after P2P_DISCOVER_RETRY_SEC", async () => {
    const u = user("disc");
    await init(u);
    for (const [ttl, calls] of [["60", 1], ["0", 2]] as const) {
      const app = new (await import("../app.js")).App({ env: { ...u.env, P2P_DISCOVER_RETRY_SEC: ttl }, io: { out: () => {}, err: () => {} } });
      await app.load();
      const spy = vi.spyOn(app, "refreshIdentity");
      const nobody = `p2p:${"a".repeat(52)}`;
      expect(await app.discover(nobody)).toBeUndefined();
      expect(await app.discover(nobody)).toBeUndefined();
      expect(spy).toHaveBeenCalledTimes(calls);
      await app.close();
    }
  });

  it("one failing item doesn't abort the rest of a sync", async () => {
    const u = user("iso");
    await init(u);
    const app = await opened(u);
    const lines: string[] = [];
    (app as unknown as { io: { err: (s: string) => void } }).io.err = (s) => lines.push(s);
    vi.spyOn(app, "refreshIdentity").mockImplementationOnce(async () => {
      throw new Error("boom");
    });
    const peer = ids.disc;
    const someDoc = await headOf(users.find((x) => x.name === "disc")!);
    await importSync(app, { contacts: [someDoc, someDoc], petnames: { [peer]: "still-set" } });
    expect(await app.store.getPetname(peer)).toBe("still-set");
    expect(lines.some((l) => l.includes("boom"))).toBe(true);
    await app.close();
  });

  it("ls --json reports relay health and, per row, rule/viewerRule/circle", async () => {
    const a = user("la");
    await init(a);
    const b = user("lb");
    await init(b);
    const circle = await a.ok(["circle", "create", "lsc", "--open"]);
    const lnk = (await a.ok(["circle", "invite", circle.cid, "--link"])).link as string;
    await b.ok(["circle", "join", lnk, "--wait", "0"]);
    await a.ok(["circle", "ls"]);
    await b.ok(["circle", "join", lnk, "--wait", "3"]);
    await a.ok(["circle", "ls"]);
    await b.ok(["circle", "ls"]);
    await a.ok(["circle", "default", circle.cid]);
    await a.ok(["status", "--session", "las", "--state", "busy"]);
    const ls = await b.ok(["ls"]);
    expect(ls.relays).toEqual({ listed: [R], connected: [R], failed: [] });
    const row = ls.peers.find((p: { own: string }) => p.own === ids.la);
    expect(row).toMatchObject({ rule: "circle", viewerRule: "circle", senderRule: "owner", circle: circle.cid });
    // A relay that's down shows up as failed.
    const off = new User("lb-off", { [R]: "ws://127.0.0.1:9/v3" }, { P2P_HOME: b.home });
    const ls2 = await off.ok(["ls"]);
    expect(ls2.relays.connected).toEqual([]);
    expect(ls2.relays.failed[0].url).toBe(R);
  });
});

describe("held ids", () => {
  it("are 16 b32 characters of SHA-256 over the held object; approve needs an exact id or a unique 8+ prefix", async () => {
    const base = { type: "invite" as const, from: `p2p:${"b".repeat(52)}`, at: 1, invite: "x.y.z" };
    const one = withHeldId(base);
    expect(one.id).toMatch(/^i[a-z2-7]{16}$/);
    expect(withHeldId({ ...base, at: 99 }).id).toBe(one.id); // arrival time isn't part of it
    expect(withHeldId({ ...base, invite: "x.y.w" }).id).not.toBe(one.id);
    const u = user("held");
    await init(u);
    const app = await opened(u);
    const two = { ...withHeldId({ ...base, invite: "a.b.c" }) };
    // Force a shared 8-char prefix to check ambiguity handling.
    const clash = { ...two, id: `${one.id.slice(0, 9)}zzzzzzzz` };
    await app.state.put("held", [one, clash]);
    expect((await getHeld(app, one.id)).id).toBe(one.id);
    await expect(getHeld(app, one.id.slice(0, 9))).rejects.toMatchObject({ code: "ambiguous" });
    await expect(getHeld(app, one.id.slice(0, 5))).rejects.toMatchObject({ code: "not_found" });
    await app.state.put("held", [one]);
    expect((await getHeld(app, one.id.slice(0, 8))).id).toBe(one.id);
    await app.close();
  });
});

describe("CLI: link --expect-compare, secret phrase prompt, send --stdin", () => {
  const stub = { load: async () => true, close: async () => {}, connect: async () => ({}), connectAndDrain: async () => ({}) } as unknown as App;
  async function cli(argv: string[], ops: Record<string, unknown>, io: Record<string, unknown> = {}) {
    const out: string[] = [];
    const err: string[] = [];
    const code = await main(argv, { env: {}, io: { out: (s) => out.push(s), err: (s) => err.push(s), ...io }, ops: ops as never, makeApp: () => stub });
    process.exitCode = 0;
    let json: any;
    try {
      json = JSON.parse(out.at(-1) ?? "");
    } catch {
      json = undefined;
    }
    return { code, json, err };
  }
  const fakeLink = (shown: string) => ({
    linkStart: async () => ({
      code: "p2p-link:x@r",
      relay: "wss://r/v3",
      expiresAt: 0,
      cancel: () => {},
      wait: async (confirm: (r: unknown) => Promise<boolean>) => {
        if (!(await confirm({ label: "laptop", compareCode: shown, did: "d_x" }))) throw Object.assign(new Error("declined"), {});
        return { did: "d_x", label: "laptop", keyholder: true, ver: 2 };
      },
    }),
  });

  it("link start never accepts the first device blindly", async () => {
    expect((await cli(["link", "start", "--json"], fakeLink("abcdefgh"))).json.error).toBe("usage");
    expect((await cli(["link", "start", "--keyholder", "--expect-compare", "zzzzzzzz", "--json"], fakeLink("abcdefgh"))).code).toBe(1);
    const ok = await cli(["link", "start", "--keyholder", "--expect-compare", "ABCDEFGH", "--json"], fakeLink("abcdefgh"));
    expect(ok.code).toBe(0);
    expect(ok.json.compareCode).toBe("abcdefgh");
    expect(ok.err.some((l) => l.includes('"compareCode":"abcdefgh"'))).toBe(true);
    // The old --yes is gone.
    expect((await cli(["link", "start", "--yes"], fakeLink("abcdefgh"))).code).toBe(1);
  });

  it("restore reads the phrase without echo, and refuses an echoing prompt", async () => {
    const seen: string[] = [];
    const backupRestore = async (_a: unknown, phrase: string) => {
      seen.push(phrase);
      return { userId: "u", address: "a", did: "d", ver: 2, revoked: [], warnings: [], merged: 0 };
    };
    const secret = await cli(["backup", "restore", "--json"], { backupRestore }, { promptSecret: async () => "words", prompt: async () => "echoed" });
    expect(secret.code).toBe(0);
    expect(seen).toEqual(["words"]);
    const echoing = await cli(["backup", "restore", "--json"], { backupRestore }, { prompt: async () => "echoed" });
    expect(echoing.json.error).toBe("usage");
  });

  it("send reads stdin with --stdin or `-`, also with --notify-when-idle; never otherwise for a subscription", async () => {
    const calls: { text: string; notifyWhenIdle?: boolean }[] = [];
    const sendMessage = async (_a: unknown, o: { text: string; notifyWhenIdle?: boolean }) => {
      calls.push(o);
      return { delivered: o.text !== "", to: { userId: "u", address: "a", own: "u", sid: "s", ref: "abcdef" }, relays: 1, devices: 1 };
    };
    const stdin = { readStdin: async () => "piped text\n" };
    await cli(["send", "--from-session", "s", "--to", "b", "--notify-when-idle", "--stdin", "--json"], { sendMessage }, stdin);
    await cli(["send", "--from-session", "s", "--to", "b", "--notify-when-idle", "-", "--json"], { sendMessage }, stdin);
    await cli(["send", "--from-session", "s", "--to", "b", "--notify-when-idle", "--json"], { sendMessage }, stdin);
    expect(calls.map((c) => c.text)).toEqual(["piped text", "piped text", ""]);
  });
});

