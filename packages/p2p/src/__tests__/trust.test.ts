// Copyright 2026 Ix Infrastructure Inc.
//
// `p2p trust`: per-person trust for message delivery, by full userId or circle id, in config.json
// (0600). A trusted circle covers its members as its verified state has them when asked: a member
// removed from it stops being trusted. A blocked user is never trusted.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-trust.test/v3";
let relay: TestRelay;
let ann: User;
let ben: User;
let cat: User;
const ids: Record<string, string> = {};
const addr: Record<string, string> = {};

describe("p2p trust", () => {
  beforeAll(async () => {
    relay = await startRelay(R);
    const t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    ann = new User("ann", t);
    ben = new User("ben", t);
    cat = new User("cat", t);
    for (const u of [ann, ben, cat]) {
      const r = await u.ok(["init", "--name", u.name, "--relay", R, "--yes"]);
      ids[u.name] = r.userId;
      addr[u.name] = r.address;
    }
    for (const u of [ben, cat]) {
      const code = (await ann.ok(["invite"])).code as string;
      await u.ok(["join", "--confirmed", code]);
      await ann.ok(["friends"]);
    }
  }, 90_000);

  afterAll(async () => {
    await relay?.close();
    for (const u of [ann, ben, cat]) u?.cleanup();
  });

  it("a user by full userId or name@fingerprint, never a bare name; stored 0600; ls and check", async () => {
    expect((await ann.run(["trust", "add", "ben"])).json.error).toBe("usage");
    expect(await ann.ok(["trust", "add", addr.ben])).toMatchObject({ kind: "user", added: ids.ben });
    expect(await ann.ok(["trust", "check", ids.ben])).toMatchObject({ trusted: true, via: "user" });
    expect(await ann.ok(["trust", "check", ids.cat])).toMatchObject({ trusted: false });
    const file = join(ann.home, "config.json");
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(JSON.parse(readFileSync(file, "utf8")).trust.users).toEqual([ids.ben]);
    expect((await ann.ok(["trust", "ls"])).trusted).toEqual([ids.ben]);
    expect(await ann.ok(["trust", "remove", ids.ben])).toMatchObject({ removed: ids.ben });
    expect(await ann.ok(["trust", "check", ids.ben])).toMatchObject({ trusted: false });
    expect((await ann.run(["trust", "add", ids.ann])).json.error).toBe("usage");
  }, 60_000);

  it("a blocked user is never trusted: refused when added, dropped when checked", async () => {
    await ann.ok(["trust", "add", ids.cat]);
    await ann.ok(["block", ids.cat]);
    expect(await ann.ok(["trust", "check", ids.cat])).toMatchObject({ trusted: false });
    expect((await ann.ok(["trust", "ls"])).trusted).not.toContain(ids.cat);
    await ann.ok(["trust", "remove", ids.cat]);
    expect((await ann.run(["trust", "add", ids.cat])).json.error).toBe("blocked");
    await ann.ok(["unblock", ids.cat]);
  }, 60_000);

  it("a trusted circle covers its current members; one removed from it stops being trusted", async () => {
    const cid = (await ann.ok(["circle", "create", "team"])).cid as string;
    await ann.ok(["circle", "invite", cid, ids.ben]);
    const held = (await ben.ok(["held"])).held;
    await ben.ok(["held", "approve", held[0].id, "--wait", "3"]);
    await ann.ok(["circle", "ls"]);
    expect(await ann.ok(["trust", "add", `circle:${cid}`])).toMatchObject({ kind: "circle", added: cid });
    expect(await ann.ok(["trust", "check", ids.ben])).toMatchObject({ trusted: true, via: `circle:${cid}` });
    expect((await ann.ok(["trust", "ls"])).circles).toEqual([expect.objectContaining({ cid, joined: true, members: [ids.ben] })]);
    // Ben leaves the circle (removed by its owner): no longer trusted, though the circle still is.
    await ann.ok(["circle", "propose", cid, "remove", ids.ben]);
    expect(await ann.ok(["trust", "check", ids.ben])).toMatchObject({ trusted: false });
    expect((await ann.ok(["trust", "ls"])).circles[0].members).toEqual([]);
    expect(await ann.ok(["trust", "remove", `circle:${cid}`])).toMatchObject({ removed: cid });
  }, 90_000);

  it("N1: an open circle can't be trusted; a trusted circle switched to open trusts nobody until it is invite-only again", async () => {
    const open = (await ann.ok(["circle", "create", "lobby", "--open"])).cid as string;
    expect((await ann.run(["trust", "add", `circle:${open}`])).json.error).toBe("open_circle");
    const cid = (await ann.ok(["circle", "create", "crew"])).cid as string;
    await ann.ok(["circle", "invite", cid, ids.cat]);
    const held = (await cat.ok(["held"])).held.filter((h: { type: string }) => h.type === "circle-invite");
    await cat.ok(["held", "approve", held[0].id, "--wait", "3"]);
    await ann.ok(["circle", "ls"]);
    await ann.ok(["trust", "add", `circle:${cid}`]);
    expect(await ann.ok(["trust", "check", ids.cat])).toMatchObject({ trusted: true, via: `circle:${cid}` });
    await ann.ok(["circle", "policy", cid, "open"]);
    expect(await ann.ok(["trust", "check", ids.cat])).toMatchObject({ trusted: false });
    expect((await ann.ok(["trust", "ls"])).circles).toEqual([expect.objectContaining({ cid, open: true, members: [] })]);
    await ann.ok(["circle", "policy", cid, "invite"]);
    expect(await ann.ok(["trust", "check", ids.cat])).toMatchObject({ trusted: true });
    await ann.ok(["trust", "remove", `circle:${cid}`]);
  }, 90_000);

  it("N3: concurrent trust and receipts changes never lose an update (config.json under the state lock)", async () => {
    const users = Array.from({ length: 12 }, (_, i) => `p2p:${String.fromCharCode(97 + i).repeat(52)}`);
    // Not known identities: written straight through the store-free path, as `trust add` would, by userId.
    await Promise.all([
      ...users.map((u) => ann.run(["trust", "add", u])),
      ann.run(["receipts", "off"]),
      ann.run(["receipts", "on"]),
      ann.run(["receipts", "off"]),
    ]);
    const cfg = JSON.parse(readFileSync(join(ann.home, "config.json"), "utf8"));
    expect([...cfg.trust.users].sort()).toEqual([...users].sort());
    expect(typeof cfg.receipts).toBe("boolean");
    for (const u of users) await ann.ok(["trust", "remove", u]);
    await ann.ok(["receipts", "on"]);
  }, 90_000);
});
