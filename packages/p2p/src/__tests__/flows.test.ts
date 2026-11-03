// Copyright 2026 Ix Infrastructure Inc.
//
// The flows the main end-to-end test doesn't reach, over one in-process relay
// that asks for proof of work on cap-less contacts: the hello check, a
// stranger's first contact held for approval, profiles and proofs,
// notify-when-idle, a circle invite held and approved, transfer and policy.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { invite } from "../social.js";
import { proofVerify } from "../identity.js";
import { RelayConnection } from "../relay-client.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-pow.test/v3";
let relay: TestRelay;
let xena: User;
let yuri: User;
const ids: Record<string, string> = {};
let cid = "";

describe("more p2p flows", () => {
  beforeAll(async () => {
    relay = await startRelay(R, { powBits: 8 });
    const t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    xena = new User("xena", t);
    yuri = new User("yuri", t);
    for (const u of [xena, yuri]) ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
  });

  afterAll(async () => {
    await relay?.close();
    xena?.cleanup();
    yuri?.cleanup();
  });

  it("closes a relay whose hello names another URL (H5)", async () => {
    const c = new RelayConnection("wss://impostor.test/v3", { ws: `ws://127.0.0.1:${relay.port}/v3`, http: "" }, { timeoutMs: 3000 });
    await expect(c.open()).rejects.toMatchObject({ code: "relay_mismatch" });
  });

  it("a stranger's invite arrives by contact with proof of work, is held, and approval makes friends", async () => {
    const app = await xena.app();
    await app.load();
    await app.connect();
    await app.refreshIdentity(ids.yuri, [R], { force: true });
    const r = await invite(app, { to: ids.yuri });
    await app.close();
    expect(r.delivered?.relays).toEqual([R]);
    const held = await yuri.ok(["held"]);
    expect(held.held).toHaveLength(1);
    expect(held.held[0]).toMatchObject({ type: "invite", from: ids.xena });
    const ok = await yuri.ok(["held", "approve", held.held[0].id]);
    expect(ok.friend.userId).toBe(ids.xena);
    expect((await yuri.ok(["held"])).held).toHaveLength(0);
    expect((await xena.ok(["friends"])).friends.map((f: any) => f.userId)).toEqual([ids.yuri]);
  });

  it("profile: set, size cap, shown to others sanitized", async () => {
    const p = await xena.ok(["profile", "set", "--bio", "builds <relays>", "--link", "https://example.com/x"]);
    expect(p.profile.bio).toBe("builds relays");
    const big = await xena.run(["profile", "set", "--avatar", `data:image/png;base64,${"A".repeat(5000)}`]);
    expect(big.json.error).toBe("bad_profile");
    const seen = await yuri.ok(["profile", "show", ids.xena]);
    expect(seen.profile).toMatchObject({ bio: "builds relays", links: ["https://example.com/x"] });
  });

  it("proofs: dns prints the TXT record, verify checks it", async () => {
    const add = await xena.ok(["proof", "add", "dns", "Example.COM"]);
    expect(add.claim).toBe("example.com");
    expect(add.publish).toContain(`_p2p.example.com  TXT  "p2p-proof=${ids.xena}"`);
    const gh = await xena.ok(["proof", "add", "github", "xena"]);
    expect(gh.pending).toBe(true);
    const app = await yuri.app();
    await app.load();
    const good = await proofVerify(app, ids.xena, { dnsTxt: async (n) => (n === "_p2p.example.com" ? [`p2p-proof=${ids.xena}`] : []) });
    expect(good.proofs).toEqual([expect.objectContaining({ kind: "dns", claim: "example.com", verified: true, display: "✓ dns: example.com" })]);
    const bad = await proofVerify(app, ids.xena, { dnsTxt: async () => ["p2p-proof=someone-else"] });
    expect(bad.proofs[0].verified).toBe(false);
    await app.close();
  });

  it("notify-when-idle: one p2p.idle to the subscribing session on busy → idle", async () => {
    await yuri.ok(["session", "roster", "ys1", "--add", ids.xena]);
    const st = await yuri.ok(["status", "--session", "ys1", "--state", "busy"]);
    expect(st.delivered.map((d: any) => d.userId)).toEqual([ids.xena]);
    const sub = await xena.ok(["send", "--from-session", "xs1", "--to", ids.yuri, "--notify-when-idle"]);
    expect(sub).toMatchObject({ delivered: false, notifyWhenIdle: true });
    await yuri.ok(["status", "--session", "ys1", "--state", "idle"]);
    const lines = await xena.watch("xs1", 1500);
    const idle = lines.filter((e) => e.kind === "p2p.idle");
    expect(idle).toHaveLength(1);
    expect(idle[0]).toMatchObject({ reason: "idle", own: ids.yuri, sid: "ys1", toSession: "xs1" });
  });

  it("circle invite to a friend is held, approval joins; transfer needs consent; policy", async () => {
    const c = await xena.ok(["circle", "create", "pair"]);
    cid = c.cid;
    const inv = await xena.ok(["circle", "invite", cid, ids.yuri]);
    expect(inv.added).toBe(true);
    const held = (await yuri.ok(["held"])).held;
    expect(held).toHaveLength(1);
    expect(held[0]).toMatchObject({ type: "circle-invite", cid });
    const j = await yuri.ok(["held", "approve", held[0].id, "--wait", "3"]);
    expect(j).toMatchObject({ status: "joined", confirmation: "owner-only", ownershipChanged: false });
    await xena.ok(["circle", "ls"]);
    const m = await yuri.ok(["circle", "members", cid]);
    expect(m.members.every((x: any) => x.stands)).toBe(true);
    // Transfer: the owner can't hand over without the successor's consent.
    const no = await xena.run(["circle", "transfer", cid, ids.yuri]);
    expect(no.json.error).toBe("needs_consent");
    await yuri.ok(["circle", "transfer", cid, "--accept"]);
    const t = await xena.ok(["circle", "transfer", cid, ids.yuri]);
    expect(t.owner).toBe(ids.yuri);
    const after = (await yuri.ok(["circle", "ls"])).circles.find((x: any) => x.cid === cid);
    expect(after).toMatchObject({ role: "owner", owner: ids.yuri });
    expect((await xena.run(["circle", "policy", cid, "open"])).json.error).toBe("not_owner");
    expect((await yuri.ok(["circle", "policy", cid, "open"])).policy).toBe("open");
    expect((await xena.ok(["circle", "ls"])).circles.find((x: any) => x.cid === cid).policy).toBe("open");
    // The former owner can now leave.
    expect((await xena.ok(["circle", "leave", cid])).left).toBe(true);
  });
});
