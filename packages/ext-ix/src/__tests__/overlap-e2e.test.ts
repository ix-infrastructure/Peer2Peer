// Copyright 2026 Ix Infrastructure Inc.
//
// Footprint overlap end to end, two users over a real relay through the real
// `p2p` and a fake `ix`: alice changes SessionStore.refresh, bob changes
// handleLogin, which calls it. Both publish (hashed names, the default: both
// clones derive the same key), and both get the "depends" overlap, each from
// their own side, named with their own names.

import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { cleanupTmp, extensionDir, fakeIx, startRelay, tmp, User, type FakeIx, type TestRelay } from "./harness.js";

const R = "wss://relay.ext-ix-overlap.test/v3";
const REMOTE = "https://github.com/Acme/Api.git";
const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" };
const git = (cwd: string, ...a: string[]) => execFileSync("git", a, { cwd, env: GIT_ENV }).toString().trim();

let relay: TestRelay;
let ix: FakeIx;
let alice: User;
let bob: User;
let carol: User;
let cRoot: string;
let aRoot: string;
let bRoot: string;
const ids: Record<string, string> = {};

describe("footprint overlap end to end", () => {
  beforeAll(async () => {
    relay = await startRelay(R);
    ix = fakeIx();
    const transport = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    const ext = extensionDir();
    alice = new User("alice", transport, { P2P_EXTENSION_PATH: ext, P2P_EXTENSIONS: "ix", ...ix.env() });
    bob = new User("bob", transport, { P2P_EXTENSION_PATH: ext, P2P_EXTENSIONS: "ix", ...ix.env() });
    // carol shares her session with alice, but alice's session isn't shared with carol.
    carol = new User("carol", transport, { P2P_EXTENSION_PATH: ext, P2P_EXTENSIONS: "ix", ...ix.env() });
    for (const u of [alice, bob, carol]) ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
    const inv = await alice.ok(["invite", "--link"]);
    await bob.ok(["accept", inv.link]);
    await alice.ok(["friends"]);
    const inv2 = await alice.ok(["invite", "--link"]);
    await carol.ok(["accept", inv2.link]);
    await alice.ok(["friends"]);
    await carol.ok(["session", "roster", "cs1", "--add", ids.alice]);
    await alice.ok(["session", "roster", "as1", "--add", ids.bob]);
    await bob.ok(["session", "roster", "bs1", "--add", ids.alice]);

    // One repository, two clones (same remote, same root commit: the same name key).
    aRoot = tmp("ov-alice-");
    mkdirSync(join(aRoot, "src", "auth"), { recursive: true });
    mkdirSync(join(aRoot, "src", "api"), { recursive: true });
    git(aRoot, "init", "-q", "-b", "main");
    git(aRoot, "remote", "add", "origin", REMOTE);
    writeFileSync(join(aRoot, "src/auth/session.ts"), "class SessionStore {\n  refresh() {\n    return 1;\n  }\n}\n");
    writeFileSync(join(aRoot, "src/api/login.ts"), "import { s } from '../auth/session';\nexport function handleLogin() {\n  return s.refresh();\n}\n");
    git(aRoot, "add", ".");
    git(aRoot, "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "-m", "init");
    bRoot = join(tmp("ov-bob-"), "api");
    git(aRoot, "clone", "-q", aRoot, bRoot);
    git(bRoot, "remote", "set-url", "origin", REMOTE);
    cRoot = join(tmp("ov-carol-"), "api");
    git(aRoot, "clone", "-q", aRoot, cRoot);
    git(cRoot, "remote", "set-url", "origin", REMOTE);
    writeFileSync(join(cRoot, "src/auth/session.ts"), "class SessionStore {\n  refresh() {\n    return 3;\n  }\n}\n");
    // Their edits, uncommitted: line 3 of each file.
    writeFileSync(join(aRoot, "src/auth/session.ts"), "class SessionStore {\n  refresh() {\n    return 2;\n  }\n}\n");
    writeFileSync(join(bRoot, "src/api/login.ts"), "import { s } from '../auth/session';\nexport function handleLogin() {\n  return s.refresh() && true;\n}\n");
    ix.set("around-src__auth__session.ts:3-3.json", {
      path: "src/auth/session.ts",
      symbols: [{ name: "refresh", kind: "method", path: "src/auth/session.ts", lineStart: 2, lineEnd: 4, callers: { total: 1, rows: [{ path: "src/api/login.ts", line: 3, name: "handleLogin" }] }, users: { total: 0, rows: [] }, tests: { total: 0, rows: [] } }],
      importers: { total: 1, tests: 0, rows: [{ path: "src/api/login.ts", line: 1 }] },
    });
    ix.set("around-src__api__login.ts:3-3.json", {
      path: "src/api/login.ts",
      symbols: [{ name: "handleLogin", kind: "function", path: "src/api/login.ts", lineStart: 2, lineEnd: 4, callers: { total: 0, rows: [] }, users: { total: 0, rows: [] }, tests: { total: 0, rows: [] } }],
      importers: { total: 0, tests: 0, rows: [] },
    });
    await alice.ok(["status", "--session", "as1", "--state", "busy", "--label", "auth", "--file", "src/auth/session.ts"]);
    await bob.ok(["status", "--session", "bs1", "--state", "busy", "--label", "api", "--file", "src/api/login.ts"]);
    await carol.ok(["status", "--session", "cs1", "--state", "busy", "--label", "auth2", "--file", "src/auth/session.ts"]);
    // alice shares another session (as2) with carol, so carol's footprint can reach her; as1 stays bob's only.
    await alice.ok(["session", "roster", "as2", "--add", ids.carol]);
    await alice.ok(["status", "--session", "as2", "--state", "idle", "--label", "notes"]);
    await carol.ok(["ls"]);
    await alice.ok(["ls"]);
    await bob.ok(["ls"]);
  }, 180_000);

  afterAll(async () => {
    await relay?.close().catch(() => {});
    cleanupTmp();
  });

  it("both publish hashed footprints, and both get the depends overlap from their own side, named only as far as the peer already knows", async () => {
    const a = await alice.ok(["ix", "footprint", "--session", "as1", "--publish"], { cwd: aRoot });
    const b = await bob.ok(["ix", "footprint", "--session", "bs1", "--publish"], { cwd: bRoot });
    expect([a.published, b.published, a.names, b.names]).toEqual([true, true, "hmac", "hmac"]);
    expect(a.footprint.keyId).toBe(b.footprint.keyId);

    const ao = await alice.ok(["ix", "overlaps", "--session", "as1"], { cwd: aRoot });
    const bo = await bob.ok(["ix", "overlaps", "--session", "bs1"], { cwd: bRoot });
    expect(ao.overlaps.filter((o: any) => o.peer.own === ids.bob)).toEqual([expect.objectContaining({ tier: "depends", direction: "mine-affects-theirs", severity: "medium", peer: expect.objectContaining({ own: ids.bob, sid: "bs1" }) })]);
    expect(bo.overlaps).toEqual([expect.objectContaining({ tier: "depends", direction: "theirs-affects-mine", severity: "medium", peer: expect.objectContaining({ own: ids.alice, sid: "as1" }) })]);
    // Hashed: the lines a model reads name nothing the peer doesn't already hold. Bob's own status
    // shares src/api/login.ts in the clear, so his line may say the file; alice's names nothing.
    expect(ao.overlaps[0].message).toMatch(/^POSSIBLE CONFLICT \(medium, depends\) with bob@[a-z2-7-]+: your change affects code they're editing \(it calls it\) \(hashed: names stay private\)$/);
    expect(bo.overlaps[0].message).toMatch(/^POSSIBLE CONFLICT \(medium, depends\) with alice@[a-z2-7-]+: their change affects code in src\/api\/login\.ts you're editing \(it calls their change\) \(hashed: names stay private\)$/);
    // --json (what a client or a model's shell reads) never carries the readable detail.
    expect(JSON.stringify([ao, bo])).not.toMatch(/SessionStore|handleLogin|"detail"/);
    // A person at a terminal gets their own readable names.
    const human = await alice.run(["ix", "overlaps", "--session", "as1"], { json: false, cwd: aRoot, answer: "n" });
    expect(human.out).toMatch(/your change affects src\/api\/login\.ts#handleLogin they're editing \(it calls it\)/);
  });

  it("L1, project boundaries: a peer outside my session's audience (in my peers() because they share with me) isn't compared at all", async () => {
    await new Promise((res) => setTimeout(res, 200));
    const c = await carol.ok(["ix", "footprint", "--session", "cs1", "--publish"], { cwd: cRoot });
    expect(c.delivered.map((d: any) => d.userId)).toEqual([ids.alice]);
    // peers() does include her (she shares her session with alice, and her footprint reached alice), but
    // as1 isn't shared with her: overlap is only between sessions that see each other.
    expect((await alice.ok(["ls"])).peers.some((p: any) => p.own === ids.carol && p.sid === "cs1")).toBe(true);
    const ao = await alice.ok(["ix", "overlaps", "--session", "as1"], { cwd: aRoot });
    expect(ao.overlaps.filter((o: any) => o.peer.own === ids.carol)).toEqual([]);
    expect(ao.skipped.filter((x: any) => x.peer.own === ids.carol)).toEqual([]);
    expect(JSON.stringify(ao)).not.toContain(ids.carol);
  });

  it("a peer in another repository isn't compared", async () => {
    await bob.ok(["status", "--session", "bs1", "--state", "busy", "--label", "api", "--file", "src/api/login.ts"]);
    git(bRoot, "remote", "set-url", "origin", "https://github.com/Acme/Other.git");
    // The remote is part of a project's identity (projects.ts): this is a new project, private until bob shares it.
    await bob.ok(["project", "share", "--add", "--person", ids.alice], { cwd: bRoot });
    await new Promise((res) => setTimeout(res, 5_200));
    await bob.ok(["ix", "footprint", "--session", "bs1", "--publish", "--force"], { cwd: bRoot });
    const ao = await alice.ok(["ix", "overlaps", "--session", "as1"], { cwd: aRoot });
    expect(ao.overlaps.filter((o: any) => o.peer.own === ids.bob)).toEqual([]);
    expect(ao.skipped).toEqual([expect.objectContaining({ peer: expect.objectContaining({ own: ids.bob }), reason: "another repository" })]);
  });
});
