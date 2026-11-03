// Copyright 2026 Ix Infrastructure Inc.
//
// x:ix.footprint end to end over a real in-process relay, through the real
// `p2p` CLI and a fake `ix` on PATH:
//   alice computes her session's footprint from a git diff and publishes it;
//   bob, in her session's audience, keeps it as her session's state, never
//   as an event (his watch, and so a model, never sees it);
//   publishing is spaced (30 s), skipped when unchanged, kept alive (5 min);
//   hashed names come from `p2p ix config`;
//   without Ix there is no footprint, one error, and nothing published.

import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { cleanupTmp, extensionDir, fakeIx, gitRepo, startRelay, User, type FakeIx, type TestRelay } from "./harness.js";

const R = "wss://relay.ext-ix-footprint.test/v3";
const TOKEN_TS = ["class Token {", "  refresh() {", "    return 1;", "  }", "}", ""].join("\n");

let relay: TestRelay;
let ix: FakeIx;
let alice: User;
let bob: User;
let carol: User;
let root: string;
let publishedAt = 0;
const ids: Record<string, string> = {};

function kvOf(u: User): any {
  return JSON.parse(readFileSync(join(u.home, "ext", "ix.json"), "utf8"));
}
function setKv(u: User, f: (kv: any) => void): void {
  const kv = kvOf(u);
  f(kv);
  writeFileSync(join(u.home, "ext", "ix.json"), JSON.stringify(kv));
}
/** Every stored document of bob's that mentions `needle` (state lives in P2P_HOME's JSON documents). */
function storedWith(u: User, needle: string): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (readFileSync(p, "utf8").includes(needle)) out.push(p);
    }
  };
  walk(u.home);
  return out;
}

describe("x:ix.footprint end to end", () => {
  beforeAll(async () => {
    relay = await startRelay(R);
    ix = fakeIx();
    const transport = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    const ext = extensionDir();
    alice = new User("alice", transport, { P2P_EXTENSION_PATH: ext, P2P_EXTENSIONS: "ix", ...ix.env() });
    bob = new User("bob", transport, { P2P_EXTENSION_PATH: ext, P2P_EXTENSIONS: "ix", ...ix.env() });
    // carol is alice's friend with a live, state-aware session, but outside alice's session's roster.
    carol = new User("carol", transport, { P2P_EXTENSION_PATH: ext, P2P_EXTENSIONS: "ix", ...ix.env() });
    for (const u of [alice, bob, carol]) ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
    const inv = await alice.ok(["invite", "--link"]);
    await bob.ok(["accept", inv.link]);
    await alice.ok(["friends"]);
    const inv2 = await alice.ok(["invite", "--link"]);
    await carol.ok(["accept", inv2.link]);
    await alice.ok(["friends"]);
    await carol.ok(["session", "roster", "cs1", "--add", ids.alice]);
    await carol.ok(["status", "--session", "cs1", "--state", "busy", "--label", "docs"]);
    await alice.ok(["session", "roster", "as1", "--add", ids.bob]);
    await bob.ok(["session", "roster", "bs1", "--add", ids.alice]);
    // bob's live status advertises xstate.v1 (and x:ix.footprint.v1): alice may publish to him.
    const b = await bob.ok(["status", "--session", "bs1", "--state", "busy", "--label", "api"]);
    expect(b.status.caps).toEqual(expect.arrayContaining(["xstate.v1", "x:ix.footprint.v1"]));

    root = gitRepo("https://github.com/Acme/Widgets.git").root;
    const g = (...a: string[]) => execFileSync("git", a, { cwd: root, env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" } });
    writeFileSync(join(root, "src", "auth", "token.ts"), TOKEN_TS);
    g("add", ".");
    g("-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "-m", "token");
    writeFileSync(join(root, "src", "auth", "token.ts"), TOKEN_TS.replace("return 1;", "return 2;"));
    ix.set("impact-src__auth__token.ts.json", {
      resolvedTarget: { kind: "file", name: "token.ts" },
      riskLevel: "high",
      riskSummary: "r",
      topImpactedMembers: [{ name: "Token", kind: "class", callerCount: 2, path: `${root}/src/auth/token.ts`, lineStart: 1, lineEnd: 5 }],
      propagationBuckets: [
        { region: "auth", regionKind: "subsystem", count: 2, members: [] },
        { region: "api", regionKind: "subsystem", count: 1, members: [] },
      ],
    });
    ix.set("around-src__auth__token.ts:3-3.json", {
      path: "src/auth/token.ts",
      symbols: [{ name: "refresh", kind: "method", path: "src/auth/token.ts", lineStart: 2, lineEnd: 4, callers: { total: 1, rows: [{ path: "src/api/handler.ts", line: 3, name: "handle" }] }, users: { total: 0, rows: [] }, tests: { total: 0, rows: [] } }],
      importers: { total: 1, tests: 0, rows: [{ path: "src/app.ts", line: 1 }] },
    });
    await alice.ok(["status", "--session", "as1", "--state", "busy", "--label", "web", "--file", "src/auth/token.ts"]);
    await bob.ok(["ls"]);
  }, 90_000);

  afterAll(async () => {
    await relay?.close().catch(() => {});
    cleanupTmp();
  });

  it("hashed by default: no path, symbol or region leaves in the clear", async () => {
    const r = await alice.ok(["ix", "footprint", "--session", "as1"], { cwd: root });
    expect(r).toMatchObject({ published: false, names: "hmac", namesWhy: "hashed by default", footprint: { names: "hmac", keyId: expect.stringMatching(/^k:[0-9a-f]{8}$/) } });
    expect(JSON.stringify(r.footprint.actors) + JSON.stringify(r.footprint.merged)).not.toMatch(/token|handler|auth|api/);
    expect(r.fallback).toBe("Ix footprint: 1 symbol in 2 areas, high risk; enable ext-ix to compare");
  });

  it("publishing honours P2P_SHARE_STATUS=0 and P2P_IX_FOOTPRINT=0, whoever runs it", async () => {
    for (const [k, v] of [["P2P_SHARE_STATUS", "0"], ["P2P_IX_FOOTPRINT", "0"]] as const) {
      const off = new User("alice", { [R]: `ws://127.0.0.1:${relay.port}/v3` }, { ...alice.extraEnv, [k]: v });
      (off as { home: string }).home = alice.home;
      const r = await off.ok(["ix", "footprint", "--session", "as1", "--publish", "--force"], { cwd: root });
      expect(r).toMatchObject({ published: false, skipped: "disabled" });
    }
    expect(ix.calls().filter((c) => c.argv[0] === "impact")).toHaveLength(1);
  });

  it("publishes to the session's audience; bob keeps it as state, never as an event", async () => {
    // Readable names are the person's explicit choice (typed `p2p ix config`).
    await alice.ok(["ix", "config", "names=plain"]);
    const r = await alice.ok(["ix", "footprint", "--session", "as1", "--publish"], { cwd: root });
    publishedAt = Date.now();
    expect(r.published).toBe(true);
    // Only the session's status audience: bob, never carol (a friend outside its roster).
    expect(r.delivered.map((d: any) => d.userId)).toEqual([ids.bob]);
    expect([...r.skipped, ...r.failed].map((d: any) => d.userId)).not.toContain(ids.carol);
    expect(r.names).toBe("plain");
    expect(r.footprint).toMatchObject({
      repo: { remote: "github.com/acme/widgets", branch: "main" },
      names: "plain",
      seq: 1,
      actors: [
        {
          a: "main",
          graph: "base",
          risk: "high",
          changed: { files: ["src/auth/token.ts"], symbols: [{ k: "src/auth/token.ts#Token.refresh", kind: "method" }] },
          ring1: { files: [{ f: "src/api/handler.ts", rel: "call" }, { f: "src/app.ts", rel: "import" }], symbols: [{ k: "src/api/handler.ts#handle", rel: "call" }] },
        },
      ],
      merged: { risk: "high", counts: { changedSymbols: 1, ring1Files: 2, ring2Files: 0 } },
    });
    expect(JSON.stringify(r.footprint)).not.toContain(root);
    expect(r.fallback).toBe("Ix footprint: 1 symbol in 2 areas (auth, api), high risk, ~2 files downstream; enable ext-ix to compare");

    // bob: the session's state (a bounded summary in ls), its body stored by ext-ix, no event.
    const row = (await bob.ok(["ls"])).peers.find((p: any) => p.own === ids.alice && p.sid === "as1");
    expect(row.xstate).toEqual([{ kind: "x:ix.footprint", at: expect.any(Number), expiresAt: expect.any(Number), fallback: r.fallback, bytes: expect.any(Number) }]);
    expect(JSON.stringify(row)).not.toContain("Token.refresh");
    expect(storedWith(bob, "src/auth/token.ts#Token.refresh").length).toBeGreaterThan(0);
    await carol.ok(["ls"]);
    expect(storedWith(carol, "Token.refresh")).toEqual([]);
    const w = await bob.watch("bs1", 1200);
    expect(w.events.filter((e) => e.kind === "p2p.ext")).toEqual([]);
    expect(w.raw.join("\n")).not.toContain("footprint");
  });

  it("at most one computation every 30 s; unchanged isn't resent until the 5 min keepalive", async () => {
    const before = ix.calls().length;
    const soon = await alice.ok(["ix", "footprint", "--session", "as1", "--publish"], { cwd: root });
    expect(soon).toMatchObject({ published: false, skipped: "too_soon", retryAfterMs: expect.any(Number) });
    expect(ix.calls().length).toBe(before);
    setKv(alice, (kv) => (kv.footprint.as1.computedAt -= 31_000));
    const same = await alice.ok(["ix", "footprint", "--session", "as1", "--publish"], { cwd: root });
    expect(same).toMatchObject({ published: false, skipped: "unchanged" });
    // The per-file cache: the unchanged file cost no impact or around call.
    expect(ix.calls().slice(before).map((c) => c.argv[0])).toEqual(["--version", "status"]);
    setKv(alice, (kv) => {
      kv.footprint.as1.computedAt -= 31_000;
      kv.footprint.as1.publishedAt -= 6 * 60_000;
    });
    // p2p's own spacing (one publish of a kind per session every 5 s) runs on the real clock.
    await new Promise((res) => setTimeout(res, Math.max(0, publishedAt + 5_200 - Date.now())));
    const alive = await alice.ok(["ix", "footprint", "--session", "as1", "--publish"], { cwd: root });
    expect(alive).toMatchObject({ published: true, footprint: { seq: 2 } });
  });

  it("M-a: names=plain written into the store by anything but `p2p ix config` is ignored", async () => {
    // (names=plain, signed, since the publish test.)
    expect((await alice.ok(["ix", "footprint", "--session", "as1"], { cwd: root })).names).toBe("plain");
    // A tool editing the store directly: the setting without this device's MAC over it.
    setKv(alice, (kv) => {
      kv.config = { names: "plain", circles: { c_team: "plain" } };
    });
    const r = await alice.ok(["ix", "footprint", "--session", "as1"], { cwd: root });
    expect(r.names).toBe("hmac");
    const shown = await alice.ok(["ix", "config"]);
    expect(shown).toMatchObject({ config: { circles: {} }, ignoredUnsigned: true });
    // A copied MAC doesn't carry over to other settings.
    await alice.ok(["ix", "config", "names=hmac"]);
    const signed = kvOf(alice).config.mac;
    setKv(alice, (kv) => {
      kv.config = { names: "plain", mac: signed };
    });
    expect((await alice.ok(["ix", "footprint", "--session", "as1"], { cwd: root })).names).toBe("hmac");
    // Typed again by the person: signed, honoured.
    await alice.ok(["ix", "config", "names=plain"]);
    expect((await alice.ok(["ix", "footprint", "--session", "as1"], { cwd: root })).names).toBe("plain");
  });

  it("a shallow clone gets no_hmac_key (its oldest commit isn't the repository's root), nothing published", async () => {
    const shallow = join(root, "..", `shallow-${Date.now()}`);
    const g = (cwd: string, ...a: string[]) => execFileSync("git", a, { cwd, env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" } });
    g(root, "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "second");
    g(root, "clone", "-q", "--depth", "1", `file://${root}`, shallow);
    g(shallow, "remote", "set-url", "origin", "https://github.com/Acme/Widgets.git");
    await alice.ok(["ix", "config", "names=auto"]);
    setKv(alice, (kv) => (kv.footprint.as1.computedAt -= 31_000));
    const r = await alice.run(["ix", "footprint", "--session", "as1", "--publish"], { cwd: shallow });
    expect(r.code).toBe(1);
    expect(r.json).toMatchObject({ error: "no_hmac_key" });
    expect(r.json.reason).toMatch(/shallow clone/);
    await alice.ok(["ix", "config", "names=plain"]);
  });

  it("an open circle stays hashed under a global names=plain; only its own setting makes it plain", async () => {
    // (names=plain globally since the publish test.)
    const open = await alice.ok(["circle", "create", "town square", "--open"]);
    await alice.ok(["session", "roster", "as1", "--circle", open.cid]);
    const h = await alice.ok(["ix", "footprint", "--session", "as1"], { cwd: root });
    expect(h.names).toBe("hmac");
    expect(h.namesWhy).toMatch(/open circle/);
    await alice.ok(["ix", "config", "--circle", open.cid, "names=plain"]);
    expect((await alice.ok(["ix", "footprint", "--session", "as1"], { cwd: root })).names).toBe("plain");
    await alice.ok(["ix", "config", "--circle", open.cid, "names=auto"]);
    await alice.ok(["session", "roster", "as1", "--private", "--add", ids.bob]);
    expect((await alice.ok(["ix", "footprint", "--session", "as1"], { cwd: root })).names).toBe("plain");
    // Back to the default: hashed.
    const c = await alice.ok(["ix", "config", "names=auto"]);
    expect(c.config).toEqual({ circles: {} });
    expect((await alice.ok(["ix", "footprint", "--session", "as1"], { cwd: root })).names).toBe("hmac");
  });

  it("no Ix: no footprint, one error, nothing published", async () => {
    const noIx = new User("alice", { [R]: `ws://127.0.0.1:${relay.port}/v3` }, { P2P_EXTENSION_PATH: alice.extraEnv.P2P_EXTENSION_PATH, P2P_EXTENSIONS: "ix", PATH: "/usr/bin:/bin" });
    (noIx as { home: string }).home = alice.home;
    const seq = kvOf(alice).footprint.as1.seq;
    setKv(alice, (kv) => (kv.footprint.as1.computedAt -= 31_000));
    const r = await noIx.run(["ix", "footprint", "--session", "as1", "--publish"], { cwd: root });
    expect(r.code).toBe(1);
    expect(r.json).toMatchObject({ error: "ix_missing" });
    expect(r.err.split("\n").filter(Boolean).length).toBeLessThanOrEqual(1);
    expect(kvOf(alice).footprint.as1.seq).toBe(seq);
  });
});
