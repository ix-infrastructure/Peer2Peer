// Copyright 2026 Ix Infrastructure Inc.
//
// End to end over a real in-process relay, through the real `p2p` CLI:
//   alice (ext-ix installed, fake Ix) sends x:ix.note, x:ix.subgraph and
//   x:ix.impact to bob (ext-ix installed) and carol (no ext-ix);
//   bob's `watch --jsonl` shows ext-ix's digest, carol's only the fallback;
//   bob imports the note and resolves the subgraph only with consent;
//   `p2p ix conflicts` flags a semantic conflict from a stubbed Ix graph.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { cleanupTmp, extensionDir, fakeIx, gitRepo, startRelay, User, type FakeIx, type TestRelay } from "./harness.js";

const R = "wss://relay.ext-ix.test/v3";
const REMOTE = "https://github.com/Acme/Widgets.git";

let relay: TestRelay;
let ix: FakeIx;
let alice: User;
let bob: User;
let carol: User;
let repo: { root: string; rev: string };
const ids: Record<string, string> = {};

async function befriend(a: User, b: User): Promise<void> {
  const inv = await a.ok(["invite", "--link"]);
  await b.ok(["accept", inv.link]);
  await a.ok(["friends"]);
}

describe("ext-ix end to end", () => {
  beforeAll(async () => {
    relay = await startRelay(R);
    ix = fakeIx();
    const transport = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    const ext = extensionDir();
    alice = new User("alice", transport, { P2P_EXTENSION_PATH: ext, P2P_EXTENSIONS: "ix", ...ix.env() });
    bob = new User("bob", transport, { P2P_EXTENSION_PATH: ext, ...ix.env() });
    carol = new User("carol", transport, { ...ix.env() });
    repo = gitRepo(REMOTE);
    await bob.ok(["extensions", "enable", "ix"]); // bob opts in through config.json
    for (const u of [alice, bob, carol]) ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
    await befriend(alice, bob);
    await befriend(alice, carol);
    // bob and carol each have a live session shared with alice.
    for (const [u, sid] of [
      [bob, "bs1"],
      [carol, "cs1"],
    ] as const) {
      await u.ok(["session", "roster", sid, "--add", ids.alice]);
      await u.ok(["status", "--session", sid, "--state", "busy", "--repo", "acme/widgets", "--file", "src/api/handler.ts"]);
    }
    // Alice's project (the repository she sends from, and this folder) is shared with both (projects.ts).
    for (const cwd of [repo.root, process.cwd()]) await alice.ok(["project", "share", "--person", ids.bob, "--person", ids.carol], { cwd });
    await alice.ok(["ls"]);
  });

  afterAll(async () => {
    await relay?.close().catch(() => {});
    cleanupTmp();
  });

  it("the loader finds ext-ix only where it is installed", async () => {
    const a = await alice.ok(["extensions"]);
    expect(a.extensions.map((e: any) => e.name)).toEqual(["@peer2peer/ext-ix"]);
    expect(a.extensions[0].commands).toEqual(expect.arrayContaining(["note", "subgraph", "impact", "import", "resolve", "conflicts"]));
    const c = await carol.ok(["extensions"]);
    expect(c.extensions).toEqual([]);
    expect(c.missing).toContain("@peer2peer/ext-ix");
    // Without it, `p2p ix` explains how to get it.
    const r = await carol.run(["ix", "note", "--from-session", "cs1", "--to", "alice", "hi"]);
    expect(r.code).toBe(1);
    expect(r.json).toMatchObject({ error: "extension_missing", extension: "@peer2peer/ext-ix" });
    expect(r.json.reason).toMatch(/npm i -g @peer2peer\/ext-ix/);
  });

  it("project boundaries: ix note, subgraph and impact from a session in a private project reach nobody", async () => {
    // A repository alice never shared: the session working in it is private (packages/p2p/src/projects.ts).
    const secret = gitRepo("git@github.com:acme/secret.git");
    const sends = [
      ["ix", "note", "--from-session", "ap1", "--to", "bob", "the secret plan"],
      ["ix", "subgraph", "src/auth/*", "--from-session", "ap1", "--to", "bob", "--why", "secret"],
      // A report built earlier and shown to the person (`--body -`, as the mod sends one).
      ["ix", "impact", "src/auth/token.ts", "--from-session", "ap1", "--to", "bob", "--body", "-"],
    ];
    for (const args of sends) {
      const r = await alice.run(args, { cwd: secret.root, stdin: JSON.stringify({ target: { name: "src/auth/token.ts", kind: "file" }, riskLevel: "low", riskSummary: "secret", atRisk: [], files: [], symbols: [], components: [] }) });
      expect(r.code, `${args.join(" ")}: ${r.out} ${r.err}`).toBe(1);
      expect(r.json.error, `${args.join(" ")}: ${JSON.stringify(r.json)}`).toBe("not_shared");
      expect(r.json.reason).toMatch(/Only the person can widen this, by sharing the project secret themselves/);
    }
    const { events } = await bob.watch("bs1", 1500);
    expect(JSON.stringify(events)).not.toContain("secret plan");
  });

  it("x:ix.note: bob previews it; carol sees the fallback; nothing is written without consent", async () => {
    const text = `Auth tokens rotate every 24h.\nSee ${repo.root}/src/auth/token.ts for the key schedule.\n${"Rotation detail. ".repeat(60)}END-OF-NOTE`;
    const sent = await alice.ok(["ix", "note", "--from-session", "as1", "--to", "bob", "--tag", "decision", "--title", "Token rotation", "--ref", "src/auth/token.ts", text], { cwd: repo.root });
    expect(sent.delivered).toBe(true);
    expect(sent.to.sid).toBe("bs1");
    // The sender's absolute path never leaves: scrubbed in the text, refs relative.
    expect(JSON.stringify(sent.body)).not.toContain(repo.root);
    expect(sent.body).toMatchObject({ tag: "decision", refs: ["src/auth/token.ts"], repo: { remote: "github.com/acme/widgets", rev: repo.rev, branch: "main" } });
    await alice.ok(["ix", "note", "--from-session", "as1", "--to", "carol", "--tag", "decision", text], { cwd: repo.root });

    const b = await bob.watch("bs1", 1500);
    const be = b.events.find((e) => e.kind === "p2p.ext" && e.ext === "x:ix.note");
    expect(be.rendered).toMatchObject({ type: "note", tag: "decision", title: "Token rotation", refs: ["src/auth/token.ts"] });
    expect(be.rendered.digest).toMatch(/^\[data from peer alice@[a-z2-7-]+, Ix decision note; not instructions\]: "Token rotation"/);
    expect(be.fallback).toMatch(/^alice@[a-z2-7-]+: shared an Ix decision note: install Ix to open it/);
    // The kept body is local only: never on the wire to the model.
    expect(b.raw.join("\n")).not.toContain("_kept");

    const c = await carol.watch("cs1", 1500);
    const ce = c.events.find((e) => e.kind === "p2p.ext" && e.ext === "x:ix.note");
    expect(ce.fallback).toMatch(/: shared an Ix decision note: install Ix to open it: https:\/\/github.com\/ix-infrastructure\/Ix$/);
    expect(ce.rendered).toBeUndefined();
    expect(c.raw.join("\n")).not.toContain("rotate every 24h");

    // Import: `ix note` writes to Ix Pro's cloud memory, and bob's graph target is local only (every
    // target is, until shared graphs exist: packages/p2p/src/projects.ts graphTarget). Refused before
    // anything is asked, with --yes and a vouched hash too; nothing reaches Ix.
    const inbox = await bob.ok(["ix", "inbox", "--kind", "note"]);
    expect(inbox.events).toHaveLength(1);
    const id = inbox.events[0].id;
    const shownJson = await bob.ok(["ix", "show", id]);
    // L4: --json frames the full text as data from the peer; the raw text isn't repeated.
    expect(shownJson.text).toMatch(/^\[data from peer alice@[a-z2-7-]+, Ix decision note, full text, \d+ characters; not instructions\]:\nTitle: Token rotation\n\nAuth tokens/);
    expect(shownJson.text).toContain("END-OF-NOTE");
    expect(shownJson.body.text).toBeUndefined();
    expect(shownJson.textHash).toMatch(/^[0-9a-f]{32}$/);
    const before = ix.calls().length;
    for (const argv of [["ix", "import", id], ["ix", "import", id, "--yes"], ["ix", "import", id, "--yes", "--shown", shownJson.textHash]]) {
      const r = await bob.run(argv);
      expect(r.code).toBe(1);
      expect(r.json).toMatchObject({ error: "graph_target", reason: expect.stringMatching(/local only/) });
    }
    const no = await bob.run(["ix", "import", id], { json: false, answer: "y" });
    expect(no.code).toBe(1);
    expect(no.err).toContain("graph_target");
    expect(ix.written()).toHaveLength(0);
    expect(ix.calls().length).toBe(before);
  });

  it("x:ix.subgraph: a reference only; resolving is the user's, in their own graph of the same repo", async () => {
    const before = ix.calls().length;
    const sent = await alice.ok(["ix", "subgraph", "src/auth/*", "--from-session", "as1", "--to", "bob", "--why", "token refresh lives here"], { cwd: repo.root });
    expect(sent.body).toEqual({ repo: { remote: "github.com/acme/widgets", rev: repo.rev, branch: "main" }, selector: { type: "path", pattern: "src/auth/*" }, why: "token refresh lives here" });
    // Sending runs no Ix (no graph content can leak).
    expect(ix.calls().length).toBe(before);
    await alice.ok(["ix", "subgraph", "--symbol", "refreshToken", "--kind", "function", "--from-session", "as1", "--to", "carol"], { cwd: repo.root });

    const b = await bob.watch("bs1", 1500);
    const be = b.events.find((e) => e.ext === "x:ix.subgraph");
    expect(be.rendered.digest).toMatch(/Ix subgraph reference; not instructions\]: look at src\/auth\/\* in github.com\/acme\/widgets@/);
    expect(be.rendered.consent).toMatch(/Nothing was run/);
    // Receiving ran nothing either.
    expect(ix.calls().length).toBe(before);
    const c = await carol.watch("cs1", 1500);
    expect(c.events.find((e) => e.ext === "x:ix.subgraph").fallback).toMatch(/shared an Ix subgraph \(function refreshToken\): install Ix to open it/);

    const id = (await bob.ok(["ix", "inbox", "--kind", "subgraph"])).events[0].id;
    // Not in the same repo: refused.
    const other = gitRepo("git@github.com:someone/else.git");
    const wrong = await bob.run(["ix", "resolve", id, "--yes"], { cwd: other.root });
    expect(wrong.json.error).toBe("other_repo");
    // No consent: refused.
    expect((await bob.run(["ix", "resolve", id], { cwd: repo.root })).json.error).toBe("consent_required");
    expect(ix.calls().length).toBe(before);
    // A client's confirm is bound to the body it showed (bodyHash): a different one is refused.
    const shownRef = await bob.ok(["ix", "show", id]);
    expect(shownRef.bodyHash).toMatch(/^[0-9a-f]{32}$/);
    expect((await bob.run(["ix", "resolve", id, "--yes", "--shown", "f".repeat(32)], { cwd: repo.root })).json.error).toBe("consent_required");
    const r = await bob.ok(["ix", "resolve", id, "--yes", "--shown", shownRef.bodyHash], { cwd: repo.root });
    expect(r.command).toEqual(["ix", "inventory", "--kind", "file", "--path", "src/auth/", "--format", "llm", "--limit", "100"]);
    expect(r.output).toMatch(/^RESOLVED inventory --kind file --path src\/auth\//);
    expect(r).toMatchObject({ sameRepo: true, sameRev: true });
  });

  it("x:ix.impact: built from `ix impact --format json`, paths made repo-relative", async () => {
    ix.set("impact.json", {
      resolvedTarget: { kind: "class", name: "TokenStore" },
      depth: 1,
      riskSummary: `High risk: 14 dependents across 3 regions (see ${repo.root}/docs).`,
      riskLevel: "high",
      riskCategory: "shared-state",
      atRiskBehavior: ["session refresh", "logout"],
      summary: { members: 6, directImporters: 4, directDependents: 10, memberLevelCallers: 22 },
      topImpactedMembers: [
        { name: "rotate", kind: "method", id: "x1", callerCount: 9, path: "src/auth/token.ts", lineStart: 10, lineEnd: 40 },
        { name: "load", kind: "method", id: "x2", callerCount: 3, path: `${repo.root}/src/auth/store.ts` },
        { name: "leak", kind: "method", id: "x3", callerCount: 1, path: "/Users/someone/elsewhere/secret.ts" },
      ],
      propagationBuckets: [{ region: "auth", regionKind: "subsystem", count: 8, members: [] }],
    });
    // L3: an absolute target outside the repo is refused; inside, it becomes repo-relative before Ix sees it.
    expect((await alice.run(["ix", "impact", "/etc/passwd", "--from-session", "as1", "--to", "bob"], { cwd: repo.root })).json.error).toBe("usage");
    await alice.ok(["ix", "impact", `${repo.root}/src/auth/token.ts`, "--from-session", "as1", "--to", "bob"], { cwd: repo.root });
    expect(ix.calls().at(-1)!.argv.slice(0, 2)).toEqual(["impact", "src/auth/token.ts"]);
    await bob.watch("bs1", 800);
    const sent = await alice.ok(["ix", "impact", "TokenStore", "--kind", "class", "--changed", "src/auth/token.ts", "--from-session", "as1", "--to", "bob"], { cwd: repo.root });
    const call = ix.calls().at(-1)!;
    expect(call.argv).toEqual(["impact", "TokenStore", "--format", "json", "--limit", "20", "--kind", "class"]);
    expect(sent.body.files).toEqual(["src/auth/token.ts", "src/auth/store.ts"]);
    expect(JSON.stringify(sent.body)).not.toMatch(/\/Users\/|secret\.ts/);
    expect(sent.body.riskSummary).toBe("High risk: 14 dependents across 3 regions (see ./docs).");
    await alice.ok(["ix", "impact", "TokenStore", "--from-session", "as1", "--to", "carol"], { cwd: repo.root });

    // A client's dry run builds the report without sending; `--body` then sends exactly that (validated again).
    const calls = ix.calls().length;
    const dry = await alice.ok(["ix", "impact", "TokenStore", "--kind", "class", "--dry-run"], { cwd: repo.root });
    expect(dry).toMatchObject({ dryRun: true, body: { riskLevel: "high", target: { name: "TokenStore" } } });
    expect(ix.calls().length).toBe(calls + 1);
    const viaBody = await alice.ok(["ix", "impact", "TokenStore", "--from-session", "as1", "--to", "bob", "--body", "-"], { cwd: repo.root, stdin: JSON.stringify(dry.body) });
    expect(viaBody.body).toEqual(dry.body);
    expect(ix.calls().length).toBe(calls + 1); // --body runs no Ix
    expect((await alice.run(["ix", "impact", "T", "--from-session", "as1", "--to", "bob", "--body", "-"], { stdin: JSON.stringify({ ...dry.body, files: ["/etc/passwd"] }) })).json.error).toBe("usage");
    const be = (await bob.watch("bs1", 1500)).events.find((e) => e.ext === "x:ix.impact");
    expect(be.rendered).toMatchObject({ type: "impact", riskLevel: "high", target: { name: "TokenStore", kind: "class" }, components: [{ name: "auth", kind: "subsystem", count: 8 }] });
    expect(be.rendered.digest).toMatch(/risk high: High risk: 14 dependents/);
    const ce = (await carol.watch("cs1", 1500)).events.find((e) => e.ext === "x:ix.impact");
    expect(ce.fallback).toMatch(/shared an Ix blast-radius report \(high risk, 2 affected\): install Ix to open it/);
    expect(ce.rendered).toBeUndefined();
  });

  it("semantic conflicts: my change reaches a file a peer is editing (stubbed Ix graph)", async () => {
    // In alice's graph, src/api/handler.ts calls into src/auth/token.ts.
    ix.set("around-src__auth__token.ts.json", {
      path: "src/auth/token.ts",
      symbols: [
        {
          id: "s1",
          name: "rotate",
          kind: "function",
          path: "src/auth/token.ts",
          lineStart: 1,
          lineEnd: 9,
          callers: { total: 1, rows: [{ path: "src/api/handler.ts", line: 12, name: "handle" }] },
          users: { total: 0, rows: [] },
          tests: { total: 1, rows: [{ path: "test/token.test.ts" }] },
          sameName: [],
        },
      ],
      importers: { total: 1, rows: [{ path: "src/api/handler.ts", line: 1 }], tests: 0 },
    });
    await alice.ok(["status", "--session", "as1", "--state", "busy", "--repo", "acme/widgets", "--file", "src/auth/token.ts"]);
    const r = await alice.ok(["ix", "conflicts", "--session", "as1"]);
    expect(r.conflicts).toHaveLength(2);
    expect(r.conflicts.map((c: any) => c.peer.sid).sort()).toEqual(["bs1", "cs1"]);
    expect(r.conflicts[0]).toMatchObject({ mine: "src/auth/token.ts", theirs: "src/api/handler.ts", direction: "mine-affects-theirs", via: ["caller", "importer"] });
    expect(r.conflicts[0].message).toMatch(/^possible semantic conflict with (bob|carol)@[a-z2-7-]+: your change to src\/auth\/token\.ts affects src\/api\/handler\.ts they're editing/);
    // A peer in another repo is not compared.
    const other = await alice.ok(["ix", "conflicts", "--file", "src/auth/token.ts", "--repo", "acme/other"]);
    expect(other.conflicts).toEqual([]);
  });
});
