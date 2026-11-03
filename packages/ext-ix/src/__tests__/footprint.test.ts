// Copyright 2026 Ix Infrastructure Inc.
//
// x:ix.footprint (SPEC.md §8), without a network: computing a footprint from
// git diffs and a scripted Ix, stable names across checkouts and worktrees,
// deterministic truncation, hashed names, strict receive validation, and no
// Ix meaning no footprint and no error.

import { execFileSync } from "node:child_process";
import { mkdirSync, realpathSync, writeFileSync } from "node:fs";
import { stat } from "node:fs/promises";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { receiveIx } from "../extension.js";
import { assembleFootprint, FOOTPRINT_KIND, footprintFallback, MAX_FOOTPRINT_BYTES, parseFootprintBody, symbolKey, type RawActor } from "../footprint.js";
import { computeFootprint, declaredNames, groupRanges, parseUnifiedDiff, parseWorktrees, type ComputeDeps } from "../footprint-compute.js";
import { footprintNames } from "../footprint-command.js";
import { deriveNameKey, hashFile, pickRootCommit } from "../hmac.js";
import { IxExtError } from "../text.js";
import type { IxRunner } from "../ix.js";
import { gitOut } from "../repo.js";
import { cleanupTmp, tmp } from "./harness.js";

afterAll(() => cleanupTmp());

const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" };
const git = (cwd: string, ...a: string[]) => execFileSync("git", a, { cwd, env: GIT_ENV }).toString().trim();

const TOKEN_TS = ["class Token {", "  refresh() {", "    return 1;", "  }", "  revoke() {", "    return 2;", "  }", "}", "export function helper() { return 3; }", ""].join("\n");

/** A repo with src/auth/token.ts committed; `edit` changes line 3 (inside Token.refresh) in the working tree. */
function repo(dir?: string): string {
  const root = dir ?? realpathSync(tmp("fp-repo-"));
  mkdirSync(join(root, "src", "auth"), { recursive: true });
  git(root, "init", "-q", "-b", "main");
  git(root, "remote", "add", "origin", "https://github.com/Acme/Widgets.git");
  writeFileSync(join(root, "src", "auth", "token.ts"), TOKEN_TS);
  git(root, "add", ".");
  git(root, "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "-m", "init");
  return root;
}
const edit = (root: string) => writeFileSync(join(root, "src", "auth", "token.ts"), TOKEN_TS.replace("    return 1;", "    return 10;"));

/** Ix as the real 0.12.1 answers for this repo: impact members with (absolute) spans, around for a line range. */
function scriptedIx(opts: { unmapped?: string[]; absRoot?: string; fail?: boolean } = {}): IxRunner & { calls: { argv: string[]; cwd?: string }[] } {
  const calls: { argv: string[]; cwd?: string }[] = [];
  const out = (j: unknown, code = 0) => Promise.resolve({ code, stdout: JSON.stringify(j), stderr: "" });
  return {
    calls,
    run: (argv, o = {}) => {
      calls.push({ argv: [...argv], cwd: o.cwd });
      if (opts.fail) return Promise.reject(new IxExtError("ix_missing", "no ix"));
      const [cmd, target] = argv;
      if (cmd === "status") {
        const root = argv[argv.indexOf("--root") + 1] ?? "";
        const unmapped = opts.unmapped?.some((u) => root.endsWith(u));
        return out(unmapped ? { backend: "ok", graphCompleted: false } : { backend: "ok", graphCompleted: true, lastIngestAt: "2100-01-01T00:00:00Z" });
      }
      if (cmd === "impact" && target === "src/auth/token.ts") {
        return out({
          resolvedTarget: { kind: "file", name: "token.ts" },
          riskLevel: "high",
          riskSummary: "x",
          topImpactedMembers: [
            // Ix's member paths can be absolute: they are made repo-relative.
            { name: "Token", kind: "class", id: "u1", callerCount: 3, path: `${opts.absRoot ?? o.cwd}/src/auth/token.ts`, lineStart: 1, lineEnd: 8 },
            { name: "helper", kind: "function", id: "u2", callerCount: 1, path: "src/auth/token.ts", lineStart: 9, lineEnd: 9 },
          ],
          propagationBuckets: [
            { region: "auth", regionKind: "subsystem", count: 3, members: [] },
            { region: "api", regionKind: "subsystem", count: 2, members: [] },
          ],
        });
      }
      if (cmd === "around" && target === "src/auth/token.ts:3-3") {
        return out({
          path: "src/auth/token.ts",
          symbols: [
            {
              id: "u3",
              name: "refresh",
              kind: "method",
              path: "src/auth/token.ts",
              lineStart: 2,
              lineEnd: 4,
              callers: { total: 2, rows: [{ path: "src/api/handler.ts", line: 10, name: "handle" }, { path: "src/auth/token.ts", line: 9, name: "helper" }] },
              users: { total: 1, rows: [{ path: "src/web/ui.ts", line: 3 }] },
              tests: { total: 1, rows: [{ path: "src/auth/token.test.ts", line: 5, name: "refresh works" }] },
            },
          ],
          importers: { total: 1, tests: 0, rows: [{ path: "src/app.ts", line: 1 }] },
        });
      }
      if (cmd === "around" && target === "src/api/handler.ts") {
        return out({ path: target, symbols: [{ name: "handle", kind: "function", lineStart: 10, lineEnd: 20, callers: { total: 1, rows: [{ path: "src/server.ts", line: 4, name: "main" }] }, users: { total: 0, rows: [] }, tests: { total: 0, rows: [] } }], importers: { total: 1, rows: [{ path: "src/routes.ts" }] } });
      }
      return out({ error: "unresolved_target", message: "not in the graph" }, 1);
    },
  };
}

function deps(ix: IxRunner, now = () => 1_761_100_000_000): ComputeDeps {
  return {
    ix,
    git: (cwd, args, o) => gitOut(cwd, args, GIT_ENV, o),
    stat: async (p) => {
      try {
        const s = await stat(p);
        return { mtimeMs: Math.floor(s.mtimeMs), size: s.size };
      } catch {
        return undefined;
      }
    },
    now,
  };
}

const REPO_REF = { remote: "github.com/acme/widgets" };

describe("computing a footprint from git diffs and Ix", () => {
  it("maps hunks to the touched definitions, with ring 1, regions and risk", async () => {
    const root = repo();
    edit(root);
    const ix = scriptedIx();
    const r = await computeFootprint({ root, own: { files: ["src/auth/token.ts"] } }, deps(ix));
    expect(r.mapped).toBe(true);
    expect(r.actors).toHaveLength(1);
    const a = r.actors[0];
    expect(a).toMatchObject({ a: "main", graph: "base", risk: "high", files: ["src/auth/token.ts"] });
    // The method is named with its container (Ix's qualifiedKey); the class around it isn't "changed".
    expect(a.symbols).toEqual([{ k: "src/auth/token.ts#Token.refresh", kind: "method" }]);
    expect(a.ring1Files).toEqual(
      expect.arrayContaining([
        { f: "src/api/handler.ts", rel: "call" },
        { f: "src/web/ui.ts", rel: "use" },
        { f: "src/auth/token.test.ts", rel: "test" },
        { f: "src/app.ts", rel: "import" },
      ]),
    );
    expect(a.ring1Symbols).toEqual(expect.arrayContaining([{ k: "src/api/handler.ts#handle", rel: "call" }, { k: "src/auth/token.ts#helper", rel: "call" }]));
    expect(a.components).toEqual([
      { n: "auth", kind: "subsystem", count: 3 },
      { n: "api", kind: "subsystem", count: 2 },
    ]);
    expect(a.coarse).toBeUndefined();
    // Bounded: one status, one impact and one around (one hunk group) per file.
    expect(ix.calls.map((c) => c.argv.slice(0, 2).join(" "))).toEqual(["status --format", "impact src/auth/token.ts", "around src/auth/token.ts:3-3"]);
    expect(ix.calls.every((c) => c.cwd === root)).toBe(true);
  });

  it("ring 2 (depth 2) adds who depends on the ring-1 files, without repeating ring 1", async () => {
    const root = repo();
    edit(root);
    const r = await computeFootprint({ root, own: { files: ["src/auth/token.ts"] }, depth: 2 }, deps(scriptedIx()));
    expect(r.actors[0].ring2Files).toEqual(["src/server.ts", "src/routes.ts"]);
  });

  it("caps Ix calls: what doesn't fit is partial, and nothing throws", async () => {
    const root = repo();
    edit(root);
    const r = await computeFootprint({ root, own: { files: ["src/auth/token.ts"] }, maxCalls: 2 }, deps(scriptedIx()));
    expect(r.calls).toBe(2);
    expect(r.partial).toBe(true);
    expect(r.actors[0].partial).toBe(true);
  });

  it("a file Ix doesn't know is file-level, and new declarations on added lines are named", async () => {
    const root = repo();
    writeFileSync(join(root, "src", "auth", "new.ts"), "export function brandNew() {}\n");
    git(root, "add", "-N", "src/auth/new.ts");
    const r = await computeFootprint({ root, own: { files: ["src/auth/new.ts"] } }, deps(scriptedIx()));
    expect(r.actors[0]).toMatchObject({ files: ["src/auth/new.ts"], symbols: [], newSymbols: ["src/auth/new.ts#brandNew"] });
  });

  it("parses diffs, groups hunks, reads worktrees and declarations", () => {
    const d = parseUnifiedDiff(["diff --git a/x.ts b/x.ts", "--- a/x.ts", "+++ b/x.ts", "@@ -3 +3 @@", "-a", "+b", "@@ -10,0 +11,2 @@", "+function foo() {", "+}", ""].join("\n"));
    expect(d.get("x.ts")).toEqual({ old: [{ start: 3, end: 3 }, { start: 10, end: 10 }], new: [{ start: 3, end: 3 }, { start: 11, end: 12 }], added: ["b", "function foo() {", "}"] });
    expect(groupRanges([{ start: 1, end: 2 }, { start: 10, end: 11 }, { start: 100, end: 100 }, { start: 200, end: 201 }, { start: 400, end: 400 }])).toEqual([
      { start: 1, end: 100 },
      { start: 200, end: 201 },
      { start: 400, end: 400 },
    ]);
    expect(parseWorktrees("worktree /r\nHEAD abc\nbranch refs/heads/main\n\nworktree /r/.claude/worktrees/x\nHEAD def\nbranch refs/heads/wt-x\n")).toEqual(
      new Map([
        ["main", "/r"],
        ["wt-x", "/r/.claude/worktrees/x"],
      ]),
    );
    expect(declaredNames(["export async function go() {", "  const x = 1;", "class Foo extends Bar {", "const h = () => 1", "func (s *S) Serve() {", "pub fn run() {"])).toEqual(["go", "Foo", "h", "Serve", "run"]);
  });
});

describe("stable names (SPEC §8.3)", () => {
  it("the same change names the same keys from two checkouts at different absolute paths", async () => {
    const a = repo();
    const b = repo(realpathSync(tmp("fp-other-place-")));
    edit(a);
    edit(b);
    const fa = await computeFootprint({ root: a, own: { files: ["src/auth/token.ts"] } }, deps(scriptedIx({ absRoot: a })));
    const fb = await computeFootprint({ root: b, own: { files: ["src/auth/token.ts"] } }, deps(scriptedIx({ absRoot: b })));
    const ba = assembleFootprint({ repo: REPO_REF, at: 1, seq: 1, actors: fa.actors }).body;
    const bb = assembleFootprint({ repo: REPO_REF, at: 1, seq: 1, actors: fb.actors }).body;
    expect(ba).toEqual(bb);
    expect(JSON.stringify(ba)).not.toContain(a);
    expect(JSON.stringify(bb)).not.toContain(b);
    // Hashed names agree too: the key is the remote and the root commit, never the path.
    const ka = deriveNameKey("github.com/acme/widgets", "a".repeat(40));
    expect(assembleFootprint({ repo: REPO_REF, at: 1, seq: 1, actors: fa.actors, key: ka }).body).toEqual(assembleFootprint({ repo: REPO_REF, at: 1, seq: 1, actors: fb.actors, key: ka }).body);
  });

  it("an agent in an unmapped worktree is measured against the main checkout's graph, with the same keys", async () => {
    const root = repo();
    const wt = join(root, ".claude", "worktrees", "wa");
    git(root, "worktree", "add", "-q", "-b", "wt-a", wt);
    edit(wt);
    const ix = scriptedIx({ unmapped: ["/wa"], absRoot: root });
    const now = 1_761_100_000_000;
    const r = await computeFootprint({ root, own: { files: [], agents: [{ id: "a1", state: "running", wt: true, branch: "wt-a", files: ["src/auth/token.ts"], at: now }] } }, deps(ix, () => now));
    expect(r.actors).toHaveLength(1);
    const a1 = r.actors[0];
    expect(a1).toMatchObject({ a: "a1", graph: "base", wt: true, branch: "wt-a", base: git(root, "rev-parse", "HEAD").slice(0, 12) });
    expect(a1.symbols).toEqual([{ k: "src/auth/token.ts#Token.refresh", kind: "method" }]);
    // Ix ran in the main checkout (its graph), never in the worktree.
    expect(ix.calls.filter((c) => c.argv[0] !== "status").every((c) => c.cwd === root)).toBe(true);
    // A mapped worktree uses its own graph.
    const own = await computeFootprint({ root, own: { files: [], agents: [{ id: "a1", state: "running", wt: true, branch: "wt-a", files: ["src/auth/token.ts"], at: now }] } }, deps(scriptedIx({ absRoot: wt }), () => now));
    expect(own.actors[0]).toMatchObject({ graph: "worktree", symbols: [{ k: "src/auth/token.ts#Token.refresh", kind: "method" }] });
  });

  it("symbol keys are path#qualifiedKey, with characters the wire refuses made safe", () => {
    expect(symbolKey("src/a.ts", "Foo.bar")).toBe("src/a.ts#Foo.bar");
    expect(symbolKey("src/a.rs", "impl Foo for Bar")).toBe("src/a.rs#impl_Foo_for_Bar");
    expect(symbolKey("src/a.ts", "0day")).toBe("src/a.ts#_0day");
    expect(symbolKey("/abs/a.ts", "x")).toBeUndefined();
    expect(symbolKey("src/#odd.ts", "x")).toBeUndefined();
  });
});

const actor = (a: string, n: number, extra: Partial<RawActor> = {}): RawActor => ({
  a,
  graph: "base",
  risk: "medium",
  files: Array.from({ length: n }, (_, i) => `src/${a}/f${String(i).padStart(3, "0")}.ts`),
  symbols: Array.from({ length: n * 2 }, (_, i) => ({ k: `src/${a}/f${String(i % n).padStart(3, "0")}.ts#Sym${i}`, kind: "function" })),
  ring1Files: Array.from({ length: n * 3 }, (_, i) => ({ f: `src/deps/${a}-r1-${String(i).padStart(3, "0")}.ts`, rel: i % 2 ? "call" : "import" })),
  ring1Symbols: Array.from({ length: n * 3 }, (_, i) => ({ k: `src/deps/${a}-r1-${String(i).padStart(3, "0")}.ts#caller${i}`, rel: "call" as const })),
  ring2Files: Array.from({ length: n * 4 }, (_, i) => `src/far/${a}-r2-${String(i).padStart(3, "0")}.ts`),
  components: [{ n: `region-${a}`, kind: "subsystem", count: n }],
  ...extra,
});

describe("caps and truncation (SPEC §8.4)", () => {
  it("a big footprint is trimmed to 16 KiB, deterministically, ring 2 first", () => {
    const actors = [actor("main", 25), actor("a1", 25), actor("a2", 25, { done: true }), actor("a3", 25)];
    const one = assembleFootprint({ repo: REPO_REF, at: 1, seq: 1, actors });
    const two = assembleFootprint({ repo: REPO_REF, at: 1, seq: 1, actors });
    expect(one).toEqual(two);
    const bytes = Buffer.byteLength(JSON.stringify(one.body));
    expect(bytes).toBeLessThanOrEqual(MAX_FOOTPRINT_BYTES);
    expect(Buffer.byteLength(JSON.stringify({ v: 1, body: one.body }))).toBeLessThanOrEqual(16 * 1024);
    expect(one.body.truncated).toBe(true);
    expect(one.body.actors.every((a) => a.ring2 === undefined)).toBe(true);
    // The main loop is kept, with its changed files, and the merge counts the untrimmed actors.
    expect(one.body.actors[0].a).toBe("main");
    expect(one.body.actors[0].changed.files).toHaveLength(25);
    expect(one.body.merged.counts.ring1Files).toBe(4 * 60);
    expect(parseFootprintBody(one.body)).toEqual(one.body);
  });

  it("trims only as far as it must: ring 2 alone when that is enough", () => {
    const actors = [actor("main", 8, { ring2Files: Array.from({ length: 100 }, (_, i) => `src/far/${"x".repeat(150)}-${i}.ts`) })];
    const { body } = assembleFootprint({ repo: REPO_REF, at: 1, seq: 1, actors });
    expect(body.truncated).toBe(true);
    expect(body.actors[0].ring2!.files.length).toBeGreaterThan(0);
    expect(body.actors[0].ring2!.files.length).toBeLessThan(100);
    expect(body.actors[0].ring1.files).toHaveLength(24);
    // The head of the sorted list survives.
    expect(body.actors[0].ring2!.files[0]).toBe(`src/far/${"x".repeat(150)}-0.ts`);
  });

  it("per-actor caps hold before any trimming", () => {
    const { body } = assembleFootprint({ repo: REPO_REF, at: 1, seq: 1, actors: [actor("main", 40)], maxBytes: 10_000_000 });
    const a = body.actors[0];
    expect([a.changed.files.length, a.changed.symbols.length, a.ring1.files.length, a.ring1.symbols.length, a.ring2!.files.length]).toEqual([25, 40, 60, 60, 100]);
    expect(body.truncated).toBeUndefined();
  });
});

describe("hashed names (SPEC §8.6)", () => {
  const key = deriveNameKey("github.com/acme/widgets", "b".repeat(40));
  const raw = [actor("main", 3)];

  it("replaces every file, symbol and region name with an h: token, and says which key", () => {
    const { body, fallback } = assembleFootprint({ repo: REPO_REF, at: 1, seq: 1, actors: raw, key });
    expect(body.names).toBe("hmac");
    expect(body.keyId).toMatch(/^k:[0-9a-f]{8}$/);
    const json = JSON.stringify(body.actors) + JSON.stringify(body.merged);
    expect(json).not.toMatch(/src\/|Sym\d|region-main/);
    expect(body.actors[0].changed.files[0]).toBe(hashFile(key, "src/main/f000.ts"));
    expect(body.actors[0].changed.files[0]).toMatch(/^h:[A-Za-z0-9_-]{22}$/);
    // The fallback names no area either.
    expect(fallback).toBe("Ix footprint: 6 symbols in 1 area, medium risk; enable ext-ix to compare");
    expect(parseFootprintBody(body)).toEqual(body);
    // Paths compare case-folded, as Ix does.
    expect(hashFile(key, "SRC/A.ts")).toBe(hashFile(key, "src/a.ts"));
  });

  it("the key is the remote plus the smallest root commit; another repo's key differs", () => {
    expect(pickRootCommit(`${"f".repeat(40)}\n${"0".repeat(40)}\n`)).toBe("0".repeat(40));
    expect(pickRootCommit("not a commit")).toBeUndefined();
    expect(deriveNameKey("github.com/acme/widgets", "b".repeat(40)).keyId).toBe(key.keyId);
    expect(deriveNameKey("github.com/acme/other", "b".repeat(40)).keyId).not.toBe(key.keyId);
  });

  it("is the default for every audience; plain only by an explicit choice", () => {
    const pick = (audience: Parameters<typeof footprintNames>[0]["audience"], o: Partial<Parameters<typeof footprintNames>[0]> = {}) => footprintNames({ audience, ...o }).names;
    expect(pick({ vis: "private", people: 0 })).toBe("hmac");
    expect(pick({ vis: "circle", circle: "c1", people: 3 })).toBe("hmac");
    expect(pick({ vis: "circle", circle: "c1", people: 3, open: true })).toBe("hmac");
    expect(pick({ vis: "circle", circle: "c1", people: 3, orgs: 2 })).toBe("hmac");
    expect(pick(undefined)).toBe("hmac");
    expect(pick(null)).toBe("hmac");
    // Explicit choices, most specific first.
    expect(pick({ vis: "circle", circle: "c1", people: 3 }, { config: { circles: { c1: "plain" } } })).toBe("plain");
    expect(pick({ vis: "circle", circle: "c1", people: 3 }, { config: { names: "plain" } })).toBe("plain");
    expect(pick({ vis: "circle", circle: "c1", people: 3 }, { config: { names: "plain", circles: { c1: "hmac" } } })).toBe("hmac");
    // An open circle: only its own setting; an unreadable audience: no setting applies.
    expect(pick({ vis: "circle", circle: "c1", people: 3, open: true }, { config: { names: "plain" } })).toBe("hmac");
    expect(pick({ vis: "circle", circle: "c1", people: 3, open: true }, { config: { circles: { c1: "plain" } } })).toBe("plain");
    expect(pick(undefined, { config: { names: "plain", circles: { c1: "plain" } } })).toBe("hmac");
    expect(pick({ vis: "private", people: 0 }, { env: "plain" })).toBe("plain");
    expect(pick({ vis: "circle", circle: "c1", people: 1, open: true }, { flag: "plain", env: "hmac" })).toBe("plain");
  });
});

describe("receiving (strict, SPEC §8.5)", () => {
  const good = () => structuredClone(assembleFootprint({ repo: REPO_REF, at: 1_761_100_000_000, seq: 3, actors: [actor("main", 2), actor("a1", 1, { wt: true, branch: "wt-a", base: "abcdef1234" })] }).body) as any;
  const input = (body: unknown, v = 1) => ({ kind: FOOTPRINT_KIND, v, body, fallback: "f", from: { userId: "p2p:x", address: "ann@x", self: false }, session: { own: "p2p:x", sid: "s1", ref: "r" }, state: { ttl: 600 } }) as const;

  it("keeps a valid body and renders nothing a model could read", () => {
    const r = receiveIx(input(good()) as any);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.keep).toEqual(good());
      expect(r.rendered).toEqual({ type: "footprint" });
    }
  });

  it("drops unknown fields and keeps validating the rest", () => {
    const b = good();
    b.extra = "x";
    b.actors[0].extra = 1;
    const r = receiveIx(input(b) as any);
    expect(r.ok).toBe(true);
    expect(r.ok && (r.keep as any).extra).toBe(undefined);
    expect(r.ok && (r.keep as any).actors[0].extra).toBe(undefined);
  });

  const bad: [string, (b: any) => void][] = [
    ["an absolute path", (b) => (b.actors[0].changed.files[0] = "/home/ann/src/a.ts")],
    ["a .. path", (b) => (b.actors[0].ring1.files[0].f = "../etc/passwd")],
    ["a symbol key without a path", (b) => (b.actors[0].changed.symbols[0].k = "#Foo")],
    ["a symbol key with spaces", (b) => (b.actors[0].changed.symbols[0].k = "src/a.ts#Foo bar")],
    ["an h: token in plain mode", (b) => (b.actors[0].changed.files[0] = `h:${"A".repeat(22)}`)],
    ["hmac without keyId", (b) => (b.names = "hmac")],
    ["keyId in plain mode", (b) => (b.keyId = "k:01234567")],
    ["an unknown graph", (b) => (b.actors[0].graph = "remote")],
    ["an unknown rel", (b) => (b.actors[0].ring1.files[0].rel = "owns")],
    ["a ring-1 symbol that is a test", (b) => (b.actors[0].ring1.symbols[0].rel = "test")],
    ["a bad agent id", (b) => (b.actors[1].a = "agent-7")],
    ["the same actor twice", (b) => (b.actors[1].a = "main")],
    ["no actors", (b) => (b.actors = [])],
    ["ten actors", (b) => (b.actors = Array.from({ length: 10 }, (_, i) => ({ ...b.actors[0], a: i ? `a${i}` : "main" })))],
    ["too many changed files", (b) => (b.actors[0].changed.files = Array.from({ length: 26 }, (_, i) => `f${i}.ts`))],
    ["a negative count", (b) => (b.merged.counts.ring1Files = -1)],
    ["a fractional count", (b) => (b.actors[0].components[0].count = 1.5)],
    ["wt: false", (b) => (b.actors[1].wt = false)],
    ["a region with a control character", (b) => (b.actors[0].components[0].n = "auth\u0007")],
    ["a remote that is a path", (b) => (b.repo.remote = "/srv/git/widgets")],
    ["a body over 16 KiB", (b) => (b.actors[0].changed.files = Array.from({ length: 25 }, (_, i) => `${"d".repeat(280)}/${i}.ts`)) && (b.actors[0].ring1.files = Array.from({ length: 60 }, (_, i) => ({ f: `${"e".repeat(280)}/${i}.ts`, rel: "call" })))],
    ["no merged", (b) => delete b.merged],
    ["a string seq", (b) => (b.seq = "3")],
  ];
  for (const [what, mutate] of bad) {
    it(`refuses ${what}`, () => {
      const b = good();
      mutate(b);
      const r = receiveIx(input(b) as any);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toMatch(/^invalid x:ix\.footprint: /);
    });
  }

  it("refuses a newer version, naming the update", () => {
    const r = receiveIx(input(good(), 2) as any);
    expect(r).toEqual({ ok: false, reason: expect.stringMatching(/newer than this ext-ix/) });
  });

  it("an hmac body validates as tokens", () => {
    const key = deriveNameKey("github.com/acme/widgets", "c".repeat(40));
    const { body } = assembleFootprint({ repo: REPO_REF, at: 1, seq: 1, actors: [actor("main", 2)], key });
    expect(receiveIx(input(body) as any).ok).toBe(true);
    const b = structuredClone(body) as any;
    b.actors[0].changed.files[0] = "src/a.ts";
    expect(receiveIx(input(b) as any).ok).toBe(false);
  });
});

describe("the fallback line", () => {
  it("names areas in plain mode, within 200 characters", () => {
    const { body, fallback } = assembleFootprint({
      repo: REPO_REF,
      at: 1,
      seq: 1,
      actors: [actor("main", 2, { risk: "high", components: [{ n: "auth", count: 5 }, { n: "billing", count: 3 }, { n: "api", count: 1 }] })],
    });
    expect(fallback).toBe(`Ix footprint: 4 symbols in 3 areas (auth, billing, api), high risk, ~${body.merged.counts.ring1Files + body.merged.counts.ring2Files} files downstream; enable ext-ix to compare`);
    const many = footprintFallback({ ...body, merged: { ...body.merged, components: Array.from({ length: 25 }, (_, i) => ({ n: `${"r".repeat(60)}${i}`, count: 1 })) } });
    expect([...many].length).toBeLessThanOrEqual(200);
  });
});

describe("no Ix", () => {
  it("computing never throws: everything is file level, and no graph means nothing to publish", async () => {
    const root = repo();
    edit(root);
    const r = await computeFootprint({ root, own: { files: ["src/auth/token.ts"] } }, deps(scriptedIx({ fail: true })));
    expect(r.mapped).toBe(false);
    expect(r.actors.map((a) => a.graph)).toEqual(["none"]);
  });
});

describe("what Ix names is scrubbed before it leaves (M1, L2, L3)", () => {
  it("region and symbol names lose local paths and user names; rows outside the repo are dropped", async () => {
    const root = repo();
    edit(root);
    const home = "/Users/alice";
    const leaky: IxRunner = {
      run: (argv) => {
        const out = (j: unknown, code = 0) => Promise.resolve({ code, stdout: JSON.stringify(j), stderr: "" });
        if (argv[0] === "status") return out({ graphCompleted: true });
        if (argv[0] === "impact")
          return out({
            riskLevel: "low",
            propagationBuckets: [
              { region: "/Users/alice/secret-proj", regionKind: "subsystem", count: 1 },
              { region: `${root}/src/auth`, regionKind: "subsystem", count: 1 },
              { region: "auth\u202e", count: 1 },
            ],
          });
        if (argv[0] === "around")
          return out({
            path: "src/auth/token.ts",
            symbols: [
              { name: "/Users/alice/proj/refresh", kind: "method", path: "src/auth/token.ts", lineStart: 2, lineEnd: 4, callers: { total: 2, rows: [{ path: "/Users/alice/other/x.ts", name: "leak" }, { path: "src/api/h.ts", name: "alice@example.com" }] }, users: { total: 0, rows: [] }, tests: { total: 0, rows: [] } },
              { name: "elsewhere", kind: "function", path: "/opt/other/repo/x.ts", lineStart: 1, lineEnd: 9 },
            ],
            importers: { total: 1, rows: [{ path: "../outside.ts" }] },
          });
        return out({ error: "x" }, 1);
      },
    };
    const r = await computeFootprint({ root, own: { files: ["src/auth/token.ts"] }, home, hostname: "alices-mbp.local" }, deps(leaky));
    const { body } = assembleFootprint({ repo: REPO_REF, at: 1, seq: 1, actors: r.actors });
    const json = JSON.stringify(body);
    expect(json).not.toMatch(/alice|Users|secret-proj\/|opt\/other|outside|\u202e/);
    expect(body.actors[0].components.map((c) => c.n)).toEqual(["./src/auth", "auth", "~/secret-proj"]);
    expect(body.actors[0].changed.symbols.map((s) => s.k)).toEqual(["src/auth/token.ts#__proj_refresh"]);
    expect(body.actors[0].ring1.files).toEqual([{ f: "src/api/h.ts", rel: "call" }]);
    expect(body.actors[0].ring1.symbols).toEqual([{ k: "src/api/h.ts#_email_", rel: "call" }]);
  });

  it("git paths with control or bidi characters, or git-quoted, never become entries; invalid raw entries are dropped", async () => {
    const root = repo();
    const r = await computeFootprint({ root, own: { files: ["src/ok.ts", '"src/quoted.ts"', "src/bidi\u202e.ts", "src/nul\u0007.ts", "/abs.ts", "../up.ts"] } }, deps(scriptedIx()));
    expect(r.actors[0].files).toEqual(["src/ok.ts"]);
    const { body } = assembleFootprint({
      repo: REPO_REF,
      at: 1,
      seq: 1,
      actors: [{ ...actor("main", 1), files: ["src/a.ts", "/etc/passwd"], ring1Files: [{ f: "../x.ts", rel: "call" }], components: [{ n: "bad\u0007", count: 1 }, { n: "ok", count: 1 }] }],
    });
    expect(body.actors[0].changed.files).toEqual(["src/a.ts"]);
    expect(body.actors[0].ring1.files).toEqual([]);
    expect(body.actors[0].components.map((c) => c.n)).toEqual(["ok"]);
  });
});
