// Copyright 2026 Ix Infrastructure Inc.
//
// Graph targets (projects.ts graphTarget, epic #41 piece 5), adversarially: a private project, or a
// session bound to one, resolves to the local graph only; a shared project resolves to local while
// no shared graph exists; intersection across a session's projects (empty or mixed: local); a
// cloned repository's `.p2p-private` stays local; nothing an agent can set (IX_ENDPOINT, IX_PAT,
// config.json) widens the target or moves the local endpoint off this machine; and the env an
// extension and the CLI's own `ix` calls get carries only the local endpoint.

import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { App } from "../app.js";
import { extContext } from "../ext-host.js";
import { ExtensionRegistry, type P2PExtension } from "../extensions.js";
import { ixChildEnv, runIx, setupIx } from "../ix-local.js";
import {
  bindSession,
  DEFAULT_IX_ENDPOINT,
  describeGraphTarget,
  graphPinnedEnv,
  graphTarget,
  graphTargetOf,
  isLoopbackEndpoint,
  localGraphEndpoint,
  PRIVATE_MARKER,
  type GraphTarget,
} from "../projects.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-graph.test/v3";
const CLOUD = "https://prod.cloud.ix-infra.com";
const GRAPH = "https://graph.example.test";

function gitRepo(dir: string, remote?: string): string {
  mkdirSync(join(dir, ".git"), { recursive: true });
  writeFileSync(join(dir, ".git", "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(dir, ".git", "config"), `[core]\n\tbare = false\n${remote ? `[remote "origin"]\n\turl = ${remote}\n` : ""}`);
  return dir;
}

const local = (t: GraphTarget): Extract<GraphTarget, { kind: "local" }> => {
  expect(t.kind).toBe("local");
  return t as Extract<GraphTarget, { kind: "local" }>;
};

describe("graphTargetOf: intersection semantics (pure)", () => {
  const lo = { local: DEFAULT_IX_ENDPOINT };
  const reg = new Map([
    ["c1", GRAPH],
    ["c2", "https://graph-two.example.test"],
  ]);
  const shared = (circles: string[], people: string[] = []) => ({ circles, people });

  it("empty, private, repository-private or people-only: local", () => {
    expect(local(graphTargetOf([], { ...lo, sharedGraphs: reg })).why).toMatch(/no project/);
    expect(local(graphTargetOf([{ name: "p", share: "private" }], { ...lo, sharedGraphs: reg })).why).toMatch(/p is private/);
    expect(local(graphTargetOf([{ name: "r", share: shared(["c1"]), repoPrivate: true }], { ...lo, sharedGraphs: reg })).why).toContain(PRIVATE_MARKER);
    expect(local(graphTargetOf([{ name: "f", share: shared([], ["u_friend"]) }], { ...lo, sharedGraphs: reg })).why).toMatch(/isn't shared with a circle/);
  });

  it("shared with one circle that has a graph: that graph; mixed with a private project: local", () => {
    expect(graphTargetOf([{ name: "s", share: shared(["c1"]) }], { ...lo, sharedGraphs: reg })).toEqual({ kind: "shared", circle: "c1", endpoint: GRAPH });
    expect(graphTargetOf([{ name: "s", share: shared(["c1"]) }, { name: "q", share: shared(["c1", "c3"]) }], { ...lo, sharedGraphs: reg })).toEqual({ kind: "shared", circle: "c1", endpoint: GRAPH });
    local(graphTargetOf([{ name: "s", share: shared(["c1"]) }, { name: "p", share: "private" }], { ...lo, sharedGraphs: reg }));
    expect(local(graphTargetOf([{ name: "s", share: shared(["c1"]) }, { name: "t", share: shared(["c2"]) }], { ...lo, sharedGraphs: reg })).why).toMatch(/no circle in common/);
  });

  it("a choice of circles, an http or loopback graph, or no registry at all: local", () => {
    expect(local(graphTargetOf([{ name: "q", share: shared(["c1", "c2"]) }], { ...lo, sharedGraphs: reg })).why).toMatch(/more than one circle/);
    local(graphTargetOf([{ name: "s", share: shared(["c1"]) }], { ...lo, sharedGraphs: new Map([["c1", "http://graph.example.test"]]) }));
    local(graphTargetOf([{ name: "s", share: shared(["c1"]) }], { ...lo, sharedGraphs: new Map([["c1", "https://localhost:8090"]]) }));
    // Today's registry (SHARED_GRAPHS) is empty: every shared project is local.
    expect(local(graphTargetOf([{ name: "s", share: shared(["c1"]) }], lo)).why).toMatch(/no shared graph for its circle yet/);
  });

  it("the local endpoint is always on this machine", () => {
    for (const u of ["http://localhost:8090", "http://127.0.0.1:9", "https://[::1]:8443/"]) expect(isLoopbackEndpoint(u), u).toBe(true);
    for (const u of [CLOUD, "http://localhost.evil.example", "http://127.0.0.1@evil.example", "http://user:pw@localhost:8090", "http://10.0.0.5:8090", "file:///etc/passwd", "http://localhost:8090/?x=1", "ws://localhost:8090"]) {
      expect(isLoopbackEndpoint(u), u).toBe(false);
    }
    // Never from the environment (an agent or a project config sets it), loopback or not.
    expect(localGraphEndpoint({ IX_ENDPOINT: CLOUD })).toBe(DEFAULT_IX_ENDPOINT);
    expect(localGraphEndpoint({ IX_ENDPOINT: "http://127.0.0.1:9999/" })).toBe(DEFAULT_IX_ENDPOINT);
    // Only the person's config.json, loopback only, normalised to origin + path.
    expect(localGraphEndpoint({}, { ixEndpoint: "https://evil.example" })).toBe(DEFAULT_IX_ENDPOINT);
    expect(localGraphEndpoint({}, { ixEndpoint: "http://localhost:7000" })).toBe("http://localhost:7000");
    expect(localGraphEndpoint({}, { ixEndpoint: "HTTP://LOCALHOST:7000/ix//" })).toBe("http://localhost:7000/ix");
    expect(localGraphEndpoint({}, { ixEndpoint: "http://127.0.0.1:80/" })).toBe("http://127.0.0.1");
    expect(describeGraphTarget({ kind: "local", endpoint: DEFAULT_IX_ENDPOINT, why: "x" })).toBe(`local only (${DEFAULT_IX_ENDPOINT})`);
  });
});

describe("graphTarget: the chokepoint, with real projects and a session", () => {
  let relay: TestRelay;
  let ann: User;
  let team: string;
  let other: string;
  let root: string;
  const repo: Record<string, string> = {};
  const app = async (extra: Record<string, string> = {}) => {
    const a = new App({ env: { ...ann.env, ...extra }, io: { out: () => {}, err: () => {} } });
    a.front = true;
    await a.load();
    return a;
  };

  beforeAll(async () => {
    root = realpathSync(mkdtempSync(join(tmpdir(), "p2p-graph-")));
    repo.S = gitRepo(join(root, "shared"), "git@github.com:acme/shared.git");
    repo.Q = gitRepo(join(root, "both"), "git@github.com:acme/both.git");
    repo.P = gitRepo(join(root, "secret"), "git@github.com:acme/secret.git");
    // A clone of a shared remote carrying .p2p-private: the repository asks for privacy.
    repo.C = gitRepo(join(root, "clone"), "git@github.com:acme/clone.git");
    relay = await startRelay(R);
    ann = new User("ann", { [R]: `ws://127.0.0.1:${relay.port}/v3` });
    ann.autoShareProject = false;
    await ann.ok(["init", "--name", "ann", "--relay", R, "--yes"]);
    team = (await ann.ok(["circle", "create", "team"])).cid;
    other = (await ann.ok(["circle", "create", "other"])).cid;
    await ann.ok(["project", "share", team, "--dir", repo.S]);
    await ann.ok(["project", "share", team, other, "--dir", repo.Q]);
    await ann.ok(["project", "share", team, "--dir", repo.C]);
    // The test process's own cwd is always intersected too (projects.ts graphTarget): shared with the team here.
    await ann.ok(["project", "share", team, "--dir", process.cwd()]);
    writeFileSync(join(repo.C, PRIVATE_MARKER), "");
  }, 60_000);

  afterAll(async () => {
    await relay?.close().catch(() => {});
    ann?.cleanup();
    rmSync(root, { recursive: true, force: true });
  });

  it("today every project is local: private, unmapped, shared and the cloned .p2p-private repository", async () => {
    const a = await app();
    try {
      for (const d of [repo.P, repo.S, repo.Q, repo.C, root]) local(await graphTarget(a, { dirs: [d] }));
      expect((await graphTarget(a, { dirs: [repo.C] }, new Map([[team, GRAPH]]))).kind).toBe("local");
      expect(local(await graphTarget(a, { dirs: [repo.C] }, new Map([[team, GRAPH]]))).why).toContain(PRIVATE_MARKER);
    } finally {
      await a.close();
    }
  });

  it("with a shared graph for the circle: a registered session in a shared project reaches it, but not alongside a private one or a session bound to one", async () => {
    const reg = new Map([[team, GRAPH]]);
    const a = await app();
    try {
      // No session, or one no front end registered: never shared.
      expect(local(await graphTarget(a, { dirs: [repo.S] }, reg)).why).toMatch(/only a session your front end registered/);
      await bindSession(a, "g0", [repo.S]);
      expect(await graphTarget(a, { sid: "g0", dirs: [repo.S] }, reg)).toEqual({ kind: "shared", circle: team, endpoint: GRAPH });
      // Two projects, one shared with two circles: the intersection is the team.
      expect(await graphTarget(a, { sid: "g0", dirs: [repo.S, repo.Q] }, reg)).toEqual({ kind: "shared", circle: team, endpoint: GRAPH });
      // Mixed with a private project: local, whichever order.
      local(await graphTarget(a, { sid: "g0", dirs: [repo.S, repo.P] }, reg));
      local(await graphTarget(a, { sid: "g0", dirs: [repo.P, repo.S] }, reg));
      // A path argument in a private project (a target file, --path, --changed): local.
      local(await graphTarget(a, { sid: "g0", dirs: [repo.S], paths: [join(repo.P, "src", "keys.ts")] }, reg));
      expect((await graphTarget(a, { sid: "g0", dirs: [repo.S], paths: [join(repo.S, "src", "a.ts"), join(repo.Q, "lib")] }, reg)).kind).toBe("shared");
      // A relative path, or too many: local (fail closed).
      expect(local(await graphTarget(a, { sid: "g0", dirs: [repo.S], paths: ["src/a.ts"] }, reg)).why).toMatch(/isn't absolute/);
      local(await graphTarget(a, { sid: "g0", dirs: [repo.S], paths: Array.from({ length: 65 }, (_, i) => join(repo.S, `f${i}`)) }, reg));
      // A session that once worked in the private project stays local, even run from the shared one.
      await bindSession(a, "g1", [repo.S, repo.P]);
      expect(local(await graphTarget(a, { sid: "g1", dirs: [repo.S] }, reg)).why).toMatch(/session g1 is private/);
      // A session bound to the shared project only: shared; an agent naming a shared sibling can't widen a private one.
      await bindSession(a, "g2", [repo.S]);
      expect((await graphTarget(a, { sid: "g2", dirs: [repo.S] }, reg)).kind).toBe("shared");
      local(await graphTarget(a, { sid: "g2", dirs: [repo.S, repo.P] }, reg));
      // Too many folders: local.
      local(await graphTarget(a, { sid: "g2", dirs: [repo.S], over: true }, reg));
    } finally {
      await a.close();
    }
  });

  it.skipIf(process.platform === "win32")("P2P_WORKDIR doesn't replace the process's real cwd: a private cwd keeps it local", async () => {
    const reg = new Map([[team, GRAPH]]);
    const a = await app();
    const was = process.cwd();
    try {
      await bindSession(a, "g3", [repo.S]);
      process.chdir(repo.P);
      local(await graphTarget(a, { sid: "g3", dirs: [repo.S] }, reg));
      process.chdir(repo.S);
      expect((await graphTarget(a, { sid: "g3", dirs: [repo.S] }, reg)).kind).toBe("shared");
    } finally {
      process.chdir(was);
      await a.close();
    }
  });

  it("an agent can't widen the target: env, config.json and an agent's own session name change nothing", async () => {
    // Pro-like login in the environment, plus config.json keys that look like a registry.
    const cfg = join(ann.home, "config.json");
    const before = (() => {
      try {
        return readFileSync(cfg, "utf8");
      } catch {
        return undefined;
      }
    })();
    writeFileSync(cfg, JSON.stringify({ ixEndpoint: CLOUD, sharedGraphs: { [team]: GRAPH }, graphTarget: "shared" }));
    const a = await app({ IX_ENDPOINT: CLOUD, IX_PAT: "kpat_abcdefgh", IX_ORG: "acme", P2P_GRAPH_TARGET: "shared", P2P_SHARED_GRAPHS: JSON.stringify({ [team]: GRAPH }) });
    try {
      for (const d of [repo.S, repo.Q]) {
        const t = local(await graphTarget(a, { dirs: [d] }));
        expect(t.endpoint).toBe(DEFAULT_IX_ENDPOINT);
      }
      // An agent's shell naming a session nobody bound: local (fail closed), even from a shared project.
      const agent = new App({ env: { ...ann.env, P2P_PERSON_TOKEN: undefined, CLAUDECODE: "1" }, io: { out: () => {}, err: () => {} } });
      await agent.load();
      try {
        local(await graphTarget(agent, { sid: "nobody", dirs: [repo.S] }, new Map([[team, GRAPH]])));
      } finally {
        await agent.close();
      }
    } finally {
      await a.close();
      if (before === undefined) rmSync(cfg, { force: true });
      else writeFileSync(cfg, before);
    }
  });

  it("an extension's context: graphTarget is the chokepoint's, and its env carries no cloud setting", async () => {
    const a = await app({ IX_ENDPOINT: CLOUD, IX_PAT: "kpat_abcdefgh", IX_ORG: "acme", IX_PUSH_TOKEN: "t", IX_AUTO_MAP_CLOUD: "1", IX_HOME: "/tmp/ixhome", IX_BIN: "/usr/local/bin/ix", P2P_WORKDIR: repo.P });
    try {
      const ext = { api: 1, ns: "ix", name: "@peer2peer/ext-ix", version: "0" } as P2PExtension;
      a.extensions = new ExtensionRegistry();
      const ctx = extContext(a, ext, { out: () => {}, err: () => {} }, true, async () => false);
      const t = await ctx.graphTarget!({ sid: "g1" });
      expect(t).toMatchObject({ kind: "local", endpoint: DEFAULT_IX_ENDPOINT });
      expect(ctx.env.IX_ENDPOINT).toBe(DEFAULT_IX_ENDPOINT);
      for (const k of ["IX_PAT", "IX_ORG", "IX_PUSH_TOKEN", "IX_AUTO_MAP_CLOUD"]) {
        expect(k in ctx.env, k).toBe(true);
        expect(ctx.env[k], k).toBeUndefined();
      }
      expect(ctx.env).toMatchObject({ IX_HOME: "/tmp/ixhome", IX_BIN: "/usr/local/bin/ix", IX_MAP_BACKGROUND_REFRESH: "0" });
      // An older ext-ix spreads {...process.env, ...ctx.env}: the cloud settings still drop out.
      const merged = { ...{ IX_PAT: "kpat_from_shell", IX_ENDPOINT: CLOUD }, ...ctx.env };
      expect(merged.IX_PAT).toBeUndefined();
      expect(merged.IX_ENDPOINT).toBe(DEFAULT_IX_ENDPOINT);
    } finally {
      await a.close();
    }
  });

  it("project show and ls print the graph target: local only", async () => {
    const show = await ann.ok(["project", "show", "--dir", repo.S]);
    expect(show.project.graph).toMatchObject({ kind: "local", endpoint: DEFAULT_IX_ENDPOINT });
    const human = await ann.run(["project", "show", "--dir", repo.P], { json: false });
    expect(human.out).toMatch(/graph: local only \(http:\/\/localhost:8090\)/);
    const ls = await ann.ok(["project", "ls"]);
    expect(ls.projects.every((p: { graph: GraphTarget }) => p.graph.kind === "local")).toBe(true);
  });
});

describe("the env the CLI's own `ix` calls get (setup, doctor)", () => {
  let d: string;
  beforeAll(() => {
    d = realpathSync(mkdtempSync(join(tmpdir(), "p2p-ixenv-")));
  });
  afterAll(() => rmSync(d, { recursive: true, force: true }));

  it("PATH keeps only absolute entries (a relative or empty one means the repository's cwd)", () => {
    expect(ixChildEnv({ PATH: ["/usr/bin", "", ".", "node_modules/.bin", "/opt/ix/bin"].join(":") }, { endpoint: DEFAULT_IX_ENDPOINT }).PATH).toBe(process.platform === "win32" ? "" : "/usr/bin:/opt/ix/bin");
  });

  it("an allowlist, with the target's endpoint pinned: no IX_PAT, IX_ENDPOINT, NODE_OPTIONS or P2P_*", () => {
    const env = ixChildEnv({ PATH: "/bin", HOME: "/h", IX_ENDPOINT: CLOUD, IX_PAT: "kpat_x", IX_ORG: "o", IX_HOME: "/ix", IX_TOKEN: "local", NODE_OPTIONS: "--require /x.js", P2P_PERSON_TOKEN: "secret", HTTPS_PROXY: "http://p" }, { endpoint: DEFAULT_IX_ENDPOINT });
    expect(env).toEqual({ PATH: "/bin", HOME: "/h", IX_HOME: "/ix", IX_TOKEN: "local", IX_ENDPOINT: DEFAULT_IX_ENDPOINT, IX_MAP_BACKGROUND_REFRESH: "0", IX_NO_UPDATE_CHECK: "1" });
    const pinned = graphPinnedEnv({ IX_ENDPOINT: CLOUD, ix_pat: "x" }, { kind: "local", endpoint: DEFAULT_IX_ENDPOINT, why: "" }, {});
    expect(pinned).toMatchObject({ IX_ENDPOINT: DEFAULT_IX_ENDPOINT, ix_pat: undefined });
  });

  it.skipIf(process.platform === "win32")("a real child sees only the local endpoint, with a Pro-like login in the caller's env", async () => {
    const bin = join(d, "ix");
    writeFileSync(bin, `#!/usr/bin/env node\nprocess.stdout.write(JSON.stringify(process.env))\n`);
    chmodSync(bin, 0o755);
    const r = await runIx(bin, ["status"], { env: { ...process.env, IX_ENDPOINT: CLOUD, IX_PAT: "kpat_abcdefgh", IX_ORG: "acme" }, target: { endpoint: DEFAULT_IX_ENDPOINT }, timeoutMs: 10_000 });
    const seen = JSON.parse(r.stdout) as Record<string, string>;
    expect(seen.IX_ENDPOINT).toBe(DEFAULT_IX_ENDPOINT);
    expect(Object.keys(seen).filter((k) => /^IX_/.test(k)).sort()).toEqual(["IX_ENDPOINT", "IX_MAP_BACKGROUND_REFRESH", "IX_NO_UPDATE_CHECK"]);
    expect(JSON.stringify(seen)).not.toContain(CLOUD);
  });
});

describe("Ix on by default (setupIx)", () => {
  let d: string;
  beforeAll(() => {
    d = realpathSync(mkdtempSync(join(tmpdir(), "p2p-setupix-")));
  });
  afterAll(() => rmSync(d, { recursive: true, force: true }));

  const fakeApp = (env: Record<string, string | undefined>, file: Record<string, unknown> = {}) => ({ env, file, home: join(d, "home"), front: false }) as unknown as App;

  it("no Ix: says how to get it, enables nothing", async () => {
    const r = await setupIx(fakeApp({ PATH: join(d, "empty") }), true);
    expect(r).toMatchObject({ found: false, enabled: false, hint: expect.stringMatching(/github\.com\/ix-infrastructure\/Ix/) });
  });

  it.skipIf(process.platform === "win32")("Ix present: enabled only with ext-ix installed and the person's yes (or front end); never from an agent", async () => {
    const bin = join(d, "bin");
    mkdirSync(bin, { recursive: true });
    writeFileSync(join(bin, "ix"), "#!/bin/sh\necho 0.12.1\n");
    chmodSync(join(bin, "ix"), 0o755);
    expect(await setupIx(fakeApp({ PATH: bin }), true)).toMatchObject({ found: true, enabled: false, hint: expect.stringMatching(/npm i -g @peer2peer\/ext-ix/) });
    // Already chosen in config.json: left alone.
    expect(await setupIx(fakeApp({ PATH: bin }, { extensions: ["ix"] }), true)).toMatchObject({ found: true, enabled: true });
    // ext-ix installed (P2P_EXTENSION_PATH): asks on the terminal; "no", an agent, or an existing install change nothing.
    const extDir = join(d, "ext");
    const pkg = join(extDir, "node_modules", "@peer2peer", "ext-ix");
    mkdirSync(pkg, { recursive: true });
    writeFileSync(join(pkg, "package.json"), JSON.stringify({ name: "@peer2peer/ext-ix", main: "index.js" }));
    writeFileSync(join(pkg, "index.js"), "export const extension = {};\n");
    const home = join(d, "home");
    mkdirSync(home, { recursive: true });
    const env = { PATH: bin, P2P_EXTENSION_PATH: extDir };
    const asked: string[] = [];
    const mk = (o: { yes?: boolean; front?: boolean; env?: Record<string, string> } = {}) =>
      ({ env: { ...env, ...o.env }, file: {}, home, front: o.front === true, confirmTty: async (q: string) => (asked.push(q), o.yes === true) }) as unknown as App;
    expect(await setupIx(mk({ yes: false }), true)).toMatchObject({ enabled: false });
    expect(asked).toHaveLength(1);
    expect(await setupIx(mk({ yes: true, env: { CLAUDECODE: "1" } }), true)).toMatchObject({ enabled: false });
    expect(asked).toHaveLength(1);
    expect(await setupIx(mk({ yes: true }), false)).toMatchObject({ enabled: false });
    expect(await setupIx(mk({ yes: true }), true)).toMatchObject({ enabled: true, enabledNow: true });
    expect(JSON.parse(readFileSync(join(home, "config.json"), "utf8")).extensions).toEqual(["ix"]);
    rmSync(join(home, "config.json"));
    // The person's front end (its token: the mod's typed /peers setup) needs no terminal.
    expect(await setupIx(mk({ front: true }), true)).toMatchObject({ enabled: true, enabledNow: true });
  });
});

describe("an ext-ix from before graph targets isn't loaded", () => {
  it("the ix namespace needs graphTargets >= 1; other namespaces don't", async () => {
    const { checkExtension } = await import("../extensions.js");
    const old = { api: 1, ns: "ix", name: "@peer2peer/ext-ix", version: "0.1.0", commands: [] };
    expect(checkExtension({ extension: old }, "ix")).toMatchObject({ why: expect.stringMatching(/predates graph targets.*update @peer2peer\/ext-ix/) });
    expect(checkExtension({ extension: { ...old, graphTargets: 0 } }, "ix").ext).toBeUndefined();
    expect(checkExtension({ extension: { ...old, graphTargets: "1" } }, "ix").ext).toBeUndefined();
    expect(checkExtension({ extension: { ...old, graphTargets: 1 } }, "ix").ext).toBeDefined();
    expect(checkExtension({ extension: { ...old, ns: "kartr", name: "@peer2peer/ext-kartr" } }, "kartr").ext).toBeDefined();
  });
});
