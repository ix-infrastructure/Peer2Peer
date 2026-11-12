// Copyright 2026 Ix Infrastructure Inc.
//
// The extension seam (extensions.ts, ext-host.ts), with a throwaway
// extension in a namespace registered for this file only (`acme`), installed in a temp
// directory (no real extension package):
//   - loading is opt-in (P2P_EXTENSIONS or config.json `extensions`), from
//     explicit directories only, and announced the first time per location;
//   - its commands appear under `p2p <ns>`; a registered namespace that
//     isn't enabled gets a stub that says how;
//   - an inbound `x:<ns>.*` kind is rendered by it when loaded, and is only
//     the fallback when not; kept bodies never reach `watch`;
//   - an extension can only send its own namespace.

import { mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { enabledNamespaces, extensionDirs, isInside, KNOWN_EXTENSIONS, kindNamespace, loadExtensions, resolveIn, siblingNodeModules } from "../extensions.js";
import { eventLine } from "../watch.js";
import { extWorkdir } from "../ext-host.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-ext.test/v3";

const DEMO = `
export const extension = {
  api: 1,
  ns: "acme",
  name: "@peer2peer/ext-acme",
  version: "0.0.1",
  receive(input) {
    if (input.kind !== "x:acme.ping") return { ok: false, reason: "unknown demo kind" };
    if (typeof input.body?.n !== "number") return { ok: false, reason: "n must be a number" };
    return { ok: true, rendered: { type: "ping", n: input.body.n, digest: "[data from peer " + input.from.address + "]: ping " + input.body.n + " <b>" }, keep: input.body };
  },
  commands: [
    {
      name: "ping",
      args: "<n>",
      description: "Send a demo ping",
      options: [{ flags: "--from-session <sid>", description: "session" }, { flags: "--to <address>", description: "peer" }, { flags: "--kind <kind>", description: "override the kind" }],
      async run(ctx, args, opts) {
        const r = await ctx.send({ fromSession: opts.fromSession, to: opts.to, kind: opts.kind ?? "x:acme.ping", v: 1, body: { n: Number(args[0]) }, fallback: "sent a demo ping: install @peer2peer/ext-acme" });
        return { json: r, human: "pinged" };
      },
    },
    {
      name: "seen",
      description: "Pings received",
      async run(ctx) {
        const ev = await ctx.events();
        await ctx.kv.set("count", ev.length);
        return { json: { events: ev, count: await ctx.kv.get("count"), interactive: ctx.interactive }, human: String(ev.length) };
      },
    },
    {
      name: "fail",
      description: "Fails with a code",
      async run() {
        const e = new Error("demo says no");
        e.code = "demo_refused";
        throw e;
      },
    },
  ],
};
`;

function installPkg(nodeModules: string, name: string, files: Record<string, string>, pkg: object = {}): string {
  const p = join(nodeModules, ...name.split("/"));
  mkdirSync(p, { recursive: true });
  writeFileSync(join(p, "package.json"), JSON.stringify({ name, version: "0.0.1", type: "module", exports: { ".": { default: "./index.js" } }, ...pkg }));
  for (const [f, text] of Object.entries(files)) writeFileSync(join(p, f), text);
  return p;
}

let relay: TestRelay;
let extDir: string;
let alice: User;
let bob: User;
let carol: User;
let scratch: User;
const ids: Record<string, string> = {};

describe("extension seam", () => {
  // Only `ix` is registered (protocol §8.3). This file registers `acme` for its demo extension, in
  // this module instance only (vitest isolates test files); no environment or config can add one.
  const known = KNOWN_EXTENSIONS as string[];
  beforeAll(async () => {
    expect([...known]).toEqual(["ix"]);
    known.push("acme");
    relay = await startRelay(R);
    const transport = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    scratch = new User("scratch", {});
    extDir = join(scratch.home, "exts");
    installPkg(join(extDir, "node_modules"), "@peer2peer/ext-acme", { "index.js": DEMO });
    alice = new User("alice", transport, { P2P_EXTENSION_PATH: extDir, P2P_EXTENSIONS: "acme" });
    // bob enables it in config.json (below); carol enables it but hasn't installed it.
    bob = new User("bob", transport, { P2P_EXTENSION_PATH: extDir });
    carol = new User("carol", transport, { P2P_EXTENSIONS: "acme" });
    for (const u of [alice, bob, carol]) ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
    for (const u of [bob, carol]) {
      const inv = await alice.ok(["invite", "--link"]);
      await u.ok(["accept", inv.link]);
      await alice.ok(["friends"]);
      await u.ok(["session", "roster", `${u.name}-s`, "--add", ids.alice]);
      await u.ok(["status", "--session", `${u.name}-s`, "--state", "busy"]);
    }
    // Alice's project is shared with both (projects.ts: a session sends only within its project).
    await alice.share(ids.bob, ids.carol);
    await alice.ok(["ls"]);
  });

  afterAll(async () => {
    await relay?.close().catch(() => {});
    for (const u of [alice, bob, carol, scratch]) u?.cleanup();
    known.splice(known.indexOf("acme"), 1);
  });

  it("only registered namespaces can be enabled (L2); opt-in", () => {
    expect(enabledNamespaces({})).toEqual({ enabled: [], ignored: [] });
    expect(enabledNamespaces({}, { extensions: ["ix"] })).toEqual({ enabled: ["ix"], ignored: [] });
    expect(enabledNamespaces({ P2P_EXTENSIONS: "@peer2peer/ext-ix, acme ,demo,ix" }, { extensions: ["acme"] })).toEqual({ enabled: ["ix", "acme"], ignored: ["demo"] });
    expect(enabledNamespaces({ P2P_EXTENSIONS: "none" }, { extensions: ["ix"] }).enabled).toEqual([]);
    // A namespace that isn't registered is refused, whether it comes from the environment or config.json.
    expect(enabledNamespaces({ P2P_EXTENSIONS: "@peer2peer/ext-other,other" }, { extensions: ["other"] })).toEqual({ enabled: [], ignored: ["@peer2peer/ext-other", "other"] });
    expect(enabledNamespaces({}, { extensions: ["other", "ix"] })).toEqual({ enabled: ["ix"], ignored: ["other"] });
    // "config": only config.json counts (what the Claude mod passes, so a shell variable can't enable for it).
    expect(enabledNamespaces({ P2P_EXTENSIONS: "config" }, { extensions: ["ix"] }).enabled).toEqual(["ix"]);
    expect(enabledNamespaces({ P2P_EXTENSIONS: "config" }, {}).enabled).toEqual([]);
    expect(kindNamespace("x:ix.note")).toBe("ix");
    expect(kindNamespace("msg")).toBeUndefined();
  });

  it("nothing enabled, nothing loaded, even when installed (M3)", async () => {
    const warns: string[] = [];
    expect((await loadExtensions({ env: { P2P_EXTENSION_PATH: extDir }, warn: (m) => warns.push(m) })).list()).toEqual([]);
    expect(warns).toEqual([]);
    expect((await bob.ok(["extensions"])).extensions).toEqual([]);
    const r = await bob.run(["acme", "ping", "1"]);
    expect(r.json).toMatchObject({ error: "extension_missing" });
    expect(r.json.reason).toMatch(/p2p extensions enable acme/);
  });

  it("enable/disable edit config.json; the first load from a location is announced once", async () => {
    expect(await bob.ok(["extensions", "enable", "acme"])).toEqual({ enabled: ["acme"] });
    const first = await bob.run(["extensions"]);
    expect(first.json.extensions.map((e: any) => e.ns)).toEqual(["acme"]);
    expect(first.err).toMatch(/loading extension @peer2peer\/ext-acme 0\.0\.1 from .*ext-acme\/index\.js \(it runs with your p2p identity/);
    const again = await bob.run(["extensions"]);
    expect(again.err).not.toMatch(/loading extension/);
    expect((await bob.run(["extensions", "enable", "demo"])).json).toMatchObject({ error: "usage" });
    expect(await bob.ok(["extensions", "disable", "acme"])).toEqual({ enabled: [] });
    expect((await bob.ok(["extensions"])).extensions).toEqual([]);
    await bob.ok(["extensions", "enable", "acme"]);
  });

  it("resolves only inside the explicit directories: no walk-up, NODE_PATH or escapes (M3, L1)", async () => {
    const root = join(scratch.home, "resolve");
    // An ancestor node_modules and NODE_PATH both hold a package; neither is used.
    installPkg(join(root, "node_modules"), "@peer2peer/ext-acme", { "index.js": DEMO });
    mkdirSync(join(root, "sub", "deeper"), { recursive: true });
    const env = { P2P_EXTENSIONS: "acme", P2P_EXTENSION_PATH: join(root, "sub", "deeper"), NODE_PATH: join(root, "node_modules") };
    const warns: string[] = [];
    const nowhere = pathToFileURL(join(root, "sub", "x.js")).href;
    expect((await loadExtensions({ env, selfUrl: nowhere, warn: (m) => warns.push(m) })).list()).toEqual([]);
    expect(warns.join("\n")).toMatch(/enabled but not installed/);
    // An entry that points outside the package is refused, and that base skipped: the next base still loads.
    const bad = join(scratch.home, "bad");
    installPkg(join(bad, "node_modules"), "@peer2peer/ext-acme", {}, { exports: { ".": { default: "../../../../exts/node_modules/@peer2peer/ext-acme/index.js" } } });
    expect(() => resolveIn(join(bad, "node_modules"), "@peer2peer/ext-acme")).toThrow(/outside the package/);
    const broken = join(scratch.home, "broken");
    mkdirSync(join(broken, "node_modules", "@peer2peer", "ext-acme"), { recursive: true });
    writeFileSync(join(broken, "node_modules", "@peer2peer", "ext-acme", "package.json"), "{not json");
    const w2: string[] = [];
    const reg = await loadExtensions({ env: { P2P_EXTENSIONS: "acme", P2P_EXTENSION_PATH: [bad, broken, extDir].join(":") }, selfUrl: nowhere, warn: (m) => w2.push(m) });
    expect(reg.get("acme")?.version).toBe("0.0.1");
    expect(w2.filter((m) => /skipping/.test(m))).toHaveLength(2);
    // A symlinked package (npm link) is fine: the entry is inside its real directory.
    const linked = join(scratch.home, "linked", "node_modules", "@peer2peer");
    mkdirSync(linked, { recursive: true });
    symlinkSync(join(extDir, "node_modules", "@peer2peer", "ext-acme"), join(linked, "ext-acme"), "dir");
    expect(resolveIn(join(scratch.home, "linked", "node_modules"), "@peer2peer/ext-acme")).toMatch(/exts\/node_modules\/@peer2peer\/ext-acme\/index\.js$/);
  });

  it("P2P_EXTENSION_EXCLUDE drops entries inside a directory by real path (a symlink can't hide it)", () => {
    const repo = join(scratch.home, "repo")
    mkdirSync(join(repo, "vendor", "exts"), { recursive: true })
    const outside = join(scratch.home, "outside-link")
    symlinkSync(join(repo, "vendor"), outside, "dir")
    const self = "file:///usr/lib/node_modules/@peer2peer/cli/dist/extensions.js"
    const env = { P2P_EXTENSION_PATH: [join(repo, "vendor", "exts"), join(outside, "exts"), extDir].join(":"), P2P_EXTENSION_EXCLUDE: repo }
    expect(extensionDirs(env, self)).toEqual([join(extDir, "node_modules"), "/usr/lib/node_modules"])
    // And the other way round: the repo reached through a symlink is still the repo.
    const repoLink = join(scratch.home, "repo-link")
    symlinkSync(repo, repoLink, "dir")
    expect(extensionDirs({ ...env, P2P_EXTENSION_EXCLUDE: repoLink }, self)).toEqual([join(extDir, "node_modules"), "/usr/lib/node_modules"])
    expect(isInside(join(repo, "missing", "x"), repoLink)).toBe(true)
    expect(isInside(extDir, repo)).toBe(false)
  });

  it("the CLI's sibling node_modules is a base only when installed as a package", () => {
    expect(siblingNodeModules("/usr/lib/node_modules/@peer2peer/cli/dist/extensions.js")).toBe("/usr/lib/node_modules");
    expect(siblingNodeModules("/work/Peer2Peer/packages/p2p/dist/extensions.js")).toBeUndefined();
    expect(siblingNodeModules("/home/me/.claude/plugins/peer2peer/bin/p2p.mjs")).toBeUndefined();
    expect(extensionDirs({ P2P_EXTENSION_PATH: "/a:/b/node_modules" }, "file:///usr/lib/node_modules/@peer2peer/cli/dist/extensions.js")).toEqual(["/a/node_modules", "/b/node_modules", "/usr/lib/node_modules"]);
  });

  it("an enabled namespace that isn't installed explains itself", async () => {
    const c = await carol.run(["extensions"]);
    expect(c.json.extensions).toEqual([]);
    expect(c.err).toMatch(/@peer2peer\/ext-acme is enabled but not installed/);
    const r = await carol.run(["ix", "note", "--to", "x", "hello"]);
    expect(r.code).toBe(1);
    expect(r.json).toMatchObject({ error: "extension_missing", extension: "@peer2peer/ext-ix" });
  });

  it("renders with the extension; the fallback without it; kept bodies stay local", async () => {
    const sent = await alice.ok(["acme", "ping", "7", "--from-session", "as", "--to", "bob"]);
    expect(sent).toMatchObject({ delivered: true, kind: "x:acme.ping", to: { sid: "bob-s" } });
    await alice.ok(["acme", "ping", "8", "--from-session", "as", "--to", "carol"]);
    const b = await bob.watch("bob-s", 1500);
    const be = b.find((e) => e.kind === "p2p.ext");
    expect(be).toMatchObject({ ext: "x:acme.ping", rendered: { type: "ping", n: 7 } });
    expect(be.rendered.digest).toMatch(/: ping 7 b$/); // sanitized by p2p too
    expect(be.fallback).toMatch(/^alice@[a-z2-7-]+: sent a demo ping: install @peer2peer\/ext-acme$/);
    expect(be._kept).toBeUndefined();
    const seen = await bob.ok(["acme", "seen"]);
    expect(seen.events[0]).toMatchObject({ kind: "x:acme.ping", kept: { v: 1, body: { n: 7 } } });
    expect(seen).toMatchObject({ count: 1, interactive: false });
    const c = await carol.watch("carol-s", 1500);
    const ce = c.find((e) => e.kind === "p2p.ext");
    expect(ce.rendered).toBeUndefined();
    expect(ce.fallback).toMatch(/: sent a demo ping/);
  });

  it("an invalid body shows the fallback with the reason", async () => {
    await alice.ok(["acme", "ping", "9", "--from-session", "as", "--to", "bob", "--kind", "x:acme.other"]);
    const be = (await bob.watch("bob-s", 1500)).find((e) => e.kind === "p2p.ext");
    expect(be).toMatchObject({ ext: "x:acme.other", extError: "unknown demo kind" });
    expect(be.rendered).toBeUndefined();
  });

  it("an extension can only send its own namespace; its errors keep their code", async () => {
    const r = await alice.run(["acme", "ping", "1", "--from-session", "as", "--to", "bob", "--kind", "x:ix.note"]);
    expect(r.json).toMatchObject({ error: "usage", reason: expect.stringMatching(/may only send x:acme/) });
    const f = await alice.run(["acme", "fail"]);
    expect(f.json).toEqual({ error: "demo_refused", reason: "demo says no" });
  });

  it("M2: the docs say an extension runs with your identity, not in a sandbox", () => {
    const here = fileURLToPath(new URL(".", import.meta.url));
    const readme = readFileSync(join(here, "../../README.md"), "utf8");
    const section = readme.slice(readme.indexOf("## Extensions"), readme.indexOf("## Readings chosen here"));
    expect(section).toMatch(/code you run with your identity/);
    expect(section).toMatch(/not a sandbox/);
    expect(section).toMatch(/identity and device keys/);
    expect(section).toMatch(/opt-in/);
    expect(section).not.toMatch(/No keys, no store/);
    const arch = readFileSync(join(here, "../../../../docs/architecture.md"), "utf8");
    const rule1 = arch.slice(arch.indexOf("1. **Core never imports an extension.**"), arch.indexOf("2. **Extensions plug in only"));
    expect(rule1).toMatch(/not containment/);
    expect(rule1).toMatch(/full access to `~\/\.p2p` and the identity key/);
    expect(rule1).not.toMatch(/gets no keys/);
  });

  it("P2P_WORKDIR sets the working directory extension commands see", () => {
    expect(extWorkdir({ P2P_WORKDIR: scratch.home })).toBe(scratch.home);
    expect(extWorkdir({ P2P_WORKDIR: "relative/dir" })).toBe(process.cwd());
    expect(extWorkdir({ P2P_WORKDIR: join(scratch.home, "missing") })).toBe(process.cwd());
    expect(extWorkdir({})).toBe(process.cwd());
  });

  it("watch never prints underscore fields", () => {
    const line = eventLine({ n: 1, id: "p2p.ext:x", at: 1, kind: "p2p.ext", data: { fallback: "f", _kept: { v: 1, body: "secret" } } });
    expect(line).not.toContain("secret");
    expect(JSON.parse(line)).toEqual({ kind: "p2p.ext", id: "p2p.ext:x", at: 1, fallback: "f" });
  });
});
