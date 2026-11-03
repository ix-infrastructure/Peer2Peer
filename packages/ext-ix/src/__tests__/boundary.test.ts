// Copyright 2026 Ix Infrastructure Inc.
//
// The layer rule: core and p2p never import ext-ix (statically or by a
// literal dynamic import) and never depend on it; the one dynamic loader in
// p2p finds it when it is installed and degrades cleanly when it isn't.

import { execFile } from "node:child_process";
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { afterAll, describe, expect, it } from "vitest";
import { ExtensionRegistry, loadExtensions, renderExtension, type P2PExtension } from "@peer2peer/cli";
import { cleanupTmp, extensionDir, REPO, tmp } from "./harness.js";

const run = promisify(execFile);
const CHECK = join(REPO, "scripts", "check-boundaries.mjs");

afterAll(() => cleanupTmp());

async function check(root?: string): Promise<{ code: number; out: string }> {
  try {
    const r = await run(process.execPath, [CHECK, ...(root ? ["--root", root] : [])]);
    return { code: 0, out: r.stdout + r.stderr };
  } catch (e) {
    const x = e as { code: number; stdout: string; stderr: string };
    return { code: x.code, out: x.stdout + x.stderr };
  }
}

function write(root: string, rel: string, text: string): void {
  mkdirSync(join(root, rel, ".."), { recursive: true });
  writeFileSync(join(root, rel), text);
}

function* sources(dir: string): Generator<string> {
  for (const n of readdirSync(dir)) {
    if (n === "node_modules" || n === "dist") continue;
    const p = join(dir, n);
    if (statSync(p).isDirectory()) yield* sources(p);
    else if (/\.(?:[cm]?[jt]sx?)$/.test(n)) yield p;
  }
}

describe("check-boundaries", () => {
  it("passes on this repository", async () => {
    const r = await check();
    expect(r.out).toMatch(/boundaries ok/);
    expect(r.code).toBe(0);
  });

  it("no core or p2p source names ext-ix in an import", () => {
    for (const area of ["packages/core/src", "packages/p2p/src", "packages/relay/src", "packages/codex-bridge/src", "mods"]) {
      for (const f of sources(join(REPO, area))) {
        expect(readFileSync(f, "utf8"), f).not.toMatch(/(?:from|import|require)\s*\(?\s*["'`]@peer2peer\/ext-/);
      }
    }
  });

  it("refuses static, literal-dynamic and computed imports and dependencies; allows the loader", async () => {
    const root = tmp("boundaries-");
    write(root, "packages/p2p/src/extensions.ts", 'const href = "file:///x.js";\nexport const m = await import(href);\n');
    write(root, "packages/p2p/src/fine.ts", 'export const s = "@peer2peer/ext-ix is a package name in a string";\nconst c = await import("./circle-ops.js");\n');
    expect((await check(root)).code).toBe(0);

    write(root, "packages/p2p/src/static.ts", 'import { extension } from "@peer2peer/ext-ix";\n');
    write(root, "packages/core/src/dyn.ts", "export async function f(name: string) {\n  return import(name);\n}\n");
    write(root, "mods/claude/x/hooks/a.ts", 'export const m = () => import("@peer2peer/ext-ix");\n');
    write(root, "mods/claude/x/hooks/b.ts", 'import { extension } from "../ext/node_modules/@peer2peer/ext-ix/index.mjs";\n');
    write(root, "packages/relay/src/req.ts", "const n = 'x';\nexport const r = require(n);\n");
    write(root, "packages/p2p/package.json", JSON.stringify({ name: "@peer2peer/cli", optionalDependencies: { "@peer2peer/ext-ix": "*" } }));
    const r = await check(root);
    expect(r.code).toBe(1);
    expect(r.out).toContain("packages/p2p/src/static.ts:1  imports @peer2peer/ext-ix");
    expect(r.out).toContain("packages/core/src/dyn.ts:2  computed import()");
    expect(r.out).toContain("mods/claude/x/hooks/a.ts:1  imports @peer2peer/ext-ix");
    expect(r.out).toContain("mods/claude/x/hooks/b.ts:1  imports ../ext/node_modules/@peer2peer/ext-ix/index.mjs");
    expect(r.out).toContain("packages/relay/src/req.ts:2  computed require()");
    expect(r.out).toContain("packages/p2p/package.json  optionalDependencies lists @peer2peer/ext-ix");
    expect(r.out).not.toContain("packages/p2p/src/extensions.ts:");
    expect(r.out).not.toContain("fine.ts");
  });
});

describe("the dynamic loader", () => {
  // A base where nothing is installed, so "next to the CLI" finds nothing.
  const nowhere = () => pathToFileURL(join(tmp("nowhere-"), "x.js")).href;

  it("loads ext-ix when it is installed", async () => {
    const reg = await loadExtensions({ env: { P2P_EXTENSION_PATH: extensionDir(), P2P_EXTENSIONS: "ix" }, selfUrl: nowhere() });
    const ix = reg.get("ix");
    expect(ix?.name).toBe("@peer2peer/ext-ix");
    expect(reg.forKind("x:ix.note")).toBe(ix);
    expect(reg.forKind("x:kartr.badge")).toBeUndefined();
  });

  it("degrades cleanly when it isn't, or is turned off", async () => {
    expect((await loadExtensions({ env: { P2P_EXTENSIONS: "ix" }, selfUrl: nowhere() })).list()).toEqual([]);
    // Installed but not enabled (M3: opt-in): not loaded.
    expect((await loadExtensions({ env: { P2P_EXTENSION_PATH: extensionDir() }, selfUrl: nowhere() })).list()).toEqual([]);
    expect((await loadExtensions({ env: { P2P_EXTENSION_PATH: extensionDir(), P2P_EXTENSIONS: "none" }, selfUrl: nowhere() })).list()).toEqual([]);
    expect((await loadExtensions({ env: { P2P_EXTENSION_PATH: "/does/not/exist", P2P_EXTENSIONS: "ix" }, selfUrl: nowhere() })).list()).toEqual([]);
  });

  it("skips a broken or incompatible extension, with a warning", async () => {
    const d = tmp("ext-broken-");
    const pkg = (name: string, body: string) => {
      const dir = join(d, "node_modules", "@peer2peer", name);
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "package.json"), JSON.stringify({ name: `@peer2peer/${name}`, type: "module", exports: { ".": { default: "./index.js" } } }));
      writeFileSync(join(dir, "index.js"), body);
    };
    pkg("ext-ix", 'export const extension = { api: 99, ns: "ix", name: "@peer2peer/ext-ix", version: "9" };\n');
    pkg("ext-kartr", 'throw new Error("boom at import");\n');
    const logs: string[] = [];
    const reg = await loadExtensions({ env: { P2P_EXTENSION_PATH: d, P2P_EXTENSIONS: "ix,kartr" }, selfUrl: nowhere(), warn: (m) => logs.push(m) });
    expect(reg.list()).toEqual([]);
    expect(logs.join("\n")).toMatch(/ext-ix skipped: built for extension API 99/);
    expect(logs.join("\n")).toMatch(/ext-kartr failed to load: boom at import/);
  });

  it("the copy the Claude mod ships is what the sources build, and loads only once enabled", async () => {
    const r = await run(process.execPath, [join(REPO, "packages/ext-ix/scripts/bundle.mjs"), "--check"]);
    expect(r.stdout).toMatch(/matches a fresh build/);
    const pluginExt = join(REPO, "mods/claude/peer2peer/ext");
    expect((await loadExtensions({ env: { P2P_EXTENSION_PATH: pluginExt }, selfUrl: nowhere() })).list()).toEqual([]);
    const reg = await loadExtensions({ env: { P2P_EXTENSION_PATH: pluginExt, P2P_EXTENSIONS: "ix" }, selfUrl: nowhere() });
    expect(reg.list()[0]?.from).toMatch(/mods\/claude\/peer2peer\/ext\/node_modules\/@peer2peer\/ext-ix\/index\.mjs$/);
    const out = reg.get("ix")!.receive!({ kind: "x:ix.note", v: 1, body: { tag: "note", text: "hi" }, fallback: "a: f", from: { userId: "u", address: "a@x", self: false }, session: { own: "u", sid: "s", ref: "abcdef" } });
    expect(out.ok).toBe(true);
  });

  it("L4: the mod's bin/p2p.mjs and its ext-ix copy inline the same core, today's", async () => {
    const fp = (await import(pathToFileURL(join(REPO, "scripts/core-fingerprint.mjs")).href)) as {
      coreFingerprint: (repo: string) => { version: string; hash: string };
      coreLine: (fp: { version: string; hash: string }) => string;
      bundledCoreLine: (file: string) => string | undefined;
    };
    const want = fp.coreLine(fp.coreFingerprint(REPO));
    expect(fp.bundledCoreLine(join(REPO, "mods/claude/peer2peer/bin/p2p.mjs"))).toBe(want);
    expect(fp.bundledCoreLine(join(REPO, "mods/claude/peer2peer/ext/node_modules/@peer2peer/ext-ix/index.mjs"))).toBe(want);
  });

  it("renders defensively: a throwing or oversized receive falls back", () => {
    const base = { api: 1, ns: "ix", name: "t", version: "0" };
    const input = { kind: "x:ix.note" as const, v: 1, body: {}, fallback: "a: f", from: { userId: "u", address: "a", self: false }, session: { own: "u", sid: "s", ref: "abcdef" } };
    const reg = (receive: P2PExtension["receive"]) => new ExtensionRegistry([{ ext: { ...base, receive }, from: "t" }]);
    expect(renderExtension(reg(() => { throw new Error("nope"); }), input)).toEqual({ extError: "t failed: nope" });
    expect(renderExtension(reg(() => ({ ok: true, rendered: { digest: "x".repeat(4000), more: Array(10).fill("y".repeat(4000)) } })), input).extError).toMatch(/too large/);
    const ok = renderExtension(reg(() => ({ ok: true, rendered: { digest: "a‮b <c>", __proto__x: 1 }, keep: { k: 1 } })), input);
    expect(ok).toEqual({ rendered: { digest: "ab c" }, kept: { v: 1, body: { k: 1 } } });
    expect(renderExtension(new ExtensionRegistry(), input)).toEqual({});
  });
});
