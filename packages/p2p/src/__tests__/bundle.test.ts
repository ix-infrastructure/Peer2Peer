// Copyright 2026 Ix Infrastructure Inc.
//
// The committed single-file CLI (mods/claude/peer2peer/bin/p2p.mjs): it is
// exactly what the sources build, and it works on its own with `node`,
// reading the defaults.json beside it.

import { execFile } from "node:child_process";
import { chmodSync, copyFileSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { currentPersonToken, personTokenFor, startRelay, type TestRelay } from "./harness.js";

const run = promisify(execFile);
const pkg = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const BUNDLE = resolve(pkg, "../../mods/claude/peer2peer/bin/p2p.mjs");
const R = "wss://bundle.test/v3";
let relay: TestRelay;
const dirs: string[] = [];

beforeAll(async () => {
  relay = await startRelay(R);
});
afterAll(async () => {
  await relay?.close();
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const tmp = (p: string) => {
  const d = mkdtempSync(join(tmpdir(), p));
  dirs.push(d);
  return d;
};

describe("the bundled CLI", () => {
  it("is byte-for-byte what a fresh build produces", async () => {
    const r = await run(process.execPath, [join(pkg, "scripts/bundle.mjs"), "--check"], { cwd: pkg });
    expect(r.stdout).toMatch(/matches a fresh build/);
  }, 60_000);

  it("postbuild makes the p2p entry point executable (tsc writes 0644)", async () => {
    const pkgJson = JSON.parse(readFileSync(join(pkg, "package.json"), "utf8")) as { scripts: Record<string, string>; bin: Record<string, string> };
    expect(pkgJson.scripts.postbuild).toBe("node scripts/postbuild.mjs");
    expect(pkgJson.bin.p2p).toBe("./dist/bin.js");
    const f = join(tmp("p2p-postbuild-"), "bin.js");
    writeFileSync(f, "#!/usr/bin/env node\n", { mode: 0o644 });
    chmodSync(f, 0o644);
    await run(process.execPath, [join(pkg, "scripts/postbuild.mjs"), f]);
    if (process.platform !== "win32") expect(statSync(f).mode & 0o777).toBe(0o755);
  });

  it("ships an empty defaults.json beside it", () => {
    expect(JSON.parse(readFileSync(join(dirname(BUNDLE), "defaults.json"), "utf8"))).toEqual({ defaultRelays: [] });
  });

  it("runs alone with node: setup from its defaults.json, invite, join", async () => {
    const bin = tmp("p2p-bin-");
    copyFileSync(BUNDLE, join(bin, "p2p.mjs"));
    writeFileSync(join(bin, "defaults.json"), JSON.stringify({ defaultRelays: [R] }));
    // The person token (projects.ts): this bundle runs in a child process, whose ancestry may hold an agent.
    // Read again on every run: the CLI replaces person.key when an identity is created here.
    const seeded = new Set<string>();
    const tokenOf = (home: string) => (seeded.has(home) || (seeded.add(home), personTokenFor(home)), currentPersonToken(home));
    const env = (home: string) => ({
      PATH: process.env.PATH ?? "",
      P2P_HOME: home,
      P2P_PERSON_TOKEN: tokenOf(home),
      P2P_RELAY_TRANSPORT: JSON.stringify({ [R]: `ws://127.0.0.1:${relay.port}/v3` }),
      P2P_DRAIN_QUIET_MS: "250",
      P2P_DRAIN_MAX_MS: "3000",
      P2P_DOC_REFRESH_SEC: "0",
    });
    const p2p = async (home: string, args: string[]) => JSON.parse((await run(process.execPath, [join(bin, "p2p.mjs"), ...args], { env: env(home) })).stdout.trim().split("\n").at(-1)!);
    const a = tmp("p2p-a-");
    const b = tmp("p2p-b-");
    expect((await run(process.execPath, [join(bin, "p2p.mjs"), "--version"], { env: env(a) })).stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
    expect(await p2p(a, ["setup", "--name", "ann", "--no-backup", "--json"])).toMatchObject({ created: true, relays: [R] });
    const inv = await p2p(a, ["invite", "--json", "--", "ben"]);
    expect(inv.code).toMatch(/^bundle\.test\//);
    const j = await p2p(b, ["join", "--confirmed", "--json", "--wait", "0", "--name", "ben", "--", inv.code]);
    expect(j.friend.address).toMatch(/^ann@/);
    const list = await p2p(a, ["invites", "--json"]);
    expect(list.invites[0]).toMatchObject({ status: "redeemed", label: "ben" });
  }, 60_000);
});
