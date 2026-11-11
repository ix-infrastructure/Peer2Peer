// Copyright 2026 Ix Infrastructure Inc.
//
// Graph memory end to end (SPEC §10): the real `p2p` with ext-ix loaded the ordinary way, a fake
// `ix` on PATH, and a local Ix endpoint whose port this test process holds (the listener check,
// listener.ts, passes for it). A session in a shared project posts statuses (`p2p status`, the hook
// path: no Ix runs there); its `p2p watch` writes the session's record and edited files into the
// LOCAL graph in the background. With a Pro-like login present (config.yaml's cloud endpoint,
// IX_ENDPOINT and IX_PAT in the environment) every write still lands at the pinned local endpoint. A
// session in a private project is never recorded. With Ix Pro installed, or an Ix without the OSS
// `ix note`, nothing is written, and `p2p doctor` says why.

import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { cleanupTmp, extensionDir, fakeIx, OSS_HELP, ownedEndpoint, PRO_HELP, setIxEndpoint, startRelay, tmp, User, type FakeIx, type TestRelay } from "./harness.js";

const R = "wss://relay-memory-e2e.test/v3";
const CLOUD = "https://prod.cloud.ix-infra.com";

let relay: TestRelay;
let owned: Awaited<ReturnType<typeof ownedEndpoint>>;

beforeAll(async () => {
  relay = await startRelay(R);
  owned = await ownedEndpoint();
  if (!owned.observable && process.env.CI) throw new Error("the listener check can't see this test's own listener in CI");
});
afterAll(async () => {
  await relay?.close().catch(() => {});
  await owned?.close();
  cleanupTmp();
});

/** A person with the Ix extension, the owned local endpoint, and this folder's project shared with a circle of theirs. */
async function person(name: string, ix: FakeIx, extra: Record<string, string> = {}): Promise<User> {
  const u = new User(name, { [R]: `ws://127.0.0.1:${relay.port}/v3` }, { P2P_EXTENSION_PATH: extensionDir(), P2P_EXTENSIONS: "ix", P2P_IX_MEMORY_TICK_MS: "1000", ...ix.env(), ...extra });
  u.autoShareProject = false;
  await u.ok(["init", "--name", name, "--relay", R, "--yes"]);
  setIxEndpoint(u.home, owned.endpoint);
  const cid = (await u.ok(["circle", "create", "team"])).cid;
  await u.ok(["project", "share", cid, "--dir", process.cwd()]);
  return u;
}

const PREFIX = "Recorded by Peer2Peer \\(agent-generated, untrusted\\)\\n";

describe.skipIf(process.platform === "win32")("graph memory: p2p watch writes the session into the local graph", () => {
  it("OSS `ix note`, a shared project, a Pro-like login present: the record and edited files, at the local endpoint only; status runs no Ix; a private project's session never", async () => {
    const ix = fakeIx();
    ix.set("help.txt", OSS_HELP);
    ix.set("config.yaml", `endpoint: "${CLOUD}"\nactive: acme\ncluster: prod\n`);
    const dave = await person("dave", ix, { IX_ENDPOINT: CLOUD, IX_PAT: "kpat_abcdefghijkl", IX_ORG: "acme" });
    const before = ix.calls().length;
    await dave.ok(["status", "--session", "ds1", "--state", "busy", "--label", "widgets", "--repo", "widgets", "--branch", "main", "--file", "src/auth/token.ts"]);
    // A second session that also works in a private folder: its ceiling is private.
    const secret = join(tmp("secret-"), "repo");
    mkdirSync(secret, { recursive: true });
    await dave.ok(["status", "--session", "dpriv", "--state", "busy", "--label", "secret", "--file", "plans.md", "--project-dir", secret]);
    // The hook path ran no Ix at all.
    expect(ix.calls().length).toBe(before);
    await dave.watch("ds1", 3500);
    if (!owned.observable) {
      // This environment hides the socket tables: the check fails closed, nothing is written.
      expect(ix.written()).toEqual([]);
      expect(ix.sessions()).toEqual([]);
      expect(JSON.stringify((await dave.run(["doctor"])).json)).toMatch(/isn't one Peer2Peer can trust/);
      return;
    }
    const sessions = ix.sessions();
    expect(sessions).toHaveLength(1);
    expect(sessions[0].argv).toEqual(["session", "--json", "create", "p2p-ds1", "--purpose=Peer2Peer session widgets (repo widgets, branch main)", expect.stringMatching(/^--actor=p2p:dave@/), "--ttl=720"]);
    const notes = ix.written();
    expect(notes.map((n) => n.text)).toEqual([expect.stringMatching(new RegExp(`^${PREFIX}Session started .*: widgets \\(repo widgets, branch main\\)\\.$`)), expect.stringMatching(new RegExp(`^${PREFIX}Edited \\(.*\\): src/auth/token\\.ts$`))]);
    expect(notes.every((n) => n.argv.includes("--tag=finding"))).toBe(true);
    for (const w of [...sessions, ...notes]) expect(w.endpoint).toBe(owned.endpoint);
    expect(JSON.stringify(ix.calls())).not.toContain(CLOUD);
    // The private session's context is nowhere.
    expect(JSON.stringify(ix.calls())).not.toMatch(/dpriv|plans\.md|secret/);
    // Another status with a new file: one more note, nothing repeated.
    await dave.ok(["status", "--session", "ds1", "--state", "idle", "--file", "src/auth/token.ts", "--file", "src/api/handler.ts"]);
    await dave.watch("ds1", 2500);
    expect(ix.written().map((n) => n.text).slice(2)).toEqual([expect.stringMatching(/Edited \(.*\): src\/api\/handler\.ts$/)]);
    expect(ix.sessions()).toHaveLength(1);
    // The doctor reports it.
    const doc = await dave.run(["doctor"]);
    expect(JSON.stringify(doc.json)).toMatch(/Ix graph memory.*on: .*local graph only \(http:\/\/127\.0\.0\.1:\d+\); 3 written, 0 queued/);
  }, 60_000);

  it("Ix Pro installed, or an Ix without a local `ix note`: nothing is written, and the doctor says why", async () => {
    for (const [help, why] of [[PRO_HELP, /Ix Pro is installed/], [undefined, /no local `ix note`/]] as const) {
      const ix = fakeIx();
      if (help) ix.set("help.txt", help);
      const erin = await person(`erin${help ? "p" : "o"}`, ix);
      await erin.ok(["status", "--session", "es1", "--state", "busy", "--file", "src/a.ts"]);
      await erin.watch("es1", 2500);
      expect(ix.written()).toEqual([]);
      expect(ix.sessions()).toEqual([]);
      expect(ix.calls().every((c) => c.argv.length === 1 && ["--help", "--version"].includes(c.argv[0]))).toBe(true);
      const doc = await erin.run(["doctor"]);
      expect(JSON.stringify(doc.json)).toMatch(why);
    }
  }, 60_000);

  it("turned off (P2P_IX_MEMORY=0): no Ix runs from watch at all", async () => {
    const ix = fakeIx();
    ix.set("help.txt", OSS_HELP);
    const fay = await person("fay", ix, { P2P_IX_MEMORY: "0" });
    await fay.ok(["status", "--session", "fs1", "--state", "busy", "--file", "src/a.ts"]);
    await fay.watch("fs1", 2500);
    expect(ix.calls()).toEqual([]);
  }, 60_000);
});
