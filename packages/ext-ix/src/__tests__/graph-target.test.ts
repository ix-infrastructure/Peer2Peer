// Copyright 2026 Ix Infrastructure Inc.
//
// ext-ix takes the Ix endpoint (and any token) only from p2p's graph-target chokepoint
// (ExtContext.graphTarget, packages/p2p/src/projects.ts), adversarially: a Pro-like login in the
// environment (IX_ENDPOINT / IX_PAT pointing at the cloud) never reaches `ix`; a host's target is
// checked again (a cloud URL named "local" is refused); a failing or missing chokepoint is local;
// env injection (NODE_OPTIONS, P2P_PERSON_TOKEN, proxies) doesn't pass; and the commands that can
// reach Ix Pro's cloud whatever IX_ENDPOINT says (`ix note`, `ix map`) are refused for a local target.

import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { ExtContext } from "@peer2peer/cli";
import { runner } from "../extension.js";
import { checkedTarget, DEFAULT_IX_ENDPOINT, guardRunner, ixEnv, ixRunner, localTarget, refuseForTarget, type IxRunner } from "../ix.js";

const CLOUD = "https://prod.cloud.ix-infra.com";
const PRO_LOGIN = { IX_ENDPOINT: CLOUD, IX_PAT: "kpat_abcdefghijkl", IX_ORG: "acme", IX_PUSH_ENDPOINT: CLOUD, IX_PUSH_TOKEN: "push", IX_AUTO_MAP_CLOUD: "1", IX_OAUTH_CLIENT_SECRET: "s" };

let dir: string;
let bin: string;
let seenFile: string;

/** A fake `ix` that records the environment it was given. */
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "ext-ix-target-"));
  bin = join(dir, "ix");
  seenFile = join(dir, "seen.json");
  writeFileSync(bin, `#!/usr/bin/env node\nrequire("node:fs").writeFileSync(${JSON.stringify(seenFile)}, JSON.stringify({ argv: process.argv.slice(2), env: process.env }));\nprocess.stdout.write("{}");\n`);
  chmodSync(bin, 0o755);
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const seen = (): { argv: string[]; env: Record<string, string> } => JSON.parse(readFileSync(seenFile, "utf8"));
const ixKeys = (env: Record<string, string>) => Object.keys(env).filter((k) => /^IX_/i.test(k)).sort();

/** The smallest ExtContext a runner needs. */
function ctx(env: Record<string, string | undefined>, graphTarget?: ExtContext["graphTarget"]): ExtContext {
  return { env, cwd: dir, ...(graphTarget ? { graphTarget } : {}) } as unknown as ExtContext;
}

describe("targets are checked again in ext-ix", () => {
  it("a local target must be loopback; a shared one https off this machine; anything else is the default local", () => {
    expect(checkedTarget({ kind: "local", endpoint: "http://127.0.0.1:9000/" })).toEqual({ kind: "local", endpoint: "http://127.0.0.1:9000" });
    for (const bad of [{ kind: "local", endpoint: CLOUD }, { kind: "local", endpoint: "http://localhost@evil.example" }, { kind: "shared", circle: "c", endpoint: "http://graph.example" }, { kind: "shared", circle: "c", endpoint: "https://localhost:1" }, { kind: "cloud", endpoint: CLOUD }, null, "local", 7]) {
      expect(checkedTarget(bad), JSON.stringify(bad)).toEqual({ kind: "local", endpoint: DEFAULT_IX_ENDPOINT });
    }
    expect(checkedTarget({ kind: "shared", circle: "c1", endpoint: "https://graph.example/", token: "tok" })).toEqual({ kind: "shared", circle: "c1", endpoint: "https://graph.example", token: "tok" });
    expect(localTarget({ IX_ENDPOINT: CLOUD })).toEqual({ kind: "local", endpoint: DEFAULT_IX_ENDPOINT });
    expect(localTarget({ IX_ENDPOINT: "http://localhost:9999" })).toEqual({ kind: "local", endpoint: "http://localhost:9999" });
  });

  it("ixEnv: an allowlist plus the pinned endpoint; a shared target's token only from the target", () => {
    const env = ixEnv({ PATH: "/bin", HOME: "/h", ...PRO_LOGIN, IX_HOME: "/ixh", IX_TOKEN: "lt", NODE_OPTIONS: "--require /evil.js", P2P_PERSON_TOKEN: "secret", HTTPS_PROXY: "http://proxy", DYLD_INSERT_LIBRARIES: "/x" }, { kind: "local", endpoint: DEFAULT_IX_ENDPOINT });
    expect(env).toEqual({ PATH: "/bin", HOME: "/h", IX_HOME: "/ixh", IX_TOKEN: "lt", IX_ENDPOINT: DEFAULT_IX_ENDPOINT, IX_MAP_BACKGROUND_REFRESH: "0", IX_NO_UPDATE_CHECK: "1" });
    const shared = ixEnv({ PATH: "/bin", IX_PAT: "kpat_from_shell" }, { kind: "shared", circle: "c1", endpoint: "https://graph.example", token: "kpat_from_target" });
    expect(shared).toMatchObject({ IX_ENDPOINT: "https://graph.example", IX_PAT: "kpat_from_target" });
    expect(ixEnv({ IX_PAT: "kpat_from_shell" }, { kind: "shared", circle: "c1", endpoint: "https://graph.example" }).IX_PAT).toBeUndefined();
  });

  it("commands that can reach Ix Pro's cloud are refused for a local target; reads pass", async () => {
    const t = { kind: "local" as const, endpoint: DEFAULT_IX_ENDPOINT, why: "secret is private" };
    expect(refuseForTarget(["note", "--json", "show", "n1"], t)).toMatchObject({ code: "graph_target", message: expect.stringMatching(/local only \(secret is private\)/) });
    for (const c of ["note", "map", "login", "org", "memory", "session", "agent", "workspace", "-c", ""]) expect(refuseForTarget([c], t), c).toBeDefined();
    for (const c of ["--version", "impact", "around", "overview", "inventory", "context", "subsystems", "status"]) expect(refuseForTarget([c], t), c).toBeUndefined();
    const calls: string[][] = [];
    const inner: IxRunner = { run: async (argv) => (calls.push([...argv]), { code: 0, stdout: "{}", stderr: "" }) };
    const g = guardRunner(inner, async () => t);
    await expect(g.run(["note", "--tag=note", "--json"], { stdin: "private text" })).rejects.toMatchObject({ code: "graph_target" });
    await g.run(["impact", "x", "--format", "json"]);
    expect(calls).toEqual([["impact", "x", "--format", "json"]]);
  });
});

describe.skipIf(process.platform === "win32")("a real `ix` child sees only the chokepoint's endpoint", () => {
  it("a private session with a Pro-like login in the environment: only the local endpoint, no IX_PAT", async () => {
    const saved = { ...process.env };
    Object.assign(process.env, PRO_LOGIN, { NODE_OPTIONS: "", P2P_PERSON_TOKEN: "secret" });
    try {
      const c = ctx({ IX_BIN: bin, ...PRO_LOGIN }, async () => ({ kind: "local", endpoint: DEFAULT_IX_ENDPOINT, why: "session s1 is private: secret is private" }));
      await runner(c, {}, "s1").run(["status", "--format", "json"]);
      const s = seen();
      expect(s.env.IX_ENDPOINT).toBe(DEFAULT_IX_ENDPOINT);
      expect(ixKeys(s.env)).toEqual(["IX_ENDPOINT", "IX_MAP_BACKGROUND_REFRESH", "IX_NO_UPDATE_CHECK"]);
      expect(JSON.stringify(s.env)).not.toContain(CLOUD);
      expect(s.env.P2P_PERSON_TOKEN).toBeUndefined();
      // And `ix note` (Ix Pro's cloud memory) never runs for it.
      await expect(runner(c, {}, "s1").run(["note", "--json", "show", "n1"])).rejects.toMatchObject({ code: "graph_target" });
      expect(seen().argv[0]).toBe("status");
    } finally {
      for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
      Object.assign(process.env, saved);
    }
  });

  it("a host that widens the target (a cloud URL as `local`), one that throws, and one from before graph targets: all local", async () => {
    for (const graphTarget of [async () => ({ kind: "local" as const, endpoint: CLOUD, why: "" }), async () => ({ kind: "cloud", endpoint: CLOUD }) as never, async () => Promise.reject(new Error("boom")), undefined]) {
      await runner(ctx({ IX_BIN: bin, IX_ENDPOINT: CLOUD, IX_PAT: "kpat_abcdefghijkl" }, graphTarget), {}).run(["status"]);
      const s = seen();
      expect(s.env.IX_ENDPOINT).toBe(DEFAULT_IX_ENDPOINT);
      expect(s.env.IX_PAT).toBeUndefined();
    }
  });

  it("the session id goes to the chokepoint; an agent's env can't pick the endpoint", async () => {
    const asked: unknown[] = [];
    await runner(ctx({ IX_BIN: bin, IX_ENDPOINT: "https://attacker.example" }, async (o) => (asked.push(o), { kind: "local", endpoint: "http://127.0.0.1:8123", why: "" })), {}, "sess-9").run(["impact", "x"]);
    expect(asked).toEqual([{ sid: "sess-9" }]);
    expect(seen().env.IX_ENDPOINT).toBe("http://127.0.0.1:8123");
    // A library caller (the Claude mod's conflicts) with no target: local, a loopback IX_ENDPOINT honoured, a cloud one not.
    await ixRunner({ env: { IX_BIN: bin, IX_ENDPOINT: CLOUD } }).run(["status"]);
    expect(seen().env.IX_ENDPOINT).toBe(DEFAULT_IX_ENDPOINT);
  });
});
