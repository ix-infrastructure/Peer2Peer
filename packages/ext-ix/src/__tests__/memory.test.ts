// Copyright 2026 Ix Infrastructure Inc.
//
// Graph memory (SPEC §10), adversarially: the memory writer and the `ix note` / `ix session` calls
// ext-ix now makes go to the LOCAL graph only, through the OSS commands only.
//   - Only exact argv forms pass the guard (no positional text, no extra or repeated flag, no other
//     subcommand), and none of them against a shared target.
//   - Which `ix note` answers is read from `ix --help` (the capability), never by trying a write:
//     Ix Pro's (the cloud org) and none (an Ix from before #916) are refused before any write.
//   - With a Pro-like login present (config.yaml's cloud `endpoint`, IX_ENDPOINT / IX_PAT in the
//     environment), a real `ix` child still only ever sees the pinned local endpoint.
//   - A write that doesn't confirm the local backend on stderr stops the batch (ix_unconfirmed).

import { chmodSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import type { ExtContext } from "@peer2peer/cli";
import { createIxExtension, runner } from "../extension.js";
import { confirmsLocalWrite, DEFAULT_IX_ENDPOINT, guardRunner, memoryCall, parseMemorySupport, refuseForTarget, type IxRunner } from "../ix.js";
import { memoryActor, memoryPurpose, memorySessionName, memoryText } from "../memory.js";
import { cleanupTmp, fakeIx, OSS_HELP, PRO_HELP, tmp } from "./harness.js";

afterAll(() => cleanupTmp());

const CLOUD = "https://prod.cloud.ix-infra.com";
const PRO_ENV = { IX_ENDPOINT: CLOUD, IX_PAT: "kpat_abcdefghijkl", IX_ORG: "acme", IX_PUSH_ENDPOINT: CLOUD, NODE_OPTIONS: "--require /evil.js", P2P_PERSON_TOKEN: "secret" };
const PRO_CONFIG = `endpoint: "${CLOUD}"\nactive: acme\ncluster: prod\norgs:\n  acme:\n    jwt: "eyJ.fake.jwt"\n`;
const local = { kind: "local" as const, endpoint: DEFAULT_IX_ENDPOINT, why: "x is private" };

describe("memory calls: only exact forms, to a local target only", () => {
  it("the forms ext-ix makes pass", () => {
    expect(memoryCall(["--help"])).toBe("help");
    expect(memoryCall(["note", "--json", "show", "n-1"])).toBe("note-show");
    expect(memoryCall(["note", "--tag=note", "--json"])).toBe("note-create");
    expect(memoryCall(["note", "--tag=decision", "--session=sess-1", "--actor=p2p:alice@abcd-efgh", "--json"])).toBe("note-create");
    expect(memoryCall(["session", "--json", "create", "p2p-s1", "--purpose=Peer2Peer session x", "--actor=p2p", "--ttl=720"])).toBe("session-create");
  });

  it("anything else is no memory call (and is refused for a local target)", () => {
    const bad: string[][] = [
      ["--help", "note"],
      ["note"],
      ["note", "--json"], // no tag
      ["note", "secret text in argv", "--tag=note", "--json"], // positional text: never in argv
      ["note", "--tag=note", "--tag=decision", "--json"],
      ["note", "--tag=note", "--json", "--json"],
      ["note", "--tag=evil", "--json"],
      ["note", "--tag", "note", "--json"], // the split form is not ours
      ["note", "--tag=note", "--node=n1", "--json"],
      ["note", "--tag=note", "--format=json", "--json"],
      ["note", "--tag=note", "--session=-rf", "--json"],
      ["note", "--tag=note", "--session=a b", "--json"],
      ["note", "--tag=note", "--actor=root", "--json"],
      ["note", "--tag=note", "--actor=p2p:a b", "--json"],
      ["note", "ls", "--json"],
      ["note", "--json", "show", "-"], // `-` is "the last note": not an id
      ["note", "--json", "show", "--all"],
      ["note", "--json", "supersede", "n1"],
      ["note", "--json", "retract", "n1"],
      ["note", "show", "n1", "--json"],
      ["session", "--json", "delete", "p2p-s1", "--force"],
      ["session", "--json", "join", "p2p-s1", "--actor=p2p"],
      ["session", "--json", "pin", "p2p-s1", "n1"],
      ["session", "--json", "create", "s1", "--purpose=x", "--actor=p2p", "--ttl=720"], // not a p2p- name
      ["session", "--json", "create", "p2p-s1", "--purpose=a\nb", "--actor=p2p", "--ttl=720"],
      ["session", "--json", "create", "p2p-s1", "--purpose=a\u202eb", "--actor=p2p", "--ttl=720"],
      ["session", "--json", "create", "p2p-s1", `--purpose=${"x".repeat(201)}`, "--actor=p2p", "--ttl=720"],
      ["session", "--json", "create", "p2p-s1", "--purpose= padded", "--actor=p2p", "--ttl=720"],
      ["session", "--json", "create", "p2p-s1", "--purpose=x", "--actor=admin", "--ttl=720"],
      ["session", "--json", "create", "p2p-s1", "--purpose=x", "--actor=p2p", "--ttl=0"],
      ["session", "--json", "create", "p2p-s1", "--purpose=x", "--actor=p2p", "--ttl=99999"],
      ["session", "--json", "create", "p2p-s1", "--purpose=x", "--actor=p2p", "--ttl=720", "--extra"],
      ["session", "create", "p2p-s1", "--purpose=x", "--actor=p2p", "--ttl=720", "--json"],
    ];
    for (const argv of bad) {
      expect(memoryCall(argv), JSON.stringify(argv)).toBeUndefined();
      if (argv[0] !== "--help") expect(refuseForTarget(argv, local), JSON.stringify(argv)).toMatchObject({ code: "graph_target" });
    }
  });

  it("no memory call, of any form, goes to a shared target", () => {
    const shared = { kind: "shared" as const, circle: "c1", endpoint: "https://graph.example" };
    for (const argv of [["note", "--tag=note", "--json"], ["note", "--json", "show", "n1"], ["session", "--json", "create", "p2p-s1", "--purpose=x", "--actor=p2p", "--ttl=720"]]) {
      expect(refuseForTarget(argv, shared)).toMatchObject({ code: "graph_target", message: expect.stringMatching(/local graph only, never to a shared graph/) });
    }
  });
});

describe("which `ix note` answers: from `ix --help`, never by trying", () => {
  it("OSS (Memory:), Ix Pro (Pro:), or none", () => {
    expect(parseMemorySupport(OSS_HELP)).toBe("oss");
    expect(parseMemorySupport(PRO_HELP)).toBe("pro");
    expect(parseMemorySupport("Usage: ix\n\nSystem:\n  status   Check status\n")).toBe("none");
    // Colour codes don't matter.
    expect(parseMemorySupport(OSS_HELP.replace("Memory:", "\u001b[1mMemory:\u001b[22m"))).toBe("oss");
    // Pro wins over anything that also looks like the OSS section.
    expect(parseMemorySupport(`${OSS_HELP}\nPro:\n  note   x\n`)).toBe("pro");
    // Half a section, or "Memory:" that isn't a heading: none.
    expect(parseMemorySupport("Memory:\n  note [text]   Record a note\n")).toBe("none");
    expect(parseMemorySupport("  see Memory: note session\n")).toBe("none");
    expect(parseMemorySupport("Memory:\n\n  note [text]  x\n  session [actor] y\n")).toBe("none");
    expect(parseMemorySupport("")).toBe("none");
  });

  it("a write must confirm the pinned local backend on stderr", () => {
    expect(confirmsLocalWrite("ix: failed to load x\n→ local backend http://localhost:8090\n", "http://localhost:8090")).toBe(true);
    expect(confirmsLocalWrite("\u001b[2m→ local backend http://localhost:8090\u001b[22m", "http://localhost:8090")).toBe(true);
    for (const e of [`→ backend ${CLOUD}`, "→ local backend http://localhost:8091", "→ local backend http://localhost:8090.evil.example", "local backend http://localhost:8090", ""]) {
      expect(confirmsLocalWrite(e, "http://localhost:8090"), e).toBe(false);
    }
  });

  it("the guard asks once per guard, refuses Pro and an old Ix before the write, and runs reads as before", async () => {
    for (const [help, msg] of [[PRO_HELP, /Ix Pro is installed/], ["Usage: ix\n", /upgrade Ix/]] as const) {
      const calls: string[][] = [];
      const inner: IxRunner = { run: async (argv) => (calls.push([...argv]), { code: 0, stdout: argv[0] === "--help" ? help : "{}", stderr: "" }) };
      const g = guardRunner(inner, async () => local);
      await expect(g.run(["note", "--tag=note", "--json"], { stdin: "t" })).rejects.toMatchObject({ code: "graph_target", message: expect.stringMatching(msg) });
      await expect(g.run(["note", "--json", "show", "n1"])).rejects.toMatchObject({ code: "graph_target" });
      expect(calls).toEqual([["--help"]]);
    }
  });
});

/** An ExtContext for the memory writer, over a fake `ix` (real child processes). */
function memCtx(ix: ReturnType<typeof fakeIx>, o: { graphTarget?: ExtContext["graphTarget"]; address?: string; env?: Record<string, string> } = {}) {
  const store = new Map<string, unknown>();
  const ctx = {
    env: { ...ix.env(), IX_BIN: join(ix.bin, "ix"), ...(o.env ?? {}) },
    cwd: tmp("mem-cwd-"),
    graphTarget: o.graphTarget ?? (async () => ({ ...local })),
    kv: { get: async (k: string) => store.get(k), set: async (k: string, v: unknown) => void store.set(k, v) },
    self: async () => ({ userId: "p2p:u", address: o.address ?? "alice@abcd-efgh-ijkl-mnop" }),
    io: { err: () => {} },
    json: true,
    interactive: false,
  } as unknown as ExtContext;
  return { ctx, store };
}

const memory = createIxExtension().memory!;
const items = (at = Date.UTC(2026, 10, 9, 12)) => [
  { kind: "start" as const, at, label: "widgets", repo: "widgets", branch: "main" },
  { kind: "status" as const, at, summary: "Refactoring token rotation" },
  { kind: "files" as const, at, files: ["src/auth/token.ts", "../../etc/passwd", "/abs/x.ts", "src/a.ts"] },
  { kind: "end" as const, at },
];

describe.skipIf(process.platform === "win32")("the memory writer against a real `ix` child", () => {
  it("a Pro-like login present (config.yaml's cloud endpoint, IX_ENDPOINT and IX_PAT in the environment): the child only ever sees the pinned local endpoint", async () => {
    const ix = fakeIx();
    ix.set("help.txt", OSS_HELP);
    ix.set("config.yaml", PRO_CONFIG);
    const saved = { ...process.env };
    Object.assign(process.env, PRO_ENV);
    try {
      const { ctx, store } = memCtx(ix, { env: PRO_ENV });
      expect(await memory.available(ctx)).toEqual({ ok: true });
      const r = await memory.write(ctx, { sid: "s-1", items: items() });
      expect(r).toEqual({ written: 4 });
      // One session record, four notes, all at the local endpoint; text on stdin only.
      expect(ix.sessions()).toEqual([{ argv: ["session", "--json", "create", "p2p-s-1", "--purpose=Peer2Peer session widgets (repo widgets, branch main)", "--actor=p2p:alice@abcd-efgh-ijkl-mnop", "--ttl=720"], endpoint: DEFAULT_IX_ENDPOINT }]);
      const notes = ix.written();
      expect(notes.map((n) => n.endpoint)).toEqual(Array(4).fill(DEFAULT_IX_ENDPOINT));
      expect(notes.map((n) => n.argv)).toEqual(Array(4).fill(["note", "--tag=note", "--session=sess-s-1", "--actor=p2p:alice@abcd-efgh-ijkl-mnop", "--json"]));
      expect(notes.map((n) => n.text)).toEqual([
        "Session started 2026-11-09T12:00:00.000Z: widgets (repo widgets, branch main).",
        "Status (2026-11-09T12:00:00.000Z): Refactoring token rotation",
        "Edited (2026-11-09T12:00:00.000Z): src/auth/token.ts, src/a.ts",
        "Session ended 2026-11-09T12:00:00.000Z.",
      ]);
      // Every child (help probes included) saw the pinned endpoint and no Pro variable.
      for (const c of ix.calls()) expect(c.argv.join(" ")).not.toContain(CLOUD);
      // The Ix session id is remembered: the next batch writes no second record.
      expect(store.get("memory")).toMatchObject({ sessions: { "s-1": { id: "sess-s-1" } } });
      await memory.write(ctx, { sid: "s-1", items: [{ kind: "status", at: 1, summary: "next" }] });
      expect(ix.sessions()).toHaveLength(1);
    } finally {
      for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
      Object.assign(process.env, saved);
    }
  });

  it("the child's environment: the pinned endpoint and nothing of the login", async () => {
    const ix = fakeIx();
    const seen = join(ix.dir, "env.json");
    // A wrapper that records the env, then is the fake.
    const wrap = join(ix.bin, "ix-env");
    writeFileSync(wrap, `#!/usr/bin/env node\nrequire("node:fs").appendFileSync(${JSON.stringify(seen)}, JSON.stringify(process.env) + "\\n");\nrequire(${JSON.stringify(join(ix.bin, "ix"))});\n`);
    chmodSync(wrap, 0o755);
    ix.set("help.txt", OSS_HELP);
    ix.set("config.yaml", PRO_CONFIG);
    const { ctx } = memCtx(ix, { env: { ...PRO_ENV, IX_BIN: wrap } });
    expect((await memory.write(ctx, { sid: "s-2", items: [{ kind: "status", at: 1, summary: "x" }] })).written).toBe(1);
    const envs = (await import("node:fs")).readFileSync(seen, "utf8").trim().split("\n").map((l) => JSON.parse(l) as Record<string, string>);
    expect(envs.length).toBeGreaterThanOrEqual(3); // --version, --help, session create, note
    for (const e of envs) {
      expect(e.IX_ENDPOINT).toBe(DEFAULT_IX_ENDPOINT);
      expect(Object.keys(e).filter((k) => /^IX_/.test(k)).sort()).toEqual(["IX_ENDPOINT", "IX_HOME", "IX_MAP_BACKGROUND_REFRESH", "IX_NO_UPDATE_CHECK"]);
      expect(e.NODE_OPTIONS).toBeUndefined();
      expect(e.P2P_PERSON_TOKEN).toBeUndefined();
      expect(JSON.stringify(e)).not.toContain(CLOUD);
    }
  });

  it("`--ix-note` (ix note --json show): read from the local graph with the OSS command, refused with Ix Pro", async () => {
    const ix = fakeIx();
    ix.set("note.json", { id: "n1", text: "local note", tag: "decision", at: "2026-11-09T00:00:00Z" });
    ix.set("config.yaml", PRO_CONFIG);
    const { ctx } = memCtx(ix, { env: PRO_ENV });
    ix.set("help.txt", PRO_HELP);
    await expect(runner(ctx, {}, "s").run(["note", "--json", "show", "n1"])).rejects.toMatchObject({ code: "graph_target", message: expect.stringMatching(/Ix Pro/) });
    expect(ix.calls().map((c) => c.argv[0])).toEqual(["--help"]);
    ix.set("help.txt", OSS_HELP);
    const r = await runner(ctx, {}, "s").run(["note", "--json", "show", "n1"]);
    expect(JSON.parse(r.stdout)).toMatchObject({ text: "local note" });
    expect(ix.calls().map((c) => c.argv)).toEqual([["--help"], ["--help"], ["note", "--json", "show", "n1"]]);
  });

  it("Ix Pro installed: unavailable (ix_pro), and nothing but the help probe runs", async () => {
    const ix = fakeIx();
    ix.set("help.txt", PRO_HELP);
    const { ctx } = memCtx(ix);
    expect(await memory.available(ctx)).toMatchObject({ ok: false, reason: "ix_pro", message: expect.stringMatching(/cloud org/) });
    const r = await memory.write(ctx, { sid: "s-3", items: items() });
    expect(r).toMatchObject({ written: 0, unavailable: { reason: "ix_pro" }, failed: [{ reason: "graph_target", n: 4 }] });
    expect(ix.written()).toHaveLength(0);
    expect(ix.sessions()).toHaveLength(0);
    expect(ix.calls().every((c) => c.argv[0] === "--help" || c.argv[0] === "--version")).toBe(true);
  });

  it("an Ix from before #916: unavailable (ix_upgrade, says upgrade Ix); no Ix: ix_missing", async () => {
    const ix = fakeIx();
    const { ctx } = memCtx(ix);
    expect(await memory.available(ctx)).toMatchObject({ ok: false, reason: "ix_upgrade", message: expect.stringMatching(/upgrade Ix/) });
    expect(await memory.write(ctx, { sid: "s-4", items: items() })).toMatchObject({ written: 0, unavailable: { reason: "ix_upgrade" } });
    expect(ix.written()).toHaveLength(0);
    const none = memCtx(ix, { env: { IX_BIN: join(ix.dir, "no-such-ix"), PATH: "/nonexistent" } });
    expect(await memory.available(none.ctx)).toMatchObject({ ok: false, reason: "ix_missing" });
  });

  it("a shared target (or a host that throws then widens): refused before any `ix` runs; a cloud URL called local is the default local", async () => {
    const ix = fakeIx();
    ix.set("help.txt", OSS_HELP);
    const shared = memCtx(ix, { graphTarget: async () => ({ kind: "shared", circle: "c1", endpoint: "https://graph.example" }) });
    expect(await memory.write(shared.ctx, { sid: "s-5", items: items() })).toEqual({ written: 0, failed: [{ reason: "not_local", n: 4, message: expect.any(String) }] });
    expect(ix.calls()).toHaveLength(0);
    // A host naming a cloud URL "local" is checked again: the default local endpoint.
    const widened = memCtx(ix, { graphTarget: async () => ({ kind: "local", endpoint: CLOUD, why: "" }) });
    expect((await memory.write(widened.ctx, { sid: "s-6", items: [{ kind: "end", at: 1 }] })).written).toBe(1);
    expect(ix.written().map((n) => n.endpoint)).toEqual([DEFAULT_IX_ENDPOINT]);
    const throwing = memCtx(ix, { graphTarget: async () => Promise.reject(new Error("boom")) });
    expect((await memory.write(throwing.ctx, { sid: "s-7", items: [{ kind: "end", at: 1 }] })).written).toBe(1);
    expect(ix.written().at(-1)!.endpoint).toBe(DEFAULT_IX_ENDPOINT);
  });

  it("a per-call target that turns shared mid-batch: the guard refuses that call", async () => {
    const ix = fakeIx();
    ix.set("help.txt", OSS_HELP);
    let n = 0;
    // The batch check sees local; every later per-call target is shared.
    const { ctx } = memCtx(ix, { graphTarget: async () => (n++ === 0 ? { ...local } : { kind: "shared", circle: "c1", endpoint: "https://graph.example" }) });
    const r = await memory.write(ctx, { sid: "s-8", items: items() });
    expect(r.written).toBe(0);
    expect(r.unavailable).toBeDefined();
    expect(ix.written()).toHaveLength(0);
    expect(ix.sessions()).toHaveLength(0);
  });

  it("a write that doesn't confirm the local backend stops the batch (ix_unconfirmed)", async () => {
    const ix = fakeIx();
    ix.set("help.txt", OSS_HELP);
    ix.set("stderr.txt", `→ backend ${CLOUD}\n`);
    const { ctx } = memCtx(ix);
    const r = await memory.write(ctx, { sid: "s-9", items: items() });
    expect(r).toMatchObject({ written: 0, unavailable: { reason: "ix_unconfirmed" }, failed: [{ reason: "ix_unconfirmed", n: 4 }] });
    // One write was attempted (the session record), then nothing more.
    expect(ix.sessions()).toHaveLength(1);
    expect(ix.written()).toHaveLength(0);
    // The local marker for a different endpoint doesn't count either.
    const ix2 = fakeIx();
    ix2.set("help.txt", OSS_HELP);
    ix2.set("stderr.txt", "→ local backend http://127.0.0.1:9\n");
    expect((await memory.write(memCtx(ix2).ctx, { sid: "s-10", items: items() })).unavailable).toMatchObject({ reason: "ix_unconfirmed" });
  });
});

describe("what memory writes", () => {
  it("one-line, bounded text; files repo-relative only; names and actors safe", () => {
    expect(memoryText({ kind: "status", at: 0, summary: "a\nb\u202ec\u0007d" })).toMatch(/: a b c d$/);
    expect(memoryText({ kind: "status", at: 0, summary: "  " })).toBeUndefined();
    expect(memoryText({ kind: "status", at: 0, summary: "x".repeat(1000) })!.length).toBeLessThan(360);
    expect(memoryText({ kind: "files", at: 0, files: ["../x", "/etc/passwd", "a/./b", "ok.ts", "ok.ts"] })).toMatch(/: ok\.ts$/);
    expect(memoryText({ kind: "files", at: 0, files: ["../x"] })).toBeUndefined();
    expect(memoryText({ kind: "files", at: 0, files: Array.from({ length: 60 }, (_, i) => `f${i}.ts`) })).toMatch(/and 10 more$/);
    expect(memoryPurpose({ label: "l\nx", repo: "r", branch: "b" })).toBe("Peer2Peer session l x (repo r, branch b)");
    expect(memoryPurpose({ label: "x".repeat(500) }).length).toBeLessThanOrEqual(200);
    expect(memorySessionName("abc-123")).toBe("p2p-abc-123");
    expect(memorySessionName(".hidden")).toMatch(/^p2p-[0-9a-f]{32}$/);
    expect(memorySessionName("x".repeat(128))).toMatch(/^p2p-[0-9a-f]{32}$/);
    expect(memoryActor("alice@abcd-efgh")).toBe("p2p:alice@abcd-efgh");
    expect(memoryActor("evil name; rm -rf")).toBe("p2p");
    // Every session create argv the writer can build is one the guard accepts.
    for (const label of ["a", "x".repeat(500), "  sp  ", "\u202e", ""]) {
      const argv = ["session", "--json", "create", memorySessionName("s"), `--purpose=${memoryPurpose({ label, repo: "r\nr", branch: "b" })}`, `--actor=${memoryActor("bad name")}`, "--ttl=720"];
      expect(memoryCall(argv), label).toBe("session-create");
    }
  });
});
