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
import { createServer, type Server } from "node:net";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { ExtContext } from "@peer2peer/cli";
import { createIxExtension, runner } from "../extension.js";
import { checkedTarget, confirmsLocalWrite, DEFAULT_IX_ENDPOINT, guardRunner, memoryCall, parseMemorySupport, refuseForTarget, type IxRunner } from "../ix.js";
import { memoryActor, memoryPurpose, memorySessionName, memoryText, recordOf } from "../memory.js";
import { checkLoopbackListener } from "../listener.js";
import { cleanupTmp, fakeIx, OSS_HELP, PRO_HELP, tmp } from "./harness.js";

// A real loopback listener this test process owns: the local endpoint every writer test uses, so the
// real listener check (listener.ts) runs against it and passes.
let server: Server;
let EP = "";
/**
 * Whether this machine lets the test see its own listener (a sandbox can hide the socket tables
 * from child processes; the check then fails closed). Required in CI, where the real check runs.
 */
let observable = false;
beforeAll(async () => {
  server = createServer(() => {});
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  EP = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  observable = (await checkLoopbackListener(EP)).ok;
  if (!observable && process.env.CI) throw new Error("the listener check can't see this test's own listener in CI");
  if (!observable) console.warn("listener check: this environment hides the socket tables; the writer tests stand in for it");
  memory = createIxExtension(observable ? {} : { listener: async () => ({ ok: true }) }).memory!;
});
afterAll(async () => {
  await new Promise((r) => server.close(r));
  cleanupTmp();
});
const here = () => ({ kind: "local" as const, endpoint: EP, why: "x is private" });

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
      const g = guardRunner(inner, async () => local, undefined, { listener: async () => ({ ok: true }) });
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
    graphTarget: o.graphTarget ?? (async () => here()),
    kv: { get: async (k: string) => store.get(k), set: async (k: string, v: unknown) => void store.set(k, v) },
    self: async () => ({ userId: "p2p:u", address: o.address ?? "alice@abcd-efgh-ijkl-mnop" }),
    io: { err: () => {} },
    json: true,
    interactive: false,
  } as unknown as ExtContext;
  return { ctx, store };
}

let memory = createIxExtension().memory!;
/** For the tests at Ix's default endpoint (nothing listens there): the listener check stood in for. */
const memoryOk = createIxExtension({ listener: async () => ({ ok: true }) }).memory!;
const PREFIX = "Recorded by Peer2Peer (agent-generated, untrusted)\n";
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
      expect(ix.sessions()).toEqual([{ argv: ["session", "--json", "create", "p2p-s-1", "--purpose=Peer2Peer session widgets (repo widgets, branch main)", "--actor=p2p:alice@abcd-efgh-ijkl-mnop", "--ttl=720"], endpoint: EP }]);
      const notes = ix.written();
      expect(notes.map((n) => n.endpoint)).toEqual(Array(4).fill(EP));
      // Tagged `finding` and framed as untrusted, agent-generated records.
      expect(notes.map((n) => n.argv)).toEqual(Array(4).fill(["note", "--tag=finding", "--session=sess-s-1", "--actor=p2p:alice@abcd-efgh-ijkl-mnop", "--json"]));
      expect(notes.map((n) => n.text)).toEqual([
        `${PREFIX}Session started 2026-11-09T12:00:00.000Z: widgets (repo widgets, branch main).`,
        `${PREFIX}Status (2026-11-09T12:00:00.000Z): Refactoring token rotation`,
        `${PREFIX}Edited (2026-11-09T12:00:00.000Z): src/auth/token.ts, src/a.ts`,
        `${PREFIX}Session ended 2026-11-09T12:00:00.000Z.`,
      ]);
      // Every child (help probes included) saw the pinned endpoint and no Pro variable.
      for (const c of ix.calls()) expect(c.argv.join(" ")).not.toContain(CLOUD);
      // The Ix session id is remembered: the next batch writes no second record.
      expect(store.get("memory")).toMatchObject({ sessions: { "s-1": { id: "sess-s-1", endpoint: EP } } });
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
      expect(e.IX_ENDPOINT).toBe(EP);
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
    await expect(runner(ctx, observable ? {} : { listener: async () => ({ ok: true }) }, "s").run(["note", "--json", "show", "n1"])).rejects.toMatchObject({ code: "graph_target", message: expect.stringMatching(/Ix Pro/) });
    expect(ix.calls().map((c) => c.argv[0])).toEqual(["--help"]);
    ix.set("help.txt", OSS_HELP);
    const r = await runner(ctx, observable ? {} : { listener: async () => ({ ok: true }) }, "s").run(["note", "--json", "show", "n1"]);
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
    expect((await memoryOk.write(widened.ctx, { sid: "s-6", items: [{ kind: "end", at: 1 }] })).written).toBe(1);
    expect(ix.written().map((n) => n.endpoint)).toEqual([DEFAULT_IX_ENDPOINT]);
    const throwing = memCtx(ix, { graphTarget: async () => Promise.reject(new Error("boom")) });
    expect((await memoryOk.write(throwing.ctx, { sid: "s-7", items: [{ kind: "end", at: 1 }] })).written).toBe(1);
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
    expect(memoryText({ kind: "status", at: 0, summary: "x".repeat(1000) })!.length).toBeLessThan(420);
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

describe("review fixes (M1, M2, L3-L6)", () => {
  const ok = async () => ({ ok: true as const });
  const ossInner = (calls: string[][], o: { help?: () => string; note?: (argv: readonly string[]) => { code: number; stdout: string; stderr: string } } = {}): IxRunner => ({
    run: async (argv) => {
      calls.push([...argv]);
      if (argv[0] === "--help") return { code: 0, stdout: o.help ? o.help() : OSS_HELP, stderr: "" };
      if (argv[0] === "--version") return { code: 0, stdout: "0.14.0", stderr: "" };
      if (o.note) return o.note(argv);
      return { code: 0, stdout: "{}", stderr: `→ local backend ${DEFAULT_IX_ENDPOINT}` };
    },
  });

  it("M1: a port held by someone else: no memory call runs at all (writes, reads, import), and memory reports ix_listener", async () => {
    const calls: string[][] = [];
    const no = async () => ({ ok: false as const, why: "port 8090 is held by another user (uid 1001), not your Ix backend" });
    const g = guardRunner(ossInner(calls), async () => local, undefined, { listener: no });
    for (const argv of [["note", "--tag=note", "--json"], ["note", "--json", "show", "n1"], ["session", "--json", "create", "p2p-s", "--purpose=x", "--actor=p2p", "--ttl=720"], ["session", "--json", "show", "s"]]) {
      await expect(g.run(argv, { stdin: "secret status" })).rejects.toMatchObject({ code: "ix_listener", message: expect.stringMatching(/held by another user/) });
    }
    expect(calls).toEqual([]);
    // Reads of the graph (#44's) are unaffected.
    await g.run(["status", "--format", "json"]);
    const ix = fakeIx();
    ix.set("help.txt", OSS_HELP);
    const m = createIxExtension({ listener: no }).memory!;
    const { ctx } = memCtx(ix);
    expect(await m.available(ctx)).toMatchObject({ ok: false, reason: "ix_listener" });
    expect(await m.write(ctx, { sid: "l1", items: items() })).toMatchObject({ written: 0, unavailable: { reason: "ix_listener" } });
    expect(ix.written()).toEqual([]);
    expect(ix.sessions()).toEqual([]);
  });

  it("L3: a write without the local-backend line is ix_unconfirmed whatever its exit code; Pro is asked again right before session create", async () => {
    for (const code of [0, 1, 2]) {
      const g = guardRunner(ossInner([], { note: () => ({ code, stdout: "", stderr: "Error: fetch failed" }) }), async () => local, undefined, { listener: ok });
      await expect(g.run(["note", "--tag=note", "--json"], { stdin: "t" })).rejects.toMatchObject({ code: "ix_unconfirmed" });
    }
    // OSS at first, Pro by the time a session is created: refused, and the note read before was fine.
    let n = 0;
    const calls: string[][] = [];
    const g = guardRunner(ossInner(calls, { help: () => (n++ === 0 ? OSS_HELP : PRO_HELP), note: () => ({ code: 0, stdout: "{}", stderr: "" }) }), async () => local, undefined, { listener: ok });
    await g.run(["note", "--json", "show", "n1"]);
    await expect(g.run(["session", "--json", "create", "p2p-s", "--purpose=x", "--actor=p2p", "--ttl=720"])).rejects.toMatchObject({ code: "graph_target", message: expect.stringMatching(/Ix Pro/) });
    expect(calls.map((c) => c[0] + (c[2] ? ` ${c[2]}` : ""))).toEqual(["--help", "note show", "--help"]);
  });

  it("L4: an aborted batch writes nothing more; aborting mid-batch stops before the next write", async () => {
    const ix = fakeIx();
    ix.set("help.txt", OSS_HELP);
    const { ctx } = memCtx(ix);
    const pre = new AbortController();
    pre.abort();
    expect(await memory.write(ctx, { sid: "a1", items: items(), signal: pre.signal })).toMatchObject({ written: 0, failed: [{ reason: "aborted", n: 4 }] });
    expect(ix.calls()).toEqual([]);
    // A runner that aborts once the first note is written.
    const stop = new AbortController();
    const m = createIxExtension({
      listener: ok,
      ix: (c) => {
        const inner = runner(c, { listener: ok });
        return { run: async (argv, o) => { const r = await inner.run(argv, o); if (argv[0] === "note") stop.abort(); return r; } };
      },
    }).memory!;
    // Deps.ix replaces the guarded runner's inner: the guard still wraps it.
    const r = await m.write(ctx, { sid: "a2", items: items(), signal: stop.signal });
    expect(r).toMatchObject({ written: 1, failed: [{ reason: "aborted", n: 3 }] });
    expect(ix.written()).toHaveLength(1);
  });

  it("L5: records are framed and tagged; file names with spaces, controls or past 200 characters are dropped", () => {
    const t = memoryText({ kind: "files", at: 0, files: ["ok.ts", "has space.ts", "tab\there.ts", "nl\nx.ts", "bidi‮.ts", `${"d/".repeat(120)}x.ts`, "src/fine-name_1.ts"] })!;
    expect(t.split("\n")[0]).toBe("Recorded by Peer2Peer (agent-generated, untrusted)");
    expect(t.split("\n")[1]).toMatch(/: ok\.ts, src\/fine-name_1\.ts$/);
    expect(t.split("\n")).toHaveLength(2);
  });

  it("L6: a remembered session is checked; gone, or created at another endpoint, it is made again; never twice in a batch", async () => {
    const ix = fakeIx();
    ix.set("help.txt", OSS_HELP);
    const { ctx, store } = memCtx(ix);
    await memory.write(ctx, { sid: "k1", items: [{ kind: "status", at: 1, summary: "one" }, { kind: "status", at: 2, summary: "two" }] });
    expect(ix.sessions()).toHaveLength(1);
    // Next batch: checked with `session show` once, reused.
    await memory.write(ctx, { sid: "k1", items: [{ kind: "status", at: 3, summary: "three" }, { kind: "end", at: 4 }] });
    expect(ix.sessions()).toHaveLength(1);
    expect(ix.calls().filter((c) => c.argv[0] === "session" && c.argv[2] === "show")).toHaveLength(1);
    // The backend lost it: made again.
    ix.set("gone.txt", "sess-k1");
    await memory.write(ctx, { sid: "k1", items: [{ kind: "status", at: 5, summary: "five" }] });
    expect(ix.sessions()).toHaveLength(2);
    // Remembered for another endpoint: not used there, made again here.
    ix.set("gone.txt", "");
    store.set("memory", { sessions: { k2: { id: "sess-k2", endpoint: "http://127.0.0.1:1", at: 1 } } });
    await memory.write(ctx, { sid: "k2", items: [{ kind: "status", at: 6, summary: "six" }] });
    expect(ix.sessions().at(-1)!.argv[3]).toBe("p2p-k2");
    expect(store.get("memory")).toMatchObject({ sessions: { k2: { id: "sess-k2", endpoint: EP } } });
  });

  it("re-review 2: the listener is asked before every write (a read once per guard); trustRoot only from the target", async () => {
    const asked: { endpoint: string; trustRoot?: boolean }[] = [];
    const listener = async (endpoint: string, o?: { trustRoot?: boolean }) => (asked.push({ endpoint, trustRoot: o?.trustRoot }), { ok: true as const });
    const g = guardRunner(ossInner([]), async () => local, undefined, { listener });
    await g.run(["note", "--json", "show", "n1"]);
    await g.run(["note", "--json", "show", "n2"]);
    await g.run(["note", "--tag=note", "--json"], { stdin: "a" });
    await g.run(["note", "--tag=note", "--json"], { stdin: "b" });
    expect(asked).toHaveLength(3); // one read check, then one per write
    expect(asked.every((a) => a.trustRoot === false)).toBe(true);
    // A target that carries the person's opt-in passes it on; a forged field on a non-local target can't.
    const g2 = guardRunner(ossInner([]), async () => ({ ...local, trustRootListener: true as const }), undefined, { listener });
    await g2.run(["note", "--tag=note", "--json"], { stdin: "c" });
    expect(asked.at(-1)!.trustRoot).toBe(true);
    expect(checkedTarget({ kind: "local", endpoint: "http://localhost:8090", trustRootListener: true })).toMatchObject({ trustRootListener: true });
    expect(checkedTarget({ kind: "local", endpoint: "http://localhost:8090", trustRootListener: "yes" })).not.toHaveProperty("trustRootListener");
    expect(checkedTarget({ kind: "shared", circle: "c", endpoint: "https://g.example", trustRootListener: true })).not.toHaveProperty("trustRootListener");
  });

  it("re-review 4: the store is MACed with the device's key; a planted or altered mapping counts as no record", async () => {
    const ix = fakeIx();
    ix.set("help.txt", OSS_HELP);
    const { ctx, store } = memCtx(ix);
    const mac = (d: string) => `mac:${d.length}:${d.slice(0, 40)}`;
    (ctx as unknown as { localMac: (d: string) => string }).localMac = mac;
    await memory.write(ctx, { sid: "m1", items: [{ kind: "status", at: 1, summary: "one" }] });
    const saved = store.get("memory") as { sessions: Record<string, { id: string }>; mac: string };
    expect(saved.mac).toMatch(/^mac:/);
    // Reused while the MAC verifies.
    await memory.write(ctx, { sid: "m1", items: [{ kind: "status", at: 2, summary: "two" }] });
    expect(ix.sessions()).toHaveLength(1);
    // A model's file tools rewrite the store (point m1 at someone else's session): no record, made again.
    store.set("memory", { ...saved, sessions: { ...saved.sessions, m1: { ...saved.sessions.m1, id: "sess-attacker" } } });
    await memory.write(ctx, { sid: "m1", items: [{ kind: "status", at: 3, summary: "three" }] });
    expect(ix.sessions()).toHaveLength(2);
    expect(ix.written().at(-1)!.argv).toContain("--session=sess-m1");
    // And recordOf traces nothing through a planted mapping.
    store.set("memory", { sessions: { X: { id: "sess-X", endpoint: EP, at: 1 } }, mac: "forged" });
    expect(await recordOf(ctx, { sessionId: "sess-X", sessionName: "renamed", text: "plain" })).toBeUndefined();
  });

  describe("M2: `--ix-note` won't pass on another session's Peer2Peer record", () => {
    const noteCmd = createIxExtension().commands!.find((c) => c.name === "note")!;
    const send = { calls: 0 };
    function noteCtx(note: Record<string, unknown>, o: { may?: (a: string, b: string) => Promise<boolean>; kv?: unknown } = {}) {
      const ixDeps = { listener: ok, ix: () => ossInner([], { note: () => ({ code: 0, stdout: JSON.stringify(note), stderr: "" }) }) };
      const store = new Map<string, unknown>(o.kv ? [["memory", o.kv]] : []);
      const ctx = {
        env: {},
        cwd: tmp("ixnote-"),
        graphTarget: async () => ({ ...local }),
        kv: { get: async (k: string) => store.get(k), set: async (k: string, v: unknown) => void store.set(k, v) },
        self: async () => ({ userId: "p2p:u", address: "me@abcd" }),
        send: async () => (send.calls++, { delivered: true, to: { userId: "u2", address: "bob@x", own: "u2", sid: "b1", ref: "r" }, relays: 1, devices: 1, kind: "x:ix.note", bytes: 10 }),
        io: { err: () => {} },
        json: true,
        interactive: false,
        ...(o.may ? { mayShareSessionContext: o.may } : {}),
      } as unknown as ExtContext;
      const cmd = createIxExtension(ixDeps).commands!.find((c) => c.name === "note")!;
      return (from: string) => cmd.run(ctx, [], { fromSession: from, to: "bob", ixNote: "n1" });
    }
    const rec = (session: Record<string, unknown>) => ({ id: "n1", text: "Recorded by Peer2Peer (agent-generated, untrusted)\nStatus: secret plan", tag: "finding", at: "2026-11-09T00:00:00Z", ...session });

    it("its own session's record goes out; another's only when p2p says that session's context may (shared, wider)", async () => {
      expect(noteCmd).toBeDefined();
      const before = send.calls;
      await noteCtx(rec({ sessionName: "p2p-A" }))("A");
      expect(send.calls).toBe(before + 1);
      const asked: string[][] = [];
      await noteCtx(rec({ sessionName: "p2p-A" }), { may: async (a, b) => (asked.push([a, b]), true) })("B");
      expect(asked).toEqual([["A", "B"]]);
      expect(send.calls).toBe(before + 2);
    });

    it("refused: a private (or narrower) session's record, an older p2p, a hashed name, a record with no session, an id from the store", async () => {
      const before = send.calls;
      for (const [note, o] of [
        [rec({ sessionName: "p2p-A" }), { may: async () => false }],
        [rec({ sessionName: "p2p-A" }), { may: async () => Promise.reject(new Error("x")) }],
        [rec({ sessionName: "p2p-A" }), {}], // a p2p without mayShareSessionContext
        [rec({ sessionName: `p2p-${"a".repeat(32)}` }), { may: async () => true }], // can't be traced back
        [rec({}), { may: async () => true }], // the prefix alone marks it
        [rec({ sessionId: "sess-X", sessionName: "renamed" }), { kv: { sessions: { X: { id: "sess-X", endpoint: EP, at: 1 } } }, may: async () => false }],
      ] as const) {
        await expect(noteCtx(note, o as never)("B")).rejects.toMatchObject({ code: "not_shared" });
      }
      expect(send.calls).toBe(before);
    });

    it("the person's own notes go out as before", async () => {
      const before = send.calls;
      await noteCtx({ id: "n1", text: "my own decision", tag: "decision", at: "2026-11-09T00:00:00Z", sessionName: "sprint-23" })("B");
      expect(send.calls).toBe(before + 1);
    });
  });
});
