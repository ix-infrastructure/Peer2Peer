// Copyright 2026 Ix Infrastructure Inc.
//
// Graph memory (graph-memory.ts, epic #41 piece 2), adversarially:
//   - it is gathered from this device's own statuses only (never a peer's, never another device's);
//   - every batch goes through the chokepoint (projects.ts graphTarget) and anything that isn't
//     local is refused before the extension is asked (`not_local`), with a test-only shared graph;
//   - the queue is bounded and every drop is counted (what `p2p doctor` shows);
//   - nothing runs without the extension's memory writer, when it says it can't, or when the
//     person turned it off; a malformed writer is never asked;
//   - `p2p status` (the hook path) never waits on it.

import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { App } from "../app.js";
import { ExtensionRegistry, memoryOf, type ExtMemory, type ExtMemoryItem, type P2PExtension } from "../extensions.js";
import { drainGraphMemory, gather, gatherGraphMemory, GRAPH_MEMORY_QUEUE_MAX, graphMemoryLoop, type GraphMemoryDoc } from "../graph-memory.js";
import { parseIxMemorySupport } from "../ix-local.js";
import { bindSession, graphTarget } from "../projects.js";
import type { PeerStatusRec } from "../state.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-memory.test/v3";
const GRAPH = "https://graph.example.test";
const NOW = Date.UTC(2026, 10, 9, 12);

const empty = (): GraphMemoryDoc => ({ v: 1, sessions: {}, queue: [], written: 0, dropped: {} });
const rec = (sid: string, status: Partial<PeerStatusRec["status"]> = {}, o: Partial<PeerStatusRec> = {}): PeerStatusRec => ({ own: "me", sid, did: "d1", ts: NOW, self: true, status: { state: "busy", label: "widgets", ...status }, ...o }) as PeerStatusRec;

describe("gather (pure)", () => {
  it("a session's start, status one-liners, new files and end, each once", () => {
    let d = gather(empty(), [rec("s1", { repo: "widgets", branch: "main", summary: "Fixing login", files: ["a.ts"] })], () => false, NOW).doc;
    expect(d.queue.map((i) => i.kind)).toEqual(["start", "status", "files"]);
    expect(d.queue[0]).toMatchObject({ sid: "s1", label: "widgets", repo: "widgets", branch: "main" });
    // Nothing changed: nothing more.
    d = gather(d, [rec("s1", { repo: "widgets", branch: "main", summary: "Fixing login", files: ["a.ts"] })], () => false, NOW).doc;
    expect(d.queue).toHaveLength(3);
    // A new status and one new file (an agent's counts too); then the end, once.
    d = gather(d, [rec("s1", { summary: "Writing tests", files: ["a.ts"], agents: [{ id: "a1", type: "x", state: "busy", files: ["b.ts"] }] as never })], () => false, NOW).doc;
    expect(d.queue.slice(3)).toMatchObject([{ kind: "status", summary: "Writing tests" }, { kind: "files", files: ["b.ts"] }]);
    d = gather(d, [rec("s1")], () => true, NOW).doc;
    d = gather(d, [rec("s1", { summary: "after the end" })], () => true, NOW).doc;
    expect(d.queue.map((i) => i.kind)).toEqual(["start", "status", "files", "status", "files", "end"]);
  });

  it("a session already over, or stale, when first seen: not recorded after the fact", () => {
    expect(gather(empty(), [rec("old", {}, { ts: NOW - 7 * 3600_000 })], () => false, NOW).doc.queue).toEqual([]);
    expect(gather(empty(), [rec("gone")], () => true, NOW).doc.queue).toEqual([]);
  });

  it("bounded: past the cap, new items are dropped and counted", () => {
    let d = empty();
    const recs = Array.from({ length: 40 }, (_, i) => rec(`s${i}`, { summary: `s ${i}` }));
    const r = gather(d, recs, () => false, NOW);
    d = r.doc;
    expect(d.queue).toHaveLength(GRAPH_MEMORY_QUEUE_MAX);
    expect(r.dropped).toBe(80 - GRAPH_MEMORY_QUEUE_MAX);
    expect(d.dropped.queue_full).toBe(80 - GRAPH_MEMORY_QUEUE_MAX);
  });

  it("a status's text is sanitized and capped before it is queued", () => {
    const d = gather(empty(), [rec("s1", { summary: `a‮\u0007b${"x".repeat(400)}`, label: "l\nl" })], () => false, NOW).doc;
    const s = d.queue.find((i) => i.kind === "status")!;
    expect(s.summary).not.toMatch(/[‮\u0007]/);
    expect([...s.summary!].length).toBeLessThanOrEqual(280);
    expect(d.queue[0].label).not.toContain("\n");
  });
});

describe("Ix memory support, as p2p doctor reads it", () => {
  it("Memory: (OSS), Pro: (cloud), or neither", () => {
    expect(parseIxMemorySupport("System:\n  status  x\n\nMemory:\n  note [text]           Record a note\n  session [actor]       Sessions\n")).toBe("oss");
    expect(parseIxMemorySupport("Memory:\n  note [text]  x\n  session [actor]  y\n\nPro:\n  note  z\n")).toBe("pro");
    expect(parseIxMemorySupport("System:\n  status  x\n")).toBe("none");
    expect(parseIxMemorySupport("Memory:\n  note [text]  x\n")).toBe("none");
  });
});

/** A memory writer that records what it was asked. */
function fakeMemory(o: { available?: ExtMemory["available"]; write?: ExtMemory["write"] } = {}) {
  const writes: { sid: string; items: ExtMemoryItem[] }[] = [];
  let asked = 0;
  const mem: ExtMemory = {
    v: 1,
    available:
      o.available ??
      (async () => {
        asked++;
        return { ok: true };
      }),
    write: o.write ?? (async (_ctx, b) => (writes.push(b), { written: b.items.length })),
  };
  const ext = { api: 1, graphTargets: 1, ns: "ix", name: "@peer2peer/ext-ix", version: "0", memory: mem } as P2PExtension;
  return { mem, ext, writes, asked: () => asked };
}

describe("draining, with real state and the chokepoint", () => {
  let relay: TestRelay;
  let ann: User;
  let team: string;
  let root: string;
  let shared: string;
  const app = async (extra: Record<string, string> = {}) => {
    const a = new App({ env: { ...ann.env, ...extra }, io: { out: () => {}, err: () => {} } });
    a.front = true;
    await a.load();
    return a;
  };
  const putStatus = (a: App, sid: string, status: Partial<PeerStatusRec["status"]>, o: Partial<PeerStatusRec> = {}) =>
    a.state.update("peers", (cur = {}) => ({ next: { ...cur, [`${o.own ?? a.userId}|${sid}`]: { own: a.userId, sid, did: a.did, ts: Date.now(), self: true, status: { state: "busy", label: "widgets", ...status }, ...o } as PeerStatusRec }, result: undefined }));
  const reset = async (a: App) => {
    await a.state.update("graphMemory", () => ({ next: empty(), result: undefined }));
    await a.state.update("peers", () => ({ next: {}, result: undefined }));
  };

  beforeAll(async () => {
    root = realpathSync(mkdtempSync(join(tmpdir(), "p2p-memory-")));
    shared = join(root, "shared");
    mkdirSync(join(shared, ".git"), { recursive: true });
    writeFileSync(join(shared, ".git", "HEAD"), "ref: refs/heads/main\n");
    writeFileSync(join(shared, ".git", "config"), '[core]\n\tbare = false\n[remote "origin"]\n\turl = git@github.com:acme/shared.git\n');
    relay = await startRelay(R);
    ann = new User("ann", { [R]: `ws://127.0.0.1:${relay.port}/v3` });
    ann.autoShareProject = false;
    await ann.ok(["init", "--name", "ann", "--relay", R, "--yes"]);
    team = (await ann.ok(["circle", "create", "team"])).cid;
    await ann.ok(["project", "share", team, "--dir", shared]);
    await ann.ok(["project", "share", team, "--dir", process.cwd()]);
  }, 60_000);

  afterAll(async () => {
    await relay?.close().catch(() => {});
    ann?.cleanup();
    rmSync(root, { recursive: true, force: true });
  });

  it("today: own sessions' items go to the writer, a session at a time, and are counted", async () => {
    const a = await app();
    try {
      await reset(a);
      const f = fakeMemory();
      await putStatus(a, "m1", { repo: "widgets", branch: "main", summary: "Fixing login", files: ["src/a.ts"] });
      await putStatus(a, "m2", { summary: "Other" });
      // A peer's session and another device's of ours: never gathered.
      await putStatus(a, "peer", { summary: "theirs" }, { own: "p2p:someone-else", self: false } as Partial<PeerStatusRec>);
      await putStatus(a, "other-device", { summary: "elsewhere" }, { did: "another-device" });
      expect(await gatherGraphMemory(a)).toEqual({ queued: 5, dropped: 0 });
      const r = await drainGraphMemory(a, f.ext, f.mem);
      expect(r).toEqual({ written: 5, dropped: 0 });
      expect(f.writes.map((w) => [w.sid, w.items.map((i) => i.kind)])).toEqual([
        ["m1", ["start", "status", "files"]],
        ["m2", ["start", "status"]],
      ]);
      expect(JSON.stringify(f.writes)).not.toMatch(/theirs|elsewhere/);
      const d = (await a.state.get("graphMemory"))!;
      expect(d).toMatchObject({ written: 5, queue: [] });
      // Gathered once: nothing more to write.
      await gatherGraphMemory(a);
      expect((await drainGraphMemory(a, f.ext, f.mem)).written).toBe(0);
    } finally {
      await a.close();
    }
  });

  it("a session whose graph target isn't local (a test-only shared graph): refused, never handed to the writer, counted as not_local", async () => {
    const a = await app();
    const was = process.cwd();
    try {
      await reset(a);
      const f = fakeMemory();
      await bindSession(a, "sh1", [shared]);
      process.chdir(shared);
      const reg = new Map([[team, GRAPH]]);
      // The chokepoint itself, with a shared graph for the circle: this session would reach it.
      const target = (sid: string) => graphTarget(a, { sid, dirs: [shared] }, reg);
      expect((await target("sh1")).kind).toBe("shared");
      await putStatus(a, "sh1", { summary: "shared work", files: ["x.ts"] });
      await gatherGraphMemory(a);
      const r = await drainGraphMemory(a, f.ext, f.mem, { target });
      expect(r).toEqual({ written: 0, dropped: 3 });
      expect(f.writes).toEqual([]);
      expect((await a.state.get("graphMemory"))!.dropped.not_local).toBe(3);
      // A target function that throws is not local either.
      await putStatus(a, "sh1", { summary: "more" });
      await gatherGraphMemory(a);
      expect(await drainGraphMemory(a, f.ext, f.mem, { target: () => Promise.reject(new Error("boom")) })).toEqual({ written: 0, dropped: 1 });
      expect(f.writes).toEqual([]);
    } finally {
      process.chdir(was);
      await a.close();
    }
  });

  it("failures, a throwing writer and an unavailable answer are counted; a lying writer's count is clamped", async () => {
    const a = await app();
    try {
      await reset(a);
      let n = 0;
      const f = fakeMemory({
        write: async (_ctx, b) => {
          n++;
          if (n === 1) return { written: 999, failed: [{ reason: "ix_failed", n: 999 }] };
          if (n === 2) throw new Error("crash");
          return { written: 0, failed: [{ reason: "ix_unconfirmed", n: b.items.length }], unavailable: { ok: false, reason: "ix_unconfirmed", message: "not local" } };
        },
      });
      for (const sid of ["f1", "f2", "f3"]) await putStatus(a, sid, { summary: sid });
      await gatherGraphMemory(a);
      const r = await drainGraphMemory(a, f.ext, f.mem);
      expect(r.unavailable).toMatchObject({ reason: "ix_unconfirmed" });
      const d = (await a.state.get("graphMemory"))!;
      expect(d.written).toBe(2); // clamped to the batch
      expect(d.dropped).toMatchObject({ ix_failed: 2, ext_failed: 2, ix_unconfirmed: 2 });
      expect(d.unavailable).toMatchObject({ reason: "ix_unconfirmed" });
    } finally {
      await a.close();
    }
  });

  it("the loop: nothing without a writer, with a malformed one, when it can't, or when the person turned it off", async () => {
    // Turned off by the environment.
    const off = await app({ P2P_IX_MEMORY: "0" });
    try {
      await reset(off);
      const f = fakeMemory();
      off.extensions = new ExtensionRegistry([{ ext: f.ext, from: "test" }]);
      await putStatus(off, "o1", { summary: "x" });
      await graphMemoryLoop(off).tick();
      expect(f.asked()).toBe(0);
      expect((await off.state.get("graphMemory"))!.queue).toEqual([]);
    } finally {
      await off.close();
    }
    const a = await app();
    try {
      await reset(a);
      await putStatus(a, "o2", { summary: "x" });
      // No extension, and one whose memory is malformed: never asked.
      a.extensions = new ExtensionRegistry();
      await graphMemoryLoop(a).tick();
      const bad = { api: 1, graphTargets: 1, ns: "ix", name: "x", version: "0", memory: { v: 2, available: () => Promise.reject(new Error("asked")), write: () => Promise.reject(new Error("asked")) } } as unknown as P2PExtension;
      expect(memoryOf(bad)).toBeUndefined();
      a.extensions = new ExtensionRegistry([{ ext: bad, from: "test" }]);
      await graphMemoryLoop(a).tick();
      expect((await a.state.get("graphMemory"))!.queue).toEqual([]);
      // Unavailable (an Ix without a local `ix note`): nothing gathered, and the doctor's reason kept.
      const no = fakeMemory({ available: async () => ({ ok: false, reason: "ix_upgrade", message: "upgrade Ix" }) });
      a.extensions = new ExtensionRegistry([{ ext: no.ext, from: "test" }]);
      await graphMemoryLoop(a).tick();
      expect(no.writes).toEqual([]);
      const d = (await a.state.get("graphMemory"))!;
      expect(d.queue).toEqual([]);
      expect(d.unavailable).toMatchObject({ reason: "ix_upgrade", message: "upgrade Ix" });
      // Available: gathered and written in one tick; the reason is cleared.
      const yes = fakeMemory();
      a.extensions = new ExtensionRegistry([{ ext: yes.ext, from: "test" }]);
      await graphMemoryLoop(a).tick();
      expect(yes.writes.map((w) => w.sid)).toEqual(["o2"]);
      expect((await a.state.get("graphMemory"))!.unavailable).toBeUndefined();
    } finally {
      await a.close();
    }
  });

  it("`p2p status` (the hook path) never waits on graph memory: a writer that never answers changes nothing", async () => {
    const never = new Promise<never>(() => {});
    const f = fakeMemory({ available: () => never, write: () => never });
    const a = await app();
    try {
      await reset(a);
      a.extensions = new ExtensionRegistry([{ ext: f.ext, from: "test" }]);
      const t0 = Date.now();
      await ann.ok(["status", "--session", "hook1", "--state", "busy", "--summary", "quick"]);
      expect(Date.now() - t0).toBeLessThan(10_000);
      expect((await a.state.get("graphMemory"))!.queue).toEqual([]);
      expect(f.writes).toEqual([]);
    } finally {
      await a.close();
    }
  });
});
