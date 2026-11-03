// Copyright 2026 Ix Infrastructure Inc.
//
// §4.3 "Status agents" (cap agents.v1, footprint P1) end to end over an
// in-process relay: `p2p status --agents-json` reaches a peer whose live
// sessions advertise agents.v1 as `agents`, and every other peer as the
// `(+N agents)` summary; the sender normalizes what it is handed; `ls`,
// watch lines and ExtContext carry the validated list.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CLI_FEATURE_CAPS } from "../features.js";
import { STATUS_AGENTS_MAX, STATUS_CAP_AGENTS, STATUS_CAP_TOLERANT, STATUS_CAP_XSTATE, validStatusAgents, type StatusAgent, type StatusBody } from "@peer2peer/core/v3";
import { receiving } from "../inbound.js";
import { buildStatus, getSession, MAX_STATUS_PATHS, normalizeAgents, statusWithoutAgents, understandsAgents } from "../sessions.js";
import { extContext } from "../ext-host.js";
import type { P2PExtension } from "../extensions.js";
import type { PeerStatusRec } from "../state.js";
import { CliError } from "../errors.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const NOW = Date.now();
const AGENTS = [
  { id: "a1", type: "Explore", task: "Survey the auth module", state: "running", files: ["src/auth.ts"], at: NOW - 1000 },
  { id: "a2", parent: "a1", type: "general-purpose", task: "Fix the session tests", state: "running", files: ["test/session.test.ts"], wt: true, branch: "fix/session", at: NOW - 500 },
  { id: "a3", type: "Plan", task: "Plan the migration", state: "done", at: NOW - 60_000 },
];

describe("normalizeAgents (what the sender is handed is never trusted as is)", () => {
  it("keeps valid entries, ordered at work first then most recent", () => {
    const out = normalizeAgents(AGENTS);
    expect(out.map((a) => a.id)).toEqual(["a2", "a1", "a3"]);
    expect(validStatusAgents(out)).toBe(true);
    expect(out.find((a) => a.id === "a2")).toMatchObject({ parent: "a1", wt: true, branch: "fix/session" });
  });

  it("sanitizes or drops hostile fields; never a worktree, .git, absolute or traversal path", () => {
    const out = normalizeAgents([
      {
        id: "a1",
        type: "Explore<script>\n",
        task: "line one\nline two <b>\u202e" + "x".repeat(200),
        state: "completed",
        files: ["/abs/x.ts", "../up.ts", ".claude/worktrees/agent-a206a0b95f04a3e20/src/x.ts", ".Claude/Worktrees/agent-x/y.ts", ".git/config", "C:\\x", "ok.ts", "ok.ts"],
        branch: "not-in-a-worktree",
        prompt: "the whole prompt",
        transcript: "/Users/x/t.jsonl",
        at: -5,
      },
      { id: "agent-a206a0b95f04a3e20", type: "Explore", task: "raw engine id", state: "running", at: 1 },
      { id: "a2", type: "Explore", task: "bad state", state: "exploded", at: 1 },
      { id: "a1", type: "Explore", task: "repeated id", state: "running", at: 1 },
      "a4",
      null,
    ]);
    expect(out).toHaveLength(1);
    const [a] = out;
    expect(a.type).toBe("Explorescript");
    expect(a.task).not.toMatch(/[\n<>\u202e]/);
    expect([...a.task].length).toBeLessThanOrEqual(80);
    expect(a.state).toBe("done");
    expect(a.files).toEqual(["ok.ts"]);
    expect(a).not.toHaveProperty("branch"); // a branch only with wt
    expect(a).not.toHaveProperty("prompt");
    expect(a).not.toHaveProperty("transcript");
    expect(a.at).toBeGreaterThan(0);
    expect(validStatusAgents(out)).toBe(true);
    expect(() => normalizeAgents({ a1: {} })).toThrow(CliError);
  });

  it("review M3: a task line loses absolute and home paths and secret shapes", () => {
    const [a] = normalizeAgents([{ id: "a1", type: "Explore", task: "Use sk-proj-abcDEF1234567890xyz on /Users/sam/app and C:\\Users\\sam\\x", state: "running", at: 1 }]);
    expect(a.task).toBe("Use [redacted] on and");
    const [b] = normalizeAgents([{ id: "a1", type: "Explore", task: "~/.ssh/id_ed25519 AKIAIOSFODNN7EXAMPLE", state: "running", at: 1 }]);
    expect(b.task).toBe("[redacted]");
    const [c] = normalizeAgents([{ id: "a1", type: "Explore", task: "/etc/passwd", state: "running", at: 1 }]);
    expect(c.task).toBe("Explore"); // nothing left: the type
  });

  it("at most 8 agents (done ones with no files go first), nesting flattened to depth 2", () => {
    const many = Array.from({ length: 12 }, (_, i) => ({ id: `a${i + 1}`, type: "Explore", task: `t${i}`, state: i < 3 ? "done" : "running", at: NOW + i }));
    const out = normalizeAgents(many);
    expect(out).toHaveLength(STATUS_AGENTS_MAX);
    expect(out.every((a) => a.state === "running")).toBe(true);
    const nested = normalizeAgents([
      { id: "a1", type: "x", task: "t", state: "running", at: 3 },
      { id: "a2", parent: "a1", type: "x", task: "t", state: "running", at: 2 },
      { id: "a3", parent: "a2", type: "x", task: "t", state: "running", at: 1 },
      { id: "a4", parent: "a9", type: "x", task: "t", state: "running", at: 0 },
    ]);
    expect(nested.map((a) => [a.id, a.parent])).toEqual([
      ["a1", undefined],
      ["a2", "a1"],
      ["a3", "a1"],
      ["a4", undefined],
    ]);
    expect(validStatusAgents(nested)).toBe(true);
  });

  it("at most 60 distinct paths across the main files and every agent's; the plaintext stays under 8 KiB", () => {
    const files = Array.from({ length: 25 }, (_, i) => `main/f${i}.ts`);
    const agents = Array.from({ length: 8 }, (_, i) => ({ id: `a${i + 1}`, type: "Explore", task: "t".repeat(80), state: "running", files: Array.from({ length: 10 }, (_, j) => `agent${i}/${"d".repeat(150)}/f${j}.ts`), at: NOW - i }));
    const s = buildStatus({ session: "s", state: "busy", label: "x", files, emitCaps: true, agents });
    const paths = new Set([...(s.files ?? []), ...(s.agents ?? []).flatMap((a) => a.files ?? [])]);
    expect(paths.size).toBeLessThanOrEqual(MAX_STATUS_PATHS);
    expect(Buffer.byteLength(JSON.stringify({ status: s }), "utf8")).toBeLessThanOrEqual(8 * 1024);
    expect(validStatusAgents(s.agents)).toBe(true);
  });

  it("with status caps off, agents never go on the wire, but those at work count in the summary", () => {
    const s = buildStatus({ session: "s", state: "busy", label: "x", summary: "Fixing auth.", agents: AGENTS });
    expect(s).not.toHaveProperty("agents");
    expect(s.caps).toBeUndefined();
    expect(s.summary).toBe("Fixing auth. (+2 agents)");
  });

  it("statusWithoutAgents: the summary fallback, and nothing else changes", () => {
    const s = buildStatus({ session: "s", state: "busy", label: "x", summary: "Fixing auth.", emitCaps: true, agents: AGENTS });
    const lite = statusWithoutAgents(s);
    expect(lite).not.toHaveProperty("agents");
    expect(lite.summary).toBe("Fixing auth. (+2 agents)");
    expect(lite.caps).toEqual(s.caps);
    expect(statusWithoutAgents({ state: "idle", label: "x" })).toEqual({ state: "idle", label: "x" });
  });

  it("understandsAgents: every live session of that user (not this device's) advertises agents.v1", () => {
    const rec = (own: string, sid: string, status: Partial<StatusBody>, ts = Date.now(), did = "d_X"): PeerStatusRec => ({ own, sid, did, ts, status: { state: "busy", label: "x", ...status } });
    const self = { userId: "me", did: "d_ME" };
    const aware = { caps: [STATUS_CAP_TOLERANT, STATUS_CAP_AGENTS, STATUS_CAP_XSTATE, ...CLI_FEATURE_CAPS] };
    expect(understandsAgents({ k1: rec("u", "s1", aware) }, "u", self)).toBe(true);
    expect(understandsAgents({}, "u", self)).toBe(false); // nothing known: the fallback
    expect(understandsAgents({ k1: rec("u", "s1", aware), k2: rec("u", "s2", {}) }, "u", self)).toBe(false); // one older client
    expect(understandsAgents({ k1: rec("u", "s1", aware), k2: rec("u", "s2", {}, Date.now() - 10 * 60_000) }, "u", self)).toBe(true); // that one isn't live
    expect(understandsAgents({ k1: rec("u", "s1", { caps: "agents.v1" as unknown as string[] }) }, "u", self)).toBe(false); // review L1
    // Our own other devices: this device's own sessions don't count.
    expect(understandsAgents({ k1: rec("me", "s1", {}, Date.now(), "d_ME"), k2: rec("me", "s2", aware, Date.now(), "d_LAPTOP") }, "me", self)).toBe(true);
  });
});

const R = "wss://relay-agents.test/v3";
let relay: TestRelay;
let alice: User;
let bob: User;
let carol: User;
const ids: Record<string, string> = {};

describe("status agents over a relay", () => {
  beforeAll(async () => {
    relay = await startRelay(R);
    const t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    alice = new User("alice", t);
    bob = new User("bob", t);
    // carol's client sends no caps: she stands for a peer that doesn't understand agents.v1.
    carol = new User("carol", t, { P2P_STATUS_CAPS: "0" });
    for (const u of [alice, bob, carol]) ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
    for (const u of [alice, carol]) {
      const inv = await bob.ok(["invite", "--link"]);
      await u.ok(["accept", inv.link]);
      await bob.ok(["friends"]);
    }
    await bob.ok(["session", "roster", "bs1", "--add", ids.alice, "--add", ids.carol]);
    await alice.ok(["session", "roster", "as1", "--add", ids.bob]);
    await carol.ok(["session", "roster", "cs1", "--add", ids.bob]);
    // Their own statuses tell bob what each understands.
    await alice.ok(["status", "--session", "as1", "--state", "busy", "--label", "web"]);
    await carol.ok(["status", "--session", "cs1", "--state", "busy", "--label", "web"]);
  });

  afterAll(async () => {
    await relay?.close().catch(() => {});
    for (const u of [alice, bob, carol]) u?.cleanup();
  });

  it("agents go to the peer that understands agents.v1, and the (+N agents) summary to the one that doesn't", async () => {
    const st = await bob.ok(["status", "--session", "bs1", "--state", "busy", "--label", "api", "--summary", "Fixing auth.", "--file", "src/main.ts", "--agents-json", "-"], { stdin: JSON.stringify(AGENTS) });
    expect(st.status.agents.map((a: StatusAgent) => a.id)).toEqual(["a2", "a1", "a3"]);
    const byUser = Object.fromEntries(st.delivered.map((d: any) => [d.userId, d.agents]));
    expect(byUser).toEqual({ [ids.alice]: true, [ids.carol]: false });

    const seen = (await alice.ok(["ls"])).peers.find((p: any) => p.own === ids.bob);
    expect(seen.summary).toBe("Fixing auth.");
    expect(seen.files).toEqual(["src/main.ts"]);
    expect(seen.agents).toEqual(st.status.agents);

    const old = (await carol.ok(["ls"])).peers.find((p: any) => p.own === ids.bob);
    expect(old.summary).toBe("Fixing auth. (+2 agents)");
    expect(old).not.toHaveProperty("agents");
    // Not dropped on receipt: it was never in carol's plaintext.
    const app = await carol.app();
    await app.load();
    const rec = Object.values((await app.state.get("peers")) ?? {}).find((p) => p.own === ids.bob && p.sid === "bs1");
    await app.close();
    expect(JSON.stringify(rec)).not.toContain("Survey the auth module");
    expect(rec?.status.caps).toEqual([STATUS_CAP_TOLERANT, STATUS_CAP_AGENTS, STATUS_CAP_XSTATE, ...CLI_FEATURE_CAPS]);

    // This device keeps the full status for its own ls.
    const mine = (await bob.ok(["ls"])).peers.find((p: any) => p.own === ids.bob && p.sid === "bs1");
    expect(mine.agents).toHaveLength(3);
  });

  it("watch lines carry the validated agents", async () => {
    await bob.ok(["status", "--session", "bs1", "--state", "idle", "--label", "api", "--agents-json", JSON.stringify(AGENTS.slice(0, 1))]);
    const ev = (await alice.watch("as1", 1500)).find((e) => e.kind === "p2p.status" && e.own === ids.bob);
    expect(ev?.status.agents).toEqual([AGENTS[0]]);
  });

  it("a second live session of alice's from an older client turns her fallback on too", async () => {
    await sendRaw(alice, ids.bob, "as2", { state: "busy", label: "old" });
    const st = await bob.ok(["status", "--session", "bs1", "--state", "busy", "--label", "api", "--agents-json", JSON.stringify(AGENTS)]);
    const byUser = Object.fromEntries(st.delivered.map((d: any) => [d.userId, d.agents]));
    expect(byUser[ids.alice]).toBe(false);
    const seen = (await alice.ok(["ls"])).peers.find((p: any) => p.own === ids.bob);
    expect(seen).not.toHaveProperty("agents");
    expect(seen.summary).toBe("(+2 agents)");
  });

  it("a bad --agents-json is a usage error before anything is sent", async () => {
    for (const bad of ["{not json", JSON.stringify({ a1: {} })]) {
      const r = await bob.run(["status", "--session", "bs1", "--state", "busy", "--agents-json", bad]);
      expect(r.code).not.toBe(0);
      expect(r.json.error).toBe("usage");
    }
  });

  it("ExtContext: peers() and ownStatus() carry caps and agents (review I4)", async () => {
    await alice.ok(["status", "--session", "as2", "--state", "busy", "--label", "web"]);
    await bob.ok(["status", "--session", "bs1", "--state", "busy", "--label", "api", "--agents-json", JSON.stringify(AGENTS)]);
    const app = await bob.app();
    await app.load();
    try {
      const ext = { name: "@peer2peer/ext-test", ns: "test", version: "0.0.0", kinds: {}, commands: [] } as unknown as P2PExtension;
      const ctx = extContext(app, ext, { out: () => undefined, err: () => undefined }, true, async () => false);
      const own = await ctx.ownStatus("bs1");
      expect(own?.caps).toEqual([STATUS_CAP_TOLERANT, STATUS_CAP_AGENTS, STATUS_CAP_XSTATE, ...CLI_FEATURE_CAPS]);
      expect(own?.agents?.map((a) => a.id)).toEqual(["a2", "a1", "a3"]);
      const row = (await ctx.peers()).find((p) => p.own === ids.bob && p.sid === "bs1");
      expect(row?.agents).toHaveLength(3);
      expect(row?.caps).toContain(STATUS_CAP_AGENTS);
      // Copies: changing what the extension got changes nothing stored.
      own?.agents?.[0]?.files?.push("tampered.ts");
      expect((await ctx.ownStatus("bs1"))?.agents?.[0]?.files).not.toContain("tampered.ts");
    } finally {
      await app.close();
    }
  });
});

/** Sends a hand-built status plaintext from `u` to `to` (as an older client would), bypassing buildStatus. */
async function sendRaw(u: User, to: string, sid: string, status: Record<string, unknown>): Promise<void> {
  const app = await u.app();
  await app.load();
  receiving(app);
  const sess = await getSession(app, sid);
  await app.connectAndDrain();
  if (!sess.parts?.includes(to)) {
    await app.close();
    await u.ok(["session", "roster", sid, "--add", to]);
    return sendRaw(u, to, sid, status);
  }
  const d = await app.deliver(to, "status", { own: app.userId, sid }, { status, roster: sess.jws });
  await app.close();
  expect(d.relays.length).toBeGreaterThan(0);
}
