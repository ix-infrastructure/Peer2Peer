// Copyright 2026 Ix Infrastructure Inc.
//
// Regression tests for the pre-release security review: the untrusted local socket
// (H1), the trusted mode sources (M3), and the lows.

import { spawn } from "node:child_process";
import { appendFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { confirmDir, consumeNonce, nonceFileName, PersonGate, writeNonce } from "../confirm.js";
import { descendsFromCodex, parseLsofPeer, parseSsPeer, peerPid, serve, socketPath } from "../ipc.js";
import { classifyMode, isInside, parseAutoDeliver, screenMessage, TMPDIR_ROOT, touchesSecrets, writableRootsOf } from "../lib.js";
import { sanitizeReport } from "../server.js";
import { findRollout, RolloutReader } from "../trusted.js";
import { makeBridge, World } from "./world.js";

const dirs: string[] = [];
const tmp = (name: string) => {
  const d = mkdtempSync(join(tmpdir(), name));
  dirs.push(d);
  return d;
};
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const turnContext = (approval: string, sandbox: string, turn = "t") => JSON.stringify({ type: "turn_context", payload: { turn_id: turn, cwd: "/repo/web", approval_policy: approval, sandbox_policy: { type: sandbox }, approvals_reviewer: "user" } });
const sessionMeta = (thread: string, at = new Date().toISOString()) => JSON.stringify({ timestamp: at, type: "session_meta", payload: { id: thread, session_id: thread } });

describe("H1: who may release a held message (sandbox-based)", () => {
  const gate = (o: { tty?: boolean; descends?: boolean; reach?: boolean; nonce?: boolean; rate?: number } = {}) => {
    const printed: string[] = [];
    let t = 1_000_000;
    const g = new PersonGate({
      tty: () => (o.tty === false ? null : (text: string) => void printed.push(text)),
      descends: async () => o.descends === true,
      reach: () => (o.reach === false ? { ok: false, reason: "refused: P2P_HOME is inside a writable root" } : { ok: true }),
      nonce: (_op, _id, n) => o.nonce !== false && n?.secret === "good",
      now: () => t,
      code: () => "K7QM3X",
      ...(o.rate ? { ratePerMinute: o.rate } : {}),
    });
    return { g, printed, tick: (ms: number) => (t += ms) };
  };
  const good = { secret: "good" };
  const pid = async () => undefined as number | undefined;

  it("a double-forked daemon (no longer a Codex descendant) without the nonce file is refused, with or without a terminal", async () => {
    for (const tty of [true, false]) {
      const { g, printed } = gate({ tty });
      const r = await g.check("release", "m1", "K7QM3X", "x", async () => 4242, undefined);
      expect(r.ok).toBe(false);
      expect(r.ok ? "" : r.reason).toContain("confirmation file");
      expect(printed).toHaveLength(0); // no banner for it to fish with
    }
  });

  it("a known Codex descendant is refused even with a nonce", async () => {
    const { g } = gate({ descends: true });
    const r = await g.check("release", "m1", undefined, "x", async () => 4242, good);
    expect(r.ok ? "" : r.reason).toContain("process Codex started");
  });

  it("without a terminal: the fresh nonce file is enough (no 'pid check alone' path)", async () => {
    const { g } = gate({ tty: false });
    expect(await g.check("release", "m1", undefined, "x", pid, good)).toEqual({ ok: true });
    expect((await gate({ tty: false }).g.check("release", "m1", undefined, "x", async () => 77, undefined)).ok).toBe(false);
  });

  it("with a terminal: nonce file AND the code printed only there, each round with a fresh nonce", async () => {
    const { g, printed } = gate();
    const first = await g.check("release", "m1", undefined, 'the message from ann ("hi")', pid, good);
    expect(first).toEqual({ ok: false, needsCode: true, reason: expect.any(String) });
    expect(printed[0]).toContain("K7QM3X");
    expect(printed[0]).toContain("in a separate terminal");
    expect(printed[0]).toContain("Never paste it into Codex");
    expect(JSON.stringify(first)).not.toContain("K7QM3X");
    // The code alone, without a nonce file, is refused.
    expect((await g.check("release", "m1", "K7QM3X", "x", pid, undefined)).ok).toBe(false);
    expect(await g.check("release", "m1", "k7qm3x", "x", pid, good)).toEqual({ ok: true });
  });

  it("P2P_HOME inside a writable root (or no sandbox, or unknown roots): refused outright, nonce or not", async () => {
    const { g, printed } = gate({ reach: false });
    const r = await g.check("release", "m1", undefined, "x", pid, good);
    expect(r.ok ? "" : r.reason).toContain("writable root");
    expect(printed).toHaveLength(0);
  });

  it("rate limit: 5 of the person's requests a minute", async () => {
    const { g, tick } = gate({ tty: false });
    for (let i = 0; i < 5; i++) {
      expect(await g.check("release", `m${i}`, undefined, "x", pid, good)).toEqual({ ok: true });
      tick(1);
    }
    const r = await g.check("release", "m9", undefined, "x", pid, good);
    expect(r.ok ? "" : r.reason).toMatch(/requests a minute/);
    tick(61_000);
    expect(await g.check("release", "m9", undefined, "x", pid, good)).toEqual({ ok: true });
  });

  it("backoff is exponential after the person's wrong codes: each further failure doubles the wait", async () => {
    const { g, tick } = gate({ rate: 1000 });
    await g.check("release", "m", undefined, "x", pid, good); // challenge
    const wrong = () => g.check("release", "m", "NOPE00", "x", pid, good);
    const probe = async () => {
      const r = await g.check("release", "m", "NOPE00", "x", pid, good);
      const s = Number(/wait (\d+) s/.exec(r.ok ? "" : r.reason)?.[1] ?? 0);
      tick(s * 1000 + 1);
      return s;
    };
    await wrong();
    await wrong();
    const waits = [await probe()];
    await g.check("release", "m", undefined, "x", pid, good); // a new challenge (three tries used)
    await wrong();
    waits.push(await probe());
    expect(waits).toEqual([2, 4]);
  });

  it("L3: refusals of strangers (no nonce, Codex descendants) never push the person into backoff", async () => {
    const { g } = gate({ tty: false });
    for (let i = 0; i < 40; i++) await g.check("release", "m1", undefined, "x", async () => 4242, undefined);
    // The stranger is throttled...
    const r = await g.check("release", "m1", undefined, "x", pid, undefined);
    expect(r.ok ? "" : r.reason).toMatch(/too many failed attempts|requests a minute/);
    // ...the person isn't.
    expect(await g.check("release", "m1", undefined, "x", pid, good)).toEqual({ ok: true });
    const d = gate({ tty: false, descends: true });
    for (let i = 0; i < 10; i++) await d.g.check("release", "m1", undefined, "x", async () => 4242, good);
    expect(await d.g.check("release", "m1", undefined, "x", pid, good)).toEqual({ ok: true });
  });

  it("three wrong codes end the challenge", async () => {
    const { g, tick } = gate({ rate: 100 });
    await g.check("release", "m1", undefined, "x", pid, good);
    for (let i = 0; i < 3; i++) {
      await g.check("release", "m1", "NOPE00", "x", pid, good);
      tick(20 * 60_000);
    }
    expect((await g.check("release", "m1", "K7QM3X", "x", pid, good)).ok).toBe(false);
  });

  it("the nonce file: fresh, matching, a regular file of this user; consumed once", () => {
    const home = tmp("p2p-home-");
    const now = Date.now();
    const n = writeNonce(home, "release", "m1");
    expect((statSync(join(confirmDir(home), nonceFileName(n.secret))).mode & 0o777).toString(8)).toBe("600");
    expect((statSync(confirmDir(home)).mode & 0o777).toString(8)).toBe("700");
    expect(consumeNonce(home, "release", "m1", n, now)).toBe(true);
    expect(consumeNonce(home, "release", "m1", n, now)).toBe(false); // gone
    const other = writeNonce(home, "release", "m1");
    expect(consumeNonce(home, "decline", "m1", other, now)).toBe(false); // wrong op (and consumed)
    const stale = writeNonce(home, "release", "m1");
    expect(consumeNonce(home, "release", "m1", stale, now + 61_000)).toBe(false);
    expect(consumeNonce(home, "release", "m1", { secret: "../../x" }, now)).toBe(false);
    // A symlink where the file should be: refused.
    const target = writeNonce(home, "release", "m1");
    const decoy = writeNonce(home, "release", "m1");
    rmSync(join(confirmDir(home), nonceFileName(decoy.secret)));
    symlinkSync(join(confirmDir(home), nonceFileName(target.secret)), join(confirmDir(home), nonceFileName(decoy.secret)));
    expect(consumeNonce(home, "release", "m1", decoy, now)).toBe(false);
  });

  it("L2: reading the confirm folder isn't enough to spend the person's nonce", () => {
    const home = tmp("p2p-home-");
    const now = Date.now();
    const n = writeNonce(home, "release", "m1");
    // A sandboxed reader sees the file's name and content...
    const [name] = readdirSync(confirmDir(home));
    const content = readFileSync(join(confirmDir(home), name as string), "utf8");
    expect(content).not.toContain(n.secret);
    expect(name).not.toContain(n.secret);
    // ...and whatever it presents from them names no file (and so spends nothing).
    for (const guess of [(name as string).replace(/\.nonce$/, ""), createHash("sha256").update(content).digest("hex")]) {
      expect(consumeNonce(home, "release", "m1", { secret: guess }, now)).toBe(false);
    }
    expect(consumeNonce(home, "release", "m1", n, now)).toBe(true);
  });

  it("L1: symlinked codex/ or confirm/ folders: the CLI won't write there and the bridge won't accept from there", () => {
    const home = tmp("p2p-home-");
    const elsewhere = tmp("p2p-elsewhere-");
    mkdirSync(join(home, "codex"), { recursive: true });
    symlinkSync(elsewhere, join(home, "codex", "confirm"));
    expect(() => writeNonce(home, "release", "m1")).toThrow(/symbolic link/);
    const home2 = tmp("p2p-home-");
    const n = writeNonce(home2, "release", "m1");
    const real = join(home2, "codex");
    const moved = `${real}-real`;
    renameSync(real, moved);
    symlinkSync(moved, real);
    expect(consumeNonce(home2, "release", "m1", n, Date.now())).toBe(false);
  });

  it("a hook report is reduced to what may only tighten (no transcript mode, no thread binding)", () => {
    const r = sanitizeReport({ event: "UserPromptSubmit", mode: { permissionMode: "default", approval: "on-request", sandbox: "read-only" }, sessionId: "t", files: ["a", 1], cwd: "relative" });
    expect(r).toEqual({ event: "UserPromptSubmit", mode: { permissionMode: "default" }, files: ["a"] });
  });

  it("an over's reasons are plain words, and only ride along with over (a report can't un-private a session)", () => {
    expect(sanitizeReport({ event: "PreToolUse", over: true, overWhy: ["unresolved", "EVIL;rm -rf", 5] })).toMatchObject({ over: true, overWhy: ["unresolved"] });
    expect(sanitizeReport({ event: "PreToolUse", overWhy: ["unresolved"] })).not.toHaveProperty("overWhy");
    expect(sanitizeReport({ event: "PreToolUse", dirs: Array.from({ length: 300 }, (_, i) => `/d${i}`) })).toMatchObject({ over: true, overWhy: ["folders"] });
  });
});

describe("H1: P2P_HOME must be out of the sandbox's reach", () => {
  const bridgeWith = async (writable: string[] | "all" | undefined, o: { codexHome?: string; meta?: Record<string, unknown> } = {}) => {
    const world = new World();
    world.trusted = { mode: { approval: "on-request", sandbox: "workspace-write", autoReview: false }, seq: 1, ...(writable !== undefined ? { writable } : {}) };
    const { bridge } = await makeBridge({ world, ...(o.codexHome ? { codexHome: o.codexHome } : {}) });
    bridge.noteToolCall({ threadId: "thread-1", mode: (o.meta ?? { sandbox: "workspace-write" }) as never });
    await bridge.refreshTrusted();
    return bridge;
  };

  it("outside every writable root: allowed", async () => {
    const b = await bridgeWith(["/work/web", TMPDIR_ROOT, "/tmp"]);
    expect(b.releaseReach("/Users/ann/.p2p")).toEqual({ ok: true });
  });

  it("inside one (the repo, TMPDIR, /tmp, an extra writable root): refused", async () => {
    const b = await bridgeWith(["/Users/ann", TMPDIR_ROOT]);
    expect(b.releaseReach("/Users/ann/.p2p")).toMatchObject({ ok: false });
    expect(b.releaseReach(join(tmpdir(), "p2p-home"))).toMatchObject({ ok: false });
  });

  it("danger-full-access (rollout or _meta), unknown roots, or no rollout: refused", async () => {
    expect((await bridgeWith("all")).releaseReach("/Users/ann/.p2p").ok).toBe(false);
    expect((await bridgeWith(["/w"], { meta: { sandbox: "danger-full-access" } })).releaseReach("/Users/ann/.p2p").ok).toBe(false);
    expect((await bridgeWith(undefined)).releaseReach("/Users/ann/.p2p").ok).toBe(false);
    const { bridge } = await makeBridge();
    expect(bridge.releaseReach("/Users/ann/.p2p").ok).toBe(false);
  });

  it("planted rollout (low): CODEX_HOME inside a writable root makes the rollout untrusted, and the mode unknown", async () => {
    const b = await bridgeWith(["/Users/ann"], { codexHome: "/Users/ann/.codex", meta: { sandbox: "read-only" } });
    expect(b.untrustedTranscript).toContain("CODEX_HOME");
    expect(b.modeClass()).toBe("unknown");
    expect(b.releaseReach("/elsewhere/.p2p").ok).toBe(false);
    // A writable ~/.codex/memories (as Codex grants) doesn't reach sessions/: still trusted.
    const m = await bridgeWith(["/w", "/Users/ann/.codex/memories"], { codexHome: "/Users/ann/.codex", meta: { sandbox: "read-only" } });
    expect(m.untrustedTranscript).toBeUndefined();
  });

  it("planted rollout (low): any turn context that ever declared CODEX_HOME writable keeps the rollout untrusted", async () => {
    const world = new World();
    world.trusted = { mode: { approval: "on-request", sandbox: "read-only", autoReview: false }, seq: 2, writable: [], writableEver: ["/Users/ann"] };
    const { bridge } = await makeBridge({ world, codexHome: "/Users/ann/.codex" });
    bridge.noteToolCall({ threadId: "thread-1", mode: { sandbox: "read-only" } });
    await bridge.refreshTrusted();
    expect(bridge.untrustedTranscript).toContain("CODEX_HOME");
  });

  it("L1: a writable root inside P2P_HOME (or its confirm folder) refuses too: checked in both directions", async () => {
    const b = await bridgeWith(["/w", "/Users/ann/.p2p/codex/confirm"]);
    expect(b.releaseReach("/Users/ann/.p2p")).toMatchObject({ ok: false });
    const c = await bridgeWith(["/w", "/Users/ann/.p2p"]);
    expect(c.releaseReach("/Users/ann/.p2p")).toMatchObject({ ok: false });
  });

  it("L1: P2P_HOME reached through a symlink into a writable root, or a symlinked confirm folder: refused", async () => {
    const roots = tmp("roots-");
    const writable = join(roots, "repo");
    mkdirSync(join(writable, "p2p-home"), { recursive: true });
    const link = join(roots, "home-link");
    symlinkSync(join(writable, "p2p-home"), link);
    const b = await bridgeWith([writable]);
    expect(b.releaseReach(link)).toMatchObject({ ok: false });
    const home = join(roots, "real-home");
    mkdirSync(join(home, "codex"), { recursive: true });
    symlinkSync(tmp("elsewhere-"), join(home, "codex", "confirm"));
    expect(b.releaseReach(home)).toMatchObject({ ok: false });
  });

  it("writableRootsOf reads Codex's file-system policy and the legacy sandbox policy", () => {
    expect(
      writableRootsOf({
        file_system_sandbox_policy: {
          kind: "restricted",
          entries: [
            { path: { type: "special", value: { kind: "root" } }, access: "read" },
            { path: { type: "path", path: "/w" }, access: "write" },
            { path: { type: "special", value: { kind: "slash_tmp" } }, access: "write" },
            { path: { type: "special", value: { kind: "tmpdir" } }, access: "write" },
            { path: { type: "path", path: "/w/.git" }, access: "read" },
          ],
        },
      }),
    ).toEqual(["/w", "/tmp", "/private/tmp", TMPDIR_ROOT]);
    expect(writableRootsOf({ file_system_sandbox_policy: { kind: "restricted", entries: [{ path: { type: "special", value: { kind: "root" } }, access: "write" }] } })).toBe("all");
    expect(writableRootsOf({ file_system_sandbox_policy: { kind: "restricted", entries: [{ path: { type: "special", value: { kind: "mystery" } }, access: "write" }] } })).toBeUndefined();
    expect(writableRootsOf({ sandbox_policy: { type: "workspace-write", writable_roots: ["/m"], exclude_tmpdir_env_var: true, exclude_slash_tmp: false }, cwd: "/w", workspace_roots: ["/w2"] })).toEqual(["/m", "/w2", "/w", "/tmp", "/private/tmp"]);
    expect(writableRootsOf({ sandbox_policy: { type: "danger-full-access" } })).toBe("all");
    expect(writableRootsOf({ sandbox_policy: { type: "read-only" } })).toEqual([]);
    expect(writableRootsOf({ sandbox_policy: { type: "new-kind" } })).toBeUndefined();
  });

  it("isInside compares whole path segments", () => {
    expect(isInside("/Users/ann/.p2p", "/Users/ann", false)).toBe(true);
    expect(isInside("/Users/anna/.p2p", "/Users/ann", false)).toBe(false);
    expect(isInside("/x", "/", false)).toBe(true);
  });
});

describe("H1: the caller's pid from the OS", () => {
  it("parses macOS lsof: the peer names our socket's kernel address", () => {
    const out = ["p100", "f13", "d0xaaa", "n/tmp/x.sock", "p200", "f12", "d0xbbb", "n->0xaaa", "p300", "f5", "d0xccc", "n->0xddd"].join("\n");
    expect(parseLsofPeer(out, 100, 13)).toBe(200);
    expect(parseLsofPeer(out, 100, 99)).toBeUndefined();
  });

  it("parses Linux ss -xp: the line whose peer is our inode", () => {
    const out = [
      "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
      'u_str ESTAB 0 0 /tmp/x.sock 5001 * 5002 users:(("node",pid=100,fd=13))',
      'u_str ESTAB 0 0 * 5002 * 5001 users:(("node",pid=200,fd=12))',
    ].join("\n");
    expect(parseSsPeer(out, "5001")).toBe(200);
    expect(parseSsPeer(out, "9999")).toBeUndefined();
  });

  it("parses ss robustly when socket paths contain spaces (low)", () => {
    const out = [
      'u_str ESTAB 0 0 /home/ann/My P2P/codex/sessions/1.sock 7001 * 7002 users:(("node",pid=100,fd=13))',
      'u_str ESTAB 0 0 * 7002 /home/ann/My P2P/codex/sessions/1.sock 7001 users:(("node",pid=300,fd=12))',
      "u_str ESTAB 0 0 /x 8001 * 8002",
    ].join("\n");
    expect(parseSsPeer(out, "7001")).toBe(300);
    expect(parseSsPeer(out, "8002")).toBeUndefined();
  });

  it.skipIf(process.platform !== "darwin" && process.platform !== "linux")("finds a real caller, and sees that a child of the Codex-like process descends from it", async () => {
    const dir = tmp("p2p-peer-");
    const sock = join(dir, "s.sock");
    let seen: number | undefined;
    let descends: boolean | undefined;
    const server = await serve(sock, async (_req, conn) => {
      seen = await peerPid(conn);
      // Checked while the caller is still alive (it waits for this answer).
      if (seen !== undefined) descends = await descendsFromCodex(seen, [process.pid]);
      return { ok: true };
    });
    // A sandboxed command is a descendant of Codex; here "Codex" is this test process.
    const child = spawn(process.execPath, ["-e", `const c=require("net").createConnection(${JSON.stringify(sock)});c.on("connect",()=>c.write('{"op":"x"}\\n'));c.on("data",()=>process.exit(0));`], { stdio: "ignore" });
    await new Promise((r) => child.once("exit", r));
    server.close();
    // ss may be missing on a minimal Linux: then the code confirmation alone stands.
    if (process.platform === "darwin") expect(seen).toBe(child.pid);
    if (seen !== undefined) {
      expect(seen).toBe(child.pid);
      expect(descends).toBe(true);
    }
    expect(await descendsFromCodex(process.pid, [123456789])).toBe(false);
  });
});

describe("M3: the trusted mode comes from the thread's own rollout file", () => {
  it("finds the rollout by thread id under CODEX_HOME/sessions/YYYY/MM/DD", async () => {
    const home = tmp("codex-home-");
    const day = join(home, "sessions", "2026", "10", "21");
    mkdirSync(day, { recursive: true });
    const thread = "01a161e4-cbde-7fb2-8b50-79fefdc8d486";
    writeFileSync(join(day, `rollout-2026-10-21T10-00-00-${thread}.jsonl`), "");
    expect(await findRollout(join(home, "sessions"), thread)).toBe(join(day, `rollout-2026-10-21T10-00-00-${thread}.jsonl`));
    expect(await findRollout(join(home, "sessions"), "../../etc")).toBeUndefined();
  });

  it("reads incrementally: a turn context far back (beyond any tail) still counts; huge lines are skipped", async () => {
    const home = tmp("codex-home-");
    const day = join(home, "sessions", "2026", "10", "21");
    mkdirSync(day, { recursive: true });
    const thread = "019a0000-0000-7000-8000-000000000001";
    const file = join(day, `rollout-x-${thread}.jsonl`);
    writeFileSync(file, `${sessionMeta(thread)}\n${turnContext("on-request", "read-only", "t1")}\n`);
    // 3 MB of other lines (one of them a single 2 MB line) after it.
    appendFileSync(file, `${JSON.stringify({ type: "response_item", payload: { blob: "x".repeat(2 * 1024 * 1024) } })}\n`);
    for (let i = 0; i < 2000; i++) appendFileSync(file, `${JSON.stringify({ type: "event_msg", payload: { n: i, pad: "y".repeat(400) } })}\n`);
    const reader = new RolloutReader(home, thread);
    const first = await reader.refresh();
    expect(first).toEqual({ mode: { approval: "on-request", sandbox: "read-only", autoReview: false }, seq: 1, cwd: "/repo/web", writable: [], writableEver: [] });
    // Codex records a new turn context when the settings change: seen on the next refresh.
    appendFileSync(file, `${turnContext("never", "danger-full-access", "t2")}\n`);
    const second = await reader.refresh();
    expect(second?.seq).toBe(2);
    expect(second?.mode.approval).toBe("never");
    expect(second?.writable).toBe("all");
    expect(second?.writableEver).toBe("all");
  });

  it("M1: only prompts the person typed count (the rollout's user messages), never wrappers or the bridge's own queued pointer", async () => {
    const home = tmp("codex-home-");
    const day = join(home, "sessions", "2026", "11", "05");
    mkdirSync(day, { recursive: true });
    const thread = "019a0000-0000-7000-8000-0000000000b1";
    const file = join(day, `rollout-x-${thread}.jsonl`);
    const user = (text: string) => JSON.stringify({ type: "event_msg", payload: { type: "item_completed", item: { type: "UserMessage", id: "u", content: [{ type: "text", text, text_elements: [] }] } } });
    writeFileSync(file, `${sessionMeta(thread)}\n${turnContext("on-request", "read-only", "t1")}\n${user("fix the login form")}\n`);
    const reader = new RolloutReader(home, thread);
    expect((await reader.refresh())?.typed).toBe(1);
    appendFileSync(file, [user("<environment_context>cwd</environment_context>"), user("<peer2peer-inbox>\nMessages from Peer2Peer</peer2peer-inbox>"), user("[Peer2Peer] 1 new message from p2p:me@meme. Call the p2p_inbox tool to read it"), JSON.stringify({ type: "response_item", payload: { type: "message", role: "user", content: [{ type: "input_text", text: "not counted twice" }] } })].join("\n") + "\n");
    expect((await reader.refresh())?.typed).toBe(1);
    appendFileSync(file, `${JSON.stringify({ type: "event_msg", payload: { type: "user_message", message: "and the signup page" } })}\n`);
    expect((await reader.refresh())?.typed).toBe(2);
  });

  it("planted rollouts (low) are untrusted: two files for the thread, a foreign session_meta, a future or backwards timestamp", async () => {
    const thread = "019a0000-0000-7000-8000-00000000000a";
    const setup = (files: Record<string, string>) => {
      const home = tmp("codex-home-");
      for (const [rel, body] of Object.entries(files)) {
        const full = join(home, "sessions", rel);
        mkdirSync(join(full, ".."), { recursive: true });
        writeFileSync(full, body);
      }
      return new RolloutReader(home, thread);
    };
    const ok = `${sessionMeta(thread)}\n${turnContext("on-request", "read-only")}\n`;
    expect((await setup({ [`2026/10/21/rollout-a-${thread}.jsonl`]: ok }).refresh())?.untrusted).toBeUndefined();
    const two = await setup({ [`2026/10/21/rollout-a-${thread}.jsonl`]: ok, [`2026/10/22/rollout-b-${thread}.jsonl`]: ok }).refresh();
    expect(two?.untrusted).toContain("2 rollout files");
    expect(two?.mode).toEqual({});
    const foreign = await setup({ [`2026/10/21/rollout-a-${thread}.jsonl`]: `${sessionMeta("019a0000-0000-7000-8000-0000000000ff")}\n${turnContext("on-request", "read-only")}\n` }).refresh();
    expect(foreign?.untrusted).toContain("session_meta");
    const future = await setup({ [`2026/10/21/rollout-a-${thread}.jsonl`]: `${sessionMeta(thread, new Date(Date.now() + 3_600_000).toISOString())}\n` }).refresh();
    expect(future?.untrusted).toContain("future");
    const backwards = `${sessionMeta(thread)}\n${JSON.stringify({ timestamp: new Date(Date.now() - 3_600_000).toISOString(), type: "event_msg", payload: {} })}\n`;
    expect((await setup({ [`2026/10/21/rollout-a-${thread}.jsonl`]: backwards }).refresh())?.untrusted).toContain("backwards");
  });

  it("no turn context seen: the mode stays unknown", async () => {
    const reader = new RolloutReader(tmp("codex-home-"), "019a0000-0000-7000-8000-000000000002");
    expect(await reader.refresh()).toBeNull();
    expect(classifyMode({ transcript: {}, meta: { sandbox: "read-only" }, reportedAuto: false, confirmed: true })).toBe("unknown");
  });

  it("classifyMode: asking needs the transcript, any source may make it auto, unconfirmed is unknown", () => {
    const ask = { approval: "on-request", sandbox: "read-only", autoReview: false };
    expect(classifyMode({ transcript: ask, meta: {}, reportedAuto: false, confirmed: true })).toBe("asking");
    expect(classifyMode({ transcript: ask, meta: {}, reportedAuto: false, confirmed: false })).toBe("unknown");
    expect(classifyMode({ transcript: ask, meta: { sandbox: "workspace-write" }, reportedAuto: false, confirmed: true })).toBe("auto");
    expect(classifyMode({ transcript: ask, meta: { autoReview: true }, reportedAuto: false, confirmed: true })).toBe("auto");
    expect(classifyMode({ transcript: ask, meta: {}, reportedAuto: true, confirmed: true })).toBe("auto");
    expect(classifyMode({ transcript: { approval: "never", sandbox: "read-only" }, meta: {}, reportedAuto: false, confirmed: false })).toBe("auto");
  });

  it("screenMessage: unknown and auto hold others; own devices and listed userIds pass", () => {
    const none = parseAutoDeliver(undefined);
    const ann = "p2p:annannannannannannannannannannann";
    expect(screenMessage({ fromSelf: false, fromUserId: ann, mode: "unknown", autoDeliver: none })).toMatchObject({ deliver: false, reason: "unknown" });
    expect(screenMessage({ fromSelf: false, fromUserId: ann, mode: "auto", autoDeliver: none })).toMatchObject({ deliver: false, reason: "auto" });
    expect(screenMessage({ fromSelf: true, fromUserId: ann, mode: "auto", autoDeliver: none })).toEqual({ deliver: true });
    expect(screenMessage({ fromSelf: false, fromUserId: ann, mode: "auto", autoDeliver: parseAutoDeliver(ann) })).toEqual({ deliver: true });
  });
});

describe("lows", () => {
  it("L2: the guard also covers the bridges' registry and sockets under ~/.p2p/codex", () => {
    expect(touchesSecrets("ls ~/.p2p/codex/sessions")).toBe(true);
    expect(touchesSecrets("node -e \"require('net').connect(process.env.HOME+'/.p2p/codex/sessions/1.sock')\"")).toBe(true);
  });

  it("L5: Windows pipe names carry an unpredictable suffix", () => {
    const a = socketPath("/h", 42, "win32");
    const b = socketPath("/h", 42, "win32");
    expect(a).toMatch(/^\\\\\.\\pipe\\p2p-codex-42-[0-9a-f]{32}$/);
    expect(a).not.toBe(b);
  });
});
