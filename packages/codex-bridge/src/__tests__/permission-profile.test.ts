// Copyright 2026 Ix Infrastructure Inc.
//
// Codex 0.169.0 stopped writing `sandbox_policy` into a rollout's turn_context and writes only
// `permission_profile` (codex-rs/protocol TurnContextItem). The fixtures below are turn_context
// lines in the shapes Codex serializes: legacy (up to 0.129), both (0.130 to 0.168), profile only
// (0.169+), including a `[permissions.peer2peer]` profile that extends `:workspace` or `:read-only`
// with a deny entry, as `p2p sandbox enable --codex` writes it. Unknown shapes must keep peer
// messages held.

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { classifyMode, modeFromTranscript, parseAutoDeliver, permissionProfileOf, screenMessage, TMPDIR_ROOT, turnContextOf, writableRootsOf } from "../lib.js";
import { isTurnContextStart, RolloutReader } from "../trusted.js";
import { makeBridge, World } from "./world.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const REPO = "/Users/ann/src/web";
const P2P_HOME = "/Users/ann/.p2p";
const at = () => new Date().toISOString();
const special = (kind: string) => ({ type: "special", value: { kind } });
const path = (p: string) => ({ type: "path", path: p });

/** `:workspace` as Codex materializes it for a turn (project roots resolved to the repo). */
const workspaceEntries = [
  { path: special("root"), access: "read" },
  { path: path(REPO), access: "write" },
  { path: special("slash_tmp"), access: "write" },
  { path: special("tmpdir"), access: "write" },
  { path: path(`${REPO}/.git`), access: "read" },
  { path: path(`${REPO}/.agents`), access: "read" },
  { path: path(`${REPO}/.codex`), access: "read" },
];
const readOnlyEntries = [{ path: special("root"), access: "read" }];
const deny = { path: path(P2P_HOME), access: "deny" };
const managed = (entries: unknown[], network = "restricted") => ({ type: "managed", file_system: { type: "restricted", entries }, network });

/** One turn_context line as Codex writes it, with the permission fields given. */
const line = (fields: Record<string, unknown>, approval = "on-request", turn = "t1") =>
  JSON.stringify({
    timestamp: at(),
    type: "turn_context",
    payload: { turn_id: turn, cwd: REPO, approval_policy: approval, approvals_reviewer: "user", ...fields, model: "gpt-5.5", summary: "none" },
  });

describe("permission_profile in a turn_context (Codex 0.169.0+)", () => {
  it(":read-only: read-only, nothing writable (asking under on-request)", () => {
    const ctx = turnContextOf(line({ permission_profile: managed(readOnlyEntries), active_permission_profile: { id: ":read-only" } }));
    expect(ctx?.mode).toEqual({ approval: "on-request", sandbox: "read-only", autoReview: false });
    expect(ctx?.writable).toEqual([]);
    expect(classifyMode({ transcript: ctx!.mode, meta: {}, reportedAuto: false, confirmed: true })).toBe("asking");
  });

  it(":workspace: workspace-write with the materialized roots (auto: others' messages held)", () => {
    const ctx = turnContextOf(line({ permission_profile: managed(workspaceEntries), active_permission_profile: { id: ":workspace" } }));
    expect(ctx?.mode.sandbox).toBe("workspace-write");
    expect(ctx?.writable).toEqual([REPO, "/tmp", "/private/tmp", TMPDIR_ROOT]);
    expect(classifyMode({ transcript: ctx!.mode, meta: {}, reportedAuto: false, confirmed: true })).toBe("auto");
  });

  it("the peer2peer profile extending :workspace with a deny entry: workspace-write, the deny adds nothing writable", () => {
    const ctx = turnContextOf(line({ permission_profile: managed([...workspaceEntries, { path: path("/Users/ann/build"), access: "write" }, deny], "enabled"), active_permission_profile: { id: "peer2peer", extends: ":workspace" } }));
    expect(ctx?.mode.sandbox).toBe("workspace-write");
    expect(ctx?.writable).toEqual([REPO, "/tmp", "/private/tmp", TMPDIR_ROOT, "/Users/ann/build"]);
  });

  it("the peer2peer profile extending :read-only with a deny entry: still read-only (asking under on-request)", () => {
    const ctx = turnContextOf(line({ permission_profile: managed([...readOnlyEntries, deny, { path: { type: "glob_pattern", pattern: `${P2P_HOME}/**` }, access: "none" }]), active_permission_profile: { id: "peer2peer", extends: ":read-only" } }));
    expect(ctx?.mode).toEqual({ approval: "on-request", sandbox: "read-only", autoReview: false });
    expect(ctx?.writable).toEqual([]);
  });

  it("disabled, unrestricted and external: never read-only", () => {
    expect(permissionProfileOf({ type: "disabled" })).toEqual({ sandbox: "danger-full-access", writable: "all" });
    expect(permissionProfileOf({ type: "managed", file_system: { type: "unrestricted" }, network: "enabled" })).toEqual({ sandbox: "danger-full-access", writable: "all" });
    expect(permissionProfileOf({ type: "external", network: "restricted" })).toEqual({ sandbox: "external-sandbox" });
    expect(permissionProfileOf(managed([{ path: special("root"), access: "write" }]))).toEqual({ sandbox: "workspace-write", writable: "all" });
    const ctx = turnContextOf(line({ permission_profile: { type: "disabled" }, active_permission_profile: { id: ":danger-full-access" } }, "never"));
    expect(ctx?.mode).toEqual({ approval: "never", sandbox: "danger-full-access", autoReview: false });
    expect(ctx?.writable).toBe("all");
  });

  it("unknown shapes: no sandbox and no writable roots, so the mode is unknown and others' messages are held", () => {
    const unknown: unknown[] = [
      undefined,
      null,
      "workspace-write",
      { type: "sandboxed" },
      { type: "managed", file_system: { type: "restricted", entries: readOnlyEntries } }, // no network
      { type: "managed", file_system: { type: "restricted", entries: readOnlyEntries }, network: "partial" },
      { type: "managed", file_system: { type: "layered" }, network: "restricted" },
      { type: "managed", file_system: { type: "restricted", entries: "all" }, network: "restricted" },
      managed([{ path: special("root"), access: "read" }, { path: path(REPO), access: "append" }]),
    ];
    for (const pp of unknown) {
      const fields = pp === undefined ? {} : { permission_profile: pp };
      const ctx = turnContextOf(line(fields));
      expect(ctx?.mode.sandbox, JSON.stringify(pp)).toBeNull();
      expect(ctx?.writable, JSON.stringify(pp)).toBeUndefined();
      const mode = classifyMode({ transcript: ctx!.mode, meta: {}, reportedAuto: false, confirmed: true });
      expect(mode).toBe("unknown");
      expect(screenMessage({ fromSelf: false, fromUserId: "p2p:annannannannannannannannannannann", mode, autoDeliver: parseAutoDeliver(undefined) })).toMatchObject({ deliver: false, reason: "unknown" });
    }
  });

  it("entries it can't place leave the writable roots unknown (the sandbox counts as writing somewhere)", () => {
    for (const bad of [
      { path: special("project_roots"), access: "write" }, // not materialized
      { path: special("minimal"), access: "write" },
      { path: { type: "special", value: { kind: "unknown", path: ":future" } }, access: "write" },
      { path: { type: "glob_pattern", pattern: "/Users/ann/**" }, access: "write" },
      { path: path("relative/dir"), access: "write" },
      { path: path("file:///Users/ann/x"), access: "write" },
      "write",
    ]) {
      const ctx = turnContextOf(line({ permission_profile: managed([...readOnlyEntries, bad]) }));
      expect(ctx?.writable, JSON.stringify(bad)).toBeUndefined();
      expect(ctx?.mode.sandbox === null || ctx?.mode.sandbox === "workspace-write", JSON.stringify(bad)).toBe(true);
    }
    expect(writableRootsOf({ permission_profile: managed([{ path: path("C:\\Users\\ann\\src"), access: "write" }]) })).toEqual(["C:\\Users\\ann\\src"]);
  });
});

describe("turn contexts that carry both (Codex 0.130.0 to 0.168.x)", () => {
  it("the legacy fields decide as before; a readable profile can only widen them", () => {
    const legacy = { sandbox_policy: { type: "read-only" } };
    // Agreeing: unchanged.
    expect(turnContextOf(line({ ...legacy, permission_profile: managed(readOnlyEntries) }))?.mode.sandbox).toBe("read-only");
    // A profile that writes overrides a read-only sandbox_policy, and adds its roots.
    const wider = turnContextOf(line({ ...legacy, permission_profile: managed(workspaceEntries) }));
    expect(wider?.mode.sandbox).toBe("workspace-write");
    expect(wider?.writable).toEqual([REPO, "/tmp", "/private/tmp", TMPDIR_ROOT]);
    // A narrower profile never narrows a broader sandbox_policy.
    const ws = { sandbox_policy: { type: "workspace-write", writable_roots: [], exclude_tmpdir_env_var: true, exclude_slash_tmp: true } };
    const narrow = turnContextOf(line({ ...ws, permission_profile: managed(readOnlyEntries) }));
    expect(narrow?.mode.sandbox).toBe("workspace-write");
    expect(narrow?.writable).toEqual([REPO]);
    expect(turnContextOf(line({ sandbox_policy: { type: "danger-full-access" }, permission_profile: managed(readOnlyEntries) }))?.writable).toBe("all");
    expect(turnContextOf(line({ ...legacy, permission_profile: { type: "disabled" } }))?.writable).toBe("all");
    // A profile whose roots it can't read makes them unknown, whatever the legacy fields say (Codex enforces the profile).
    const unresolved = managed([{ path: special("root"), access: "read" }, { path: special("project_roots"), access: "write" }]);
    expect(turnContextOf(line({ ...ws, permission_profile: unresolved }))?.writable).toBeUndefined();
    // An unreadable legacy policy stays unknown whatever the profile says.
    expect(turnContextOf(line({ sandbox_policy: { type: "new-kind" }, permission_profile: managed(readOnlyEntries) }))?.writable).toBeUndefined();
  });

  it("a read-only sandbox_policy beside a profile it can't fully read: releases refused (roots unknown)", () => {
    const legacy = { sandbox_policy: { type: "read-only" } };
    const cases: [string, unknown, string | null][] = [
      ["external", { type: "external", network: "restricted" }, "external-sandbox"],
      ["unknown type", { type: "sandboxed", level: 2 }, null],
      ["glob write", managed([...readOnlyEntries, { path: { type: "glob_pattern", pattern: `${P2P_HOME}/**` }, access: "write" }]), "workspace-write"],
    ];
    for (const [name, pp, sandbox] of cases) {
      const ctx = turnContextOf(line({ ...legacy, permission_profile: pp }));
      expect(ctx?.writable, name).toBeUndefined();
      expect(ctx?.mode.sandbox, name).toBe(sandbox);
      expect(classifyMode({ transcript: ctx!.mode, meta: {}, reportedAuto: false, confirmed: true }), name).not.toBe("asking");
    }
  });

  it("sandbox_policy: null beside a read-only profile: unknown, not read-only", () => {
    const ctx = turnContextOf(line({ sandbox_policy: null, permission_profile: managed(readOnlyEntries) }));
    expect(ctx?.mode.sandbox).toBeNull();
    expect(ctx?.writable).toBeUndefined();
    expect(classifyMode({ transcript: ctx!.mode, meta: {}, reportedAuto: false, confirmed: true })).toBe("unknown");
  });

  it("an object-form approval_policy (granular) is unknown: held", () => {
    const ctx = turnContextOf(line({ permission_profile: managed(readOnlyEntries) }, { granular: { sandbox_approval: true, rules: true, mcp_elicitations: true } } as unknown as string));
    expect(ctx?.mode.approval).toBeNull();
    const mode = classifyMode({ transcript: ctx!.mode, meta: {}, reportedAuto: false, confirmed: true });
    expect(mode).toBe("unknown");
    expect(screenMessage({ fromSelf: false, fromUserId: "p2p:annannannannannannannannannannann", mode, autoDeliver: parseAutoDeliver(undefined) })).toMatchObject({ deliver: false });
  });

  it("legacy only (up to 0.129) reads as before", () => {
    expect(modeFromTranscript(line({ sandbox_policy: { type: "read-only" } }))).toEqual({ approval: "on-request", sandbox: "read-only", autoReview: false });
    expect(turnContextOf(line({ sandbox_policy: "danger-full-access" }))?.mode.sandbox).toBe("danger-full-access");
  });
});

describe("a 0.169+ rollout end to end", () => {
  const rollout = (lines: string[]) => {
    const home = mkdtempSync(join(tmpdir(), "codex-home-"));
    dirs.push(home);
    const thread = "019a0000-0000-7000-8000-0000000001a9";
    const day = join(home, "sessions", "2026", "11", "19");
    mkdirSync(day, { recursive: true });
    const meta = JSON.stringify({ timestamp: at(), type: "session_meta", payload: { id: thread, session_id: thread, cwd: REPO } });
    writeFileSync(join(day, `rollout-2026-11-19T09-00-00-${thread}.jsonl`), [meta, ...lines].join("\n") + "\n");
    return new RolloutReader(home, thread);
  };

  it("read-only profile: the session asks, so messages are delivered; workspace profile: auto, held", async () => {
    const asking = await rollout([line({ permission_profile: managed([...readOnlyEntries, deny]), active_permission_profile: { id: "peer2peer", extends: ":read-only" } })]).refresh();
    expect(asking).toMatchObject({ mode: { approval: "on-request", sandbox: "read-only", autoReview: false }, writable: [], writableEver: [] });
    const world = new World();
    world.trusted = asking;
    const { bridge } = await makeBridge({ world });
    bridge.noteToolCall({ threadId: "thread-1" });
    await bridge.refreshTrusted();
    expect(bridge.modeClass()).toBe("asking");

    world.trusted = await rollout([line({ permission_profile: managed([...workspaceEntries, deny]), active_permission_profile: { id: "peer2peer", extends: ":workspace" } })]).refresh();
    await bridge.refreshTrusted();
    expect(bridge.modeClass()).toBe("auto");
  });

  it("an external profile (beside a read-only sandbox_policy too): auto, and releases refused", async () => {
    for (const fields of [{ permission_profile: { type: "external", network: "restricted" } }, { sandbox_policy: { type: "read-only" }, permission_profile: { type: "external", network: "enabled" } }]) {
      const t = await rollout([line(fields)]).refresh();
      expect(t?.writable).toBeUndefined();
      const world = new World();
      world.trusted = t;
      const { bridge } = await makeBridge({ world });
      bridge.noteToolCall({ threadId: "thread-1" });
      await bridge.refreshTrusted();
      expect(bridge.modeClass()).toBe("auto");
      expect(bridge.releaseReach(P2P_HOME).ok).toBe(false);
    }
  });

  it("a turn context line too long to read distrusts the rollout from there (the earlier mode doesn't stay in force)", async () => {
    const big = JSON.stringify({ timestamp: at(), type: "turn_context", payload: { turn_id: "t2", cwd: REPO, approval_policy: "never", permission_profile: { type: "disabled" }, pad: "x".repeat(2 * 1024 * 1024) } });
    const reader = rollout([line({ permission_profile: managed(readOnlyEntries) }), big, JSON.stringify({ timestamp: at(), type: "event_msg", payload: {} })]);
    const t = await reader.refresh();
    expect(t?.untrusted).toContain("too long");
    expect(t?.mode).toEqual({});
    // A huge line of another kind is still just skipped.
    const other = await rollout([line({ permission_profile: managed(readOnlyEntries) }), JSON.stringify({ timestamp: at(), type: "response_item", payload: { blob: "y".repeat(2 * 1024 * 1024) } })]).refresh();
    expect(other?.untrusted).toBeUndefined();
    expect(other?.mode.sandbox).toBe("read-only");
    expect(isTurnContextStart('{"timestamp":"2026-11-19T09:00:00.000Z","type":"turn_context","payload":{')).toBe(true);
    expect(isTurnContextStart('{"timestamp":"2026-11-19T09:00:00.000Z","type":"response_item","payload":{"text":"\\"type\\":\\"turn_context\\""')).toBe(false);
  });

  it("an unrecognised profile: unknown, held, and releases refused", async () => {
    const t = await rollout([line({ permission_profile: { type: "sandboxed", level: 2 } })]).refresh();
    expect(t?.mode.sandbox).toBeNull();
    expect(t?.writable).toBeUndefined();
    expect(t?.writableEver).toBe("unknown");
    const world = new World();
    world.trusted = t;
    const { bridge } = await makeBridge({ world });
    bridge.noteToolCall({ threadId: "thread-1" });
    await bridge.refreshTrusted();
    expect(bridge.modeClass()).toBe("unknown");
    expect(bridge.releaseReach(P2P_HOME).ok).toBe(false);
  });
});
