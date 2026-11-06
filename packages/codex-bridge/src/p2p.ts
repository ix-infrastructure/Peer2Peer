// Copyright 2026 Ix Infrastructure Inc.
//
// The bridge's calls to the `p2p` CLI, as child processes (argv, no shell),
// mirroring the Claude mod's backend (mods/claude/peer2peer/hooks/backend.ts).
// The bridge never touches keys: `p2p` holds the identity and device keys,
// seals and verifies every envelope, and keeps its state in P2P_HOME.
// Peer-derived positionals follow `--` and peer-derived option values use
// `--opt=value`, so neither can be read as a flag. Message text goes over
// stdin (`--stdin`), never argv, so it never shows in a process listing.
//
// Only read-only and session-scoped verbs are here: whoami, ls, status, send,
// held (list), friends, session roster (read, no change) and watch. Nothing
// that changes who reaches this user (join, approve, relays, invite, …).

import { spawn } from "node:child_process";
import { inert } from "./lib.js";
import type { PeerRow } from "./lib.js";

export type RunResult = { exitCode: number; stdout: string; stderr: string };

/** Runs a command by argv. */
export interface Exec {
  run(argv: readonly string[], init?: { stdin?: string; timeoutMs?: number }): Promise<RunResult>;
}

export type Outcome<T> = { ok: true; value: T } | { ok: false; error: string; reason: string };

const TIMEOUT_MS = 30_000;

/** Exec over node's child_process with the given environment. */
export function nodeExec(env: NodeJS.ProcessEnv = process.env): Exec {
  return {
    run: (argv, init) =>
      new Promise<RunResult>((resolve, reject) => {
        const child = spawn(argv[0] as string, argv.slice(1), { env, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
        let stdout = "";
        let stderr = "";
        const timer = setTimeout(() => child.kill("SIGKILL"), init?.timeoutMs ?? TIMEOUT_MS);
        child.stdout.on("data", (d) => (stdout += String(d)));
        child.stderr.on("data", (d) => (stderr = `${stderr}${String(d)}`.slice(-8_000)));
        child.on("error", (e) => {
          clearTimeout(timer);
          reject(e);
        });
        child.on("close", (code) => {
          clearTimeout(timer);
          resolve({ exitCode: code ?? 1, stdout, stderr });
        });
        child.stdin.on("error", () => {});
        child.stdin.end(init?.stdin ?? "");
      }),
  };
}

/** The JSON object a `--json` command printed (its last line), or null. */
export function parseJson<T>(stdout: string): T | null {
  const lines = stdout.trim().split("\n");
  try {
    return JSON.parse(lines.at(-1) ?? "") as T;
  } catch {
    return null;
  }
}

export type Whoami = { userId: string; name: string; address: string; did: string; relays: string[] };
export type HeldItem = { id: string; type: string; from: string; at: number; address: string; summary: string; cid?: string };
export type RosterView = { sid: string; ref: string; vis: "circle" | "private"; circle?: string; parts: { userId: string; address: string }[] };
export type SendResult = { delivered: boolean; to: { userId: string; address: string; own: string; sid: string; ref: string }; relays: number };
/** What `p2p status` says about the session's projects (projects.ts). */
export type ProjectInfo = { projects: { id: string; name: string }[]; policy: "private" | "shared" | "none"; why?: string; circles?: string[]; people?: string[] };
export type RelaysInfo = { listed: string[]; connected: string[]; failed: { url: string; reason: string }[] };

export class P2P {
  constructor(
    private readonly exec: Exec,
    /** The `p2p` command, argv[0] first. */
    readonly bin: readonly string[],
  ) {}

  /** Runs `p2p <args> --json` and parses its one JSON object. Never rejects. */
  async call<T>(args: readonly string[], init: { stdin?: string; timeoutMs?: number } = {}): Promise<Outcome<T>> {
    const dash = args.indexOf("--");
    const argv = dash < 0 ? [...args, "--json"] : [...args.slice(0, dash), "--json", ...args.slice(dash)];
    let ran: RunResult;
    try {
      ran = await this.exec.run([...this.bin, ...argv], { timeoutMs: init.timeoutMs ?? TIMEOUT_MS, ...(init.stdin !== undefined ? { stdin: init.stdin } : {}) });
    } catch (e) {
      return { ok: false, error: "cli_missing", reason: `could not run ${this.bin.join(" ")}: ${inert(String((e as Error)?.message ?? e))}` };
    }
    const parsed = parseJson<Record<string, unknown>>(ran.stdout);
    if (ran.exitCode === 0 && parsed !== null) return { ok: true, value: parsed as T };
    const error = typeof parsed?.error === "string" ? parsed.error : ran.exitCode === 0 ? "unreadable" : "failed";
    const last = ran.stderr.trim().split("\n").pop() ?? "";
    const reason = typeof parsed?.reason === "string" ? parsed.reason : last || `p2p ${args[0] ?? ""} exited ${ran.exitCode}`;
    return { ok: false, error, reason: inert(reason) };
  }

  whoami(): Promise<Outcome<Whoami>> {
    return this.call<Whoami>(["whoami"]);
  }

  async ls(): Promise<Outcome<{ peers: PeerRow[]; relays?: RelaysInfo }>> {
    const r = await this.call<{ peers: PeerRow[]; relays?: RelaysInfo }>(["ls"]);
    if (!r.ok) return r;
    return { ok: true, value: { peers: Array.isArray(r.value.peers) ? r.value.peers : [], ...(r.value.relays ? { relays: r.value.relays } : {}) } };
  }

  /**
   * This session's status. Never a mode: what this session auto-approves is nobody else's business.
   * `projectDirs`: every folder the session has worked in (projects.ts binds each one's project).
   */
  status(o: { session: string; state: "busy" | "idle"; label: string; repo?: string; branch?: string; summary?: string; files?: readonly string[]; projectDirs?: readonly string[]; projectDirsOver?: boolean }, timeoutMs?: number) {
    const args = ["status", `--session=${o.session}`, `--state=${o.state}`, `--label=${o.label}`];
    if (o.repo) args.push(`--repo=${o.repo}`);
    if (o.branch) args.push(`--branch=${o.branch}`);
    if (o.summary) args.push(`--summary=${o.summary}`);
    for (const file of o.files ?? []) args.push(`--file=${file}`);
    for (const dir of o.projectDirs ?? []) args.push(`--project-dir=${dir}`);
    if (o.projectDirsOver) args.push("--project-dirs-over");
    return this.call<{ delivered: unknown[]; failed: { address: string; error: string }[]; roster?: RosterView; warnings?: string[]; project?: ProjectInfo }>(args, timeoutMs !== undefined ? { timeoutMs } : {});
  }

  /** A message from this session; refused (`not_shared`) to anyone its projects don't share (projects.ts). */
  send(o: { fromSession: string; to: string; text: string; notifyWhenIdle?: boolean; projectDirs?: readonly string[]; projectDirsOver?: boolean }): Promise<Outcome<SendResult>> {
    const dirs = [...(o.projectDirs ?? []).map((d) => `--project-dir=${d}`), ...(o.projectDirsOver ? ["--project-dirs-over"] : [])];
    return this.call<SendResult>(["send", `--from-session=${o.fromSession}`, `--to=${o.to}`, ...(o.notifyWhenIdle ? ["--notify-when-idle"] : []), ...dirs, "--stdin"], { stdin: o.text });
  }

  /**
   * `p2p own-agents`, read only: whether this user's agent sessions' messages skip the hold
   * (`deliver`), or only those from some other devices (`devices`). Setting it is the person's, in a terminal.
   */
  ownAgents(): Promise<Outcome<{ ownAgents: "hold" | "deliver"; devices: string[] | "all-other" }>> {
    return this.call(["own-agents"]);
  }

  /** This session's roster, read only (the default circle, else private). Changing it is the person's, in a terminal. */
  async roster(sid: string): Promise<Outcome<RosterView>> {
    const r = await this.call<{ roster: RosterView }>(["session", "roster", "--", sid]);
    return r.ok ? { ok: true, value: r.value.roster } : r;
  }

  async held(): Promise<Outcome<HeldItem[]>> {
    const r = await this.call<{ held: HeldItem[] }>(["held"]);
    return r.ok ? { ok: true, value: Array.isArray(r.value.held) ? r.value.held : [] } : r;
  }
}
