// Copyright 2026 Ix Infrastructure Inc.
//
// The mode sources the bridge trusts, read by the bridge itself:
//   - this thread's own rollout file, `CODEX_HOME/sessions/**/rollout-*-<thread>.jsonl`.
//     Codex writes it, outside the sandbox's writable roots, so a sandboxed
//     command can't forge a turn context there. The thread id comes only
//     from `_meta` on a tool call, which Codex builds (never from a hook).
// The file is read incrementally from where the last read stopped, so a
// turn context far back in a long session is still seen (Codex writes one
// only when the settings change). No turn context seen: the mode is unknown.
//
// A planted file is refused: more than one file for the thread, a first
// line that isn't this thread's `session_meta`, or timestamps that run
// backwards or into the future make the whole file untrusted. (The bridge
// also refuses it when CODEX_HOME is inside a writable root: Bridge.)

import { open, readdir } from "node:fs/promises";
import { join } from "node:path";
import { turnContextOf, type CodexMode } from "./lib.js";

export type TrustedMode = {
  mode: CodexMode;
  seq: number;
  cwd?: string;
  /** Where sandboxed commands may write, per the latest turn context (see writableRootsOf). */
  writable?: string[] | "all";
  /**
   * Every root any turn context in the file has declared writable ("all", or
   * "unknown" once one couldn't be read). CODEX_HOME must stay outside all of
   * them: Codex records the first turn context before the model runs any
   * command, so a sandbox that could plant a file here has already said so.
   */
  writableEver?: string[] | "all" | "unknown";
  /** Why the file isn't trusted at all (planted or malformed): then nothing in it counts. */
  untrusted?: string;
};

export interface TranscriptSource {
  /** The latest turn context seen (and how many have been seen), or null with none. */
  refresh(): Promise<TrustedMode | null>;
}

const CHUNK = 256 * 1024;
/** A turn context is a few KB; a longer line is skipped rather than buffered. */
const MAX_LINE = 1024 * 1024;
/** Clock skew allowed for a timestamp "in the future". */
const FUTURE_SLACK_MS = 5 * 60_000;

/** Every rollout file of `threadId` under `sessionsDir` (YYYY/MM/DD folders). */
export async function findRollouts(sessionsDir: string, threadId: string, depth = 4): Promise<string[]> {
  if (!/^[0-9A-Za-z-]{8,80}$/.test(threadId)) return [];
  const suffix = `-${threadId}.jsonl`;
  const out: string[] = [];
  const walk = async (dir: string, left: number): Promise<void> => {
    let names: string[];
    try {
      names = await readdir(dir);
    } catch {
      return;
    }
    for (const name of names) {
      if (name.startsWith("rollout-") && name.endsWith(suffix)) out.push(join(dir, name));
      else if (left > 0 && /^\d+$/.test(name)) await walk(join(dir, name), left - 1);
    }
  };
  await walk(sessionsDir, depth);
  return out.sort();
}

/** The one rollout file of `threadId`, or undefined (none, or more than one: possibly planted). */
export async function findRollout(sessionsDir: string, threadId: string, depth = 4): Promise<string | undefined> {
  const all = await findRollouts(sessionsDir, threadId, depth);
  return all.length === 1 ? all[0] : undefined;
}

/** Reads one thread's rollout file as it grows, keeping its latest turn context. */
export class RolloutReader implements TranscriptSource {
  private path: string | undefined;
  private offset = 0;
  private partial = "";
  private last: TrustedMode | null = null;
  private seq = 0;
  private isSkipping = false;
  private isFirstLine = true;
  private lastAt = 0;
  private untrusted: string | undefined;
  private ever: Set<string> | "all" | "unknown" = new Set();

  constructor(
    private readonly codexHome: string,
    readonly threadId: string,
    private readonly now: () => number = Date.now,
  ) {}

  private distrust(why: string): TrustedMode {
    this.untrusted ??= why;
    this.last = { mode: {}, seq: this.seq, untrusted: this.untrusted };
    return this.last;
  }

  async refresh(): Promise<TrustedMode | null> {
    if (this.untrusted) return this.last;
    if (!this.path) {
      const all = await findRollouts(join(this.codexHome, "sessions"), this.threadId);
      if (all.length > 1) return this.distrust(`${all.length} rollout files claim this thread`);
      this.path = all[0];
    }
    if (!this.path) return this.last;
    let fh;
    try {
      fh = await open(this.path, "r");
    } catch {
      return this.last;
    }
    try {
      const { size } = await fh.stat();
      if (size < this.offset) return this.distrust("the rollout file shrank");
      while (this.offset < size) {
        const buf = Buffer.alloc(Math.min(CHUNK, size - this.offset));
        const { bytesRead } = await fh.read(buf, 0, buf.length, this.offset);
        if (bytesRead === 0) break;
        this.offset += bytesRead;
        const lines = (this.partial + buf.subarray(0, bytesRead).toString("utf8")).split("\n");
        this.partial = lines.pop() ?? "";
        if (this.isSkipping && lines.length > 0) {
          // The rest of a huge line (an image, a big tool output): never a turn context.
          lines.shift();
          this.isSkipping = false;
        }
        if (this.partial.length > MAX_LINE) {
          this.partial = "";
          this.isSkipping = true;
        }
        for (const line of lines) {
          const bad = this.check(line);
          if (bad) return this.distrust(bad);
          const ctx = turnContextOf(line);
          if (ctx) {
            this.seq += 1;
            if (this.ever instanceof Set) {
              if (ctx.writable === undefined) this.ever = "unknown";
              else if (ctx.writable === "all") this.ever = "all";
              else for (const r of ctx.writable) this.ever.add(r);
            }
            this.last = {
              mode: ctx.mode,
              seq: this.seq,
              ...(ctx.cwd ? { cwd: ctx.cwd } : {}),
              ...(ctx.writable !== undefined ? { writable: ctx.writable } : {}),
              writableEver: this.ever instanceof Set ? [...this.ever] : this.ever,
            };
          }
        }
      }
    } finally {
      await fh.close();
    }
    return this.last;
  }

  /** Why a line makes the file untrusted, or undefined: the first must be this thread's session_meta; times never run backwards or ahead. */
  private check(line: string): string | undefined {
    if (line.trim() === "") return undefined;
    const ts = /^\{"timestamp":"([^"]{10,40})"/.exec(line)?.[1];
    if (this.isFirstLine) {
      this.isFirstLine = false;
      try {
        const v = JSON.parse(line) as { type?: string; payload?: { id?: unknown; session_id?: unknown } };
        if (v.type !== "session_meta" || (v.payload?.id !== this.threadId && v.payload?.session_id !== this.threadId)) return "the rollout file doesn't start with this thread's session_meta";
      } catch {
        return "the rollout file's first line isn't JSON";
      }
    }
    if (ts !== undefined) {
      const at = Date.parse(ts);
      if (Number.isFinite(at)) {
        if (at > this.now() + FUTURE_SLACK_MS) return "a rollout timestamp is in the future";
        if (at + 60_000 < this.lastAt) return "rollout timestamps run backwards";
        this.lastAt = Math.max(this.lastAt, at);
      }
    }
    return undefined;
  }
}
