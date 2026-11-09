// Copyright 2026 Ix Infrastructure Inc.
//
// Local graph as memory (epic #41 piece 2; SPEC.md §10): the context of this device's own sessions,
// written into the person's local Ix graph as it happens. `p2p watch` gathers it from the statuses
// the session posted (packages/p2p/src/graph-memory.ts), queues it, and hands it here in batches,
// off the hook path. Per session:
//
//   ix session --json create p2p-<sid> --purpose=<label, repo, branch> --actor=p2p:<address> --ttl=720
//   ix note --tag=note --session=<its id> --actor=p2p:<address> --json   < "Session started …"
//                                                                         < "Status: …"
//                                                                         < "Edited: a.ts, b.ts"
//                                                                         < "Session ended …"
//
// Every call goes through the guarded runner (ix.ts guardRunner): the graph target of the session
// (p2p's chokepoint) must be local, the `ix` that answers must have the OSS `ix note` / `ix session`
// (never Ix Pro's, which write to the cloud org), and each write must say on stderr that it reached
// the local endpoint. Text goes on stdin only. Nothing here is a peer's: it is this person's own
// sessions, written to their own machine.

import { createHash } from "node:crypto";
import type { ExtContext, ExtMemory, ExtMemoryItem, ExtMemoryResult, ExtMemoryUnavailable } from "@peer2peer/cli";
import { isSafeRelativePath } from "@peer2peer/core/v3";
import { checkedTarget, IX_ACTOR_RE, IX_SESSION_NAME_RE, IX_SESSION_REF_RE, ixAvailable, MAX_PURPOSE, memoryRefusal, memorySupport, type IxRunner } from "./ix.js";
import { IxExtError } from "./text.js";

/** How long Ix keeps a session record: 30 days. */
export const MEMORY_TTL_HOURS = 720;
/** At most this many sessions' Ix ids are remembered (ExtContext.kv is 64 KiB). */
export const MAX_MEMORY_SESSIONS = 50;
/** Longest one-line text written per item (characters). */
export const MAX_MEMORY_LINE = 300;
/** At most this many files named per note. */
export const MAX_MEMORY_FILES = 50;
/** Bound on one `ix` call made for memory. */
export const MEMORY_IX_TIMEOUT_MS = 15_000;

const KV_KEY = "memory";

interface MemoryKv {
  /** Peer2Peer session id → its Ix session id. */
  sessions: Record<string, { id: string; at: number }>;
}

/** One line: control and format characters dropped, whitespace collapsed, capped. */
export function oneLine(s: unknown, max = MAX_MEMORY_LINE): string {
  if (typeof s !== "string") return "";
  const t = s
    .replace(/[\p{Cc}\p{Cf}\u2028\u2029]+/gu, " ")
    .replace(/\s+/g, " ")
    .trim();
  const cps = [...t];
  return cps.length > max ? `${cps.slice(0, max - 1).join("")}…` : t;
}

/** The Ix session name of Peer2Peer session `sid`: `p2p-<sid>`, or `p2p-` and its hash when the id doesn't fit. */
export function memorySessionName(sid: string): string {
  const name = `p2p-${sid}`;
  return IX_SESSION_NAME_RE.test(name) ? name : `p2p-${createHash("sha256").update(sid).digest("hex").slice(0, 32)}`;
}

/** `--actor=`: `p2p:<address>` when the address is a plain one, else `p2p`. */
export function memoryActor(address: string | undefined): string {
  const a = `p2p:${address ?? ""}`;
  return IX_ACTOR_RE.test(a) ? a : "p2p";
}

const iso = (ms: number) => (Number.isFinite(ms) && ms > 0 ? new Date(ms).toISOString() : new Date().toISOString());

/** Where a session runs, in words: `label (repo widgets, branch main)`. */
function where(i: Pick<ExtMemoryItem, "label" | "repo" | "branch">): string {
  const label = oneLine(i.label, 64) || "session";
  const bits = [i.repo ? `repo ${oneLine(i.repo, 100)}` : "", i.branch ? `branch ${oneLine(i.branch, 100)}` : ""].filter(Boolean);
  return bits.length ? `${label} (${bits.join(", ")})` : label;
}

/** The session record's purpose (one line, at most MAX_PURPOSE characters). */
export function memoryPurpose(i: Pick<ExtMemoryItem, "label" | "repo" | "branch">): string {
  return oneLine(`Peer2Peer session ${where(i)}`, MAX_PURPOSE);
}

/** The note text of one item; undefined when there is nothing to write (an empty status, no valid file). */
export function memoryText(i: ExtMemoryItem): string | undefined {
  switch (i.kind) {
    case "start":
      return `Session started ${iso(i.at)}: ${where(i)}.`;
    case "status": {
      const s = oneLine(i.summary);
      return s ? `Status (${iso(i.at)}): ${s}` : undefined;
    }
    case "files": {
      const files = [...new Set((i.files ?? []).filter((f) => typeof f === "string" && f.length <= 300 && isSafeRelativePath(f) && oneLine(f, 300) === f))];
      if (files.length === 0) return undefined;
      const shown = files.slice(0, MAX_MEMORY_FILES);
      return `Edited (${iso(i.at)}): ${shown.join(", ")}${files.length > shown.length ? ` and ${files.length - shown.length} more` : ""}`;
    }
    case "end":
      return `Session ended ${iso(i.at)}.`;
    default:
      return undefined;
  }
}

async function loadKv(ctx: ExtContext): Promise<MemoryKv> {
  const v = (await ctx.kv.get(KV_KEY)) as Partial<MemoryKv> | undefined;
  const sessions: MemoryKv["sessions"] = {};
  if (v && typeof v.sessions === "object" && v.sessions !== null) {
    for (const [sid, s] of Object.entries(v.sessions)) if (s && typeof s.id === "string" && IX_SESSION_REF_RE.test(s.id) && typeof s.at === "number") sessions[sid] = { id: s.id, at: s.at };
  }
  return { sessions };
}

async function saveKv(ctx: ExtContext, kv: MemoryKv): Promise<void> {
  const kept = Object.entries(kv.sessions)
    .sort((a, b) => a[1].at - b[1].at)
    .slice(-MAX_MEMORY_SESSIONS);
  await ctx.kv.set(KV_KEY, { sessions: Object.fromEntries(kept) });
}

/** An error's reason code (IxExtError's, else ix_failed). */
const reasonOf = (e: unknown) => (e instanceof IxExtError ? e.code : "ix_failed");

/** Reasons that stop a batch and turn memory off until available() says otherwise. */
const STOPS = new Set(["graph_target", "ix_unconfirmed", "ix_missing"]);

/** What available() reports for a support answer that isn't "oss". */
function unavailable(support: "pro" | "none", installed: boolean): ExtMemoryUnavailable {
  if (!installed) return { ok: false, reason: "ix_missing", message: "Ix isn't installed: graph memory is off (https://github.com/ix-infrastructure/Ix)" };
  const e = memoryRefusal(support, { kind: "local", endpoint: "" });
  return { ok: false, reason: support === "pro" ? "ix_pro" : "ix_upgrade", message: e.message };
}

/**
 * The memory writer. `runner(ctx, sid)` is the guarded runner of a call made for session `sid`
 * (extension.ts runner: pinned to that session's graph target, OSS-only for note and session).
 */
export function ixMemory(runner: (ctx: ExtContext, sid?: string) => IxRunner): ExtMemory {
  return {
    v: 1,
    available: async (ctx) => {
      const ix = runner(ctx);
      if (!(await ixAvailable(ix))) return unavailable("none", false);
      const s = await memorySupport(ix);
      return s === "oss" ? { ok: true } : unavailable(s, true);
    },
    write: async (ctx, batch): Promise<ExtMemoryResult> => {
      const items = Array.isArray(batch?.items) ? batch.items : [];
      const sid = typeof batch?.sid === "string" ? batch.sid : "";
      if (items.length === 0 || sid === "") return { written: 0 };
      // The chokepoint first, for the whole batch: anything but local is refused, before any `ix` runs.
      let target;
      try {
        target = ctx.graphTarget ? checkedTarget(await ctx.graphTarget({ sid })) : checkedTarget(undefined);
      } catch {
        target = checkedTarget(undefined);
      }
      if (target.kind !== "local") {
        return { written: 0, failed: [{ reason: "not_local", n: items.length, message: "graph memory goes to the local graph only, and this session's target isn't local" }] };
      }
      const ix = runner(ctx, sid);
      const actor = memoryActor((await ctx.self().catch(() => undefined))?.address);
      const kv = await loadKv(ctx);
      let written = 0;
      const failed = new Map<string, { n: number; message?: string }>();
      const fail = (reason: string, n: number, message?: string) => {
        const f = failed.get(reason) ?? { n: 0 };
        failed.set(reason, { n: f.n + n, message: message ?? f.message });
      };
      const sessionId = async (first: ExtMemoryItem): Promise<string> => {
        const known = kv.sessions[sid];
        if (known) return known.id;
        const argv = ["session", "--json", "create", memorySessionName(sid), `--purpose=${memoryPurpose(first)}`, `--actor=${actor}`, `--ttl=${MEMORY_TTL_HOURS}`];
        const r = await ix.run(argv, { timeoutMs: MEMORY_IX_TIMEOUT_MS });
        if (r.code !== 0) throw new IxExtError("ix_failed", `ix session create failed (exit ${r.code})`);
        let id: unknown;
        try {
          id = (JSON.parse(r.stdout) as { sessionId?: unknown }).sessionId;
        } catch {
          id = undefined;
        }
        if (typeof id !== "string" || !IX_SESSION_REF_RE.test(id)) throw new IxExtError("ix_failed", "ix session create printed no session id");
        kv.sessions[sid] = { id, at: Date.now() };
        await saveKv(ctx, kv);
        return id;
      };
      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        const text = memoryText(item);
        if (text === undefined) continue;
        try {
          const ixSession = await sessionId(item);
          const r = await ix.run(["note", "--tag=note", `--session=${ixSession}`, `--actor=${actor}`, "--json"], { stdin: text, timeoutMs: MEMORY_IX_TIMEOUT_MS });
          if (r.code !== 0) throw new IxExtError("ix_failed", `ix note failed (exit ${r.code})`);
          written++;
        } catch (e) {
          const reason = reasonOf(e);
          const message = e instanceof Error ? e.message : undefined;
          if (STOPS.has(reason)) {
            fail(reason, items.length - i, message);
            const support = (e as IxExtError).extra?.ix;
            return {
              written,
              failed: [...failed].map(([r, f]) => ({ reason: r, ...f })),
              unavailable: { ok: false, reason: support === "pro" ? "ix_pro" : support === "upgrade" ? "ix_upgrade" : reason, message: message ?? reason },
            };
          }
          fail(reason, 1, message);
        }
      }
      return { written, ...(failed.size ? { failed: [...failed].map(([reason, f]) => ({ reason, ...f })) } : {}) };
    },
  };
}
