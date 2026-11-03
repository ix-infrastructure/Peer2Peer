// Copyright 2026 Ix Infrastructure Inc.
//
// Measuring a session's footprint with the local Ix (SPEC.md §8.2), per
// actor: the main loop, then each subagent in the session's status.
//
//   1. Checkout and graph. The main loop and agents editing the session's own
//      checkout use its graph ("base"). An agent in its own git worktree uses
//      that worktree's graph when Ix has mapped it ("worktree"), otherwise the
//      main checkout's graph with the worktree's repo-relative paths ("base"),
//      and its hunks on the merge base's side, which is what that graph holds.
//      An unmapped checkout gives a file-level actor ("none").
//   2. Changed files: the actor's files from the status, plus (worktree
//      agents) `git diff --name-only <merge-base>`, which catches Bash edits.
//   3. Changed symbols: `git diff -U0` hunks, then per file
//      `ix impact <file> --format json --limit 50` (risk, regions, and member
//      spans) and `ix around <file>:<start>-<end> --format json` for up to 3
//      hunk groups (the definitions the edit touched, innermost first). A file
//      whose edits name no symbol falls back to `ix overview`'s key items
//      (coarse).
//   4. Ring 1: the callers, users, tests and importers `ix around` reports.
//   5. Ring 2 (depth 2): `ix around` of the first ring-1 files.
//
// Every `ix` call is bounded: at most `maxCalls` per computation, each with a
// timeout, all within one budget (40 s, inside p2p's 60 s command deadline);
// what doesn't fit is marked `partial`. Results are cached per (checkout,
// file, mtime, size, hunks), so an unchanged file costs no Ix call.

import { join } from "node:path";
import type { IxRunner } from "./ix.js";
import { FP_LIMITS, symbolKey, type FpComponent, type FpGraph, type FpRel, type FpSymbolRel, type RawActor } from "./footprint.js";
import { isSafeRelativePath } from "@peer2peer/core/v3";
import { cps, isObj, LIMITS, line, RISK_LEVELS, scrubPaths, toRepoRelative, type O, type RiskLevel } from "./text.js";

export const FOOTPRINT_BUDGET_MS = 40_000;
export const FOOTPRINT_MAX_CALLS = 80;
const PER_CALL_MS = 12_000;
/** Files measured at once (each runs up to 4 `ix` processes together). */
const CONCURRENCY = 2;
/** Agents count while running or waiting, or for this long after their last activity. */
export const AGENT_RECENT_MS = 10 * 60_000;
const MAX_AGENTS = FP_LIMITS.actors - 1;
const RING2_FROM = 5;
const HUNK_GROUPS = 3;
const HUNK_GAP = 30;

export interface Range {
  start: number;
  end: number;
}

export interface AgentLike {
  id: string;
  state: string;
  files?: string[];
  wt?: true | boolean;
  branch?: string;
  at: number;
}

export interface ComputeDeps {
  ix: IxRunner;
  /** git's stdout, or undefined on failure. */
  git(cwd: string, args: string[], opts?: { maxBuffer?: number; trim?: boolean; timeoutMs?: number }): Promise<string | undefined>;
  stat(abs: string): Promise<{ mtimeMs: number; size: number } | undefined>;
  now(): number;
}

/** One file's measured result, plain names (what the cache holds). */
export interface FileResult {
  inGraph: boolean;
  risk: RiskLevel;
  symbols: { k: string; kind: string }[];
  coarse?: boolean;
  partial?: boolean;
  ring1Files: { f: string; rel: FpRel }[];
  ring1Symbols: { k: string; rel: FpSymbolRel }[];
  components: FpComponent[];
  newSymbols?: string[];
}

export interface FileCache {
  get(key: string): FileResult | undefined;
  set(key: string, value: FileResult): void;
}

export interface ComputeInput {
  /** The session's checkout (absolute; local only, never sent). */
  root: string;
  /** Every spelling of `root` (symlinks), for making Ix's paths repo-relative. */
  roots?: string[];
  own: { files: string[]; agents?: AgentLike[] };
  depth?: 1 | 2;
  /** This machine's home directory and host name: scrubbed from every name Ix gives (region and symbol names). */
  home?: string;
  hostname?: string;
  budgetMs?: number;
  maxCalls?: number;
  cache?: FileCache;
}

export interface ComputeResult {
  actors: RawActor[];
  /** `ix` invocations made. */
  calls: number;
  /** Whether the session's own checkout is mapped by Ix. */
  mapped: boolean;
  partial: boolean;
}

// ---------------------------------------------------------------------------
// git diff

export interface FileDiff {
  /** Ranges on the old (merge-base / HEAD) side. */
  old: Range[];
  /** Ranges on the new (working tree) side. */
  new: Range[];
  /** Added lines (for naming symbols that exist only on the new side). */
  added: string[];
}

/** Reads `git diff -U0` output (core.quotePath=false) into per-file hunks. Quoted (unusual) paths are skipped. */
export function parseUnifiedDiff(text: string): Map<string, FileDiff> {
  const out = new Map<string, FileDiff>();
  let cur: FileDiff | undefined;
  let oldPath: string | undefined;
  for (const l of text.split("\n")) {
    if (l.startsWith("diff --git ")) {
      cur = undefined;
      oldPath = undefined;
      continue;
    }
    if (l.startsWith("--- ")) {
      oldPath = l.startsWith("--- a/") ? l.slice(6) : undefined;
      continue;
    }
    if (l.startsWith("+++ ")) {
      const p = l.startsWith("+++ b/") ? l.slice(6) : oldPath;
      cur = p ? (out.get(p) ?? { old: [], new: [], added: [] }) : undefined;
      if (p && cur) out.set(p, cur);
      continue;
    }
    const h = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(l);
    if (h && cur) {
      const os = Number(h[1]);
      const oc = h[2] === undefined ? 1 : Number(h[2]);
      const ns = Number(h[3]);
      const nc = h[4] === undefined ? 1 : Number(h[4]);
      // A side with no lines is the point the change sits after (at least line 1).
      cur.old.push(oc === 0 ? { start: Math.max(1, os), end: Math.max(1, os) } : { start: os, end: os + oc - 1 });
      cur.new.push(nc === 0 ? { start: Math.max(1, ns), end: Math.max(1, ns) } : { start: ns, end: ns + nc - 1 });
      continue;
    }
    if (cur && l.startsWith("+") && !l.startsWith("+++") && cur.added.length < 400) cur.added.push(l.slice(1));
  }
  return out;
}

/** At most `max` ranges: neighbours within `gap` lines merge, then the closest pairs until few enough. */
export function groupRanges(ranges: Range[], max = HUNK_GROUPS, gap = HUNK_GAP): Range[] {
  const sorted = [...ranges].sort((a, b) => a.start - b.start || a.end - b.end);
  const out: Range[] = [];
  for (const r of sorted) {
    const last = out[out.length - 1];
    if (last && r.start - last.end <= gap) last.end = Math.max(last.end, r.end);
    else out.push({ ...r });
  }
  while (out.length > max) {
    let j = 0;
    for (let i = 1; i < out.length - 1; i++) if (out[i + 1].start - out[i].end < out[j + 1].start - out[j].end) j = i;
    out.splice(j, 2, { start: out[j].start, end: Math.max(out[j].end, out[j + 1].end) });
  }
  return out;
}

const DIFF_ARGS = ["-c", "core.quotePath=false", "diff", "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames", "-U0"];

// ---------------------------------------------------------------------------
// Bounded Ix calls

type IxAnswer = { ok: true; json: O } | { ok: false; json?: O; skipped?: boolean };

class Budget {
  calls = 0;
  partial = false;
  constructor(
    private readonly ix: IxRunner,
    readonly deadline: number,
    private readonly maxCalls: number,
    private readonly now: () => number,
  ) {}

  async json(argv: string[], cwd: string): Promise<IxAnswer> {
    const left = this.deadline - this.now();
    if (this.calls >= this.maxCalls || left < 500) {
      this.partial = true;
      return { ok: false, skipped: true };
    }
    this.calls++;
    let r;
    try {
      r = await this.ix.run(argv, { cwd, timeoutMs: Math.min(PER_CALL_MS, left) });
    } catch {
      // A timeout, or Ix vanished mid-run: this file is partial.
      this.partial = true;
      return { ok: false, skipped: true };
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(r.stdout);
    } catch {
      return { ok: false };
    }
    if (!isObj(parsed)) return { ok: false };
    if (r.code !== 0 || typeof parsed.error === "string") return { ok: false, json: parsed };
    return { ok: true, json: parsed };
  }
}

/**
 * git inside the same budget: each call's timeout is what is left of it (at most its own), and
 * none starts once the budget is spent. A timed-out git is killed (SIGKILL), like a timed-out ix.
 */
function budgetedGit(deps: ComputeDeps, b: Budget): ComputeDeps["git"] {
  return async (cwd, args, o = {}) => {
    const left = b.deadline - deps.now();
    if (left < 500) {
      b.partial = true;
      return undefined;
    }
    return deps.git(cwd, args, { ...o, timeoutMs: Math.min(o.timeoutMs ?? 5_000, left) });
  };
}

async function pool<T, R>(items: T[], n: number, f: (x: T, i: number) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await f(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
  return out;
}

// ---------------------------------------------------------------------------
// One file

const rows = (sec: unknown): O[] => (isObj(sec) && Array.isArray(sec.rows) ? (sec.rows as unknown[]).filter(isObj) : []);
const num = (v: unknown): number | undefined => (typeof v === "number" && Number.isSafeInteger(v) && v > 0 ? v : undefined);
const str = (v: unknown): string | undefined => (typeof v === "string" && v.trim() !== "" ? v.trim() : undefined);
const kindOf = (v: unknown): string => {
  const s = str(v)?.toLowerCase().replace(/[^a-z0-9_-]/g, "_").slice(0, 32);
  return s && /^[a-z]/.test(s) ? s : "unknown";
};

interface Def {
  name: string;
  kind: string;
  start: number;
  end: number;
}

/** `name` qualified by the innermost other definition whose span holds it (Ix's `container.name`), when there is one. */
function qualify(d: Def, defs: Def[]): string {
  if (d.name.includes(".")) return d.name;
  let best: Def | undefined;
  for (const o of defs) {
    if (o === d || o.name === d.name) continue;
    const holds = o.start <= d.start && o.end >= d.end && o.end - o.start > d.end - d.start;
    if (holds && (!best || o.end - o.start < best.end - best.start)) best = o;
  }
  return best ? `${best.name.split(".").pop()}.${d.name}` : d.name;
}

const overlaps = (d: Def, ranges: Range[]) => ranges.some((r) => d.start <= r.end && d.end >= r.start);

const DECL_RES = [
  /^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?(?:async\s+)?(?:function\*?|class|interface|enum|type|struct|trait|def|fn|func|object|record)\s+([A-Za-z_$][\w$]*)/,
  /^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\(|function\b)/,
  /^\s*func\s+\([^)]*\)\s*([A-Za-z_]\w*)/,
  /^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)/,
];

/** Names declared on added lines: symbols that may exist only on the new side. */
export function declaredNames(added: string[]): string[] {
  const out: string[] = [];
  for (const l of added) {
    for (const re of DECL_RES) {
      const m = re.exec(l);
      if (m) {
        if (!out.includes(m[1])) out.push(m[1]);
        break;
      }
    }
  }
  return out;
}

/** A name from Ix as it may leave this machine: local paths, the home directory, e-mail and host name scrubbed, one sanitized line. */
export type Scrub = (name: string, max: number) => string | undefined;
export function nameScrubber(roots: string[], home?: string, hostname?: string): Scrub {
  return (name, max) => {
    const s = line(scrubPaths(name, { root: roots, home, hostname }), max).trim();
    return s === "" ? undefined : s;
  };
}

async function fileFootprint(b: Budget, cwd: string, roots: string[], file: string, ranges: Range[] | undefined, scrub: Scrub): Promise<FileResult> {
  const rel = (p: unknown) => (typeof p === "string" ? toRepoRelative(p, roots) : undefined);
  const res: FileResult = { inGraph: false, risk: "unknown", symbols: [], ring1Files: [], ring1Symbols: [], components: [] };
  // A path Ix would read as an option is measured at file level only.
  if (file.startsWith("-")) return { ...res, coarse: true };
  const groups = ranges && ranges.length ? groupRanges(ranges) : [];
  const [impact, ...arounds] = await Promise.all([
    b.json(["impact", file, "--format", "json", "--limit", "50"], cwd),
    ...(groups.length ? groups.map((g) => b.json(["around", `${file}:${g.start}-${g.end}`, "--format", "json", "--limit", "20"], cwd)) : [b.json(["around", file, "--format", "json", "--limit", "20"], cwd)]),
  ]);
  if ([impact, ...arounds].some((a) => !a.ok && a.skipped)) res.partial = true;
  const defs: Def[] = [];
  const changed: Def[] = [];
  const addDef = (list: Def[], d: Def) => {
    if (!list.some((x) => x.name === d.name && x.start === d.start)) list.push(d);
  };
  if (impact.ok) {
    res.inGraph = true;
    const j = impact.json;
    if ((RISK_LEVELS as readonly string[]).includes(String(j.riskLevel))) res.risk = j.riskLevel as RiskLevel;
    for (const bkt of Array.isArray(j.propagationBuckets) ? j.propagationBuckets : []) {
      if (!isObj(bkt)) continue;
      // Region names come from the graph: scrubbed like any free text that leaves (impact.ts buildImpact).
      const raw = str(bkt.region);
      const n = raw ? scrub(raw, LIMITS.region) : undefined;
      if (!n) continue;
      const kind = str(bkt.regionKind) ? kindOf(bkt.regionKind) : undefined;
      res.components.push({ n, ...(kind ? { kind } : {}), count: Math.min(FP_LIMITS.counts, num(bkt.count) ?? 0) });
    }
    for (const m of Array.isArray(j.topImpactedMembers) ? j.topImpactedMembers : []) {
      if (!isObj(m) || rel(m.path) !== file) continue;
      const raw = str(m.name);
      const name = raw ? scrub(raw, LIMITS.symbol) : undefined;
      const start = num(m.lineStart);
      if (!name || name === "(unnamed)" || !start) continue;
      const d = { name, kind: kindOf(m.kind), start, end: num(m.lineEnd) ?? start };
      addDef(defs, d);
      if (groups.length && overlaps(d, ranges!)) addDef(changed, d);
    }
  }
  for (const a of arounds) {
    if (!a.ok) continue;
    res.inGraph = true;
    const j = a.json;
    for (const s of Array.isArray(j.symbols) ? j.symbols : []) {
      if (!isObj(s)) continue;
      // Only the file asked about (a row elsewhere, or outside the repo, is dropped), its name scrubbed.
      if (s.path !== undefined && rel(s.path) !== file) continue;
      const rawName = str(s.name);
      const name = rawName ? scrub(rawName, LIMITS.symbol) : undefined;
      const start = num(s.lineStart);
      if (name && start) {
        const d = { name, kind: kindOf(s.kind), start, end: num(s.lineEnd) ?? start };
        addDef(defs, d);
        // With a line range, `ix around` names exactly the definitions the edit touched.
        if (groups.length) addDef(changed, d);
      }
      // Without hunks, only the file's importers count (the symbols it picks weren't necessarily touched).
      if (!groups.length) continue;
      const ring = (sec: unknown, r: FpRel) => {
        for (const row of rows(sec)) {
          const p = rel(row.path);
          if (!p) continue;
          if (p !== file) res.ring1Files.push({ f: p, rel: r });
          const rawNm = str(row.name);
          const nm = rawNm ? scrub(rawNm, LIMITS.symbol) : undefined;
          if (nm && (r === "call" || r === "use")) {
            const k = symbolKey(p, nm);
            if (k) res.ring1Symbols.push({ k, rel: r });
          }
        }
      };
      ring(s.callers, "call");
      ring(s.users, "use");
      ring(s.tests, "test");
    }
    for (const row of rows(j.importers)) {
      const p = rel(row.path);
      if (p && p !== file) res.ring1Files.push({ f: p, rel: "import" });
    }
  }
  // Innermost first, as `ix around` does: a definition around another changed one (a class around
  // the method whose body changed) isn't itself a change to every user of it.
  const inner = changed.filter((d) => !changed.some((o) => o !== d && d.start <= o.start && d.end >= o.end && d.end - d.start > o.end - o.start));
  inner.sort((x, y) => x.start - y.start || (x.name < y.name ? -1 : 1));
  for (const d of inner) {
    const k = symbolKey(file, qualify(d, defs));
    if (k && !res.symbols.some((s) => s.k === k)) res.symbols.push({ k, kind: d.kind });
  }
  if (res.inGraph && res.symbols.length === 0 && groups.length) {
    // Edits that name no definition Ix knows: the file's key items, marked coarse.
    res.coarse = true;
    const ov = await b.json(["overview", file, "--format", "json"], cwd);
    if (!ov.ok && ov.skipped) res.partial = true;
    if (ov.ok) {
      for (const it of Array.isArray(ov.json.keyItems) ? ov.json.keyItems.slice(0, 10) : []) {
        if (!isObj(it)) continue;
        const rawName = str(it.name);
        const name = rawName ? scrub(rawName, LIMITS.symbol) : undefined;
        const k = name ? symbolKey(file, name) : undefined;
        if (k && !res.symbols.some((s) => s.k === k)) res.symbols.push({ k, kind: kindOf(it.kind) });
      }
    }
  }
  if (!groups.length) res.coarse = true;
  return res;
}

// ---------------------------------------------------------------------------
// Actors

interface ActorSpec {
  a: string;
  graph: FpGraph;
  /** Where Ix runs (the checkout whose graph is used). */
  ixCwd: string;
  /** Where the actor's files are (for mtimes). */
  checkout: string;
  files: string[];
  /** Per file: the ranges in the graph's coordinates; undefined when there are no hunks. */
  ranges: Map<string, Range[]>;
  added: Map<string, string[]>;
  wt?: boolean;
  branch?: string;
  base?: string;
  done?: boolean;
  /** Only symbols on the new side can be new: a worktree measured against the base graph. */
  wantNew: boolean;
  /** The graph's last ingest, when it is the actor's own checkout's (stale check). */
  lastIngestAt?: number;
  /** The graph's last ingest, whichever graph it is (a re-map invalidates cached results). */
  graphIngest?: number;
}

const ingestTime = (j: O | undefined): number | undefined => {
  const t = typeof j?.lastIngestAt === "string" ? Date.parse(j.lastIngestAt) : NaN;
  return Number.isFinite(t) ? t : undefined;
};

function diffsToRanges(diffs: Map<string, FileDiff> | undefined, files: string[], side: "old" | "new") {
  const ranges = new Map<string, Range[]>();
  const added = new Map<string, string[]>();
  for (const f of files) {
    const d = diffs?.get(f);
    if (!d) continue;
    ranges.set(f, d[side]);
    added.set(f, d.added);
  }
  return { ranges, added };
}

/** Bumped whenever what a cached FileResult holds changes (v2: names scrubbed, rows outside the repo dropped). */
export const FILE_CACHE_VERSION = 2;
const cacheKey = (graph: FpGraph, cwd: string, ingest: number | undefined, file: string, st: { mtimeMs: number; size: number } | undefined, ranges: Range[] | undefined) =>
  JSON.stringify([FILE_CACHE_VERSION, graph, cwd, ingest ?? 0, file, st?.mtimeMs ?? 0, st?.size ?? 0, ranges ?? null]);

async function measureActor(b: Budget, deps: ComputeDeps, spec: ActorSpec, roots: string[], scrub: Scrub, cache?: FileCache): Promise<RawActor> {
  const actor: RawActor = {
    a: spec.a,
    graph: spec.graph,
    ...(spec.wt ? { wt: true } : {}),
    ...(spec.branch ? { branch: spec.branch } : {}),
    ...(spec.base ? { base: spec.base } : {}),
    ...(spec.done ? { done: true } : {}),
    risk: "unknown",
    files: spec.files,
    symbols: [],
    ring1Files: [],
    ring1Symbols: [],
    components: [],
  };
  if (spec.graph === "none") return { ...actor, coarse: true };
  const results = await pool(spec.files, CONCURRENCY, async (file) => {
    const st = await deps.stat(join(spec.checkout, file));
    const ranges = spec.ranges.get(file);
    const key = cacheKey(spec.graph, spec.ixCwd, spec.graphIngest, file, st, ranges);
    let r = cache?.get(key);
    if (!r) {
      r = await fileFootprint(b, spec.ixCwd, roots, file, ranges, scrub);
      if (!r.partial) cache?.set(key, r);
    }
    const stale = spec.lastIngestAt !== undefined && st !== undefined && st.mtimeMs > spec.lastIngestAt;
    return { file, r, stale };
  });
  const risks: RiskLevel[] = [];
  const newSyms: string[] = [];
  for (const { file, r, stale } of results) {
    risks.push(r.risk);
    actor.symbols.push(...r.symbols);
    actor.ring1Files.push(...r.ring1Files);
    actor.ring1Symbols.push(...r.ring1Symbols);
    actor.components.push(...r.components);
    if (r.coarse) actor.coarse = true;
    if (r.partial) actor.partial = true;
    if (stale) actor.stale = true;
    // A symbol declared on the new side that the graph doesn't name.
    if (spec.wantNew || !r.inGraph) {
      const known = new Set(r.symbols.map((s) => s.k.slice(s.k.indexOf("#") + 1).split(".").pop()));
      for (const n of declaredNames(spec.added.get(file) ?? [])) {
        const k = known.has(n) ? undefined : symbolKey(file, n);
        if (k && !newSyms.includes(k)) newSyms.push(k);
      }
    }
  }
  if (newSyms.length) actor.newSymbols = newSyms.slice(0, FP_LIMITS.newSymbols);
  const order: RiskLevel[] = ["unknown", "low", "medium", "high", "critical"];
  actor.risk = risks.reduce<RiskLevel>((m, r) => (order.indexOf(r) > order.indexOf(m) ? r : m), "unknown");
  return actor;
}

/** Ring 2: `ix around` of the first ring-1 files (not tests): who calls, uses or imports them. */
async function ring2(b: Budget, spec: ActorSpec, actor: RawActor, roots: string[]): Promise<string[]> {
  const seen = new Set([...spec.files, ...actor.ring1Files.map((x) => x.f)]);
  const from = [...new Set(actor.ring1Files.filter((x) => x.rel !== "test").map((x) => x.f))].filter((f) => !f.startsWith("-")).slice(0, RING2_FROM);
  const out: string[] = [];
  const answers = await pool(from, CONCURRENCY, (f) => b.json(["around", f, "--format", "json", "--limit", "20"], spec.ixCwd));
  for (const a of answers) {
    if (!a.ok) {
      if (a.skipped) actor.partial = true;
      continue;
    }
    const add = (p: unknown) => {
      const r = typeof p === "string" ? toRepoRelative(p, roots) : undefined;
      if (r && !seen.has(r)) {
        seen.add(r);
        out.push(r);
      }
    };
    for (const s of Array.isArray(a.json.symbols) ? a.json.symbols : []) {
      if (!isObj(s)) continue;
      for (const row of [...rows(s.callers), ...rows(s.users)]) add(row.path);
    }
    for (const row of rows(a.json.importers)) add(row.path);
  }
  return out.slice(0, FP_LIMITS.ring2Files);
}

/** `git worktree list --porcelain`: worktree path by branch (refs/heads/ stripped). */
export function parseWorktrees(text: string): Map<string, string> {
  const out = new Map<string, string>();
  let path: string | undefined;
  for (const l of text.split("\n")) {
    if (l.startsWith("worktree ")) path = l.slice(9);
    else if (l.startsWith("branch ") && path) out.set(l.slice(7).replace(/^refs\/heads\//, ""), path);
    else if (l === "") path = undefined;
  }
  return out;
}

/** Repo-relative paths only: no control or bidi characters, no git-quoted names (`"…"`), nothing core's `files` rule refuses. */
const safeFiles = (fs: readonly string[]) =>
  [...new Set(fs.filter((f) => typeof f === "string" && !f.startsWith('"') && isSafeRelativePath(f) && cps(f) <= LIMITS.path && line(f, LIMITS.path) === f && !/[\p{Cc}\p{Cf}]/u.test(f)))];

/** Measures every actor (SPEC.md §8.2). Never throws for an Ix or git failure: what fails is coarse or partial. */
export async function computeFootprint(input: ComputeInput, deps: ComputeDeps): Promise<ComputeResult> {
  const now = deps.now();
  const b = new Budget(deps.ix, now + (input.budgetMs ?? FOOTPRINT_BUDGET_MS), input.maxCalls ?? FOOTPRINT_MAX_CALLS, deps.now);
  const roots = [...new Set([input.root, ...(input.roots ?? [])])];
  const root = input.root;
  const scrub = nameScrubber(roots, input.home, input.hostname);
  deps = { ...deps, git: budgetedGit(deps, b) };
  const st = await b.json(["status", "--format", "json", "--root", root], root);
  const mapped = st.ok && st.json.graphCompleted === true;
  const rootIngest = mapped ? ingestTime(st.ok ? st.json : undefined) : undefined;
  const specs: ActorSpec[] = [];
  const headDiff = async (files: string[]) => {
    if (files.length === 0) return undefined;
    const out = await deps.git(root, [...DIFF_ARGS, "HEAD", "--", ...files], { maxBuffer: 4 << 20, trim: false, timeoutMs: 10_000 });
    return out === undefined ? undefined : parseUnifiedDiff(out);
  };
  const mainFiles = safeFiles(input.own.files).slice(0, FP_LIMITS.files);
  if (mainFiles.length) {
    const { ranges, added } = diffsToRanges(await headDiff(mainFiles), mainFiles, "new");
    specs.push({ a: "main", graph: mapped ? "base" : "none", ixCwd: root, checkout: root, files: mainFiles, ranges, added, wantNew: false, lastIngestAt: rootIngest, graphIngest: rootIngest });
  }
  const agents = (input.own.agents ?? [])
    .filter((x) => /^a[1-9][0-9]{0,3}$/.test(x.id))
    .filter((x) => x.state === "running" || x.state === "waiting" || now - x.at < AGENT_RECENT_MS)
    .filter((x) => (x.files?.length ?? 0) > 0 || x.wt)
    .slice(0, MAX_AGENTS);
  let worktrees: Map<string, string> | undefined;
  let rootHead: string | undefined;
  for (const ag of agents) {
    const done = ag.state === "done" || ag.state === "failed";
    const files0 = safeFiles(ag.files ?? []);
    if (!ag.wt) {
      const files = files0.slice(0, FP_LIMITS.files);
      const { ranges, added } = diffsToRanges(await headDiff(files), files, "new");
      specs.push({ a: ag.id, graph: mapped ? "base" : "none", ixCwd: root, checkout: root, files, ranges, added, done, wantNew: false, lastIngestAt: rootIngest, graphIngest: rootIngest });
      continue;
    }
    worktrees ??= parseWorktrees((await deps.git(root, ["worktree", "list", "--porcelain"])) ?? "");
    rootHead ??= await deps.git(root, ["rev-parse", "HEAD"]);
    const wtPath = ag.branch ? worktrees.get(ag.branch) : undefined;
    if (!wtPath || !rootHead) {
      // Its worktree isn't found here (removed, or another machine's): file level, against the base graph.
      const files = files0.slice(0, FP_LIMITS.files);
      specs.push({ a: ag.id, graph: mapped ? "base" : "none", ixCwd: root, checkout: root, files, ranges: new Map(), added: new Map(), wt: true, branch: ag.branch, done, wantNew: false, graphIngest: rootIngest });
      continue;
    }
    const wst = await b.json(["status", "--format", "json", "--root", wtPath], wtPath);
    const own = wst.ok && wst.json.graphCompleted === true;
    const graph: FpGraph = own ? "worktree" : mapped ? "base" : "none";
    const mb = await deps.git(wtPath, ["merge-base", "HEAD", rootHead]);
    const base = mb && /^[0-9a-f]{7,64}$/.test(mb) ? mb : undefined;
    const names = base ? ((await deps.git(wtPath, ["-c", "core.quotePath=false", "diff", "--name-only", "--no-renames", base])) ?? "").split("\n").filter(Boolean) : [];
    const files = safeFiles([...files0, ...names]).slice(0, FP_LIMITS.files);
    const raw = base && files.length ? await deps.git(wtPath, [...DIFF_ARGS, base, "--", ...files], { maxBuffer: 4 << 20, trim: false, timeoutMs: 10_000 }) : undefined;
    // The base graph holds the merge base's lines, so its side of each hunk; the worktree's own graph, the new side.
    const { ranges, added } = diffsToRanges(raw === undefined ? undefined : parseUnifiedDiff(raw), files, own ? "new" : "old");
    specs.push({
      a: ag.id,
      graph,
      ixCwd: own ? wtPath : root,
      checkout: wtPath,
      files,
      ranges,
      added,
      wt: true,
      branch: ag.branch,
      ...(base ? { base: base.slice(0, 12) } : {}),
      done,
      wantNew: !own,
      lastIngestAt: own ? ingestTime(wst.ok ? wst.json : undefined) : undefined,
      graphIngest: own ? ingestTime(wst.ok ? wst.json : undefined) : rootIngest,
    });
  }
  const actors: RawActor[] = [];
  for (const spec of specs) {
    const actor = await measureActor(b, deps, spec, spec.ixCwd === root ? roots : [spec.ixCwd], scrub, input.cache);
    if (input.depth === 2 && spec.graph !== "none" && actor.ring1Files.length) actor.ring2Files = await ring2(b, spec, actor, spec.ixCwd === root ? roots : [spec.ixCwd]);
    actors.push(actor);
  }
  return { actors, calls: b.calls, mapped, partial: b.partial };
}
