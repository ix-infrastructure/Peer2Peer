// Copyright 2026 Ix Infrastructure Inc.
//
// x:ix.footprint (SPEC.md §8): a session's code footprint as its local Ix
// sees it: per actor (the main loop and each subagent), the symbols it
// changed, the code one hop downstream of them (ring 1, optionally ring 2)
// and the architecture regions involved. It is a state kind (protocol §4.3
// "Extension state kinds"): published to the session's status audience,
// kept latest-wins by the receiver, never an event, never shown to a model.
//
// This file is the wire: the body's types, strict validation on receive, and
// assembling a body from what footprint-compute.ts measured: stable names,
// hashed names (hmac.ts), per-actor caps, the per-session merge and the
// deterministic trimming that keeps a body within 16 KiB.

import { createHash } from "node:crypto";
import { isSafeRelativePath } from "@peer2peer/core/v3";
import { hashFile, hashRegion, hashSymbol, HMAC_TOKEN_RE, KEY_ID_RE, type NameKey } from "./hmac.js";
import { parseRepo, type RepoRef } from "./repo.js";
import { cps, fail, isObj, jsonBytes, LIMITS, line, list, oneOf, optInt, relPath, RISK_LEVELS, type O, type RiskLevel } from "./text.js";

export const FOOTPRINT_KIND = "x:ix.footprint" as const;
/** Seconds a footprint stays valid at the receiver without a newer one (it is republished every 5 min while unchanged). */
export const FOOTPRINT_TTL = 600;
/** The body's cap: `{v, body}` must fit p2p's 16 KiB state value (EXT_STATE_MAX_BYTES). */
export const MAX_FOOTPRINT_BYTES = 16 * 1024 - 64;

export const FP_LIMITS = {
  actors: 9,
  files: 25,
  changed: 40,
  newSymbols: 10,
  ring1Files: 60,
  ring1Symbols: 60,
  ring2Files: 100,
  components: 25,
  /** A symbol's qualified key, after `path#`. */
  qualifiedKey: 200,
  counts: 1_000_000,
} as const;

export const FP_GRAPHS = ["base", "worktree", "branch", "none"] as const;
export type FpGraph = (typeof FP_GRAPHS)[number];
export const FP_RELS = ["call", "use", "test", "import"] as const;
export type FpRel = (typeof FP_RELS)[number];
export const FP_SYMBOL_RELS = ["call", "use"] as const;
export type FpSymbolRel = (typeof FP_SYMBOL_RELS)[number];
export const FP_NAMES = ["plain", "hmac"] as const;
export type FpNames = (typeof FP_NAMES)[number];

export interface FpComponent {
  /** A region name, or its hmac token. */
  n: string;
  kind?: string;
  count: number;
}

export interface FpActor {
  /** "main", or the status agent id ("a1", …). */
  a: string;
  graph: FpGraph;
  wt?: true;
  branch?: string;
  /** The merge base a worktree agent's diff was taken against. */
  base?: string;
  risk: RiskLevel;
  stale?: true;
  coarse?: true;
  partial?: true;
  changed: { files: string[]; symbols: { k: string; kind: string }[]; new?: string[] };
  ring1: { files: { f: string; rel: FpRel }[]; symbols: { k: string; rel: FpSymbolRel }[] };
  ring2?: { files: string[] };
  components: FpComponent[];
}

export interface FootprintBody {
  repo: RepoRef;
  at: number;
  seq: number;
  names: FpNames;
  keyId?: string;
  actors: FpActor[];
  merged: { components: FpComponent[]; risk: RiskLevel; counts: { changedSymbols: number; ring1Files: number; ring2Files: number } };
  truncated?: true;
}

// ---------------------------------------------------------------------------
// Names (§8.3): repo-relative `path`, `path#qualifiedKey`, region names.

const QK_RE = /^[A-Za-z_$][A-Za-z0-9_$.:#<>,]{0,199}$/;
const KIND_RE = /^[A-Za-z][A-Za-z0-9_-]{0,31}$/;
const AGENT_RE = /^(?:main|a[1-9][0-9]{0,3})$/;
const BRANCH_RE = /^[A-Za-z0-9._/+@-]{1,128}$/;
const BASE_RE = /^[0-9a-f]{7,64}$/;

/** A qualified key as the wire allows it: disallowed characters become "_" (deterministic), at most 200. */
export function wireQualifiedKey(qk: string): string | undefined {
  let s = qk.trim().replace(/[^A-Za-z0-9_$.:#<>,]/g, "_");
  if (s === "") return undefined;
  if (!/^[A-Za-z_$]/.test(s)) s = `_${s}`;
  s = s.slice(0, FP_LIMITS.qualifiedKey);
  return QK_RE.test(s) ? s : undefined;
}

/** `path#qualifiedKey`, or undefined when either part can't be sent. A path containing "#" has no symbol keys. */
export function symbolKey(path: string, qualifiedKey: string): string | undefined {
  if (path.includes("#") || !isSafeRelativePath(path) || cps(path) > LIMITS.path) return undefined;
  const qk = wireQualifiedKey(qualifiedKey);
  return qk ? `${path}#${qk}` : undefined;
}

function parseFile(v: unknown, names: FpNames, what: string): string {
  if (names === "hmac") {
    if (typeof v !== "string" || !HMAC_TOKEN_RE.test(v)) return fail(`${what} must be an h: token`);
    return v;
  }
  return relPath(v, what);
}

function parseSymbolKey(v: unknown, names: FpNames, what: string): string {
  if (typeof v !== "string") return fail(`${what} must be a string`);
  if (names === "hmac") {
    if (!HMAC_TOKEN_RE.test(v)) return fail(`${what} must be an h: token`);
    return v;
  }
  const i = v.indexOf("#");
  if (i <= 0) return fail(`${what} must be path#qualifiedKey`);
  relPath(v.slice(0, i), `${what} (its path)`);
  if (!QK_RE.test(v.slice(i + 1))) return fail(`${what} has a qualified key the wire doesn't allow`);
  return v;
}

function parseRegion(v: unknown, names: FpNames, what: string): string {
  if (typeof v !== "string") return fail(`${what} must be a string`);
  if (names === "hmac") {
    if (!HMAC_TOKEN_RE.test(v)) return fail(`${what} must be an h: token`);
    return v;
  }
  if (v.trim() !== v || v === "" || cps(v) > LIMITS.region || line(v, LIMITS.region) !== v) return fail(`${what} must be a plain region name of 1-${LIMITS.region}`);
  return v;
}

function parseKind(o: O, k: string, what: string, required: boolean): string | undefined {
  const v = o[k];
  if (v === undefined && !required) return undefined;
  if (typeof v !== "string" || !KIND_RE.test(v)) return fail(`${what}.${k} must be an entity kind`);
  return v;
}

function optTrue(o: O, k: string, what: string): true | undefined {
  const v = o[k];
  if (v === undefined) return undefined;
  if (v !== true) return fail(`${what}.${k} may only be true`);
  return true;
}

const int = (o: O, k: string, what: string, max: number = FP_LIMITS.counts): number => {
  const n = optInt(o, k, what, max);
  if (n === undefined) return fail(`${what}.${k} is required`);
  return n;
};

function parseComponents(o: O, names: FpNames, what: string): FpComponent[] {
  if (o.components === undefined) return fail(`${what}.components is required`);
  return list(o, "components", FP_LIMITS.components, what, (x, i) => {
    const w = `${what}.components[${i}]`;
    if (!isObj(x)) return fail(`${w} must be an object`);
    const n = parseRegion(x.n, names, `${w}.n`);
    const kind = parseKind(x, "kind", w, false);
    return { n, ...(kind ? { kind } : {}), count: int(x, "count", w) };
  });
}

function obj(v: unknown, what: string): O {
  if (!isObj(v)) return fail(`${what} must be an object`);
  return v;
}

function parseActor(x: unknown, i: number, names: FpNames): FpActor {
  const w = `footprint.actors[${i}]`;
  const o = obj(x, w);
  if (typeof o.a !== "string" || !AGENT_RE.test(o.a)) return fail(`${w}.a must be "main" or an agent id`);
  const graph = oneOf(o, "graph", FP_GRAPHS, w);
  const wt = optTrue(o, "wt", w);
  const branch = o.branch === undefined ? undefined : typeof o.branch === "string" && BRANCH_RE.test(o.branch) ? o.branch : fail(`${w}.branch has characters a branch can't`);
  const base = o.base === undefined ? undefined : typeof o.base === "string" && BASE_RE.test(o.base) ? o.base : fail(`${w}.base must be a commit id`);
  const risk = oneOf(o, "risk", RISK_LEVELS, w);
  const c = obj(o.changed, `${w}.changed`);
  const files = list(c, "files", FP_LIMITS.files, `${w}.changed`, (f, j) => parseFile(f, names, `${w}.changed.files[${j}]`));
  const symbols = list(c, "symbols", FP_LIMITS.changed, `${w}.changed`, (s, j) => {
    const sw = `${w}.changed.symbols[${j}]`;
    const so = obj(s, sw);
    return { k: parseSymbolKey(so.k, names, `${sw}.k`), kind: parseKind(so, "kind", sw, true)! };
  });
  const fresh = c.new === undefined ? undefined : list(c, "new", FP_LIMITS.newSymbols, `${w}.changed`, (s, j) => parseSymbolKey(s, names, `${w}.changed.new[${j}]`));
  const r1 = obj(o.ring1, `${w}.ring1`);
  const r1files = list(r1, "files", FP_LIMITS.ring1Files, `${w}.ring1`, (f, j) => {
    const fw = `${w}.ring1.files[${j}]`;
    const fo = obj(f, fw);
    return { f: parseFile(fo.f, names, `${fw}.f`), rel: oneOf(fo, "rel", FP_RELS, fw) };
  });
  const r1syms = list(r1, "symbols", FP_LIMITS.ring1Symbols, `${w}.ring1`, (s, j) => {
    const sw = `${w}.ring1.symbols[${j}]`;
    const so = obj(s, sw);
    return { k: parseSymbolKey(so.k, names, `${sw}.k`), rel: oneOf(so, "rel", FP_SYMBOL_RELS, sw) };
  });
  let ring2: FpActor["ring2"];
  if (o.ring2 !== undefined) {
    const r2 = obj(o.ring2, `${w}.ring2`);
    ring2 = { files: list(r2, "files", FP_LIMITS.ring2Files, `${w}.ring2`, (f, j) => parseFile(f, names, `${w}.ring2.files[${j}]`)) };
  }
  const components = parseComponents(o, names, w);
  return {
    a: o.a,
    graph,
    ...(wt ? { wt } : {}),
    ...(branch ? { branch } : {}),
    ...(base ? { base } : {}),
    risk,
    ...(optTrue(o, "stale", w) ? { stale: true as const } : {}),
    ...(optTrue(o, "coarse", w) ? { coarse: true as const } : {}),
    ...(optTrue(o, "partial", w) ? { partial: true as const } : {}),
    changed: { files, symbols, ...(fresh && fresh.length ? { new: fresh } : {}) },
    ring1: { files: r1files, symbols: r1syms },
    ...(ring2 ? { ring2 } : {}),
    components,
  };
}

/**
 * Receiving (strict, SPEC.md §8.5): every known field is checked against its
 * type, pattern and cap, and one bad field makes the whole body invalid.
 * Unknown fields are dropped (SPEC §1). Paths are repo-relative, symbol keys
 * `path#qualifiedKey`, or `h:` tokens in hmac mode, never both.
 */
export function parseFootprintBody(v: unknown): FootprintBody {
  const o = obj(v, "footprint body");
  if (jsonBytes(o) > MAX_FOOTPRINT_BYTES) fail(`footprint body is larger than ${MAX_FOOTPRINT_BYTES} bytes`);
  const repo = parseRepo(o.repo, "footprint.repo");
  const at = int(o, "at", "footprint", 8.64e15);
  const seq = int(o, "seq", "footprint", Number.MAX_SAFE_INTEGER);
  const names = oneOf(o, "names", FP_NAMES, "footprint");
  let keyId: string | undefined;
  if (names === "hmac") {
    if (typeof o.keyId !== "string" || !KEY_ID_RE.test(o.keyId)) fail("footprint.keyId is required in hmac mode (k: + 8 hex)");
    keyId = o.keyId as string;
  } else if (o.keyId !== undefined) fail("footprint.keyId is only for hmac mode");
  if (!Array.isArray(o.actors) || o.actors.length === 0) fail("footprint.actors must be a non-empty list");
  const actors = list(o, "actors", FP_LIMITS.actors, "footprint", (x, i) => parseActor(x, i, names));
  const ids = new Set<string>();
  for (const a of actors) {
    if (ids.has(a.a)) fail(`footprint.actors has ${a.a} twice`);
    ids.add(a.a);
  }
  const m = obj(o.merged, "footprint.merged");
  const counts = obj(m.counts, "footprint.merged.counts");
  const merged = {
    components: parseComponents(m, names, "footprint.merged"),
    risk: oneOf(m, "risk", RISK_LEVELS, "footprint.merged"),
    counts: { changedSymbols: int(counts, "changedSymbols", "footprint.merged.counts"), ring1Files: int(counts, "ring1Files", "footprint.merged.counts"), ring2Files: int(counts, "ring2Files", "footprint.merged.counts") },
  };
  const truncated = optTrue(o, "truncated", "footprint");
  return { repo, at, seq, names, ...(keyId ? { keyId } : {}), actors, merged, ...(truncated ? { truncated } : {}) };
}

// ---------------------------------------------------------------------------
// Assembling a body (sending)

/** One actor as measured locally, with plain names (footprint-compute.ts). */
export interface RawActor {
  a: string;
  graph: FpGraph;
  wt?: boolean;
  branch?: string;
  base?: string;
  risk: RiskLevel;
  stale?: boolean;
  coarse?: boolean;
  partial?: boolean;
  /** A finished agent (done or failed): trimmed before the running ones. */
  done?: boolean;
  files: string[];
  symbols: { k: string; kind: string }[];
  newSymbols?: string[];
  ring1Files: { f: string; rel: FpRel }[];
  ring1Symbols: { k: string; rel: FpSymbolRel }[];
  ring2Files?: string[];
  components: FpComponent[];
}

const RISK_ORDER: Record<RiskLevel, number> = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };
export const maxRisk = (rs: Iterable<RiskLevel>): RiskLevel => {
  let best: RiskLevel = "unknown";
  for (const r of rs) if (RISK_ORDER[r] > RISK_ORDER[best]) best = r;
  return best;
};

const REL_ORDER: Record<FpRel, number> = { call: 0, use: 1, import: 2, test: 3 };

const uniq = <T>(xs: T[], key: (x: T) => string): T[] => {
  const seen = new Set<string>();
  return xs.filter((x) => {
    const k = key(x);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
};

/** Components summed by (name, kind), largest first, then by name. */
export function mergeComponents(lists: FpComponent[][]): FpComponent[] {
  const by = new Map<string, FpComponent>();
  for (const l of lists) {
    for (const c of l) {
      const k = `${c.n}\u0000${c.kind ?? ""}`;
      const cur = by.get(k);
      if (cur) cur.count = Math.min(FP_LIMITS.counts, cur.count + c.count);
      else by.set(k, { ...c });
    }
  }
  return [...by.values()].sort((a, b) => b.count - a.count || (a.n < b.n ? -1 : a.n > b.n ? 1 : 0)).slice(0, FP_LIMITS.components);
}

/** Whether `f` would pass the receiver's check (§8.5), before any hashing: invalid entries are dropped, not sent. */
const ok = (f: () => unknown): boolean => {
  try {
    f();
    return true;
  } catch {
    return false;
  }
};
const okFile = (p: string) => ok(() => parseFile(p, "plain", "file"));
const okKey = (k: string) => ok(() => parseSymbolKey(k, "plain", "symbol"));
const okRegion = (n: string) => ok(() => parseRegion(n, "plain", "region"));
const okKind = (k: string | undefined) => k === undefined || KIND_RE.test(k);

/** A raw actor with every entry the receiver would refuse dropped. */
function validEntries(r: RawActor): RawActor {
  return {
    ...r,
    files: r.files.filter(okFile),
    symbols: r.symbols.filter((s) => okKey(s.k) && okKind(s.kind)),
    ...(r.newSymbols ? { newSymbols: r.newSymbols.filter(okKey) } : {}),
    ring1Files: r.ring1Files.filter((x) => okFile(x.f)),
    ring1Symbols: r.ring1Symbols.filter((x) => okKey(x.k)),
    ...(r.ring2Files ? { ring2Files: r.ring2Files.filter(okFile) } : {}),
    components: r.components.filter((c) => okRegion(c.n) && okKind(c.kind) && Number.isSafeInteger(c.count) && c.count >= 0),
  };
}

/** A raw actor capped, sorted deterministically and named (plain or hashed). */
function wireActor(r: RawActor, name: Namer): FpActor & { done?: boolean } {
  const files = uniq(r.files.map(name.file), (x) => x).slice(0, FP_LIMITS.files);
  const symbols = uniq(r.symbols.map((s) => ({ k: name.symbol(s.k), kind: s.kind })), (s) => s.k).slice(0, FP_LIMITS.changed);
  const fresh = uniq((r.newSymbols ?? []).map(name.symbol), (x) => x).slice(0, FP_LIMITS.newSymbols);
  const r1f = uniq(
    [...r.ring1Files].sort((x, y) => REL_ORDER[x.rel] - REL_ORDER[y.rel] || (x.f < y.f ? -1 : x.f > y.f ? 1 : 0)),
    (x) => x.f,
  )
    .map((x) => ({ f: name.file(x.f), rel: x.rel }))
    .slice(0, FP_LIMITS.ring1Files);
  const r1s = uniq(
    [...r.ring1Symbols].sort((x, y) => REL_ORDER[x.rel] - REL_ORDER[y.rel] || (x.k < y.k ? -1 : x.k > y.k ? 1 : 0)),
    (x) => x.k,
  )
    .map((x) => ({ k: name.symbol(x.k), rel: x.rel }))
    .slice(0, FP_LIMITS.ring1Symbols);
  const r2 = r.ring2Files ? uniq([...r.ring2Files].sort(), (x) => x).map(name.file).slice(0, FP_LIMITS.ring2Files) : undefined;
  return {
    a: r.a,
    graph: r.graph,
    ...(r.wt ? { wt: true as const } : {}),
    ...(r.branch && BRANCH_RE.test(r.branch) ? { branch: r.branch } : {}),
    ...(r.base && BASE_RE.test(r.base) ? { base: r.base } : {}),
    risk: r.risk,
    ...(r.stale ? { stale: true as const } : {}),
    ...(r.coarse ? { coarse: true as const } : {}),
    ...(r.partial ? { partial: true as const } : {}),
    changed: { files, symbols, ...(fresh.length ? { new: fresh } : {}) },
    ring1: { files: r1f, symbols: r1s },
    ...(r2 && r2.length ? { ring2: { files: r2 } } : {}),
    components: mergeComponents([r.components.map((c) => ({ ...c, n: name.region(c.n) }))]),
    ...(r.done ? { done: true } : {}),
  };
}

interface Namer {
  file(p: string): string;
  symbol(k: string): string;
  region(n: string): string;
}

const plainNamer: Namer = { file: (p) => p, symbol: (k) => k, region: (n) => n };
const hmacNamer = (k: NameKey): Namer => ({ file: (p) => hashFile(k, p), symbol: (s) => hashSymbol(k, s), region: (n) => hashRegion(k, n) });

export interface AssembleInput {
  repo: RepoRef;
  at: number;
  seq: number;
  actors: RawActor[];
  /** Set for hmac mode. */
  key?: NameKey;
  /** Test seam: the byte cap (default MAX_FOOTPRINT_BYTES). */
  maxBytes?: number;
}

/**
 * Builds the body: names (plain or hmac), per-actor caps, the merge (from the
 * untrimmed actors), then trimming until it fits, in this order (SPEC §8.4):
 * ring 2, ring-1 symbols, ring-1 files, finished agents, changed symbols,
 * per-actor components, the merged components, running agents (last first).
 * Each step takes from the longest list (ties: the later actor) a quarter of
 * it from the end, so what is kept is the head of each sorted list, and the
 * same input always gives the same body.
 */
export function assembleFootprint(i: AssembleInput): { body: FootprintBody; fallback: string } {
  const name = i.key ? hmacNamer(i.key) : plainNamer;
  const actors = i.actors.slice(0, FP_LIMITS.actors).map((r) => wireActor(validEntries(r), name));
  const ring1 = new Set<string>();
  const ring2 = new Set<string>();
  let changedSymbols = 0;
  for (const a of actors) {
    changedSymbols += a.changed.symbols.length + (a.changed.new?.length ?? 0);
    for (const f of a.ring1.files) ring1.add(f.f);
    for (const f of a.ring2?.files ?? []) ring2.add(f);
  }
  for (const f of ring1) ring2.delete(f);
  const merged: FootprintBody["merged"] = {
    components: mergeComponents(actors.map((a) => a.components)),
    risk: maxRisk(actors.map((a) => a.risk)),
    counts: { changedSymbols: Math.min(changedSymbols, FP_LIMITS.counts), ring1Files: ring1.size, ring2Files: ring2.size },
  };
  const body: Omit<FootprintBody, "actors"> & { actors: (FpActor & { done?: boolean })[] } = {
    repo: i.repo,
    at: i.at,
    seq: i.seq,
    names: i.key ? "hmac" : "plain",
    ...(i.key ? { keyId: i.key.keyId } : {}),
    actors,
    merged,
  };
  const max = i.maxBytes ?? MAX_FOOTPRINT_BYTES;
  const size = () => jsonBytes({ ...body, actors: body.actors.map(stripDone), truncated: true });
  let truncated = false;
  const lists: ((a: FpActor) => unknown[] | undefined)[] = [
    (a) => a.ring2?.files,
    (a) => a.ring1.symbols,
    (a) => a.ring1.files,
  ];
  const shrink = (get: (a: FpActor) => unknown[] | undefined, among: FpActor[]): boolean => {
    let pick: FpActor | undefined;
    for (const a of among) {
      const l = get(a)?.length ?? 0;
      if (l > 0 && (!pick || l >= (get(pick)?.length ?? 0))) pick = a;
    }
    if (!pick) return false;
    const l = get(pick)!;
    l.splice(l.length - Math.max(1, Math.ceil(l.length / 4)));
    return true;
  };
  for (const get of lists) while (size() > max && shrink(get, body.actors)) truncated = true;
  // Finished agents, the last first.
  while (size() > max) {
    const j = body.actors.map((a) => a.done === true).lastIndexOf(true);
    if (j < 0) break;
    body.actors.splice(j, 1);
    truncated = true;
  }
  for (const get of [(a: FpActor) => a.changed.new, (a: FpActor) => a.changed.symbols, (a: FpActor) => a.components]) {
    while (size() > max && shrink(get, body.actors)) truncated = true;
  }
  while (size() > max && body.merged.components.length > 0) {
    body.merged.components.splice(body.merged.components.length - Math.max(1, Math.ceil(body.merged.components.length / 4)));
    truncated = true;
  }
  while (size() > max && body.actors.length > 1) {
    body.actors.pop();
    truncated = true;
  }
  while (size() > max && shrink((a) => a.changed.files, body.actors)) truncated = true;
  for (const a of body.actors) if (a.ring2 && a.ring2.files.length === 0) delete a.ring2;
  const out: FootprintBody = { ...body, actors: body.actors.map(stripDone), ...(truncated ? { truncated: true as const } : {}) };
  if (jsonBytes(out) > max) throw new Error("footprint body doesn't fit even trimmed");
  // The sender holds itself to the receiver's check: what goes out is exactly what validates.
  const checked = max <= MAX_FOOTPRINT_BYTES ? parseFootprintBody(out) : out;
  return { body: checked, fallback: footprintFallback(checked) };
}

function stripDone(a: FpActor & { done?: boolean }): FpActor {
  const { done: _d, ...rest } = a;
  return rest;
}

/**
 * The line a state-aware client without ext-ix shows (≤200 characters). Area
 * names only in plain mode.
 */
export function footprintFallback(b: Pick<FootprintBody, "names" | "merged" | "actors">): string {
  const n = b.merged.counts.changedSymbols;
  const files = new Set(b.actors.flatMap((a) => a.changed.files)).size;
  const areas = b.merged.components.length;
  const risk = b.merged.risk === "unknown" ? "" : `, ${b.merged.risk} risk`;
  const down = b.merged.counts.ring1Files + b.merged.counts.ring2Files;
  const downstream = down > 0 && b.names === "plain" ? `, ~${down} files downstream` : "";
  const tail = "; enable ext-ix to compare";
  const plural = (k: number, w: string) => `${k} ${w}${k === 1 ? "" : "s"}`;
  const where = areas > 0 ? `in ${plural(areas, "area")}` : `in ${plural(files, "file")}`;
  const head = `Ix footprint: ${plural(n, "symbol")} ${where}`;
  if (b.names === "plain" && areas > 0) {
    const all = b.merged.components.map((c) => line(c.n, 40));
    for (let k = Math.min(all.length, 5); k > 0; k--) {
      const s = `${head} (${all.slice(0, k).join(", ")}${k < all.length ? ", …" : ""})${risk}${downstream}${tail}`;
      if (cps(s) <= 200) return s;
    }
  }
  return `${head}${risk}${downstream}${tail}`.slice(0, 200);
}

/** What decides republishing: the body without its time and sequence number. */
export function footprintDigest(b: FootprintBody): string {
  const { at: _a, seq: _s, ...rest } = b;
  return createHash("sha256").update(JSON.stringify(rest)).digest("hex").slice(0, 32);
}
