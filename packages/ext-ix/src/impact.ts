// Copyright 2026 Ix Infrastructure Inc.
//
// x:ix.impact: a blast-radius report for a change, made by the sender's Ix
// (`ix impact <target> --format json`, SPEC.md §5). The receiver only reads
// it: it lists files, symbols and components, and a risk summary.

import { parseRepo, type RepoRef } from "./repo.js";
import {
  fail,
  frame,
  isObj,
  jsonBytes,
  LIMITS,
  line,
  list,
  MAX_BODY_BYTES,
  oneOf,
  optInt,
  optStr,
  relPath,
  RISK_LEVELS,
  scrubPaths,
  str,
  toRepoRelative,
  type O,
  type Roots,
  type RiskLevel,
} from "./text.js";

export const IMPACT_KIND = "x:ix.impact" as const;

export interface ImpactSymbol {
  name: string;
  kind: string;
  path?: string;
  /** Callers Ix counted for it. */
  callers?: number;
}

export interface ImpactComponent {
  name: string;
  kind?: string;
  /** Dependents in it. */
  count: number;
}

export interface ImpactBody {
  target: { name: string; kind: string };
  repo?: RepoRef;
  riskLevel: RiskLevel;
  riskSummary: string;
  riskCategory?: string;
  atRisk: string[];
  /** Affected files (repo-relative). */
  files: string[];
  /** The sender's changed files (repo-relative), when they said. */
  changed?: string[];
  symbols: ImpactSymbol[];
  components: ImpactComponent[];
  counts?: { callers?: number; callees?: number; members?: number; importers?: number; dependents?: number };
  /** The sender's graph had lost edges: the counts are a floor. */
  graphDegraded?: boolean;
  nextStep?: string;
}

const NAME_MAX = LIMITS.symbol;

function parseSymbol(x: unknown, i: number): ImpactSymbol {
  if (!isObj(x)) return fail(`impact.symbols[${i}] must be an object`);
  const name = str(x, "name", NAME_MAX, `impact.symbols[${i}]`);
  const kind = str(x, "kind", LIMITS.kind, `impact.symbols[${i}]`);
  const path = x.path === undefined ? undefined : relPath(x.path, `impact.symbols[${i}].path`);
  const callers = optInt(x, "callers", `impact.symbols[${i}]`);
  return { name, kind, ...(path ? { path } : {}), ...(callers !== undefined ? { callers } : {}) };
}

function parseComponent(x: unknown, i: number): ImpactComponent {
  if (!isObj(x)) return fail(`impact.components[${i}] must be an object`);
  const name = str(x, "name", LIMITS.region, `impact.components[${i}]`);
  const kind = optStr(x, "kind", LIMITS.kind, `impact.components[${i}]`);
  const count = optInt(x, "count", `impact.components[${i}]`) ?? 0;
  return { name, ...(kind ? { kind } : {}), count };
}

export function parseImpactBody(v: unknown): ImpactBody {
  if (!isObj(v)) return fail("impact body must be an object");
  const o = v as O;
  if (jsonBytes(o) > MAX_BODY_BYTES) fail(`impact body is larger than ${MAX_BODY_BYTES} bytes`);
  if (!isObj(o.target)) fail("impact.target must be {name, kind}");
  const t = o.target as O;
  const target = { name: str(t, "name", NAME_MAX, "impact.target"), kind: str(t, "kind", LIMITS.kind, "impact.target") };
  const repo = o.repo === undefined ? undefined : parseRepo(o.repo, "impact.repo");
  const riskLevel = oneOf(o, "riskLevel", RISK_LEVELS, "impact");
  const riskSummary = str(o, "riskSummary", LIMITS.riskSummary, "impact");
  const riskCategory = optStr(o, "riskCategory", 40, "impact");
  const atRisk = list(o, "atRisk", LIMITS.atRisk, "impact", (x, i) => {
    if (typeof x !== "string" || x.trim() === "" || [...x].length > LIMITS.atRiskItem) return fail(`impact.atRisk[${i}] must be a string of 1-${LIMITS.atRiskItem}`);
    return x.trim();
  });
  const files = list(o, "files", LIMITS.files, "impact", (x, i) => relPath(x, `impact.files[${i}]`));
  const changed = list(o, "changed", LIMITS.changed, "impact", (x, i) => relPath(x, `impact.changed[${i}]`));
  const symbols = list(o, "symbols", LIMITS.symbols, "impact", parseSymbol);
  const components = list(o, "components", LIMITS.components, "impact", parseComponent);
  let counts: ImpactBody["counts"];
  if (o.counts !== undefined) {
    if (!isObj(o.counts)) fail("impact.counts must be an object");
    const c = o.counts as O;
    counts = {};
    for (const k of ["callers", "callees", "members", "importers", "dependents"] as const) {
      const n = optInt(c, k, "impact.counts");
      if (n !== undefined) counts[k] = n;
    }
  }
  if (o.graphDegraded !== undefined && typeof o.graphDegraded !== "boolean") fail("impact.graphDegraded must be a boolean");
  const nextStep = optStr(o, "nextStep", LIMITS.nextStep, "impact");
  return {
    target,
    ...(repo ? { repo } : {}),
    riskLevel,
    riskSummary,
    ...(riskCategory ? { riskCategory } : {}),
    atRisk,
    files,
    ...(changed.length ? { changed } : {}),
    symbols,
    components,
    ...(counts && Object.keys(counts).length ? { counts } : {}),
    ...(o.graphDegraded === true ? { graphDegraded: true } : {}),
    ...(nextStep ? { nextStep } : {}),
  };
}

export function impactFallback(b: Pick<ImpactBody, "riskLevel" | "files" | "symbols">): string {
  const n = b.files.length || b.symbols.length;
  const what = b.riskLevel === "unknown" ? "" : `${b.riskLevel} risk, `;
  return `shared an Ix blast-radius report (${what}${n} affected): install Ix to open it: https://github.com/ix-infrastructure/Ix`;
}

const num = (v: unknown): number | undefined => (typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : undefined);
const s = (v: unknown, max: number): string | undefined => (typeof v === "string" && v.trim() !== "" ? v.trim().slice(0, max) : undefined);

export interface ImpactInput {
  /** `ix impact <target> --format json` output. */
  ix: unknown;
  repo?: RepoRef;
  changed?: string[];
  root?: Roots;
  home?: string;
  hostname?: string;
}

/**
 * Sending: maps Ix's impact JSON (container or leaf shape) to a body. Paths
 * are made repo-relative (others dropped), free text scrubbed of local
 * paths, every list capped.
 */
export function buildImpact(i: ImpactInput): { body: ImpactBody; fallback: string } {
  if (!isObj(i.ix)) return fail("ix impact output must be a JSON object");
  const x = i.ix as O;
  if (typeof x.error === "string") fail(`ix impact: ${String(x.message ?? x.error).slice(0, 200)}`);
  // L3: every free-text field, names included (a target or symbol can be a path).
  const scrub = (t: string) => scrubPaths(t, { root: i.root, home: i.home, hostname: i.hostname });
  const rt = isObj(x.resolvedTarget) ? (x.resolvedTarget as O) : {};
  const target = { name: scrub(s(rt.name, NAME_MAX) ?? "(unknown)"), kind: s(rt.kind, LIMITS.kind) ?? "unknown" };
  const riskLevel = (RISK_LEVELS as readonly string[]).includes(String(x.riskLevel)) ? (x.riskLevel as RiskLevel) : "unknown";
  const rel = (p: unknown) => (typeof p === "string" ? toRepoRelative(p, i.root) : undefined);
  const symbols: ImpactSymbol[] = [];
  const seen = new Set<string>();
  const addSym = (m: unknown) => {
    if (!isObj(m) || symbols.length >= LIMITS.symbols) return;
    const raw = s(m.name, NAME_MAX);
    if (!raw || raw === "(unnamed)") return;
    const name = scrub(raw);
    const kind = s(m.kind, LIMITS.kind) ?? "unknown";
    const path = rel(m.path);
    const key = `${kind}|${name}|${path ?? ""}`;
    if (seen.has(key)) return;
    seen.add(key);
    const callers = num(m.callerCount);
    symbols.push({ name, kind, ...(path ? { path } : {}), ...(callers !== undefined ? { callers } : {}) });
  };
  for (const m of Array.isArray(x.topImpactedMembers) ? x.topImpactedMembers : []) addSym(m);
  for (const m of Array.isArray(x.callerList) ? x.callerList : []) addSym(m);
  const components: ImpactComponent[] = [];
  for (const b of Array.isArray(x.propagationBuckets) ? x.propagationBuckets : []) {
    if (!isObj(b) || components.length >= LIMITS.components) continue;
    const region = s(b.region, LIMITS.region);
    if (!region) continue;
    const name = scrub(region);
    const kind = s(b.regionKind, LIMITS.kind);
    components.push({ name, ...(kind ? { kind } : {}), count: num(b.count) ?? 0 });
  }
  const files = [...new Set(symbols.map((m) => m.path).filter((p): p is string => !!p))].slice(0, LIMITS.files);
  const sum = isObj(x.summary) ? (x.summary as O) : {};
  const counts: NonNullable<ImpactBody["counts"]> = {};
  const map: [keyof NonNullable<ImpactBody["counts"]>, string][] = [
    ["callers", "callers"],
    ["callees", "callees"],
    ["members", "members"],
    ["importers", "directImporters"],
    ["dependents", "directDependents"],
  ];
  for (const [k, from] of map) {
    const n = num(sum[from]);
    if (n !== undefined) counts[k] = n;
  }
  const atRisk = (Array.isArray(x.atRiskBehavior) ? x.atRiskBehavior : [])
    .map((b) => s(b, LIMITS.atRiskItem))
    .filter((b): b is string => !!b)
    .map(scrub)
    .slice(0, LIMITS.atRisk);
  const changed = [...new Set((i.changed ?? []).map((p) => toRepoRelative(p, i.root)).filter((p): p is string => !!p))].slice(0, LIMITS.changed);
  const nextStep = s(x.nextStep, LIMITS.nextStep);
  const rc = s(x.riskCategory, 40);
  const riskCategory = rc ? scrub(rc) : undefined;
  const raw: O = {
    target,
    ...(i.repo ? { repo: i.repo } : {}),
    riskLevel,
    riskSummary: scrub(s(x.riskSummary, LIMITS.riskSummary) ?? "No risk summary."),
    ...(riskCategory ? { riskCategory } : {}),
    atRisk,
    files,
    ...(changed.length ? { changed } : {}),
    symbols,
    components,
    ...(Object.keys(counts).length ? { counts } : {}),
    ...(x.graph !== undefined ? { graphDegraded: true } : {}),
    ...(nextStep ? { nextStep: scrub(nextStep) } : {}),
  };
  const body = parseImpactBody(raw);
  return { body, fallback: impactFallback(body) };
}

export function renderImpact(b: ImpactBody, from: { address: string }): Record<string, unknown> {
  const files = b.files.slice(0, 15);
  const comps = b.components.slice(0, 8).map((c) => `${line(c.name, LIMITS.region)} (${c.count})`);
  const parts = [
    `change to ${line(b.target.kind, LIMITS.kind)} ${line(b.target.name, NAME_MAX)}${b.repo ? ` in ${line(b.repo.remote, LIMITS.remote)}` : ""}`,
    `risk ${b.riskLevel}: ${line(b.riskSummary, LIMITS.riskSummary)}`,
    b.atRisk.length ? `at risk: ${b.atRisk.slice(0, 5).map((a) => line(a, LIMITS.atRiskItem)).join("; ")}` : undefined,
    comps.length ? `components: ${comps.join(", ")}` : undefined,
    files.length ? `files: ${files.join(", ")}${b.files.length > files.length ? `, +${b.files.length - files.length} more` : ""}` : undefined,
    b.graphDegraded ? "the sender's graph is degraded, so counts are a floor" : undefined,
  ].filter(Boolean);
  return {
    type: "impact",
    target: { name: line(b.target.name, NAME_MAX), kind: line(b.target.kind, LIMITS.kind) },
    ...(b.repo ? { repo: b.repo } : {}),
    riskLevel: b.riskLevel,
    riskSummary: line(b.riskSummary, LIMITS.riskSummary),
    ...(b.riskCategory ? { riskCategory: line(b.riskCategory, 40) } : {}),
    atRisk: b.atRisk.map((a) => line(a, LIMITS.atRiskItem)),
    files: b.files,
    ...(b.changed ? { changed: b.changed } : {}),
    symbols: b.symbols.map((m) => ({ name: line(m.name, NAME_MAX), kind: line(m.kind, LIMITS.kind), ...(m.path ? { path: m.path } : {}), ...(m.callers !== undefined ? { callers: m.callers } : {}) })),
    components: b.components.map((c) => ({ name: line(c.name, LIMITS.region), ...(c.kind ? { kind: line(c.kind, LIMITS.kind) } : {}), count: c.count })),
    ...(b.counts ? { counts: b.counts } : {}),
    ...(b.graphDegraded ? { graphDegraded: true } : {}),
    ...(b.nextStep ? { nextStep: line(b.nextStep, LIMITS.nextStep) } : {}),
    digest: frame(from.address, "Ix blast-radius report", parts.join("; ")),
  };
}
