// Copyright 2026 Ix Infrastructure Inc.
//
// x:ix.subgraph: a reference to part of the sender's graph ("look at auth/*
// in my graph", SPEC.md §4). It carries only what the receiver's Ix needs to
// find the same part of the same repo in its own graph: the repo's
// normalized remote, a revision, and a selector. It carries no graph content
// and no local path; the sender's Ix isn't even run.
//
// Resolving it is something the receiving user starts (`p2p ix resolve`),
// never the peer: the selector becomes a fixed, validated argv for the
// receiver's own `ix`.

import { compareRepo, parseRepo, type RepoRef } from "./repo.js";
import { cps, fail, frame, scrubPaths, trimEnd, type Roots, isObj, jsonBytes, LIMITS, line, MAX_BODY_BYTES, optInt, optStr, str, type O } from "./text.js";
import { isSafeRelativePath } from "@peer2peer/core/v3";

export const SUBGRAPH_KIND = "x:ix.subgraph" as const;

export type Selector =
  /** A file, a directory, or a directory glob ("auth/*", "auth/**"), repo-relative. */
  | { type: "path"; pattern: string }
  /** A named entity (function, class, …), optionally narrowed by kind and a path substring. */
  | { type: "symbol"; name: string; kind?: string; path?: string }
  /** A region of Ix's architecture map (`ix subsystems`). */
  | { type: "region"; name: string };

export interface SubgraphBody {
  repo: RepoRef;
  selector: Selector;
  title?: string;
  /** Why the sender wants them to look (free text). */
  why?: string;
  /** The sender's Ix graph revision (informational). */
  graphRev?: number;
}

// Strict patterns: what a peer can make the receiver's `ix` see is exactly these.
const PATH_SEG = /^[A-Za-z0-9._@+-][A-Za-z0-9._@+ -]*$/;
const SYMBOL_RE = /^[A-Za-z_$][A-Za-z0-9_$.:#]{0,199}$/;
const KIND_RE = /^[a-z][a-z_]{0,31}$/;
const REGION_RE = /^[A-Za-z0-9][A-Za-z0-9 ._/-]{0,127}$/;

/** "auth/*" → {prefix: "auth", glob: "*"}; a plain path → {prefix: path}. Undefined when invalid. */
export function splitPattern(p: string): { prefix: string; glob?: "*" | "**" } | undefined {
  if (cps(p) > LIMITS.path || p.startsWith("-")) return undefined;
  const m = /^(.*?)(?:\/(\*\*?))?$/.exec(p);
  const prefix = trimEnd(m?.[1] ?? "", "/");
  const glob = m?.[2] as "*" | "**" | undefined;
  if (prefix === "" || !isSafeRelativePath(prefix) || !prefix.split("/").every((s) => PATH_SEG.test(s))) return undefined;
  return { prefix, ...(glob ? { glob } : {}) };
}

export function parseSelector(v: unknown): Selector {
  if (!isObj(v)) return fail("subgraph.selector must be an object");
  const o = v as O;
  switch (o.type) {
    case "path": {
      const pattern = str(o, "pattern", LIMITS.path, "selector");
      if (!splitPattern(pattern)) fail("selector.pattern must be a repo-relative path, optionally ending in /* or /**");
      return { type: "path", pattern };
    }
    case "symbol": {
      const name = str(o, "name", LIMITS.symbol, "selector");
      if (!SYMBOL_RE.test(name)) fail("selector.name must be an identifier (letters, digits, _ $ . : #)");
      const kind = optStr(o, "kind", LIMITS.kind, "selector");
      if (kind !== undefined && !KIND_RE.test(kind)) fail("selector.kind must be a lowercase entity kind");
      const path = optStr(o, "path", LIMITS.path, "selector");
      if (path !== undefined && !splitPattern(path)) fail("selector.path must be a repo-relative path");
      return { type: "symbol", name, ...(kind ? { kind } : {}), ...(path ? { path } : {}) };
    }
    case "region": {
      const name = str(o, "name", LIMITS.region, "selector");
      // L6: Ix sends --target to its backend as a region-name query (`getSubsystemMap({target})`), not a
      // path; still, nothing path-like: no "..", "//" or "./" segments.
      if (!REGION_RE.test(name) || name.split("/").some((seg) => /^\s*\.{1,2}\s*$/.test(seg)) || name.includes("//")) fail("selector.name must be a region name");
      return { type: "region", name };
    }
    default:
      return fail("selector.type must be path, symbol or region");
  }
}

export function parseSubgraphBody(v: unknown): SubgraphBody {
  if (!isObj(v)) return fail("subgraph body must be an object");
  const o = v as O;
  if (jsonBytes(o) > MAX_BODY_BYTES) fail(`subgraph body is larger than ${MAX_BODY_BYTES} bytes`);
  const repo = parseRepo(o.repo, "subgraph.repo");
  const selector = parseSelector(o.selector);
  const title = optStr(o, "title", LIMITS.title, "subgraph");
  const why = optStr(o, "why", LIMITS.why, "subgraph");
  const graphRev = optInt(o, "graphRev", "subgraph");
  return { repo, selector, ...(title ? { title } : {}), ...(why ? { why } : {}), ...(graphRev !== undefined ? { graphRev } : {}) };
}

export function describeSelector(s: Selector): string {
  if (s.type === "path") return s.pattern;
  if (s.type === "symbol") return `${s.kind ? `${s.kind} ` : ""}${s.name}${s.path ? ` in ${s.path}` : ""}`;
  return `region ${s.name}`;
}

export function subgraphFallback(b: SubgraphBody): string {
  const what = line(describeSelector(b.selector), 60);
  return `shared an Ix subgraph (${what}): install Ix to open it: https://github.com/ix-infrastructure/Ix`.slice(0, 200);
}

export interface SubgraphInput {
  repo: RepoRef | undefined;
  selector: Selector;
  title?: string;
  why?: string;
  graphRev?: number;
  /** For scrubbing title and why (never sent). */
  root?: Roots;
  home?: string;
  hostname?: string;
}

export function buildSubgraph(i: SubgraphInput): { body: SubgraphBody; fallback: string } {
  if (!i.repo) fail("not in a git repository with an `origin` remote: a subgraph reference names the repo (or pass --remote)");
  const scrub = (t: string) => scrubPaths(t, { root: i.root, home: i.home, hostname: i.hostname });
  const body = parseSubgraphBody({ repo: i.repo, selector: i.selector, ...(i.title ? { title: scrub(i.title) } : {}), ...(i.why ? { why: scrub(i.why) } : {}), ...(i.graphRev !== undefined ? { graphRev: i.graphRev } : {}) });
  return { body, fallback: subgraphFallback(body) };
}

/** The receiver's own `ix` argv for a selector (validated: no element can be read as an option). */
export function resolveArgv(s: Selector, limit = 100): string[] {
  let argv: string[];
  if (s.type === "path") {
    const sp = splitPattern(s.pattern);
    if (!sp) return fail("bad selector");
    // A glob or a directory-looking path lists files under it; a file gets its structural overview.
    const looksLikeFile = !sp.glob && /\.[A-Za-z0-9]{1,8}$/.test(sp.prefix);
    argv = looksLikeFile ? ["overview", sp.prefix, "--format", "llm"] : ["inventory", "--kind", "file", "--path", `${sp.prefix}/`, "--format", "llm", "--limit", String(limit)];
  } else if (s.type === "symbol") {
    argv = ["context", s.name, "--format", "llm", ...(s.kind ? ["--kind", s.kind] : []), ...(s.path ? ["--path", s.path] : [])];
  } else {
    argv = ["subsystems", "--target", s.name, "--format", "llm"];
  }
  // Belt and braces: the patterns above never allow a leading "-".
  for (const a of argv.slice(1)) if (a.startsWith("-") && !/^--[a-z]+$/.test(a)) fail("refusing an argument that looks like an option");
  return argv;
}

export function renderSubgraph(b: SubgraphBody, from: { address: string }, mine?: RepoRef): Record<string, unknown> {
  const where = describeSelector(b.selector);
  const cmp = compareRepo(b.repo, mine);
  const repoNote = mine === undefined ? "" : !cmp.sameRepo ? " (not the repo this session is in)" : cmp.sameRev === false ? " (same repo, another revision)" : "";
  const parts = [
    `look at ${line(where, 200)} in ${line(b.repo.remote, LIMITS.remote)}${b.repo.rev ? `@${b.repo.rev.slice(0, 12)}` : ""}${repoNote}`,
    b.title ? `"${line(b.title, LIMITS.title)}"` : undefined,
    b.why ? `why: ${line(b.why, LIMITS.why)}` : undefined,
  ].filter(Boolean);
  return {
    type: "subgraph",
    repo: b.repo,
    selector: b.selector,
    ...(b.title ? { title: line(b.title, LIMITS.title) } : {}),
    ...(b.why ? { why: line(b.why, LIMITS.why) } : {}),
    ...(mine !== undefined ? { sameRepo: cmp.sameRepo, ...(cmp.sameRev !== undefined ? { sameRev: cmp.sameRev } : {}) } : {}),
    digest: frame(from.address, "Ix subgraph reference", parts.join("; ")),
    consent: "Nothing was run. The user opens it in their own graph with `p2p ix resolve <event id>`.",
  };
}
