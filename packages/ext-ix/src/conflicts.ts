// Copyright 2026 Ix Infrastructure Inc.
//
// Semantic conflicts (SPEC.md §7): core flags two sessions changing the
// *same* file; with Ix, two sessions changing *connected* files are flagged
// too. For each file I'm changing, the local Ix says who depends on it
// (`ix around <file> --format json`: callers, users, tests and importers, by
// repo-relative path); where that meets a file a peer's session says it is
// changing, my change may break theirs. The same question about their files
// catches the other direction.
//
// Only the local graph is asked, about files named in statuses the peer
// already shared (protocol §4.3 `files`); nothing is sent. The result is
// information for the user and their agent, never an authorisation decision.

import { isSafeRelativePath } from "@peer2peer/core/v3";
import { ixJson, type IxRunner } from "./ix.js";
import { isObj, line, type O } from "./text.js";

export type Relation = "caller" | "user" | "test" | "importer";

/** Files that depend on a file, each with how. */
export type Neighbourhood = Map<string, Set<Relation>>;
export type NeighbourhoodFn = (file: string) => Promise<Neighbourhood>;

export interface PeerChanges {
  address: string;
  own: string;
  sid: string;
  ref: string;
  repo?: string;
  files: readonly string[];
}

export interface SemanticConflict {
  peer: { address: string; own: string; sid: string; ref: string };
  /** My file and theirs. */
  mine: string;
  theirs: string;
  direction: "mine-affects-theirs" | "theirs-affects-mine";
  via: Relation[];
  message: string;
}

export interface ConflictOptions {
  mine: readonly string[];
  peers: readonly PeerChanges[];
  neighbourhood: NeighbourhoodFn;
  /** My repo, as statuses carry it; peers in another repo are skipped. */
  repo?: string;
  /** At most this many of my files and of theirs are looked up (default 25 and 50). */
  maxMine?: number;
  maxTheirs?: number;
  /** Total time for every lookup (default 40 s, inside p2p's 60 s command deadline). */
  budgetMs?: number;
  now?: () => number;
}

/** Default total lookup time. */
export const CONFLICT_BUDGET_MS = 40_000;

/**
 * L5: the "theirs" slots shared fairly: round-robin over peers, one file each
 * per round, so one peer listing many files can't crowd the others out.
 */
export function shareSlots(peers: readonly { files: readonly string[] }[], skip: ReadonlySet<string>, max: number): string[] {
  const queues = peers.map((p) => p.files.filter((f) => isSafeRelativePath(f) && !skip.has(f)));
  const out = new Set<string>();
  for (let round = 0; out.size < max && queues.some((q) => q.length > round); round++) {
    for (const q of queues) {
      if (out.size >= max) break;
      if (round < q.length) out.add(q[round]);
    }
  }
  return [...out];
}

const ORDER: Relation[] = ["caller", "user", "importer", "test"];

/** Reads `ix around <file> --format json` (AroundResult) into a neighbourhood. */
export function parseAround(json: unknown, self: string): Neighbourhood {
  const out: Neighbourhood = new Map();
  const add = (p: unknown, rel: Relation) => {
    if (typeof p !== "string") return;
    const path = p.replace(/^\.\//, "");
    if (path === self || !isSafeRelativePath(path)) return;
    const set = out.get(path) ?? new Set<Relation>();
    set.add(rel);
    out.set(path, set);
  };
  const rows = (sec: unknown): unknown[] => (isObj(sec) && Array.isArray((sec as O).rows) ? ((sec as O).rows as unknown[]) : []);
  if (!isObj(json)) return out;
  const j = json as O;
  for (const sym of Array.isArray(j.symbols) ? j.symbols : []) {
    if (!isObj(sym)) continue;
    for (const r of rows(sym.callers)) if (isObj(r)) add(r.path, "caller");
    for (const r of rows(sym.users)) if (isObj(r)) add(r.path, "user");
    for (const r of rows(sym.tests)) if (isObj(r)) add(r.path, "test");
  }
  for (const r of rows(j.importers)) if (isObj(r)) add(r.path, "importer");
  return out;
}

/** The neighbourhood function backed by the local Ix (`ix around`). Cached per file. */
export function ixNeighbourhood(ix: IxRunner, opts: { limit?: number } = {}): NeighbourhoodFn {
  const cache = new Map<string, Promise<Neighbourhood>>();
  return (file) => {
    let p = cache.get(file);
    if (!p) {
      if (!isSafeRelativePath(file) || file.startsWith("-")) return Promise.resolve(new Map());
      p = ixJson(ix, ["around", file, "--format", "json", "--limit", String(opts.limit ?? 20)]).then((j) => parseAround(j, file));
      cache.set(file, p);
    }
    return p;
  };
}

function relWord(via: Relation[]): string {
  const r = via[0];
  return r === "caller" ? "calls into" : r === "user" ? "uses" : r === "importer" ? "imports" : "tests";
}

/**
 * Possible semantic conflicts between my changed files and each live peer
 * session's. Lookups that fail are skipped (reported in `errors`); the same
 * file on both sides is left to core's same-file conflict.
 */
export async function semanticConflicts(o: ConflictOptions): Promise<{ conflicts: SemanticConflict[]; errors: string[] }> {
  const errors: string[] = [];
  const mine = [...new Set(o.mine.filter((f) => isSafeRelativePath(f)))].slice(0, o.maxMine ?? 25);
  const mineSet = new Set(mine);
  const peers = o.peers.filter((p) => !o.repo || !p.repo || p.repo.toLowerCase() === o.repo.toLowerCase());
  const theirsAll = shareSlots(peers, mineSet, o.maxTheirs ?? 50);
  const now = o.now ?? Date.now;
  const deadline = now() + (o.budgetMs ?? CONFLICT_BUDGET_MS);
  let skipped = 0;
  const look = async (f: string): Promise<Neighbourhood | undefined> => {
    const left = deadline - now();
    if (left <= 0) {
      skipped++;
      return undefined;
    }
    let timer: NodeJS.Timeout | undefined;
    try {
      // A lookup that would overrun the budget is abandoned (its result ignored).
      return await Promise.race([
        o.neighbourhood(f),
        new Promise<undefined>((resolve) => {
          timer = setTimeout(() => {
            skipped++;
            resolve(undefined);
          }, left);
        }),
      ]);
    } catch (e) {
      errors.push(`${line(f, 120)}: ${line((e as Error).message, 200)}`);
      return undefined;
    } finally {
      clearTimeout(timer);
    }
  };
  const nMine = new Map<string, Neighbourhood | undefined>();
  for (const f of mine) nMine.set(f, await look(f));
  const nTheirs = new Map<string, Neighbourhood | undefined>();
  for (const f of theirsAll) nTheirs.set(f, await look(f));

  if (skipped > 0) errors.push(`time budget (${Math.round((o.budgetMs ?? CONFLICT_BUDGET_MS) / 1000)} s) reached: ${skipped} file(s) not checked`);
  const out: SemanticConflict[] = [];
  const seen = new Set<string>();
  for (const p of peers) {
    const peer = { address: line(p.address, 80), own: p.own, sid: p.sid, ref: p.ref };
    const theirs = p.files.filter((f) => nTheirs.has(f));
    for (const m of mine) {
      const hood = nMine.get(m);
      for (const t of theirs) {
        const via = hood?.get(t);
        if (!via) continue;
        const key = `${p.own}|${p.sid}|${m}|${t}|m`;
        if (seen.has(key)) continue;
        seen.add(key);
        const v = ORDER.filter((r) => via.has(r));
        out.push({
          peer,
          mine: m,
          theirs: t,
          direction: "mine-affects-theirs",
          via: v,
          message: `possible semantic conflict with ${peer.address}: your change to ${m} affects ${line(t, 300)} they're editing (it ${relWord(v)} ${m})`,
        });
      }
    }
    for (const t of theirs) {
      const hood = nTheirs.get(t);
      for (const m of mine) {
        const via = hood?.get(m);
        if (!via) continue;
        const key = `${p.own}|${p.sid}|${m}|${t}|t`;
        if (seen.has(key)) continue;
        seen.add(key);
        const v = ORDER.filter((r) => via.has(r));
        out.push({
          peer,
          mine: m,
          theirs: t,
          direction: "theirs-affects-mine",
          via: v,
          message: `possible semantic conflict with ${peer.address}: their change to ${line(t, 300)} affects ${m} you're editing (it ${relWord(v)} ${line(t, 300)})`,
        });
      }
    }
  }
  return { conflicts: out, errors };
}
