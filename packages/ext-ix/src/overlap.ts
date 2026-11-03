// Copyright 2026 Ix Infrastructure Inc.
//
// Footprint overlap (SPEC.md §9): this session's footprint against each live
// peer session's, both ways, per pair of actors, in tiers:
//
//   T1 same symbol   both change it                              high
//   T2 depends       one changes what the other's change calls,  medium (high when it calls
//                    uses or imports (ring 1), either way         it and my risk is high+)
//   T3 same file     both edit it, no T1                         medium
//   T4 same area     a shared region, no T1-T3                   low
//   T5 transitive    two hops (ring 2), no T1-T4                 low
//
// No Ix call: only the two bodies. Hashed names compare as tokens (both sides
// derive the same key from the repository); a plain side is hashed with that
// key first, so plain, hashed and mixed bodies all compare. A peer body is
// never shown: messages name only what this side knows (its own readable
// names, or a peer's plain names), sanitized and capped.

import type { FootprintBody, FpActor } from "./footprint.js";
import { hashFile, hashRegion, hashSymbol, type NameKey } from "./hmac.js";
import { line } from "./text.js";

export const OVERLAP_TIERS = ["same-symbol", "depends", "same-file", "same-area", "transitive"] as const;
export type OverlapTier = (typeof OVERLAP_TIERS)[number];
export type OverlapSeverity = "high" | "medium" | "low";
export type OverlapDirection = "both" | "mine-affects-theirs" | "theirs-affects-mine";

export interface OverlapPeer {
  own: string;
  sid: string;
  ref: string;
  address: string;
  body: FootprintBody;
}

export interface Overlap {
  peer: { own: string; sid: string; ref: string; address: string };
  /** My actor ("main", "a1", …) and theirs. */
  mine: string;
  theirs: string;
  tier: OverlapTier;
  severity: OverlapSeverity;
  direction: OverlapDirection;
  /** The matched entry (compare keys: plain names, or h: tokens) and the ring relation. */
  via: { key: string; rel?: string };
  /** Up to 3 matched entries in all. */
  examples: number;
  /** Whether the line names things (the peer's body is plain); a hashed overlap stays generic. */
  named: boolean;
  /** Changes when the overlap does: (peer user, tier, direction, matched entry). */
  key: string;
  /** For a model: one line, at most 240 characters, sanitized; no name the peer doesn't already hold. */
  message: string;
  /** For the person (a terminal): the same, with my own readable names. Never for a model. */
  detail: string;
}

const SEVERITY_RANK: Record<OverlapSeverity, number> = { high: 3, medium: 2, low: 1 };
const TIER_LABEL: Record<OverlapTier, string> = { "same-symbol": "same symbol", depends: "depends", "same-file": "same file", "same-area": "same area", transitive: "transitive" };
const REL_WORD: Record<string, string> = { call: "calls", use: "uses", import: "imports", test: "tests" };

type Kind = "f" | "s" | "c";

/** How names compare: as plain names, or as tokens under the repository's key. */
interface Mode {
  tokens: boolean;
  key?: NameKey;
}

/** One side's actor, with every name as a compare key and, where this side knows it, a readable name. */
interface Side {
  a: string;
  risk: string;
  wt: boolean;
  approx: boolean;
  changedSyms: Map<string, string | undefined>;
  changedFiles: Map<string, string | undefined>;
  ring1Syms: Map<string, { d?: string; rel: string }>;
  ring1Files: Map<string, { d?: string; rel: string }>;
  ring2: Map<string, string | undefined>;
  comps: Map<string, string | undefined>;
}

function compareKey(kind: Kind, name: string, plain: boolean, mode: Mode): string | undefined {
  if (!plain) return name; // already a token
  if (!mode.tokens) {
    if (kind === "f") return name.toLowerCase();
    if (kind === "s") {
      const i = name.indexOf("#");
      return `${name.slice(0, i).toLowerCase()}#${name.slice(i + 1)}`;
    }
    return name;
  }
  if (!mode.key) return undefined;
  return kind === "f" ? hashFile(mode.key, name) : kind === "s" ? hashSymbol(mode.key, name) : hashRegion(mode.key, name);
}

function side(a: FpActor, plain: boolean, mode: Mode): Side {
  const put = <V>(m: Map<string, V>, kind: Kind, name: string, v: V) => {
    const k = compareKey(kind, name, plain, mode);
    if (k !== undefined && !m.has(k)) m.set(k, v);
  };
  const d = (n: string) => (plain ? n : undefined);
  const s: Side = {
    a: a.a,
    risk: a.risk,
    wt: a.wt === true,
    approx: a.stale === true || a.coarse === true,
    changedSyms: new Map(),
    changedFiles: new Map(),
    ring1Syms: new Map(),
    ring1Files: new Map(),
    ring2: new Map(),
    comps: new Map(),
  };
  for (const x of a.changed.symbols) put(s.changedSyms, "s", x.k, d(x.k));
  for (const x of a.changed.new ?? []) put(s.changedSyms, "s", x, d(x));
  for (const f of a.changed.files) put(s.changedFiles, "f", f, d(f));
  for (const x of a.ring1.symbols) put(s.ring1Syms, "s", x.k, { d: d(x.k), rel: x.rel });
  for (const x of a.ring1.files) put(s.ring1Files, "f", x.f, { d: d(x.f), rel: x.rel });
  for (const f of a.ring2?.files ?? []) put(s.ring2, "f", f, d(f));
  for (const c of a.components) put(s.comps, "c", c.n, d(c.n));
  return s;
}

const sortedHits = <V>(a: Map<string, unknown>, b: Map<string, V>): [string, V][] =>
  [...a.keys()]
    .filter((k) => b.has(k))
    .sort()
    .map((k) => [k, b.get(k) as V]);

interface Found {
  tier: OverlapTier;
  severity: OverlapSeverity;
  direction: OverlapDirection;
  key: string;
  rel?: string;
  examples: number;
  /** For a model: names only what the peer already holds. */
  text: string;
  /** For the person: my own readable names. */
  detail: string;
}

interface Naming {
  /** The peer's body has plain names. */
  peerPlain: boolean;
  /** Files my status shares in the clear (lower case). */
  statusFiles: Set<string>;
}

/** The overlaps between my actor `m` and their actor `t`, top tier per direction. */
function pair(m: Side, t: Side, n: Naming): Found[] {
  const out: Found[] = [];
  // My readable name for a key (I know my names): for the person only (`detail`).
  const mine = (k: string) => m.changedSyms.get(k) ?? m.changedFiles.get(k) ?? m.ring1Syms.get(k)?.d ?? m.ring1Files.get(k)?.d ?? m.ring2.get(k) ?? m.comps.get(k);
  // Their name for a key, from their own (plain) body: they already have it, so a model line may say it.
  const theirs = (k: string) => t.changedSyms.get(k) ?? t.changedFiles.get(k) ?? t.ring1Syms.get(k)?.d ?? t.ring1Files.get(k)?.d ?? t.ring2.get(k) ?? t.comps.get(k);
  /**
   * A name for the model's line. Only a name the peer's plain body holds (they have it already);
   * otherwise generic, with the file only when my own status already shares it in the clear.
   */
  const say = (k: string, generic: string): string => {
    const t0 = n.peerPlain ? theirs(k) : undefined;
    if (t0) return t0;
    const my = mine(k);
    const file = my ? (my.includes("#") ? my.slice(0, my.indexOf("#")) : my) : undefined;
    return file && n.statusFiles.has(file.toLowerCase()) ? `${generic} in ${file}` : generic;
  };
  const hashed = n.peerPlain ? "" : " (hashed: names stay private)";
  const det = (k: string, fallback: string) => mine(k) ?? theirs(k) ?? fallback;
  // T1
  const t1 = sortedHits(m.changedSyms, t.changedSyms);
  if (t1.length) {
    const k = t1[0][0];
    out.push({ tier: "same-symbol", severity: "high", direction: "both", key: k, examples: Math.min(3, t1.length), text: `you both change ${say(k, "a symbol you are changing")}${hashed}`, detail: `you both change ${det(k, "the same symbol")}` });
  }
  // T2, mine affects theirs: they edit what depends on my change (in my ring 1).
  const a2 = sortedHits(t.changedSyms, m.ring1Syms);
  const a2f = a2.length ? [] : sortedHits(t.changedFiles, m.ring1Files);
  const a2hit = a2[0] ?? a2f[0];
  if (a2hit) {
    const [k, v] = a2hit;
    const high = v.rel === "call" && (m.risk === "high" || m.risk === "critical");
    const rel = REL_WORD[v.rel] ?? "depends on";
    out.push({ tier: "depends", severity: high ? "high" : "medium", direction: "mine-affects-theirs", key: k, rel: v.rel, examples: Math.min(3, a2.length + a2f.length), text: `your change affects ${say(k, "code")} they're editing (it ${rel} it)${hashed}`, detail: `your change affects ${det(k, "code")} they're editing (it ${rel} it)` });
  }
  // T2, theirs affects mine: I edit what depends on their change (in their ring 1).
  const b2 = sortedHits(m.changedSyms, t.ring1Syms);
  const b2f = b2.length ? [] : sortedHits(m.changedFiles, t.ring1Files);
  const b2hit = b2[0] ?? b2f[0];
  if (b2hit) {
    const [k, v] = b2hit;
    const high = v.rel === "call" && (t.risk === "high" || t.risk === "critical");
    const rel = REL_WORD[v.rel] ?? "depends on";
    out.push({ tier: "depends", severity: high ? "high" : "medium", direction: "theirs-affects-mine", key: k, rel: v.rel, examples: Math.min(3, b2.length + b2f.length), text: `their change affects ${say(k, "code")} you're editing (it ${rel} their change)${hashed}`, detail: `their change affects ${det(k, "code")} you're editing (it ${rel} their change)` });
  }
  // T3
  if (!t1.length) {
    const t3 = sortedHits(m.changedFiles, t.changedFiles);
    if (t3.length) {
      const k = t3[0][0];
      out.push({ tier: "same-file", severity: "medium", direction: "both", key: k, examples: Math.min(3, t3.length), text: `you both edit ${say(k, "a file")} (different symbols)${hashed}`, detail: `you both edit ${det(k, "a file")} (different symbols)` });
    }
  }
  // T4
  if (!out.length) {
    const t4 = sortedHits(m.comps, t.comps);
    if (t4.length) {
      const k = t4[0][0];
      out.push({ tier: "same-area", severity: "low", direction: "both", key: k, examples: Math.min(3, t4.length), text: `you both work in ${n.peerPlain ? (theirs(k) ?? "the same area") : "the same area"}${hashed}`, detail: `you both work in ${det(k, "the same area")}` });
    }
  }
  // T5
  if (!out.length) {
    const a5 = sortedHits(t.changedFiles, m.ring2);
    if (a5.length) out.push({ tier: "transitive", severity: "low", direction: "mine-affects-theirs", key: a5[0][0], examples: Math.min(3, a5.length), text: `your change may reach ${say(a5[0][0], "a file")} they're editing (two hops)${hashed}`, detail: `your change may reach ${det(a5[0][0], "a file")} they're editing (two hops)` });
    const b5 = sortedHits(m.changedFiles, t.ring2);
    if (b5.length) out.push({ tier: "transitive", severity: "low", direction: "theirs-affects-mine", key: b5[0][0], examples: Math.min(3, b5.length), text: `their change may reach ${say(b5[0][0], "a file")} you're editing (two hops)${hashed}`, detail: `their change may reach ${det(b5[0][0], "a file")} you're editing (two hops)` });
  }
  return out;
}

export interface OverlapInput {
  /** My footprint: preferably with plain names (`detail` names things for the person); hashed works too. */
  mine: FootprintBody;
  peers: OverlapPeer[];
  /** The repository's name key (needed when either side is hashed and the other plain). */
  key?: NameKey;
  /**
   * Files my own status shares in the clear (repo-relative): a model line about a hashed overlap
   * may name one of these, for a peer in `statusAudience` (who already sees that status).
   */
  statusFiles?: readonly string[];
  /** The users my session's status reaches (its roster audience, and my own userId). Default: none. */
  statusAudience?: readonly string[];
  /**
   * How my session's published footprint names things (default: hashed). A peer's plain names
   * appear in a model line only when mine are plain too (we chose readable names for this
   * audience) and the peer is in my status audience. Otherwise a peer could publish guesses and
   * read our model's confirmation.
   */
  publishedNames?: "plain" | "hmac";
}

/** One line, at most 240 characters: the modifiers stay whole, the description gives way (with "…"). */
function fit(head: string, text: string, tail: string): string {
  const room = Math.max(20, 240 - [...head].length - [...tail].length);
  const t = line(text, 1000);
  return line(`${head}${[...t].length > room ? `${[...t].slice(0, room - 1).join("")}…` : t}${tail}`, 240);
}

/**
 * Overlaps with each peer, both ways. Different remotes, or a different key id (another root
 * commit), are skipped. Sorted: severity, then key; one per key (the peer user, tier, direction
 * and matched entry: not the peer's session or agent ids, which they choose).
 *
 * `message` is for a model: it names something only when the peer's own plain body holds the
 * name (they have it), or a file my status already shares; a hashed overlap otherwise stays
 * generic and says so. `detail` names things with my own readable names, for the person only.
 */
export function computeOverlaps(i: OverlapInput): { overlaps: Overlap[]; skipped: { peer: { own: string; sid: string; address: string }; reason: string }[] } {
  const overlaps: Overlap[] = [];
  const skipped: { peer: { own: string; sid: string; address: string }; reason: string }[] = [];
  const statusFiles = new Set((i.statusFiles ?? []).map((f) => f.toLowerCase()));
  const audience = new Set(i.statusAudience ?? []);
  const published = i.publishedNames ?? "hmac";
  for (const p of i.peers) {
    const who = { own: p.own, sid: p.sid, address: p.address };
    if (p.body.repo.remote !== i.mine.repo.remote) {
      skipped.push({ peer: who, reason: "another repository" });
      continue;
    }
    const tokens = i.mine.names === "hmac" || p.body.names === "hmac";
    const keyIds = [i.mine.keyId, p.body.keyId, i.key?.keyId].filter((x): x is string => !!x);
    if (tokens && new Set(keyIds).size > 1) {
      skipped.push({ peer: who, reason: "another repository key (a fork, or another root commit)" });
      continue;
    }
    const mixed = tokens && (i.mine.names === "plain" || p.body.names === "plain");
    if (mixed && !i.key) {
      skipped.push({ peer: who, reason: "no repository key to compare hashed names" });
      continue;
    }
    const mode: Mode = { tokens, ...(i.key ? { key: i.key } : {}) };
    // Names in a model line: only when both sides chose readable names (theirs, and our published
    // body), and status files only for someone our status reaches.
    const naming: Naming = { peerPlain: p.body.names === "plain" && published === "plain" && audience.has(p.own), statusFiles: audience.has(p.own) ? statusFiles : new Set() };
    const mySides = i.mine.actors.map((a) => side(a, i.mine.names === "plain", mode));
    const theirSides = p.body.actors.map((a) => side(a, p.body.names === "plain", mode));
    const branch = p.body.repo.branch && i.mine.repo.branch && p.body.repo.branch !== i.mine.repo.branch ? p.body.repo.branch : undefined;
    for (const m of mySides) {
      for (const t of theirSides) {
        for (const f of pair(m, t, naming)) {
          // Their agent by id only: a task line is theirs to write, and stays out of the model's line.
          const agent = t.a === "main" ? "" : ` [agent ${t.a}${t.wt ? ", worktree" : ""}]`;
          const mods = [m.a !== "main" ? `your agent ${m.a}` : "", m.wt || t.wt ? "unmerged, agent worktree" : "", branch && naming.peerPlain ? `on branch ${line(branch, 60)}` : "", m.approx || t.approx ? "approximate" : ""].filter(Boolean);
          const head = `POSSIBLE CONFLICT (${f.severity}, ${TIER_LABEL[f.tier]}) with ${line(p.address, 80)}${agent}: `;
          const tail = mods.length ? ` (${mods.join("; ")})` : "";
          overlaps.push({
            peer: { own: p.own, sid: p.sid, ref: p.ref, address: p.address },
            mine: m.a,
            theirs: t.a,
            tier: f.tier,
            severity: f.severity,
            direction: f.direction,
            via: { key: f.key, ...(f.rel ? { rel: f.rel } : {}) },
            examples: f.examples,
            named: naming.peerPlain,
            key: JSON.stringify([p.own, f.tier, f.direction, f.key]),
            message: fit(head, f.text, tail),
            detail: fit(head, f.detail, tail),
          });
        }
      }
    }
  }
  overlaps.sort((x, y) => SEVERITY_RANK[y.severity] - SEVERITY_RANK[x.severity] || (x.key < y.key ? -1 : x.key > y.key ? 1 : 0));
  const seen = new Set<string>();
  return { overlaps: overlaps.filter((o) => !seen.has(o.key) && seen.add(o.key)), skipped };
}
