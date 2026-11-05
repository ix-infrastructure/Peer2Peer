// Copyright 2026 Ix Infrastructure Inc.
//
// `p2p ix overlaps` (SPEC.md §9): this session's footprint against the live
// peer sessions' stored footprints, and, for peers without one, today's
// `ix around` check on their status files.

import type { ExtContext, ExtPeer } from "@peer2peer/cli";
import { ixNeighbourhood, semanticConflicts, type SemanticConflict } from "./conflicts.js";
import type { Here } from "./extension.js";
import { FOOTPRINT_KIND, parseFootprintBody, type FootprintBody } from "./footprint.js";
import type { NameKey } from "./hmac.js";
import { ixAvailable, type IxRunner } from "./ix.js";
import { computeOverlaps, type Overlap, type OverlapPeer } from "./overlap.js";
import type { RepoRef } from "./repo.js";
import { InvalidBody } from "./text.js";

function parsed(v: unknown): FootprintBody | undefined {
  if (v === undefined) return undefined;
  try {
    return parseFootprintBody(v);
  } catch (e) {
    if (e instanceof InvalidBody) return undefined;
    throw e;
  }
}

export interface OverlapsResult {
  overlaps: Overlap[];
  skipped: { peer: { own: string; sid: string; address: string }; reason: string }[];
  /** Live peer sessions with a footprint compared. */
  checked: number;
  /** Live peer sessions without one (for the `ix around` fallback). */
  withoutFootprint: ExtPeer[];
  note?: string;
}

/** The users a session's status reaches, and this user: whose sessions it may be compared with. */
export async function audienceOf(ctx: ExtContext, sid: string, self: string): Promise<Set<string>> {
  const aud = ctx.audience ? await ctx.audience(sid).catch(() => undefined) : undefined;
  return new Set([self, ...(aud?.members ?? [])]);
}

export async function overlapsFor(
  ctx: ExtContext,
  sid: string,
  h: {
    readMine(live: readonly string[]): Promise<FootprintBody | undefined>;
    repo(): Promise<Here>;
    nameKey(root: string, ref: RepoRef, env: NodeJS.ProcessEnv): Promise<{ key: NameKey } | { why: string }>;
  },
): Promise<OverlapsResult> {
  const rows = await ctx.peers();
  const self = await ctx.self();
  const isThis = (r: ExtPeer) => r.own === self.userId && r.sid === sid;
  const me = rows.find(isThis);
  // My own names when this device computed them; else what this session published.
  // (Own sessions still live on this device: the readable bodies of ended ones are pruned.)
  const live = rows.filter((r) => r.own === self.userId && r.thisDevice && r.live).map((r) => r.sid);
  const mine = parsed(await h.readMine(live.includes(sid) ? live : [...live, sid])) ?? parsed(me?.xstate?.[FOOTPRINT_KIND]?.body);
  // Project boundaries (the CLI's projects.ts): only sessions this one's status reaches, and this
  // user's own. A session in a private project compares with nobody else's; one in a shared project
  // only with those its project shares (who see this session too). An audience that can't be read
  // fails closed: own sessions only.
  const reach = await audienceOf(ctx, sid, self.userId);
  const others = rows.filter((r) => r.live && !isThis(r) && reach.has(r.own));
  const withFp: OverlapPeer[] = [];
  const withoutFootprint: ExtPeer[] = [];
  for (const r of others) {
    const body = parsed(r.xstate?.[FOOTPRINT_KIND]?.body);
    if (!body) {
      withoutFootprint.push(r);
      continue;
    }
    withFp.push({ own: r.own, sid: r.sid, ref: r.ref, address: r.address, body });
  }
  if (!mine) return { overlaps: [], skipped: [], checked: withFp.length, withoutFootprint, note: "This session has no footprint yet (`p2p ix footprint`)." };
  let key: NameKey | undefined;
  if (mine.names === "hmac" || withFp.some((p) => p.body.names === "hmac")) {
    const here = await h.repo();
    if (here.root && here.ref && here.ref.remote === mine.repo.remote) {
      const k = await h.nameKey(here.root, here.ref, { ...process.env, ...ctx.env } as NodeJS.ProcessEnv);
      if ("key" in k) key = k.key;
    }
  }
  // What my status already shares in the clear (a hashed overlap's line may name only these files).
  const own = await ctx.ownStatus(sid);
  const statusFiles = [...(own?.files ?? []), ...(own?.agents ?? []).flatMap((a) => (a.wt ? [] : (a.files ?? [])))];
  // Who my status reaches (a peer outside it may still share theirs with me, and so be in peers()).
  const aud = ctx.audience ? await ctx.audience(sid).catch(() => undefined) : undefined;
  const statusAudience = [self.userId, ...(aud?.members ?? [])];
  const publishedNames = parsed(me?.xstate?.[FOOTPRINT_KIND]?.body)?.names ?? "hmac";
  const r = computeOverlaps({ mine, peers: withFp, statusFiles, statusAudience, publishedNames, ...(key ? { key } : {}) });
  return { ...r, checked: withFp.length, withoutFootprint };
}

/** Peers without a footprint: today's semantic-conflict check (`ix around`) on their status files. */
export async function conflictPeersWithoutFootprint(ctx: ExtContext, sid: string, peers: ExtPeer[], ix: IxRunner): Promise<SemanticConflict[]> {
  const own = await ctx.ownStatus(sid);
  if (!own || own.files.length === 0 || !(await ixAvailable(ix))) return [];
  const r = await semanticConflicts({ mine: own.files, peers, ...(own.repo ? { repo: own.repo } : {}), neighbourhood: ixNeighbourhood(ix) });
  return r.conflicts;
}
