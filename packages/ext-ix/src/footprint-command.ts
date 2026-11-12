// Copyright 2026 Ix Infrastructure Inc.
//
// `p2p ix footprint` and `p2p ix config` (SPEC.md §8): computing this
// session's footprint from the local Ix and publishing it as the session's
// x:ix.footprint state, to the session's status audience only.

import { createHash, timingSafeEqual } from "node:crypto";
import { stat } from "node:fs/promises";
import { homedir, hostname } from "node:os";
import type { ExtAudience, ExtCommand, ExtContext } from "@peer2peer/cli";
import type { Deps, Here } from "./extension.js";
import { assembleFootprint, footprintDigest, FOOTPRINT_KIND, FP_NAMES, type FootprintBody, type FpNames } from "./footprint.js";
import { computeFootprint, type FileCache, type FileResult } from "./footprint-compute.js";
import { deriveNameKey, pickRootCommit, type NameKey } from "./hmac.js";
import { ixAvailable, type IxRunner } from "./ix.js";
import { conflictPeersWithoutFootprint, overlapsFor } from "./overlap-command.js";
import { gitOut, type RepoRef } from "./repo.js";
import { IxExtError, jsonBytes, SPEC_VERSION } from "./text.js";

/** At most one computation per session this often (SPEC §8.4). */
export const FOOTPRINT_MIN_INTERVAL_MS = 30_000;
/** An unchanged footprint is republished this often, so it stays live at the receivers. */
export const FOOTPRINT_KEEPALIVE_MS = 5 * 60_000;

const STATE_KEY = "footprint";
const CONFIG_KEY = "config";
/** The per-file cache; `fpcache` (v1, before names were scrubbed) is dropped on the next save. */
const CACHE_KEY = "fpcache2";
const OLD_CACHE_KEYS = ["fpcache"];
const MAX_SESSIONS = 16;
const MAX_CACHE = 60;
const MAX_CACHE_BYTES = 16 * 1024;
/** This device's own footprints with plain names, by session (for the person's `detail` lines). */
const MINE_KEY = "mine2";
const OLD_MINE_KEYS = ["mine"];
/** At most this many sessions' readable bodies (bounded: the store is 64 KiB). */
const MAX_MINE = 2;
const MAX_CIRCLES = 50;
const CID_RE = /^[A-Za-z0-9_-]{1,80}$/;

interface SessionState {
  seq: number;
  computedAt: number;
  digest?: string;
  publishedAt?: number;
}

export interface FootprintConfig {
  /** The default for every session (otherwise decided by the audience). */
  names?: FpNames;
  /** Per circle (cid). */
  circles?: Record<string, FpNames>;
}

const usage = (m: string) => new IxExtError("usage", m);

/**
 * Plain or hashed names (SPEC §8.6). Hashed is the default for every audience. Plain only by the
 * person's explicit choice, most specific first: --names, P2P_IX_FOOTPRINT_NAMES, then
 * `p2p ix config --circle <cid> names=…` for the session's circle, then `p2p ix config names=…`.
 * An open circle takes plain only from its own circle setting (or --names / the variable), never
 * from the global one. An audience that can't be read (no roster yet, a circle that can't be
 * loaded, an older p2p) gets no circle setting and no global plain: hashed (fail closed).
 */
export function footprintNames(o: { flag?: unknown; env?: string; config?: FootprintConfig; audience: ExtAudience | undefined | null }): { names: FpNames; why: string } {
  const pick = (v: unknown): FpNames | undefined => ((FP_NAMES as readonly unknown[]).includes(v) ? (v as FpNames) : undefined);
  const flag = pick(o.flag);
  if (flag) return { names: flag, why: "--names" };
  const env = pick(o.env?.trim());
  if (env) return { names: env, why: "P2P_IX_FOOTPRINT_NAMES" };
  const a = o.audience;
  if (!a) return { names: "hmac", why: "hashed by default (who the session reaches can't be read)" };
  const circle = a.circle ? pick(o.config?.circles?.[a.circle]) : undefined;
  if (circle) return { names: circle, why: `p2p ix config --circle ${a.circle}` };
  const def = pick(o.config?.names);
  if (def && !a.open) return { names: def, why: "p2p ix config" };
  return { names: "hmac", why: a.open ? "hashed by default (an open circle: plain only with its own --circle setting)" : "hashed by default" };
}

/** The settings as the MAC covers them: the names choices only, in a fixed order. */
function canonicalConfig(c: FootprintConfig): string {
  const circles = Object.entries(c.circles ?? {})
    .filter(([, v]) => (FP_NAMES as readonly unknown[]).includes(v))
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return JSON.stringify(["ix-footprint-config/v1", c.names ?? null, circles]);
}

function macOk(ctx: ExtContext, c: FootprintConfig & { mac?: unknown }): boolean {
  if (!ctx.localMac || typeof c.mac !== "string") return false;
  let want: string;
  try {
    want = ctx.localMac(canonicalConfig(c));
  } catch {
    return false;
  }
  const a = Buffer.from(c.mac);
  const b = Buffer.from(want);
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * The person's footprint settings. A setting that makes names plain counts only when the store
 * carries a MAC over the settings keyed by this device's secret (ExtContext.localMac), which
 * `p2p ix config` writes: an edit of the store by file tools, or settings copied from another
 * device or circle, can't opt into plain names. Not a boundary against something that runs
 * `p2p ix config` as the user (SPEC §8.6). Hashed settings need no MAC (they only narrow what is
 * shared).
 */
export async function readConfig(ctx: ExtContext): Promise<FootprintConfig & { unverified?: true }> {
  const raw = await ctx.kv.get(CONFIG_KEY);
  const c = raw && typeof raw === "object" && !Array.isArray(raw) ? (raw as FootprintConfig & { mac?: unknown }) : {};
  const cfg: FootprintConfig = {
    ...((FP_NAMES as readonly unknown[]).includes(c.names) ? { names: c.names } : {}),
    circles: Object.fromEntries(Object.entries(c.circles && typeof c.circles === "object" ? c.circles : {}).filter(([k, v]) => CID_RE.test(k) && (FP_NAMES as readonly unknown[]).includes(v))),
  };
  if (macOk(ctx, { ...cfg, mac: c.mac })) return cfg;
  const plain = cfg.names === "plain" || Object.values(cfg.circles ?? {}).includes("plain");
  if (!plain) return cfg;
  return {
    ...(cfg.names === "hmac" ? { names: "hmac" as const } : {}),
    circles: Object.fromEntries(Object.entries(cfg.circles ?? {}).filter(([, v]) => v === "hmac")),
    unverified: true,
  };
}

async function writeConfig(ctx: ExtContext, cfg: FootprintConfig): Promise<void> {
  if (!ctx.localMac) {
    const plain = cfg.names === "plain" || Object.values(cfg.circles ?? {}).includes("plain");
    if (plain) throw new IxExtError("unsupported", "this p2p can't sign settings (ExtContext.localMac): update @peer2peer/cli to set names=plain");
    await ctx.kv.set(CONFIG_KEY, cfg);
    return;
  }
  await ctx.kv.set(CONFIG_KEY, { ...cfg, mac: ctx.localMac(canonicalConfig(cfg)) });
}

/** The per-file result cache, kept in the extension's store (bounded). */
async function loadCache(ctx: ExtContext): Promise<{ cache: FileCache; save: () => Promise<void> }> {
  const raw = await ctx.kv.get(CACHE_KEY).catch(() => undefined);
  const map = new Map<string, { t: number; r: FileResult }>(raw && typeof raw === "object" && !Array.isArray(raw) ? Object.entries(raw as Record<string, { t: number; r: FileResult }>) : []);
  const h = (k: string) => createHash("sha256").update(k).digest("base64url").slice(0, 24);
  let dirty = false;
  let t = 0;
  return {
    cache: {
      get: (k) => {
        const e = map.get(h(k));
        return e && typeof e === "object" && e.r && typeof e.r === "object" ? e.r : undefined;
      },
      set: (k, r) => {
        map.set(h(k), { t: Date.now() + t++, r });
        dirty = true;
      },
    },
    save: async () => {
      if (!dirty) return;
      let entries = [...map.entries()].sort((a, b) => b[1].t - a[1].t).slice(0, MAX_CACHE);
      while (entries.length && jsonBytes(Object.fromEntries(entries)) > MAX_CACHE_BYTES) entries = entries.slice(0, -1);
      for (const old of OLD_CACHE_KEYS) if ((await ctx.kv.get(old).catch(() => undefined)) !== undefined) await ctx.kv.set(old, undefined).catch(() => undefined);
      await ctx.kv.set(CACHE_KEY, Object.fromEntries(entries)).catch(() => undefined);
    },
  };
}

async function sessionStates(ctx: ExtContext): Promise<Record<string, SessionState>> {
  const v = await ctx.kv.get(STATE_KEY);
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, SessionState>) : {};
}

async function saveSessionState(ctx: ExtContext, sid: string, st: SessionState): Promise<void> {
  const all = { ...(await sessionStates(ctx)), [sid]: st };
  const kept = Object.entries(all)
    .sort((a, b) => (b[1].computedAt ?? 0) - (a[1].computedAt ?? 0))
    .slice(0, MAX_SESSIONS);
  await ctx.kv.set(STATE_KEY, Object.fromEntries(kept));
}

type MineStore = Record<string, { at: number; body: FootprintBody }>;

async function mineStore(ctx: ExtContext): Promise<MineStore> {
  const v = await ctx.kv.get(MINE_KEY).catch(() => undefined);
  return v && typeof v === "object" && !Array.isArray(v) ? (v as MineStore) : {};
}

/** Keeps this session's latest plain-names footprint (local only, never sent): newest MAX_MINE sessions. */
async function saveMine(ctx: ExtContext, sid: string, body: FootprintBody): Promise<void> {
  if (jsonBytes(body) > 16 * 1024) return;
  const all: MineStore = { ...(await mineStore(ctx)), [sid]: { at: body.at, body } };
  const kept = Object.entries(all)
    .sort((a, b) => (b[1].at ?? 0) - (a[1].at ?? 0))
    .slice(0, MAX_MINE);
  for (const old of OLD_MINE_KEYS) if ((await ctx.kv.get(old).catch(() => undefined)) !== undefined) await ctx.kv.set(old, undefined).catch(() => undefined);
  await ctx.kv.set(MINE_KEY, Object.fromEntries(kept)).catch(() => undefined);
}

/** This session's readable body; sessions no longer live on this device (`live`) are pruned. */
export async function readMine(ctx: ExtContext, sid: string, live?: readonly string[]): Promise<FootprintBody | undefined> {
  const all = await mineStore(ctx);
  if (live) {
    const gone = Object.keys(all).filter((s) => !live.includes(s));
    if (gone.length) {
      for (const s of gone) delete all[s];
      await ctx.kv.set(MINE_KEY, all).catch(() => undefined);
    }
  }
  const e = all[sid];
  return e && e.body && typeof e.body === "object" ? e.body : undefined;
}

/** The repository's name key, or why there is none (SPEC §8.6): no root commit, or a shallow clone. */
export async function repoNameKey(root: string, ref: RepoRef, env: NodeJS.ProcessEnv): Promise<{ key: NameKey } | { why: string }> {
  const shallow = await gitOut(root, ["rev-parse", "--is-shallow-repository"], env, { timeoutMs: 10_000 });
  if (shallow === "true") return { why: "shallow clone (its root commit isn't the repository's, so hashed names wouldn't match peers'): `git fetch --unshallow`" };
  const rc = pickRootCommit((await gitOut(root, ["rev-list", "--max-parents=0", "HEAD"], env, { maxBuffer: 1 << 16, timeoutMs: 10_000 })) ?? "");
  if (!rc) return { why: "git didn't give the repository's root commit (in time)" };
  return { key: deriveNameKey(ref.remote, rc) };
}

function summary(b: FootprintBody): string {
  const head = `Footprint (${b.names} names${b.truncated ? ", truncated" : ""}): ${b.merged.counts.changedSymbols} changed symbol(s), ${b.merged.counts.ring1Files} file(s) one hop downstream${b.merged.counts.ring2Files ? `, ${b.merged.counts.ring2Files} two hops` : ""}, risk ${b.merged.risk}`;
  const actors = b.actors.map(
    (a) =>
      `  ${a.a}: graph ${a.graph}${a.wt ? " (worktree)" : ""}, ${a.changed.files.length} file(s), ${a.changed.symbols.length} symbol(s)${a.changed.new?.length ? ` + ${a.changed.new.length} new` : ""}, ring 1 ${a.ring1.files.length}${a.coarse ? ", coarse" : ""}${a.stale ? ", stale" : ""}${a.partial ? ", partial" : ""}`,
  );
  return [head, ...actors].join("\n");
}

export interface FootprintHelpers {
  runner(ctx: ExtContext, deps: Deps, sid?: string): IxRunner;
  repoOf(ctx: ExtContext): Promise<Here>;
}

export function footprintCommands(deps: Deps, h: FootprintHelpers): ExtCommand[] {
  const now = () => (deps.now ? deps.now() : Date.now());
  return [
    {
      name: "overlaps",
      description: "Overlaps between this session's Ix footprint and live peer sessions' (same symbol, depends, same file, same area, transitive), both ways",
      options: [
        { flags: "--session <sid>", description: "Your session (default: the one live session of yours on this device)" },
        { flags: "--fallback", description: "For peers without a footprint, also ask your Ix about their status files (`ix around`, as `p2p ix conflicts`)" },
      ],
      run: async (ctx, _args, opts) => {
        let sid = typeof opts.session === "string" ? opts.session : undefined;
        if (!sid) {
          const mine = (await ctx.peers()).filter((p) => p.self && p.thisDevice && p.live);
          if (mine.length !== 1) throw usage(mine.length ? "several live sessions of yours on this device: give --session" : "no live session of yours on this device: give --session");
          sid = mine[0].sid;
        }
        const r = await overlapsFor(ctx, sid, {
          readMine: (live) => readMine(ctx, sid!, live),
          repo: () => h.repoOf(ctx),
          nameKey: repoNameKey,
        });
        let fallback: unknown[] = [];
        if (opts.fallback && r.withoutFootprint.length) fallback = await conflictPeersWithoutFootprint(ctx, sid, r.withoutFootprint, h.runner(ctx, deps, sid));
        // Readable names (`detail`) only for a person at a terminal; --json (what a client, or a
        // model's shell, reads) carries the model-safe line only.
        const lines = r.overlaps.map((o) => (ctx.interactive ? o.detail : o.message));
        const human = r.overlaps.length || fallback.length ? [...lines, ...fallback.map((c) => String((c as { message: string }).message))].join("\n") : r.note ?? `No overlaps with ${r.checked} live session${r.checked === 1 ? "" : "s"} with a footprint.`;
        const overlaps = r.overlaps.map(({ detail: _d, ...o }) => o);
        return { json: { overlaps, fallback, skipped: r.skipped, checked: r.checked, withoutFootprint: r.withoutFootprint.length, ...(r.note ? { note: r.note } : {}) }, human };
      },
    },
    {
      name: "footprint",
      description: "This session's Ix footprint (x:ix.footprint): changed symbols, their blast radius and regions, per agent; --publish shares it with the session's status audience",
      options: [
        { flags: "--session <sid>", description: "Your session (default: the one live session of yours on this device)" },
        { flags: "--publish", description: "Publish it as the session's footprint state (at most every 30 s; only when it changed, or every 5 min)" },
        { flags: "--names <mode>", description: "plain or hmac (default: hmac; plain is opt-in, see `p2p ix config`)" },
        { flags: "--depth <n>", description: "1 (default), or 2 for a second ring (P2P_IX_FOOTPRINT_DEPTH)" },
        { flags: "--force", description: "Ignore the 30 s spacing and publish even when unchanged" },
      ],
      run: async (ctx, _args, opts) => {
        const t0 = now();
        let sid = typeof opts.session === "string" ? opts.session : undefined;
        if (!sid) {
          const mine = (await ctx.peers()).filter((p) => p.self && p.thisDevice && p.live);
          if (mine.length !== 1) throw usage(mine.length ? "several live sessions of yours on this device: give --session" : "no live session of yours on this device: give --session");
          sid = mine[0].sid;
        }
        if (opts.names !== undefined && !(FP_NAMES as readonly unknown[]).includes(opts.names)) throw usage("--names must be plain or hmac");
        const depthRaw = opts.depth ?? ctx.env.P2P_IX_FOOTPRINT_DEPTH;
        const depth = depthRaw === undefined || depthRaw === "" ? 1 : Number(depthRaw);
        if (depth !== 1 && depth !== 2) throw usage("--depth must be 1 or 2");
        const publish = Boolean(opts.publish);
        // Publishing follows the same switches as the session's status, whoever runs it.
        const off = ctx.env.P2P_SHARE_STATUS === "0" || ctx.env.IX_PEERS_SHARE_STATUS === "0" ? "P2P_SHARE_STATUS=0" : ctx.env.P2P_IX_FOOTPRINT === "0" ? "P2P_IX_FOOTPRINT=0" : undefined;
        if (publish && off) return { json: { published: false, skipped: "disabled", why: off }, human: `Not published: ${off}.` };
        const states = await sessionStates(ctx);
        const prev = states[sid];
        if (publish && !opts.force && prev && t0 - prev.computedAt < FOOTPRINT_MIN_INTERVAL_MS && prev.computedAt <= t0) {
          const retryAfterMs = FOOTPRINT_MIN_INTERVAL_MS - (t0 - prev.computedAt);
          return { json: { published: false, skipped: "too_soon", retryAfterMs }, human: `Computed less than 30 s ago; next in ${Math.ceil(retryAfterMs / 1000)} s.` };
        }
        const own = await ctx.ownStatus(sid);
        if (!own) throw new IxExtError("no_status", `session ${sid} has posted no status on this device yet`);
        const here = await h.repoOf(ctx);
        if (!here.root) throw new IxExtError("not_a_repo", "not in a git repository: a footprint needs the session's repo (P2P_WORKDIR)");
        if (!here.ref) throw new IxExtError("no_remote", "this repository has no origin remote: a footprint names its repo by its remote");
        const ix = h.runner(ctx, deps, sid);
        // No Ix: no footprint, one clear error (a client stops asking for this run).
        if (!(await ixAvailable(ix))) throw new IxExtError("ix_missing", "Ix isn't installed: https://github.com/ix-infrastructure/Ix");
        const env = { ...process.env, ...ctx.env } as NodeJS.ProcessEnv;
        const { cache, save } = await loadCache(ctx);
        const computed = await computeFootprint(
          { root: here.root, roots: here.roots, home: homedir(), hostname: hostname(), own: { files: own.files, ...(own.agents ? { agents: own.agents } : {}) }, depth: depth as 1 | 2, cache },
          {
            ix,
            git: (cwd, args, o) => gitOut(cwd, args, env, o),
            stat: async (p) => {
              try {
                const s = await stat(p);
                return { mtimeMs: Math.floor(s.mtimeMs), size: s.size };
              } catch {
                return undefined;
              }
            },
            now,
          },
        );
        await save();
        const nextState: SessionState = { seq: prev?.seq ?? 0, computedAt: t0, ...(prev?.digest ? { digest: prev.digest } : {}), ...(prev?.publishedAt ? { publishedAt: prev.publishedAt } : {}) };
        const usable = computed.actors.filter((a) => a.graph !== "none");
        if (computed.actors.length === 0 || usable.length === 0) {
          if (publish) await saveSessionState(ctx, sid, nextState);
          const skipped = computed.actors.length === 0 ? "nothing_changed" : "not_mapped";
          return {
            json: { published: false, skipped, calls: computed.calls },
            human: skipped === "nothing_changed" ? "No changed files in this session's status: no footprint." : "This repository isn't mapped by Ix (`ix map`): no footprint.",
          };
        }
        const audience = ctx.audience ? await ctx.audience(sid).catch(() => null) : null;
        const mode = footprintNames({ flag: opts.names, env: ctx.env.P2P_IX_FOOTPRINT_NAMES, config: await readConfig(ctx), audience });
        let key;
        if (mode.names === "hmac") {
          // Fail closed: hashed names were called for, and plain ones never go out instead.
          const k = await repoNameKey(here.root, here.ref, env);
          if ("why" in k) throw new IxExtError("no_hmac_key", `no_hmac_key: ${k.why}; nothing published${/shallow/.test(k.why) ? "" : "; the next try computes again"}`);
          key = k.key;
        }
        const seq = (prev?.seq ?? 0) + 1;
        const { body, fallback } = assembleFootprint({ repo: here.ref, at: t0, seq, actors: computed.actors, ...(key ? { key } : {}) });
        // This side's own names, kept locally (never sent): overlap messages name things with them.
        await saveMine(ctx, sid, key ? assembleFootprint({ repo: here.ref, at: t0, seq, actors: computed.actors }).body : body);
        const digest = footprintDigest(body);
        const out = { names: mode.names, namesWhy: mode.why, calls: computed.calls, ...(computed.partial ? { partial: true } : {}), footprint: body, fallback };
        if (!publish) return { json: { published: false, ...out }, human: summary(body) };
        const fresh = prev?.publishedAt !== undefined && digest === prev.digest && t0 - prev.publishedAt < FOOTPRINT_KEEPALIVE_MS && prev.publishedAt <= t0;
        if (fresh && !opts.force) {
          await saveSessionState(ctx, sid, nextState);
          return { json: { published: false, skipped: "unchanged", ...out }, human: `${summary(body)}\nUnchanged since the last publish: not sent.` };
        }
        let r;
        try {
          r = await ctx.publish({ fromSession: sid, kind: FOOTPRINT_KIND, v: SPEC_VERSION, body, fallback });
        } catch (e) {
          await saveSessionState(ctx, sid, nextState);
          const code = (e as { code?: unknown }).code;
          if (code === "rate_limited") return { json: { published: false, skipped: "rate_limited", ...out }, human: "Published less than 5 s ago: not sent." };
          throw e;
        }
        await saveSessionState(ctx, sid, { seq, computedAt: t0, digest, publishedAt: t0 });
        const n = r.delivered.length;
        return { json: { published: true, delivered: r.delivered, skipped: r.skipped, failed: r.failed, ...out }, human: `${summary(body)}\nPublished to ${n} ${n === 1 ? "person" : "people"}${r.skipped.length ? ` (${r.skipped.length} skipped: their clients don't keep footprints)` : ""}.` };
      },
    },
    {
      name: "config",
      args: "[settings...]",
      description: "Footprint settings: names=plain|hmac|auto, for every session or one circle (--circle)",
      options: [{ flags: "--circle <cid>", description: "Set it for sessions shared with this circle" }],
      offline: true,
      run: async (ctx, args, opts) => {
        const settings = Array.isArray(args[0]) ? (args[0] as unknown[]).map(String) : [];
        const { unverified, ...cfg } = await readConfig(ctx);
        const circle = typeof opts.circle === "string" ? opts.circle : undefined;
        if (circle !== undefined && !CID_RE.test(circle)) throw usage("--circle must be a circle id");
        for (const s of settings) {
          const m = /^names=(plain|hmac|auto)$/.exec(s);
          if (!m) throw usage(`unknown setting ${JSON.stringify(s.slice(0, 40))}: names=plain|hmac|auto`);
          const v = m[1] === "auto" ? undefined : (m[1] as FpNames);
          if (circle) {
            const circles = { ...(cfg.circles ?? {}) };
            if (v) circles[circle] = v;
            else delete circles[circle];
            if (Object.keys(circles).length > MAX_CIRCLES) throw usage(`at most ${MAX_CIRCLES} circles have their own setting`);
            cfg.circles = circles;
          } else if (v) cfg.names = v;
          else delete cfg.names;
        }
        if (settings.length) await writeConfig(ctx, cfg);
        const lines = [`names: ${cfg.names ?? "auto (hashed; plain only where you set names=plain)"}`, ...Object.entries(cfg.circles ?? {}).map(([c, v]) => `circle ${c}: names=${v}`)];
        if (unverified && !settings.length) lines.push("ignored: a names=plain setting in the store that this device didn't sign (set it again with `p2p ix config`)");
        return { json: { config: cfg, ...(unverified && !settings.length ? { ignoredUnsigned: true } : {}) }, human: lines.join("\n") };
      },
    },
  ];
}
