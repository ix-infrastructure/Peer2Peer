// Copyright 2026 Ix Infrastructure Inc.
//
// The P2PExtension `p2p` loads (packages/p2p/src/extensions.ts): `receive`
// renders inbound x:ix.* kinds, and `commands` become `p2p ix …`.
//
// Consent and safety (SPEC.md §2):
//   - receiving only validates, sanitizes and renders: no Ix call, no write;
//   - `import` (a note into the local graph) and `resolve` (a subgraph in the
//     local graph) run only when the user starts them, and ask first (or take
//     --yes; with --json and no --yes they refuse);
//   - everything sent is size-capped and has absolute paths made relative or
//     dropped.
//
// The types are the seam's (import type only: no runtime dependency on p2p).

import { createHash } from "node:crypto";
import { homedir, hostname } from "node:os";
import { readFile } from "node:fs/promises";
import { realpathSync } from "node:fs";
import { isAbsolute, relative, resolve as resolvePath } from "node:path";
import type { ExtCommand, ExtContext, ExtEvent, ExtReceived, ExtReceiveInput, P2PExtension } from "@peer2peer/cli";
import { ixNeighbourhood, semanticConflicts } from "./conflicts.js";
import { audienceOf } from "./overlap-command.js";
import { FOOTPRINT_KIND, FOOTPRINT_TTL, parseFootprintBody } from "./footprint.js";
import { footprintCommands } from "./footprint-command.js";
import { buildImpact, IMPACT_KIND, impactFallback, parseImpactBody, renderImpact } from "./impact.js";
import { callPaths, checkedTarget, guardRunner, refuseForTarget, ixAvailable, ixJson, ixRunner, IX_NOTE_ID_RE, localTarget, memoryRefusal, memorySupport, type IxRunner, type IxTarget, type TargetFn } from "./ix.js";
import { ixMemory } from "./memory.js";
import { buildNote, NOTE_KIND, parseNoteBody, renderNote, type NoteBody } from "./note.js";
import { compareRepo, localRepo, normalizeRemote, type RepoRef } from "./repo.js";
import { buildSubgraph, describeSelector, parseSubgraphBody, renderSubgraph, resolveArgv, SUBGRAPH_KIND, type Selector } from "./subgraph.js";
import { frame, InvalidBody, IxExtError, line, NOTE_TAGS, SPEC_VERSION, toRepoRelative } from "./text.js";

export const VERSION = "0.1.0";
export const KINDS = [NOTE_KIND, SUBGRAPH_KIND, IMPACT_KIND] as const;
/** Cap on local Ix output a command hands back (resolve). */
export const MAX_RESOLVE_OUTPUT = 32 * 1024;

// ---------------------------------------------------------------------------
// Receiving

/** Validates and renders one inbound kind. Never runs Ix, never writes. */
export function receiveIx(input: ExtReceiveInput): ExtReceived {
  if (input.v > SPEC_VERSION) return { ok: false, reason: `${input.kind} v${input.v} is newer than this ext-ix (v${SPEC_VERSION}): update @peer2peer/ext-ix` };
  if (input.v < 1) return { ok: false, reason: `${input.kind} v${input.v} is not a known version` };
  const from = { address: input.from.address };
  try {
    switch (input.kind) {
      case NOTE_KIND: {
        const b = parseNoteBody(input.body);
        return { ok: true, rendered: renderNote(b, from), keep: b };
      }
      case SUBGRAPH_KIND: {
        const b = parseSubgraphBody(input.body);
        return { ok: true, rendered: renderSubgraph(b, from), keep: b };
      }
      case IMPACT_KIND: {
        const b = parseImpactBody(input.body);
        return { ok: true, rendered: renderImpact(b, from), keep: b };
      }
      case FOOTPRINT_KIND: {
        // A state kind (SPEC §8.5): validated strictly and kept; nothing rendered, so nothing a
        // person or a model reads comes from it (p2p never logs a state value as an event).
        const b = parseFootprintBody(input.body);
        return { ok: true, rendered: { type: "footprint" }, keep: b };
      }
      default:
        return { ok: false, reason: `${input.kind} is not an Ix kind this version knows` };
    }
  } catch (e) {
    if (e instanceof InvalidBody) return { ok: false, reason: `invalid ${input.kind}: ${e.message}` };
    throw e;
  }
}

// ---------------------------------------------------------------------------
// Commands

/** A received note in full, framed as data from the named peer (L4): what `show` prints and `import` asks about. */
export function noteFull(b: NoteBody, address: string): string {
  const head = frame(address, `Ix ${b.tag} note, full text, ${[...b.text].length} characters`, "");
  return `${head.trimEnd()}\n${b.title ? `Title: ${line(b.title, 120)}\n` : ""}\n${b.text}`;
}

const SHOWN_KEY = "shown";
const MAX_SHOWN = 100;
const bodyHash = (body: unknown) => createHash("sha256").update(JSON.stringify(body) ?? "").digest("hex").slice(0, 32);
const noteHash = (b: NoteBody) => createHash("sha256").update(JSON.stringify([b.title ?? "", b.text])).digest("hex").slice(0, 32);

/** Records that a person read this note in full at a terminal. */
async function markShown(ctx: ExtContext, id: string, b: NoteBody): Promise<void> {
  const cur = ((await ctx.kv.get(SHOWN_KEY)) ?? {}) as Record<string, string>;
  const next = Object.entries({ ...cur, [id]: noteHash(b) }).slice(-MAX_SHOWN);
  await ctx.kv.set(SHOWN_KEY, Object.fromEntries(next));
}

async function wasShown(ctx: ExtContext, id: string, b: NoteBody): Promise<boolean> {
  const cur = (await ctx.kv.get(SHOWN_KEY)) as Record<string, string> | undefined;
  return cur?.[id] === noteHash(b);
}

const usage = (m: string) => new IxExtError("usage", m);
const asUsage = <T>(f: () => T): T => {
  try {
    return f();
  } catch (e) {
    if (e instanceof InvalidBody) throw usage(e.message);
    throw e;
  }
};

const sendOpts = [
  { flags: "--from-session <sid>", description: "Your session id (required)" },
  { flags: "--to <address>", description: 'The peer: name@fingerprint, userId or petname, optionally "[ref]" or /sid (required)' },
];

function need(opts: Record<string, unknown>, k: string, flag: string): string {
  const v = opts[k];
  if (typeof v !== "string" || v.trim() === "") throw usage(`${flag} is required`);
  return v;
}

/** Test seam: the runner and the git environment the commands use. */
export interface Deps {
  ix?: (ctx: ExtContext) => IxRunner;
  /** The clock (footprint debounce and timestamps). */
  now?: () => number;
}

/**
 * The graph target of a call (packages/p2p/src/projects.ts graphTarget, through ExtContext): the
 * only place an `ix` endpoint comes from. A p2p from before graph targets has none to give: local.
 * Any failure is local too.
 */
export function targetOf(ctx: ExtContext, sid?: string, extra: readonly string[] = []): TargetFn {
  const memo = new Map<string, Promise<IxTarget>>();
  const more = extra.filter((p) => typeof p === "string" && p !== "").map((p) => (isAbsolute(p) ? p : resolvePath(ctx.cwd, p)));
  return (call) => {
    const paths = [...new Set([...more, ...callPaths(call)])];
    const key = JSON.stringify(paths);
    let p = memo.get(key);
    if (!p) {
      p = (async () => {
        if (!ctx.graphTarget) return localTarget();
        try {
          return checkedTarget(await ctx.graphTarget({ ...(sid ? { sid } : {}), paths }));
        } catch {
          return localTarget();
        }
      })();
      memo.set(key, p);
    }
    return p;
  };
}

/**
 * The `ix` a command runs: each call pinned to the graph target of session `sid` (when the command
 * has one), its folders, the paths the call names (callPaths) and `extra` (the command's own path
 * arguments: --changed, --file), and limited to the commands that target allows.
 */
export function runner(ctx: ExtContext, deps: Deps, sid?: string, extra: readonly string[] = []): IxRunner {
  const target = targetOf(ctx, sid, extra);
  return guardRunner(deps.ix ? deps.ix(ctx) : ixRunner({ env: ctx.env, cwd: ctx.cwd, target }), target, ctx.cwd);
}

export interface Here {
  /** git's spelling of the root (local only, never sent). */
  root?: string;
  /** Every spelling of the root: git's, its realpath, and the one the cwd uses (symlinked dirs). */
  roots: string[];
  ref?: RepoRef;
}

export async function repoOf(ctx: ExtContext): Promise<Here> {
  const r = await localRepo(ctx.cwd, { ...process.env, ...ctx.env } as NodeJS.ProcessEnv);
  const roots = new Set<string>();
  const real = (p: string) => {
    try {
      return realpathSync(p);
    } catch {
      return p;
    }
  };
  if (r.root) {
    roots.add(r.root);
    roots.add(real(r.root));
    // The cwd's own spellings of the root (the shell's logical $PWD keeps symlinks): minus the path below the root.
    const pwd = process.env.PWD;
    for (const cwd of [ctx.cwd, ...(pwd && real(pwd) === real(ctx.cwd) ? [pwd] : [])]) {
      const below = relative(real(r.root), real(cwd));
      if (below.startsWith("..") || isAbsolute(below)) continue;
      const up = below === "" ? cwd : cwd.slice(0, Math.max(0, cwd.length - below.length - 1));
      if (up) roots.add(up);
    }
  }
  return { ...r, roots: [...roots] };
}

async function findEvent(ctx: ExtContext, idArg: string, kind?: string): Promise<ExtEvent> {
  const all = await ctx.events(kind ? { kind } : {});
  const hits = all.filter((e) => e.id === idArg || (idArg.length >= 6 && e.id.endsWith(idArg)) || (idArg.length >= 8 && e.id.includes(idArg)));
  if (hits.length === 0) throw new IxExtError("not_found", `no received ${kind ?? "x:ix.*"} event ${line(idArg, 80)} (see \`p2p ix inbox\`)`);
  if (hits.length > 1) throw new IxExtError("ambiguous", `${hits.length} events match ${line(idArg, 80)}: give the full id`);
  return hits[0];
}

function keptBody<T>(e: ExtEvent, parse: (v: unknown) => T): T {
  if (!e.kept) throw new IxExtError("unavailable", "this event's content wasn't kept (it arrived before ext-ix was installed, or was invalid or too large)");
  try {
    return parse(e.kept.body);
  } catch (err) {
    if (err instanceof InvalidBody) throw new IxExtError("invalid", `the kept content no longer validates: ${err.message}`);
    throw err;
  }
}

async function readTextArg(ctx: ExtContext, words: unknown, stdin: boolean): Promise<string> {
  const arr = Array.isArray(words) ? words.map(String) : [];
  const fromStdin = stdin || (arr.length === 1 && arr[0] === "-");
  if (fromStdin || arr.length === 0) return ctx.io.readStdin ? (await ctx.io.readStdin()).replace(/\n$/, "") : "";
  return arr.join(" ");
}

function sentHuman(kind: string, r: { to: { address: string; ref: string; own: string; userId: string; sid: string }; relays: number }): string {
  const where = r.to.own === r.to.userId ? `${r.to.address} [${r.to.ref}]` : `${r.to.address} (in your session ${r.to.sid})`;
  return `Sent ${kind} to ${where} via ${r.relays} relay${r.relays === 1 ? "" : "s"}.`;
}

export function ixCommands(deps: Deps = {}): ExtCommand[] {
  return [
    {
      name: "note",
      args: "[text...]",
      description: "Share an Ix session note with a peer session (x:ix.note); text from args, stdin, or --ix-note ID",
      options: [
        ...sendOpts,
        { flags: "--tag <tag>", description: `${NOTE_TAGS.join("|")} (default: note, or the Ix note's tag)` },
        { flags: "--title <title>", description: "A short title" },
        { flags: "--session <name>", description: "The Ix session it belongs to (a label for the reader)" },
        { flags: "--ix-note <id>", description: "Share an existing Ix note (read with `ix note show <id> --json`)" },
        { flags: "--ref <path>", description: "A repo-relative file the note is about (repeatable)", repeatable: true },
        { flags: "--stdin", description: "Read the text from stdin" },
        { flags: "--without-repo", description: "Don't name the repo and revision" },
      ],
      run: async (ctx, args, opts) => {
        const fromSession = need(opts, "fromSession", "--from-session");
        const to = need(opts, "to", "--to");
        const here = await repoOf(ctx);
        const repo = opts.withoutRepo ? { roots: here.roots } : here;
        let text: string;
        let tag = opts.tag as string | undefined;
        let at: string | undefined;
        if (typeof opts.ixNote === "string") {
          if (!IX_NOTE_ID_RE.test(opts.ixNote)) throw usage("--ix-note must be a note id");
          const n = (await ixJson(runner(ctx, deps, fromSession), ["note", "--json", "show", opts.ixNote])) as Partial<{ text: string; tag: string; at: string }>;
          if (typeof n?.text !== "string") throw new IxExtError("ix_failed", "ix note show returned no text");
          text = n.text;
          tag ??= typeof n.tag === "string" && (NOTE_TAGS as readonly string[]).includes(n.tag) ? n.tag : undefined;
          at = typeof n.at === "string" ? n.at : undefined;
        } else {
          text = await readTextArg(ctx, args[0], Boolean(opts.stdin));
        }
        if (text.trim() === "") throw usage("nothing to share: give the note text, pipe it on stdin, or --ix-note ID");
        const { body, fallback } = asUsage(() =>
          buildNote({
            text,
            tag,
            title: opts.title as string | undefined,
            session: opts.session as string | undefined,
            refs: (opts.ref as string[] | undefined)?.map((r) => (isAbsolute(r) ? r : resolvePath(ctx.cwd, r))),
            repo: repo.ref,
            at,
            root: repo.roots,
            home: homedir(),
            hostname: hostname(),
          }),
        );
        const r = await ctx.send({ fromSession, to, kind: NOTE_KIND, v: SPEC_VERSION, body, fallback });
        return { json: { ...r, body }, human: sentHuman("an Ix note", r) };
      },
    },
    {
      name: "subgraph",
      args: "[pattern]",
      description: 'Point a peer at part of your graph (x:ix.subgraph): a path like "auth/*", or --symbol / --region. Sends a reference, no graph content',
      options: [
        ...sendOpts,
        { flags: "--symbol <name>", description: "A symbol instead of a path" },
        { flags: "--kind <kind>", description: "With --symbol: its entity kind (function, class, …)" },
        { flags: "--path <path>", description: "With --symbol: a repo-relative path it lives under" },
        { flags: "--region <name>", description: "An architecture region (ix subsystems) instead of a path" },
        { flags: "--title <title>", description: "A short title" },
        { flags: "--why <text>", description: "Why they should look" },
        { flags: "--remote <remote>", description: "The repo's remote (default: this checkout's origin)" },
        { flags: "--rev <commit>", description: "The revision (default: this checkout's HEAD)" },
      ],
      run: async (ctx, args, opts) => {
        const fromSession = need(opts, "fromSession", "--from-session");
        const to = need(opts, "to", "--to");
        const pattern = typeof args[0] === "string" ? args[0] : undefined;
        const picks = [pattern, opts.symbol, opts.region].filter((x) => typeof x === "string").length;
        if (picks !== 1) throw usage("give exactly one of: a path pattern, --symbol <name>, --region <name>");
        const local = await repoOf(ctx);
        let repo = local.ref;
        if (typeof opts.remote === "string") {
          const remote = normalizeRemote(opts.remote) ?? (/^[a-z0-9.-]+(\/[a-z0-9._~-]+)+$/.test(opts.remote) ? opts.remote : undefined);
          if (!remote) throw usage("--remote must be a git remote URL or host/owner/name");
          repo = { remote, ...(repo?.remote === remote && repo.rev ? { rev: repo.rev } : {}) };
        }
        if (typeof opts.rev === "string" && repo) repo = { ...repo, rev: opts.rev.toLowerCase() };
        let selector: Selector;
        if (pattern !== undefined) {
          // A path given as absolute or ./relative becomes repo-relative; others stay as typed.
          const glob = /\/(\*\*?)$/.exec(pattern)?.[0] ?? "";
          const bare = glob ? pattern.slice(0, -glob.length) : pattern;
          const rel = isAbsolute(bare) ? toRepoRelative(bare, local.roots) : bare.replace(/^\.\//, "");
          if (rel === undefined) throw usage("the path must be inside this repository");
          selector = { type: "path", pattern: rel + glob };
        } else if (typeof opts.symbol === "string") {
          selector = { type: "symbol", name: opts.symbol, ...(typeof opts.kind === "string" ? { kind: opts.kind } : {}), ...(typeof opts.path === "string" ? { path: opts.path } : {}) };
        } else selector = { type: "region", name: opts.region as string };
        const { body, fallback } = asUsage(() => buildSubgraph({ repo, selector, title: opts.title as string | undefined, why: opts.why as string | undefined, root: local.roots, home: homedir(), hostname: hostname() }));
        const r = await ctx.send({ fromSession, to, kind: SUBGRAPH_KIND, v: SPEC_VERSION, body, fallback });
        return { json: { ...r, body }, human: sentHuman(`a reference to ${describeSelector(selector)}`, r) };
      },
    },
    {
      name: "impact",
      args: "<target>",
      description: "Share a blast-radius report of a change (x:ix.impact), made by your Ix (`ix impact TARGET --format json`)",
      options: [
        ...sendOpts,
        { flags: "--kind <kind>", description: "Ix: filter the target by kind" },
        { flags: "--path <path>", description: "Ix: restrict to symbols under this path" },
        { flags: "--depth <n>", description: "Ix: expansion depth 1-3" },
        { flags: "--changed <file>", description: "A file your change touches (repeatable)", repeatable: true },
        { flags: "--ix-json <file>", description: "Use this saved `ix impact --format json` output (- for stdin) instead of running Ix" },
        { flags: "--without-repo", description: "Don't name the repo and revision" },
        { flags: "--dry-run", description: "Build the report and print it (`body`) without sending: for a client to show its user first" },
        { flags: "--body <file>", description: "Send this already-built report body (- for stdin; e.g. a --dry-run's, as shown to the user) instead of running Ix" },
      ],
      run: async (ctx, args, opts) => {
        // A body built earlier (a client's dry run, shown to its user): validated again, sent as is.
        if (typeof opts.body === "string") {
          const fromSession = need(opts, "fromSession", "--from-session");
          const to = need(opts, "to", "--to");
          const raw = opts.body === "-" ? ((await ctx.io.readStdin?.()) ?? "") : await readFile(resolvePath(ctx.cwd, opts.body), "utf8");
          let parsed: unknown;
          try {
            parsed = JSON.parse(raw);
          } catch {
            throw usage("--body is not JSON");
          }
          const body = asUsage(() => parseImpactBody(parsed));
          const r = await ctx.send({ fromSession, to, kind: IMPACT_KIND, v: SPEC_VERSION, body, fallback: impactFallback(body) });
          return { json: { ...r, body }, human: sentHuman(`an Ix blast-radius report (${body.riskLevel} risk)`, r) };
        }
        const dryRun = Boolean(opts.dryRun);
        const fromSession = dryRun ? "" : need(opts, "fromSession", "--from-session");
        const to = dryRun ? "" : need(opts, "to", "--to");
        const here = await repoOf(ctx);
        let target = String(args[0] ?? "");
        // L3: an absolute target becomes repo-relative, or is refused: it would reach the report.
        if (isAbsolute(target) || /^[A-Za-z]:[\\/]/.test(target)) {
          const rel = toRepoRelative(target, here.roots.length ? here.roots : [ctx.cwd]);
          if (!rel) throw usage("<target> is an absolute path outside this repository: give a symbol or a repo-relative path");
          target = rel;
        }
        if (!/^[A-Za-z0-9_$.:#/@+-]{1,300}$/.test(target) || target.startsWith("-")) throw usage("<target> must be a symbol or a path");
        let ixOut: unknown;
        if (typeof opts.ixJson === "string") {
          const raw = opts.ixJson === "-" ? ((await ctx.io.readStdin?.()) ?? "") : await readFile(resolvePath(ctx.cwd, opts.ixJson), "utf8");
          try {
            ixOut = JSON.parse(raw);
          } catch {
            throw usage("--ix-json is not JSON");
          }
        } else {
          const argv = ["impact", target, "--format", "json", "--limit", "20"];
          if (typeof opts.kind === "string") {
            if (!/^[a-z][a-z_]{0,31}$/.test(opts.kind)) throw usage("--kind must be an entity kind");
            argv.push("--kind", opts.kind);
          }
          if (typeof opts.path === "string") {
            if (opts.path.startsWith("-")) throw usage("--path must be a path");
            argv.push("--path", opts.path);
          }
          if (opts.depth !== undefined) {
            const d = Number(opts.depth);
            if (!Number.isInteger(d) || d < 1 || d > 3) throw usage("--depth must be 1, 2 or 3");
            argv.push("--depth", String(d));
          }
          ixOut = await ixJson(runner(ctx, deps, fromSession || undefined, (opts.changed as string[] | undefined) ?? []), argv);
        }
        const repo = opts.withoutRepo ? { roots: here.roots } : here;
        const changed = (opts.changed as string[] | undefined)?.map((r) => (isAbsolute(r) ? r : resolvePath(ctx.cwd, r)));
        const { body, fallback } = asUsage(() => buildImpact({ ix: ixOut, repo: repo.ref, changed, root: repo.roots.length ? repo.roots : [ctx.cwd], home: homedir(), hostname: hostname() }));
        if (dryRun) return { json: { dryRun: true, body, fallback }, human: JSON.stringify(body, null, 2) };
        const r = await ctx.send({ fromSession, to, kind: IMPACT_KIND, v: SPEC_VERSION, body, fallback });
        return { json: { ...r, body }, human: sentHuman(`an Ix blast-radius report (${body.riskLevel} risk)`, r) };
      },
    },
    {
      name: "inbox",
      description: "Ix notes, subgraph references and impact reports peers sent you",
      options: [{ flags: "--kind <kind>", description: "note, subgraph or impact" }],
      offline: true,
      run: async (ctx, _args, opts) => {
        const kind = typeof opts.kind === "string" ? `x:ix.${opts.kind}` : undefined;
        if (kind && !(KINDS as readonly string[]).includes(kind)) throw usage("--kind must be note, subgraph or impact");
        const events = await ctx.events(kind ? { kind } : {});
        const rows = events.map((e) => ({
          id: e.id,
          at: e.at,
          kind: e.kind,
          from: e.from,
          ...(e.ref ? { ref: e.ref } : {}),
          digest: typeof e.rendered?.digest === "string" ? e.rendered.digest : e.fallback,
          ...(e.extError ? { extError: e.extError } : {}),
          kept: e.kept !== undefined,
        }));
        const human = rows.length ? rows.map((r) => `${r.id}  ${r.kind.slice(5)}  ${r.from.address}: ${r.digest}`).join("\n") : "Nothing from peers yet.";
        return { json: { events: rows }, human };
      },
    },
    {
      name: "show",
      args: "<event>",
      description: "Show a received x:ix.* item in full (read-only)",
      offline: true,
      run: async (ctx, args) => {
        const e = await findEvent(ctx, String(args[0]));
        const event = { id: e.id, at: e.at, kind: e.kind, from: e.from, fallback: e.fallback, rendered: e.rendered, ...(e.extError ? { extError: e.extError } : {}) };
        // L4: everything shown is framed as data from the named peer, in --json too.
        if (e.kind === NOTE_KIND && e.kept) {
          const b = keptBody(e, parseNoteBody);
          const text = noteFull(b, e.from.address);
          // M1: a person read the whole note at a terminal; `import --yes` may rely on that.
          if (ctx.interactive) await markShown(ctx, e.id, b);
          const { text: _t, ...rest } = b;
          // `textHash` names exactly this title and text: a client that displayed them in full to its
          // user passes it back as `import --yes --shown=<textHash>`.
          return { json: { event, text, textHash: noteHash(b), body: rest }, human: text };
        }
        const framing = frame(e.from.address, e.kind, "(the body below)").replace(/: \(the body below\)$/, "");
        // `bodyHash` names exactly this body: a client shows it, then passes it back (`resolve --yes --shown=`).
        return { json: { event, framing, body: e.kept?.body, ...(e.kept ? { bodyHash: bodyHash(e.kept.body) } : {}) }, human: String(e.rendered?.digest ?? e.fallback) };
      },
    },
    {
      name: "import",
      args: "<event>",
      description: "Write a received Ix note into your local Ix graph (asks first; the user's decision, never the agent's). Needs an Ix with the OSS `ix note`",
      options: [
        { flags: "--tag <tag>", description: "Override the note's tag" },
        { flags: "--session <name>", description: "Attach it to one of your Ix sessions" },
        { flags: "-y, --yes", description: "Don't ask (the user already agreed)" },
        { flags: "--shown <hash>", description: "With --yes: the textHash `ix show --json` gave for what your client displayed to the user in full" },
      ],
      run: async (ctx, args, opts) => {
        const e = await findEvent(ctx, String(args[0]), NOTE_KIND);
        const b = keptBody(e, parseNoteBody);
        const tag = (opts.tag as string | undefined) ?? b.tag;
        if (!(NOTE_TAGS as readonly string[]).includes(tag)) throw usage(`--tag must be one of ${NOTE_TAGS.join(", ")}`);
        const session = opts.session as string | undefined;
        if (session !== undefined && !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(session)) throw usage("--session must be an Ix session name or id");
        const address = line(e.from.address, 80);
        const actor = /^[A-Za-z0-9._@-]{1,80}$/.test(address) ? [`--actor=p2p:${address}`] : [];
        const argv = ["note", `--tag=${tag}`, ...(session ? [`--session=${session}`] : []), ...actor, "--json"];
        // Before anything is asked: the graph target must allow this exact call (local, never shared),
        // and the `ix` that answers must have the OSS `ix note` (the local backend), not Ix Pro's (the
        // cloud org) or none (an Ix from before #916: upgrade). The guarded runner checks both again.
        const target = await targetOf(ctx)({ argv, cwd: ctx.cwd });
        const refused = refuseForTarget(argv, target);
        if (refused) throw refused;
        const ix = runner(ctx, deps);
        if (!(await ixAvailable(ix))) throw new IxExtError("ix_missing", "Ix isn't installed: https://github.com/ix-infrastructure/Ix");
        const support = await memorySupport(ix);
        if (support !== "oss") throw memoryRefusal(support, target);
        const text = `Shared by ${address} over Peer2Peer${b.title ? `: ${b.title}` : ""}\n\n${b.text}`;
        // M1: consent covers exactly what is written. Either the full title and text are shown here
        // and the user agrees, or --yes after the user read this very note with `p2p ix show` at a terminal.
        if (opts.yes) {
          // A client UI (the Claude mod's typed /peers ix import) shows the full note itself and vouches with
          // the hash of what it showed; a stale or different hash doesn't count.
          const vouched = typeof opts.shown === "string" && opts.shown === noteHash(b);
          if (!vouched && !(await wasShown(ctx, e.id, b))) {
            throw new IxExtError("consent_required", `not imported: the user hasn't read this note in full: run \`p2p ix show ${e.id}\` in a terminal first (or import without --yes there)`);
          }
        } else {
          const ok = await ctx.confirm(`${noteFull(b, address)}\n\nWrite all of this ${tag} note (${[...b.text].length} characters, shown in full above) from ${address} into your Ix graph?`);
          if (!ok) throw new IxExtError("consent_required", "not imported: the user didn't agree (run it in a terminal, or `p2p ix show` it there and then import with --yes)");
        }
        const r = await ix.run(argv, { stdin: text });
        if (r.code !== 0) throw new IxExtError("ix_failed", `ix note failed (exit ${r.code})${r.stderr ? `: ${line(r.stderr, 300)}` : ""}`);
        let created: { id?: unknown } = {};
        try {
          created = JSON.parse(r.stdout) as { id?: unknown };
        } catch {
          // older Ix: no JSON
        }
        const id = typeof created.id === "string" ? created.id : undefined;
        return { json: { imported: true, event: e.id, ...(id ? { noteId: id } : {}), tag }, human: `Imported into your Ix graph${id ? ` as note ${id}` : ""}.` };
      },
    },
    {
      name: "resolve",
      args: "<event>",
      description: "Open a received subgraph reference in your own Ix graph (asks first; runs your `ix`, read-only)",
      options: [
        { flags: "--any-repo", description: "Resolve even when this checkout isn't the referenced repo" },
        { flags: "-y, --yes", description: "Don't ask (the user already agreed)" },
        { flags: "--shown <hash>", description: "The bodyHash `ix show --json` gave for what your client displayed; refused if the reference differs" },
      ],
      run: async (ctx, args, opts) => {
        const e = await findEvent(ctx, String(args[0]), SUBGRAPH_KIND);
        const b = keptBody(e, parseSubgraphBody);
        // Bound like import: a client's confirm covers exactly the reference it showed.
        if (typeof opts.shown === "string" && opts.shown !== bodyHash(e.kept!.body)) {
          throw new IxExtError("consent_required", "not resolved: the reference isn't the one that was shown (show it again)");
        }
        const local = await repoOf(ctx);
        const cmp = compareRepo(b.repo, local.ref);
        if (!cmp.sameRepo && !opts.anyRepo) {
          throw new IxExtError("other_repo", `the reference is to ${b.repo.remote}, but this checkout is ${local.ref?.remote ?? "not a git repo with an origin"}: run it there, or pass --any-repo`);
        }
        const argv = resolveArgv(b.selector);
        const ok = await ctx.confirm(`Run \`ix ${argv.join(" ")}\` on your graph for ${line(e.from.address, 80)}?`, Boolean(opts.yes));
        if (!ok) throw new IxExtError("consent_required", "not resolved: the user didn't agree (run it in a terminal, or with --yes once they have)");
        const ix = runner(ctx, deps);
        const r = await ix.run(argv);
        if (r.code !== 0) throw new IxExtError("ix_failed", `ix ${argv[0]} failed (exit ${r.code})${r.stderr ? `: ${line(r.stderr, 300)}` : ""}`);
        const out = r.stdout.length > MAX_RESOLVE_OUTPUT ? `${r.stdout.slice(0, MAX_RESOLVE_OUTPUT)}\n… (truncated)` : r.stdout;
        const warn = cmp.sameRev === false ? `note: they referenced ${b.repo.rev?.slice(0, 12)}, this checkout is at ${local.ref?.rev?.slice(0, 12)}` : undefined;
        return {
          json: { event: e.id, selector: b.selector, repo: b.repo, sameRepo: cmp.sameRepo, ...(cmp.sameRev !== undefined ? { sameRev: cmp.sameRev } : {}), command: ["ix", ...argv], output: out },
          human: [warn, out.trimEnd()].filter(Boolean).join("\n"),
        };
      },
    },
    {
      name: "conflicts",
      description: "Possible semantic conflicts: live peer sessions changing files connected (in your Ix graph) to the ones you're changing",
      options: [
        { flags: "--session <sid>", description: "Your session (its last status gives your files and repo)" },
        { flags: "--file <path>", description: "A repo-relative file you're changing (repeatable; instead of the status)", repeatable: true },
        { flags: "--repo <repo>", description: "Your repo as statuses name it (default: the session's status)" },
      ],
      run: async (ctx, _args, opts) => {
        const own = typeof opts.session === "string" ? await ctx.ownStatus(opts.session) : undefined;
        const mine = (opts.file as string[] | undefined) ?? own?.files ?? [];
        const repo = (opts.repo as string | undefined) ?? own?.repo;
        if (mine.length === 0) return { json: { conflicts: [], errors: [], checked: 0 }, human: "No files of yours to check (give --file, or --session with a posted status)." };
        const ix = runner(ctx, deps, typeof opts.session === "string" ? opts.session : undefined, mine);
        if (!(await ixAvailable(ix))) throw new IxExtError("ix_missing", "Ix isn't installed: https://github.com/ix-infrastructure/Ix");
        // For a session: only sessions its status reaches (project boundaries), and this user's own.
        const reach = typeof opts.session === "string" ? await audienceOf(ctx, opts.session, (await ctx.self()).userId) : undefined;
        const peers = (await ctx.peers()).filter((p) => p.live && !p.thisDevice && !(p.self && p.sid === opts.session) && (!reach || reach.has(p.own)));
        const r = await semanticConflicts({ mine, peers, repo, neighbourhood: ixNeighbourhood(ix) });
        const human = r.conflicts.length ? r.conflicts.map((c) => c.message).join("\n") : `No semantic conflicts with ${peers.length} live session${peers.length === 1 ? "" : "s"}.`;
        return { json: { ...r, checked: peers.length }, human };
      },
    },
    ...footprintCommands(deps, { runner, repoOf }),
  ];
}

export function createIxExtension(deps: Deps = {}): P2PExtension {
  return {
    api: 1,
    // Every Ix call takes its endpoint from ExtContext.graphTarget (p2p refuses an ext-ix without this).
    graphTargets: 1,
    ns: "ix",
    name: "@peer2peer/ext-ix",
    version: VERSION,
    description: "Ix: share notes, subgraph references and blast-radius reports; semantic conflicts; session footprints",
    receive: receiveIx,
    commands: ixCommands(deps),
    // x:ix.footprint is a state kind: published to the session's status audience, kept latest-wins.
    state: { [FOOTPRINT_KIND]: { ttl: FOOTPRINT_TTL } },
    // Graph memory (SPEC §10): this device's own sessions' context, into the local graph only.
    memory: ixMemory((ctx, sid) => runner(ctx, deps, sid)),
  };
}

/** What `p2p` loads. */
export const extension: P2PExtension = createIxExtension();
