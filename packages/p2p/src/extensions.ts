// Copyright 2026 Ix Infrastructure Inc.
//
// The extension seam (docs/architecture.md "The rules that keep the layers
// apart", docs/protocol.md §4.3 and §8). `p2p` never imports an extension
// statically: it loads the ones the user enabled with a dynamic import of a
// *resolved file URL*, never of a literal specifier, so
// scripts/check-boundaries.mjs keeps refusing every static (or literal
// dynamic) import of an extension while allowing this one loader (it is
// allowlisted by path there).
//
// Trust: an extension is code that runs inside `p2p`, with everything `p2p`
// can reach (the home directory, the identity and device keys). ExtContext
// is the API it is meant to use, not a sandbox. So loading is opt-in:
//   - Which: only namespaces registered in protocol §8.3 (KNOWN_EXTENSIONS)
//     that the user enabled: P2P_EXTENSIONS ("ix,kartr"; "none" = none), else
//     `extensions` in <home>/config.json (`p2p extensions enable ix`). Nothing
//     enabled, nothing loaded.
//   - Where: only explicit node_modules directories: each P2P_EXTENSION_PATH
//     entry (a directory, or its node_modules), then the CLI's own sibling
//     node_modules when it is installed as a package. No walk-up, NODE_PATH
//     or global folders; the entry file must lie inside the package.
//   - The first load from a new location is announced (stderr).
//
// What an extension is for (P2PExtension):
//   - `receive`: validate, sanitize and render the body of an inbound
//     `x:<ns>.*` envelope into a JSON digest that `p2p watch --jsonl` prints.
//     It must not act on the content (protocol §4.3). Anything it throws, or
//     a digest that is too big, degrades to the plain fallback.
//   - `state`: kinds that are a session's latest value rather than events
//     (§4.3 "Extension state kinds", cap xstate.v1; xstate.ts): sent with
//     `publish` to the session's status audience, stored latest-wins with a
//     ttl, never logged, toasted or shown to a model.
//   - `commands`: subcommands under `p2p <ns> …`, declared as data; `p2p`
//     builds them and owns the output and exit codes, and hands them an
//     ExtContext (send kinds of their namespace through the ordinary
//     §4.2-authorised path, read the events they rendered, list live peers).
//
// A missing, broken or incompatible extension never fails a command: it is
// skipped with a warning, and its kinds are shown as their fallback.

import { existsSync, mkdirSync, readFileSync, realpathSync, renameSync, writeFileSync } from "node:fs";
import { basename, delimiter, dirname, isAbsolute, join, relative, resolve as resolvePath, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { extensionKindCap, isExtensionKind, isExtStateTtl, sanitizePeerText, type ExtensionKind, type StatusAgent } from "@peer2peer/core/v3";
import type { Env } from "./config.js";

/** The seam's version; an extension declares the one it was built against. */
export const EXTENSION_API = 1;

/** Namespaces registered in docs/protocol.md §8.3: the only ones that can be enabled. */
export const KNOWN_EXTENSIONS: readonly string[] = ["ix", "kartr"];

/** Cap on the JSON a `receive` digest may add to an event. */
export const MAX_RENDERED_BYTES = 16 * 1024;
/** Cap on the validated body kept with an event (for user-initiated actions later). */
export const MAX_KEPT_BYTES = 24 * 1024;
/** Each string in a digest passes the peer-text sanitizer with this cap. */
export const MAX_RENDERED_STRING = 4000;

export function extensionPackageName(ns: string): string {
  return `@peer2peer/ext-${ns}`;
}

/** The namespace of an `x:<ns>.<type>` kind. */
export function kindNamespace(kind: string): string | undefined {
  return isExtensionKind(kind) ? kind.slice(2, kind.indexOf(".")) : undefined;
}

// ---------------------------------------------------------------------------
// The contract an extension implements

export interface ExtReceiveInput {
  kind: ExtensionKind;
  /** `ext.v` as sent. */
  v: number;
  /** `ext.body` as sent: untrusted peer data of any JSON shape. */
  body: unknown;
  /** The core-sanitized fallback line, already prefixed with the sender's address. */
  fallback: string;
  from: { userId: string; address: string; self: boolean };
  session: { own: string; sid: string; ref: string };
  /** Set for a state kind (§4.3 "Extension state kinds"): what `keep` returns is stored as the session's latest value. */
  state?: { ttl: number };
}

export type ExtReceived =
  /** `rendered` is printed with the event; `keep` is stored (not printed) for a later user-initiated action. */
  | { ok: true; rendered: Record<string, unknown>; keep?: unknown }
  /** Invalid or unsupported: the event shows the fallback, with `extError: reason`. */
  | { ok: false; reason: string };

export interface ExtOption {
  /** Commander flags, e.g. "--tag <tag>" or "--yes". */
  flags: string;
  description: string;
  /** May be given more than once (the value is then a string array). */
  repeatable?: boolean;
  default?: string | boolean;
}

export interface ExtCommand {
  /** The subcommand name: `p2p <ns> <name>`. */
  name: string;
  /** Commander argument syntax, e.g. "<event>" or "[text...]". */
  args?: string;
  description: string;
  options?: ExtOption[];
  /** Commands that only read local files and run no network step (default: false). */
  offline?: boolean;
  run(ctx: ExtContext, args: unknown[], opts: Record<string, unknown>): Promise<{ json: unknown; human: string }>;
}

export interface P2PExtension {
  api: number;
  /**
   * The graph-target contract this extension implements (1: every Ix call takes its endpoint only from
   * ExtContext.graphTarget). Required of the `ix` namespace (REQUIRED_GRAPH_TARGETS): an ext-ix from
   * before it would run Ix with the caller's environment and config, which Ix Pro routes to the cloud.
   */
  graphTargets?: number;
  /** Its §8.1 namespace: the package must be `@peer2peer/ext-<ns>`. */
  ns: string;
  name: string;
  version: string;
  /** One-line description for `p2p <ns> --help`. */
  description?: string;
  receive?(input: ExtReceiveInput): ExtReceived;
  commands?: ExtCommand[];
  /**
   * Its state kinds (§4.3 "Extension state kinds"), by kind (of its own
   * namespace): sent with ExtContext.publish, kept latest-wins for `ttl`
   * seconds (10-3600, default 600), never logged as events. `p2p status`
   * advertises `<kind>.v1` for each.
   */
  state?: Record<string, ExtStateKind>;
  /**
   * Graph memory (epic #41 piece 2): writes this device's own sessions' context (their record, status
   * one-liners, the files they edit) into the person's local graph. `p2p watch` gathers it from the
   * statuses this device posted, queues it (bounded) and hands it over in batches, off the hook path.
   * Optional: an extension without it (an older ext-ix) is simply never asked. Each batch is for one
   * session and has already been checked local by graphTarget; the extension checks again.
   */
  memory?: ExtMemory;
}

/** One thing to remember about a session (graph-memory.ts). Every string is local, the person's own. */
export interface ExtMemoryItem {
  kind: "start" | "status" | "files" | "end";
  /** When it happened (ms). */
  at: number;
  /** start: the session's label, repository and branch. */
  label?: string;
  repo?: string;
  branch?: string;
  /** status: the one-line status. */
  summary?: string;
  /** files: repo-relative files edited since the last batch. */
  files?: string[];
}

/** Why memory can't be written now; `message` says what the person can do. */
export interface ExtMemoryUnavailable {
  ok: false;
  /** e.g. `ix_missing`, `ix_upgrade` (no local `ix note`), `ix_pro` (Ix Pro answers: cloud). */
  reason: string;
  message: string;
}

export interface ExtMemoryResult {
  written: number;
  /** Items not written, by reason (counted as dropped). */
  failed?: { reason: string; n: number; message?: string }[];
  /** Stop asking for now (the same as available() turning false). */
  unavailable?: ExtMemoryUnavailable;
}

export interface ExtMemory {
  v: 1;
  /** Whether the writes can go to the local graph at all (asked before anything is gathered). */
  available(ctx: ExtContext): Promise<{ ok: true } | ExtMemoryUnavailable>;
  write(ctx: ExtContext, batch: { sid: string; items: ExtMemoryItem[] }): Promise<ExtMemoryResult>;
}

/** `ext.memory` when it is a usable v1 memory writer; undefined otherwise (absent or malformed: never asked). */
export function memoryOf(ext: P2PExtension | undefined): ExtMemory | undefined {
  const m = ext?.memory as Partial<ExtMemory> | undefined;
  return m && typeof m === "object" && m.v === 1 && typeof m.available === "function" && typeof m.write === "function" ? (m as ExtMemory) : undefined;
}

export interface ExtStateKind {
  /** Seconds a value stays valid (EXT_STATE_TTL_MIN-MAX); default EXT_STATE_TTL_DEFAULT. */
  ttl?: number;
}

/** A received extension event, as ExtContext.events() returns it. */
export interface ExtEvent {
  id: string;
  at: number;
  kind: string;
  from: { userId: string; address: string; self: boolean };
  own?: string;
  sid?: string;
  ref?: string;
  fallback: string;
  rendered?: Record<string, unknown>;
  /** The `keep` value `receive` returned (validated body), when it fit. */
  kept?: { v: number; body: unknown };
  extError?: string;
}

export interface ExtSendOptions {
  fromSession: string;
  /** name@fingerprint, userId or petname, optionally "[ref]" or /sid (as `p2p send --to`). */
  to: string;
  kind: ExtensionKind;
  v: number;
  body: unknown;
  /** ≤200 characters of plain text (§4.3). */
  fallback: string;
}

export interface ExtSendResult {
  /** The folders it was given are bound for good (sessions.ts). */
  bound?: true;
  delivered: boolean;
  to: { userId: string; address: string; own: string; sid: string; ref: string };
  relays: number;
  devices: number;
  kind: string;
  bytes: number;
}

export interface ExtPublishOptions {
  fromSession: string;
  /** A state kind this extension declares. */
  kind: ExtensionKind;
  v: number;
  body: unknown;
  /** ≤200 characters of plain text: what a state-aware client without the extension shows in `ls`. */
  fallback: string;
  /** Seconds; default the kind's declared ttl. */
  ttl?: number;
}

export interface ExtPublishResult {
  kind: string;
  bytes: number;
  ttl: number;
  delivered: { userId: string; address: string; relays: number; devices: number }[];
  skipped: { userId: string; address: string; reason: string }[];
  failed: { userId: string; address: string; error: string }[];
}

/** A session's stored value of one state kind. */
export interface ExtStateValue {
  v: number;
  /** The body this extension's `receive` validated and kept (absent when it refused or kept nothing). */
  body?: unknown;
  /** The sanitized fallback line. */
  fallback: string;
  /** The sender's ts (ms). */
  at: number;
  expiresAt: number;
  extError?: string;
}

/** One live session's value of a state kind (ExtContext.peerState). */
export interface ExtPeerState extends ExtStateValue {
  own: string;
  sid: string;
  ref: string;
  address: string;
  self: boolean;
  thisDevice: boolean;
  kind: string;
}

export interface ExtPeer {
  own: string;
  sid: string;
  ref: string;
  address: string;
  self: boolean;
  thisDevice: boolean;
  live: boolean;
  state: "busy" | "idle";
  label: string;
  repo?: string;
  branch?: string;
  files: string[];
  /** What the session's client understands (§4.3 "Status caps"); absent from older clients. */
  caps?: string[];
  /** Its subagents (§4.3 "Status agents"), validated and sanitized; only from a session that sent them to this user. */
  agents?: StatusAgent[];
  /** Its stored values of this extension's state kinds (§4.3 "Extension state kinds"), by kind: live sessions, within the ttl. */
  xstate?: Record<string, ExtStateValue>;
}

/** ExtContext.audience: who a session's status reaches. */
export interface ExtAudience {
  vis: "circle" | "private";
  circle?: string;
  /** The circle's policy is open: anyone its owner admits sees the session. */
  open?: true;
  /** Other people the roster lets see the session now. */
  people: number;
  /** Their userIds (this user's own devices see it too, and aren't listed). */
  members?: string[];
  /** Distinct verified organisations among them (a trust provider's labels); absent when unknown. */
  orgs?: number;
}

/**
 * Which Ix graph a call may reach (projects.ts graphTarget, the chokepoint): this machine's backend,
 * or one circle's shared graph. An extension that runs Ix takes the endpoint (and any token) only
 * from here, never from its environment.
 */
export type ExtGraphTarget = { kind: "local"; endpoint: string; why: string } | { kind: "shared"; circle: string; endpoint: string; token?: string };

/** What a command gets from `p2p`: no keys, no store, only these. */
export interface ExtContext {
  env: Env;
  /** The user's working directory: P2P_WORKDIR (an existing absolute directory), else the process's. */
  cwd: string;
  /**
   * The graph target for a call made for session `sid` (when given), working in this context's folders
   * (P2P_WORKDIR, P2P_PROJECT_DIRS and the process's cwd) and naming `paths` (absolute: the call's
   * targets, `--path`, `--changed`, the child's cwd; every one is intersected in): projects.ts
   * graphTarget. Absent on clients from before graph targets: an extension then treats every call as local.
   */
  graphTarget?(opts?: { sid?: string; paths?: readonly string[] }): Promise<ExtGraphTarget>;
  /** stdout lines are for `--json`-less output only; use the returned `human`. */
  io: { err(s: string): void; readStdin?: () => Promise<string> };
  /** Whether --json was given (no prompts then). */
  json: boolean;
  /** A person at a terminal: prompts can be answered and what is printed is read (not --json, a TTY). */
  interactive: boolean;
  /** A small JSON store of this extension's own (<home>/ext/<ns>.json, 0600; at most 64 KiB). */
  kv: { get(key: string): Promise<unknown>; set(key: string, value: unknown): Promise<void> };
  /** Asks the user (y/N). False when there is no terminal, unless `yes`. */
  confirm(question: string, yes?: boolean): Promise<boolean>;
  self(): Promise<{ userId: string; address: string }>;
  /** Sends an `x:<ns>.*` envelope of this extension's namespace (§4.2-authorised, like `p2p send`). Not for state kinds: see publish. */
  send(opts: ExtSendOptions): Promise<ExtSendResult>;
  /**
   * Publishes the session's latest value of one of this extension's state
   * kinds to the session's status audience, to recipients that advertise
   * xstate.v1 only (§4.3 "Extension state kinds"). At most once every 5 s per
   * kind and session (`rate_limited`), at most 16 KiB.
   */
  publish(opts: ExtPublishOptions): Promise<ExtPublishResult>;
  /** Live sessions' stored values of one of this extension's state kinds (this user's own included). */
  peerState(kind: string): Promise<ExtPeerState[]>;
  /** Received events of this extension's kinds, newest last. */
  events(filter?: { id?: string; kind?: string }): Promise<ExtEvent[]>;
  /** Peer sessions from the local status table (receives what's queued first). */
  peers(opts?: { all?: boolean }): Promise<ExtPeer[]>;
  /**
   * Who an own session's status (and so its state kinds) reaches: the roster's visibility,
   * its circle and whether that circle is open, and how many other people it lets see the
   * session. Undefined for a session with no roster yet, or whose circle can't be loaded. `orgs`, the number of distinct
   * verified organisations among them, is set only once a trust provider supplies org labels.
   */
  audience?(sid: string): Promise<ExtAudience | undefined>;
  /**
   * A MAC over `data` keyed by this device's secret (never shown to the extension): base64url
   * HMAC-SHA256 under a key derived from the device signing key and the extension's namespace.
   * For settings an extension keeps in its own store that must come from the person running
   * `p2p` rather than from anything that can write files in P2P_HOME without the keys (a model's
   * file tools): store the MAC with the setting and honour the setting only when it verifies.
   */
  localMac?(data: string): string;
  /** Own sessions' last posted statuses on this device. */
  ownStatus(sid: string): Promise<{ repo?: string; files: string[]; caps?: string[]; agents?: StatusAgent[] } | undefined>;
}

// ---------------------------------------------------------------------------
// The registry and the loader

export interface LoadedExtension {
  ext: P2PExtension;
  /** Where it was loaded from (a file path). */
  from: string;
}

export class ExtensionRegistry {
  private readonly byNs = new Map<string, LoadedExtension>();

  constructor(list: readonly LoadedExtension[] = []) {
    for (const l of list) if (!this.byNs.has(l.ext.ns)) this.byNs.set(l.ext.ns, l);
  }

  get(ns: string): P2PExtension | undefined {
    return this.byNs.get(ns)?.ext;
  }

  forKind(kind: string): P2PExtension | undefined {
    const ns = kindNamespace(kind);
    return ns ? this.get(ns) : undefined;
  }

  list(): LoadedExtension[] {
    return [...this.byNs.values()];
  }
}

export interface LoadOptions {
  env: Env;
  /** P2P_HOME: where config.json (`extensions`) and the record of load locations live. */
  home?: string;
  /** config.json as read (its `extensions` list enables namespaces). */
  config?: { extensions?: unknown };
  /** Always shown (stderr): enabled-but-missing, a bad base, the first load from a new location. */
  warn?: (msg: string) => void;
  /** Debug output (P2P_DEBUG=1). */
  log?: (msg: string) => void;
  /** Overrides where this CLI is installed (tests). */
  selfUrl?: string;
}

/** Namespaces that run Ix, and the graph-target contract version each must declare to load. */
export const REQUIRED_GRAPH_TARGETS: Readonly<Record<string, number>> = { ix: 1 };

/** Validates what a module exports; undefined (with a reason) when it isn't a usable extension. */
export function checkExtension(mod: unknown, ns: string): { ext?: P2PExtension; why?: string } {
  const m = mod as { extension?: unknown; default?: unknown } | null;
  const ext = (m?.extension ?? (m?.default as { extension?: unknown } | undefined)?.extension ?? m?.default) as P2PExtension | undefined;
  if (!ext || typeof ext !== "object") return { why: "exports no `extension`" };
  if (ext.api !== EXTENSION_API) return { why: `built for extension API ${String(ext.api)}, this p2p has ${EXTENSION_API}` };
  if (ext.ns !== ns) return { why: `declares namespace ${String(ext.ns)}, expected ${ns}` };
  const need = REQUIRED_GRAPH_TARGETS[ns];
  if (need !== undefined && !(typeof ext.graphTargets === "number" && ext.graphTargets >= need)) {
    return { why: `it predates graph targets (it would run Ix with your environment and config, which Ix Pro can route to the cloud): update ${extensionPackageName(ns)} (npm i -g ${extensionPackageName(ns)}@latest; the Claude Code mod ships a current copy)` };
  }
  if (ext.receive !== undefined && typeof ext.receive !== "function") return { why: "receive is not a function" };
  if (ext.state !== undefined) {
    if (typeof ext.state !== "object" || ext.state === null || Array.isArray(ext.state)) return { why: "state is malformed" };
    for (const [kind, d] of Object.entries(ext.state)) {
      if (!isExtensionKind(kind) || kindNamespace(kind) !== ns) return { why: `state kind ${sanitizePeerText(kind, 60)} is not an x:${ns}.<type> kind` };
      if (!extensionKindCap(kind)) return { why: `state kind ${kind} is too long for its cap (${kind}.v1, at most 40 characters)` };
      if (typeof d !== "object" || d === null || (d.ttl !== undefined && !isExtStateTtl(d.ttl))) return { why: `state kind ${kind}: ttl must be an integer of 10-3600 seconds` };
    }
  }
  if (ext.commands !== undefined && (!Array.isArray(ext.commands) || ext.commands.some((c) => !c || typeof c.name !== "string" || !/^[a-z][a-z0-9-]{0,31}$/.test(c.name) || typeof c.run !== "function"))) {
    return { why: "commands are malformed" };
  }
  return { ext };
}

/**
 * The namespaces the user enabled (opt-in): P2P_EXTENSIONS when set ("none"
 * or "" = none; "config" = defer to config.json), else `extensions` in
 * config.json, else none. Only
 * namespaces registered in protocol §8.3 count; others are ignored (`ignored`).
 */
export function enabledNamespaces(env: Env, config?: { extensions?: unknown }): { enabled: string[]; ignored: string[] } {
  let raw: string[];
  // "config" means: only config.json counts (a client that must not inherit its user's shell setting).
  if (env.P2P_EXTENSIONS !== undefined && env.P2P_EXTENSIONS.trim() !== "config") {
    const t = env.P2P_EXTENSIONS.trim();
    raw = t === "" || t === "none" || t === "0" ? [] : t.split(/[\s,]+/);
  } else if (Array.isArray(config?.extensions)) {
    raw = config!.extensions.filter((x): x is string => typeof x === "string");
  } else raw = [];
  const enabled: string[] = [];
  const ignored: string[] = [];
  for (const r of raw) {
    const ns = r.trim().replace(/^@peer2peer\/ext-/, "");
    if (ns === "") continue;
    if (KNOWN_EXTENSIONS.includes(ns)) {
      if (!enabled.includes(ns)) enabled.push(ns);
    } else ignored.push(sanitizePeerText(r, 64));
  }
  return { enabled, ignored };
}

/**
 * The CLI's own sibling node_modules, when it is installed as a package
 * (`…/node_modules/@peer2peer/cli/dist/extensions.js` → `…/node_modules`):
 * where a global `npm i -g @peer2peer/cli @peer2peer/ext-ix` puts both.
 * Nothing for a checkout or the bundled single file.
 */
export function siblingNodeModules(selfFile: string): string | undefined {
  const parts = resolvePath(selfFile).split(sep);
  for (let i = parts.length - 3; i >= 0; i--) {
    if (parts[i] === "node_modules" && parts[i + 1] === "@peer2peer" && parts[i + 2] === "cli") return parts.slice(0, i + 1).join(sep) || sep;
  }
  return undefined;
}

/** A path with symlinks resolved as far as it exists (a missing tail is kept as written). */
function realish(p: string): string {
  try {
    return realpathSync(p);
  } catch {
    const parent = dirname(p);
    return parent === p ? p : join(realish(parent), basename(p));
  }
}

/** Whether `p` is `dir` or inside it, comparing real paths (a symlink can't hide where it points). */
export function isInside(p: string, dir: string): boolean {
  const r = realish(resolvePath(p));
  const d = realish(resolvePath(dir));
  const rel = relative(d, r);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

/**
 * The node_modules directories searched, in order: P2P_EXTENSION_PATH's, then the CLI's sibling one.
 * P2P_EXTENSION_EXCLUDE (path-delimiter separated) drops entries inside those directories, by real
 * path: a client passes the session's repository, so a cloned repo can't supply an extension.
 */
export function extensionDirs(env: Env, selfUrl: string): string[] {
  const excluded = (env.P2P_EXTENSION_EXCLUDE ?? "")
    .split(delimiter)
    .map((d) => d.trim())
    .filter((d) => d !== "" && isAbsolute(d));
  const dirs = (env.P2P_EXTENSION_PATH ?? "")
    .split(delimiter)
    .map((d) => d.trim())
    .filter(Boolean)
    .filter((d) => !excluded.some((x) => isInside(d, x)))
    .map((d) => (basename(d) === "node_modules" ? d : join(d, "node_modules")));
  const self = selfUrl.startsWith("file:") ? fileURLToPath(selfUrl) : selfUrl;
  const sib = siblingNodeModules(self);
  return [...new Set([...dirs, ...(sib ? [sib] : [])])];
}

export class ExtResolveError extends Error {}

/**
 * Resolves `name` inside one node_modules directory only: no walk-up, no
 * NODE_PATH, no global folders. The package's entry (exports "." import /
 * default, else main, else index.js) must be a file inside the package.
 * Undefined when the package isn't there; ExtResolveError when it is but is
 * malformed.
 */
export function resolveIn(nodeModules: string, name: string): string | undefined {
  const pkgDir = join(nodeModules, ...name.split("/"));
  if (!existsSync(join(pkgDir, "package.json"))) return undefined;
  let pkg: { name?: unknown; exports?: unknown; main?: unknown };
  try {
    pkg = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8"));
  } catch {
    throw new ExtResolveError(`${join(pkgDir, "package.json")} is not valid JSON`);
  }
  if (pkg?.name !== name) throw new ExtResolveError(`${pkgDir} is not ${name}`);
  const dot = typeof pkg.exports === "string" ? pkg.exports : (pkg.exports as Record<string, unknown> | undefined)?.["."];
  const cond = typeof dot === "string" ? dot : dot && typeof dot === "object" ? ((dot as Record<string, unknown>).import ?? (dot as Record<string, unknown>).default) : undefined;
  const entry = typeof cond === "string" ? cond : typeof pkg.main === "string" ? pkg.main : "index.js";
  let real: string;
  let realPkg: string;
  try {
    realPkg = realpathSync(pkgDir);
    real = realpathSync(resolvePath(pkgDir, entry));
  } catch {
    throw new ExtResolveError(`${name}'s entry ${sanitizePeerText(entry, 120)} doesn't exist`);
  }
  if (!real.startsWith(realPkg + sep)) throw new ExtResolveError(`${name}'s entry points outside the package`);
  return real;
}

const SEEN_FILE = "extension-locations.json";

/** Records where each namespace was loaded from; true when this location is new for it. */
function firstFromHere(home: string | undefined, ns: string, file: string): boolean {
  if (!home) return true;
  const p = join(home, SEEN_FILE);
  let seen: Record<string, string> = {};
  try {
    seen = JSON.parse(readFileSync(p, "utf8"));
  } catch {
    // none yet
  }
  if (seen[ns] === file) return false;
  try {
    if (existsSync(home)) {
      const tmp = `${p}.${process.pid}.tmp`;
      writeFileSync(tmp, JSON.stringify({ ...seen, [ns]: file }), { mode: 0o600 });
      renameSync(tmp, p);
    }
  } catch {
    // best effort: it is said again next time
  }
  return true;
}

/**
 * Loads the extensions the user enabled, from the explicit directories only.
 * Never throws: an enabled one that isn't found, a bad directory, or a broken
 * package is a warning, and the rest still load.
 */
export async function loadExtensions(opts: LoadOptions): Promise<ExtensionRegistry> {
  const warn = opts.warn ?? (() => {});
  const log = opts.env.P2P_DEBUG === "1" ? (opts.log ?? warn) : () => {};
  const { enabled, ignored } = enabledNamespaces(opts.env, opts.config);
  if (ignored.length) warn(`p2p: ignoring extensions that aren't registered (protocol §8.3): ${ignored.join(", ")}`);
  if (enabled.length === 0) return new ExtensionRegistry();
  const dirs = extensionDirs(opts.env, opts.selfUrl ?? import.meta.url);
  const loaded: LoadedExtension[] = [];
  for (const ns of enabled) {
    const name = extensionPackageName(ns);
    let file: string | undefined;
    for (const dir of dirs) {
      try {
        file = resolveIn(dir, name);
      } catch (e) {
        // L1: a bad base is skipped, not the namespace.
        warn(`p2p: skipping ${sanitizePeerText(dir, 200)} for ${name}: ${sanitizePeerText((e as Error).message, 300)}`);
        continue;
      }
      if (file) break;
    }
    if (!file) {
      warn(`p2p: extension ${name} is enabled but not installed in ${dirs.length ? dirs.map((d) => sanitizePeerText(d, 200)).join(", ") : "any extension directory (set P2P_EXTENSION_PATH)"}`);
      continue;
    }
    try {
      // The one dynamic import of an extension: a resolved file URL, never a literal specifier.
      const href = pathToFileURL(file).href;
      const mod: unknown = await import(href);
      const { ext, why } = checkExtension(mod, ns);
      if (!ext) {
        warn(`p2p: extension ${name} skipped: ${why}`);
        continue;
      }
      if (firstFromHere(opts.home, ns, file)) warn(`p2p: loading extension ${name} ${sanitizePeerText(ext.version, 32)} from ${file} (it runs with your p2p identity: only enable extensions you trust)`);
      else log(`p2p: extension ${name} from ${file}`);
      loaded.push({ ext, from: file });
    } catch (e) {
      warn(`p2p: extension ${name} failed to load: ${sanitizePeerText((e as Error).message, 300)}`);
    }
  }
  return new ExtensionRegistry(loaded);
}

/** `p2p extensions enable|disable <ns>`: edits `extensions` in <home>/config.json. */
export function setExtensionEnabled(home: string, ns: string, on: boolean): string[] {
  if (!KNOWN_EXTENSIONS.includes(ns)) throw new Error(`${ns} is not a registered extension namespace (${KNOWN_EXTENSIONS.join(", ")})`);
  const p = join(home, "config.json");
  let cfg: Record<string, unknown> = {};
  if (existsSync(p)) {
    const v: unknown = JSON.parse(readFileSync(p, "utf8"));
    if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error("config.json must hold a JSON object");
    cfg = v as Record<string, unknown>;
  }
  const cur = Array.isArray(cfg.extensions) ? cfg.extensions.filter((x): x is string => typeof x === "string") : [];
  const next = on ? [...new Set([...cur, ns])] : cur.filter((x) => x !== ns);
  mkdirSync(home, { recursive: true, mode: 0o700 });
  const tmp = `${p}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify({ ...cfg, extensions: next }, null, 2) + "\n", { mode: 0o600 });
  renameSync(tmp, p);
  return next;
}

// ---------------------------------------------------------------------------
// Receiving: render through the extension, or degrade to the fallback

/** Every string sanitized and capped; depth- and size-bounded; non-JSON values dropped. */
export function sanitizeRendered(v: unknown, depth = 0): unknown {
  if (depth > 6) return undefined;
  if (typeof v === "string") return sanitizePeerText(v, MAX_RENDERED_STRING);
  if (typeof v === "number") return Number.isFinite(v) ? v : undefined;
  if (typeof v === "boolean" || v === null) return v;
  if (Array.isArray(v)) return v.slice(0, 200).map((x) => sanitizeRendered(x, depth + 1)).filter((x) => x !== undefined);
  if (typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>).slice(0, 100)) {
      if (!/^[A-Za-z][A-Za-z0-9_]{0,39}$/.test(k)) continue;
      const s = sanitizeRendered(x, depth + 1);
      if (s !== undefined) out[k] = s;
    }
    return out;
  }
  return undefined;
}

export interface RenderOutcome {
  rendered?: Record<string, unknown>;
  kept?: { v: number; body: unknown };
  extError?: string;
}

/** Runs the extension's `receive` defensively. Without one, nothing (the fallback stands). */
export function renderExtension(reg: ExtensionRegistry | undefined, input: ExtReceiveInput): RenderOutcome {
  const ext = reg?.forKind(input.kind);
  if (!ext?.receive) return {};
  let r: ExtReceived;
  try {
    r = ext.receive(input);
  } catch (e) {
    return { extError: sanitizePeerText(`${ext.name} failed: ${(e as Error)?.message ?? String(e)}`, 200) };
  }
  if (!r || typeof r !== "object") return { extError: "the extension returned nothing" };
  if (!r.ok) return { extError: sanitizePeerText(String(r.reason), 200) };
  const out: RenderOutcome = {};
  // A state kind needs no digest (it is never printed), only what it keeps.
  if (!(input.state && r.rendered === undefined)) {
    const rendered = sanitizeRendered(r.rendered) as Record<string, unknown> | undefined;
    if (rendered && typeof rendered === "object" && Buffer.byteLength(JSON.stringify(rendered), "utf8") <= MAX_RENDERED_BYTES) out.rendered = rendered;
    else out.extError = "the rendered digest was too large";
  }
  if (r.keep !== undefined) {
    try {
      const s = JSON.stringify(r.keep);
      if (s !== undefined && Buffer.byteLength(s, "utf8") <= MAX_KEPT_BYTES) out.kept = { v: input.v, body: JSON.parse(s) };
    } catch {
      // not JSON: not kept
    }
  }
  return out;
}
