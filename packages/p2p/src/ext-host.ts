// Copyright 2026 Ix Infrastructure Inc.
//
// The host side of the extension seam (extensions.ts): the ExtContext a
// command of an extension runs with, and the `p2p <ns> …` commands built from
// its declarations. An extension sees only this context: it can send kinds of
// its own namespace through the ordinary session path (§4.2 decides who may
// receive them), read the events it rendered, and read the local status
// table. It never sees keys or the trust store.

import { createHash, createHmac } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import type { Command } from "commander";
import { displayStatus, sanitizePeerText, type ExtensionKind } from "@peer2peer/core/v3";
import type { App, Io } from "./app.js";
import { CliError } from "./errors.js";
import {
  enabledNamespaces,
  extensionPackageName,
  kindNamespace,
  KNOWN_EXTENSIONS,
  setExtensionEnabled,
  type ExtContext,
  type ExtensionRegistry,
  type ExtEvent,
  type ExtPeer,
  type ExtStateValue,
  type P2PExtension,
} from "./extensions.js";
import { listPeers, sendExtension, sessionAudience, sessionRef } from "./sessions.js";
import { sessKey, type EventRec, type XStateRec } from "./state.js";
import { declaredState, expiresAt, keptCopy, liveStates, publishExtensionState } from "./xstate.js";

/** ExtContext.localMac: HMAC-SHA256 keyed by sha256(label, namespace, this device's signing secret). */
function localMac(app: App, ns: string, data: string): string {
  const secret = app.device?.signingSecretKey;
  if (!secret) throw new CliError("no_identity", "no identity here yet: run `p2p init`");
  const key = createHash("sha256").update("p2p/ext-local-mac/v1|").update(ns).update("|").update(secret).digest();
  return createHmac("sha256", key).update(data, "utf8").digest("base64url");
}

export const IX_INSTALL_HINT = "https://github.com/ix-infrastructure/Ix";

function stateValue(r: XStateRec): ExtStateValue {
  const body = keptCopy(r.body);
  return { v: r.v, ...(body !== undefined ? { body } : {}), fallback: r.fallback, at: r.ts, expiresAt: expiresAt(r), ...(r.extError ? { extError: r.extError } : {}) };
}

function toExtEvent(e: EventRec): ExtEvent {
  const d = e.data as Record<string, any>;
  return {
    id: e.id,
    at: e.at,
    kind: String(d.ext),
    from: { userId: String(d.from?.userId ?? ""), address: String(d.from?.address ?? ""), self: d.from?.self === true },
    ...(e.own ? { own: e.own } : {}),
    ...(e.sid ? { sid: e.sid } : {}),
    ...(typeof d.ref === "string" ? { ref: d.ref } : {}),
    fallback: String(d.fallback ?? ""),
    ...(d.rendered && typeof d.rendered === "object" ? { rendered: d.rendered } : {}),
    ...(d._kept && typeof d._kept === "object" ? { kept: d._kept } : {}),
    ...(typeof d.extError === "string" ? { extError: d.extError } : {}),
  };
}

export function extContext(app: App, ext: P2PExtension, io: Io, json: boolean, confirm: (q: string, yes?: boolean) => Promise<boolean>): ExtContext {
  return {
    env: app.env,
    cwd: extWorkdir(app.env),
    io: { err: (s) => io.err(s), ...(io.readStdin ? { readStdin: io.readStdin } : {}) },
    json,
    interactive: !json && io.prompt !== undefined,
    kv: extStore(app.home, ext.ns),
    confirm: (q, yes) => (json && !yes ? Promise.resolve(false) : confirm(q, yes)),
    self: async () => ({ userId: app.userId, address: await app.addressOf(app.userId) }),
    send: async (o) => {
      if (kindNamespace(o.kind) !== ext.ns) throw new CliError("usage", `${ext.name} may only send x:${ext.ns}.* kinds`);
      if (ext.state?.[o.kind]) throw new CliError("usage", `${o.kind} is a state kind: publish it (to the session's status audience), don't send it`);
      return sendExtension(app, { ...o, kind: o.kind as ExtensionKind });
    },
    publish: async (o) => {
      if (kindNamespace(o.kind) !== ext.ns) throw new CliError("usage", `${ext.name} may only publish x:${ext.ns}.* kinds`);
      const decl = ext.state?.[o.kind] ? declaredState(app.extensions, o.kind) : undefined;
      if (!decl) throw new CliError("usage", `${o.kind} isn't one of ${ext.name}'s state kinds`);
      return publishExtensionState(app, { fromSession: o.fromSession, kind: o.kind, v: o.v, body: o.body, fallback: o.fallback, ttl: o.ttl ?? decl.ttl });
    },
    peerState: async (kind) => {
      if (kindNamespace(kind) !== ext.ns) throw new CliError("usage", `${ext.name} may only read x:${ext.ns}.* state`);
      await app.connectAndDrain().catch((e) => io.err(`p2p: offline: ${sanitizePeerText((e as Error).message, 200)}`));
      const blocks = new Set((await app.store.listBlocks()).map((b) => b.userId));
      const out = [];
      for (const r of await liveStates(app, { kind })) {
        if (blocks.has(r.own)) continue;
        out.push({ own: r.own, sid: r.sid, ref: sessionRef(r.own, r.sid), address: await app.addressOf(r.own), self: r.own === app.userId, thisDevice: r.own === app.userId && r.did === app.did, kind: r.kind, ...stateValue(r) });
      }
      return out;
    },
    events: async (filter = {}) => {
      const log = (await app.state.get("events"))?.items ?? [];
      return log
        .filter((e) => e.kind === "p2p.ext" && kindNamespace(String(e.data.ext)) === ext.ns)
        .filter((e) => (filter.id === undefined || e.id === filter.id) && (filter.kind === undefined || e.data.ext === filter.kind))
        .map(toExtEvent);
    },
    peers: async (opts = {}) => {
      await app.connectAndDrain().catch((e) => io.err(`p2p: offline: ${sanitizePeerText((e as Error).message, 200)}`));
      const rows = await listPeers(app, { all: opts.all });
      const states = await liveStates(app, { ns: ext.ns });
      return rows.map((r): ExtPeer => {
        const mine = states.filter((x) => x.own === r.own && x.sid === r.sid);
        return {
          own: r.own,
          sid: r.sid,
          ref: r.ref,
          address: r.address,
          self: r.self,
          thisDevice: r.thisDevice,
          live: r.live,
          state: r.state,
          label: r.label,
          ...(r.repo ? { repo: r.repo } : {}),
          ...(r.branch ? { branch: r.branch } : {}),
          files: r.files,
          ...(r.caps ? { caps: [...r.caps] } : {}),
          ...(r.agents ? { agents: r.agents.map((a) => ({ ...a, ...(a.files ? { files: [...a.files] } : {}) })) } : {}),
          ...(mine.length > 0 ? { xstate: Object.fromEntries(mine.map((x) => [x.kind, stateValue(x)])) } : {}),
        };
      });
    },
    audience: (sid) => sessionAudience(app, sid),
    localMac: (data) => localMac(app, ext.ns, data),
    ownStatus: async (sid) => {
      const rec = (await app.state.get("peers"))?.[sessKey(app.userId, sid)];
      if (!rec) return undefined;
      // Through displayStatus, as peers() is: the same validation and copies, never the stored objects.
      const d = displayStatus(rec.status);
      return { ...(rec.status.repo ? { repo: rec.status.repo } : {}), files: rec.status.files ?? [], ...(d.caps ? { caps: d.caps } : {}), ...(d.agents ? { agents: d.agents } : {}) };
    },
  };
}

/** ExtContext.kv: <home>/ext/<ns>.json, written atomically, 0600. */
export const MAX_EXT_STORE_BYTES = 64 * 1024;
function extStore(home: string, ns: string): ExtContext["kv"] {
  const dir = join(home, "ext");
  const file = join(dir, `${ns}.json`);
  const read = (): Record<string, unknown> => {
    try {
      const v: unknown = JSON.parse(readFileSync(file, "utf8"));
      return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
    } catch {
      return {};
    }
  };
  return {
    get: async (key) => read()[key],
    set: async (key, value) => {
      const next = JSON.stringify({ ...read(), [key]: value });
      if (Buffer.byteLength(next, "utf8") > MAX_EXT_STORE_BYTES) throw new CliError("too_large", `the ${ns} extension's store would exceed ${MAX_EXT_STORE_BYTES} bytes`);
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      const tmp = `${file}.${process.pid}.tmp`;
      writeFileSync(tmp, next, { mode: 0o600 });
      renameSync(tmp, file);
    },
  };
}

/**
 * The directory extension commands treat as the user's working directory (the
 * repo an Ix command looks at): P2P_WORKDIR when it names an existing absolute
 * directory, else the process's. A client that runs `p2p` from elsewhere (the
 * Claude mod runs it from the plugin folder) passes the session's directory here.
 */
export function extWorkdir(env: Record<string, string | undefined>): string {
  const w = env.P2P_WORKDIR?.trim();
  if (w && isAbsolute(w)) {
    try {
      if (statSync(w).isDirectory()) return w;
    } catch {
      // not there: the process's own
    }
  }
  return process.cwd();
}

type RunFn = <A extends unknown[]>(fn: (app: App, ...args: A) => Promise<{ json: unknown; human: string }>, opts?: { requireIdentity?: boolean }) => (...args: A) => Promise<void>;

/** An error an extension threw, as a CliError (extensions can't share our class: duck-typed `code`). */
function asCliError(e: unknown): unknown {
  if (e instanceof CliError) return e;
  const x = e as { code?: unknown; message?: unknown; extra?: unknown } | null;
  if (x && typeof x.code === "string" && /^[a-z][a-z0-9_]{0,39}$/.test(x.code) && typeof x.message === "string") {
    return new CliError(x.code, x.message, x.extra && typeof x.extra === "object" ? (x.extra as Record<string, unknown>) : {});
  }
  return e;
}

/**
 * Adds `p2p <ns> …` for every loaded extension with commands, a stub for each
 * registered namespace that isn't installed (it explains how to get it), and
 * `p2p extensions`.
 */
export function registerExtensionCommands(
  program: Command,
  reg: ExtensionRegistry,
  deps: { io: Io; run: RunFn; confirm: (q: string, yes?: boolean) => Promise<boolean>; collect: (v: string, prev?: string[]) => string[] },
): void {
  const taken = (name: string) => program.commands.some((c) => c.name() === name);
  for (const { ext } of reg.list()) {
    if (!ext.commands?.length || taken(ext.ns)) continue;
    const group = program.command(ext.ns).description(sanitizePeerText(ext.description ?? `${ext.name} ${ext.version}`, 200));
    for (const c of ext.commands) {
      const cmd = group.command(c.args ? `${c.name} ${c.args}` : c.name).description(sanitizePeerText(c.description, 300));
      for (const o of c.options ?? []) {
        if (o.repeatable) cmd.option(o.flags, o.description, deps.collect);
        else if (o.default !== undefined) cmd.option(o.flags, o.description, o.default);
        else cmd.option(o.flags, o.description);
      }
      cmd.option("--json", "JSON output");
      cmd.action(
        deps.run(async (app, ...rest: unknown[]) => {
          const command = rest[rest.length - 1] as Command;
          const opts = (rest[rest.length - 2] ?? {}) as Record<string, unknown>;
          const args = rest.slice(0, -2);
          try {
            return await c.run(extContext(app, ext, deps.io, Boolean(command.opts().json), deps.confirm), args, opts);
          } catch (e) {
            throw asCliError(e);
          }
        }),
      );
    }
  }
  for (const ns of KNOWN_EXTENSIONS) {
    if (reg.get(ns) || taken(ns)) continue;
    const pkg = extensionPackageName(ns);
    const how = `npm i -g ${pkg}${ns === "ix" ? ` (and Ix itself: ${IX_INSTALL_HINT})` : ""}, then \`p2p extensions enable ${ns}\` (extensions run with your identity: install only ones you trust)`;
    program
      .command(ns)
      .description(`(not enabled) the ${ns} extension: ${how}`)
      .argument("[args...]")
      .allowUnknownOption()
      .helpOption(false)
      .option("--json", "JSON output")
      .action(
        deps.run(
          async () => {
            throw new CliError("extension_missing", `\`p2p ${ns}\` needs the ${ns} extension: ${how}`, { extension: pkg });
          },
          { requireIdentity: false },
        ),
      );
  }
  const group = program
    .command("extensions")
    .description("Extensions (@peer2peer/ext-*): loaded, enabled, and how to enable one (opt-in; they run with your identity)")
    .option("--json", "JSON output")
    .action(
      deps.run(
        async (app) => {
          const loaded = reg.list().map((l) => ({ ns: l.ext.ns, name: l.ext.name, version: l.ext.version, from: l.from, commands: (l.ext.commands ?? []).map((c) => c.name) }));
          const { enabled, ignored } = enabledNamespaces(app.env, app.file);
          const missing = KNOWN_EXTENSIONS.filter((ns) => !reg.get(ns)).map(extensionPackageName);
          const human = [
            ...(loaded.length ? loaded.map((l) => `${l.name} ${l.version} (x:${l.ns}.*): ${l.from}`) : ["no extensions loaded"]),
            `enabled: ${enabled.length ? enabled.join(", ") : "none"}${app.env.P2P_EXTENSIONS !== undefined ? " (from P2P_EXTENSIONS)" : ""}`,
            ...(ignored.length ? [`ignored (not registered): ${ignored.join(", ")}`] : []),
          ].join("\n");
          return { json: { extensions: loaded, enabled, missing, ...(ignored.length ? { ignored } : {}) }, human };
        },
        { requireIdentity: false },
      ),
    );
  for (const on of [true, false]) {
    group
      .command(`${on ? "enable" : "disable"} <ns>`)
      .description(on ? `Enable an installed extension (${KNOWN_EXTENSIONS.join(", ")}): its code runs inside p2p with your identity` : "Disable an extension")
      .option("--json", "JSON output")
      .action(
        deps.run(
          async (app, ns: string) => {
            let list: string[];
            try {
              list = setExtensionEnabled(app.home, ns, on);
            } catch (e) {
              throw new CliError("usage", (e as Error).message);
            }
            const note = app.env.P2P_EXTENSIONS !== undefined ? " (P2P_EXTENSIONS is set and overrides config.json)" : "";
            return { json: { enabled: list }, human: `${on ? "Enabled" : "Disabled"} ${ns}; enabled: ${list.length ? list.join(", ") : "none"}${note}.` };
          },
          { requireIdentity: false },
        ),
      );
  }
}
