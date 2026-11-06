// Copyright 2026 Ix Infrastructure Inc.
//
// A fake `p2p` and a manual clock for unit tests: every CLI call is
// recorded (argv and stdin), and answered from `world`.

import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bridge, type Clock } from "../bridge.js";
import type { TrustedMode } from "../trusted.js";
import type { PeerRow } from "../lib.js";
import { McpServer, type JsonObject } from "../mcp.js";
import { P2P, type Exec } from "../p2p.js";
import { makeTools, refuseMutating, serverInstructions } from "../tools.js";

export const ME = "p2p:mememememememememememememememememe";
export const ANN = "p2p:annannannannannannannannannannann";
export const ANN_ADDR = "ann@anna-nnan-nann-anna";
export const BEN = "p2p:benbenbenbenbenbenbenbenbenbenbenb";
export const BEN_ADDR = "ben@benb-enbe-nben-benb";

export type Call = { argv: string[]; stdin?: string };

export class World {
  calls: Call[] = [];
  peers: PeerRow[] = [];
  held: unknown[] = [];
  identity = true;
  /** What the thread's rollout file says (the trusted mode), as RolloutReader would report it. */
  trusted: TrustedMode | null = null;
  /** What `p2p own-agents` says (the person's setting). */
  ownAgents: { ownAgents: "hold" | "deliver"; devices: string[] | "all-other" } = { ownAgents: "hold", devices: [] };
  t = 1_000_000;
  timers: { at: number; every?: number; fn: () => void; dead?: boolean }[] = [];

  exec: Exec = {
    run: async (argv, init) => {
      const args = argv.slice(1);
      this.calls.push({ argv: args, ...(init?.stdin !== undefined ? { stdin: init.stdin } : {}) });
      const verb = args[0];
      const ok = (v: unknown) => ({ exitCode: 0, stdout: JSON.stringify(v), stderr: "" });
      if (verb === "whoami") return this.identity ? ok({ userId: ME, name: "me", address: "me@meme-meme-meme-meme", did: "d1", relays: ["wss://r/v3"] }) : { exitCode: 1, stdout: JSON.stringify({ error: "no_identity", reason: "none" }), stderr: "" };
      if (verb === "session") return ok({ roster: { sid: args.at(-1), ref: "aaa111", vis: "private", parts: [] } });
      if (verb === "status") return ok({ delivered: [], failed: [] });
      if (verb === "ls") return ok({ peers: this.peers, relays: { listed: ["wss://r/v3"], connected: ["wss://r/v3"], failed: [] } });
      if (verb === "held") return ok({ held: this.held });
      if (verb === "own-agents") return ok(this.ownAgents);
      if (verb === "send") {
        const to = (args.find((a) => a.startsWith("--to=")) ?? "").slice(5);
        return ok({ delivered: true, to: { userId: to.split(" ")[0], address: ANN_ADDR, own: ANN, sid: "s1", ref: "abc123" }, relays: 1 });
      }
      return { exitCode: 1, stdout: JSON.stringify({ error: "unknown", reason: `fake p2p: ${verb}` }), stderr: "" };
    },
  };

  clock: Clock = {
    now: () => this.t,
    every: (ms, fn) => {
      const t: World["timers"][number] = { at: this.t + ms, every: ms, fn };
      this.timers.push(t);
      return { cancel: () => void Object.assign(t, { dead: true }) };
    },
    after: (ms, fn) => {
      const t: World["timers"][number] = { at: this.t + ms, fn };
      this.timers.push(t);
      return { cancel: () => void Object.assign(t, { dead: true }) };
    },
    sleep: () => new Promise(() => {}),
  };

  advance(ms: number): void {
    const end = this.t + ms;
    for (;;) {
      const next = this.timers.filter((t) => !t.dead && t.at <= end).sort((a, b) => a.at - b.at)[0];
      if (!next) break;
      this.t = next.at;
      if (next.every) next.at += next.every;
      else next.dead = true;
      next.fn();
    }
    this.t = end;
  }

  sent(): Call[] {
    return this.calls.filter((c) => c.argv[0] === "send");
  }
  statuses(): Call[] {
    return this.calls.filter((c) => c.argv[0] === "status");
  }
}

export const tick = () => new Promise((r) => setTimeout(r, 0));

export async function makeBridge(o: { env?: Record<string, string>; root?: string; world?: World; queue?: (id: string, text: string) => Promise<boolean>; codexHome?: string; p2pHome?: string; refusal?: string; releaseRefusal?: string; cwd?: string } = {}) {
  const world = o.world ?? new World();
  // A real folder: shared files must exist in the repo.
  const root = o.root ?? realpathSync(mkdtempSync(join(tmpdir(), "bridge-repo-")));
  if (!o.root) {
    mkdirSync(join(root, "src"), { recursive: true });
    for (const f of ["a.ts", "auth.ts", "b.ts", "x.ts", "z.ts"]) writeFileSync(join(root, "src", f), "");
  }
  const lines: ((line: string) => void)[] = [];
  const bridge = new Bridge({
    p2p: new P2P(world.exec, ["p2p"]),
    bin: ["p2p"],
    watch: async (_argv, onLine, signal) => {
      lines.push(onLine);
      await new Promise<void>((r) => signal.addEventListener("abort", () => r(), { once: true }));
      return { code: 0, stderr: "" };
    },
    env: o.env ?? {},
    clock: world.clock,
    git: async (_cwd, args) => (args.includes("--show-toplevel") ? root : args.includes("HEAD") ? "main" : undefined),
    cwd: o.cwd ?? root,
    transcript: () => ({ refresh: async () => world.trusted }),
    ...(o.codexHome ? { codexHome: o.codexHome } : {}),
    ...(o.p2pHome ? { p2pHome: o.p2pHome } : {}),
    ...(o.refusal ? { refusal: o.refusal } : {}),
    ...(o.releaseRefusal ? { releaseRefusal: o.releaseRefusal } : {}),
    ...(o.queue ? { queue: o.queue } : {}),
  });
  await bridge.start();
  await bridge.settled();
  const server = new McpServer({ name: "peer2peer", version: "t", instructions: serverInstructions() }, makeTools(bridge), (line) => out.push(JSON.parse(line)), refuseMutating);
  const out: JsonObject[] = [];
  let id = 0;
  const call = async (name: string, args: JsonObject = {}, meta?: JsonObject) => {
    const n = ++id;
    await server.onLine(JSON.stringify({ jsonrpc: "2.0", id: n, method: "tools/call", params: { name, arguments: args, ...(meta ? { _meta: meta } : {}) } }));
    const r = out.find((m) => m.id === n) as { result: { content: { text: string }[]; isError?: boolean } };
    return { text: r.result.content.map((c) => c.text).join("\n"), isError: r.result.isError === true };
  };
  /** Feeds one watch line, as `p2p watch --jsonl` prints it. */
  const feed = async (event: Record<string, unknown>) => {
    await bridge.onLine(JSON.stringify(event.toSession === "SELF" ? { ...event, toSession: bridge.sid } : event));
  };
  /**
   * Codex says, through its trusted channels, that this session asks before
   * acting: a tool call's _meta binds the thread (sandbox read-only), and the
   * thread's rollout file has an on-request, read-only turn context.
   */
  const asking = async () => {
    world.trusted = { mode: { approval: "on-request", sandbox: "read-only", autoReview: false }, seq: (world.trusted?.seq ?? 0) + 1 };
    bridge.noteToolCall({ threadId: "thread-1", mode: { sandbox: "read-only", autoReview: false } });
    await bridge.refreshTrusted();
  };
  return { world, bridge, server, call, feed, out, lines, root, asking };
}

let seq = 0;
export function message(o: {
  from?: string;
  address?: string;
  text: string;
  self?: boolean;
  toSession?: string | null;
  own?: string;
  sid?: string;
  /** The sending device ("d1" is this one). */
  did?: string;
  /** An own-session message's origin as the CLI logs it (sessions.ts ownOrigin). */
  via?: "person" | "agent";
  fromRef?: string;
}) {
  const from = o.from ?? ANN;
  return {
    kind: "p2p.message",
    id: `m${++seq}`,
    at: 1_000_000,
    from: { userId: from, address: o.address ?? ANN_ADDR, did: o.did ?? "x", self: o.self === true },
    own: o.own ?? from,
    sid: o.sid ?? "s1",
    ref: "abc123",
    text: o.text,
    ...(o.via ? { via: o.via } : {}),
    ...(o.fromRef ? { fromRef: o.fromRef } : {}),
    ...(o.toSession === null ? {} : { toSession: o.toSession ?? "SELF" }),
  };
}
