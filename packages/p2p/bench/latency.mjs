#!/usr/bin/env node
// Copyright 2026 Ix Infrastructure Inc.
//
// The end-to-end latency benchmark: two throwaway identities (temporary P2P
// homes and HOME, never ~/.p2p) on a local relay (packages/relay, SQLite in a
// temporary directory), reached through a TCP proxy that adds a simulated
// round-trip time. It reports p50/p95 for:
//
//   a  cold `p2p` startup: node boot, module load, keys and state, extensions
//   b  relay connect: WebSocket open + hello, then device auth
//   c  `p2p send` until the message line appears in the recipient's `watch --jsonl`
//   d  `p2p status` until the status reaches the peer's watch, and the peer's `ls`;
//      and a status to a session shared with --friends more friends (the fan-out)
//   e  the Claude mod path: backend.ts P2P.send → watchLoop event → <cross-session-message>
//      (as the mod's integration test drives it; an idle session adds the mod's gather window)
//   f  `p2p ls --json` with N peer sessions held
//   g  an identity document refresh (HTTP tips + verification), and verification alone
//
// with each CLI command broken into stages from its P2P_DEBUG step log
// (connect, drain, relay requests, document refresh, and the rest: boot,
// disk, crypto, close). Every scenario runs at RTT 0 (loopback) and at the
// simulated RTT (default 80 ms: users are on a private network or the internet).
//
// Usage (from packages/p2p, after building core, relay, codex-bridge and p2p):
//   node bench/latency.mjs [--iters 15] [--rtt 80] [--peers 1,50,200] [--friends 6] [--bin bundle|dist] [--json out.json] [--only a,b,c] [--trace]
//   (--trace prints the last run's P2P_DEBUG step log per scenario, with arrival times)
//
// Nothing here talks to a real relay or reads a real P2P home.

import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { build } from "esbuild";
import { WebSocket } from "ws";
import * as coreMod from "../../core/dist/v3/index.js";
import * as relayMod from "../../relay/dist/index.js";
import * as cliMod from "../dist/index.js";
import { startProxy } from "./proxy.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const pkg = resolve(here, "..");
const repo = resolve(pkg, "../..");

const { values: args } = parseArgs({
  options: {
    iters: { type: "string", default: "15" },
    rtt: { type: "string", default: "80" },
    peers: { type: "string", default: "1,50,200" },
    friends: { type: "string", default: "6" },
    bin: { type: "string", default: "bundle" },
    json: { type: "string" },
    only: { type: "string" },
    trace: { type: "boolean", default: false },
  },
});
const ITERS = Number(args.iters);
const RTTS = [0, Number(args.rtt)].filter((v, i, a) => a.indexOf(v) === i);
const PEER_COUNTS = args.peers.split(",").map(Number);
const ONLY = args.only ? new Set(args.only.split(",")) : undefined;
const want = (s) => !ONLY || ONLY.has(s);
const BUNDLE = join(repo, "mods/claude/peer2peer/bin/p2p.mjs");
const DIST = join(pkg, "dist/bin.js");
const BIN = args.bin === "dist" || !existsSync(BUNDLE) ? DIST : BUNDLE;
const RELAY = "wss://relay-bench.test/v3";


// ---------------------------------------------------------------------------
// Stats

function pct(xs, p) {
  if (xs.length === 0) return NaN;
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.max(0, Math.ceil((p / 100) * s.length) - 1))];
}
const results = [];
/** --trace: the watch child's P2P_DEBUG lines, with arrival times. */
const watchTrace = [];
function record(scenario, rtt, metric, samples) {
  results.push({ scenario, rtt, metric, n: samples.length, p50: pct(samples, 50), p95: pct(samples, 95) });
}
const now = () => performance.now();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// The simulated link: a TCP proxy that holds each chunk for RTT/2 in each direction (proxy.mjs,
// shared with the soak harness in scripts/soak).

// ---------------------------------------------------------------------------
// Homes and the CLI

const scratch = mkdtempSync(join(tmpdir(), "p2p-bench-"));
let proxy;

function envFor(home, extra = {}) {
  // Built from scratch: nothing from the caller's environment but PATH, so no P2P_* setting leaks in.
  return {
    PATH: process.env.PATH ?? "",
    HOME: join(scratch, "home"),
    P2P_HOME: home,
    P2P_DEFAULT_RELAYS: RELAY,
    P2P_RELAY_TRANSPORT: JSON.stringify({ [RELAY]: `ws://127.0.0.1:${proxy.port}/v3` }),
    P2P_EXTENSIONS: "none",
    ...extra,
  };
}

const STEP_RE = /^p2p: debug: (.*): (done in|failed after) (\d+)ms/;

/** Runs `p2p <argv>` and times it; stderr lines carry the parent's arrival time. */
function cli(home, argv, { stdin = "", env = {}, debug = true } = {}) {
  return new Promise((resolveRun, reject) => {
    const t0 = now();
    const child = spawn(process.execPath, [BIN, ...argv], { env: envFor(home, { ...(debug ? { P2P_DEBUG: "1" } : {}), ...env }), stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let errBuf = "";
    const lines = [];
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => {
      const t = now();
      errBuf += d;
      let i;
      while ((i = errBuf.indexOf("\n")) >= 0) {
        lines.push({ t, line: errBuf.slice(0, i) });
        errBuf = errBuf.slice(i + 1);
      }
    });
    child.on("error", reject);
    child.on("close", (code) => {
      const t1 = now();
      let json;
      try {
        json = JSON.parse(stdout);
      } catch {
        json = undefined;
      }
      resolveRun({ code, json, stdout, lines, t0, t1, ms: t1 - t0 });
    });
    child.stdin.end(stdin);
  });
}

/** Stage durations from a run's P2P_DEBUG lines. */
function stagesOf(run) {
  const s = { connect: 0, drain: 0, request: 0, docRefresh: 0, fetch: 0, lock: 0 };
  let last = run.t0;
  for (const { t, line } of run.lines) {
    last = Math.max(last, t);
    const m = STEP_RE.exec(line);
    if (!m) continue;
    const label = m[1];
    const ms = Number(m[3]);
    if (/^connecting to/.test(label)) s.connect += ms;
    else if (/^receiving what your relays queued|^handling \d+ queued/.test(label)) s.drain += ms;
    else if (/^waiting for .* to answer auth/.test(label)) continue; // inside connect
    else if (/^waiting for .* to answer/.test(label)) s.request += ms;
    else if (/^refreshing .* identity document/.test(label)) s.docRefresh += ms;
    else if (/^fetching/.test(label)) s.fetch += ms;
  }
  // What the step log doesn't cover: node boot and module load, keys and state on disk,
  // crypto, and closing the connection on the way out.
  s.other = Math.max(0, run.ms - s.connect - s.drain - s.request - s.docRefresh);
  return s;
}

function recordStages(scenario, rtt, runs) {
  if (args.trace) {
    const r = runs.at(-1);
    console.error(`trace: ${scenario} @ RTT ${rtt} (${Math.round(r.ms)} ms)`);
    for (const { t, line } of r.lines) console.error(`  +${String(Math.round(t - r.t0)).padStart(5)}  ${line}`);
  }
  const keys = ["connect", "drain", "request", "docRefresh", "fetch", "other"];
  const st = runs.map(stagesOf);
  for (const k of keys) {
    const xs = st.map((x) => x[k]);
    if (xs.some((v) => v > 0)) record(scenario, rtt, `  stage: ${k}`, xs);
  }
}

function ok(run, what) {
  if (run.code !== 0) throw new Error(`${what} failed (${run.code}): ${run.stdout}\n${run.lines.map((l) => l.line).join("\n")}`);
  return run.json;
}

// ---------------------------------------------------------------------------
// The mod's backend (hooks/backend.ts + lib.ts), bundled once for node

async function loadModBackend() {
  const src = join(scratch, "mod-entry.ts");
  writeFileSync(
    src,
    `export { P2P, watchLoop } from ${JSON.stringify(join(repo, "mods/claude/peer2peer/hooks/backend.ts"))};\nexport { wrapMessage, eventAddress } from ${JSON.stringify(join(repo, "mods/claude/peer2peer/hooks/lib.ts"))};\n`,
  );
  // Next to this script (gitignored) so the import below is a literal: scripts/check-boundaries.mjs
  // allows a computed import() nowhere but the extension loader. Removed once loaded.
  const out = join(here, ".mod-backend.mjs");
  await build({ entryPoints: [src], outfile: out, bundle: true, platform: "node", format: "esm", logLevel: "error" });
  try {
    return await import("./.mod-backend.mjs");
  } finally {
    rmSync(out, { force: true });
  }
}

/** node's child_process as the mod's Exec (what `$.process` is in Claude Code; as the integration harness). */
function nodeExec(env) {
  return {
    run: (argv, init) =>
      new Promise((res, rej) => {
        const child = spawn(argv[0], argv.slice(1), { env, stdio: ["pipe", "pipe", "pipe"] });
        let stdout = "";
        let stderr = "";
        const timer = setTimeout(() => child.kill("SIGKILL"), init?.timeoutMs ?? 30_000);
        child.stdout.on("data", (d) => (stdout += d));
        child.stderr.on("data", (d) => (stderr += d));
        child.on("error", (e) => (clearTimeout(timer), rej(e)));
        child.on("close", (code) => (clearTimeout(timer), res({ exitCode: code ?? 1, stdout, stderr })));
        child.stdin.end(init?.stdin ?? "");
      }),
    spawn: (argv, init) =>
      (async function* () {
        const child = spawn(argv[0], argv.slice(1), { env, stdio: ["ignore", "pipe", "pipe"] });
        // return() can't reach a generator parked on the next chunk: the run's signal kills the child.
        init?.signal?.addEventListener("abort", () => child.kill("SIGTERM"), { once: true });
        const queue = [];
        let ended = null;
        let wake = null;
        const push = () => (wake?.(), (wake = null));
        child.stdout.on("data", (d) => (queue.push({ stream: "stdout", text: String(d) }), push()));
        child.stderr.on("data", (d) => {
          if (args.trace) for (const line of String(d).split("\n")) if (line) watchTrace.push({ t: now(), line });
          queue.push({ stream: "stderr", text: String(d) });
          push();
        });
        child.on("close", (code, signal) => ((ended = { code, signal }), push()));
        try {
          for (;;) {
            while (queue.length > 0) yield queue.shift();
            if (ended) return ended;
            await new Promise((r) => (wake = r));
          }
        } finally {
          if (!ended) child.kill("SIGTERM");
        }
      })(),
  };
}

// ---------------------------------------------------------------------------

const SID_A = "bench-ann-session";
const SID_B = "bench-ben-session";

async function main() {
  console.error(`p2p latency bench: ${BIN === BUNDLE ? "bundled CLI (mods/claude/peer2peer/bin/p2p.mjs)" : "packages/p2p/dist"}, ${ITERS} iterations, RTT ${RTTS.join(" and ")} ms`);
  const relayDir = join(scratch, "relay");
  const crypto = relayMod.createRelayCrypto();
  const store = new relayMod.SqliteStore(join(mkdtempSync(relayDir), "relay.db"));
  const relay = new relayMod.Relay({
    // The bench sends faster than any person (a status to seven friends, fifteen times over, in
    // seconds): only the per-sender send rate is lifted, so the relay's 120/min doesn't refuse it.
    config: relayMod.makeConfig(crypto, { relayUrl: RELAY, logLevel: "error", powBits: 0, limits: { sendsPerMinute: 100_000 } }),
    store,
    crypto,
    logger: relayMod.createLogger({ level: "error", sink: () => {} }),
  });
  const relayPort = await relay.listen();
  proxy = await startProxy(relayPort);
  const setRtt = (ms) => (proxy.state.oneWayMs = ms / 2);

  const ann = { name: "ann", home: join(scratch, "ann") };
  const ben = { name: "ben", home: join(scratch, "ben") };
  // --- setup (RTT 0)
  for (const u of [ann, ben]) {
    const r = ok(await cli(u.home, ["init", `--name=${u.name}`, "--yes", "--json"]), `${u.name} init`);
    u.userId = r.userId;
  }
  const inv = ok(await cli(ann.home, ["invite", "--json"]), "invite");
  ok(await cli(ben.home, ["join", "--json", "--", inv.code]), "join");
  for (let i = 0; i < 20; i++) {
    const f = ok(await cli(ann.home, ["friends", "--json"]), "friends");
    if (f.friends.some((x) => x.userId === ben.userId && x.canMessage)) break;
    await sleep(200);
  }
  ok(await cli(ann.home, ["session", "roster", `--add=${ben.userId}`, "--json", "--", SID_A]), "roster ann");
  ok(await cli(ben.home, ["session", "roster", `--add=${ann.userId}`, "--json", "--", SID_B]), "roster ben");
  ok(await cli(ben.home, ["status", `--session=${SID_B}`, "--state=idle", "--label=api", "--json"]), "status ben");
  ok(await cli(ann.home, ["status", `--session=${SID_A}`, "--state=busy", "--label=web", "--json"]), "status ann");
  // More friends of Ann's, sharing a second session of hers (the status fan-out).
  const extra = [];
  for (let i = 0; i < Number(args.friends); i++) {
    const u = { name: `friend${i}`, home: join(scratch, `friend${i}`) };
    u.userId = ok(await cli(u.home, ["init", `--name=${u.name}`, "--yes", "--json"]), "init").userId;
    const code = ok(await cli(ann.home, ["invite", "--json"]), "invite").code;
    ok(await cli(u.home, ["join", "--json", "--", code]), "join");
    extra.push(u);
  }
  for (let i = 0; i < 20 && extra.length > 0; i++) {
    const f = ok(await cli(ann.home, ["friends", "--json"]), "friends");
    if (extra.every((u) => f.friends.some((x) => x.userId === u.userId && x.canMessage))) break;
    await sleep(200);
  }
  const SID_FAN = "bench-ann-fanout";
  for (const u of [ben, ...extra]) ok(await cli(ann.home, ["session", "roster", `--add=${u.userId}`, "--json", "--", SID_FAN]), "roster fan-out");
  let benRef;
  for (let i = 0; i < 20 && !benRef; i++) {
    const ls = ok(await cli(ann.home, ["ls", "--json"]), "ls");
    benRef = ls.peers.find((p) => p.own === ben.userId && p.sid === SID_B)?.ref;
    if (!benRef) await sleep(200);
  }
  if (!benRef) throw new Error("setup: ben's session never reached ann");
  const toBen = `${ben.userId} [${benRef}]`;

  // Ben's session, watched the way the mod watches it (backend.ts watchLoop over a `p2p watch` child).
  const mod = await loadModBackend();
  const events = [];
  let waiters = [];
  const onEvent = async (e) => {
    const t = now();
    events.push({ t, e });
    for (const w of waiters) w();
    waiters = [];
  };
  let watchEnded = false;
  const watchCtl = new AbortController();
  const benExec = nodeExec(envFor(ben.home, args.trace ? { P2P_DEBUG: "1" } : {}));
  const watching = mod.watchLoop(benExec, [process.execPath, BIN], SID_B, { isEnded: () => watchEnded, onEvent, sleep, signal: watchCtl.signal });
  const waitEvent = async (pred, ms = 30_000) => {
    const end = now() + ms;
    for (;;) {
      const hit = events.find((x) => pred(x.e));
      if (hit) return hit;
      if (now() > end) throw new Error("timed out waiting for a watch event");
      await new Promise((r) => {
        waiters.push(r);
        setTimeout(r, 200);
      });
    }
  };
  // Let the watch connect.
  await sleep(1500);
  const annP2P = new mod.P2P(nodeExec(envFor(ann.home)), [process.execPath, BIN]);

  let seq = 0;
  for (const rtt of RTTS) {
    setRtt(rtt);
    await sleep(300);
    console.error(`-- RTT ${rtt} ms`);

    if (want("a") && rtt === 0) {
      const boot = [];
      const version = [];
      const whoami = [];
      const whoamiExt = [];
      const extEnv = { P2P_EXTENSIONS: "ix", P2P_EXTENSION_PATH: join(repo, "mods/claude/peer2peer/ext") };
      for (let i = 0; i < ITERS; i++) {
        let t0 = now();
        await new Promise((r) => spawn(process.execPath, ["-e", "0"]).on("close", r));
        boot.push(now() - t0);
        version.push((await cli(ann.home, ["--version"], { debug: false })).ms);
        whoami.push((await cli(ann.home, ["whoami", "--json"], { debug: false })).ms);
        whoamiExt.push((await cli(ann.home, ["whoami", "--json"], { debug: false, env: extEnv })).ms);
      }
      record("a cold startup", rtt, "node -e 0 (node boot)", boot);
      record("a cold startup", rtt, "p2p --version (+ module load)", version);
      record("a cold startup", rtt, "p2p whoami --json (+ keys, state)", whoami);
      record("a cold startup", rtt, "p2p whoami --json, ext-ix enabled", whoamiExt);
    }

    if (want("b")) {
      const keys = JSON.parse(readFileSync(join(ann.home, "cli", "keys.json"), "utf8"));
      const signingSecretKey = coreMod.b64uDecode(keys.spk, 32);
      const transport = cliMod.transportResolver(envFor(ann.home), {});
      const toHello = [];
      const full = [];
      for (let i = 0; i < ITERS; i++) {
        let t0 = now();
        await new Promise((res, rej) => {
          const ws = new WebSocket(transport(RELAY).ws, { perMessageDeflate: false });
          ws.once("message", () => (ws.terminate(), res()));
          ws.once("error", rej);
        });
        toHello.push(now() - t0);
        t0 = now();
        const conn = new cliMod.RelayConnection(RELAY, transport(RELAY), { auth: { cert: keys.cert, signingSecretKey }, timeoutMs: 10_000 });
        await conn.open();
        full.push(now() - t0);
        conn.close();
      }
      record("b relay connect", rtt, "TCP + WS upgrade + hello", toHello);
      record("b relay connect", rtt, "  + device auth (RelayConnection.open)", full);
    }

    // A session is live for 150 s after its last status (§4.3): keep Ben's fresh for the sends below.
    const keepLive = async () => ok(await cli(ben.home, ["status", `--session=${SID_B}`, "--state=idle", "--label=api", "--json"], { debug: false }), "status ben");
    await keepLive();

    if (want("c")) {
      const total = [];
      const runs = [];
      for (let i = 0; i < ITERS; i++) {
        const text = `bench-c-${rtt}-${seq++}`;
        const run = await cli(ann.home, ["send", `--from-session=${SID_A}`, `--to=${toBen}`, "--stdin", "--json"], { stdin: text });
        ok(run, "send");
        const hit = await waitEvent((e) => e.kind === "p2p.message" && e.text === text);
        total.push(hit.t - run.t0);
        runs.push(run);
        // The relay's `sent` answer, as the parent saw it: from there to the watch line.
        const sentAt = run.lines.find((l) => /to answer send: done/.test(l.line))?.t;
        run.watchLag = sentAt !== undefined ? hit.t - sentAt : NaN;
        run.hitAt = hit.t;
      }
      if (args.trace) {
        const r = runs.at(-1);
        console.error(`trace: the recipient's watch during the last send (times from the send's spawn; line at +${Math.round(r.hitAt - r.t0)})`);
        for (const { t, line } of watchTrace) if (t >= r.t0 && t <= r.hitAt + 5) console.error(`  +${String(Math.round(t - r.t0)).padStart(5)}  ${line}`);
      }
      record("c send → watch", rtt, "p2p send → line in recipient's watch", total);
      record("c send → watch", rtt, "  p2p send process (spawn → exit)", runs.map((r) => r.ms));
      recordStages("c send → watch", rtt, runs);
      record("c send → watch", rtt, "  relay 'sent' → watch line (delivery + watch poll)", runs.map((r) => r.watchLag).filter(Number.isFinite));
    }

    if (want("d")) {
      const toWatch = [];
      const toLs = [];
      const runs = [];
      const lsRuns = [];
      for (let i = 0; i < ITERS; i++) {
        const summary = `bench-d-${rtt}-${seq++}`;
        const run = await cli(ann.home, ["status", `--session=${SID_A}`, "--state=busy", "--label=web", `--summary=${summary}`, "--json"]);
        ok(run, "status");
        const hit = await waitEvent((e) => e.kind === "p2p.status" && e.status?.summary === summary);
        toWatch.push(hit.t - run.t0);
        runs.push(run);
        const ls = await cli(ben.home, ["ls", "--json"]);
        const seen = ok(ls, "ls").peers.some((p) => p.summary === summary);
        if (!seen) throw new Error("status missing from ls");
        toLs.push(ls.t1 - run.t0);
        lsRuns.push(ls);
      }
      record("d status → peer", rtt, "p2p status → peer's watch", toWatch);
      record("d status → peer", rtt, "p2p status → peer's ls (status, then ls)", toLs);
      record("d status → peer", rtt, "  p2p status process", runs.map((r) => r.ms));
      recordStages("d status → peer", rtt, runs);
      record("d status → peer", rtt, "  p2p ls process", lsRuns.map((r) => r.ms));
      if (extra.length > 0) {
        const fan = [];
        for (let i = 0; i < ITERS; i++) {
          const run = await cli(ann.home, ["status", `--session=${SID_FAN}`, "--state=busy", "--label=fan", `--summary=fan-${seq++}`, "--json"]);
          const r = ok(run, "status fan-out");
          if (r.delivered.length !== extra.length + 1) throw new Error(`fan-out reached ${r.delivered.length} of ${extra.length + 1}: ${JSON.stringify(r.failed)}`);
          fan.push(run);
        }
        record("d2 status fan-out", rtt, `p2p status to ${extra.length + 1} friends (process)`, fan.map((r) => r.ms));
        recordStages("d2 status fan-out", rtt, fan);
      }
    }

    if (want("e")) {
      await keepLive();
      const busy = [];
      const sendCall = [];
      for (let i = 0; i < ITERS; i++) {
        const text = `bench-e-${rtt}-${seq++}`;
        const t0 = now();
        const sent = await annP2P.send({ fromSession: SID_A, to: toBen, text });
        if (!sent.ok) throw new Error(`mod send: ${sent.reason}`);
        sendCall.push(now() - t0);
        const hit = await waitEvent((e) => e.kind === "p2p.message" && e.text === text);
        // What the mod does with it before the model sees it (busy session: appended at once).
        mod.wrapMessage(mod.eventAddress(hit.e, []), hit.e.text);
        busy.push(Math.max(hit.t, now()) - t0);
      }
      record("e mod SendMessage → <cross-session-message>", rtt, "busy recipient (next tool round)", busy);
      record("e mod SendMessage → <cross-session-message>", rtt, "idle recipient (+ 500 ms gather, DELIVER_DEBOUNCE_MS)", busy.map((x) => x + 500));
      record("e mod SendMessage → <cross-session-message>", rtt, "  SendMessage tool call (P2P.send) returns", sendCall);
    }

    if (want("g")) {
      const { App } = cliMod;
      const quietIo = { out: () => {}, err: () => {} };
      const refresh = [];
      const verifyOnly = [];
      const verifyWarm = [];
      const tips = [];
      for (let i = 0; i < ITERS; i++) {
        const app = new App({ env: envFor(ben.home), io: quietIo });
        await app.load(true);
        let t0 = now();
        await app.refreshIdentity(ann.userId, app.relays, { force: true });
        refresh.push(now() - t0);
        const stored = await app.store.getIdentity(ann.userId);
        // Cold: what a fresh process pays (the in-process verification memo, where there is one, emptied).
        coreMod.clearVerifyMemo?.();
        t0 = now();
        coreMod.IdentityChain.fromStored(stored).view();
        verifyOnly.push(now() - t0);
        t0 = now();
        coreMod.IdentityChain.fromStored(stored).view();
        verifyWarm.push(now() - t0);
        t0 = now();
        await cliMod.fetchTips(app.transport(RELAY), ann.userId, 10_000);
        tips.push(now() - t0);
      }
      record("g identity doc refresh", rtt, "refreshIdentity (force)", refresh);
      record("g identity doc refresh", rtt, "  HTTP tips fetch alone", tips);
      record("g identity doc refresh", rtt, "  verify held chain alone (cold process)", verifyOnly);
      record("g identity doc refresh", rtt, "  verify held chain again (same process)", verifyWarm);
    }
  }

  watchEnded = true;
  watchCtl.abort();
  await watching.catch(() => undefined);

  if (want("f")) {
    // Peer sessions held by Ben: N records of Ann's sessions (what `ls` reads, resolves and renders).
    const peersPath = join(ben.home, "cli", "peers.json");
    const base = JSON.parse(readFileSync(peersPath, "utf8"));
    const annRec = Object.values(base).find((p) => p.own === ann.userId);
    for (const n of PEER_COUNTS) {
      const doc = { ...Object.fromEntries(Object.entries(base).filter(([, p]) => p.own !== ann.userId)) };
      for (let i = 0; i < n; i++) {
        const sid = i === 0 ? annRec.sid : `bench-peer-${i}`;
        doc[`${ann.userId}|${sid}`] = { ...annRec, sid, ts: Date.now() };
      }
      writeFileSync(peersPath, JSON.stringify(doc), { mode: 0o600 });
      for (const rtt of RTTS) {
        setRtt(rtt);
        const runs = [];
        for (let i = 0; i < ITERS; i++) runs.push(await cli(ben.home, ["ls", "--json"]));
        for (const r of runs) if (ok(r, "ls").peers.length < n) throw new Error(`ls shows ${r.json.peers.length} of ${n}`);
        record(`f ls (N=${n})`, rtt, `p2p ls --json, ${n} peer sessions`, runs.map((r) => r.ms));
        recordStages(`f ls (N=${n})`, rtt, runs);
      }
    }
  }

  await proxy.close();
  await relay.close();
  store.close?.();

  // --- report
  const fmtMs = (v) => (Number.isFinite(v) ? `${Math.round(v)}` : "-");
  const rows = ["| scenario | metric | RTT ms | p50 ms | p95 ms | n |", "|---|---|---:|---:|---:|---:|"];
  const order = [...new Set(results.map((r) => r.scenario))];
  for (const sc of order) {
    for (const rtt of RTTS) for (const r of results.filter((x) => x.scenario === sc && x.rtt === rtt)) rows.push(`| ${sc} | ${r.metric} | ${rtt} | ${fmtMs(r.p50)} | ${fmtMs(r.p95)} | ${r.n} |`);
  }
  console.log(rows.join("\n"));
  if (args.json) writeFileSync(args.json, JSON.stringify({ bin: BIN === BUNDLE ? "bundle" : "dist", iters: ITERS, rtts: RTTS, node: process.version, platform: process.platform, results }, null, 2) + "\n");
}

try {
  await main();
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
process.exit(0);
