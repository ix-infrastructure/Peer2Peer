#!/usr/bin/env node
// Copyright 2026 Ix Infrastructure Inc.
//
// The multi-user soak and chaos test: several simulated users, each with two
// devices and several sessions, on two local relays reached through simulated
// links (0-150 ms RTT with jitter), driven through the real `p2p` binary for
// minutes to hours, under a seeded random workload (statuses with subagents,
// direct and circle messages, Ix footprints from a fake `ix` over one shared
// fake repository, unfriend and re-invite, circle leave and re-join, sessions
// starting and ending, identity document refreshes) and seeded chaos (relay
// SIGKILL and restart, laptop sleep by SIGSTOP, dropped connections, a skewed
// clock, a mailbox filled near its quota, malformed and poison envelopes, a
// client killed between receiving a message and applying it). Invariants are
// checked continuously and after every heal; see README.md.
//
//   npm run soak -- --quick --seed 7            (from packages/p2p; about 3 minutes)
//   npm run soak -- --minutes 60 --seed 7       (the long mode: 10-minute epochs)
//
// Nothing here reads ~/.p2p or talks to a real relay.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync, copyFileSync, chmodSync, readdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { parseArgs } from "node:util";
import { monitorEventLoopDelay } from "node:perf_hooks";
import { Device, JOIN_APPROVAL_POLL_MS, RelayProc, deliveryErrors, diag, joinedHere, refusedWhilePairChanged, sameSummary, EXT_IX_PKG, FAKE_IX, P2P_BUNDLE_BIN, P2P_DIST_BIN, RELAY_BIN, crashLines, dirBytes, freePort, pct, processesUnder, relayLimits, rng, rssKb, sleep, snapshot } from "./lib.mjs";

const { values: args } = parseArgs({
  options: {
    minutes: { type: "string" },
    seed: { type: "string" },
    quick: { type: "boolean", default: false },
    users: { type: "string" },
    "epoch-minutes": { type: "string" },
    "heal-timeout": { type: "string" },
    bin: { type: "string", default: "dist" },
    out: { type: "string" },
    keep: { type: "boolean", default: false },
    "max-rtt": { type: "string", default: "150" },
    concurrency: { type: "string" },
    "no-chaos": { type: "boolean", default: false },
    "trace-slow": { type: "string" },
    "cpu-prof": { type: "string" },
    help: { type: "boolean", default: false },
  },
});

if (args.help) {
  console.log(readFileSync(new URL("./README.md", import.meta.url), "utf8"));
  process.exit(0);
}

const MODE = args.quick ? "quick" : "long";
const SEED = args.seed !== undefined ? Number(args.seed) : Math.floor(Math.random() * 1e9);
const MINUTES = Number(args.minutes ?? (args.quick ? 2 : 30));
const N_USERS = Math.min(10, Math.max(3, Number(args.users ?? (args.quick ? 3 : 4))));
const EPOCH_MIN = Number(args["epoch-minutes"] ?? (args.quick ? MINUTES : 10));
const HEAL_TIMEOUT_S = Number(args["heal-timeout"] ?? (args.quick ? 90 : 150));
const MAX_RTT = Number(args["max-rtt"]);
const CONCURRENCY = Number(args.concurrency ?? 6);
const CHAOS = !args["no-chaos"];
// dist, bundle, or the path of another build of the CLI (a before/after comparison).
const BIN = args.bin === "bundle" ? P2P_BUNDLE_BIN : args.bin === "dist" ? P2P_DIST_BIN : resolve(args.bin);
const R = rng(SEED);
const planR = R.fork("plan");

for (const f of [BIN, RELAY_BIN, join(EXT_IX_PKG, "dist/index.js"), FAKE_IX]) {
  if (!existsSync(f)) {
    console.error(`missing ${relative(process.cwd(), f)}: build core, relay, codex-bridge, p2p and ext-ix first (in that order)`);
    process.exit(2);
  }
}

const scratch = mkdtempSync(join(tmpdir(), "p2p-soak-"));
const outPath = args.out ?? join(tmpdir(), "p2p-soak-reports", `soak-${MODE}-seed${SEED}-${new Date().toISOString().replace(/[:.]/g, "-")}.json`);
// Diagnostics for tail latency (see lib.mjs `diag`).
if (args["trace-slow"] !== undefined) {
  diag.traceSlowMs = Math.max(1, Number(args["trace-slow"]));
  diag.traceDir = `${outPath.replace(/\.json$/, "")}.traces`;
  mkdirSync(diag.traceDir, { recursive: true });
}
if (args["cpu-prof"] !== undefined) {
  diag.cpuProfDir = resolve(args["cpu-prof"]);
  mkdirSync(diag.cpuProfDir, { recursive: true });
}
const T0 = Date.now();
const since = () => Date.now() - T0;
const log = (...a) => console.error(`[${(since() / 1000).toFixed(1).padStart(7)}s]`, ...a);

// ---------------------------------------------------------------------------
// The recorder: timeline, problems (per invariant), latency samples, children.

const INVARIANTS = {
  "delivery-exactly-once": "every message sent to a reachable recipient is applied on the target device, once, within the heal timeout",
  "no-duplicates": "no message applied twice on a device, and no watch line printed twice (except a line re-printed after its watch was killed)",
  "status-convergence": "every viewer's view of every visible session converges to the latest status delivered to it (summary and agents)",
  "footprint-overlap": "overlaps flagged for every deliberately overlapping pair, both directions, at the right tier; never for non-overlapping pairs",
  "hashed-names": "no readable symbol name of one user in another user's stored state or derived overlap lines",
  "poison-gave-up": "a poison envelope is given up after 3 attempts (never applied) and counted in p2p doctor",
  "malformed-rejected": "a malformed envelope is rejected without crashing the receiver or changing what it holds",
  "crash-mid-apply": "a client killed between receiving and applying a message applies it after restarting, once",
  "doctor": "p2p doctor changes nothing in P2P_HOME and ends with no failed check after healing",
  "resources": "relay and client memory and P2P_HOME size stay bounded",
  "latency": "p50/p95 per operation (calm samples) within budget of the bench README baselines",
  "no-crashes": "no unhandled exception, crash or hang in any process",
  "no-orphans": "no process left running and no relay connection left open after shutdown",
};

// The host itself stalling (the machine slept, or the harness was starved): every timer runs late.
// Commands that span a stall are not the client's hangs, and no sample near one is calm.
const hostStalls = [];
let lastTick = Date.now();
setInterval(() => {
  const now = Date.now();
  if (now - lastTick > 15_000) {
    hostStalls.push({ from: lastTick, to: now });
    rec.ev("host-stall", { s: Math.round((now - lastTick) / 1000) });
    log(`host stalled for ${Math.round((now - lastTick) / 1000)}s (sleep?): run under \`caffeinate -i\` on macOS`);
  }
  lastTick = now;
}, 1000).unref();

// --trace-slow: the harness's own event-loop lag, every second. The links' proxies run in this
// process, so a lag here delays every simulated round trip; a slow command during one is the
// harness's, not the client's.
const harnessLag = [];
if (diag.traceSlowMs > 0) {
  const h = monitorEventLoopDelay({ resolution: 10 });
  h.enable();
  setInterval(() => {
    const max = h.max / 1e6;
    if (max >= 100) harnessLag.push({ t: since(), maxMs: Math.round(max), p99Ms: Math.round(h.percentile(99) / 1e6) });
    h.reset();
  }, 1000).unref();
}
const stalledDuring = (from, to) => hostStalls.some((h) => h.to >= from && h.from <= to);

const rec = {
  timeline: [],
  problems: [],
  samples: {},
  children: new Set(),
  harnessErrors: [],
  crashExpected: new Set(),
  stderrNotes: { gaveUp: 0, rejected: [], warnings: 0 },
  track(child, label) {
    const c = { child, label };
    this.children.add(c);
    child.on("exit", () => this.children.delete(c));
  },
  ev(type, data = {}) {
    this.timeline.push({ t: since(), type, ...data });
  },
  problem(inv, msg, data = {}) {
    if (!INVARIANTS[inv]) inv = "no-crashes";
    this.problems.push({ inv, t: since(), msg, ...data });
    log(`PROBLEM [${inv}] ${msg}`);
  },
  slow: [],
  onSlow(dev, res, op, lines) {
    if (this.slow.length < 400) this.slow.push({ t: since(), startedAt: Math.round(Date.now() - res.ms), pid: res.pid, dev: dev.id, op, ms: Math.round(res.ms), calm: world.calm(dev), lines: lines.slice(0, 400) });
  },
  sample(op, ms, calm) {
    (this.samples[op] ??= []).push({ ms, calm, setup: world.inSetup, t: since() });
  },
  onStderrLine(dev, what, line) {
    if (!line) return;
    if (/^gave-up:/.test(line)) this.stderrNotes.gaveUp++;
    if (/rejected an envelope/.test(line)) this.stderrNotes.rejected.push({ t: since(), dev: dev.id, line: line.slice(0, 300) });
    const bad = crashLines(line);
    if (bad.length > 0) this.problem("no-crashes", `${dev.id} ${what}: ${bad[0].slice(0, 300)}`);
  },
  onCommand(dev, res, op) {
    const calm = world.calm(dev);
    if (res.code === 0) this.sample(op, res.ms, calm);
    for (const line of res.stderr.split("\n")) this.onStderrLine(dev, `p2p ${res.argv[0]}`, line);
    if (res.timedOut && stalledDuring(Date.now() - res.ms - 1000, Date.now())) this.ev("host-stall-timeout", { dev: dev.id, cmd: res.argv[0] });
    else if (res.timedOut) this.problem("no-crashes", `${dev.id} \`p2p ${res.argv.slice(0, 3).join(" ")}\` hung (killed after its timeout)`);
    else if (res.signal === "SIGKILL") {
      if (crashedSince(dev, res)) this.ev("crash-fault", { dev: dev.id, cmd: res.argv[0] });
      else this.problem("no-crashes", `${dev.id} \`p2p ${res.argv[0]}\` died of SIGKILL`);
    } else if (res.signal) this.problem("no-crashes", `${dev.id} \`p2p ${res.argv[0]}\` died of ${res.signal}`);
    else if (res.code !== 0 && res.code !== 1) this.problem("no-crashes", `${dev.id} \`p2p ${res.argv[0]}\` exited ${res.code}`, { stderr: res.stderr.slice(-400) });
  },
  onWatchEvent(dev, w, e) {
    // Duplicate lines: within one watch's lifetime never; across restarts only after an unclean exit.
    const n = (w.ids.get(e.id) ?? 0) + 1;
    w.ids.set(e.id, n);
    if (n > 1) this.problem("no-duplicates", `${dev.id} watch ${w.sid} printed event ${e.id} twice`);
    const seen = (dev.printed ??= new Map());
    const prev = seen.get(e.id);
    if (prev && prev.watchStart !== w.startedAt && prev.sid === w.sid && !prev.uncleanAfter) this.problem("no-duplicates", `${dev.id} watch ${w.sid} re-printed ${e.id} after a clean restart`);
    seen.set(e.id, { watchStart: w.startedAt, sid: w.sid });
    if (e.kind === "p2p.message" && typeof e.text === "string") world.onPrinted(dev, w, e);
  },
  onWatchExit(dev, w, code, signal) {
    // Lines a watch printed before an unclean exit may be printed once more by the next one (its cursor lags a line).
    if (signal === "SIGKILL" && dev.printed) for (const v of dev.printed.values()) if (v.watchStart === w.startedAt) v.uncleanAfter = true;
    if (!w.wanted || world.stopping) return;
    if (signal === "SIGKILL" && crashedSince(dev, { t0: w.startedAt })) this.ev("crash-fault", { dev: dev.id, cmd: `watch ${w.sid}` });
    else this.problem("no-crashes", `${dev.id} watch ${w.sid} exited (code ${code}, signal ${signal})`);
    // The mod restarts its watch: so does the harness.
    setTimeout(() => {
      if (!world.stopping && w.wanted && world.sessionLive(dev, w.sid)) {
        dev.startWatch(w.sid);
        this.ev("watch-restart", { dev: dev.id, sid: w.sid });
      }
    }, 1000);
  },
};

/** A crash-fault marker this device wrote recently: an expected SIGKILL. */
function crashedSince(dev, _res) {
  try {
    const now = Date.now();
    for (const f of readdirSync(dev.faultDir)) {
      if (!f.startsWith("crashed-")) continue;
      const at = JSON.parse(readFileSync(join(dev.faultDir, f), "utf8")).at;
      if (Math.abs(now - at) < 120_000 + Math.abs(dev.skewMs)) return true;
    }
  } catch {}
  return false;
}

// ---------------------------------------------------------------------------
// The world model: what the harness did, so it knows what every device should end up with.

const world = {
  stopping: false,
  inSetup: false,
  relays: [],
  users: [],
  devices: [],
  cid: undefined,
  sessions: new Map(), // `${devId}|${sid}` -> session
  messages: new Map(), // text -> message
  msgN: 0,
  statusN: 0,
  chaos: { relayDown: new Set(), dropAt: 0, pausedUntil: new Map() },
  socialLog: [], // {t, kind, users}
  poison: [],
  crashes: [],
  malformed: [],
  floods: [],
  fpNames: new Map(), // userId -> Set of readable names that user itself published or computed
  calm(dev) {
    if (this.inCheckpoint) return false;
    // Setup runs its steps for every device at once (every session's first status, every
    // device's `circle ls` and `ls`): a synchronized burst on one machine's disk that no real
    // user produces. Reported apart (stats `setup`), not held to the latency budget.
    if (this.inSetup) return false;
    if (stalledDuring(Date.now() - 30_000, Date.now())) return false;
    if (this.chaos.relayDown.size > 0) return false;
    if (Date.now() - this.chaos.dropAt < 10_000) return false;
    if (dev && (dev.paused || Date.now() - dev.lastDropAt < 10_000 || Date.now() - (dev.resumedAt ?? 0) < 15_000)) return false;
    return true;
  },
  sessionLive(dev, sid) {
    const s = this.sessions.get(`${dev.id}|${sid}`);
    return !!s && !s.ended;
  },
  /** A change to who may reach whom: "friend" between a pair, or "circle" for one member. */
  social(kind, userIds) {
    this.socialLog.push({ t: Date.now(), kind, users: new Set(userIds) });
  },
  /** May `viewer` (a user) see session `s` now, per the model (§4.2)? */
  canSee(viewer, s) {
    if (viewer === s.user) return true;
    if (s.vis === "circle") return s.user.inCircle && viewer.inCircle;
    return s.parts.includes(viewer.userId) && s.user.friends.has(viewer.userId);
  },
  onPrinted(dev, w, e) {
    const m = this.messages.get(e.text);
    if (!m) return;
    if (m.to.dev === dev.id && m.to.sid === w.sid) {
      m.printed = (m.printed ?? 0) + 1;
      if (m.printedAt === undefined) {
        m.printedAt = Date.now();
        if (m.calmSend && this.calm(dev)) rec.sample("send → recipient's watch", m.printedAt - m.sentAt, true);
      }
    }
  },
};

// ---------------------------------------------------------------------------
// The fake repository and the fake ix's answers (packages/ext-ix/scripts/fake-ix.cjs)

const N_FILES = 6;
const REMOTE = "https://github.com/soak-test/fake-repo.git";
const fileOf = (k) => `src/m${k}.ts`;
const symName = (k, s) => (s === "a" ? `SoakAlpha${k}` : `SoakBeta${k}`);
const NAME_RE = /SoakAlpha\d+|SoakBeta\d+/g;

function fileText(k, edit) {
  const a = edit === "a" ? `  return ${k} + 1;` : `  return ${k};`;
  const b = edit === "b" ? `  return ${k} + 2;` : `  return ${k};`;
  return `// m${k}\nexport function ${symName(k, "a")}() {\n${a}\n}\n\nexport function ${symName(k, "b")}() {\n${b}\n}\n`;
}

function aroundAnswers(dir) {
  for (let k = 0; k < N_FILES; k++) {
    const f = fileOf(k);
    const caller = (k + 1) % N_FILES;
    writeFileSync(
      join(dir, `around-${f.replace(/\//g, "__")}:3-3.json`),
      JSON.stringify({
        path: f,
        symbols: [{ name: symName(k, "a"), kind: "function", path: f, lineStart: 2, lineEnd: 4, callers: { total: 1, rows: [{ path: fileOf(caller), line: 7, name: symName(caller, "b") }] }, users: { total: 0, rows: [] }, tests: { total: 0, rows: [] } }],
        importers: { total: 0, tests: 0, rows: [] },
      }),
    );
    writeFileSync(
      join(dir, `around-${f.replace(/\//g, "__")}:7-7.json`),
      JSON.stringify({
        path: f,
        symbols: [{ name: symName(k, "b"), kind: "function", path: f, lineStart: 6, lineEnd: 8, callers: { total: 0, rows: [] }, users: { total: 0, rows: [] }, tests: { total: 0, rows: [] } }],
        importers: { total: 0, tests: 0, rows: [] },
      }),
    );
  }
}

const gitEnv = { PATH: process.env.PATH ?? "", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null", HOME: scratch };
const git = (cwd, ...a) => execFileSync("git", a, { cwd, env: gitEnv, stdio: ["ignore", "pipe", "pipe"] }).toString().trim();

function makeOrigin() {
  const root = join(scratch, "origin");
  mkdirSync(join(root, "src"), { recursive: true });
  git(root, "init", "-q", "-b", "main");
  for (let k = 0; k < N_FILES; k++) writeFileSync(join(root, fileOf(k)), fileText(k));
  git(root, "add", ".");
  git(root, "-c", "user.email=soak@example.com", "-c", "user.name=soak", "commit", "-q", "-m", "init");
  return root;
}

/** The expected overlaps of my spot with theirs (packages/ext-ix/SPEC.md §9), as "tier/direction/severity". */
function expectedOverlaps(m, t) {
  const out = new Set();
  if (!m || !t) return out;
  if (m.k === t.k && m.s === t.s) out.add("same-symbol/high");
  if (m.s === "a" && t.k === (m.k + 1) % N_FILES) out.add("depends/mine-affects-theirs/medium");
  if (t.s === "a" && m.k === (t.k + 1) % N_FILES) out.add("depends/theirs-affects-mine/medium");
  if (m.k === t.k && m.s !== t.s) out.add("same-file/medium");
  return out;
}

/** The names a user's own footprint holds (changed and ring 1): readable on their own devices only. */
function ownNames(spot) {
  const n = [symName(spot.k, spot.s)];
  if (spot.s === "a") n.push(symName((spot.k + 1) % N_FILES, "b"));
  return n;
}

// ---------------------------------------------------------------------------
// Setup

async function setup() {
  world.inSetup = true;
  try {
    await setupSteps();
  } finally {
    world.inSetup = false;
  }
}

async function setupSteps() {
  const limits = relayLimits(MODE);
  for (const [i, name] of ["relay-a", "relay-b"].entries()) {
    const r = new RelayProc({ name, url: `wss://${name}.soak.test/v3`, dir: join(scratch, name), port: await freePort(), metricsPort: await freePort(), limits });
    await r.start();
    world.relays.push(r);
    rec.ev("relay-start", { relay: name, i });
  }
  const ext = join(scratch, "ext");
  mkdirSync(join(ext, "node_modules", "@peer2peer"), { recursive: true });
  symlinkSync(EXT_IX_PKG, join(ext, "node_modules", "@peer2peer", "ext-ix"), "dir");
  const fakeBin = join(scratch, "fake-ix-bin");
  mkdirSync(fakeBin, { recursive: true });
  copyFileSync(FAKE_IX, join(fakeBin, "ix"));
  chmodSync(join(fakeBin, "ix"), 0o755);
  const origin = makeOrigin();

  const linkR = R.fork("links");
  for (let i = 0; i < N_USERS; i++) {
    const name = `u${i}`;
    const udir = join(scratch, name);
    const fakeIxDir = join(udir, "fake-ix");
    mkdirSync(fakeIxDir, { recursive: true });
    aroundAnswers(fakeIxDir);
    const repo = join(udir, "repo");
    git(scratch, "clone", "-q", origin, repo);
    git(repo, "remote", "set-url", "origin", REMOTE);
    const user = { name, idx: i, dir: udir, repo, fakeIxDir, devices: [], friends: new Set(), inCircle: false, spot: undefined, fpN: 0 };
    for (const d of [1, 2]) {
      const dev = new Device({
        id: `${name}d${d}`,
        user,
        dir: join(udir, `d${d}`),
        relays: world.relays,
        ext,
        fakeIxBin: fakeBin,
        fakeIxDir,
        bin: BIN,
        rtt: linkR.int(0, MAX_RTT),
        jitter: linkR.int(0, 30),
        random: linkR.fork(`${name}d${d}`).next,
        recorder: rec,
      });
      await dev.startLinks();
      user.devices.push(dev);
      world.devices.push(dev);
    }
    world.users.push(user);
  }
  log(`setup: ${N_USERS} users × 2 devices, links ${world.devices.map((d) => `${d.id}:${d.rtt}±${d.jitter}ms`).join(" ")}`);

  // Identities, and each user's second device linked to the first.
  for (const u of world.users) {
    const d1 = u.devices[0];
    const r = await must(d1.run(["init", "--name", u.name, "--relay", world.relays[0].url, "--relay", world.relays[1].url, "--yes", "--json"]), "init");
    u.userId = r.userId;
    world.fpNames.set(u.userId, new Set());
  }
  await Promise.all(
    world.users.map(async (u) => {
      const [d1, d2] = u.devices;
      const codeFile = join(u.dir, "link-code");
      const [a, b] = await Promise.all([d1.helper(["link-start", codeFile, `${u.name}-laptop`]), d2.helper(["link-join", codeFile, `${u.name}-laptop`])]);
      if (!a.json?.ok || !b.json?.ok) throw new Error(`linking ${u.name}'s second device failed: ${JSON.stringify(a.json ?? a.stderr.slice(-300))} / ${JSON.stringify(b.json ?? b.stderr.slice(-300))}`);
      rmSync(codeFile, { force: true });
      rmSync(`${codeFile}.answer`, { force: true });
    }),
  );
  rec.ev("linked");

  // Everyone friends with everyone.
  for (let i = 0; i < N_USERS; i++)
    for (let j = i + 1; j < N_USERS; j++) {
      await befriend(world.users[i], world.users[j]);
    }
  rec.ev("friends");

  // One open circle, owned by u0, everyone in it.
  const owner = world.users[0];
  const c = await must(owner.devices[0].run(["circle", "create", "soak", "--open", "--json"]), "circle create");
  world.cid = c.cid;
  owner.inCircle = true;
  for (const u of world.users.slice(1)) await joinCircle(u, true);
  // Everyone's default circle (what `p2p setup` and the mod's onboarding leave a member with).
  for (const u of world.users) await must(u.devices[0].run(["circle", "default", world.cid, "--json"]), "circle default");
  rec.ev("circle", { cid: world.cid });

  // Every device handles what is queued for it (second devices learn the friendships and the circle by sync).
  for (let round = 0; round < 2; round++) await Promise.all(world.devices.map((d) => d.run(["circle", "ls", "--json"], { op: "circle ls" })));
  // Sessions: d1 runs "fp" (the circle; publishes footprints) and "dm" (private, every friend); d2 runs "c2" (the circle).
  for (const u of world.users) {
    await newSession(u.devices[0], "fp", "circle", { footprint: true, required: true });
    await newSession(u.devices[0], "dm", "direct", { required: true });
    await newSession(u.devices[1], "c2", "circle", { required: true });
  }
  // First statuses, then everyone looks (drains), so every sender knows every live session.
  await Promise.all([...world.sessions.values()].map((s) => postStatus(s)));
  for (let round = 0; round < 2; round++) await Promise.all(world.devices.map((d) => d.run(["ls", "--json"], { op: "ls" })));
  rec.ev("setup-done");
}

async function must(p, what) {
  const r = await p;
  if (r.code !== 0) throw new Error(`setup step ${what} failed (${r.code}${r.signal ? ` ${r.signal}` : ""}): ${(r.json?.error ? JSON.stringify(r.json) : r.stderr.slice(-400)).trim()}`);
  return r.json;
}

async function befriend(a, b) {
  const inv = await must(a.devices[0].run(["invite", "--link", "--no-circle", "--json"]), "invite");
  const acc = await b.devices[0].run(["accept", inv.link, "--json"]);
  if (acc.code !== 0) {
    // Why, for the report (the error code and message only: never the link).
    rec.ev("accept-failed", { a: a.name, b: b.name, error: acc.json?.error, message: String(acc.json?.message ?? acc.stderr.split("\n").filter(Boolean).at(-1) ?? "").slice(0, 300), delivery: deliveryErrors(acc.json) });
    return false;
  }
  await a.devices[0].run(["friends", "--json"]);
  a.friends.add(b.userId);
  b.friends.add(a.userId);
  return true;
}

async function joinCircle(u, setupPhase) {
  const owner = world.users[0].devices[0];
  const link = setupPhase ? (await must(owner.run(["circle", "invite", world.cid, "--link", "--json"]), "circle invite")).link : (await owner.run(["circle", "invite", world.cid, "--link", "--json"])).json?.link;
  if (!link) return false;
  const d = u.devices[0];
  await d.run(["circle", "join", link, "--wait", "0", "--json"], { op: "circle join" });
  await owner.run(["circle", "ls", "--json"], { op: "circle ls" });
  const j = await d.run(["circle", "join", link, "--wait", "8", "--yes", "--json"], { op: "circle join" });
  await owner.run(["circle", "ls", "--json"], { op: "circle ls" });
  let ok = setupPhase ? j.json?.status === "joined" : joinedHere(j.json);
  if (ok && !setupPhase) {
    // A former member's join is held for the owner, whether it left or was removed (protocol P2):
    // the owner approves it, as a person would, once it arrives (which can take a while under chaos).
    let approved = false;
    for (const end = Date.now() + JOIN_APPROVAL_POLL_MS; Date.now() < end && !approved; ) {
      const held = (await owner.run(["held", "--json"], { op: "held" })).json?.held ?? [];
      const item = held.find((h) => h.type === "circle-join" && h.from === u.userId);
      if (item) {
        rec.ev("circle-join-held", { user: u.name, reason: item.reason });
        if (item.reason !== "previously-removed") rec.problem("status-convergence", `${u.name}'s re-join was held as "${item.reason}", not previously-removed`);
        approved = (await owner.run(["held", "approve", item.id, "--json"], { op: "held approve" })).code === 0;
      } else if ((await owner.run(["circle", "members", world.cid, "--json"], { op: "circle members" })).json?.members?.some((m) => m.userId === u.userId)) {
        rec.problem("status-convergence", `${u.name}'s re-join was admitted without approval (a former member's must be held)`);
        approved = true;
      } else await sleep(1500);
    }
    await owner.run(["circle", "ls", "--json"], { op: "circle ls" });
    ok = approved;
  }
  if (!ok && setupPhase) throw new Error(`${u.name} couldn't join the circle: ${JSON.stringify(j.json ?? j.stderr.slice(-300))}`);
  if (ok) u.inCircle = true;
  return ok;
}

let dynN = 0;
async function newSession(dev, sid, vis, extra = {}) {
  const u = dev.user;
  const parts = vis === "direct" ? world.users.filter((x) => x !== u).map((x) => x.userId) : [];
  const args2 = vis === "circle" ? ["session", "roster", sid, "--circle", world.cid, "--json"] : ["session", "roster", sid, "--private", ...parts.flatMap((p) => ["--add", p]), "--json"];
  const r = await dev.run(args2, { op: "session roster" });
  if (r.code !== 0) {
    rec.ev("session-roster-failed", { dev: dev.id, sid, vis, error: r.json?.error, message: String(r.json?.message ?? r.stderr).slice(0, 200) });
    if (extra.required) throw new Error(`${dev.id}: session roster ${sid} failed: ${JSON.stringify(r.json ?? r.stderr.slice(-200))}`);
    return undefined;
  }
  const s = { key: `${dev.id}|${sid}`, sid, dev, user: u, vis, parts, footprint: !!extra.footprint, startedAt: Date.now(), n: 0, delivered: new Map(), lastPost: 0 };
  world.sessions.set(s.key, s);
  dev.startWatch(sid);
  rec.ev("session-start", { dev: dev.id, sid, vis });
  return s;
}

// ---------------------------------------------------------------------------
// The workload

const wR = R.fork("workload");
const TYPES = ["Explore", "general-purpose", "teammate", "Plan"];
const TASKS = ["map the auth flow", "fix the flaky test", "review the migration", "draft release notes", "trace a slow query"];

function agentsFor(s) {
  const n = wR.int(0, 3);
  const out = [];
  for (let i = 1; i <= n; i++) {
    out.push({
      id: `a${i}`,
      ...(i > 1 && wR.chance(0.3) ? { parent: "a1" } : {}),
      type: wR.pick(TYPES),
      task: wR.pick(TASKS),
      state: wR.pick(["running", "waiting", "idle", "done"]),
      ...(s.footprint && s.user.spot ? { files: [fileOf(s.user.spot.k)] } : wR.chance(0.5) ? { files: [`docs/${s.sid}-${i}.md`] } : {}),
      at: Date.now() - wR.int(0, 60_000),
    });
  }
  return out;
}

async function postStatus(s, { files } = {}) {
  const dev = s.dev;
  if (dev.paused) return;
  const summary = `st-${s.sid}-${s.user.name}-${++world.statusN}`;
  const agents = agentsFor(s);
  const fileArgs = (files ?? (s.footprint && s.user.spot ? [fileOf(s.user.spot.k)] : [])).flatMap((f) => ["--file", f]);
  s.lastPost = Date.now();
  // The envelope's ts is the sender's clock: receivers keep the status with the highest ts.
  const ts = Date.now() + dev.skewMs;
  // Every attempt, even one that then reports failure: its envelope may have gone out before it
  // failed (a timeout or exit after some deliveries), and a viewer showing it isn't stale.
  (s.attempts ??= []).push({ summary, ts });
  const r = await dev.run(["status", "--session", s.sid, "--state", wR.pick(["busy", "idle"]), "--label", s.sid, "--summary", summary, "--cap", "agents.v1", "--cap", "receipts.v1", ...fileArgs, "--agents-json", JSON.stringify(agents), "--json"], {
    op: "status",
    cwd: s.footprint ? s.user.repo : undefined,
  });
  if (r.code !== 0 || !r.json) return;
  for (const d of r.json.delivered ?? []) {
    const prev = s.delivered.get(d.userId);
    const entry = { summary, agents: d.agents ? (r.json.status?.agents ?? []) : undefined, at: Date.now(), ts };
    // Latest by ts (§4.3), not by when it was sent: a clock set back makes a newer post "older".
    if (!prev || ts > prev.ts) s.delivered.set(d.userId, { ...entry, near: [summary] });
    else if (prev.ts - ts < 2000) prev.near.push(summary);
  }
  s.lastSummary = summary;
}

/** A spot for this user's next footprint: often deliberately overlapping someone's current one. */
function nextSpot(u) {
  const others = world.users.filter((x) => x !== u && x.spot);
  if (others.length > 0 && wR.chance(0.6)) {
    const t = wR.pick(others).spot;
    const kind = wR.pick(["same-symbol", "same-file", "mine-affects", "theirs-affects"]);
    if (kind === "same-symbol") return { k: t.k, s: t.s };
    if (kind === "same-file") return { k: t.k, s: t.s === "a" ? "b" : "a" };
    if (kind === "mine-affects") return { k: (t.k + N_FILES - 1) % N_FILES, s: "a" };
    if (t.s === "a") return { k: (t.k + 1) % N_FILES, s: wR.pick(["a", "b"]) };
  }
  // Somewhere nobody else is near (if there is such a spot).
  const cands = [];
  for (let k = 0; k < N_FILES; k++) for (const s of ["a", "b"]) if (others.every((o) => expectedOverlaps({ k, s }, o.spot).size === 0)) cands.push({ k, s });
  return cands.length > 0 ? wR.pick(cands) : { k: wR.int(0, N_FILES - 1), s: wR.pick(["a", "b"]) };
}

async function publishFootprint(u, { force = true, spot } = {}) {
  const s = world.sessions.get(`${u.devices[0].id}|fp`);
  if (!s || s.ended || s.dev.paused) return;
  if (Date.now() - (u.fpAt ?? 0) < 6000) return;
  u.fpAt = Date.now();
  const next = spot ?? nextSpot(u);
  // The working tree holds exactly this one edit.
  for (let k = 0; k < N_FILES; k++) writeFileSync(join(u.repo, fileOf(k)), fileText(k, k === next.k ? next.s : undefined));
  u.spot = next;
  for (const n of ownNames(next)) world.fpNames.get(u.userId).add(n);
  await postStatus(s, { files: [fileOf(next.k)] });
  const r = await s.dev.run(["ix", "footprint", "--session", "fp", "--publish", ...(force ? ["--force"] : []), "--json"], { op: "ix footprint --publish", cwd: u.repo });
  u.fpPublished = { spot: next, at: Date.now(), ok: r.code === 0 && r.json?.published === true, delivered: (r.json?.delivered ?? []).map((d) => d.userId), skipped: r.json?.skipped, error: r.json?.error };
  rec.ev("footprint", { user: u.name, spot: `${fileOf(next.k)}#${next.s}`, published: u.fpPublished.ok, skipped: r.json?.skipped, error: r.json?.error });
}

/** Sends one message from a live session of `from` (a device) into a visible live session of someone else. */
async function sendMessage(fromDev, { text, target } = {}) {
  const u = fromDev.user;
  const mine = [...world.sessions.values()].filter((s) => s.dev === fromDev && !s.ended);
  if (mine.length === 0) return;
  const src = wR.pick(mine);
  const targets =
    target !== undefined
      ? [target]
      : [...world.sessions.values()].filter((s) => s.user !== u && !s.ended && Date.now() - s.lastPost < 100_000 && world.canSee(u, s));
  if (targets.length === 0) return;
  const t = wR.pick(targets);
  const m = {
    text: text ?? `msg-${++world.msgN}-${fromDev.id}-to-${t.dev.id}-${t.sid}`,
    kind: t.vis === "circle" ? "circle" : "direct",
    from: { dev: fromDev.id, sid: src.sid, user: u.userId },
    to: { dev: t.dev.id, sid: t.sid, user: t.user.userId },
    sentAt: Date.now(),
    calmSend: world.calm(fromDev) && world.calm(t.dev) && !t.dev.paused,
    authorized: world.canSee(u, t),
  };
  // In the ledger before it's sent: the recipient may apply it before `p2p send` returns.
  m.state = "sending";
  world.messages.set(m.text, m);
  const r = await fromDev.run(["send", "--from-session", src.sid, "--to", `${t.user.userId}/${t.sid}`, "--stdin", "--json"], { stdin: m.text, op: "send" });
  m.sendMs = r.ms;
  if (r.code === 0 && (r.json?.delivered || r.json?.queued)) {
    // Queued (the session offline, or this device's outbox): held to the same exactly-once rule.
    m.state = "sent";
    m.relays = r.json.relays;
    if (r.json.queued) m.queued = r.json.state;
  } else {
    m.state = "send-failed";
    m.error = r.json?.error ?? (r.signal ? `signal ${r.signal}` : `exit ${r.code}`);
  }
  world.messages.set(m.text, m);
  return m;
}

// --- social churn

async function unfriendCycle() {
  const pairs = [];
  for (const a of world.users) for (const b of world.users) if (a.idx < b.idx && a.friends.has(b.userId) && !a.busySocial && !b.busySocial) pairs.push([a, b]);
  if (pairs.length === 0) return;
  const [a, b] = wR.pick(pairs);
  if (a.devices[0].paused || b.devices[0].paused) return;
  a.busySocial = b.busySocial = true;
  try {
    world.social("friend", [a.userId, b.userId]);
    const r = await a.devices[0].run(["unfriend", b.userId, "--json"], { op: "unfriend" });
    if (r.code !== 0) return;
    a.friends.delete(b.userId);
    b.friends.delete(a.userId);
    world.social("friend", [a.userId, b.userId]);
    rec.ev("unfriend", { a: a.name, b: b.name });
    await sleep(wR.int(10, 40) * 1000);
    while (a.devices[0].paused || b.devices[0].paused) await sleep(1000);
    world.social("friend", [a.userId, b.userId]);
    const ok = await befriend(a, b).catch(() => false);
    world.social("friend", [a.userId, b.userId]);
    rec.ev("re-friend", { a: a.name, b: b.name, ok });
    if (!ok) world.pendingFriend = [...(world.pendingFriend ?? []), [a, b]];
  } finally {
    a.busySocial = b.busySocial = false;
  }
}

async function circleCycle() {
  const cands = world.users.slice(1).filter((u) => u.inCircle && !u.busySocial && !u.devices[0].paused);
  if (cands.length === 0) return;
  const u = wR.pick(cands);
  u.busySocial = true;
  try {
    world.social("circle", [u.userId]);
    const r = await u.devices[0].run(["circle", "leave", world.cid, "--json"], { op: "circle leave" });
    if (r.code !== 0) return;
    u.inCircle = false;
    world.social("circle", [u.userId]);
    rec.ev("circle-leave", { user: u.name });
    await sleep(wR.int(15, 50) * 1000);
    while (u.devices[0].paused || world.users[0].devices[0].paused) await sleep(1000);
    world.social("circle", [u.userId]);
    const ok = await joinCircle(u, false).catch(() => false);
    world.social("circle", [u.userId]);
    rec.ev("circle-rejoin", { user: u.name, ok });
  } finally {
    u.busySocial = false;
  }
}

async function sessionCycle() {
  const devs = world.devices.filter((d) => !d.paused);
  const dev = wR.pick(devs);
  const sid = `dyn${++dynN}`;
  const s = await newSession(dev, sid, dev.user.inCircle ? wR.pick(["circle", "direct"]) : "direct");
  if (!s) return;
  await postStatus(s);
  setTimeout(
    async () => {
      if (world.stopping) return;
      s.ended = true;
      await dev.stopWatch(sid);
      rec.ev("session-end", { dev: dev.id, sid });
    },
    wR.int(60, 180) * 1000,
  );
}

async function identityRefresh() {
  const u = wR.pick(world.users);
  const d1 = u.devices[0];
  if (d1.paused) return;
  if (wR.chance(0.6)) {
    const r = await d1.run(["profile", "set", "--bio", `soak bio ${Date.now() % 100000}`, "--json"], { op: "profile set" });
    rec.ev("identity-refresh", { user: u.name, kind: "profile", ok: r.code === 0 });
  } else {
    const r = await d1.run(["identity", "republish", "--json"], { op: "identity republish" });
    rec.ev("identity-refresh", { user: u.name, kind: "republish", ok: r.code === 0 });
  }
}

// ---------------------------------------------------------------------------
// Chaos

const cR = R.fork("chaos");

async function chaosRelayKill() {
  const up = world.relays.filter((r) => r.up);
  if (up.length < 2) return false;
  const r = cR.pick(up);
  const downS = MODE === "quick" ? cR.int(5, 15) : cR.int(10, 60);
  world.chaos.relayDown.add(r.name);
  rec.ev("chaos-relay-kill", { relay: r.name, downS });
  log(`chaos: SIGKILL ${r.name} for ${downS}s`);
  await r.kill();
  await sleep(downS * 1000);
  if (!world.stopping) await r.start();
  world.chaos.relayDown.delete(r.name);
  rec.ev("chaos-relay-restart", { relay: r.name });
  return true;
}

async function chaosPause(devArg, sArg) {
  const dev = devArg ?? cR.pick(world.devices.filter((d) => !d.paused));
  if (!dev || dev.paused) return false;
  const s = sArg ?? (MODE === "quick" ? cR.int(30, 45) : cR.int(30, 120));
  rec.ev("chaos-pause", { dev: dev.id, s });
  log(`chaos: SIGSTOP ${dev.id} for ${s}s`);
  // Wait for this device's own commands to finish (a laptop sleeps between them, as far as we can tell).
  for (let i = 0; i < 100 && dev.inflight > 0; i++) await sleep(100);
  dev.pause();
  world.chaos.pausedUntil.set(dev.id, Date.now() + s * 1000);
  await sleep(s * 1000);
  dev.resume();
  dev.resumedAt = Date.now();
  world.chaos.pausedUntil.delete(dev.id);
  rec.ev("chaos-resume", { dev: dev.id });
  return true;
}

function chaosDrop() {
  if (cR.chance(0.3)) {
    world.chaos.dropAt = Date.now();
    for (const d of world.devices) d.dropLinks();
    rec.ev("chaos-drop", { scope: "all" });
    log("chaos: dropped every connection");
  } else {
    const d = cR.pick(world.devices);
    d.dropLinks();
    rec.ev("chaos-drop", { scope: d.id });
    log(`chaos: dropped ${d.id}'s connections`);
  }
}

/** Fills one device's mailbox near the relay's quota while it sleeps, then lets it drain everything. */
async function chaosFillMailbox() {
  const quota = relayLimits(MODE).mailboxEnvelopes;
  const victims = world.devices.filter((d) => !d.paused && [...world.sessions.values()].some((s) => s.dev === d && !s.ended && s.vis === "direct"));
  if (victims.length === 0) return false;
  const dev = cR.pick(victims);
  const s = [...world.sessions.values()].find((x) => x.dev === dev && !x.ended && x.vis === "direct");
  const sender = world.users.find((u) => u !== dev.user && dev.user.friends.has(u.userId) && !u.devices[0].paused);
  if (!s || !sender) return false;
  const n = Math.floor(quota * 0.7);
  const fillN = world.floods.length + 1;
  rec.ev("chaos-mailbox-fill", { dev: dev.id, n, quota });
  log(`chaos: filling ${dev.id}'s mailbox with ${n} of ${quota} while it sleeps`);
  const pause = chaosPause(dev, MODE === "quick" ? 40 : 60);
  await sleep(500);
  const r = await sender.devices[0].helper(["flood", dev.user.userId, readDid(dev), s.sid, String(n), `flood${fillN}-${sender.name}-to-${dev.id}`]);
  const sent = r.json?.sent ?? [];
  const at = Date.now();
  for (const x of sent) {
    world.messages.set(x.text, { text: x.text, kind: "flood", from: { dev: sender.devices[0].id, sid: "-", user: sender.userId }, to: { dev: dev.id, sid: s.sid, user: dev.user.userId }, sentAt: at, state: "sent", authorized: true, onlyTarget: true });
  }
  world.floods.push({ dev: dev.id, requested: n, sent: sent.length, quota, error: r.json?.error });
  if (!r.json?.ok) rec.problem("delivery-exactly-once", `mailbox fill helper failed: ${r.json?.error ?? r.stderr.slice(-200)}`);
  await pause;
  return true;
}

function readDid(dev) {
  return dev.readDoc("keys")?.did;
}

/** A message whose application fails every time on its recipients (poison), from a friend. */
async function chaosPoison() {
  const live = [...world.sessions.values()].filter((s) => !s.ended && s.vis === "direct" && !s.dev.paused);
  const t = cR.pick(live);
  if (!t) return false;
  const from = world.users.find((u) => u !== t.user && t.user.friends.has(u.userId) && !u.devices[0].paused);
  if (!from) return false;
  const marker = `SOAK-POISON-${world.poison.length + 1}`;
  // Before sending: the recipient can give up on it before `p2p send` even returns.
  const beforeGaveUp = Object.fromEntries(t.user.devices.map((d) => [d.id, d.readDoc("inbound")?.gaveUp ?? 0]));
  const m = await sendMessage(from.devices[0], { text: `${marker} from ${from.name}`, target: t });
  if (!m) return false;
  m.kind = "poison";
  world.poison.push({ marker, text: m.text, to: t.user, dev: t.dev.id, sentAt: m.sentAt, sent: m.state === "sent", beforeGaveUp });
  rec.ev("chaos-poison", { to: t.dev.id, sent: m.state });
  log(`chaos: poison envelope to ${t.dev.id} (${m.state})`);
  return true;
}

/** A message whose first application on each device kills that process (kill -9 mid-apply). */
async function chaosCrash() {
  const live = [...world.sessions.values()].filter((s) => !s.ended && s.vis === "direct" && !s.dev.paused);
  const t = cR.pick(live);
  if (!t) return false;
  const from = world.users.find((u) => u !== t.user && t.user.friends.has(u.userId) && !u.devices[0].paused);
  if (!from) return false;
  const marker = `SOAK-CRASH-${world.crashes.length + 1}`;
  const m = await sendMessage(from.devices[0], { text: `${marker} from ${from.name}`, target: t });
  if (!m) return false;
  m.kind = "crash";
  world.crashes.push({ marker, text: m.text, dev: t.dev.id, sent: m.state === "sent" });
  rec.ev("chaos-crash", { to: t.dev.id, sent: m.state });
  log(`chaos: crash-on-apply message to ${t.dev.id} (${m.state})`);
  return true;
}

/** A friend sends envelopes no conforming client sends (a status with an unknown state, a numeric text). */
async function chaosMalformed() {
  const live = [...world.sessions.values()].filter((s) => !s.ended && !s.dev.paused && s.vis === "direct");
  const t = cR.pick(live);
  if (!t) return false;
  const from = world.users.find((u) => u !== t.user && t.user.friends.has(u.userId) && !u.devices[0].paused);
  if (!from) return false;
  const fromSession = [...world.sessions.values()].find((s) => s.dev === from.devices[0] && s.sid === "dm");
  const before = t.user.devices.map((d) => d.readDoc("peers")?.[`${from.userId}|dm`]?.status?.summary);
  const r = await from.devices[0].helper(["malformed", t.user.userId, fromSession?.sid ?? "dm"]);
  world.malformed.push({ from: from.name, to: t.user, at: Date.now(), ok: r.json?.ok, before, error: r.json?.error });
  rec.ev("chaos-malformed", { from: from.name, to: t.user.name, ok: r.json?.ok, error: r.json?.error });
  log(`chaos: malformed envelopes ${from.name} → ${t.user.name} (${r.json?.ok ? "sent" : r.json?.error})`);
  return true;
}

function chaosSkew() {
  const dev = cR.pick(world.devices);
  dev.skewMs = cR.pick([-90_000, 90_000]);
  rec.ev("chaos-skew", { dev: dev.id, ms: dev.skewMs });
  log(`chaos: ${dev.id}'s clock is ${dev.skewMs > 0 ? "+" : ""}${dev.skewMs / 1000}s from now on`);
  // Its long-running watches pick the clock up on restart.
  for (const sid of [...dev.watches.keys()]) {
    if (!world.sessionLive(dev, sid)) continue;
    void dev.stopWatch(sid).then(() => dev.startWatch(sid));
  }
  return dev;
}

// ---------------------------------------------------------------------------
// Heal: everything back up, every social change undone, every device drained.

/** Keeps every live session live (a status at least every 100 s) while the workload loop isn't running. */
function keepAlive() {
  let stop = false;
  const loop = (async () => {
    while (!stop) {
      for (const s of world.sessions.values()) {
        if (stop) break;
        if (s.ended || s.dev.paused || s.posting || Date.now() - s.lastPost < 100_000) continue;
        s.posting = true;
        await postStatus(s).catch(() => {});
        s.posting = false;
      }
      await sleep(2000);
    }
  })();
  return async () => {
    stop = true;
    await loop;
  };
}

async function heal() {
  log("heal: resuming paused devices, restarting relays, restoring friendships and the circle");
  rec.ev("heal-start");
  while (world.chaos.pausedUntil.size > 0 || world.chaos.relayDown.size > 0) await sleep(500);
  for (const r of world.relays) if (!r.up) await r.start();
  while (world.users.some((u) => u.busySocial)) await sleep(500);
  world.pendingFriend = [];
  for (const a of world.users)
    for (const b of world.users)
      if (a.idx < b.idx && !a.friends.has(b.userId)) {
        world.social("friend", [a.userId, b.userId]);
        const ok = await befriend(a, b).catch(() => false);
        rec.ev("heal-friend", { a: a.name, b: b.name, ok });
        if (!ok) rec.problem("delivery-exactly-once", `heal: ${a.name} and ${b.name} couldn't become friends again`);
      }
  for (const u of world.users)
    if (!u.inCircle) {
      world.social("circle", [u.userId]);
      let ok = await joinCircle(u, false).catch(() => false);
      // A confirmer that never answered is asked again after a minute (JOIN_REASK_MS).
      if (!ok) {
        await sleep(62_000);
        ok = await joinCircle(u, false).catch(() => false);
      }
      rec.ev("heal-circle", { user: u.name, ok });
      if (!ok) rec.problem("status-convergence", `heal: ${u.name} couldn't re-join the circle`);
    }
  for (const u of world.users) await u.devices[0].run(["circle", "default", world.cid, "--json"], { op: "circle default" });
  for (const s of world.sessions.values()) if (!s.ended) s.dev.startWatch(s.sid);
  world.healedAt = Date.now();
  rec.ev("healed");
}

// ---------------------------------------------------------------------------
// Checks

function scanEvents() {
  for (const dev of world.devices) {
    const doc = dev.readDoc("events");
    const items = doc?.items ?? [];
    dev.applied ??= new Map(); // event id -> text
    dev.appliedTexts ??= new Map(); // text -> Set(ids)
    for (const e of items) {
      if (e.kind !== "p2p.message" || typeof e.data?.text !== "string") continue;
      // The copy logged for a session that wasn't running (shown by the user's other sessions):
      // the same message, not a second application of it.
      if (typeof e.data.unclaimedFor === "string") continue;
      if (dev.applied.has(e.id)) continue;
      dev.applied.set(e.id, e.data.text);
      const ids = dev.appliedTexts.get(e.data.text) ?? new Set();
      ids.add(e.id);
      dev.appliedTexts.set(e.data.text, ids);
      if (ids.size > 1) rec.problem("no-duplicates", `${dev.id} applied "${e.data.text.slice(0, 60)}" ${ids.size} times (event ids ${[...ids].join(", ")})`);
      const m = world.messages.get(e.data.text);
      if (m) noteApplied(m, dev);
    }
  }
  // Applied before the harness knew of the message (a flood's, recorded once the helper returned).
  for (const m of world.messages.values()) {
    if (m.appliedOn?.has(m.to.dev)) continue;
    for (const dev of world.devices) if (dev.appliedTexts?.has(m.text)) noteApplied(m, dev);
  }
}

function noteApplied(m, dev) {
  if (m.appliedOn?.has(dev.id)) return;
  if (m.kind === "poison") rec.problem("poison-gave-up", `${dev.id} applied the poison message ${m.text.slice(0, 40)}`);
  if (m.to.dev === dev.id && m.appliedAt === undefined) m.appliedAt = Date.now();
  (m.appliedOn ??= new Set()).add(dev.id);
}

/** A message the model can hold to exactly-once: no social change touched its pair while it was in flight. */
function poisonRefused(m, devId) {
  return refusedWhilePairChanged({ m, devId, socialLog: world.socialLog, rejected: rec.stderrNotes.rejected, t0: T0 });
}

function strict(m) {
  if (m.state !== "sent" || !m.authorized || m.kind === "poison") return false;
  const end = m.appliedAt ?? Infinity;
  for (const c of world.socialLog) {
    if (c.t < m.sentAt - 30_000 || c.t > end) continue;
    // An unfriend or re-friend of this pair decides a direct message; a circle leave or re-join of
    // either side decides a circle message.
    if (c.kind === "friend" && m.kind !== "circle" && c.users.has(m.from.user) && c.users.has(m.to.user)) return false;
    if (c.kind === "circle" && m.kind === "circle" && (c.users.has(m.from.user) || c.users.has(m.to.user))) return false;
  }
  return true;
}

function scanNames() {
  for (const u of world.users) {
    const own = world.fpNames.get(u.userId) ?? new Set();
    for (const dev of u.devices) {
      const walk = (d) => {
        let names;
        try {
          names = readdirSync(d);
        } catch {
          return;
        }
        for (const n of names) {
          const p = join(d, n);
          let st;
          try {
            st = statSync(p);
          } catch {
            continue;
          }
          if (st.isDirectory()) walk(p);
          else if (st.size < 8 * 1024 * 1024) {
            let text;
            try {
              text = readFileSync(p, "utf8");
            } catch {
              continue;
            }
            for (const hit of new Set(text.match(NAME_RE) ?? [])) {
              if (own.has(hit)) continue;
              const key = `${dev.id}|${relative(dev.home, p)}|${hit}`;
              if (world.leaks?.has(key)) continue;
              (world.leaks ??= new Set()).add(key);
              rec.problem("hashed-names", `${dev.id} stores another user's readable name ${hit} in ${relative(dev.home, p)}`);
            }
          }
        }
      };
      walk(dev.home);
    }
  }
}

const resources = { rss: {}, homeBytes: {}, relayDb: {}, series: [] };
function sampleResources() {
  const pids = {};
  for (const r of world.relays) if (r.pid()) pids[r.pid()] = `relay:${r.name}`;
  for (const d of world.devices) for (const w of d.watches.values()) if (!w.exited) pids[w.child.pid] = `watch`;
  const rss = rssKb(Object.keys(pids).map(Number));
  for (const [pid, kb] of Object.entries(rss)) {
    const role = pids[pid];
    resources.rss[role] = Math.max(resources.rss[role] ?? 0, kb);
  }
  return rss;
}
function sampleDisk() {
  const point = { t: since(), home: {}, relay: {} };
  for (const d of world.devices) {
    const b = dirBytes(d.home);
    point.home[d.id] = b;
    resources.homeBytes[d.id] = Math.max(resources.homeBytes[d.id] ?? 0, b);
  }
  for (const r of world.relays) {
    const b = r.dbBytes();
    point.relay[r.name] = b;
    resources.relayDb[r.name] = Math.max(resources.relayDb[r.name] ?? 0, b);
  }
  resources.series.push(point);
}

async function checkpoint(label) {
  world.inCheckpoint = true;
  try {
    return await checkpointInner(label);
  } finally {
    world.inCheckpoint = false;
  }
}

async function checkpointInner(label) {
  log(`checkpoint ${label}: draining and waiting for convergence (up to ${HEAL_TIMEOUT_S}s)`);
  const deadline = Date.now() + HEAL_TIMEOUT_S * 1000;
  const result = { label, at: since() };
  // 1. Delivery: every strict message applied on its target device.
  let pending = [];
  let statusMiss = [];
  for (let round = 0; ; round++) {
    await Promise.all(world.devices.map((d) => d.run(["ls", "--all", "--json"], { op: "ls" }).then((r) => (d.lastLs = r.json))));
    scanEvents();
    pending = [...world.messages.values()].filter((m) => strict(m) && !m.appliedOn?.has(m.to.dev));
    statusMiss = statusConvergence();
    if ((pending.length === 0 && statusMiss.length === 0) || Date.now() > deadline) break;
    if (round % 3 === 0) log(`  waiting: ${pending.length} messages (${pending[0]?.text.slice(0, 50) ?? "-"}), ${statusMiss.length} statuses (${statusMiss[0] ?? "-"})`);
    await sleep(3000);
  }
  result.deliverS = (Date.now() - world.healedAt) / 1000;
  for (const m of pending) rec.problem("delivery-exactly-once", `"${m.text.slice(0, 70)}" (${m.kind}, sent ${((m.sentAt - T0) / 1000).toFixed(0)}s) never reached ${m.to.dev} ${m.to.sid}`, { message: m.text });
  for (const x of statusMiss) rec.problem("status-convergence", x);
  // 2. Footprints: everyone publishes once more (healed), then overlaps must match the plan.
  await footprintCheck();
  // 3. Doctor: read-only, and green.
  await doctorCheck();
  // 4. Poison, crash and malformed outcomes.
  outcomeChecks();
  scanNames();
  log(`checkpoint ${label}: done`);
  return result;
}

function statusConvergence() {
  const miss = [];
  for (const s of world.sessions.values()) {
    if (s.ended || !s.lastSummary) continue;
    for (const viewer of world.devices) {
      if (viewer === s.dev) continue;
      const want = s.delivered.get(viewer.user.userId);
      if (!want) continue;
      const rows = viewer.lastLs?.peers ?? [];
      const row = rows.find((p) => p.own === s.user.userId && p.sid === s.sid);
      if (!row) {
        miss.push(`${viewer.id} doesn't list ${s.dev.id}/${s.sid} (latest delivered: ${want.summary})`);
        continue;
      }
      // Statuses whose ts are within 2 s of the latest are a tie as far as the harness can tell.
      // A later attempt whose command reported failure may still have been delivered: newer, not stale.
      const newer = (s.attempts ?? []).some((a) => a.ts > want.ts && sameSummary(row.summary, a.summary));
      if (!newer && !want.near.some((x) => sameSummary(row.summary, x))) miss.push(`${viewer.id} shows ${s.dev.id}/${s.sid} as "${row.summary}", not the latest "${want.summary}"`);
      else if (want.agents !== undefined) {
        const key = (xs) => (xs ?? []).map((a) => `${a.id}:${a.state}`).sort().join(",");
        if (key(row.agents) !== key(want.agents)) miss.push(`${viewer.id} shows ${s.dev.id}/${s.sid}'s agents as [${key(row.agents)}], not [${key(want.agents)}]`);
      }
    }
  }
  return miss;
}

async function footprintCheck() {
  const fpUsers = world.users.filter((u) => u.spot);
  if (fpUsers.length < 2) return;
  // Every live session posts first and every device takes it in: a footprint goes only to users
  // whose live sessions advertise xstate.v1 (and overlaps compare live sessions only), so a device
  // that slept through the last statuses would otherwise be skipped until the 5-minute refresh.
  await Promise.all([...world.sessions.values()].filter((s) => !s.ended && !s.posting).map((s) => postStatus(s)));
  await Promise.all(world.devices.map((d) => d.run(["ls", "--json"], { op: "ls" })));
  // Then a forced publish of every fp session.
  for (const u of fpUsers) {
    const s = world.sessions.get(`${u.devices[0].id}|fp`);
    if (!s || s.ended) continue;
    await sleep(Math.max(0, 6000 - (Date.now() - (u.fpAt ?? 0))));
    await publishFootprint(u, { spot: u.spot });
  }
  await sleep(2000);
  const deadline = Date.now() + 60_000;
  let last = [];
  for (;;) {
    last = [];
    for (const u of fpUsers) {
      const r = await u.devices[0].run(["ix", "overlaps", "--session", "fp", "--json"], { op: "ix overlaps", cwd: u.repo });
      if (r.code !== 0 || !r.json) {
        last.push({ fatal: true, msg: `${u.name}: \`p2p ix overlaps\` failed: ${(r.json?.error ?? r.stderr.slice(-200)).toString().trim()}` });
        continue;
      }
      // Derived lines: hashed peers never get a name of mine; --json never carries detail.
      const text = JSON.stringify(r.json);
      for (const hit of new Set(text.match(NAME_RE) ?? [])) last.push({ fatal: true, inv: "hashed-names", msg: `${u.name}'s overlaps (--json) name ${hit}` });
      if (/"detail"/.test(text)) last.push({ fatal: true, inv: "hashed-names", msg: `${u.name}'s overlaps --json carries "detail"` });
      for (const o of r.json.overlaps ?? []) {
        for (const f of new Set(String(o.message).match(/src\/m\d+\.ts/g) ?? [])) if (f !== fileOf(u.spot.k)) last.push({ fatal: true, inv: "hashed-names", msg: `${u.name}'s overlap line names ${f}, which isn't a file its own status shares: ${o.message}` });
      }
      for (const v of fpUsers) {
        if (v === u) continue;
        const vs = world.sessions.get(`${v.devices[0].id}|fp`);
        const want = vs && world.canSee(u, vs) && v.fpPublished?.ok ? expectedOverlaps(u.spot, v.spot) : new Set();
        const got = new Set(
          (r.json.overlaps ?? []).filter((o) => o.peer?.own === v.userId).map((o) => (o.tier === "depends" ? `${o.tier}/${o.direction}/${o.severity}` : `${o.tier}/${o.severity}`)),
        );
        const missing = [...want].filter((x) => !got.has(x));
        const extra = [...got].filter((x) => !want.has(x));
        if (missing.length || extra.length)
          last.push({ msg: `${u.name} (${fileOf(u.spot.k)}#${u.spot.s}) vs ${v.name} (${fileOf(v.spot.k)}#${v.spot.s}): missing [${missing.join(", ")}], unexpected [${extra.join(", ")}]`, skipped: (r.json.skipped ?? []).filter((x) => x.peer?.own === v.userId).map((x) => x.reason) });
      }
    }
    if (last.every((x) => x.fatal) || Date.now() > deadline) break;
    await sleep(4000);
  }
  for (const x of last) rec.problem(x.inv ?? "footprint-overlap", x.msg + (x.skipped?.length ? ` (skipped: ${x.skipped.join(", ")})` : ""));
}

async function doctorCheck() {
  for (const dev of world.devices) {
    // Its watches are stopped for the moment, so anything that changes in the home is doctor's.
    for (const w of dev.watches.values()) if (!w.exited) w.child.kill("SIGSTOP");
    await sleep(300);
    const before = snapshot(dev.home);
    const r = await dev.run(["doctor", "--json"], { op: "doctor" });
    await sleep(200);
    const after = snapshot(dev.home);
    for (const w of dev.watches.values()) if (!w.exited) w.child.kill("SIGCONT");
    const changed = [...new Set([...Object.keys(before), ...Object.keys(after)])].filter((k) => before[k] !== after[k]);
    if (changed.length > 0) rec.problem("doctor", `${dev.id}: p2p doctor changed ${changed.slice(0, 5).join(", ")}`);
    const fails = (r.json?.checks ?? []).filter((c) => c.status === "fail");
    if (!r.json) rec.problem("doctor", `${dev.id}: p2p doctor printed no JSON (exit ${r.code})`);
    for (const f of fails) {
      // The skewed device's clock is still skewed after healing: doctor is right to say so.
      if (f.id === "clock" && dev.skewMs !== 0) {
        rec.ev("doctor-clock-expected", { dev: dev.id, detail: f.detail });
        continue;
      }
      rec.problem("doctor", `${dev.id}: doctor ✗ ${f.id}: ${f.detail}`.slice(0, 300));
    }
    dev.lastDoctor = r.json;
  }
}

function outcomeChecks() {
  for (const p of world.poison) {
    if (!p.sent) continue;
    const dev = world.devices.find((d) => d.id === p.dev);
    const now = dev.readDoc("inbound")?.gaveUp ?? 0;
    const before = p.beforeGaveUp[dev.id] ?? 0;
    // An unfriend or re-friend of the pair while it was in flight decides it: the redelivery is
    // refused (not given up) once they aren't friends. Racy, as for any other message.
    const m = world.messages.get(p.text);
    if (now <= before && m && poisonRefused(m, dev.id)) {
      rec.ev("poison-racy", { dev: dev.id, marker: p.marker });
      p.checked = { before, now, racy: true };
      continue;
    }
    if (now <= before) rec.problem("poison-gave-up", `${dev.id}: the poison ${p.marker} wasn't given up (gaveUp ${before} → ${now})`);
    const inbound = (dev.lastDoctor?.checks ?? []).find((c) => c.id === "inbound");
    if (!inbound || !/couldn't be applied/.test(inbound.detail)) rec.problem("poison-gave-up", `${dev.id}: p2p doctor doesn't count the dropped envelope`);
    if (JSON.stringify(dev.lastDoctor ?? {}).includes("SOAK-POISON")) rec.problem("poison-gave-up", `${dev.id}: p2p doctor shows the poison message's content`);
    p.checked = { before, now };
  }
  for (const c of world.crashes) {
    if (!c.sent) continue;
    const dev = world.devices.find((d) => d.id === c.dev);
    const crashed = existsSync(join(dev.faultDir, `crashed-${c.marker.split("-").at(-1)}`));
    c.crashed = crashed;
    if (!crashed) rec.problem("crash-mid-apply", `${dev.id}: nothing was killed applying ${c.marker} (the fault didn't fire)`);
    const ids = dev.appliedTexts?.get(c.text);
    // As for delivery-exactly-once: an unfriend or re-friend of the pair while it was in flight
    // decides it (the redelivery after the crash is refused once they aren't friends). Racy, not a
    // failure; applied twice always is.
    const m = world.messages.get(c.text);
    if ((!ids || ids.size === 0) && m && !strict(m)) {
      rec.ev("crash-racy", { dev: dev.id, marker: c.marker });
      continue;
    }
    if (!ids || ids.size !== 1) rec.problem("crash-mid-apply", `${dev.id}: ${c.marker} applied ${ids?.size ?? 0} times after the crash, not once`);
    // Its leftover temp file (the write the kill interrupted) is the only trace allowed.
  }
  for (const m of world.malformed) {
    if (!m.ok) {
      rec.problem("malformed-rejected", `the malformed-envelope helper failed: ${m.error}`);
      continue;
    }
    for (const d of m.to.devices) {
      const now = d.readDoc("peers");
      for (const rec2 of Object.values(now ?? {})) if (rec2?.status?.label === "soak-malformed" || rec2?.status?.state === "exploding") rec.problem("malformed-rejected", `${d.id} stored the malformed status`);
    }
    const evs = m.to.devices.flatMap((d) => (d.readDoc("events")?.items ?? []).filter((e) => e.kind === "p2p.message" && typeof e.data?.text !== "string"));
    if (evs.length > 0) rec.problem("malformed-rejected", `a non-text message was applied (${evs.length})`);
  }
}

// ---------------------------------------------------------------------------
// The run

function stats(op) {
  const xs = rec.samples[op] ?? [];
  const calm = xs.filter((x) => x.calm).map((x) => x.ms);
  const setup = xs.filter((x) => x.setup).map((x) => x.ms);
  return {
    n: xs.length,
    nCalm: calm.length,
    p50: pct(calm, 50),
    p95: pct(calm, 95),
    p50all: pct(xs.map((x) => x.ms), 50),
    p95all: pct(xs.map((x) => x.ms), 95),
    ...(setup.length > 0 ? { setup: { n: setup.length, p50: pct(setup, 50), p95: pct(setup, 95), max: Math.max(...setup) } } : {}),
  };
}

// packages/p2p/bench/README.md, "after" at RTT 80 ms (this run's links average about 75 ms plus jitter).
const BASELINE = {
  send: { p50: 483, p95: 521 },
  status: { p50: 663, p95: 864 }, // the status fan-out row (a circle session reaches every member)
  ls: { p50: 368, p95: 386 },
  "send → recipient's watch": { p50: 502, p95: 544 },
};
const BUDGET = { p50: 2.5, p95: 4 };

async function workload(untilMs) {
  const inflight = new Set();
  const launch = (dev, fn) => {
    if (dev) dev.inflight++;
    const p = fn()
      .catch((e) => rec.harnessErrors.push({ t: since(), error: String(e?.stack ?? e).slice(0, 500) }))
      .finally(() => {
        if (dev) dev.inflight--;
        inflight.delete(p);
      });
    inflight.add(p);
  };
  let nextChaosAt = Date.now() + 10_000;
  const chaosPlan = [];
  if (CHAOS) {
    // Each kind at least once per epoch, in a seeded order; more of them in longer epochs.
    const kinds = ["relay", "pause", "drop", "fill", "poison", "malformed", "crash"];
    const epochMs = untilMs - Date.now();
    const rounds = Math.max(1, Math.floor(epochMs / (8 * 60_000)));
    for (let i = 0; i < rounds; i++) chaosPlan.push(...cR.shuffle(kinds));
    chaosPlan.splice(cR.int(0, chaosPlan.length), 0, "drop");
  }
  const retries = new Map();
  const chaosGap = () => Math.max(4000, (untilMs - Date.now() - 30_000) / Math.max(1, chaosPlan.length));
  let lastSample = 0;
  let lastDisk = 0;
  let lastScan = 0;
  let lastNames = Date.now();
  while (Date.now() < untilMs) {
    const now = Date.now();
    if (now - lastSample > 5000) {
      lastSample = now;
      sampleResources();
    }
    if (now - lastDisk > 30_000) {
      lastDisk = now;
      sampleDisk();
    }
    if (now - lastScan > 10_000) {
      lastScan = now;
      scanEvents();
    }
    if (now - lastNames > 60_000) {
      lastNames = now;
      scanNames();
    }
    if (CHAOS && chaosPlan.length > 0 && now >= nextChaosAt) {
      const kind = chaosPlan.shift();
      nextChaosAt = now + chaosGap();
      const fn = { relay: chaosRelayKill, pause: () => chaosPause(), drop: async () => (chaosDrop(), true), fill: chaosFillMailbox, poison: chaosPoison, malformed: chaosMalformed, crash: chaosCrash }[kind];
      launch(undefined, async () => {
        if ((await fn()) === false) {
          // Nothing eligible right now (everyone asleep, nobody's friend): try again a little later.
          const tries = (retries.get(kind) ?? 0) + 1;
          retries.set(kind, tries);
          if (tries <= 8) {
            chaosPlan.unshift(kind);
            nextChaosAt = Math.min(nextChaosAt, Date.now() + 3000);
          } else rec.ev("chaos-skipped", { kind });
        }
      });
    }
    if (inflight.size < CONCURRENCY) {
      // Keep-alive first: every live session posts at least every 45 s (the mod posts every 60 s).
      const due = [...world.sessions.values()].find((s) => !s.ended && !s.dev.paused && !s.posting && now - s.lastPost > 45_000);
      if (due) {
        due.posting = true;
        launch(due.dev, () => postStatus(due).finally(() => (due.posting = false)));
      } else {
        const pick = wR.next();
        const devs = world.devices.filter((d) => !d.paused && d.inflight < 2);
        const dev = devs.length > 0 ? wR.pick(devs) : undefined;
        if (dev) {
          if (pick < 0.45) launch(dev, () => sendMessage(dev));
          else if (pick < 0.62) {
            const s = wR.pick([...world.sessions.values()].filter((x) => x.dev === dev && !x.ended && !x.posting));
            if (s) {
              s.posting = true;
              launch(dev, () => postStatus(s).finally(() => (s.posting = false)));
            }
          } else if (pick < 0.75) {
            const u = wR.pick(world.users.filter((x) => !x.devices[0].paused && !x.fpBusy));
            if (u) {
              u.fpBusy = true;
              launch(u.devices[0], () => publishFootprint(u).finally(() => (u.fpBusy = false)));
            }
          } else if (pick < 0.8) launch(dev, () => dev.run(["ls", "--json"], { op: "ls" }));
          else if (pick < 0.83) {
            if (now - (world.lastUnfriend ?? 0) > (MODE === "quick" ? 30_000 : 120_000)) {
              world.lastUnfriend = now;
              launch(undefined, unfriendCycle);
            }
          } else if (pick < 0.855) {
            // The owner auto-accepts at most 20 open-circle joins an hour (P2): stay under it.
            if (now - (world.lastCircleCycle ?? 0) > (MODE === "quick" ? 45_000 : 240_000)) {
              world.lastCircleCycle = now;
              launch(undefined, circleCycle);
            }
          }
          else if (pick < 0.885) launch(undefined, sessionCycle);
          else if (pick < 0.9) launch(undefined, identityRefresh);
          else if (pick < 0.93) launch(dev, () => dev.run(["friends", "--json"], { op: "friends" }));
        }
      }
    }
    await sleep(MODE === "quick" ? 250 : 400);
  }
  // Long operations (social cycles, pauses) finish on their own; wait for them.
  await Promise.all([...inflight]);
  for (const kind of chaosPlan) rec.ev("chaos-skipped", { kind, why: "the epoch ended first" });
}

async function shutdown() {
  world.stopping = true;
  for (const d of world.devices) if (d.paused) d.resume();
  await Promise.all(world.devices.flatMap((d) => [...d.watches.keys()].map((sid) => d.stopWatch(sid))));
  await sleep(1500);
  // No relay connection may outlive the clients.
  const open = {};
  for (const r of world.relays) {
    const m = await r.metrics();
    open[r.name] = m?.connections_open;
  }
  for (const [name, n] of Object.entries(open)) if (n > 0) rec.problem("no-orphans", `${name} still has ${n} open connections after every client stopped`);
  for (const d of world.devices) await d.closeLinks();
  for (const r of world.relays) await r.stop();
  await sleep(500);
  const left = processesUnder(scratch);
  for (const p of left) rec.problem("no-orphans", `process left running: ${p.command}`);
  for (const c of rec.children) {
    if (c.child.exitCode === null && c.child.signalCode === null) {
      rec.problem("no-orphans", `child still running: ${c.label}`);
      c.child.kill("SIGKILL");
    }
  }
  for (const p of processesUnder(scratch)) {
    try {
      process.kill(p.pid, "SIGKILL");
    } catch {}
  }
}

function latencyChecks() {
  const out = {};
  for (const op of Object.keys(rec.samples)) out[op] = stats(op);
  for (const [op, b] of Object.entries(BASELINE)) {
    const s = out[op];
    if (!s || s.nCalm < 20) continue;
    if (s.p50 > b.p50 * BUDGET.p50) rec.problem("latency", `${op}: calm p50 ${Math.round(s.p50)} ms > ${BUDGET.p50}× the bench's ${b.p50} ms`);
    if (s.p95 > b.p95 * BUDGET.p95) rec.problem("latency", `${op}: calm p95 ${Math.round(s.p95)} ms > ${BUDGET.p95}× the bench's ${b.p95} ms`);
  }
  return out;
}

function resourceChecks() {
  const MB = 1024 * 1024;
  if ((resources.rss["relay:relay-a"] ?? 0) > 400 * 1024 || (resources.rss["relay:relay-b"] ?? 0) > 400 * 1024) rec.problem("resources", `relay peak RSS over 400 MB`);
  if ((resources.rss.watch ?? 0) > 300 * 1024) rec.problem("resources", `a watch's peak RSS ${Math.round(resources.rss.watch / 1024)} MB > 300 MB`);
  for (const [d, b] of Object.entries(resources.homeBytes)) if (b > 32 * MB) rec.problem("resources", `${d}'s P2P_HOME reached ${(b / MB).toFixed(1)} MB`);
  // Bounded, not just small: over a long run the last third mustn't keep growing like the first.
  const s = resources.series;
  if (s.length >= 12) {
    const third = Math.floor(s.length / 3);
    for (const d of world.devices) {
      const a = s.slice(third, 2 * third).map((p) => p.home[d.id]);
      const b = s.slice(2 * third).map((p) => p.home[d.id]);
      const growthA = a.at(-1) - a[0];
      const growthB = b.at(-1) - b[0];
      if (growthB > 2 * MB && growthB > 2 * Math.max(growthA, 256 * 1024)) rec.problem("resources", `${d.id}'s P2P_HOME is still growing (${(growthB / 1024).toFixed(0)} KiB in the last third)`);
    }
  }
  // Leftover temp files from interrupted writes (the crash fault) are expected; more than a few are not.
  for (const d of world.devices) {
    const tmps = [];
    for (const sub of ["cli", "v3"]) {
      try {
        for (const f of readdirSync(join(d.home, sub))) if (f.endsWith(".tmp")) tmps.push(`${sub}/${f}`);
      } catch {}
    }
    resources.tmpFiles = { ...(resources.tmpFiles ?? {}), [d.id]: tmps.length };
    if (tmps.length > 3) rec.problem("resources", `${d.id} has ${tmps.length} leftover temp files (${tmps.slice(0, 3).join(", ")})`);
  }
}

function report(extra) {
  const byInv = {};
  for (const k of Object.keys(INVARIANTS)) byInv[k] = [];
  for (const p of rec.problems) byInv[p.inv].push(p);
  const msgs = [...world.messages.values()];
  const summary = {
    seed: SEED,
    mode: MODE,
    repro: `cd packages/p2p && npm run soak -- ${MODE === "quick" ? "--quick " : ""}--seed ${SEED} --minutes ${MINUTES} --users ${N_USERS}${args["epoch-minutes"] ? ` --epoch-minutes ${EPOCH_MIN}` : ""}`,
    note: "The seed fixes the plan (users, links, which operations and chaos in which order); real timing still varies between runs.",
    minutes: MINUTES,
    users: N_USERS,
    bin: BIN === P2P_BUNDLE_BIN ? "bundle" : "dist",
    durationS: Math.round(since() / 1000),
    invariants: Object.entries(INVARIANTS).map(([name, what]) => ({ name, what, ok: byInv[name].length === 0, failures: byInv[name].slice(0, 50).map((p) => ({ t: p.t, msg: p.msg })) })),
    counts: {
      messages: msgs.length,
      sent: msgs.filter((m) => m.state === "sent").length,
      sendFailed: msgs.filter((m) => m.state === "send-failed").length,
      strict: msgs.filter(strict).length,
      appliedOnTarget: msgs.filter((m) => m.appliedOn?.has(m.to.dev)).length,
      racyExcluded: msgs.filter((m) => m.state === "sent" && m.authorized && m.kind !== "poison" && !strict(m)).length,
      statuses: world.statusN,
      sessions: world.sessions.size,
      watchRestarts: rec.timeline.filter((e) => e.type === "watch-restart").length,
      crashFaults: rec.timeline.filter((e) => e.type === "crash-fault").length,
      gaveUpLines: rec.stderrNotes.gaveUp,
      rejectedLines: rec.stderrNotes.rejected.length,
    },
    chaos: rec.timeline.filter((e) => e.type.startsWith("chaos-")),
    floods: world.floods,
    poison: world.poison.map((p) => ({ marker: p.marker, dev: p.dev, sent: p.sent, gaveUp: p.checked })),
    crashes: world.crashes.map((c) => ({ marker: c.marker, dev: c.dev, sent: c.sent, crashed: c.crashed })),
    latency: extra.latency,
    // Every sample, for comparing runs: [ms since start, duration ms, calm, during setup].
    samples: Object.fromEntries(Object.entries(rec.samples).map(([op, xs]) => [op, xs.map((x) => [x.t, Math.round(x.ms), x.calm ? 1 : 0, x.setup ? 1 : 0])])),
    ...(diag.traceSlowMs > 0 ? { slow: rec.slow, harnessLag } : {}),
    baseline: BASELINE,
    budget: BUDGET,
    resources: { peakRssKb: resources.rss, peakHomeBytes: resources.homeBytes, peakRelayDbBytes: resources.relayDb, tmpFiles: resources.tmpFiles },
    checkpoints: extra.checkpoints,
    harnessErrors: rec.harnessErrors.slice(0, 20),
    // Refused at send, by error, and how many of those were sent with no chaos near either side.
    sendFailures: msgs
      .filter((m) => m.state === "send-failed")
      .reduce((a, m) => {
        const e = (a[m.error] ??= { n: 0, calm: 0 });
        e.n++;
        if (m.calmSend) e.calm++;
        return a;
      }, {}),
    timeline: rec.timeline,
    problems: rec.problems,
  };
  summary.counts.footprints = rec.timeline.filter((e) => e.type === "footprint").length;
  mkdirSync(join(outPath, ".."), { recursive: true });
  writeFileSync(outPath, JSON.stringify(summary, null, 1));
  const ok = summary.invariants.every((i) => i.ok) && rec.harnessErrors.length === 0;
  // The table
  const lines = [];
  lines.push(`\np2p soak: ${MODE}, seed ${SEED}, ${N_USERS} users, ${MINUTES} min, ${summary.durationS}s total — ${ok ? "PASS" : "FAIL"}`);
  lines.push("| invariant | result | failures |");
  lines.push("|---|---|---:|");
  for (const i of summary.invariants) lines.push(`| ${i.name} | ${i.ok ? "pass" : "FAIL"} | ${byInv[i.name].length} |`);
  lines.push("");
  lines.push(`messages: ${summary.counts.sent} sent (${summary.counts.strict} held to exactly-once, ${summary.counts.appliedOnTarget} applied on target, ${summary.counts.racyExcluded} racy, ${summary.counts.sendFailed} refused at send); statuses ${summary.counts.statuses}; footprints ${summary.counts.footprints}; watch restarts ${summary.counts.watchRestarts}; crash faults ${summary.counts.crashFaults}`);
  lines.push("| operation | n (calm) | p50 calm | p95 calm | p50 all | p95 all |");
  lines.push("|---|---:|---:|---:|---:|---:|");
  const f = (v) => (Number.isFinite(v) ? Math.round(v) : "-");
  for (const [op, s] of Object.entries(extra.latency).sort()) lines.push(`| ${op} | ${s.n} (${s.nCalm}) | ${f(s.p50)} | ${f(s.p95)} | ${f(s.p50all)} | ${f(s.p95all)} |`);
  const burst = Object.entries(extra.latency)
    .filter(([, s]) => s.setup)
    .sort()
    .map(([op, s]) => `${op} ${f(s.setup.p50)}/${f(s.setup.p95)} (n ${s.setup.n})`);
  if (burst.length > 0) lines.push(`setup burst (every device at once; not calm), p50/p95 ms: ${burst.join(", ")}`);
  const skipped = rec.timeline.filter((e) => e.type === "chaos-skipped").map((e) => e.kind);
  lines.push(`chaos: ${summary.chaos.filter((e) => !["chaos-resume", "chaos-relay-restart", "chaos-skipped"].includes(e.type)).map((e) => e.type.slice(6)).join(", ")}${skipped.length ? `; skipped: ${skipped.join(", ")}` : ""}`);
  lines.push(`peak RSS (MB): ${Object.entries(resources.rss).map(([k, v]) => `${k} ${(v / 1024).toFixed(0)}`).join(", ")}`);
  lines.push(`peak P2P_HOME (KiB): ${Object.entries(resources.homeBytes).map(([k, v]) => `${k} ${(v / 1024).toFixed(0)}`).join(", ")}; relay db (KiB): ${Object.entries(resources.relayDb).map(([k, v]) => `${k} ${(v / 1024).toFixed(0)}`).join(", ")}`);
  if (!ok) {
    lines.push("\nFailures (first 25):");
    for (const p of rec.problems.slice(0, 25)) lines.push(`  [${(p.t / 1000).toFixed(0)}s] ${p.inv}: ${p.msg}`);
    for (const h of rec.harnessErrors.slice(0, 5)) lines.push(`  harness error at ${(h.t / 1000).toFixed(0)}s: ${h.error.split("\n")[0]}`);
    lines.push(`\nReproduce: ${summary.repro}`);
    lines.push(`The timeline (every operation and chaos step) is in the report.`);
  }
  lines.push(`report: ${outPath}`);
  console.log(lines.join("\n"));
  return ok;
}

let ok = false;
const cleanup = () => {
  for (const c of rec.children) {
    try {
      c.child.kill("SIGKILL");
    } catch {}
  }
};
process.on("SIGINT", () => {
  cleanup();
  process.exit(130);
});
try {
  log(`p2p soak: ${MODE}, seed ${SEED}, ${MINUTES} min, ${N_USERS} users, scratch ${scratch}`);
  await setup();
  const checkpoints = [];
  const end = Date.now() + MINUTES * 60_000;
  let epoch = 0;
  let skewed;
  while (Date.now() < end) {
    epoch++;
    if (CHAOS && !skewed) skewed = chaosSkew();
    const until = Math.min(end, Date.now() + EPOCH_MIN * 60_000);
    log(`epoch ${epoch}: workload until +${Math.round((until - T0) / 1000)}s`);
    await workload(until);
    const stopKeepAlive = keepAlive();
    await heal();
    checkpoints.push(await checkpoint(`epoch ${epoch}`));
    await stopKeepAlive();
    sampleDisk();
  }
  const latency = latencyChecks();
  resourceChecks();
  await shutdown();
  ok = report({ latency, checkpoints });
} catch (e) {
  rec.harnessErrors.push({ t: since(), error: String(e?.stack ?? e).slice(0, 2000) });
  log(`harness error: ${String(e?.stack ?? e).slice(0, 1000)}`);
  try {
    await shutdown();
  } catch {}
  try {
    ok = report({ latency: latencyChecks(), checkpoints: [] }) && false;
  } catch {}
} finally {
  cleanup();
  if (!args.keep) rmSync(scratch, { recursive: true, force: true });
  else console.error(`kept ${scratch}`);
}
process.exit(ok ? 0 : 1);
