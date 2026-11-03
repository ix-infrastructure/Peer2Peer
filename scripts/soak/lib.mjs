// Copyright 2026 Ix Infrastructure Inc.
//
// Soak harness building blocks: a seeded RNG, the relay child processes, the
// simulated links (packages/p2p/bench/proxy.mjs), and a device: one P2P home
// driven through the real `p2p` binary (short commands and long-running
// `p2p watch` children), with fault injection (faults.mjs) preloaded.
//
// Nothing here reads the caller's ~/.p2p or talks to a real relay: every home,
// HOME and relay database is under the run's scratch directory, every relay
// listens on 127.0.0.1, and every child's environment is built from scratch
// (PATH only is inherited).

import { spawn, execFileSync } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import net from "node:net";
import { join, resolve, dirname, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { startProxy } from "../../packages/p2p/bench/proxy.mjs";

export const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO = resolve(HERE, "../..");
export const P2P_DIST_BIN = join(REPO, "packages/p2p/dist/bin.js");
export const P2P_BUNDLE_BIN = join(REPO, "mods/claude/peer2peer/bin/p2p.mjs");
export const RELAY_BIN = join(REPO, "packages/relay/dist/bin.js");
export const EXT_IX_PKG = join(REPO, "packages/ext-ix");
export const FAKE_IX = join(REPO, "packages/ext-ix/scripts/fake-ix.cjs");
export const FAULTS = join(HERE, "faults.mjs");
export const HELPER = join(HERE, "helper.mjs");

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Seeded randomness (mulberry32): the same seed gives the same plan of operations.

export function rng(seed) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const r = {
    next,
    int: (lo, hi) => lo + Math.floor(next() * (hi - lo + 1)),
    pick: (xs) => xs[Math.floor(next() * xs.length)],
    chance: (p) => next() < p,
    /** A child stream: the same parent seed and label always give the same stream. */
    fork: (label) => {
      let h = seed >>> 0;
      for (const c of label) h = Math.imul(h ^ c.charCodeAt(0), 2654435761) >>> 0;
      return rng(h);
    },
    shuffle: (xs) => {
      const a2 = [...xs];
      for (let i = a2.length - 1; i > 0; i--) {
        const j = Math.floor(next() * (i + 1));
        [a2[i], a2[j]] = [a2[j], a2[i]];
      }
      return a2;
    },
  };
  return r;
}

export function pct(xs, p) {
  if (xs.length === 0) return NaN;
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.max(0, Math.ceil((p / 100) * s.length) - 1))];
}

export async function freePort() {
  return new Promise((res, rej) => {
    const s = net.createServer();
    s.once("error", rej);
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
}

// ---------------------------------------------------------------------------
// Stderr: what counts as an unhandled exception or a crash in a child's output.

const CRASH_PATTERNS = [
  /\bUnhandled(?:PromiseRejection| promise rejection| 'error' event|\b)/i,
  /\bUncaught\b/,
  /^\s*(?:TypeError|ReferenceError|SyntaxError|RangeError|AssertionError|EvalError|URIError)\b/,
  /^\s+at (?:async )?\S.*\(?(?:file:|node:|\/).*:\d+:\d+\)?$/,
  /FATAL ERROR|Segmentation fault|Abort trap|heap out of memory/i,
  /\binternal error\b/i,
];

export function crashLines(text) {
  return text.split("\n").filter((l) => CRASH_PATTERNS.some((re) => re.test(l)));
}

// ---------------------------------------------------------------------------
// Relays: child processes of packages/relay/dist/bin.js on a fixed port, SQLite on disk,
// so a SIGKILL and restart keeps what was stored.

/** Loopback is one source IP for every simulated user: per-IP limits are lifted, per-identity ones kept. */
export function relayLimits(mode) {
  const big = 1_000_000_000;
  return {
    // The quota the "fill a mailbox" chaos step works against: small, so the run can reach it.
    mailboxEnvelopes: mode === "quick" ? 150 : 400,
    // Per sender: lifted like the latency bench's, since the flood helper sends a burst.
    sendsPerMinute: 100_000,
    framesPerConnPerMinute: 20_000,
    maxConnectionsPerIp: 4096,
    maxConnectionsPerIpv4: 4096,
    maxUnauthPerIp: 256,
    httpPerIpPerMinute: big,
    connectsPerIpPerMinute: big,
    authsPerIpPerMinute: big,
    authsPerIpv4PerMinute: big,
    sendBytesPerIpPerMinute: big,
    sourceAcceptedBytesPerHour: big,
    sourceMaxBytes: big,
    newDevicesPerIpPerDay: big,
    newDevicesPerIpv4PerDay: big,
    identityPublishPerIpPerHour: big,
    contactPerIpPerHour: big,
    linkOpsPerIpPerMinute: big,
    linkOpenPerIpPerHour: big,
    linkOpenPerIp: 256,
    invitePutPerIpPerHour: big,
    inviteBytesPerIp: 64 * 1024 * 1024,
    inviteGetsPerIpPerMinute: big,
    inviteMissesPerIpPerHour: big,
  };
}

export class RelayProc {
  constructor({ name, url, dir, port, metricsPort, limits, log }) {
    Object.assign(this, { name, url, dir, port, metricsPort, limits, log });
    this.child = undefined;
    this.up = false;
    this.starts = 0;
    this.errors = [];
    this.stderrTail = [];
    mkdirSync(dir, { recursive: true });
    this.configPath = join(dir, "relay-config.json");
    writeFileSync(this.configPath, JSON.stringify({ limits }));
  }

  async start() {
    const env = {
      PATH: process.env.PATH ?? "",
      RELAY_URL: this.url,
      HOST: "127.0.0.1",
      PORT: String(this.port),
      DB_PATH: join(this.dir, "relay.db"),
      METRICS_PORT: String(this.metricsPort),
      METRICS_HOST: "127.0.0.1",
      LOG_LEVEL: "warn",
      RELAY_CONFIG: this.configPath,
    };
    // --cpu-prof: the relays are profiled too (written when they stop cleanly, not after a SIGKILL).
    const prof = diag.cpuProfDir ? ["--cpu-prof", "--cpu-prof-dir", diag.cpuProfDir, "--cpu-prof-name", `relay-${this.name}-${this.starts + 1}.cpuprofile`] : [];
    const child = spawn(process.execPath, [...prof, RELAY_BIN], { env, stdio: ["ignore", "pipe", "pipe"] });
    this.child = child;
    this.starts++;
    const onLine = (line) => {
      if (!line.trim()) return;
      this.stderrTail.push(line);
      if (this.stderrTail.length > 200) this.stderrTail.shift();
      let j;
      try {
        j = JSON.parse(line);
      } catch {
        j = undefined;
      }
      if ((j && j.level === "error") || (!j && crashLines(line).length > 0)) this.errors.push({ t: Date.now(), line: line.slice(0, 500) });
    };
    for (const s of [child.stdout, child.stderr]) {
      let buf = "";
      s.on("data", (d) => {
        buf += d;
        let i;
        while ((i = buf.indexOf("\n")) >= 0) {
          onLine(buf.slice(0, i));
          buf = buf.slice(i + 1);
        }
      });
    }
    child.on("exit", (code, signal) => {
      if (this.child === child) {
        this.up = false;
        if (!this.killing && code !== 0) this.errors.push({ t: Date.now(), line: `relay exited unexpectedly (code ${code}, signal ${signal})` });
      }
    });
    // Ready when the port answers HTTP.
    const deadline = Date.now() + 15_000;
    for (;;) {
      try {
        const r = await fetch(`http://127.0.0.1:${this.port}/v3/identity/p2p:none`).catch(() => undefined);
        if (r) break;
      } catch {}
      if (Date.now() > deadline) throw new Error(`relay ${this.name} didn't start`);
      await sleep(100);
    }
    this.up = true;
    this.killing = false;
  }

  /** SIGKILL: no clean shutdown, as a crash or an OOM kill would be. */
  async kill() {
    if (!this.child) return;
    this.killing = true;
    const c = this.child;
    const gone = new Promise((r) => c.once("exit", r));
    c.kill("SIGKILL");
    await gone;
    this.up = false;
  }

  async stop() {
    if (!this.child || this.child.exitCode !== null || this.child.signalCode !== null) return;
    this.killing = true;
    const c = this.child;
    const gone = new Promise((r) => c.once("exit", r));
    c.kill("SIGTERM");
    const t = setTimeout(() => c.kill("SIGKILL"), 5000);
    await gone;
    clearTimeout(t);
    this.up = false;
  }

  pid() {
    return this.up ? this.child?.pid : undefined;
  }

  async metrics() {
    try {
      const r = await fetch(`http://127.0.0.1:${this.metricsPort}/metrics`, { signal: AbortSignal.timeout(3000) });
      const text = await r.text();
      const out = {};
      for (const line of text.split("\n")) {
        const m = /^p2p_relay_([a-z_]+)(\{[^}]*\})?\s+([0-9.eE+-]+)$/.exec(line);
        if (!m) continue;
        const key = m[1] + (m[2] ?? "");
        out[key] = Number(m[3]);
      }
      return out;
    } catch {
      return undefined;
    }
  }

  dbBytes() {
    let n = 0;
    for (const f of existsSync(this.dir) ? readdirSync(this.dir) : []) if (f.startsWith("relay.db")) n += statSync(join(this.dir, f)).size;
    return n;
  }
}

// ---------------------------------------------------------------------------
// Directory snapshots (doctor's read-only check) and sizes.

export function snapshot(dir) {
  const out = {};
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
      else out[relative(dir, p)] = `${st.size}:${st.mtimeMs}`;
    }
  };
  walk(dir);
  return out;
}

export function dirBytes(dir) {
  let n = 0;
  const walk = (d) => {
    let names;
    try {
      names = readdirSync(d);
    } catch {
      return;
    }
    for (const x of names) {
      const p = join(d, x);
      try {
        const st = statSync(p);
        if (st.isDirectory()) walk(p);
        else n += st.size;
      } catch {}
    }
  };
  walk(dir);
  return n;
}

/** Peak-RSS sampling: one `ps` for many pids. */
export function rssKb(pids) {
  const list = pids.filter((p) => Number.isSafeInteger(p) && p > 0);
  if (list.length === 0) return {};
  try {
    const out = execFileSync("ps", ["-o", "pid=,rss=", "-p", list.join(",")], { encoding: "utf8", env: { PATH: process.env.PATH ?? "", LC_ALL: "C" } });
    const m = {};
    for (const line of out.trim().split("\n")) {
      const [pid, rss] = line.trim().split(/\s+/).map(Number);
      if (Number.isFinite(pid) && Number.isFinite(rss)) m[pid] = rss;
    }
    return m;
  } catch {
    return {};
  }
}

/** Processes whose command line names the scratch directory (anything the run left behind). */
export function processesUnder(dir) {
  try {
    const out = execFileSync("ps", ["-axww", "-o", "pid=,command="], { encoding: "utf8", env: { PATH: process.env.PATH ?? "", LC_ALL: "C" }, maxBuffer: 16 * 1024 * 1024 });
    return out
      .split("\n")
      .filter((l) => l.includes(dir))
      .map((l) => {
        const m = /^\s*(\d+)\s+(.*)$/.exec(l);
        return m ? { pid: Number(m[1]), command: m[2].replace(dir, "<scratch>").slice(0, 200) } : undefined;
      })
      .filter((x) => x && x.pid !== process.pid);
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Diagnostics (off by default): soak.mjs's --trace-slow and --cpu-prof set these.
//  traceSlowMs: every command runs with P2P_DEBUG=1, its stderr lines are stamped with
//    their arrival time (ms since spawn), and commands slower than this are kept in the
//    report's `slow` list with their step log.
//  traceDir: with traceSlowMs, the watches run with P2P_DEBUG=1 too, and their stderr goes
//    to watch-<dev>-<sid>-<pid>.log there, each line stamped with wall-clock ms.
//  cpuProfDir: every command runs with --cpu-prof; profiles of commands slower than
//    traceSlowMs (or every one, without it) are kept there, named <dev>-<op>-<ms>ms-<n>.

export const diag = { traceSlowMs: 0, cpuProfDir: undefined, traceDir: undefined, n: 0 };

// ---------------------------------------------------------------------------
// A device: one P2P home of one user, on its own simulated links to every relay.

export class Device {
  constructor({ id, user, dir, relays, ext, fakeIxBin, fakeIxDir, bin, rtt, jitter, random, recorder, skewMs = 0 }) {
    Object.assign(this, { id, user, dir, relays, ext, fakeIxBin, fakeIxDir, bin, rtt, jitter, random, recorder, skewMs });
    this.home = join(dir, "p2p");
    this.homeDir = join(dir, "home");
    this.faultDir = join(dir, "faults");
    for (const d of [this.homeDir, this.faultDir]) mkdirSync(d, { recursive: true });
    this.proxies = {};
    this.watches = new Map();
    this.paused = false;
    this.inflight = 0;
    this.lastDropAt = 0;
  }

  async startLinks() {
    for (const r of this.relays) {
      this.proxies[r.url] = await startProxy(r.port, { oneWayMs: this.rtt / 2, jitterMs: this.jitter, random: this.random });
    }
  }

  get transport() {
    return JSON.stringify(Object.fromEntries(this.relays.map((r) => [r.url, `ws://127.0.0.1:${this.proxies[r.url].port}/v3`])));
  }

  env(extra = {}) {
    // From scratch: nothing of the caller's environment but PATH, so no P2P_* setting leaks in.
    return {
      PATH: `${this.fakeIxBin}:${process.env.PATH ?? ""}`,
      HOME: this.homeDir,
      P2P_HOME: this.home,
      P2P_RELAY_TRANSPORT: this.transport,
      P2P_EXTENSIONS: "ix",
      P2P_EXTENSION_PATH: this.ext,
      FAKE_IX_DIR: this.fakeIxDir,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_SYSTEM: "/dev/null",
      SOAK_FAULT_DIR: this.faultDir,
      SOAK_SKEW_MS: String(this.skewMs),
      ...extra,
    };
  }

  /** Runs `p2p <argv>`; resolves with {code, signal, json, stdout, stderr, ms}. */
  run(argv, { stdin = "", cwd, timeoutMs = 90_000, env = {}, op } = {}) {
    return new Promise((resolveRun) => {
      const t0 = performance.now();
      const nodeArgs = ["--import", pathToFileURL(FAULTS).href];
      const runN = ++diag.n;
      const profDir = diag.cpuProfDir ? join(diag.cpuProfDir, `run-${runN}`) : undefined;
      if (profDir) nodeArgs.push("--cpu-prof", "--cpu-prof-dir", profDir);
      const traceEnv = diag.traceSlowMs > 0 ? { P2P_DEBUG: "1" } : {};
      const child = spawn(process.execPath, [...nodeArgs, this.bin, ...argv], { env: this.env({ ...traceEnv, ...env }), cwd: cwd ?? this.homeDir, stdio: ["pipe", "pipe", "pipe"] });
      this.recorder.track(child, `${this.id} p2p ${argv[0]}`);
      let stdout = "";
      let stderr = "";
      const stamped = [];
      if (diag.traceSlowMs > 0) {
        let buf = "";
        child.stderr.on("data", (d) => {
          buf += d;
          let i;
          while ((i = buf.indexOf("\n")) >= 0) {
            stamped.push(`+${Math.round(performance.now() - t0)} ${buf.slice(0, i)}`);
            buf = buf.slice(i + 1);
          }
        });
      }
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill("SIGKILL");
      }, timeoutMs);
      child.stdout.on("data", (d) => (stdout += d));
      child.stderr.on("data", (d) => (stderr += d));
      child.on("error", (e) => (stderr += `spawn error: ${e.message}\n`));
      child.on("close", (code, signal) => {
        clearTimeout(timer);
        const ms = performance.now() - t0;
        let json;
        const lines = stdout.trim().split("\n");
        for (let i = lines.length - 1; i >= 0 && json === undefined; i--) {
          try {
            json = JSON.parse(lines[i]);
          } catch {}
        }
        const res = { code, signal, json, stdout, stderr, ms, timedOut, argv, pid: child.pid };
        this.recorder.onCommand(this, res, op ?? argv[0]);
        const slow = ms >= (diag.traceSlowMs || 0);
        if (diag.traceSlowMs > 0 && slow) this.recorder.onSlow?.(this, res, op ?? argv[0], stamped);
        if (profDir) {
          try {
            const files = readdirSync(profDir);
            if (slow && files.length > 0) renameSync(join(profDir, files[0]), join(diag.cpuProfDir, `${this.id}-${op ?? argv[0]}-${Math.round(ms)}ms-${runN}.cpuprofile`));
            rmSync(profDir, { recursive: true, force: true });
          } catch {}
        }
        resolveRun(res);
      });
      child.stdin.on("error", () => {});
      child.stdin.end(stdin);
    });
  }

  /** Runs a helper.mjs subcommand against this home (the library, not the CLI). */
  helper(args, { timeoutMs = 120_000 } = {}) {
    return new Promise((res) => {
      // With the same fault injection as every `p2p` of this device: a helper that receives (flood,
      // malformed) applies this device's envelopes too, and without it a poison message sent to the
      // device while its flood ran was applied (a harness hole, not the client's).
      const child = spawn(process.execPath, ["--import", pathToFileURL(FAULTS).href, HELPER, ...args], { env: this.env(), cwd: this.homeDir, stdio: ["ignore", "pipe", "pipe"] });
      this.recorder.track(child, `${this.id} helper ${args[0]}`);
      let out = "";
      let err = "";
      const t = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
      child.stdout.on("data", (d) => (out += d));
      child.stderr.on("data", (d) => (err += d));
      child.on("close", (code, signal) => {
        clearTimeout(t);
        let json;
        try {
          json = JSON.parse(out.trim().split("\n").at(-1));
        } catch {}
        res({ code, signal, json, stdout: out, stderr: err });
      });
    });
  }

  // --- the long-running `p2p watch --session <sid> --jsonl`, one per live session

  startWatch(sid) {
    const existing = this.watches.get(sid);
    if (existing && !existing.exited) return existing;
    const w = { sid, lines: 0, exited: false, wanted: true, restarts: existing ? existing.restarts + 1 : 0, startedAt: Date.now(), ids: new Map() };
    const child = spawn(process.execPath, ["--import", pathToFileURL(FAULTS).href, this.bin, "watch", "--session", sid, "--jsonl"], { env: this.env(diag.traceSlowMs > 0 ? { P2P_DEBUG: "1" } : {}), cwd: this.homeDir, stdio: ["ignore", "pipe", "pipe"] });
    w.child = child;
    if (diag.traceSlowMs > 0 && diag.traceDir) {
      // The watch's step log, stamped with wall-clock ms, next to the report.
      const file = join(diag.traceDir, `watch-${this.id}-${sid}-${child.pid}.log`);
      let tb = "";
      child.stderr.on("data", (d) => {
        tb += d;
        let i;
        let out = "";
        while ((i = tb.indexOf("\n")) >= 0) {
          out += `${Date.now()} ${tb.slice(0, i)}\n`;
          tb = tb.slice(i + 1);
        }
        if (out) appendFileSync(file, out);
      });
    }
    this.recorder.track(child, `${this.id} watch ${sid}`);
    let buf = "";
    child.stdout.on("data", (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 1);
        if (!line.trim()) continue;
        let e;
        try {
          e = JSON.parse(line);
        } catch {
          this.recorder.problem("watch-output", `${this.id} watch ${sid} printed a non-JSON line`, { line: line.slice(0, 200) });
          continue;
        }
        w.lines++;
        this.recorder.onWatchEvent(this, w, e);
      }
    });
    let err = "";
    child.stderr.on("data", (d) => {
      err += d;
      let i;
      while ((i = err.indexOf("\n")) >= 0) {
        this.recorder.onStderrLine(this, `watch ${sid}`, err.slice(0, i));
        err = err.slice(i + 1);
      }
    });
    child.on("exit", (code, signal) => {
      w.exited = true;
      w.exit = { code, signal, at: Date.now() };
      this.recorder.onWatchExit(this, w, code, signal);
    });
    this.watches.set(sid, w);
    return w;
  }

  async stopWatch(sid) {
    const w = this.watches.get(sid);
    if (!w || w.exited) return;
    w.wanted = false;
    if (this.paused) w.child.kill("SIGCONT");
    const gone = new Promise((r) => w.child.once("exit", r));
    w.child.kill("SIGTERM");
    const t = setTimeout(() => w.child.kill("SIGKILL"), 8000);
    await gone;
    clearTimeout(t);
  }

  watchPids() {
    return [...this.watches.values()].filter((w) => !w.exited).map((w) => w.child.pid);
  }

  /** Laptop sleep: every process of this device stops (SIGSTOP); nothing new is started on it. */
  pause() {
    this.paused = true;
    for (const w of this.watches.values()) if (!w.exited) w.child.kill("SIGSTOP");
  }

  resume() {
    this.paused = false;
    for (const w of this.watches.values()) if (!w.exited) w.child.kill("SIGCONT");
  }

  dropLinks() {
    this.lastDropAt = Date.now();
    for (const p of Object.values(this.proxies)) p.dropAll();
  }

  async closeLinks() {
    for (const p of Object.values(this.proxies)) await p.close();
  }

  // --- reading this home's state (the invariants read the stored documents directly)

  readDoc(name) {
    try {
      return JSON.parse(readFileSync(join(this.home, "cli", `${name}.json`), "utf8"));
    } catch {
      return undefined;
    }
  }
}

// ---------------------------------------------------------------------------
// Checks shared with checks.test.mjs.

/**
 * Why a delivery reached no relay, from a `--json` failure (e.g. `accept`'s `undelivered`, whose
 * `delivered.errors` lists {did, relay, code}): the distinct codes, per relay, for the report.
 * Seed 9's "couldn't become friends again" left only `undelivered` behind, which says nothing.
 */
export function deliveryErrors(json) {
  const errs = Array.isArray(json?.delivered?.errors) ? json.delivered.errors : [];
  const by = new Map();
  for (const e of errs) {
    const k = `${e?.relay || "(none)"}`;
    by.set(k, [...new Set([...(by.get(k) ?? []), String(e?.code ?? "?")])]);
  }
  return [...by.entries()].map(([relay, codes]) => `${relay}: ${codes.join(",")}`).sort();
}

/**
 * How long a (re-)join waits for the owner to hold it for approval. A former member's join reaches
 * the owner as a held item, which can take longer than a few polls when relays drop connections
 * (seed 3: held after the old ~7 s of polling, so the heal's join found the device already joined
 * and gave up).
 */
export const JOIN_APPROVAL_POLL_MS = 30_000;

/**
 * Whether a `p2p circle join` result means this device has joined: `joined`, or `already` (an
 * earlier try joined here, and its join may still be waiting for the owner's approval).
 */
export function joinedHere(json) {
  return json?.status === "joined" || json?.status === "already";
}

/** `shown` (from `ls`) is exactly `posted`, apart from the ` (+N agents)` ls may append: st-x-u-1 isn't st-x-u-12. */
export function sameSummary(shown, posted) {
  return String(shown ?? "").replace(/(^| )\(\+\d+ agents?\)$/, "") === posted;
}

/** How long after it was sent an unfriend or re-friend can still decide a poison message's fate. */
export const POISON_RACE_MS = 120_000;

/**
 * A message (the poison) its recipient refused instead of giving up, because its pair unfriended or
 * re-friended while it was in flight: the pair changed within [sent - 30 s, sent + POISON_RACE_MS],
 * and the recipient device logged a refusal of an envelope from that sender in that window
 * (`rejected …: <reason>: <from> -> <to> not authorised …`). `rejected` entries carry ms since `t0`.
 */
export function refusedWhilePairChanged({ m, devId, socialLog, rejected, t0 }) {
  const from = m.sentAt - 30_000;
  const end = m.sentAt + POISON_RACE_MS;
  const changed = socialLog.some((c) => c.t >= from && c.t <= end && c.kind === "friend" && c.users.has(m.from.user) && c.users.has(m.to.user));
  if (!changed) return false;
  return rejected.some((r) => r.dev === devId && t0 + r.t >= m.sentAt && t0 + r.t <= end && r.line.includes(`${m.from.user} -> `));
}
