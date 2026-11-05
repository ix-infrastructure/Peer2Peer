// Copyright 2026 Ix Infrastructure Inc.
//
// No command hangs silently (the Windows `p2p accept` report): every network
// step is bounded and announced when slow, the whole command has a deadline,
// stdin that never ends doesn't block, a held state lock says so, and
// P2P_DEBUG=1 logs steps without secrets. Each Windows-flavoured cause is
// simulated here (a relay that never says hello, an HTTP API that never
// answers, an inherited stdin that never closes, a lock held by a live pid).

import { createServer, type Server } from "node:http";
import { createServer as createNetServer, type Server as NetServer } from "node:net";
import { readFileSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { WebSocketServer } from "ws";
import { CliError } from "../errors.js";
import { makeProgress, step } from "../progress.js";
import { fetchTips, RelayPool } from "../relay-client.js";
import { END_OF_INPUT_HINT, readAll } from "../stdin.js";
import { startRelay, User, type TestRelay } from "./harness.js";
import type { App } from "../app.js";

const BH = "wss://blackhole.test/v3";
const R = "wss://hangs-ok.test/v3";
let silentWs: WebSocketServer;
let silentHttp: Server;
let wsPort = 0;
let httpPort = 0;
let relay: TestRelay;
const users: User[] = [];

beforeAll(async () => {
  // Accepts the WebSocket, then never says hello (a relay or proxy that stalls).
  silentWs = new WebSocketServer({ port: 0, host: "127.0.0.1" });
  await new Promise<void>((r) => silentWs.once("listening", () => r()));
  wsPort = (silentWs.address() as { port: number }).port;
  // Accepts HTTP requests and never answers them.
  silentHttp = createServer(() => {});
  await new Promise<void>((r) => silentHttp.listen(0, "127.0.0.1", () => r()));
  httpPort = (silentHttp.address() as { port: number }).port;
  relay = await startRelay(R);
});

afterAll(async () => {
  for (const c of silentWs.clients) c.terminate();
  silentWs.close();
  silentHttp.closeAllConnections();
  silentHttp.close();
  await relay.close();
  for (const u of users) u.cleanup();
});

function user(name: string, extra: Record<string, string> = {}, transport: Record<string, string> = {}): User {
  const u = new User(name, { [BH]: `ws://127.0.0.1:${wsPort}/v3`, [R]: `ws://127.0.0.1:${relay.port}/v3`, ...transport }, extra);
  users.push(u);
  return u;
}

describe("bounded, announced steps", () => {
  it("a relay that never says hello: the slow step is announced, then it fails naming the relay and the step", async () => {
    const u = user("bh", { P2P_CONNECT_TIMEOUT_MS: "1200", P2P_SLOW_MS: "300" });
    await u.ok(["init", "--name", "bh", "--relay", BH, "--yes"]);
    const t0 = Date.now();
    const r = await u.run(["invite", "--no-circle"]);
    expect(Date.now() - t0).toBeLessThan(8000);
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/p2p: connecting to wss:\/\/blackhole\.test\/v3 \(relay 1\/1\)…/);
    expect(r.err).toMatch(/blackhole\.test\/v3: timed out waiting for hello \(after 1s\)/);
    expect(r.json).toMatchObject({ error: "no_relay" });
  }, 30_000);

  it("the whole command has a deadline that names the step it was on", async () => {
    const setup = user("deadline-setup", { P2P_CONNECT_TIMEOUT_MS: "1000" });
    await setup.ok(["init", "--name", "dl", "--relay", BH, "--yes"]);
    const u = user("deadline", { P2P_HOME: setup.home, P2P_PERSON_TOKEN: setup.personToken, P2P_CONNECT_TIMEOUT_MS: "20000", P2P_COMMAND_TIMEOUT_SEC: "1" });
    const t0 = Date.now();
    const r = await u.run(["invite", "--no-circle"]);
    // 1 s deadline, then at most SETTLE_MS (5 s) for what is in flight to settle.
    expect(Date.now() - t0).toBeLessThan(9000);
    expect(r.code).toBe(1);
    expect(r.json.error).toBe("timeout");
    expect(r.json.reason).toMatch(/`p2p invite` gave up after 1s while connecting to wss:\/\/blackhole\.test\/v3 \(relay 1\/1\).*P2P_DEBUG=1/);
  }, 30_000);

  it("an HTTP document API that never answers: bounded, announced", async () => {
    const lines: string[] = [];
    const p = { ...makeProgress({ P2P_SLOW_MS: "100" }, (m) => lines.push(m)) };
    const t0 = Date.now();
    const e = await fetchTips({ ws: "", http: `http://127.0.0.1:${httpPort}/v3` }, "p2p:x", 600, p).catch((x: unknown) => x);
    expect(Date.now() - t0).toBeLessThan(3000);
    expect(e).toBeInstanceOf(CliError);
    expect((e as CliError).code).toBe("timeout");
    expect(lines.join("\n")).toMatch(/fetching p2p:x's identity from http:\/\/127\.0\.0\.1:\d+…/);
  });

  it("step: announced once past slowMs, a timeout names it, and P2P_DEBUG logs start and end", async () => {
    const lines: string[] = [];
    const p = makeProgress({ P2P_SLOW_MS: "50" }, (m) => lines.push(m));
    await step(p, "doing a slow thing", () => new Promise((r) => setTimeout(r, 150)));
    expect(lines).toEqual(["doing a slow thing…"]);
    await expect(step(p, "never answering", () => new Promise(() => {}), { timeoutMs: 100 })).rejects.toThrow(/never answering: no answer after 0\.1s/);
    const dl: string[] = [];
    const d = makeProgress({ P2P_DEBUG: "1" }, (m) => dl.push(m));
    await step(d, "quick", async () => 1);
    expect(dl[0]).toBe("debug: quick…");
    expect(dl[1]).toMatch(/^debug: quick: done in \d+ms$/);
  });

  it("drain doesn't wait forever on a handler that never finishes", async () => {
    const logs: string[] = [];
    const pool = new RelayPool({
      relays: [],
      transport: () => ({ ws: "", http: "" }),
      auth: { cert: "", signingSecretKey: new Uint8Array(32) },
      timeoutMs: 1000,
      handlerGraceMs: 200,
      onEnvelope: () => new Promise(() => {}),
      log: (m) => logs.push(m),
    });
    (pool as unknown as { onEnv: (rid: string, env: string, c: unknown) => void }).onEnv("1", "env", { relay: "wss://r/v3", send() {} });
    const t0 = Date.now();
    await pool.drain(50, 100);
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(logs.join("\n")).toMatch(/still handling 1 queued message/);
    pool.close();
  });
});

describe("unreachable relays (a firewall that drops SYNs, as on a private network)", () => {
  // Accepts TCP and never answers: the dial stalls exactly like a dropped SYN would.
  let silentTcp: NetServer;
  let tcpPort = 0;
  let closedPort = 0;
  beforeAll(async () => {
    silentTcp = createNetServer(() => {});
    await new Promise<void>((r) => silentTcp.listen(0, "127.0.0.1", () => r()));
    tcpPort = (silentTcp.address() as { port: number }).port;
    const tmp = createNetServer();
    await new Promise<void>((r) => tmp.listen(0, "127.0.0.1", () => r()));
    closedPort = (tmp.address() as { port: number }).port;
    await new Promise<void>((r) => tmp.close(() => r()));
  });
  afterAll(() => {
    silentTcp.close();
  });

  it("one clear message per relay, no quiet retries; a real black-hole address too; the command stays short", async () => {
    const SILENT = "wss://silent-dial.test/v3";
    const HOLE = "wss://192.0.2.1/v3"; // TEST-NET-1: never routed, so SYNs go unanswered (or fail at once)
    const u = user("unreach", { P2P_CONNECT_TIMEOUT_MS: "1000", P2P_SLOW_MS: "60000" }, { [SILENT]: `ws://127.0.0.1:${tcpPort}/v3` });
    await u.run(["init", "--name", "un", "--relay", SILENT, "--relay", HOLE, "--yes"]);
    const t0 = Date.now();
    const r = await u.run(["invite", "--no-circle"]);
    expect(Date.now() - t0).toBeLessThan(6000);
    expect(r.code).toBe(1);
    const silentMsg = `p2p: can't reach ${SILENT} (no response on port ${tcpPort} after 1s: check your network or firewall)`;
    expect(r.err.split("\n").filter((l) => l === silentMsg)).toHaveLength(1);
    expect(r.err.split("\n").filter((l) => l.startsWith(`p2p: can't reach ${HOLE} (`))).toHaveLength(1);
    expect(r.err).not.toMatch(/timed out connecting/);
  }, 30_000);

  it("a refused connection says so", async () => {
    const REFUSED = "wss://refused.test/v3";
    const u = user("refused", { P2P_CONNECT_TIMEOUT_MS: "3000" }, { [REFUSED]: `ws://127.0.0.1:${closedPort}/v3` });
    await u.run(["init", "--name", "rf", "--relay", REFUSED, "--yes"]);
    const r = await u.run(["invite", "--no-circle"]);
    expect(r.err).toContain(`p2p: can't reach ${REFUSED} (connection refused on port ${closedPort}: check your network or firewall)`);
  }, 30_000);

  it("once unreachable, later connects and fetches in the same command fail at once (bounded total time)", async () => {
    const SILENT = "wss://silent-dial2.test/v3";
    const progress = makeProgress({}, () => {});
    const pool = new RelayPool({
      relays: [SILENT],
      transport: () => ({ ws: `ws://127.0.0.1:${tcpPort}/v3`, http: `http://127.0.0.1:${tcpPort}/v3` }),
      auth: { cert: "", signingSecretKey: new Uint8Array(32) },
      timeoutMs: 800,
      progress,
    });
    const first = await pool.connect();
    expect(first.failed[0].error).toMatch(/can't reach/);
    const t0 = Date.now();
    await expect(pool.ensure(SILENT)).rejects.toThrow(/can't reach wss:\/\/silent-dial2\.test\/v3/);
    await expect(fetchTips({ ws: "", http: `http://127.0.0.1:${tcpPort}/v3` }, "p2p:x", 5000, progress)).rejects.toThrow(/can't reach/);
    // At once: no new dial (which would wait out its 800 ms timeout); room for a slow runner below that.
    expect(Date.now() - t0).toBeLessThan(600);
    expect(pool.dials.get(SILENT)).toBe(1);
    pool.close();
  }, 30_000);

  it("a relay that answered the dial is never remembered as unreachable later in the command (the dial timer is cleared)", async () => {
    const URL_ = "wss://answers.test/v3";
    const relay = await startRelay(URL_);
    try {
      const progress = makeProgress({}, () => {});
      const pool = new RelayPool({
        relays: [URL_],
        transport: () => ({ ws: `ws://127.0.0.1:${relay.port}/v3`, http: `http://127.0.0.1:${relay.port}/v3` }),
        // A bogus device: the relay answers, then refuses the auth and closes.
        auth: { cert: "", signingSecretKey: new Uint8Array(32) },
        timeoutMs: 300,
        progress,
      });
      await pool.connect().catch(() => undefined);
      await new Promise((r) => setTimeout(r, 600));
      expect([...(progress.unreachable?.keys() ?? [])]).toEqual([]);
      pool.close();
    } finally {
      await relay.close();
    }
  }, 30_000);
});

describe("stdin that never ends (PowerShell, IDE tasks)", () => {
  it("an implicit read gives up with nothing; an explicit one says how to end the input", async () => {
    const never = new PassThrough();
    const t0 = Date.now();
    expect(await readAll(never, { implicit: true, idleMs: 100 })).toBe("");
    expect(Date.now() - t0).toBeLessThan(1000);
    const hints: string[] = [];
    const s = new PassThrough();
    const p = readAll(s, { hintMs: 50, hint: (m) => hints.push(m) });
    await new Promise((r) => setTimeout(r, 120));
    expect(hints).toEqual([END_OF_INPUT_HINT]);
    s.end("hello\n");
    expect(await p).toBe("hello\n");
    // Data before the idle limit is read in full.
    const q = new PassThrough();
    const pq = readAll(q, { implicit: true, idleMs: 200 });
    q.write("a");
    q.end("b");
    expect(await pq).toBe("ab");
  });

  it("`send` with no text and a stdin that never ends fails fast instead of hanging", async () => {
    const u = user("stdin", {}, {});
    await u.ok(["init", "--name", "si", "--relay", R, "--yes"]);
    const lines = { out: [] as string[], err: [] as string[] };
    const never = new PassThrough();
    const { main } = await import("../cli.js");
    const t0 = Date.now();
    const code = await main(["send", "--from-session", "s1", "--to", "nobody", "--json"], {
      env: u.env,
      io: { ...u.io(lines), readStdin: (o) => readAll(never, { implicit: o?.implicit, idleMs: 200 }) },
    });
    expect(Date.now() - t0).toBeLessThan(10_000);
    expect(code).toBe(1);
    // review L2: the error says how a slow producer can still pipe the text in.
    expect(lines.out.at(-1)).toMatch(/--stdin \(or `-` as the text\)/);
  }, 30_000);
});

describe("review L1: the deadline cancels the work", () => {
  /** A stand-in App with a real deadline config, abort signal and progress. */
  function deadlineApp(seconds: number) {
    const abort = new AbortController();
    return {
      abort,
      app: {
        keys: undefined,
        tun: { commandTimeoutSec: seconds },
        abort,
        progress: { log: () => {}, debug: false, slowMs: 3000, signal: abort.signal, current: "waiting for wss://r.test/v3 to answer send" },
        load: async () => true,
        close: async () => {},
      } as unknown as App,
    };
  }
  async function runWith(argv: string[], ops: Record<string, unknown>, seconds: number) {
    const { main } = await import("../cli.js");
    const { app, abort } = deadlineApp(seconds);
    const out: string[] = [];
    const t0 = Date.now();
    const code = await main(argv, { env: {}, confirmTty: async () => true, io: { out: (x) => out.push(x), err: () => {} }, ops: ops as never, makeApp: () => app });
    process.exitCode = 0;
    return { code, json: JSON.parse(out.at(-1) ?? "null"), ms: Date.now() - t0, abort };
  }

  it("a timed-out send reports 'outcome unknown', after aborting the work and letting it settle", async () => {
    let settled = false;
    let sawAbort = false;
    const sendMessage = async (a: App) =>
      new Promise((resolve) => {
        a.abort.signal.addEventListener("abort", () => {
          sawAbort = true;
          // An in-flight send finishing after the abort.
          setTimeout(() => {
            settled = true;
            resolve({ delivered: true });
          }, 300);
        });
      });
    const r = await runWith(["send", "--from-session", "s1", "--to", "bob", "hi", "--json"], { sendMessage }, 1);
    expect(r.code).toBe(1);
    expect(r.json.error).toBe("outcome_unknown");
    expect(r.json.reason).toMatch(/^outcome unknown: it may have been delivered; check before resending/);
    expect(sawAbort).toBe(true);
    expect(settled).toBe(true);
    expect(r.ms).toBeLessThan(4000);
  }, 20_000);

  it("other commands report a timeout; no new network step starts once aborted", async () => {
    const r = await runWith(["petname", "bob", "b", "--json"], { petname: () => new Promise(() => {}) }, 1);
    expect(r.json.error).toBe("timeout");
    expect(r.abort.signal.aborted).toBe(true);
    const p = { ...makeProgress({}, () => {}), signal: r.abort.signal };
    await expect(step(p, "connecting to wss://r.test/v3", async () => 1)).rejects.toThrow(/ran out of time/);
  }, 20_000);

  it("setup and backup restore are exempt from the deadline", async () => {
    const slow = (v: unknown) => () => new Promise((res) => setTimeout(() => res(v), 1600));
    const s = await runWith(["setup", "--no-backup", "--json"], { setup: slow({ created: true, userId: "u", address: "a", relays: ["r"] }) }, 1);
    expect(s.code).toBe(0);
    expect(s.json.created).toBe(true);
    const { main } = await import("../cli.js");
    const { app } = deadlineApp(1);
    const out: string[] = [];
    const code = await main(["backup", "restore", "--json"], {
      env: {},
      io: { out: (x) => out.push(x), err: () => {}, readStdin: async () => "phrase" },
      ops: { backupRestore: slow({ userId: "u", address: "a", did: "d", ver: 2, revoked: [], failed: [] }) } as never,
      makeApp: () => app,
    });
    process.exitCode = 0;
    expect(code).toBe(0);
    expect(JSON.parse(out.at(-1)!).ver).toBe(2);
  }, 20_000);

  it("restore never wipes the home once a publish may have been stored", async () => {
    // A relay that takes the identity publish and never answers it (the reply lost on the way).
    const MUTE = "wss://mute.test/v3";
    const http = createServer((_req, res) => {
      res.writeHead(404, { "content-type": "application/json" });
      res.end("{}");
    });
    const wss = new WebSocketServer({ server: http });
    let published = 0;
    wss.on("connection", (ws) => {
      ws.send(JSON.stringify({ t: "hello", relay: MUTE, nonce: "bm9uY2Vub25jZW5vbmNl", pow: 0 }));
      ws.on("message", (d) => {
        const f = JSON.parse(String(d)) as { t: string; id?: string };
        if (f.t === "auth") ws.send(JSON.stringify({ t: "ok", id: f.id }));
        if (f.t === "identity") published++;
      });
    });
    await new Promise<void>((r) => http.listen(0, "127.0.0.1", () => r()));
    const port = (http.address() as { port: number }).port;
    try {
      const owner = user("rs-owner");
      await owner.ok(["init", "--name", "rs", "--relay", R, "--yes"]);
      const phrase = (await owner.ok(["backup", "show"])).phrase as string;
      const fresh = user("rs-fresh", { P2P_REQUEST_TIMEOUT_MS: "800" }, { [MUTE]: `ws://127.0.0.1:${port}/v3` });
      const r = await fresh.run(["backup", "restore", "--relay", MUTE, "--new-chain"], { stdin: phrase });
      expect(published).toBeGreaterThan(0);
      expect(r.code).toBe(1);
      expect(r.json.error).toBe("restore_interrupted");
      expect(r.json.reason).toMatch(/was kept: run `p2p identity republish`/);
      // The keys of the device a relay may now list are still there.
      expect(JSON.parse(readFileSync(join(fresh.home, "cli", "keys.json"), "utf8")).userId).toBe((await owner.ok(["whoami"])).userId);
    } finally {
      for (const c of wss.clients) c.terminate();
      wss.close();
      http.closeAllConnections();
      http.close();
    }
  }, 30_000);
});

describe("the state lock", () => {
  it("a lock held by a live process: says what it waits for, then fails (no silent wait)", async () => {
    const u = user("locked", { P2P_SLOW_MS: "300" });
    await u.ok(["init", "--name", "lk", "--relay", R, "--yes"]);
    // A live pid on this host (this test process): the lock can't be broken.
    writeFileSync(join(u.home, "cli", ".lock"), JSON.stringify({ pid: process.pid, host: hostname(), token: "held" }));
    const r = await u.run(["circle", "default", "--none"]);
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/waiting for p2p's state lock in .* \(is another p2p command running\?\)…/);
    expect(r.out + r.err).toMatch(/locked/);
  }, 40_000);
});

describe("P2P_DEBUG=1", () => {
  it("logs each step and never a secret", async () => {
    const u = user("dbg", { P2P_DEBUG: "1" });
    await u.ok(["init", "--name", "dbg", "--relay", R, "--yes"]);
    const inv = await u.run(["invite", "--no-circle"]);
    expect(inv.code).toBe(0);
    expect(inv.err).toMatch(/debug: connecting to wss:\/\/hangs-ok\.test\/v3 \(relay 1\/1\)…/);
    expect(inv.err).toMatch(/debug: waiting for wss:\/\/hangs-ok\.test\/v3 to answer invite-put: done in \d+ms/);
    const keys = JSON.parse(readFileSync(join(u.home, "cli", "keys.json"), "utf8")) as Record<string, string>;
    for (const secret of [keys.spk, keys.kpk, keys.ik]) expect(inv.err).not.toContain(secret);
    expect(inv.err).not.toContain(inv.json.code.split("/")[1]);
  }, 30_000);
});
