#!/usr/bin/env node
// Copyright 2026 Ix Infrastructure Inc.
//
// Cross-version matrix (docs/compatibility.md): this tree's CLI against the CLI as it was at
// earlier git refs, both ways, over a local relay (this tree's), for every feature they share:
// invite and accept, messages, statuses, a circle join, the offline queue, and delivery receipts
// where both have them. It asserts that shared features work, that new-only features degrade
// cleanly (the newer side leaves them out), and that no side rejects an envelope.
//
//   node scripts/compat/matrix.mjs [--refs 70b86c7,v0.1.0] [--new mods/claude/peer2peer/bin/p2p.mjs] [--new-env K=V]... [--json]
//
// `--new-env` sets an environment variable for the new side only: `--new-env P2P_DEVICE_INFO=1` is
// step 2 of the device-info rollout, which must pass against every ref it is meant to support.
//
// Each old CLI is the committed single-file bundle at that ref (`git show <ref>:mods/claude/
// peer2peer/bin/p2p.mjs`), so nothing is built. The default ref, until there are release tags, is
// 70b86c7 (the initial public release: protocol 3.1); after that, the previous two release tags.
// Every ref must be reachable in this repository's history. P2P_COMPAT_REFS or --refs overrides it. Needs packages/relay built.
// Every home is a fresh temp directory (P2P_HOME); nothing reads ~/.p2p or talks to a real relay.

import { execFile, execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const RELAY_URL = "wss://relay-matrix.test/v3";
export const DEFAULT_REFS = ["70b86c7"];

function sh(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { cwd: ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, ...opts });
}

/** The committed CLI bundle at `ref`, written to `dir`. */
export function bundleAt(ref, dir) {
  const sha = sh("git", ["rev-parse", "--short=12", `${ref}^{commit}`]).trim();
  const file = join(dir, `p2p-${sha}.mjs`);
  if (!existsSync(file)) writeFileSync(file, sh("git", ["show", `${sha}:mods/claude/peer2peer/bin/p2p.mjs`]));
  return { ref, sha, file };
}

async function startRelay() {
  const mod = await import(pathToFileURL(join(ROOT, "packages/relay/dist/index.js")).href);
  const crypto = mod.createRelayCrypto();
  const relay = new mod.Relay({
    config: mod.makeConfig(crypto, { relayUrl: RELAY_URL, logLevel: "error", powBits: 0 }),
    store: new mod.MemoryStore(),
    crypto,
    logger: mod.createLogger({ level: "error", sink: () => {} }),
  });
  const port = await relay.listen();
  return { relay, port, close: () => relay.close() };
}

/** One user on one CLI build: a temp home, and `run` for `p2p <args> --json`. */
class Peer {
  constructor(name, bin, port, label, extraEnv = {}) {
    this.name = name;
    this.bin = bin;
    this.label = label;
    this.home = mkdtempSync(join(tmpdir(), `p2p-matrix-${name}-`));
    // The person token (packages/p2p/src/projects.ts): these runs are the person's own (an older CLI ignores it).
    const token = randomBytes(32).toString("base64url");
    mkdirSync(join(this.home, "cli"), { recursive: true, mode: 0o700 });
    writeFileSync(join(this.home, "cli", "person.key"), token, { mode: 0o600 });
    this.env = {
      PATH: process.env.PATH ?? "",
      HOME: this.home,
      P2P_HOME: this.home,
      P2P_PERSON_TOKEN: token,
      P2P_RELAY_TRANSPORT: JSON.stringify({ [RELAY_URL]: `ws://127.0.0.1:${port}/v3` }),
      P2P_DRAIN_QUIET_MS: "250",
      P2P_DRAIN_MAX_MS: "4000",
      P2P_DOC_REFRESH_SEC: "0",
      P2P_CONNECT_TIMEOUT_MS: "3000",
      ...extraEnv,
    };
    this.stderr = [];
  }

  run(args, stdin) {
    return new Promise((done) => {
      const child = execFile(process.execPath, [this.bin, ...args, "--json"], { env: this.env, maxBuffer: 16 * 1024 * 1024, timeout: 60_000 }, (err, stdout, stderr) => {
        this.stderr.push(...String(stderr).split("\n").filter(Boolean).map((l) => `${this.name}: p2p ${args[0]}: ${l}`));
        let json;
        try {
          json = JSON.parse(String(stdout).trim().split("\n").at(-1) ?? "null");
        } catch {
          json = undefined;
        }
        done({ code: err ? (typeof err.code === "number" ? err.code : 1) : 0, json, stderr: String(stderr) });
      });
      if (stdin !== undefined) child.stdin.end(stdin);
      else child.stdin.end();
    });
  }

  async ok(args, stdin) {
    const r = await this.run(args, stdin);
    if (r.code !== 0) throw new Error(`${this.name} (${this.label}): p2p ${args.join(" ")} exited ${r.code}: ${JSON.stringify(r.json)} ${r.stderr.slice(-400)}`);
    return r.json;
  }

  /** The CLI's own state document `name` (events, peers): a test-only read of the home. */
  doc(name) {
    try {
      return JSON.parse(readFileSync(join(this.home, "cli", `${name}.json`), "utf8"));
    } catch {
      return undefined;
    }
  }

  writeDoc(name, value) {
    writeFileSync(join(this.home, "cli", `${name}.json`), JSON.stringify(value));
  }

  events(kind) {
    return (this.doc("events")?.items ?? []).filter((e) => e.kind === kind);
  }

  cleanup() {
    rmSync(this.home, { recursive: true, force: true });
  }
}

const sessKey = (own, sid) => `${own}|${sid}`;

/**
 * One direction: `a` (the one that invites, creates the circle and sends first) and `b`.
 * Returns the checks that ran, each {name, ok, detail}.
 */
async function scenario(a, b) {
  const checks = [];
  const check = async (name, fn) => {
    try {
      const detail = await fn();
      checks.push({ name, ok: true, ...(detail ? { detail } : {}) });
    } catch (e) {
      checks.push({ name, ok: false, detail: String(e.message ?? e).slice(0, 600) });
    }
  };
  const ids = {};
  await check("init", async () => {
    for (const p of [a, b]) ids[p.name] = (await p.ok(["init", "--name", p.name, "--relay", RELAY_URL, "--yes"])).userId;
  });
  await check("invite and accept (short code)", async () => {
    const inv = await a.ok(["invite"]);
    // A client with invite links takes the web link, after its yes (--confirmed); an older one the code.
    await b.ok(b.inviteLinks ? ["join", "--confirmed", inv.web ?? inv.code] : ["join", inv.code]);
    await a.ok(["friends"]);
    const fa = (await a.ok(["friends"])).friends.map((f) => f.userId);
    const fb = (await b.ok(["friends"])).friends.map((f) => f.userId);
    if (!fa.includes(ids[b.name]) || !fb.includes(ids[a.name])) throw new Error(`not friends both ways: ${JSON.stringify({ fa, fb })}`);
  });
  const caps = (p) => (p.receipts ? ["--cap", "receipts.v1"] : []);
  await check("statuses (each sees the other's live session)", async () => {
    // A build with project boundaries shares the project its sessions run in (this folder) first,
    // as its person would: until then they reach nobody.
    for (const [p, other] of [
      [a, b],
      [b, a],
    ]) {
      if (p.projects) await p.ok(["project", "share", "--add", "--person", ids[other.name]]);
    }
    await a.ok(["session", "roster", "sa", "--add", ids[b.name]]);
    await b.ok(["session", "roster", "sb", "--add", ids[a.name]]);
    await a.ok(["status", "--session", "sa", "--state", "idle", "--label", "sa", ...caps(a)]);
    await b.ok(["status", "--session", "sb", "--state", "idle", "--label", "sb", ...caps(b)]);
    const la = (await a.ok(["ls"])).peers.map((r) => r.sid);
    const lb = (await b.ok(["ls"])).peers.map((r) => r.sid);
    if (!la.includes("sb") || !lb.includes("sa")) throw new Error(`ls: ${JSON.stringify({ [a.name]: la, [b.name]: lb })}`);
  });
  await check("messages both ways", async () => {
    await a.ok(["send", "--from-session", "sa", "--to", `${ids[b.name]}/sb`, "--stdin"], `hello from ${a.label}`);
    await b.ok(["send", "--from-session", "sb", "--to", `${ids[a.name]}/sa`, "--stdin"], `hello from ${b.label}`);
    await a.ok(["ls"]);
    await b.ok(["ls"]);
    const ga = a.events("p2p.message").map((e) => e.data.text);
    const gb = b.events("p2p.message").map((e) => e.data.text);
    if (!gb.includes(`hello from ${a.label}`) || !ga.includes(`hello from ${b.label}`)) throw new Error(`got ${JSON.stringify({ [a.name]: ga, [b.name]: gb })}`);
  });
  await check("project boundaries: a session in an unshared project reaches nobody, an older peer included", async () => {
    const x = a.projects ? a : b.projects ? b : undefined;
    if (!x) return "neither side has project boundaries";
    const y = x === a ? b : a;
    const ySid = y === a ? "sa" : "sb";
    const dir = mkdtempSync(join(tmpdir(), "p2p-matrix-private-"));
    const saved = x.env;
    x.env = { ...saved, P2P_WORKDIR: dir };
    try {
      const st = await x.ok(["status", "--session", "priv", "--state", "busy", "--label", "priv", "--summary", "private work"]);
      if (st.delivered.length !== 0 || st.roster.vis !== "private") throw new Error(`a private project's status went out: ${JSON.stringify(st)}`);
      const out = await x.run(["send", "--from-session", "priv", "--to", `${ids[y.name]}/${ySid}`, "--stdin"], "smuggled");
      if (out.code === 0 || out.json?.error !== "not_shared") throw new Error(`a private session sent: ${JSON.stringify(out.json)}`);
    } finally {
      x.env = saved;
      rmSync(dir, { recursive: true, force: true });
    }
    const ls = (await y.ok(["ls", "--all"])).peers.map((r) => r.sid);
    if (ls.includes("priv")) throw new Error(`${y.label} sees the private session: ${JSON.stringify(ls)}`);
    if (y.events("p2p.message").some((e) => e.data.text === "smuggled")) throw new Error(`${y.label} got the private session's message`);
    return `${x.label} kept it from ${y.label}`;
  });
  await check("delivery receipts where both have them; left out cleanly where one doesn't", async () => {
    const r = await a.ok(["send", "--from-session", "sa", "--to", `${ids[b.name]}/sb`, "--stdin"], "with a receipt?");
    await b.ok(["ls"]);
    const ev = b.events("p2p.message").find((e) => e.data.text === "with a receipt?");
    if (!ev) throw new Error("the message didn't arrive");
    const both = a.receipts && b.receipts;
    if (!both) {
      if (r.receiptId || ev.data.receipt) throw new Error(`asked for a receipt from a client without them: ${JSON.stringify(r)}`);
      return `${!a.receipts ? a.label : b.label} has no receipts: none asked for, the message delivered`;
    }
    if (!r.receiptId || ev.data.receipt !== true) throw new Error(`no receipt asked for: ${JSON.stringify(r)}`);
    await b.ok(["receipt", ev.id, "--from-session", "sb", "--outcome", "shown"]);
    await a.ok(["ls"]);
    const got = a.events("p2p.receipt").filter((e) => e.data.receiptId === r.receiptId || e.data.id === r.receiptId);
    if (got.length !== 1 || got[0].data.outcome !== "shown") throw new Error(`receipts: ${JSON.stringify(got)}`);
    return "shown, end to end";
  });
  await check("circle: create, invite, join", async () => {
    const cid = (await a.ok(["circle", "create", "matrix"])).cid;
    await a.ok(["circle", "invite", cid, ids[b.name]]);
    const held = (await b.ok(["held"])).held.filter((h) => h.type === "circle-invite");
    if (held.length !== 1) throw new Error(`held: ${JSON.stringify(held)}`);
    const j = await b.ok(["held", "approve", held[0].id, "--wait", "3"]);
    if (j.status !== "joined") throw new Error(`join: ${JSON.stringify(j)}`);
    await a.ok(["circle", "ls"]);
    const m = await a.ok(["circle", "members", cid]);
    const row = m.members.find((x) => x.userId === ids[b.name]);
    if (!row?.stands) throw new Error(`members: ${JSON.stringify(m.members)}`);
  });
  await check("one code, several circles: a client before them joins the first, the others wait as circle invites", async () => {
    if (!a.inviteLinks) return `${a.label} makes codes for one circle only (covered above)`;
    const c1 = (await a.ok(["circle", "create", "first"])).cid;
    const c2 = (await a.ok(["circle", "create", "second"])).cid;
    const inv = await a.ok(["invite", "--circle", c1, "--circle", c2]);
    if (inv.circles?.length !== 2) throw new Error(`invite: ${JSON.stringify(inv.circles)}`);
    const j = await b.ok(b.inviteLinks ? ["join", "--confirmed", inv.web, "--wait", "0"] : ["join", inv.code, "--wait", "0"]);
    // The inviter's client adds b to both on the accept; b's next commands finish what it understands.
    await a.ok(["invites"]);
    await b.ok(["circle", "ls"]);
    await b.ok(["circle", "ls"]);
    const mine = (await b.ok(["circle", "ls"])).circles;
    const joined = (cid) => mine.some((c) => c.cid === cid && c.joined);
    if (!joined(c1)) throw new Error(`not in the first circle: ${JSON.stringify({ j, mine })}`);
    if (b.inviteLinks) {
      if (!joined(c2)) throw new Error(`not in the second circle: ${JSON.stringify(mine)}`);
      return "both joined";
    }
    const held = (await b.ok(["held"])).held.filter((h) => h.type === "circle-invite" && h.cid === c2);
    if (joined(c2) || held.length !== 1) throw new Error(`an older client: ${JSON.stringify({ mine, held })}`);
    return `${b.label} joined the first; the second waits for its approval`;
  });
  await check("offline queue (a session seen recently, not live)", async () => {
    const peers = a.doc("peers") ?? {};
    const k = sessKey(ids[b.name], "sb");
    if (!peers[k]) throw new Error("no record of the other's session");
    peers[k] = { ...peers[k], ts: Date.now() - 10 * 60_000 };
    a.writeDoc("peers", peers);
    const r = await a.ok(["send", "--from-session", "sa", "--to", `${ids[b.name]}/sb`, "--stdin"], "while you were away");
    if (!r.queued || r.state !== "offline") throw new Error(`send: ${JSON.stringify(r)}`);
    if (r.receiptId) throw new Error("a receipt asked of a session that isn't live");
    await b.ok(["ls"]);
    if (!b.events("p2p.message").some((e) => e.data.text === "while you were away")) throw new Error("not delivered");
  });
  await check("no envelope rejected on either side", async () => {
    const bad = [...a.stderr, ...b.stderr].filter((l) => /rejected an envelope|unknown field|malformed|unsupported-critical/.test(l));
    if (bad.length > 0) throw new Error(bad.slice(0, 5).join("\n"));
  });
  return checks;
}

/** Does this build have delivery receipts (`p2p receipt`)? */
function hasReceipts(bin) {
  return readFileSync(bin, "utf8").includes('command("receipt <event>")');
}

/** Does this build keep sessions within their project (`p2p project share`, projects.ts)? */
function hasProjects(bin) {
  return readFileSync(bin, "utf8").includes('command("share [circles...]")');
}

/** Does this build take invite links and codes for several circles (`p2p join --confirmed`)? */
function hasInviteLinks(bin) {
  return readFileSync(bin, "utf8").includes('"--confirmed"');
}

export async function runMatrix(opts = {}) {
  const refs = opts.refs ?? (process.env.P2P_COMPAT_REFS ? process.env.P2P_COMPAT_REFS.split(",").map((s) => s.trim()).filter(Boolean) : DEFAULT_REFS);
  const newBin = resolve(ROOT, opts.newBin ?? "mods/claude/peer2peer/bin/p2p.mjs");
  const cache = mkdtempSync(join(tmpdir(), "p2p-matrix-bins-"));
  const results = [];
  try {
    for (const ref of refs) {
      const old = bundleAt(ref, cache);
      for (const dir of ["new→old", "old→new"]) {
        const relay = await startRelay();
        const mk = (name, bin, label, env) => Object.assign(new Peer(name, bin, relay.port, label, env), { receipts: hasReceipts(bin), inviteLinks: hasInviteLinks(bin), projects: hasProjects(bin) });
        const nw = mk("nina", newBin, "new", opts.newEnv ?? {});
        const od = mk("otto", old.file, `old ${old.sha}`);
        const [a, b] = dir === "new→old" ? [nw, od] : [od, nw];
        try {
          const checks = await scenario(a, b);
          results.push({ ref: old.ref, sha: old.sha, direction: dir, checks, ok: checks.every((c) => c.ok) });
        } finally {
          await relay.close();
          nw.cleanup();
          od.cleanup();
        }
      }
    }
  } finally {
    rmSync(cache, { recursive: true, force: true });
  }
  return { ok: results.every((r) => r.ok), results };
}

function format(r) {
  const lines = [];
  for (const x of r.results) {
    lines.push(`${x.ok ? "✓" : "✗"} ${x.direction} (old = ${x.ref}, ${x.sha})`);
    for (const c of x.checks) lines.push(`    ${c.ok ? "✓" : "✗"} ${c.name}${c.detail ? `: ${c.detail}` : ""}`);
  }
  lines.push("", r.ok ? "compatibility matrix: every shared feature works both ways" : "compatibility matrix: FAILED");
  return lines.join("\n");
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const argv = process.argv.slice(2);
  const arg = (k) => {
    const i = argv.indexOf(k);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const newEnv = Object.fromEntries(argv.flatMap((a, i) => (a === "--new-env" && argv[i + 1]?.includes("=") ? [argv[i + 1].split(/=(.*)/s).slice(0, 2)] : [])));
  const r = await runMatrix({ ...(arg("--refs") ? { refs: arg("--refs").split(",") } : {}), ...(arg("--new") ? { newBin: arg("--new") } : {}), newEnv });
  console.log(argv.includes("--json") ? JSON.stringify(r, null, 2) : format(r));
  process.exit(r.ok ? 0 : 1);
}
