#!/usr/bin/env node
// Copyright 2026 Ix Infrastructure Inc.
//
// Cross-version matrix (docs/compatibility.md): this tree's CLI against earlier releases, both
// ways, over a local relay (this tree's), for every feature they share: invite and accept,
// statuses, direct messages, project boundaries, delivery receipts, extension envelopes and their
// fallback, a circle join, invite codes for several circles, a message between circle members who
// aren't friends, and the offline queue. It asserts that shared features work, that new-only
// features degrade cleanly (the newer side leaves them out), and that no side rejects an envelope.
//
//   node scripts/compat/matrix.mjs [--refs v0.2.0,v0.1.0] [--npm 0.1.0[,0.2.0]] [--new mods/claude/peer2peer/bin/p2p.mjs]
//                                  [--npm-releases] [--tarballs .release/tarballs] [--new-env K=V]... [--require-npm] [--json]
//
// Baselines (the "old" side), two kinds:
//   - git refs (`--refs`, P2P_COMPAT_REFS): the committed single-file bundle at that ref
//     (`git show <ref>:mods/claude/peer2peer/bin/p2p.mjs`) and the ext-ix copy committed beside it,
//     so nothing is built. The default is the previous two release tags (`v<x.y.z>` reachable from
//     HEAD, newest first, prereleases and a tag on HEAD itself left out), filled up with 70b86c7
//     (the initial public release) while fewer than two exist.
//   - npm versions (`--npm`, P2P_COMPAT_NPM): @peer2peer/cli at exactly that version, installed from
//     the registry the way users get it (`npm install --ignore-scripts` into a temp project, the
//     lockfile's integrity checked against the registry's), with @peer2peer/ext-ix of the same
//     version when it is published. A version that isn't published yet is skipped with a notice
//     (a failure with --require-npm). With --npm and no --refs, only the npm baselines run.
//     `--npm-releases` (P2P_COMPAT_NPM_RELEASES=1) adds, for each release tag among the git
//     baselines, that release as npm installs it: the default refs plus --npm-releases is "the
//     previous two releases, from git and from npm".
//     `--tarballs <dir>` installs from scripts/release-pack.mjs's tarballs instead (manifest.json),
//     to try the installed layout before a version is published.
//
// `--new-env` sets an environment variable for the new side only: `--new-env P2P_DEVICE_INFO=1` is
// step 2 of the device-info rollout, which must pass against every release it is meant to support.
// Needs packages/relay built. Every home is a fresh temp directory (P2P_HOME); nothing reads ~/.p2p
// or talks to a real relay (npm installs talk to the npm registry only).

import { execFile, execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const RELAY_URL = "wss://relay-matrix.test/v3";
/** The initial public release: the baseline until (and while fewer than) two release tags exist. */
export const INITIAL_REF = "70b86c7";
/** How many earlier releases every release must interoperate with (docs/compatibility.md "Policy"). */
export const SUPPORTED_RELEASES = 2;
const EXT_COPY = "mods/claude/peer2peer/ext/node_modules/@peer2peer/ext-ix";
const EXACT_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

function sh(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { cwd: ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, ...opts });
}

/**
 * The previous `n` release tags: `v<x.y.z>` tags reachable from HEAD, highest version first, without
 * prereleases or a tag on HEAD itself (a release run on its own tag tests against the ones before
 * it). Filled up with the initial public release while fewer than `n` exist.
 */
export function releaseRefs(n = SUPPORTED_RELEASES) {
  let tags = [];
  let head = "";
  try {
    head = sh("git", ["rev-parse", "HEAD"]).trim();
    tags = sh("git", ["tag", "--list", "v*", "--merged", "HEAD", "--sort=-v:refname"]).split("\n").map((t) => t.trim());
  } catch {
    tags = [];
  }
  const out = [];
  for (const t of tags) {
    if (!/^v\d+\.\d+\.\d+$/.test(t)) continue;
    if (sh("git", ["rev-parse", `${t}^{commit}`]).trim() === head) continue;
    out.push(t);
    if (out.length === n) return out;
  }
  // The initial public release predates tags; it counts while there are fewer than n of them.
  try {
    if (sh("git", ["rev-parse", `${INITIAL_REF}^{commit}`]).trim() !== head) out.push(INITIAL_REF);
  } catch {
    /* not in this history */
  }
  return out;
}

/** The default git baselines (computed, so `import { DEFAULT_REFS }` sees the current tags). */
export const DEFAULT_REFS = releaseRefs();

/** The committed CLI bundle at `ref`, and the ext-ix copy committed beside it, written to `dir`. */
/** A git ref as a baseline may name it: no option-like or shell-special spelling reaches git. */
const SAFE_REF = /^[A-Za-z0-9._/-]+$/;
export function checkRef(ref) {
  if (!SAFE_REF.test(ref) || ref.startsWith("-")) throw new Error(`not a git ref this matrix takes: ${JSON.stringify(ref)}`);
  return ref;
}

export function bundleAt(ref, dir) {
  checkRef(ref);
  const sha = sh("git", ["rev-parse", "--short=12", `${ref}^{commit}`]).trim();
  const file = join(dir, `p2p-${sha}.mjs`);
  if (!existsSync(file)) writeFileSync(file, sh("git", ["show", `${sha}:mods/claude/peer2peer/bin/p2p.mjs`]));
  let extPath;
  try {
    const ext = join(dir, `ext-${sha}`, "node_modules/@peer2peer/ext-ix");
    if (!existsSync(join(ext, "index.mjs"))) {
      const index = sh("git", ["show", `${sha}:${EXT_COPY}/index.mjs`], { stdio: ["ignore", "pipe", "ignore"] });
      const pkg = sh("git", ["show", `${sha}:${EXT_COPY}/package.json`], { stdio: ["ignore", "pipe", "ignore"] });
      mkdirSync(ext, { recursive: true });
      writeFileSync(join(ext, "index.mjs"), index);
      writeFileSync(join(ext, "package.json"), pkg);
    }
    extPath = join(dir, `ext-${sha}`);
  } catch {
    extPath = undefined; // no ext-ix copy at that ref
  }
  return { kind: "ref", ref, sha, label: `old ${sha}`, file, extPath, source: readFileSync(file, "utf8") };
}

/** Every .js file under a package's dist, concatenated: what the feature probes read for an installed CLI. */
function distText(pkgDir) {
  const parts = [];
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      if (e.isDirectory()) {
        if (e.name !== "__tests__") walk(join(d, e.name));
      } else if (e.name.endsWith(".js")) parts.push(readFileSync(join(d, e.name), "utf8"));
    }
  };
  walk(join(pkgDir, "dist"));
  return parts.join("\n");
}

function npm(args, cwd) {
  return execFileSync("npm", args, { cwd, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, NPM_CONFIG_UPDATE_NOTIFIER: "false" } });
}

/** `npm view <name>@<version> dist.integrity` and its publish time, or undefined when that version isn't published. */
function registryIntegrity(name, version) {
  try {
    const out = npm(["view", `${name}@${version}`, "dist.integrity", "time", "--json"], tmpdir()).trim();
    if (!out) return undefined;
    const v = JSON.parse(out);
    const integrity = v["dist.integrity"];
    const published = v.time?.[version];
    if (typeof integrity !== "string" || typeof published !== "string") throw new Error(`no integrity or publish time in ${out.slice(0, 200)}`);
    return { integrity, published };
  } catch (e) {
    if (!("stderr" in e)) throw e;
    const err = String(e.stderr ?? e.message ?? e);
    if (/E404|404 Not Found|is not in this registry|No match found/.test(err)) return undefined;
    throw new Error(`npm view ${name}@${version}: ${err.slice(-400)}`);
  }
}

/**
 * @peer2peer/cli@<version> (and @peer2peer/ext-ix@<version> when published) installed into a fresh
 * project under `dir`, as a user installs it: exact versions, `--ignore-scripts`, and `--before` the
 * later of the two packages' publish times (so a ranged transitive dependency resolves to what existed
 * when the release shipped, never to something published since). The lockfile's integrity for each is
 * checked against the registry's, and `npm audit signatures` checks every installed package's registry
 * signature and provenance attestation where it has one. Returns undefined when the CLI isn't published.
 */
export function installFromNpm(version, dir) {
  if (!EXACT_VERSION.test(version)) throw new Error(`--npm takes exact versions (like 0.1.0), not ${JSON.stringify(version)}`);
  const want = { "@peer2peer/cli": registryIntegrity("@peer2peer/cli", version) };
  if (!want["@peer2peer/cli"]) return undefined;
  const ext = registryIntegrity("@peer2peer/ext-ix", version);
  if (ext) want["@peer2peer/ext-ix"] = ext;
  const proj = join(dir, `npm-${version}`);
  mkdirSync(proj, { recursive: true });
  writeFileSync(join(proj, "package.json"), JSON.stringify({ name: "p2p-matrix-baseline", private: true, version: "0.0.0" }));
  const before = new Date(Math.max(...Object.values(want).map((w) => Date.parse(w.published))) + 1000).toISOString();
  npm(["install", "--ignore-scripts", "--no-audit", "--no-fund", "--save-exact", `--before=${before}`, ...Object.keys(want).map((n) => `${n}@${version}`)], proj);
  try {
    npm(["audit", "signatures"], proj);
  } catch (e) {
    throw new Error(`npm audit signatures failed for ${version}: ${String(e.stdout ?? "").slice(-400)} ${String(e.stderr ?? e.message ?? e).slice(-400)}`);
  }
  const lock = JSON.parse(readFileSync(join(proj, "package-lock.json"), "utf8"));
  for (const [name, { integrity }] of Object.entries(want)) {
    const got = lock.packages?.[`node_modules/${name}`];
    if (got?.version !== version) throw new Error(`${name}: installed ${got?.version}, not ${version}`);
    if (got.integrity !== integrity) throw new Error(`${name}@${version}: the lockfile's integrity ${got.integrity} is not the registry's ${integrity}`);
  }
  return installed(proj, `npm ${version}`, { kind: "npm", ref: `npm:${version}`, sha: `npm@${version}` });
}

/** scripts/release-pack.mjs's tarballs (`<dir>/manifest.json`) installed the same way, before they are published. */
export function installFromTarballs(tarDir, dir) {
  const m = JSON.parse(readFileSync(join(tarDir, "manifest.json"), "utf8"));
  const proj = join(dir, `tarballs-${m.version}`);
  mkdirSync(proj, { recursive: true });
  writeFileSync(join(proj, "package.json"), JSON.stringify({ name: "p2p-matrix-baseline", private: true, version: "0.0.0" }));
  // Every package's tarball, so the CLI's pinned internal dependencies resolve to them, not the registry.
  npm(["install", "--ignore-scripts", "--no-audit", "--no-fund", ...m.publishOrder.map((p) => resolve(tarDir, p.tarball))], proj);
  return installed(proj, `tarballs ${m.version}`, { kind: "tarballs", ref: `tarballs:${m.version}`, sha: `tarballs@${m.version}` });
}

function installed(proj, label, extra) {
  const pkgDir = join(proj, "node_modules/@peer2peer/cli");
  const bin = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8")).bin?.p2p;
  if (!bin) throw new Error(`${label}: @peer2peer/cli has no p2p bin`);
  // ext-ix, when installed, is found as the CLI's sibling (extensions.ts siblingNodeModules): no P2P_EXTENSION_PATH.
  const hasExt = existsSync(join(proj, "node_modules/@peer2peer/ext-ix/package.json"));
  return { ...extra, label: `old ${label}`, file: join(pkgDir, bin), extPath: hasExt ? "" : undefined, source: distText(pkgDir) };
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
      // The person token is read again on every run: a current CLI replaces person.key when an identity is created here.
      const env = { ...this.env, P2P_PERSON_TOKEN: readFileSync(join(this.home, "cli", "person.key"), "utf8").trim() };
      const child = execFile(process.execPath, [this.bin, ...args, "--json"], { cwd: this.home, env, maxBuffer: 16 * 1024 * 1024, timeout: 60_000 }, (err, stdout, stderr) => {
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
async function scenario(a, b, spawn) {
  const checks = [];
  const extras = [];
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
  await check("extension envelopes: rendered where the receiver has the extension, the plain fallback where it doesn't", async () => {
    // x sends an x:ix.note to y. In the first pass the receiver has no extension enabled, so it must
    // show the fallback (and keep nothing); in the second the receiver enabled it in its own turn.
    const notes = [];
    for (const [x, y, xs, ys] of [
      [a, b, "sa", "sb"],
      [b, a, "sb", "sa"],
    ]) {
      if (x.ext === undefined) {
        notes.push(`${x.label} ships no ext-ix: nothing to send`);
        continue;
      }
      await x.ok(["extensions", "enable", "ix"]);
      x.extEnabled = true;
      const before = y.events("p2p.ext").length;
      const sent = await x.ok(["ix", "note", "--from-session", xs, "--to", `${ids[y.name]}/${ys}`, "--without-repo", "--stdin"], `an Ix note from ${x.label}`);
      await y.ok(["ls"]);
      const got = y.events("p2p.ext").slice(before).filter((e) => e.data.ext === "x:ix.note");
      if (got.length !== 1) throw new Error(`${y.label} got ${got.length} x:ix.note items (sent: ${JSON.stringify(sent).slice(0, 300)})`);
      const ev = got[0].data;
      if (typeof ev.fallback !== "string" || ev.fallback === "") throw new Error(`no fallback line: ${JSON.stringify(ev).slice(0, 300)}`);
      if (y.extEnabled) {
        if (!ev.rendered) throw new Error(`${y.label} has ext-ix enabled but didn't render it: ${JSON.stringify(ev).slice(0, 300)}`);
        notes.push(`${x.label} → ${y.label}: rendered`);
      } else {
        if (ev.rendered || ev._kept) throw new Error(`${y.label} has no extension enabled but interpreted the body: ${JSON.stringify(ev).slice(0, 300)}`);
        notes.push(`${x.label} → ${y.label}: fallback`);
      }
    }
    return notes.join("; ");
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
  await check("circle message: members who aren't friends see each other's sessions and message both ways", async () => {
    // carl runs b's build and meets a only through an open circle a created: no invite code, no friendship.
    const c = spawn("carl", b);
    extras.push(c);
    ids.carl = (await c.ok(["init", "--name", "carl", "--relay", RELAY_URL, "--yes"])).userId;
    const made = await a.ok(["circle", "create", "members", "--open"]);
    if (!made.link) throw new Error(`no link for an open circle: ${JSON.stringify(made)}`);
    // The joiner asks the owner for the circle's history, and the owner's client answers when it
    // next runs (these CLIs aren't daemons): ask, let the owner answer, then join again.
    let j = await c.ok(["circle", "join", made.link, "--yes", "--wait", "0"]);
    for (let i = 0; i < 4 && j.status !== "joined"; i++) {
      await a.ok(["circle", "ls"]);
      j = await c.ok(["circle", "join", made.link, "--yes", "--wait", "3"]);
    }
    if (j.status !== "joined") throw new Error(`carl's join: ${JSON.stringify(j)}`);
    const stands = async (p, who) => ((await p.ok(["circle", "members", made.cid])).members ?? []).some((m) => m.userId === ids[who] && m.stands);
    let both = false;
    for (let i = 0; i < 4 && !both; i++) {
      await a.ok(["circle", "ls"]);
      await c.ok(["circle", "ls"]);
      both = (await stands(a, "carl")) && (await stands(c, a.name));
    }
    if (!both) throw new Error("carl doesn't stand in the circle on both sides");
    if ((await a.ok(["friends"])).friends.some((f) => f.userId === ids.carl)) throw new Error("a and carl are friends: this would test nothing new");
    for (const [p, sid] of [
      [a, "ca"],
      [c, "cc"],
    ]) {
      if (p.projects) await p.ok(["project", "share", "--add", made.cid]);
      await p.ok(["session", "roster", sid, "--circle", made.cid]);
      await p.ok(["status", "--session", sid, "--state", "idle", "--label", sid]);
    }
    const sees = async (p, sid) => (await p.ok(["ls"])).peers.some((r) => r.sid === sid);
    if (!(await sees(a, "cc")) || !(await sees(c, "ca"))) throw new Error("the circle sessions don't see each other");
    await a.ok(["send", "--from-session", "ca", "--to", `${ids.carl}/cc`, "--stdin"], `circle hello from ${a.label}`);
    await c.ok(["send", "--from-session", "cc", "--to", `${ids[a.name]}/ca`, "--stdin"], `circle hello from ${c.label}`);
    await a.ok(["ls"]);
    await c.ok(["ls"]);
    const ga = a.events("p2p.message").map((e) => e.data.text);
    const gc = c.events("p2p.message").map((e) => e.data.text);
    if (!gc.includes(`circle hello from ${a.label}`) || !ga.includes(`circle hello from ${c.label}`)) throw new Error(`got ${JSON.stringify({ [a.name]: ga, carl: gc })}`);
    return `${a.label} ↔ ${c.label}`;
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
    const bad = [...a.stderr, ...b.stderr, ...extras.flatMap((p) => p.stderr)].filter((l) => /rejected an envelope|unknown field|malformed|unsupported-critical/.test(l));
    if (bad.length > 0) throw new Error(bad.slice(0, 5).join("\n"));
  });
  for (const p of extras) p.cleanup();
  return checks;
}

// Feature probes, over a build's source text (the single-file bundle, or an installed package's dist).
/** Does this build have delivery receipts (`p2p receipt`)? */
const hasReceipts = (src) => src.includes('command("receipt <event>")');
/** Does this build keep sessions within their project (`p2p project share`, projects.ts)? */
const hasProjects = (src) => src.includes('command("share [circles...]")');
/** Does this build take invite links and codes for several circles (`p2p join --confirmed`)? */
const hasInviteLinks = (src) => src.includes('"--confirmed"');

const list = (v) => (v ?? "").split(",").map((s) => s.trim()).filter(Boolean);

/**
 * The baselines a run tests against: git refs and npm versions. Explicit options win, then
 * P2P_COMPAT_REFS / P2P_COMPAT_NPM; with neither, the previous release tags (DEFAULT_REFS).
 */
export function baselinesOf(opts = {}, env = process.env) {
  const npmVersions = opts.npm ?? list(env.P2P_COMPAT_NPM);
  const refs = opts.refs ?? (list(env.P2P_COMPAT_REFS).length ? list(env.P2P_COMPAT_REFS) : npmVersions.length || opts.tarballs ? [] : releaseRefs());
  // --npm-releases: each release tag among the refs is also tested as npm installs it.
  const fromTags = opts.npmReleases || env.P2P_COMPAT_NPM_RELEASES === "1" ? refs.filter((r) => /^v\d+\.\d+\.\d+$/.test(r)).map((r) => r.slice(1)) : [];
  return { refs, npm: [...new Set([...npmVersions, ...fromTags])], tarballs: opts.tarballs };
}

export async function runMatrix(opts = {}) {
  const base = baselinesOf(opts);
  const newBin = resolve(ROOT, opts.newBin ?? "mods/claude/peer2peer/bin/p2p.mjs");
  const newSrc = readFileSync(newBin, "utf8");
  // This tree's ext-ix copy, when the new CLI is this tree's bundle.
  const newExt = existsSync(resolve(ROOT, EXT_COPY, "index.mjs")) ? resolve(ROOT, "mods/claude/peer2peer/ext") : undefined;
  const cache = mkdtempSync(join(tmpdir(), "p2p-matrix-bins-"));
  const results = [];
  const skipped = [];
  try {
    const olds = [];
    for (const ref of base.refs) checkRef(ref);
    for (const ref of base.refs) olds.push(bundleAt(ref, cache));
    for (const v of base.npm) {
      const o = installFromNpm(v, cache);
      if (o) olds.push(o);
      else skipped.push({ ref: `npm:${v}`, reason: `@peer2peer/cli@${v} is not published on npm (yet): skipped` });
    }
    if (base.tarballs) olds.push(installFromTarballs(resolve(base.tarballs), cache));
    for (const old of olds) {
      for (const dir of ["new→old", "old→new"]) {
        const relay = await startRelay();
        const mk = (name, side) => {
          const env = { ...side.env, ...(side.extPath ? { P2P_EXTENSION_PATH: side.extPath } : {}) };
          return Object.assign(new Peer(name, side.bin, relay.port, side.label, env), { side, ext: side.extPath, receipts: hasReceipts(side.src), inviteLinks: hasInviteLinks(side.src), projects: hasProjects(side.src) });
        };
        const newSide = { bin: newBin, src: newSrc, label: "new", extPath: newExt, env: opts.newEnv ?? {} };
        const oldSide = { bin: old.file, src: old.source, label: old.label, extPath: old.extPath, env: {} };
        const nw = mk("nina", newSide);
        const od = mk("otto", oldSide);
        const [a, b] = dir === "new→old" ? [nw, od] : [od, nw];
        try {
          const checks = await scenario(a, b, (name, like) => mk(name, like.side));
          results.push({ ref: old.ref, sha: old.sha, kind: old.kind, direction: dir, checks, ok: checks.every((c) => c.ok) });
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
  const missing = opts.requireNpm && skipped.length > 0;
  return { ok: results.length > 0 && results.every((r) => r.ok) && !missing, results, skipped };
}

function format(r) {
  const lines = [];
  for (const x of r.results) {
    lines.push(`${x.ok ? "✓" : "✗"} ${x.direction} (old = ${x.ref}${x.ref === x.sha ? "" : `, ${x.sha}`})`);
    for (const c of x.checks) lines.push(`    ${c.ok ? "✓" : "✗"} ${c.name}${c.detail ? `: ${c.detail}` : ""}`);
  }
  for (const s of r.skipped) lines.push(`- ${s.ref}: ${s.reason}`);
  if (r.results.length === 0) lines.push("", "compatibility matrix: nothing to test against");
  else lines.push("", r.ok ? "compatibility matrix: every shared feature works both ways" : "compatibility matrix: FAILED");
  return lines.join("\n");
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const argv = process.argv.slice(2);
  const arg = (k) => {
    const i = argv.indexOf(k);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const newEnv = Object.fromEntries(argv.flatMap((a, i) => (a === "--new-env" && argv[i + 1]?.includes("=") ? [argv[i + 1].split(/=(.*)/s).slice(0, 2)] : [])));
  const r = await runMatrix({
    ...(arg("--refs") !== undefined ? { refs: list(arg("--refs")) } : {}),
    ...(arg("--npm") !== undefined ? { npm: list(arg("--npm")) } : {}),
    ...(arg("--tarballs") ? { tarballs: arg("--tarballs") } : {}),
    ...(arg("--new") ? { newBin: arg("--new") } : {}),
    requireNpm: argv.includes("--require-npm"),
    npmReleases: argv.includes("--npm-releases"),
    newEnv,
  });
  console.log(argv.includes("--json") ? JSON.stringify(r, null, 2) : format(r));
  // Nothing to test against (every npm version unpublished) is a clean skip, unless --require-npm.
  process.exit(r.ok || (r.results.length === 0 && !argv.includes("--require-npm")) ? 0 : 1);
}
