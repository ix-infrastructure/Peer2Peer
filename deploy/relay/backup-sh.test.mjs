// Copyright 2026 Ix Infrastructure Inc.
//
// backup.sh's own logic, without Docker: a fake `docker` on PATH runs the
// container's node command on this machine (the mounts mapped onto temporary
// directories) and logs its arguments. Checked: it refuses root and bad
// settings, budgets free space for the copy plus the WAL growth over the whole
// timeout plus headroom, derives the timeout from the database size, throttles
// the container, hands backup.mjs its deadline, validates the path before
// POST_BACKUP, and bounds POST_BACKUP with its own timeout.
//
//   node --test deploy/relay/backup-sh.test.mjs
//
// GNU `timeout` and `flock` are shimmed where the host has none (macOS); the
// lock test runs only with a real flock.

import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const work = mkdtempSync(join(tmpdir(), "p2p-backup-sh-test-"));
const recipe = join(work, "recipe"); // a copy of deploy/relay's two scripts: backups/ and the lock land here
const vol = join(work, "volume"); // the relay-data volume
const shims = join(work, "bin");
const rootShims = join(work, "bin-root");
const dockerLog = join(work, "docker.log");
const has = (cmd) => spawnSync("sh", ["-c", `command -v ${cmd}`]).status === 0;
const realFlock = has("flock");

const FAKE_DOCKER = `#!${process.execPath}
const { appendFileSync } = require("node:fs");
const { spawnSync } = require("node:child_process");
const args = process.argv.slice(2);
appendFileSync(process.env.FAKE_DOCKER_LOG, JSON.stringify(args) + "\\n");
if (args[0] === "volume") { console.log("p2p-relay_relay-data"); process.exit(0); }
if (args[0] === "rm") process.exit(0);
if (args[0] !== "run") process.exit(2);
const valued = new Set(["--name", "--network", "--security-opt", "--memory", "--pids-limit", "--user", "--group-add", "-v", "--entrypoint", "--cpus", "--cap-drop", "--device-read-bps", "--device-write-bps"]);
const mounts = [];
let i = 1;
for (; i < args.length && args[i].startsWith("-"); i++) {
  if (!valued.has(args[i])) continue;
  if (args[i] === "-v") {
    const [src, dst] = args[i + 1].split(":");
    mounts.push({ src: src === "p2p-relay_relay-data" ? process.env.FAKE_VOL_DIR : src, dst });
  }
  i++;
}
const cmd = args.slice(i + 1); // after the image
mounts.sort((a, b) => b.dst.length - a.dst.length);
const toHost = (a) => {
  for (const m of mounts) {
    if (a === m.dst || a.startsWith(m.dst + "/")) return m.src + a.slice(m.dst.length);
    a = a.split('"' + m.dst + '/').join('"' + m.src + '/');
  }
  return a;
};
if (cmd[0] === "-e" && process.env.FAKE_DB_BYTES) { console.log(process.env.FAKE_DB_BYTES); process.exit(0); }
if (cmd[0] === "/backup.mjs" && process.env.FAKE_BACKUP_OUT) { console.log(process.env.FAKE_BACKUP_OUT); process.exit(0); }
const r = spawnSync(process.execPath, cmd.map(toHost), { stdio: ["ignore", "pipe", "inherit"], encoding: "utf8" });
let out = r.stdout;
for (const m of mounts) out = out.split(m.src + "/").join(m.dst + "/");
process.stdout.write(out);
process.exit(r.status ?? 1);
`;

// GNU timeout's interface, as backup.sh uses it: [--kill-after=D] DURATION CMD...; 124 on a timeout.
const FAKE_TIMEOUT = `#!${process.execPath}
const { spawn } = require("node:child_process");
let a = process.argv.slice(2);
while (a[0].startsWith("--")) a = a.slice(1);
const secs = parseFloat(a[0]);
const c = spawn(a[1], a.slice(2), { stdio: "inherit" });
let timedOut = false;
const t = setTimeout(() => { timedOut = true; c.kill("SIGTERM"); }, secs * 1000);
c.on("exit", (code, sig) => { clearTimeout(t); process.exit(timedOut ? 124 : code ?? 128); });
`;

function setup() {
  rmSync(work, { recursive: true, force: true });
  for (const d of [recipe, vol, shims, rootShims]) mkdirSync(d, { recursive: true });
  copyFileSync(join(here, "backup.sh"), join(recipe, "backup.sh"));
  copyFileSync(join(here, "backup.mjs"), join(recipe, "backup.mjs"));
  chmodSync(join(recipe, "backup.sh"), 0o755);
  const shim = (dir, name, body) => {
    writeFileSync(join(dir, name), body);
    chmodSync(join(dir, name), 0o755);
  };
  shim(shims, "docker", FAKE_DOCKER);
  if (!has("timeout")) shim(shims, "timeout", FAKE_TIMEOUT);
  if (!realFlock) shim(shims, "flock", "#!/bin/sh\nexit 0\n");
  shim(rootShims, "id", `#!/bin/sh\nif [ "$1" = "-u" ]; then echo 0; else exec /usr/bin/id "$@"; fi\n`);
  const db = new DatabaseSync(join(vol, "relay.db"));
  db.exec("PRAGMA journal_mode = WAL; CREATE TABLE t (x BLOB); INSERT INTO t VALUES (randomblob(100000))");
  db.close();
}

/** Runs backup.sh with a clean environment plus `env`. */
function run(env = {}, { root = false } = {}) {
  return new Promise((resolve) => {
    const PATH = [...(root ? [rootShims] : []), shims, process.env.PATH].join(":");
    const c = spawn("bash", [join(recipe, "backup.sh")], {
      cwd: work,
      env: { PATH, HOME: work, FAKE_DOCKER_LOG: dockerLog, FAKE_VOL_DIR: vol, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    c.stdout.on("data", (d) => (stdout += d));
    c.stderr.on("data", (d) => (stderr += d));
    c.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

const runs = () =>
  readFileSync(dockerLog, "utf8")
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l))
    .filter((a) => a[0] === "run");
const backups = () => readdirSync(join(recipe, "backups")).filter((f) => /^relay-.*\.db$/.test(f));

beforeEach(setup);
after(() => rmSync(work, { recursive: true, force: true }));

test("a backup: throttled container, deadline handed on, POST_BACKUP gets the validated path, no marker left", async () => {
  const r = await run({ KEEP: "1", POST_BACKUP: 'printf "%s" "$1" > "$HOME/post.out"' });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(backups().length, 1);
  assert.equal(readFileSync(join(work, "post.out"), "utf8"), `backups/${backups()[0]}`);
  assert.equal(existsSync(join(vol, "relay.db-backup")), false, "backup.mjs removes its marker");
  const last = runs().at(-1);
  assert.ok(last.join(" ").includes("--cpus 0.5"), last.join(" "));
  // A small database: the timeout's floor, 120 s, is also backup.mjs's deadline.
  assert.deepEqual(last.slice(-5), ["/backup.mjs", "/data/relay.db", "/backup", "1", "120"]);
  assert.match(r.stderr, /timeout 120s/);
});

test("refuses to run as root", async () => {
  const r = await run({}, { root: true });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /refusing to run as root/);
  assert.equal(existsSync(dockerLog), false, "nothing ran");
});

test("refuses bad settings", async () => {
  for (const env of [{ BACKUP_TIMEOUT: "abc" }, { BACKUP_TIMEOUT: "0" }, { KEEP: "-1" }, { BACKUP_CPUS: "1;id" }, { POST_BACKUP_TIMEOUT: "x" }, { BACKUP_IO_BPS: "30mb", BACKUP_IO_DEVICE: "/nonexistent" }]) {
    const r = await run(env);
    assert.equal(r.status, 1, JSON.stringify(env));
  }
});

test("BACKUP_HEADROOM_MB is checked before any arithmetic, and BACKUP_IO_BPS takes only a rate (review L7)", async () => {
  // bash evaluates $(( )) operands as expressions: a[$(cmd)] would run cmd.
  for (const v of ["a[$(touch $HOME/pwned)]", "1+1", "x", "0", "-5", "1e3"]) {
    const r = await run({ BACKUP_HEADROOM_MB: v });
    assert.equal(r.status, 1, v);
    assert.match(r.stderr, /BACKUP_HEADROOM_MB must be a positive integer/, v);
    assert.equal(existsSync(join(work, "pwned")), false, v);
  }
  assert.equal(existsSync(dockerLog), false, "nothing ran");
  for (const v of ["30mbx", "0", "030mb", "30 mb", "30mb;id", "1tb", "mb", "30kbb", "1234567890123"]) {
    const r = await run({ BACKUP_IO_BPS: v, BACKUP_IO_DEVICE: "/dev/null" });
    assert.equal(r.status, 1, v);
    assert.match(r.stderr, /BACKUP_IO_BPS must be a rate/, v);
  }
  // A good rate gets as far as the device check (no block device here).
  for (const v of ["30mb", "512k", "1G", "1048576"]) {
    const r = await run({ BACKUP_IO_BPS: v, BACKUP_IO_DEVICE: "/nonexistent" });
    assert.match(r.stderr, /BACKUP_IO_DEVICE must be a block device/, v);
  }
});

test("the timeout follows the database size, and free space covers the copy, the WAL growth over that timeout, and headroom", async () => {
  // 3 GiB at 40 MiB/s: 77 s to copy, so a 214 s timeout; 16 MiB/s of WAL over 214 s is 3424 MiB.
  const r = await run({ FAKE_DB_BYTES: String(3 * 1024 ** 3), BACKUP_HEADROOM_MB: "100000000" });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /not enough free disk for a backup: need \d+ MiB \(copy 3072, WAL growth 3424 over 214s, headroom 100000000\)/);
  assert.equal(backups().length, 0);
  // An explicit BACKUP_TIMEOUT wins, and sizes the WAL budget.
  const r2 = await run({ FAKE_DB_BYTES: String(3 * 1024 ** 3), BACKUP_HEADROOM_MB: "100000000", BACKUP_TIMEOUT: "100" });
  assert.match(r2.stderr, /WAL growth 1600 over 100s/);
});

test("an unexpected output path is never handed to POST_BACKUP", async () => {
  for (const out of ["/backup/../../etc/passwd", "/etc/passwd", "/backup/relay-20260101T000000Z.db"]) {
    const r = await run({ FAKE_BACKUP_OUT: out, POST_BACKUP: 'touch "$HOME/post.ran"' });
    assert.equal(r.status, 1, out);
    assert.match(r.stderr, /unexpected output path/);
    assert.equal(existsSync(join(work, "post.ran")), false, out);
  }
});

test("POST_BACKUP is bounded by POST_BACKUP_TIMEOUT, and the backup stays", async () => {
  const t0 = Date.now();
  const r = await run({ POST_BACKUP: "sleep 30", POST_BACKUP_TIMEOUT: "1" });
  assert.equal(r.status, 124, r.stderr);
  assert.match(r.stderr, /POST_BACKUP failed \(exit 124/);
  assert.ok(Date.now() - t0 < 20_000);
  assert.equal(backups().length, 1);
});

test("one backup at a time", { skip: realFlock ? false : "no flock(1) on this host" }, async () => {
  mkdirSync(join(recipe, "backups"), { recursive: true });
  const holder = spawn("flock", [join(recipe, ".backup.lock"), "sleep", "10"], { stdio: "ignore" });
  await new Promise((r) => setTimeout(r, 300));
  try {
    const r = await run();
    assert.equal(r.status, 1);
    assert.match(r.stderr, /another backup is running/);
  } finally {
    holder.kill("SIGKILL");
  }
});
