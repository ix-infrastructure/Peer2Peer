// Copyright 2026 Ix Infrastructure Inc.
//
// The relay install scripts, without installing anything: shellcheck and
// PSScriptAnalyzer, plus --dry-run / -DryRun plans with faked detection
// (P2P_DETECT_* environment variables), and the checksum file.
//
//   node --test scripts/install-relay.test.mjs
//
// shellcheck, pwsh and the PSScriptAnalyzer module are optional locally (those
// tests skip, saying why); with P2P_REQUIRE_INSTALLER_TOOLS=1 (CI) they must
// be present.

import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { checksums, SUMS_FILE } from "./install-relay-checksums.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repo = dirname(here);
const SH = join(here, "install-relay.sh");
const PS1 = join(here, "install-relay.ps1");
const strict = process.env.P2P_REQUIRE_INSTALLER_TOOLS === "1";
const has = (cmd) => spawnSync("sh", ["-c", `command -v ${cmd}`]).status === 0;
const elsewhere = mkdtempSync(join(tmpdir(), "p2p-install-relay-test-"));
after(() => rmSync(elsewhere, { recursive: true, force: true }));

function tool(cmd, t) {
  if (has(cmd)) return true;
  if (strict) assert.fail(`${cmd} is required (P2P_REQUIRE_INSTALLER_TOOLS=1)`);
  t.skip(`${cmd} is not installed`);
  return false;
}

// A Jetson Nano 2GB on JetPack 4: Docker 20.10, glibc 2.27, root on the SD card.
const JETSON = {
  P2P_DETECT_OS: "Linux",
  P2P_DETECT_ARCH: "aarch64",
  P2P_DETECT_MEM_MB: "1980",
  P2P_DETECT_KERNEL: "4.9.337-tegra",
  P2P_DETECT_GLIBC: "2.27",
  P2P_DETECT_DOCKER: "20.10.21",
  P2P_DETECT_BUILDX: "no",
  P2P_DETECT_NODE: "",
  P2P_DETECT_SYSTEMD: "yes",
  P2P_DETECT_DATA_DEVICE: "/dev/mmcblk0p1",
  P2P_DETECT_UID: "1000",
};

function sh(args, env = {}, opts = {}) {
  const r = spawnSync("sh", [SH, ...args], {
    cwd: opts.cwd ?? repo,
    env: { PATH: process.env.PATH, HOME: process.env.HOME, ...env },
    encoding: "utf8",
    input: opts.input,
  });
  return { code: r.status, out: r.stdout, err: r.stderr, all: r.stdout + r.stderr };
}

const URL = ["--url", "wss://relay.example.org/v3"];

// ---- install-relay.sh -----------------------------------------------------

test("install-relay.sh is shellcheck-clean as POSIX sh", (t) => {
  if (!tool("shellcheck", t)) return;
  const r = spawnSync("shellcheck", ["-s", "sh", SH], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});

test("install-relay.sh parses under every available POSIX shell", () => {
  for (const shell of ["sh", "dash", "bash", "busybox"].filter(has)) {
    const args = shell === "busybox" ? ["sh", "-n", SH] : ["-n", SH];
    const r = spawnSync(shell, args, { encoding: "utf8" });
    assert.equal(r.status, 0, `${shell}: ${r.stderr}`);
  }
});

test("a 2 GB board with Docker gets the small preset, a 768m cap and the hardening flags; SD card warned", () => {
  const r = sh(["--dry-run", ...URL], JETSON);
  assert.equal(r.code, 0, r.all);
  assert.match(r.out, /dry run: nothing will be changed/);
  assert.match(r.out, /detected: os=Linux arch=aarch64 ram=1980MB kernel=4\.9\.337-tegra glibc=2\.27 docker=20\.10\.21 buildx=no node=none/);
  assert.match(r.out, /plan: Docker 20\.10\.21, preset small, memory cap 768m, heap 384 MiB/);
  assert.match(r.out, /^\+ DOCKER_BUILDKIT=1 docker build -f \S+\/packages\/relay\/Dockerfile -t peer2peer\/relay:local /m);
  const run = r.out.split("\n").find((l) => l.startsWith("+ docker run"));
  assert.ok(run, r.out);
  for (const flag of [
    "--restart unless-stopped",
    "-p 127.0.0.1:8080:8080",
    "--mount type=volume,source=p2p-relay-data,target=/data",
    "-e RELAY_URL=wss://relay.example.org/v3",
    "-e RELAY_PRESET=small",
    "-e 'NODE_OPTIONS=--disable-warning=ExperimentalWarning --max-old-space-size=384'",
    "--memory 768m --memory-swap 768m",
    "--pids-limit 128",
    "--read-only",
    "--cap-drop ALL",
    "--security-opt no-new-privileges",
  ]) {
    assert.ok(run.includes(flag), `missing ${flag} in: ${run}`);
  }
  assert.match(r.err, /\/dev\/mmcblk0p1, an SD card or eMMC/);
  assert.match(r.out, /Give teammates this relay URL: wss:\/\/relay\.example\.org\/v3/);
  assert.doesNotMatch(r.all, /sudo/);
});

test("sizing follows RAM, and --preset and --port override it", () => {
  const tiny = sh(["--dry-run", ...URL], { ...JETSON, P2P_DETECT_MEM_MB: "1024" });
  assert.match(tiny.out, /preset small, memory cap 512m, heap 256 MiB/);
  const big = sh(["--dry-run", ...URL], { ...JETSON, P2P_DETECT_MEM_MB: "16000", P2P_DETECT_BUILDX: "yes" });
  assert.match(big.out, /preset default, memory cap 1024m, heap 768 MiB/);
  assert.match(big.out, /^\+ docker buildx build --load /m);
  const forced = sh(["--dry-run", ...URL, "--preset", "small", "--port", "9000"], { ...JETSON, P2P_DETECT_MEM_MB: "16000" });
  assert.match(forced.out, /preset small, memory cap 768m/);
  assert.match(forced.out, /-p 127\.0\.0\.1:9000:8080/);
});

test("--data-dir bind-mounts the directory and warns when it is on flash", () => {
  const r = sh(["--dry-run", ...URL, "--data-dir", "/srv/p2p-relay/data"], { ...JETSON, P2P_DETECT_DATA_DEVICE: "/dev/sda1" });
  assert.equal(r.code, 0, r.all);
  assert.match(r.out, /--mount type=bind,source=\/srv\/p2p-relay\/data,target=\/data/);
  assert.match(r.out, /sudo install -d -o 65532 -g 65532 -m 0750 \/srv\/p2p-relay\/data/); // printed advice, not run
  assert.doesNotMatch(r.err, /SD card/);
  const flash = sh(["--dry-run", ...URL, "--data-dir", "/data"], { ...JETSON, P2P_DETECT_DATA_DEVICE: "/dev/mmcblk1p2" });
  assert.match(flash.err, /\/dev\/mmcblk1p2, an SD card or eMMC/);
});

test("Docker older than 20.10.10 falls through to Node, and Node on Linux gets a hardened systemd unit", () => {
  const r = sh(["--dry-run", ...URL], { ...JETSON, P2P_DETECT_DOCKER: "20.10.9", P2P_DETECT_NODE: "22.14.0", P2P_DETECT_GLIBC: "2.36", P2P_NODE_BIN: "/usr/bin/node", P2P_DETECT_DATA_DEVICE: "/dev/sda1" });
  assert.equal(r.code, 0, r.all);
  assert.match(r.out, /plan: Node 22\.14\.0 with systemd, preset small, MemoryMax 768M/);
  const lines = r.out.split("\n");
  const notice = lines.findIndex((l) => l.startsWith("sudo is needed for the next steps only"));
  const firstSudo = lines.findIndex((l) => l.startsWith("+ sudo "));
  assert.ok(notice >= 0 && firstSudo > notice, "sudo is announced before it is used");
  // npm runs as you, never under sudo.
  assert.ok(lines.filter((l) => l.includes("npm ci")).every((l) => !l.startsWith("+ sudo")));
  assert.match(r.out, /\+ sudo useradd --system --user-group .* p2p-relay/);
  for (const line of [
    "User=p2p-relay",
    'Environment="RELAY_URL=wss://relay.example.org/v3"',
    'Environment="RELAY_PRESET=small"',
    'Environment="NODE_OPTIONS=--disable-warning=ExperimentalWarning --max-old-space-size=384"',
    'Environment="HOST=127.0.0.1"',
    'Environment="DB_PATH=/var/lib/p2p-relay/relay.db"',
    'ExecStart="/usr/bin/node" "/opt/p2p-relay/packages/relay/dist/bin.js"',
    'ReadWritePaths="/var/lib/p2p-relay"',
    "MemoryMax=768M",
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
  ]) {
    assert.ok(r.out.includes(line), `unit lacks ${line}`);
  }
  assert.match(r.out, /\+ sudo systemctl enable p2p-relay/);
});

test("a node under /home is refused: the service user couldn't read it", () => {
  const r = sh(["--dry-run", ...URL], { ...JETSON, P2P_DETECT_DOCKER: "", P2P_DETECT_NODE: "22.14.0", P2P_NODE_BIN: "/home/me/.nvm/versions/node/v22.14.0/bin/node" });
  assert.notEqual(r.code, 0);
  assert.match(r.err, /the service user can't read/);
});

test("macOS with Node prints launchd instructions and installs nothing", () => {
  const r = sh(["--dry-run", ...URL], { ...JETSON, P2P_DETECT_OS: "Darwin", P2P_DETECT_DOCKER: "", P2P_DETECT_NODE: "22.14.0", P2P_NODE_BIN: "/usr/local/bin/node" });
  assert.equal(r.code, 0, r.all);
  assert.match(r.out, /launchd/);
  assert.match(r.out, /<string>wss:\/\/relay\.example\.org\/v3<\/string>/);
  assert.doesNotMatch(r.out, /^\+ /m);
});

test("with neither, it says exactly what's missing and exits 2", () => {
  const r = sh(["--dry-run", ...URL], { ...JETSON, P2P_DETECT_DOCKER: "19.03.6", P2P_DETECT_NODE: "18.19.0" });
  assert.equal(r.code, 2, r.all);
  assert.match(r.out, /Docker 20\.10\.10 or newer: found 19\.03\.6, too old/);
  assert.match(r.out, /Node 22\.13\.0 or newer: found 18\.19\.0/);
  assert.match(r.out, /glibc 2\.27; official Node 22 builds need 2\.28, so Docker is the way here/);
  const none = sh(["--dry-run", ...URL], { ...JETSON, P2P_DETECT_DOCKER: "", P2P_DETECT_NODE: "" });
  assert.equal(none.code, 2);
  assert.match(none.out, /Node 22\.13\.0 or newer: found none/);
});

test("--env passes extra relay settings to Docker, systemd and launchd, and refuses unsafe ones", () => {
  const docker = sh(["--dry-run", ...URL, "--env", "RELAY_ALLOW_CIRCLE=c_abc", "--env", "RELAY_ALLOW=u_a u_b"], { ...JETSON, P2P_DETECT_DATA_DEVICE: "/dev/sda1" });
  assert.equal(docker.code, 0, docker.all);
  const run = docker.out.split("\n").find((l) => l.startsWith("+ docker run"));
  assert.ok(run.includes("-e RELAY_ALLOW_CIRCLE=c_abc -e 'RELAY_ALLOW=u_a u_b' peer2peer/relay:local"), run);
  const unit = sh(["--dry-run", ...URL, "--env", "RELAY_ALLOW_CIRCLE=c_abc"], { ...JETSON, P2P_DETECT_DOCKER: "", P2P_DETECT_NODE: "22.14.0", P2P_NODE_BIN: "/usr/bin/node", P2P_DETECT_DATA_DEVICE: "/dev/sda1" });
  assert.match(unit.out, /^ {4}Environment="RELAY_ALLOW_CIRCLE=c_abc"$/m);
  const mac = sh(["--dry-run", ...URL, "--env", "RELAY_ALLOW_CIRCLE=c_abc"], { ...JETSON, P2P_DETECT_OS: "Darwin", P2P_DETECT_DOCKER: "", P2P_DETECT_NODE: "22.14.0", P2P_NODE_BIN: "/usr/local/bin/node" });
  assert.match(mac.out, /<key>RELAY_ALLOW_CIRCLE<\/key><string>c_abc<\/string>/);
  for (const bad of ["lower=1", "1A=x", "NOVALUE", "X=$(id)", 'X="q"', "X=a\\b", "X=%h", "X=a\nEnvironment=Y=1"]) {
    const r = sh(["--dry-run", ...URL, "--env", bad], JETSON);
    assert.notEqual(r.code, 0, bad);
    assert.doesNotMatch(r.out, /^\+ /m, bad);
  }
});

// ---- injection and takeover (review I1, I2, I4, I5) ----------------------

const NODE_LINUX = { ...JETSON, P2P_DETECT_DOCKER: "", P2P_DETECT_NODE: "22.14.0", P2P_DETECT_GLIBC: "2.36", P2P_NODE_BIN: "/usr/bin/node", P2P_DETECT_DATA_DEVICE: "/dev/sda1" };
const DOCKER_LINUX = { ...JETSON, P2P_DETECT_DATA_DEVICE: "/dev/sda1" };
const refused = (r, what, msg) => {
  assert.notEqual(r.code, 0, `${what}: should be refused\n${r.all}`);
  if (msg) assert.match(r.err, msg, what);
  assert.doesNotMatch(r.out, /^\+ /m, `${what}: nothing may run`);
  assert.doesNotMatch(r.out, /\[Service\]|ExecStart/, `${what}: no unit may be written`);
};

test("I1: a --url or node path can't inject lines into the systemd unit, plist or docker arguments", () => {
  for (const env of [DOCKER_LINUX, NODE_LINUX, { ...NODE_LINUX, P2P_DETECT_OS: "Darwin" }]) {
    for (const url of [
      "wss://relay.example.org/v3\nExecStartPre=+/bin/sh -c 'id > /tmp/pwned'",
      "wss://relay.example.org/v3\n",
      'wss://relay.example.org/v3" ExecStartPre="+/bin/true',
      "wss://relay.example.org/v3 x",
      "wss://relay.example.org/v3</string><key>X</key>",
      "wss://relay.example.org/$(id)",
      "wss://relay.example.org/v3%h",
      "wss://user@relay.example.org/v3",
      "ws://relay.example.org/v3",
    ]) {
      refused(sh(["--dry-run", "--url", url], env), JSON.stringify(url), /--url must look like/);
    }
  }
  for (const bin of ["/usr/bin/node\nExecStartPre=+/bin/sh", "/usr/bin/no de", '/usr/bin/node"', "usr/bin/node", "/usr/../bin/node"]) {
    refused(sh(["--dry-run", ...URL], { ...NODE_LINUX, P2P_NODE_BIN: bin }), JSON.stringify(bin), /node's path/);
    refused(sh(["--dry-run", ...URL], { ...NODE_LINUX, P2P_DETECT_OS: "Darwin", P2P_NODE_BIN: bin }), `mac ${JSON.stringify(bin)}`, /node's path/);
  }
  // Everything that does reach the unit is quoted.
  const ok = sh(["--dry-run", "--url", "wss://relay.example.org:8443/v3", "--data-dir", "/srv/p2p-relay/data"], NODE_LINUX);
  assert.equal(ok.code, 0, ok.all);
  const unit = ok.out.split("\n").filter((l) => /^ {4}(Environment|ExecStart|ReadWritePaths)=/.test(l));
  assert.ok(unit.length >= 9, ok.out);
  for (const l of unit) assert.match(l, /^ {4}(Environment="[^"\n]*"|ExecStart="[^"]*" "[^"]*"|ReadWritePaths="[^"]*")$/, l);
  assert.match(ok.out, /Environment="DB_PATH=\/srv\/p2p-relay\/data\/relay\.db"/);
  assert.match(ok.out, /ReadWritePaths="\/srv\/p2p-relay\/data"/);
});

test("I2: --data-dir refuses /, home and system directories, odd characters, links and folders holding other files", () => {
  const full = join(elsewhere, "full");
  const empty = join(elsewhere, "empty");
  const link = join(elsewhere, "link");
  mkdirSync(full, { recursive: true });
  writeFileSync(join(full, "notes.txt"), "someone's files");
  mkdirSync(empty, { recursive: true });
  try { symlinkSync(empty, link); } catch { /* exists */ }
  const home = process.env.HOME;
  for (const env of [DOCKER_LINUX, NODE_LINUX]) {
    for (const [dir, msg] of [
      ["/", /must not be \//],
      [home, /home directory/],
      ["/home", /home directory/],
      ["/home/someone", /home directory/],
      ["/root", /system directory/],
      ["/etc/p2p-relay", /system directory/],
      ["/usr/local/p2p", /system directory/],
      ["/var/lib", /system directory/],
      ["/opt/p2p-relay", /system directory/],
      ["/srv", /system directory/],
      ["relative/data", /absolute path/],
      ["/srv/a b", /only letters, digits/],
      ["/srv/a\nb", /only letters, digits/],
      ['/srv/a"b', /only letters, digits/],
      ["/srv/../etc", /\.\./],
      ["/srv//x", /\/\//],
      [full, /already holds files/],
      [link, /symbolic link/],
    ]) {
      refused(sh(["--dry-run", ...URL, "--data-dir", dir], env), `${env === NODE_LINUX ? "node" : "docker"} ${JSON.stringify(dir)}`, msg);
    }
  }
  // Under a home is fine for Docker but not for the systemd service (ProtectHome).
  refused(sh(["--dry-run", ...URL, "--data-dir", "/home/someone/relay"], NODE_LINUX), "node under /home", /ProtectHome/);
  // A new or empty directory is fine: Docker prints the chown to run, the Node path creates it.
  const d = sh(["--dry-run", ...URL, "--data-dir", empty], DOCKER_LINUX);
  assert.equal(d.code, 0, d.all);
  assert.match(d.out, /It is empty, so run: sudo chown 65532:65532 /);
  const n = sh(["--dry-run", ...URL, "--data-dir", "/srv/p2p-relay/new"], NODE_LINUX);
  assert.equal(n.code, 0, n.all);
  assert.match(n.out, /\+ sudo install -d -o p2p-relay -g p2p-relay -m 0750 \/srv\/p2p-relay\/new/);
});

test("I4/I5: the unit is written inside the private build directory; only a real checkout or P2P_SOURCE_DIR is built", () => {
  const body = readFileSync(SH, "utf8");
  assert.match(body, /printf '%s\\n' "\$unit" >"\$stage\/\$NAME\.service"/);
  assert.doesNotMatch(body, /\$stage\.unit/);
  assert.match(body, /trap cleanup EXIT/);
  // A directory that merely looks like the repository isn't built from.
  const fake = join(elsewhere, "lookalike");
  mkdirSync(join(fake, "packages/relay"), { recursive: true });
  mkdirSync(join(fake, "packages/core"), { recursive: true });
  writeFileSync(join(fake, "packages/relay/Dockerfile"), "FROM scratch\n");
  const r = sh(["--dry-run", ...URL], DOCKER_LINUX, { cwd: fake });
  assert.equal(r.code, 0, r.all);
  assert.doesNotMatch(r.out, /building from the checkout/, "lookalike checkout: not built from");
  assert.ok(r.out.includes(`+ download ${pinnedSourceUrl()}, check sha256 `), "lookalike checkout: the pinned release is used instead");
  // P2P_SOURCE_DIR is an explicit choice.
  const e = sh(["--dry-run", ...URL], { ...DOCKER_LINUX, P2P_SOURCE_DIR: repo }, { cwd: elsewhere });
  assert.equal(e.code, 0, e.all);
  assert.match(e.out, /building from P2P_SOURCE_DIR=/);
});

test("bad options are refused before anything happens", () => {
  for (const [args, msg] of [
    [["--url", "https://relay.example.org/v3"], /--url must look like wss:\/\//],
    [["--preset", "tiny", ...URL], /small or default/],
    [["--port", "0", ...URL], /1-65535/],
    [["--port", "80a", ...URL], /must be a number/],
    [["--method", "podman", ...URL], /auto, docker or node/],
    [["--bogus"], /unknown option/],
  ]) {
    const r = sh(["--dry-run", ...args], JETSON);
    assert.notEqual(r.code, 0, args.join(" "));
    assert.match(r.err, msg);
    assert.doesNotMatch(r.out, /^\+ /m);
  }
  assert.match(sh(["--dry-run"], JETSON).err, /no --url/);
});

function pinnedSourceUrl() {
  const text = readFileSync(SH, "utf8");
  const v = text.match(/^RELAY_VERSION="([^"]*)"/m)[1];
  return `https://github.com/ix-infrastructure/Peer2Peer/releases/download/v${v}/peer2peer-${v}-src.tar.gz`;
}

test("outside a checkout it downloads the pinned release and checks its SHA-256, and refuses when nothing is pinned", () => {
  const text = readFileSync(SH, "utf8");
  const sum = text.match(/^RELAY_SOURCE_SHA256="([^"]*)"/m)[1];
  const r = sh(["--dry-run", ...URL], JETSON, { cwd: elsewhere });
  assert.equal(r.code, 0, r.all);
  assert.ok(r.out.includes(`+ download ${pinnedSourceUrl()}, check sha256 ${sum}, unpack`), r.out);
  const unpinned = join(elsewhere, "unpinned.sh");
  writeFileSync(unpinned, text.replace(/^RELAY_VERSION="[^"]*"/m, 'RELAY_VERSION=""').replace(/^RELAY_SOURCE_SHA256="[^"]*"/m, 'RELAY_SOURCE_SHA256=""'));
  const u = spawnSync("sh", [unpinned, "--dry-run", ...URL], { cwd: elsewhere, env: { PATH: process.env.PATH, HOME: process.env.HOME, ...JETSON }, encoding: "utf8" });
  assert.notEqual(u.status, 0);
  assert.match(u.stderr, /no Peer2Peer release is pinned in this script yet: run it from the root of a checkout/);
});

test("piped into sh it works from a checkout, and a truncated download runs nothing", () => {
  const body = readFileSync(SH, "utf8");
  const piped = spawnSync("sh", ["-s", "--", "--dry-run", ...URL], { cwd: repo, input: body, encoding: "utf8", env: { PATH: process.env.PATH, ...JETSON } });
  assert.equal(piped.status, 0, piped.stderr);
  assert.match(piped.stdout, /Give teammates this relay URL/);
  for (const frac of [0.25, 0.5, 0.75, 0.95]) {
    const cut = body.slice(0, Math.floor(body.length * frac));
    const r = spawnSync("sh", ["-s", "--", "--dry-run", ...URL], { cwd: repo, input: cut, encoding: "utf8", env: { PATH: process.env.PATH, ...JETSON } });
    assert.doesNotMatch(r.stdout + r.stderr, /detected:|^\+ /m, `truncated at ${frac}`);
  }
  assert.match(body.trimEnd().split("\n").at(-1), /^main "\$@"$/);
});

test("the relay version pin and its checksum are set together", () => {
  for (const [file, ver, sum] of [
    [SH, /^RELAY_VERSION="([^"]*)"/m, /^RELAY_SOURCE_SHA256="([^"]*)"/m],
    [PS1, /\$RelayVersion = '([^']*)'/, /\$RelaySourceSha256 = '([^']*)'/],
  ]) {
    const text = readFileSync(file, "utf8");
    const v = text.match(ver)[1];
    const s = text.match(sum)[1];
    assert.equal(Boolean(v), Boolean(s), `${file}: version and SHA-256 must be pinned together`);
    if (s) assert.match(s, /^[0-9a-f]{64}$/);
  }
});

// ---- checksums ------------------------------------------------------------

test("scripts/install-relay.sha256 is up to date (npm run install-scripts:checksums in packages/relay)", () => {
  assert.equal(readFileSync(SUMS_FILE, "utf8"), checksums());
  assert.match(checksums(), /^[0-9a-f]{64} {2}install-relay\.sh\n[0-9a-f]{64} {2}install-relay\.ps1\n$/);
});

// ---- install-relay.ps1 ----------------------------------------------------

function pwsh(script, env = {}) {
  const r = spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-Command", script], {
    cwd: repo,
    env: { ...process.env, ...env },
    encoding: "utf8",
  });
  // pwsh wraps error messages in a framed, coloured box: drop the colours and the frame so a
  // message can be matched across its line breaks.
  const all = (r.stdout + r.stderr).replace(/\x1b\[[0-9;]*m/g, "").replace(/\n\s*\|\s*/g, " ");
  return { code: r.status, out: r.stdout, err: r.stderr, all };
}

const WIN = {
  P2P_DETECT_OS: "Windows",
  P2P_DETECT_ARCH: "AMD64",
  P2P_DETECT_MEM_MB: "2048",
  P2P_DETECT_DOCKER: "27.5.1",
  P2P_DETECT_DOCKER_OSTYPE: "linux",
  P2P_DETECT_DOCKER_KERNEL: "5.15.167.4-microsoft-standard-WSL2",
  P2P_DETECT_NODE: "none",
  // Windows identities and ACLs can't be read on Linux: a plain user's SIDs, and no folder
  // above the install the user could change, unless a test says otherwise.
  P2P_DETECT_USER_SIDS: "S-1-5-21-1000-2000-3000-1001;S-1-5-11;S-1-5-32-545",
  P2P_DETECT_SWAPPABLE: "none",
  ProgramData: "C:\\ProgramData",
};
const ps = (args) => `& '${PS1}' ${args} 6>&1`;

test("install-relay.ps1 is PSScriptAnalyzer-clean, including PowerShell 5.1 syntax", (t) => {
  if (!tool("pwsh", t)) return;
  const probe = pwsh("if (Get-Module -ListAvailable PSScriptAnalyzer) { 'yes' } else { 'no' }");
  if (probe.out.trim() !== "yes") {
    if (strict) assert.fail("the PSScriptAnalyzer module is required (P2P_REQUIRE_INSTALLER_TOOLS=1)");
    t.skip("the PSScriptAnalyzer module is not installed");
    return;
  }
  const r = pwsh(
    `$s = @{ IncludeDefaultRules = $true; Rules = @{ PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('5.1', '7.0') } } }; ` +
      `$f = @(Invoke-ScriptAnalyzer -Path '${PS1}' -Settings $s); $f | Format-List RuleName, Severity, Line, Message | Out-String -Width 200; "findings=$($f.Count)"`,
  );
  assert.match(r.out, /findings=0/, r.all);
});

test("install-relay.ps1 -DryRun: Docker on WSL2 gets the small preset and the hardening flags", (t) => {
  if (!tool("pwsh", t)) return;
  const r = pwsh(ps("-DryRun -Url wss://relay.example.org/v3"), WIN);
  assert.equal(r.code, 0, r.all);
  assert.match(r.out, /docker=27\.5\.1 \(Linux containers on WSL2\)/);
  assert.match(r.out, /plan: Docker 27\.5\.1 \(Linux containers on WSL2\), preset small, memory cap 768m, heap 384 MiB/);
  const run = r.out.split("\n").find((l) => l.startsWith("+ docker run"));
  for (const flag of ["--restart unless-stopped", "-p 127.0.0.1:8080:8080", "--memory 768m", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges", "type=volume,source=p2p-relay-data"]) {
    assert.ok(run?.includes(flag), `missing ${flag} in: ${run}`);
  }
  assert.doesNotMatch(r.out, /Administrator rights/);
  assert.match(r.out, /Give teammates this relay URL: wss:\/\/relay\.example\.org\/v3/);
});

test("install-relay.ps1 -DryRun: the Node path announces elevation and uses a dedicated account", (t) => {
  if (!tool("pwsh", t)) return;
  const r = pwsh(ps("-DryRun -Url wss://relay.example.org/v3 -OpenFirewall"), { ...WIN, P2P_DETECT_DOCKER: "none", P2P_DETECT_NODE: "v22.14.0", P2P_NODE_BIN: "C:\\Program Files\\nodejs\\node.exe" });
  assert.equal(r.code, 0, r.all);
  assert.match(r.out, /Administrator rights are needed for the next step only/);
  assert.match(r.out, /New-LocalUser -Name 'p2p-relay'/);
  assert.match(r.out, /Register-ScheduledTask -TaskName 'p2p-relay'.* -RunLevel Limited/);
  assert.match(r.out, /New-NetFirewallRule .* -LocalPort 8080 .* -Profile Private/);
  assert.match(r.out, /set "HOST=0\.0\.0\.0"/);
  const local = pwsh(ps("-DryRun -Url wss://relay.example.org/v3"), { ...WIN, P2P_DETECT_DOCKER: "none", P2P_DETECT_NODE: "v22.14.0", P2P_NODE_BIN: "C:\\Program Files\\nodejs\\node.exe" });
  assert.doesNotMatch(local.out, /New-NetFirewallRule/);
  assert.match(local.out, /set "HOST=127\.0\.0\.1"/);
});

test("install-relay.ps1 -RelayEnv reaches Docker and the task's settings; unsafe values are refused", (t) => {
  if (!tool("pwsh", t)) return;
  const env = "-RelayEnv @{ RELAY_ALLOW_CIRCLE = 'c_abc'; RELAY_ALLOW = 'u_a u_b' }";
  const docker = pwsh(ps(`-DryRun -Url wss://relay.example.org/v3 ${env}`), WIN);
  assert.equal(docker.code, 0, docker.all);
  assert.match(docker.out, /-e 'RELAY_ALLOW=u_a u_b' -e RELAY_ALLOW_CIRCLE=c_abc peer2peer\/relay:local/);
  const node = pwsh(ps(`-DryRun -Url wss://relay.example.org/v3 ${env}`), { ...WIN, P2P_DETECT_DOCKER: "none", P2P_DETECT_NODE: "v22.14.0", P2P_NODE_BIN: "C:\\Program Files\\nodejs\\node.exe" });
  assert.match(node.out, /set "RELAY_ALLOW_CIRCLE=c_abc"/);
  for (const bad of ["@{ lower = 'x' }", "@{ X = '%PATH%' }", "@{ X = 'a\"b' }", "@{ X = 'a&b' }"]) {
    const r = pwsh(ps(`-DryRun -Url wss://relay.example.org/v3 -RelayEnv ${bad}`), WIN);
    assert.notEqual(r.code, 0, bad);
    assert.doesNotMatch(r.out, /^\+ /m, bad);
  }
});

const WIN_NODE = { ...WIN, P2P_DETECT_DOCKER: "none", P2P_DETECT_NODE: "v22.14.0", P2P_NODE_BIN: "C:\\Program Files\\nodejs\\node.exe" };
const psRefused = (r, what, msg) => {
  assert.notEqual(r.code, 0, `${what}: should be refused\n${r.all}`);
  if (msg) assert.match(r.all, msg, what);
  assert.doesNotMatch(r.out, /^\+ /m, `${what}: nothing may run`);
  assert.doesNotMatch(r.out, /Administrator rights|run-relay\.cmd|New-LocalUser/, `${what}: no elevated step`);
};
// A PowerShell single-quoted literal (newlines kept).
const psq = (v) => "'" + v.replace(/'/g, "''") + "'";

test("I1 (ps1): -Url, -RelayEnv and node's path can't inject into run-relay.cmd or docker arguments", (t) => {
  if (!tool("pwsh", t)) return;
  for (const env of [WIN, WIN_NODE]) {
    for (const url of ["wss://relay.example.org/v3\n", "wss://relay.example.org/v3\r\ncalc.exe", 'wss://relay.example.org/v3" & calc', "wss://relay.example.org/v3&calc", "wss://relay.example.org/%PATH%", "wss://relay.example.org/v3 x"]) {
      psRefused(pwsh(ps(`-DryRun -Url ${psq(url)}`), env), JSON.stringify(url), /-Url must look like/);
    }
    psRefused(pwsh(ps(`-DryRun -Url wss://relay.example.org/v3 -RelayEnv @{ X = "a\`nset Y=1" }`), env), "env newline", /-RelayEnv/);
  }
  for (const bin of ["C:\\Program Files\\nodejs\\node.exe\r\ncalc.exe", 'C:\\a"b\\node.exe', "C:\\a&b\\node.exe", "C:\\a%b%\\node.exe", "node.exe", "C:\\Users\\me\\node\\node.exe"]) {
    psRefused(pwsh(ps("-DryRun -Url wss://relay.example.org/v3"), { ...WIN_NODE, P2P_NODE_BIN: bin }), JSON.stringify(bin), /node/);
  }
});

test("I2 (ps1): -DataDir refuses roots, profiles, system folders, odd characters and folders holding other files", (t) => {
  if (!tool("pwsh", t)) return;
  for (const env of [WIN, WIN_NODE]) {
    for (const [dir, msg] of [
      ["C:\\", /drive root|full path/],
      ["D:\\", /drive root|full path/],
      ["C:\\Windows\\p2p", /system or profile/],
      ["C:\\Users\\bob\\relay", /system or profile/],
      ["C:\\Users", /system or profile/],
      ["C:\\Program Files\\p2p", /system or profile/],
      ["C:\\ProgramData", /ProgramData itself/],
      ["C:\\ProgramData\\Microsoft\\x", /system or profile/],
      ["data", /full path/],
      ["\\\\server\\share\\x", /full path/],
      ["D:\\a&b", /full path/],
      ["D:\\a%TEMP%b", /full path/],
      ['D:\\a"b', /full path/],
      ["D:\\relay\n", /full path/],
      ["D:\\relay\\..\\Windows", /\. or \.\. parts/],
    ]) {
      psRefused(pwsh(ps(`-DryRun -Url wss://relay.example.org/v3 -DataDir ${psq(dir)}`), env), JSON.stringify(dir), msg);
    }
    psRefused(pwsh(ps("-DryRun -Url wss://relay.example.org/v3 -DataDir 'D:\\p2p-relay\\data'"), { ...env, P2P_DETECT_DATADIR_STATE: "foreign" }), "foreign folder", /already holds files/);
    for (const state of ["new", "empty", "owned"]) {
      const r = pwsh(ps("-DryRun -Url wss://relay.example.org/v3 -DataDir 'D:\\p2p-relay\\data'"), { ...env, P2P_DETECT_DATADIR_STATE: state });
      assert.equal(r.code, 0, `${state}: ${r.all}`);
    }
  }
});

test("I3/I5/I6 (ps1): elevation via -EncodedCommand, a re-checked takeover guard, batch-logon rights, checkout markers", (t) => {
  const body = readFileSync(PS1, "utf8");
  assert.match(body, /'-EncodedCommand', \$encoded/);
  assert.doesNotMatch(body, /p2p-relay-elevated-|-File', \$file/);
  assert.match(body, /robocopy\.exe \$stage "\$installDir\\app" \/E \/XJ/);
  if (!tool("pwsh", t)) return;
  const r = pwsh(ps("-DryRun -Url wss://relay.example.org/v3"), WIN_NODE);
  assert.equal(r.code, 0, r.all);
  for (const right of ["SeBatchLogonRight", "SeDenyInteractiveLogonRight", "SeDenyRemoteInteractiveLogonRight"]) assert.ok(r.out.includes(right), right);
  assert.match(r.out, /already holds files that aren't the relay's/); // the elevated step checks again itself
  assert.match(r.out, /icacls\.exe \$dataDir \/setowner 'p2p-relay'/);
  const fake = join(elsewhere, "lookalike-ps");
  mkdirSync(join(fake, "packages/relay"), { recursive: true });
  writeFileSync(join(fake, "packages/relay/Dockerfile"), "FROM scratch\n");
  const out = spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-Command", ps("-DryRun -Url wss://relay.example.org/v3")], { cwd: fake, env: { ...process.env, ...WIN, P2P_SOURCE_DIR: "" }, encoding: "utf8" });
  assert.equal(out.status, 0, out.stdout + out.stderr);
  assert.doesNotMatch(out.stdout, /building from the checkout/);
  assert.ok(out.stdout.includes(`+ download ${pinnedSourceUrl()}, check SHA-256 `), out.stdout);
});

test("W1 (ps1): a custom -DataDir whose parent you can write is refused; the elevated step locks folders before the copy", (t) => {
  const body = readFileSync(PS1, "utf8");
  // Every icacls in the elevated step comes right after a fresh link check.
  const lines = body.split("\n");
  const icacls = lines.map((l, i) => [l, i]).filter(([l]) => /^\s*& icacls\.exe /.test(l));
  assert.ok(icacls.length >= 5);
  for (const [l, i] of icacls) assert.match(lines[i - 1], /Assert-NotLink /, `no link check right before: ${l}`);
  // The folders are locked to Administrators before the account, the copy and the task.
  const lock = body.indexOf("/setowner '*S-1-5-32-544'");
  for (const later of ["New-LocalUser", "robocopy.exe", "Register-ScheduledTask"]) assert.ok(lock > 0 && lock < body.indexOf(later), `lock before ${later}`);
  if (!tool("pwsh", t)) return;
  const custom = "-DryRun -Url wss://relay.example.org/v3 -DataDir 'D:\\p2p-relay\\data'";
  psRefused(pwsh(ps(custom), { ...WIN_NODE, P2P_DETECT_SWAPPABLE: "D:\\p2p-relay" }), "changeable parent", /you can change the folder D:\\p2p-relay/);
  const ok = pwsh(ps(custom), WIN_NODE);
  assert.equal(ok.code, 0, ok.all);
  assert.match(ok.out, /Assert-NotLink \$d/);
  // Only the Node path (which changes ACLs as Administrator) cares.
  assert.equal(pwsh(ps(custom), { ...WIN, P2P_DETECT_SWAPPABLE: "D:\\p2p-relay" }).code, 0);
});

// The shared folder-safety functions, loaded on their own.
function rightsLib() {
  const body = readFileSync(PS1, "utf8");
  const m = body.match(/# region rights\n[\s\S]*?# endregion rights\n/);
  assert.ok(m, "the rights region is in the script");
  return m[0];
}

test("F2 (ps1): generic rights are mapped before deciding whether a user could swap a folder", (t) => {
  if (!tool("pwsh", t)) return;
  const cases = [
    ["GENERIC_ALL", 268435456, true],
    ["GENERIC_WRITE", 1073741824, false],
    ["GENERIC_WRITE|GENERIC_ALL", 1073741824 + 268435456, true],
    ["GENERIC_READ (negative int)", -2147483648, false],
    ["GENERIC_EXECUTE", 536870912, false],
    ["FILE_ALL_ACCESS", 2032127, true],
    ["Modify", 197055, true],
    ["DELETE", 65536, true],
    ["WRITE_DAC", 262144, true],
    ["WRITE_OWNER", 524288, true],
    ["FILE_DELETE_CHILD", 64, true],
    ["create files and folders only", 6, false],
    ["FILE_GENERIC_WRITE", 1179926, false],
    ["ReadAndExecute", 131241, false],
  ];
  const script = rightsLib() + cases.map(([, r]) => `"swap=" + (Test-RightsLetSwap ${r})`).join("; ") +
    `; "mapped=" + (ConvertTo-SpecificRights 268435456); "mappedw=" + (ConvertTo-SpecificRights 1073741824)` +
    `; "chain=" + ((Get-WindowsChain 'D:\\a\\b') -join '|'); "root=" + ((Get-WindowsChain 'C:\\') -join '|')`;
  const r = pwsh(script);
  assert.equal(r.code, 0, r.all);
  const got = [...r.out.matchAll(/^swap=(True|False)$/gm)].map((m) => m[1] === "True");
  assert.deepEqual(got, cases.map(([, , want]) => want), cases.map(([n], i) => `${n}: ${got[i]}`).join(", "));
  assert.match(r.out, /^mapped=2302591167$|^mapped=270467583$/m);
  assert.match(r.out, /^mappedw=1074921750$/m);
  assert.match(r.out, /^chain=D:\\\|D:\\a\|D:\\a\\b$/m);
  assert.match(r.out, /^root=C:\\$/m);
});

test("F1/F3 (ps1): every folder above the install is checked, and folders another user created are refused or recreated", (t) => {
  const body = readFileSync(PS1, "utf8");
  // Elevated: someone else's empty folder is deleted and created again; non-empty is refused;
  // missing folders are created one at a time and checked; the test hook is off.
  assert.match(body, /\[IO\.Directory\]::Delete\(\$d, \$false\)/);
  assert.match(body, /belongs to another account \(\$owner\) and isn't empty/);
  assert.match(body, /New-LockedDirectory \$c\n/);
  assert.match(body, /`\$P2PElevated = `\$true/);
  for (const later of ["New-LocalUser", "robocopy.exe"]) assert.ok(body.indexOf("New-TrustedDir $d") < body.indexOf(later), `folders created before ${later}`);
  if (!tool("pwsh", t)) return;
  const deep = "-DryRun -Url wss://relay.example.org/v3 -DataDir 'D:\\a\\b\\data'";
  for (const anc of ["D:\\", "D:\\a", "D:\\a\\b"]) {
    psRefused(pwsh(ps(deep), { ...WIN_NODE, P2P_DETECT_SWAPPABLE: anc }), `ancestor ${anc}`, new RegExp(`change the folder ${anc.replace(/\\/g, "\\\\")} above`));
  }
  assert.equal(pwsh(ps(deep), WIN_NODE).code, 0);
  // The default install folder's parents are checked too.
  psRefused(pwsh(ps("-DryRun -Url wss://relay.example.org/v3"), { ...WIN_NODE, P2P_DETECT_SWAPPABLE: "C:\\ProgramData" }), "ProgramData changeable", /change the folder C:\\ProgramData/);
  // A pre-created install folder: someone else's with files is refused; empty or Administrators' is fine.
  psRefused(pwsh(ps("-DryRun -Url wss://relay.example.org/v3"), { ...WIN_NODE, P2P_DETECT_INSTALLDIR_STATE: "foreign" }), "foreign install folder", /isn't owned by Administrators and isn't empty/);
  for (const st of ["new", "empty", "owned"]) assert.equal(pwsh(ps("-DryRun -Url wss://relay.example.org/v3"), { ...WIN_NODE, P2P_DETECT_INSTALLDIR_STATE: st }).code, 0, st);
  // The elevated step works out the installing user's SIDs itself (G2): no list is handed over.
  const r = pwsh(ps("-DryRun -Url wss://relay.example.org/v3"), WIN_NODE);
  assert.equal(r.code, 0, r.all);
  assert.doesNotMatch(r.out, /S-1-5-21-1000-2000-3000-1001/);
  assert.match(r.out, /^ {4}\$userSids = Get-UserSid$/m);
});

test("G2 (ps1): the elevated step takes the user's SIDs from its own token and ignores the test hook", (t) => {
  const body = readFileSync(PS1, "utf8");
  // The header handed to the elevated step sets $P2PElevated and carries no SID list.
  const header = body.match(/\$elevated\.Add\(\("`\$installDir = .*$/m)[0];
  assert.match(header, /`\$P2PElevated = `\$true/);
  assert.doesNotMatch(header, /userSids/);
  // In the elevated body, $userSids is computed after the shared block and before it is used.
  const add = body.indexOf("$elevated.Add('$userSids = Get-UserSid')");
  assert.ok(add > body.indexOf("$elevated.Add($rightsLib)"), "computed after the shared block is loaded");
  assert.ok(add < body.indexOf("$a = Get-SwappableAncestor $d $userSids\n    if ($a) { throw \"${d}: the folder"), "computed before the elevated check");
  if (!tool("pwsh", t)) return;
  const fake = "S-1-5-21-9-9-9-500";
  const probe = (elevated) => rightsLib() + (elevated ? "$P2PElevated = $true\n" : "") +
    `try { $s = Get-UserSid; "sids=" + ($s -join ',') } catch { "token-only" }`;
  const plain = pwsh(probe(false), { P2P_DETECT_USER_SIDS: fake });
  assert.match(plain.out, new RegExp(`^sids=${fake}$`, "m"), plain.all);
  const elevated = pwsh(probe(true), { P2P_DETECT_USER_SIDS: fake });
  assert.equal(elevated.code, 0, elevated.all);
  assert.doesNotMatch(elevated.out, new RegExp(fake), "the override must be ignored in the elevated step");
  assert.match(elevated.out, /^(token-only|sids=.+)$/m);
});

test("G1 (ps1): each new folder is created with its locked security in the same call, before any icacls", (t) => {
  const lib = rightsLib();
  const fn = lib.match(/function New-LockedDirectory[\s\S]*?\n\}\n/)[0];
  // Locked from birth: no inheritance, Administrators as owner, only Administrators and SYSTEM.
  assert.match(fn, /SetAccessRuleProtection\(\$true, \$false\)/);
  assert.match(fn, /SetOwner\(\(New-Object Security\.Principal\.SecurityIdentifier 'S-1-5-32-544'\)\)/);
  assert.match(fn, /foreach \(\$sid in 'S-1-5-32-544', 'S-1-5-18'\)/);
  assert.equal((fn.match(/AddAccessRule/g) || []).length, 1);
  // One create call that takes the security: CreateDirectory(path, security) or FileSystemAclExtensions.Create.
  assert.match(fn, /GetMethod\('CreateDirectory', \[type\[\]\]@\(\[string\], \[Security\.AccessControl\.DirectorySecurity\]\)\)/);
  assert.match(fn, /\[IO\.FileSystemAclExtensions\]::Create\(/);
  assert.ok(fn.indexOf("AddAccessRule") < fn.indexOf("GetMethod('CreateDirectory'"), "security is built before the folder is created");
  // New-TrustedDir uses it (no plain New-Item), then checks link and owner.
  const body = readFileSync(PS1, "utf8");
  const trusted = body.match(/function New-TrustedDir[\s\S]*?\n\}\n/)[0];
  assert.doesNotMatch(trusted, /New-Item/);
  const order = ["New-LockedDirectory $c", "Assert-NotLink $c", "Get-OwnerSid $c"].map((x) => trusted.indexOf(x));
  assert.ok(order.every((i) => i > 0) && order[0] < order[1] && order[1] < order[2], `order ${order}`);
  // And the folders are created before the first icacls touches them.
  assert.ok(body.indexOf("    New-TrustedDir $d") < body.indexOf("& icacls.exe $d /setowner"));
  if (!tool("pwsh", t)) return;
  const r = pwsh(lib + `"loaded=" + [bool](Get-Command New-LockedDirectory)`);
  assert.match(r.out, /^loaded=True$/m, r.all);
});

test("install-relay.ps1 -DryRun: Windows containers or old Node are reported, not guessed around", (t) => {
  if (!tool("pwsh", t)) return;
  const r = pwsh(ps("-DryRun -Url wss://relay.example.org/v3"), { ...WIN, P2P_DETECT_DOCKER_OSTYPE: "windows", P2P_DETECT_NODE: "v20.1.0" });
  assert.equal(r.code, 0, r.all);
  assert.match(r.out, /switch Docker Desktop to Linux containers/);
  assert.match(r.out, /Node 22\.13\.0 or newer: found v20\.1\.0/);
  assert.doesNotMatch(r.out, /^\+ /m);
});

test("install-relay.ps1 piped into iex: env vars stand in for parameters; a truncated download does nothing", (t) => {
  if (!tool("pwsh", t)) return;
  const r = pwsh(`Get-Content -Raw '${PS1}' | Invoke-Expression 6>&1`, { ...WIN, P2P_RELAY_DRY_RUN: "1", P2P_RELAY_URL: "wss://relay.example.org/v3" });
  assert.equal(r.code, 0, r.all);
  assert.match(r.out, /dry run: nothing will be changed/);
  const body = readFileSync(PS1, "utf8");
  assert.match(body.trimEnd().split("\n").at(-1), /^Install-P2PRelay @PSBoundParameters$/);
  const cut = pwsh(`$t = (Get-Content -Raw '${PS1}'); $t = $t.Substring(0, [int]($t.Length * 0.6)); try { Invoke-Expression $t 6>&1 } catch { 'parse failed' }`, { ...WIN, P2P_RELAY_DRY_RUN: "1" });
  assert.doesNotMatch(cut.out, /detected:/);
});
