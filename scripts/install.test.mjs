// Copyright 2026 Ix Infrastructure Inc.
//
// The client install scripts (install.sh, install.ps1), without installing
// anything: shellcheck and PSScriptAnalyzer, then runs against fake `node`,
// `npm` and `p2p` commands that only record what they were asked to do, plus
// the checksum file.
//
//   node --test scripts/install.test.mjs
//
// shellcheck, pwsh and the PSScriptAnalyzer module are optional locally (those
// tests skip, saying why); with P2P_REQUIRE_INSTALLER_TOOLS=1 (CI) they must
// be present.

import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { checksums, SETS } from "./install-relay-checksums.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repo = dirname(here);
const SH = join(here, "install.sh");
const PS1 = join(here, "install.ps1");
const strict = process.env.P2P_REQUIRE_INSTALLER_TOOLS === "1";
const has = (cmd) => spawnSync("sh", ["-c", `command -v ${cmd}`]).status === 0;
const work = mkdtempSync(join(tmpdir(), "p2p-install-test-"));
after(() => {
  // A test makes a read-only prefix; make it removable again.
  spawnSync("chmod", ["-R", "u+w", work]);
  rmSync(work, { recursive: true, force: true });
});

function tool(cmd, t) {
  if (has(cmd)) return true;
  if (strict) assert.fail(`${cmd} is required (P2P_REQUIRE_INSTALLER_TOOLS=1)`);
  t.skip(`${cmd} is not installed`);
  return false;
}

// Fake commands. Each records its arguments in $FAKE_LOG and never touches
// anything outside $FAKE_PREFIX. `npm install` "installs" a fake p2p both where
// npm puts it on macOS/Linux ($prefix/bin/p2p) and on Windows ($prefix/p2p.cmd).
const FAKE_P2P = `#!/bin/sh
if [ "$1" = --version ]; then echo "\${FAKE_P2P_VERSION:-0.1.1}"; exit 0; fi
if [ -t 0 ]; then t=yes; else t=no; fi
echo "p2p $* (stdin-tty=$t)" >>"$FAKE_LOG"
exit "\${FAKE_SETUP_EXIT:-0}"
`;
const FAKES = {
  // `node --version`, or `node <script> args` runs the fake CLI's bin.js (a shell script).
  node: `#!/bin/sh\nif [ "$1" = --version ]; then echo "v\${FAKE_NODE_VERSION:-22.14.0}"; exit 0; fi\nexec sh "$@"\n`,
  npm: `#!/bin/sh
echo "npm $*" >>"$FAKE_LOG"
case "$1" in
  --version) echo 10.9.2 ;;
  # npm masks UUID-shaped folder names as *** in what it prints (FAKE_PREFIX_SHOWN).
  prefix) echo "\${FAKE_PREFIX_SHOWN:-$FAKE_PREFIX}" ;;
  exec) echo "npm exec must never be called" >&2; exit 99 ;;
  install)
    [ -n "\${FAKE_NPM_FAIL:-}" ] && exit 1
    mkdir -p "$FAKE_PREFIX/bin" "$FAKE_PREFIX/lib/node_modules"
    cat "$FAKE_BIN/p2p-template" >"$FAKE_PREFIX/bin/p2p"; chmod +x "$FAKE_PREFIX/bin/p2p"
    cat "$FAKE_BIN/p2p-template" >"$FAKE_PREFIX/p2p.cmd"; chmod +x "$FAKE_PREFIX/p2p.cmd"
    # The Windows layout: <prefix>/node_modules/@peer2peer/cli, run as node <bin script>.
    cli="$FAKE_PREFIX/node_modules/@peer2peer/cli"
    mkdir -p "$cli/dist"
    printf '{ "name": "@peer2peer/cli", "bin": { "p2p": "./dist/bin.js" } }\n' >"$cli/package.json"
    cat "$FAKE_BIN/p2p-template" >"$cli/dist/bin.js" ;;
esac
`,
};
const fakeBin = join(work, "bin");
mkdirSync(fakeBin);
for (const [name, body] of Object.entries(FAKES)) {
  writeFileSync(join(fakeBin, name), body);
  chmodSync(join(fakeBin, name), 0o755);
}
writeFileSync(join(fakeBin, "p2p-template"), FAKE_P2P);

let n = 0;
// A fresh prefix and log for one run.
function sandbox() {
  const dir = join(work, `run${++n}`);
  mkdirSync(join(dir, "prefix", "lib"), { recursive: true });
  mkdirSync(join(dir, "prefix", "bin"), { recursive: true });
  const log = join(dir, "log");
  writeFileSync(log, "");
  return { dir, prefix: join(dir, "prefix"), log, calls: () => readFileSync(log, "utf8") };
}

function sh(args, env = {}, box = sandbox()) {
  const r = spawnSync("sh", [SH, ...args], {
    cwd: work,
    env: { PATH: `${fakeBin}:/usr/bin:/bin`, HOME: work, FAKE_BIN: fakeBin, FAKE_LOG: box.log, FAKE_PREFIX: box.prefix, P2P_INSTALL_TEST: "1", P2P_DETECT_TTY: "none", ...env },
    encoding: "utf8",
    input: "",
  });
  return { code: r.status, out: r.stdout, err: r.stderr, all: r.stdout + r.stderr, calls: box.calls(), box };
}

const INSTALL = "install -g --ignore-scripts --no-fund --no-audit @peer2peer/cli@0.1.1 @peer2peer/ext-ix@0.1.1";

// ---- install.sh -----------------------------------------------------------

test("install.sh is shellcheck-clean as POSIX sh", (t) => {
  if (!tool("shellcheck", t)) return;
  const r = spawnSync("shellcheck", ["-s", "sh", SH], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});

test("install.sh parses under every available POSIX shell, and a truncated download runs nothing", () => {
  for (const shell of ["sh", "dash", "bash", "busybox"].filter(has)) {
    const args = shell === "busybox" ? ["sh", "-n", SH] : ["-n", SH];
    const r = spawnSync(shell, args, { encoding: "utf8" });
    assert.equal(r.status, 0, `${shell}: ${r.stderr}`);
  }
  const text = readFileSync(SH, "utf8");
  const lines = text.trimEnd().split("\n");
  const last = '{ main "$@"; }';
  assert.equal(lines.at(-1), last);
  assert.equal(lines.filter((l) => /^\{ main "/.test(l)).length, 1);
  // Cut the download at every byte of the last line (and just before it): nothing runs.
  const head = text.slice(0, text.lastIndexOf(last));
  for (let k = 0; k < last.length; k++) {
    const file = join(work, `truncated-${k}.sh`);
    writeFileSync(file, head + last.slice(0, k));
    const box = sandbox();
    const r = spawnSync("sh", [file, "--dry-run"], {
      env: { PATH: `${fakeBin}:/usr/bin:/bin`, HOME: work, FAKE_BIN: fakeBin, FAKE_LOG: box.log, FAKE_PREFIX: box.prefix },
      encoding: "utf8",
      input: "",
    });
    assert.doesNotMatch(r.stdout, /detected:|dry run|\+ npm/, `cut at ${k}: ${JSON.stringify(last.slice(0, k))}`);
    assert.equal(box.calls(), "", `cut at ${k}`);
  }
});

test("install.sh ignores the P2P_DETECT_* overrides unless P2P_INSTALL_TEST=1", () => {
  const r = sh(["--dry-run"], { P2P_INSTALL_TEST: undefined, P2P_DETECT_NODE: "", P2P_DETECT_OS: "Plan9" });
  assert.equal(r.code, 0, r.all);
  assert.match(r.out, /detected: os=\S+ node=22\.14\.0/);
  assert.doesNotMatch(r.all, /Plan9/);
});

test("install.sh --dry-run prints the exact npm command and runs nothing", () => {
  const r = sh(["--dry-run"]);
  assert.equal(r.code, 0, r.all);
  assert.match(r.out, /dry run: nothing will be changed/);
  assert.match(r.out, /detected: os=\S+ node=22\.14\.0 npm=10\.9\.2/);
  assert.ok(r.out.includes(`+ npm ${INSTALL}\n`), r.out);
  assert.match(r.out, /\/prefix\/bin\/p2p --version {3}\(expect 0\.1\.1\)/);
  assert.match(r.out, /Dry run done: nothing was installed/);
  assert.doesNotMatch(r.calls, /npm install/);
  assert.doesNotMatch(r.calls, /^p2p /m);
  assert.doesNotMatch(r.all, /sudo /);
  // The environment works too, for `curl ... | sh`.
  const env = sh([], { P2P_INSTALL_DRY_RUN: "1" });
  assert.equal(env.code, 0, env.all);
  assert.doesNotMatch(env.calls, /npm install/);
});

test("install.sh installs the pinned packages with npm, checks p2p --version, then hands over to p2p setup", () => {
  const r = sh([], { P2P_DETECT_TTY: "stdin" });
  assert.equal(r.code, 0, r.all);
  assert.ok(r.calls.includes(`npm ${INSTALL}\n`), r.calls);
  assert.match(r.out, /Installed: p2p 0\.1\.1 \(\S+\/prefix\/bin\/p2p\)/);
  // Each command is printed before it runs.
  assert.ok(r.out.indexOf(`+ npm ${INSTALL}`) < r.out.indexOf("Installed:"), r.out);
  assert.match(r.out, /\+ \S+\/prefix\/bin\/p2p setup\n/);
  assert.match(r.calls, /^p2p setup \(stdin-tty=no\)$/m);
  // The fake prefix isn't on PATH: say so.
  assert.match(r.err, /isn't on your PATH/);
});

test("install.sh piped without a terminal skips setup; with /dev/tty it reads answers from there", () => {
  const none = sh([], { P2P_DETECT_TTY: "none" });
  assert.equal(none.code, 0, none.all);
  assert.match(none.out, /No terminal to ask questions on, so setup was skipped\. Next: run `p2p setup`/);
  assert.doesNotMatch(none.calls, /^p2p /m);
  const dev = sh(["--dry-run"], { P2P_DETECT_TTY: "dev" });
  assert.match(dev.out, /\+ \S+\/prefix\/bin\/p2p setup <\/dev\/tty\n/);
  // With no override, `sh` under the test has no terminal at all (stdin is a pipe).
  const auto = sh([], { P2P_DETECT_TTY: undefined });
  assert.equal(auto.code, 0, auto.all);
  if (!/reading answers from \/dev\/tty/.test(auto.out)) assert.match(auto.out, /setup was skipped/);
});

test("install.sh --no-setup never runs p2p setup; a failed setup doesn't fail the install", () => {
  const r = sh(["--no-setup"], { P2P_DETECT_TTY: "stdin" });
  assert.equal(r.code, 0, r.all);
  assert.match(r.out, /Next: run `p2p setup`/);
  assert.doesNotMatch(r.calls, /^p2p setup/m);
  const env = sh([], { P2P_DETECT_TTY: "stdin", P2P_INSTALL_NO_SETUP: "1" });
  assert.doesNotMatch(env.calls, /^p2p setup/m);
  const failed = sh([], { P2P_DETECT_TTY: "stdin", FAKE_SETUP_EXIT: "1" });
  assert.equal(failed.code, 0, failed.all);
  assert.match(failed.err, /p2p setup didn't finish/);
});

test("install.sh without Node 22 or npm prints how to get them, installs nothing and exits 2", () => {
  for (const [what, env] of [
    ["no node", { P2P_DETECT_NODE: "" }],
    ["old node", { FAKE_NODE_VERSION: "20.18.1" }],
    ["no npm", { P2P_DETECT_NPM: "" }],
  ]) {
    for (const os of ["Darwin", "Linux"]) {
      const r = sh([], { ...env, P2P_DETECT_OS: os });
      assert.equal(r.code, 2, `${what} ${os}: ${r.all}`);
      assert.match(r.out, /needs Node\.js 22\.0\.0 or newer, with npm/, what);
      assert.match(r.out, /This script doesn't install Node/);
      assert.match(r.out, /nodejs\.org\/en\/download/);
      assert.match(r.out, /nvm install 22/);
      if (os === "Darwin") assert.match(r.out, /brew install node/);
      assert.doesNotMatch(r.calls, /npm install/, what);
      assert.doesNotMatch(r.out, /^\+ /m, what);
    }
  }
});

test("install.sh never uses sudo: a read-only npm prefix gets the options and exit 3", () => {
  const box = sandbox();
  chmodSync(join(box.prefix, "lib"), 0o555);
  chmodSync(join(box.prefix, "bin"), 0o555);
  const probe = join(box.prefix, "lib", "probe");
  let writable = true;
  try {
    writeFileSync(probe, "");
  } catch {
    writable = false;
  }
  if (writable) return; // running as root: permissions don't apply
  const r = sh([], {}, box);
  assert.equal(r.code, 3, r.all);
  assert.match(r.out, /isn't writable by you/);
  assert.match(r.out, /npm config set prefix "\$HOME\/\.npm-global"/);
  assert.match(r.out, /nvm/);
  assert.doesNotMatch(r.all, /sudo /);
  assert.doesNotMatch(r.calls, /npm install/);
  // A dry run shows the same advice and the plan.
  const dry = sh(["--dry-run"], {}, box);
  assert.equal(dry.code, 0, dry.all);
  assert.match(dry.out, /isn't writable by you/);
  assert.match(dry.out, /^\+ npm install /m);
});

test("install.sh --version takes only an exact version", () => {
  const r = sh(["--version", "0.2.0", "--no-setup"]);
  assert.equal(r.code, 1, r.all); // the fake p2p reports 0.1.1
  assert.ok(r.calls.includes("npm install -g --ignore-scripts --no-fund --no-audit @peer2peer/cli@0.2.0 @peer2peer/ext-ix@0.2.0\n"), r.calls);
  assert.match(r.err, /--version printed '0\.1\.1', expected 0\.2\.0/);
  const ok = sh(["--version=0.2.0", "--no-setup"], { FAKE_P2P_VERSION: "0.2.0" });
  assert.equal(ok.code, 0, ok.all);
  const env = sh(["--dry-run"], { P2P_INSTALL_VERSION: "0.3.0-rc.1" });
  assert.match(env.out, /@peer2peer\/cli@0\.3\.0-rc\.1 @peer2peer\/ext-ix@0\.3\.0-rc\.1/);
  for (const bad of ["latest", "^0.1.1", "0.1", "0.1.1 x", "0.1.1;id", "$(id)", "0.1.1\n0.1.2", ""]) {
    const b = sh(["--version", bad]);
    assert.equal(b.code, 1, JSON.stringify(bad));
    assert.match(b.err, /exact version/, JSON.stringify(bad));
    assert.doesNotMatch(b.calls, /npm install/, JSON.stringify(bad));
  }
  const missing = sh(["--version"]);
  assert.equal(missing.code, 1);
  assert.match(sh(["--bogus"]).err, /unknown option: --bogus/);
});

test("install.sh refuses a prefix npm masked as ***, before installing anything, and never runs npm exec", () => {
  const box = sandbox();
  const shown = box.prefix.replace(/run\d+/, "***");
  for (const args of [["--no-setup"], ["--dry-run"]]) {
    const r = sh(args, { FAKE_PREFIX_SHOWN: shown }, box);
    assert.equal(r.code, 1, r.all);
    assert.match(r.err, /isn't a usable path \(npm hides folder names that look like IDs as \*\*\*\)\. Nothing was installed\./);
    assert.match(r.err, /npm config set prefix .*or install directly: npm install -g @peer2peer\/cli@0\.1\.1 @peer2peer\/ext-ix@0\.1\.1/);
    assert.doesNotMatch(r.calls, /npm install|npm exec/);
    assert.doesNotMatch(r.out, /^\+ /m);
  }
  for (const bad of ["relative/npmg", "/a\n/b"]) {
    const r = sh(["--dry-run"], { FAKE_PREFIX_SHOWN: bad });
    assert.equal(r.code, 1, JSON.stringify(bad));
    assert.match(r.err, /isn't a usable path/);
  }
  assert.doesNotMatch(readFileSync(SH, "utf8").replace(/^#.*$/gm, ""), /npm exec/);
});

test("install.sh fails clearly when npm fails", () => {
  const r = sh(["--no-setup"], { FAKE_NPM_FAIL: "1" });
  assert.notEqual(r.code, 0, r.all);
  assert.doesNotMatch(r.out, /Installed:/);
});

// ---- the pin and the checksums --------------------------------------------

test("install.sh and install.ps1 pin the same version, no newer than the packages", () => {
  const sv = readFileSync(SH, "utf8").match(/^P2P_VERSION="([^"]+)"$/m)?.[1];
  const pv = readFileSync(PS1, "utf8").match(/^\s*\$P2PVersion = '([^']+)'$/m)?.[1];
  assert.ok(sv, "P2P_VERSION in install.sh");
  assert.equal(pv, sv, "install.ps1's $P2PVersion");
  const pkg = JSON.parse(readFileSync(join(repo, "packages/p2p/package.json"), "utf8")).version;
  const num = (v) => v.split(/[.-]/).slice(0, 3).map(Number);
  const [a, b] = [num(sv), num(pkg)];
  assert.ok(a[0] < b[0] || (a[0] === b[0] && (a[1] < b[1] || (a[1] === b[1] && a[2] <= b[2]))), `pin ${sv} is newer than packages/p2p ${pkg}`);
});

test("scripts/install.sha256 is up to date (npm run install-scripts:checksums in packages/relay)", () => {
  const set = SETS.find((s) => s.file.endsWith("/install.sha256"));
  assert.ok(set);
  assert.equal(readFileSync(set.file, "utf8"), checksums(set.scripts));
  assert.match(checksums(set.scripts), /^[0-9a-f]{64} {2}install\.sh\n[0-9a-f]{64} {2}install\.ps1\n$/);
  const r = spawnSync(process.execPath, [join(here, "install-relay-checksums.mjs"), "--check"], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});

// ---- install.ps1 ----------------------------------------------------------

function pwsh(script, env = {}, box = sandbox()) {
  const r = spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-Command", script], {
    cwd: work,
    env: { ...process.env, PATH: `${fakeBin}:${process.env.PATH}`, FAKE_BIN: fakeBin, FAKE_LOG: box.log, FAKE_PREFIX: box.prefix, P2P_INSTALL_TEST: "1", P2P_DETECT_OS: "Windows", P2P_DETECT_TTY: "no", ...env },
    encoding: "utf8",
  });
  const all = (r.stdout + r.stderr).replace(/\x1b\[[0-9;]*m/g, "").replace(/\n\s*\|\s*/g, " ");
  return { code: r.status, out: r.stdout, err: r.stderr, all, calls: box.calls() };
}
const ps = (args = "") => `& '${PS1}' ${args} 6>&1`;

test("install.ps1 is PSScriptAnalyzer-clean, including PowerShell 5.1 syntax", (t) => {
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

test("install.ps1 -DryRun prints the exact npm command and runs nothing", (t) => {
  if (!tool("pwsh", t)) return;
  const r = pwsh(ps("-DryRun"));
  assert.equal(r.code, 0, r.all);
  assert.match(r.out, /dry run: nothing will be changed/);
  assert.match(r.out, /detected: os=Windows node=v22\.14\.0 npm=10\.9\.2/);
  assert.match(r.out, new RegExp(`^\\+ \\S*npm ${INSTALL.replace(/[.^$*+?()[\]{}|\\/]/g, "\\$&")}$`, "m"));
  // The CLI runs as <node> <bin script> by absolute path, never through the p2p.cmd shim.
  assert.match(r.out, /^\+ \S*node \S+@peer2peer.cli.dist.bin\.js --version {3}\(expect 0\.1\.1\)$/m);
  assert.match(r.out, /dry run: not checking that/);
  assert.doesNotMatch(r.out, /\+ \S*p2p\.cmd/);
  assert.match(r.out, /Dry run done: nothing was installed/);
  assert.doesNotMatch(r.calls, /npm install/);
  assert.doesNotMatch(r.all, /RunAs|Administrator/);
});

test("install.ps1 installs the pinned packages, checks p2p --version, then hands over to p2p setup", (t) => {
  if (!tool("pwsh", t)) return;
  const r = pwsh(ps(), { P2P_DETECT_TTY: "yes" });
  assert.equal(r.code, 0, r.all);
  assert.ok(r.calls.includes(`npm ${INSTALL}\n`), r.calls);
  assert.match(r.out, /Installed: p2p 0\.1\.1 \(\S+p2p\.cmd\)/);
  assert.match(r.calls, /^p2p setup /m);
  assert.match(r.out, /^\+ \S*node \S+@peer2peer.cli.dist.bin\.js setup$/m);
  const none = pwsh(ps(), { P2P_DETECT_TTY: "no" });
  assert.equal(none.code, 0, none.all);
  // In PowerShell, `p2p` would find npm's p2p.ps1 shim, which the default execution policy blocks.
  assert.match(none.out, /No console to ask questions on, so setup was skipped\. Next: run `p2p\.cmd setup`/);
  assert.doesNotMatch(none.calls, /^p2p setup/m);
  const noSetup = pwsh(ps("-NoSetup"), { P2P_DETECT_TTY: "yes" });
  assert.equal(noSetup.code, 0, noSetup.all);
  assert.doesNotMatch(noSetup.calls, /^p2p setup/m);
  const mismatch = pwsh(ps("-NoSetup"), { FAKE_P2P_VERSION: "0.0.9" });
  assert.notEqual(mismatch.code, 0, mismatch.all);
  assert.match(mismatch.all, /printed '0\.0\.9', expected 0\.1\.1/);
});

test("install.ps1 works through `| iex` with settings from the environment, and doesn't exit the host", (t) => {
  if (!tool("pwsh", t)) return;
  // Under iex the script runs in the caller's scope: it must leave the caller's variables and
  // functions alone, and work under the caller's StrictMode.
  const r = pwsh(
    `Set-StrictMode -Version Latest; $Version = 'mine'; $DryRun = 'mine'; $NoSetup = 'mine'; ` +
      `Get-Content -Raw '${PS1}' | Invoke-Expression 6>&1; ` +
      `"vars: $Version $DryRun $NoSetup"; "fns: $(@(Get-ChildItem function: | Where-Object Name -match 'P2P|Invoke-Native|Write-Say|Find-Exe').Count)"; 'host still here'`,
    { P2P_INSTALL_DRY_RUN: "1", P2P_INSTALL_VERSION: "0.2.0" },
  );
  assert.equal(r.code, 0, r.all);
  assert.match(r.out, /vars: mine mine mine/);
  assert.match(r.out, /fns: 0/);
  assert.match(r.out, /@peer2peer\/cli@0\.2\.0 @peer2peer\/ext-ix@0\.2\.0/);
  assert.doesNotMatch(r.calls, /npm install/);
  assert.match(r.out, /host still here/);
  const fail = pwsh(`try { Get-Content -Raw '${PS1}' | Invoke-Expression 6>&1 } catch { 'caught: ' + $_ }; 'host still here'`, { P2P_DETECT_NODE: "none" });
  assert.match(fail.out, /caught: Node\.js 22\.0\.0 or newer and npm are needed/);
  assert.match(fail.out, /host still here/);
});

test("install.ps1 truncated anywhere inside its script block runs nothing (as a file and through iex)", (t) => {
  if (!tool("pwsh", t)) return;
  const text = readFileSync(PS1, "utf8");
  const open = text.indexOf("\nif ($true) {\n& {\n") + 1;
  const close = text.lastIndexOf("} @args\n}");
  assert.ok(open > 0 && close > open, "the script is one & { ... } @args block inside if ($true) { ... }");
  assert.ok(text.endsWith("} @args\n}\n"));
  // Just inside the block, a few points in the middle, and every byte of the closing lines
  // (a cut right after "}" or inside "@args" must not run the block either).
  const cuts = [open + 5, open + 15, Math.floor((open + close) / 3), Math.floor((open + close) / 2)];
  for (let k = close - 1; k < text.length - 2; k++) cuts.push(k);
  for (const cut of cuts) {
    const file = join(work, `truncated-${cut}.ps1`);
    writeFileSync(file, text.slice(0, cut));
    for (const how of [`& '${file}' -DryRun 6>&1`, `Get-Content -Raw '${file}' | Invoke-Expression 6>&1`]) {
      const r = pwsh(how);
      assert.doesNotMatch(r.out, /dry run:|detected:|^\+ /m, `cut at ${cut}: ${how}`);
      assert.equal(r.calls, "", `cut at ${cut}: ${how}`);
    }
  }
});

test("install.ps1 ignores the P2P_DETECT_* overrides unless P2P_INSTALL_TEST=1", (t) => {
  if (!tool("pwsh", t)) return;
  // On Linux, without the test switch, the real OS check wins over P2P_DETECT_OS=Windows.
  const r = pwsh(ps("-DryRun"), { P2P_INSTALL_TEST: undefined });
  assert.notEqual(r.code, 0, r.all);
  assert.match(r.all, /use install\.sh .*\(detected: other\)/);
  assert.doesNotMatch(r.calls, /npm install/);
});

test("install.ps1 without Node 22 or npm prints how to get them (winget) and installs nothing", (t) => {
  if (!tool("pwsh", t)) return;
  for (const env of [{ P2P_DETECT_NODE: "none" }, { P2P_DETECT_NODE: "v20.18.1" }, { P2P_DETECT_NPM: "none" }]) {
    const r = pwsh(ps(), env);
    assert.notEqual(r.code, 0, r.all);
    assert.match(r.out, /winget install OpenJS\.NodeJS\.LTS/);
    assert.match(r.out, /nodejs\.org\/en\/download/);
    assert.match(r.out, /This script doesn't install Node/);
    assert.doesNotMatch(r.calls, /npm install/);
    assert.doesNotMatch(r.out, /^\+ /m);
  }
});

test("install.ps1 refuses a prefix npm masked as ***, before installing anything, and never runs npm exec", (t) => {
  if (!tool("pwsh", t)) return;
  const box = sandbox();
  const shown = box.prefix.replace(/run\d+/, "***");
  for (const args of ["-NoSetup", "-DryRun"]) {
    const r = pwsh(ps(args), { FAKE_PREFIX_SHOWN: shown }, box);
    assert.notEqual(r.code, 0, r.all);
    assert.match(r.all, /isn't a usable path \(npm hides folder names that look like IDs as \*\*\*\)\. Nothing was installed\./);
    assert.match(r.all, /or install directly: npm install -g @peer2peer\/cli@0\.1\.1 @peer2peer\/ext-ix@0\.1\.1/);
    assert.doesNotMatch(r.calls, /npm install|npm exec/);
    assert.doesNotMatch(r.out, /^\+ /m);
  }
  for (const bad of ["relative/npmg", "/a\n/b"]) {
    const r = pwsh(ps("-DryRun"), { FAKE_PREFIX_SHOWN: bad });
    assert.notEqual(r.code, 0, JSON.stringify(bad));
    assert.match(r.all, /isn't a usable path/);
  }
  assert.doesNotMatch(readFileSync(PS1, "utf8").replace(/^\s*#.*$/gm, ""), /npm exec|'exec'/);
});

test("install.ps1 never elevates: an unwritable npm prefix gets the options and stops", (t) => {
  if (!tool("pwsh", t)) return;
  const r = pwsh(ps(), { P2P_DETECT_PREFIX_WRITABLE: "no" });
  assert.notEqual(r.code, 0, r.all);
  assert.match(r.out, /isn't writable by you/);
  assert.match(r.out, /npm config set prefix "\$env:APPDATA\\npm"/);
  assert.doesNotMatch(r.calls, /npm install/);
  assert.doesNotMatch(r.all, /RunAs/);
});

test("install.ps1 -Version takes only an exact version; other systems are pointed at install.sh", (t) => {
  if (!tool("pwsh", t)) return;
  for (const bad of ["latest", "^0.1.1", "0.1", "0.1.1 x", "0.1.1;id", "0.1.1`n0.1.2", "0.1.1`n"]) {
    const r = pwsh(ps(`-Version "${bad}"`));
    assert.notEqual(r.code, 0, bad);
    assert.match(r.all, /exact version/, bad);
    assert.doesNotMatch(r.calls, /npm/, bad);
  }
  const ok = pwsh(ps("-DryRun -Version 0.2.0"));
  assert.match(ok.out, /@peer2peer\/cli@0\.2\.0 @peer2peer\/ext-ix@0\.2\.0/);
  const linux = pwsh(ps("-DryRun"), { P2P_DETECT_OS: "Linux" });
  assert.notEqual(linux.code, 0);
  assert.match(linux.all, /use install\.sh/);
  assert.ok(existsSync(PS1));
});
