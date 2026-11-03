#!/usr/bin/env node
// Copyright 2026 Ix Infrastructure Inc.
//
// Builds the publishable Peer2Peer packages and packs them into .tgz files in
// a staging directory, ready for `npm publish <tarball>`. It never publishes.
//
//   node scripts/release-pack.mjs [--out <dir>] [--clean-install] [--skip-build] [--no-smoke] [--no-provenance]
//
//   --out <dir>        staging directory (default: <repo>/.release). It is wiped
//                      first, so it must not exist yet, be empty, or be one this
//                      script made (it holds a .p2p-release-pack marker)
//   --clean-install    `rm -rf node_modules && npm ci --ignore-scripts` in every
//                      package first (CI)
//   --skip-build       pack the dist/ folders already there
//   --no-smoke         skip installing the tarballs into a temp project and
//                      running p2p / p2p-relay from it
//   --no-provenance    set publishConfig.provenance to false in the tarballs, for
//                      a publish from outside GitHub Actions (docs/releasing.md)
//
// In the repository the packages depend on each other through `file:` paths
// (packages/<dir>, each with its own lockfile). Those can't be published, so
// this script copies each package's allowlisted files (package.json `files`)
// into <out>/pkg/<dir>, adds the repository LICENSE, and rewrites the copy's
// package.json: every internal dependency is pinned to exactly <version>
// (the optional peer on @peer2peer/cli becomes ^<version>), README links
// point at the v<version> tag, and `scripts` and `devDependencies` are dropped. The repository itself is left
// untouched. The packages are versioned in lockstep: all five must carry the
// same version, and so must the version constants compiled into them.
//
// Output: <out>/tarballs/*.tgz plus <out>/tarballs/manifest.json, which lists
// the tarballs in publish order (see docs/releasing.md).

import { execFileSync, spawn } from "node:child_process";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPO_BLOB = "https://github.com/ix-infrastructure/Peer2Peer/blob";
const MARKER = ".p2p-release-pack";

// Build and publish order: every package comes after the packages it depends on.
// `constant` is a version string compiled into the package that must match package.json.
const PACKAGES = [
  { dir: "core", name: "@peer2peer/core" },
  { dir: "relay", name: "@peer2peer/relay" },
  { dir: "codex-bridge", name: "@peer2peer/codex-bridge", constant: ["src/server.ts", /BRIDGE_VERSION = "([^"]+)"/] },
  { dir: "p2p", name: "@peer2peer/cli", constant: ["src/version.ts", /export const VERSION = "([^"]+)"/] },
  { dir: "ext-ix", name: "@peer2peer/ext-ix", constant: ["src/extension.ts", /export const VERSION = "([^"]+)"/] },
];
const INTERNAL = new Set(PACKAGES.map((p) => p.name));

// What a tarball may contain, and what it must never contain.
const ALLOWED_FILE = /^(package\.json|README\.md|LICENSE|SPEC\.md|dist\/.+\.(js|d\.ts))$/;
const FORBIDDEN_FILE = /((^|\/)\.|__tests__|\.test\.|\.spec\.|fixtures?\/|\.test-homes|\.map$|\.env|\.db(-|$)|\.tgz$|\.npmrc|\.pem$|\.key$)/;
const SECRET_PATTERNS = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----\s*[A-Za-z0-9+/=]{32}/, "PEM private key"],
  [/\bnpm_[A-Za-z0-9]{36}\b/, "npm token"],
  [/\b(ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{36}\b/, "GitHub token"],
  [/\bgithub_pat_[A-Za-z0-9_]{60,}/, "GitHub fine-grained token"],
  [/\bAKIA[0-9A-Z]{16}\b/, "AWS access key"],
  [/\bAIza[0-9A-Za-z_-]{35}\b/, "Google API key"],
  [/\bsk-(proj-|ant-)?[A-Za-z0-9_-]{32,}/, "OpenAI/Anthropic key"],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}/, "Slack token"],
  [/\bsk_live_[A-Za-z0-9]{20,}/, "Stripe key"],
];

const args = process.argv.slice(2);
const flag = (f) => args.includes(f);
const outArg = args.indexOf("--out");
const out = resolve(outArg >= 0 ? args[outArg + 1] ?? die("--out needs a directory") : join(root, ".release"));
for (const a of args) {
  if (a.startsWith("--") && !["--out", "--clean-install", "--skip-build", "--no-smoke", "--no-provenance"].includes(a)) die(`unknown option ${a}`);
}

function die(msg) {
  console.error(`release-pack: ${msg}`);
  process.exit(1);
}
function step(msg) {
  console.log(`\n==> ${msg}`);
}
function run(cmd, argv, opts = {}) {
  return execFileSync(cmd, argv, { stdio: opts.capture ? ["ignore", "pipe", "inherit"] : "inherit", encoding: "utf8", ...opts });
}
const readJson = (f) => JSON.parse(readFileSync(f, "utf8"));

// 1. Versions: lockstep, and the compiled-in constants agree.
step("checking versions");
const pkgs = PACKAGES.map((p) => {
  const dir = join(root, "packages", p.dir);
  const json = readJson(join(dir, "package.json"));
  if (json.name !== p.name) die(`packages/${p.dir}/package.json is named ${json.name}, expected ${p.name}`);
  return { ...p, path: dir, json };
});
const version = pkgs[0].json.version;
for (const p of pkgs) {
  if (p.json.version !== version) die(`${p.name} is ${p.json.version} but ${pkgs[0].name} is ${version}: the packages are versioned in lockstep (scripts/set-version.mjs)`);
  if (p.constant) {
    const [file, re] = p.constant;
    const m = readFileSync(join(p.path, file), "utf8").match(re);
    if (!m) die(`no version constant found in packages/${p.dir}/${file}`);
    if (m[1] !== version) die(`packages/${p.dir}/${file} says ${m[1]}, package.json says ${version} (scripts/set-version.mjs)`);
  }
}
console.log(`all packages at ${version}`);

// 2. Build, in dependency order.
if (!flag("--skip-build")) {
  for (const p of pkgs) {
    step(`building ${p.name}`);
    if (flag("--clean-install") || !existsSync(join(p.path, "node_modules"))) {
      rmSync(join(p.path, "node_modules"), { recursive: true, force: true });
      // No dependency needs its install scripts to build, test or pack (esbuild,
      // used only by the bundle checks, resolves its platform binary without them).
      run("npm", ["ci", "--ignore-scripts", "--no-audit", "--no-fund"], { cwd: p.path });
    }
    run("npm", ["run", "build"], { cwd: p.path });
  }
}

// 3. Stage a publishable copy of each package and pack it.
// The output directory is wiped, so it must be one this script owns.
if (out !== join(root, ".release") && existsSync(out)) {
  if (!statSync(out).isDirectory()) die(`--out ${out} is not a directory`);
  if (readdirSync(out).length > 0 && !existsSync(join(out, MARKER))) {
    die(`--out ${out} is not empty and wasn't made by this script (no ${MARKER} in it): refusing to wipe it`);
  }
}
rmSync(out, { recursive: true, force: true });
const tarDir = join(out, "tarballs");
mkdirSync(tarDir, { recursive: true });
writeFileSync(join(out, MARKER), "Staging directory of scripts/release-pack.mjs; wiped on every run.\n");
const results = [];
for (const p of pkgs) {
  step(`staging ${p.name}`);
  const stage = join(out, "pkg", p.dir);
  mkdirSync(stage, { recursive: true });
  const json = structuredClone(p.json);
  if (!Array.isArray(json.files)) die(`${p.name} has no "files" allowlist`);
  for (const entry of json.files) {
    if (entry.startsWith("!") || entry === "LICENSE") continue;
    const src = join(p.path, entry);
    if (!existsSync(src)) {
      if (entry === "README.md") die(`${p.name} has no README.md`);
      die(`${p.name}: "${entry}" is in files but doesn't exist (did the build run?)`);
    }
    cpSync(src, join(stage, entry), { recursive: true });
  }
  cpSync(join(root, "LICENSE"), join(stage, "LICENSE"));
  // Relative links in a README break on npmjs.com: point them at the repository.
  const readme = join(stage, "README.md");
  writeFileSync(
    readme,
    readFileSync(readme, "utf8").replace(/\]\((?!https?:|#|mailto:)([^)\s]+)\)/g, (_, rel) => {
      const abs = new URL(rel, `${REPO_BLOB}/v${version}/packages/${p.dir}/`).href;
      return `](${abs})`;
    }),
  );
  for (const field of ["dependencies", "peerDependencies", "optionalDependencies"]) {
    for (const [dep, spec] of Object.entries(json[field] ?? {})) {
      // Lockstep releases: a package runs with exactly the core (and bridge) it was
      // tested with. The optional, type-only peer stays a caret range.
      if (INTERNAL.has(dep)) json[field][dep] = field === "peerDependencies" ? `^${version}` : version;
      else if (/^(file|link|workspace|git|github):|^\.{0,2}\//.test(spec)) die(`${p.name} ${field}.${dep} is "${spec}": not publishable`);
    }
  }
  delete json.scripts;
  delete json.devDependencies;
  if (flag("--no-provenance")) json.publishConfig = { ...json.publishConfig, provenance: false };
  writeFileSync(join(stage, "package.json"), `${JSON.stringify(json, null, 2)}\n`);
  for (const bin of Object.values(typeof json.bin === "string" ? { x: json.bin } : json.bin ?? {})) {
    const f = join(stage, bin);
    if (!existsSync(f)) die(`${p.name}: bin ${bin} doesn't exist`);
    if (!readFileSync(f, "utf8").startsWith("#!/usr/bin/env node\n")) die(`${p.name}: bin ${bin} doesn't start with #!/usr/bin/env node`);
    chmodSync(f, 0o755);
  }
  const [packed] = JSON.parse(run("npm", ["pack", "--ignore-scripts", "--json", "--pack-destination", tarDir], { cwd: stage, capture: true }));
  results.push({ ...p, stage, packed, tarball: join(tarDir, packed.filename), staged: json });
}

// 4. Verify every tarball.
step("verifying tarballs");
const problems = [];
for (const r of results) {
  const files = r.packed.files.map((f) => f.path);
  for (const f of files) {
    if (!ALLOWED_FILE.test(f)) problems.push(`${r.name}: unexpected file ${f}`);
    if (FORBIDDEN_FILE.test(f)) problems.push(`${r.name}: forbidden file ${f}`);
  }
  for (const must of ["package.json", "README.md", "LICENSE"]) if (!files.includes(must)) problems.push(`${r.name}: ${must} missing`);
  // Exports, types and bins must point at files that ship.
  const targets = [r.staged.main, r.staged.types, ...Object.values(r.staged.bin ?? {})];
  const walk = (v) => (typeof v === "string" ? targets.push(v) : v && typeof v === "object" && Object.values(v).forEach(walk));
  walk(r.staged.exports);
  for (const t of targets.filter(Boolean)) if (!files.includes(t.replace(/^\.\//, ""))) problems.push(`${r.name}: ${t} is referenced but not in the tarball`);
  // Bins are executable inside the tarball (npm sets this from the bin field; check anyway).
  const listing = run("tar", ["-tvzf", r.tarball], { capture: true });
  for (const bin of Object.values(r.staged.bin ?? {})) {
    const line = listing.split("\n").find((l) => l.trimEnd().endsWith(`package/${bin.replace(/^\.\//, "")}`));
    if (!line || !/^-rwx/.test(line)) problems.push(`${r.name}: bin ${bin} is not executable in the tarball`);
  }
  // The packed manifest: no unpublishable specs, no scripts.
  const extract = mkdtempSync(join(tmpdir(), "p2p-verify-"));
  run("tar", ["-xzf", r.tarball, "-C", extract]);
  const manifest = readJson(join(extract, "package", "package.json"));
  if (manifest.scripts) problems.push(`${r.name}: packed package.json still has scripts`);
  if (manifest.license !== "Apache-2.0") problems.push(`${r.name}: license is ${manifest.license}`);
  for (const field of ["dependencies", "peerDependencies", "optionalDependencies"]) {
    for (const [dep, spec] of Object.entries(manifest[field] ?? {})) {
      if (/^(file|link|workspace):/.test(spec)) problems.push(`${r.name}: ${field}.${dep} = ${spec}`);
      if (field === "dependencies" && INTERNAL.has(dep) && spec !== version) problems.push(`${r.name}: ${dep} is "${spec}", not pinned to ${version}`);
    }
  }
  // Secret patterns in every shipped file.
  const scan = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const f = join(d, e.name);
      if (e.isDirectory()) scan(f);
      else {
        const text = readFileSync(f, "utf8");
        for (const [re, what] of SECRET_PATTERNS) if (re.test(text)) problems.push(`${r.name}: ${f.slice(extract.length + 9)} matches ${what}`);
      }
    }
  };
  scan(join(extract, "package"));
  rmSync(extract, { recursive: true, force: true });
}
if (problems.length) die(`tarball checks failed:\n  ${problems.join("\n  ")}`);
console.log("contents, manifests and secret scan OK");

// 5. Smoke test: install the tarballs into a clean project and run them.
if (!flag("--no-smoke")) {
  step("smoke test: installing the tarballs into a clean temp project");
  const proj = mkdtempSync(join(tmpdir(), "p2p-smoke-"));
  const home = join(proj, "home");
  mkdirSync(home);
  let smokeFailure;
  try {
    writeFileSync(join(proj, "package.json"), JSON.stringify({ name: "p2p-smoke", private: true, type: "module" }));
    run("npm", ["install", "--no-audit", "--no-fund", "--no-package-lock", ...results.map((r) => r.tarball)], { cwd: proj });
    const bin = (b) => join(proj, "node_modules", ".bin", b);
    // Keep the tools away from the real home directory.
    const env = { ...process.env, HOME: home, USERPROFILE: home, P2P_HOME: join(home, ".p2p"), CODEX_HOME: join(home, ".codex") };
    for (const r of results.slice(1)) {
      const dep = join(proj, "node_modules", r.name, "node_modules", "@peer2peer");
      if (existsSync(dep)) throw new Error(`${r.name} got its own nested copy of an @peer2peer package: the pinned ${version} dependencies don't resolve to the staged tarballs`);
    }

    const v = run("npx", ["--no-install", "p2p", "--version"], { cwd: proj, env, capture: true }).trim();
    if (v !== version) throw new Error(`npx p2p --version printed "${v}", expected ${version}`);
    console.log(`npx p2p --version → ${v}`);

    const help = run(bin("p2p-relay"), ["--help"], { cwd: proj, env, capture: true });
    if (!help.startsWith("p2p-relay:")) throw new Error(`p2p-relay --help printed unexpected output`);
    console.log("p2p-relay --help OK");

    const imports = [
      "@peer2peer/core",
      "@peer2peer/core/v3",
      "@peer2peer/core/v3/node",
      "@peer2peer/relay",
      "@peer2peer/codex-bridge",
      "@peer2peer/cli",
      "@peer2peer/ext-ix",
    ];
    run("node", ["--input-type=module", "-e", `for (const m of ${JSON.stringify(imports)}) await import(m);`], { cwd: proj, env });
    console.log(`imports OK: ${imports.join(", ")}`);

    await smokeRelay(bin("p2p-relay"), proj, env);
  } catch (e) {
    smokeFailure = e;
  } finally {
    rmSync(proj, { recursive: true, force: true });
  }
  // Exit only after the temp project is gone (die() skips finally blocks).
  if (smokeFailure) die(smokeFailure.message);
}

// 6. Summary.
const manifestOut = results.map((r) => ({
  name: r.name,
  version,
  tarball: r.packed.filename,
  size: r.packed.size,
  unpackedSize: r.packed.unpackedSize,
  entryCount: r.packed.entryCount,
  integrity: r.packed.integrity,
}));
writeFileSync(join(tarDir, "manifest.json"), `${JSON.stringify({ version, publishOrder: manifestOut }, null, 2)}\n`);
step(`tarballs in ${tarDir} (publish in this order)`);
for (const m of manifestOut) console.log(`  ${m.tarball.padEnd(40)} ${String(m.size).padStart(8)} B packed  ${String(m.unpackedSize).padStart(8)} B unpacked  ${String(m.entryCount).padStart(3)} files`);

async function freePort() {
  return new Promise((res, rej) => {
    const s = createServer();
    s.once("error", rej);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => res(port));
    });
  });
}

async function smokeRelay(relayBin, cwd, baseEnv) {
  const port = await freePort();
  const dbDir = mkdtempSync(join(tmpdir(), "p2p-relay-db-"));
  const env = {
    ...baseEnv,
    HOST: "127.0.0.1",
    PORT: String(port),
    RELAY_URL: `wss://localhost:${port}/v3`, // what clients dial; TLS terminates in front of a real relay
    DB_PATH: join(dbDir, "relay.db"),
    METRICS_PORT: "off",
    LOG_LEVEL: "warn",
  };
  const child = spawn(relayBin, [], { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (d) => (output += d));
  child.stderr.on("data", (d) => (output += d));
  const exited = new Promise((res) => child.once("exit", (code, signal) => res({ code, signal })));
  try {
    let healthy = false;
    for (let i = 0; i < 100 && !healthy; i++) {
      if (child.exitCode !== null) break;
      try {
        healthy = (await fetch(`http://127.0.0.1:${port}/healthz`)).ok;
      } catch {
        await new Promise((r) => setTimeout(r, 100));
      }
    }
    if (!healthy) throw new Error(`relay did not become healthy on 127.0.0.1:${port}\n${output}`);
    const info = await (await fetch(`http://127.0.0.1:${port}/.well-known/p2p-relay.json`)).json();
    if (info.software?.name !== "@peer2peer/relay" || info.software?.version !== version) {
      throw new Error(`relay discovery document reports ${JSON.stringify(info.software)}, expected @peer2peer/relay ${version}`);
    }
    if (!existsSync(env.DB_PATH) || statSync(env.DB_PATH).size === 0) throw new Error("relay didn't create its SQLite database");
    console.log(`p2p-relay started on 127.0.0.1:${port} (healthz OK, SQLite store at DB_PATH)`);
    child.kill("SIGTERM");
    const result = await Promise.race([exited, new Promise((r) => setTimeout(() => r(null), 10_000))]);
    if (!result) throw new Error("relay didn't stop within 10s of SIGTERM");
    if (result.code !== 0) throw new Error(`relay exited with ${result.code ?? result.signal} on SIGTERM\n${output}`);
    console.log("p2p-relay stopped cleanly on SIGTERM");
  } catch (e) {
    child.kill("SIGKILL");
    throw new Error(`relay smoke test: ${e.message}`);
  } finally {
    rmSync(dbDir, { recursive: true, force: true });
  }
}
