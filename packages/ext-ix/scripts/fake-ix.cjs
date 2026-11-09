#!/usr/bin/env node
// Copyright 2026 Ix Infrastructure Inc.
//
// A fake `ix` for tests and the soak harness (scripts/soak): logs every call to
// $FAKE_IX_DIR/calls.jsonl and answers from files in FAKE_IX_DIR
// (src/__tests__/harness.ts documents the file names).
const fs = require("node:fs");
const path = require("node:path");
// Its data lives in IX_HOME (the one Ix state variable ext-ix passes on), or FAKE_IX_DIR when run directly.
const dir = process.env.IX_HOME || process.env.FAKE_IX_DIR;
const argv = process.argv.slice(2);
let stdin = "";
try { if (!process.stdin.isTTY) stdin = fs.readFileSync(0, "utf8"); } catch {}
fs.appendFileSync(path.join(dir, "calls.jsonl"), JSON.stringify({ argv, stdin, cwd: process.cwd() }) + "\n");
// Like the real CLI, it prints plugin noise on stderr.
process.stderr.write("ix: failed to load context: cannot add command 'context' as already have command 'context'\n");
const file = (n) => { const p = path.join(dir, n); return fs.existsSync(p) ? fs.readFileSync(p, "utf8") : undefined; };
const cmd = argv[0];
if (cmd === "--version") { console.log("0.12.1"); process.exit(0); }
const key = (t) => String(t).replace(/[\/]/g, "__");
if (cmd === "impact") { const j = file("impact-" + key(argv[1]) + ".json") ?? file("impact.json"); if (!j) { console.error("no such target"); process.exit(1); } process.stdout.write(j); process.exit(0); }
// Footprint: `ix status --root R` (status-<basename R>.json, else status.json, else mapped), `ix overview <file>`.
if (cmd === "status") {
  const r = argv[argv.indexOf("--root") + 1] ?? "";
  const j = file("status-" + path.basename(r) + ".json") ?? file("status.json");
  process.stdout.write(j ?? JSON.stringify({ backend: "ok", graphCompleted: true, lastIngestAt: "2100-01-01T00:00:00.000Z" }));
  process.exit(0);
}
if (cmd === "overview") { const j = file("overview-" + key(argv[1]) + ".json"); if (!j) { console.log(JSON.stringify({ error: "unresolved_target", message: "no" })); process.exit(1); } process.stdout.write(j); process.exit(0); }
if (cmd === "around") {
  const j = file("around-" + key(argv[1]) + ".json");
  process.stdout.write(j ?? JSON.stringify({ path: argv[1], symbols: [], importers: { total: 0, rows: [], tests: 0 } }));
  process.exit(0);
}
// `ix --help`: help.txt when set (an OSS Ix after #916 lists "Memory:", one with Ix Pro a "Pro:"
// section), else an Ix from before #916 (neither).
if (cmd === "--help") { process.stdout.write(file("help.txt") ?? "Usage: ix [options] [command]\n\nSystem:\n  status                Check status\n"); process.exit(0); }
// Where a write goes, as the OSS CLI decides it (ix-cli config.ts getEndpoint): IX_ENDPOINT, else
// config.yaml's `endpoint` (which Ix Pro's login points at the cloud), else the default.
const endpoint = () => {
  if (process.env.IX_ENDPOINT) return process.env.IX_ENDPOINT;
  const m = /^endpoint:\s*"?([^"\n]+)"?\s*$/m.exec(file("config.yaml") ?? "");
  return m ? m[1].trim() : "http://localhost:8090";
};
const display = (e) => { try { const u = new URL(e); return u.origin + u.pathname.replace(/\/+$/, ""); } catch { return "(unparseable endpoint)"; } };
const isLocal = (e) => { try { return ["localhost", "127.0.0.1", "[::1]"].includes(new URL(e).hostname); } catch { return false; } };
// stderr.txt overrides what a write reports (a test of an `ix` that doesn't confirm the local backend).
const reportWrite = () => process.stderr.write(file("stderr.txt") ?? `→ ${isLocal(endpoint()) ? "local backend" : "backend"} ${display(endpoint())}\n`);
if (cmd === "note" && argv.includes("show")) { process.stdout.write(file("note.json") ?? "{}"); process.exit(0); }
if (cmd === "note") {
  fs.appendFileSync(path.join(dir, "notes-written.jsonl"), JSON.stringify({ argv, text: stdin, endpoint: endpoint() }) + "\n");
  reportWrite();
  console.log(JSON.stringify({ id: "note-42", text: stdin, tag: (argv.find((a) => a.startsWith("--tag=")) || "--tag=note").slice(6), nodeIds: [], at: "2026-10-21T00:00:00Z", stale: false }));
  process.exit(0);
}
if (cmd === "session" && argv[2] === "create") {
  fs.appendFileSync(path.join(dir, "sessions-written.jsonl"), JSON.stringify({ argv, endpoint: endpoint() }) + "\n");
  reportWrite();
  const val = (k) => (argv.find((a) => a.startsWith(`--${k}=`)) || "").slice(k.length + 3);
  console.log(JSON.stringify({ sessionId: "sess-" + String(argv[3]).slice(4, 40), name: argv[3], purpose: val("purpose"), actor: val("actor"), actors: [val("actor")], ttlHours: Number(val("ttl")), createdAt: "2026-11-09T00:00:00Z", lastLoadedAt: null }));
  process.exit(0);
}
console.log("RESOLVED " + argv.join(" "));
