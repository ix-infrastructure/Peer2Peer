#!/usr/bin/env node
// Copyright 2026 Ix Infrastructure Inc.
//
// A fake `ix` for tests and the soak harness (scripts/soak): logs every call to
// $FAKE_IX_DIR/calls.jsonl and answers from files in FAKE_IX_DIR
// (src/__tests__/harness.ts documents the file names).
const fs = require("node:fs");
const path = require("node:path");
const dir = process.env.FAKE_IX_DIR;
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
if (cmd === "note" && argv.includes("show")) { process.stdout.write(file("note.json") ?? "{}"); process.exit(0); }
if (cmd === "note") {
  fs.appendFileSync(path.join(dir, "notes-written.jsonl"), JSON.stringify({ argv, text: stdin }) + "\n");
  console.log(JSON.stringify({ id: "note-42", text: stdin, tag: (argv.find((a) => a.startsWith("--tag=")) || "--tag=note").slice(6), nodeIds: [], at: "2026-10-21T00:00:00Z", stale: false }));
  process.exit(0);
}
console.log("RESOLVED " + argv.join(" "));
