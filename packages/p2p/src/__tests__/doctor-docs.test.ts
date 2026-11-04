// Copyright 2026 Ix Infrastructure Inc.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, it, vi } from "vitest";
import { main } from "../cli.js";
import { doctorDocs, formatDoctor, summarize, type Check } from "../doctor.js";
import type { App } from "../app.js";

afterEach(() => { process.exitCode = 0; });

it("links diagnostic families to existing document headings", () => {
  const root = fileURLToPath(new URL("../../../../", import.meta.url));
  for (const id of ["clock", "version", "identity", "device", "relays", "relay:wss://example.test/v3", "published:wss://example.test/v3", "document", "their-document", "document-fork", "document-rotated", "their-rotation", "friendship", "cap-ours", "cap-theirs", "default-circle", "shared:session", "their-session:session", "their-sessions", "publisher", "received", "watch"]) {
    const url = new URL(doctorDocs(id)!);
    const path = url.pathname.replace("/ix-infrastructure/Peer2Peer/blob/main/", "");
    const headings = readFileSync(join(root, path), "utf8").split(/\r?\n/).filter((line) => /^#{1,6} /.test(line));
    const anchors = headings.map((heading) => heading.replace(/^#+ /, "").toLowerCase().replace(/[^\p{L}\p{N}_\-\s]/gu, "").replace(/\s/g, "-"));
    expect(anchors, id).toContain(url.hash.slice(1));
  }
  expect(doctorDocs("unmapped-future-check")).toBeUndefined();
  expect(doctorDocs("constructor")).toBeUndefined();
  expect(doctorDocs("__proto__")).toBeUndefined();
});

it("shows links for failing and unknown checks, without changing successful output", () => {
  const docs = doctorDocs("relay:wss://example.test/v3")!;
  const checks: Check[] = [
    { id: "relay:example", status: "fail", title: "relay", detail: "offline", fix: "check the relay", docs },
    { id: "clock", status: "unknown", title: "clock", detail: "no response", docs: doctorDocs("clock") },
    { id: "identity", status: "ok", title: "identity", detail: "valid", docs: doctorDocs("identity") },
  ];
  const text = formatDoctor({ scope: "device", version: "0.1.0", checks, summary: summarize(checks) });
  expect(text).toContain(`    fix: check the relay\n    see: ${docs}`);
  expect(text).toContain(`    see: ${doctorDocs("clock")}`);
  expect(text).not.toContain(`see: ${doctorDocs("identity")}`);
});

it("preserves docs in CLI JSON and prints the same link in human output", async () => {
  const docs = doctorDocs("relays")!;
  const checks: Check[] = [{ id: "relays", status: "fail", title: "relays", detail: "none", docs }];
  const result = { scope: "device" as const, version: "0.1.0", checks, summary: summarize(checks) };
  const out: string[] = [];
  const app = { close: async () => {} } as unknown as App;
  const deps = { env: {}, io: { out: (line: string) => out.push(line), err: vi.fn() }, makeApp: () => app, ops: { doctor: vi.fn(async () => result) } };
  expect(await main(["doctor", "--json"], deps)).toBe(0);
  expect(JSON.parse(out.pop()!).checks[0].docs).toBe(docs);
  expect(await main(["doctor"], deps)).toBe(0);
  expect(out.pop()).toContain(`    see: ${docs}`);
});
