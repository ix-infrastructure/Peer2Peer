// Copyright 2026 Ix Infrastructure Inc.
//
// Malformed HTTP request targets (and methods), written verbatim over TCP to a
// relay process on 127.0.0.1, as plain requests and as WebSocket upgrades.
// After every request: the process is alive, the status is one the relay
// documents, and a JSON error body carries a documented error.

import fc from "fast-check";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RelayProcess } from "../harness/relay-process.js";
import { announce, FUZZ_RUNS, FUZZ_SEED, HTTP_ERRORS, HTTP_STATUSES, jsonError, rawHttp } from "./fuzz-util.js";

const UID = "p:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PIECES = [
  "/", "//", "///", "\\", "%", "%2", "%zz", "%00", "%2F", "%E0%A4%A", "%C0%AF", "..", ".", "v3", "/v3", "identity", "/v3/identity/",
  UID, "tips", "chain", "?", "#", "&", "to=", "n=", "n=-1", "n=1e3", "@", ":", "[", "]", "[::1]", "*", "~", ";", "'", "\"", "<", ">", "|",
  "\t", " ", "\u0000", "\u007f", "é", "日本", "😀", "http:", "https://", "ws://relay.invalid", "/.well-known/p2p-relay.json", "/healthz", "/metrics",
];

/** A request target that an HTTP client could write after the method. */
const target = fc.oneof(
  { arbitrary: fc.array(fc.constantFrom(...PIECES), { minLength: 1, maxLength: 12 }).map((xs) => xs.join("")), weight: 6 },
  { arbitrary: fc.string({ maxLength: 120, unit: "binary" }), weight: 3 },
  { arbitrary: fc.webUrl({ withQueryParameters: true, withFragments: true }), weight: 2 },
  { arbitrary: fc.integer({ min: 1, max: 20_000 }).map((n) => `/v3/identity/${"a".repeat(n)}`), weight: 1 },
  { arbitrary: fc.constantFrom("*", "//", "///", "//x", "http://[", "/v3?x=%"), weight: 1 },
);

const method = fc.oneof({ arbitrary: fc.constantFrom("GET", "HEAD"), weight: 6 }, { arbitrary: fc.constantFrom("POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH", "BREW", "get"), weight: 1 });

interface Req {
  method: string;
  target: string;
  upgrade: boolean;
}

const requests = fc.record({ method, target, upgrade: fc.boolean() });

function wire(r: Req): Buffer {
  const head = [`${r.method} ${r.target} HTTP/1.1`, "Host: 127.0.0.1", "Connection: close"];
  if (r.upgrade) {
    head[2] = "Connection: Upgrade";
    head.push("Upgrade: websocket", "Sec-WebSocket-Version: 13", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==");
  }
  return Buffer.from(`${head.join("\r\n")}\r\n\r\n`, "latin1");
}

/** Targets the WHATWG URL parser refuses relative to the relay's base (the F-1 class). */
export function urlThrows(t: string): boolean {
  try {
    new URL(t, "http://relay.invalid");
    return false;
  } catch {
    return true;
  }
}

let relay: RelayProcess;
const statuses: Record<string, number> = {};

async function ensureRelay(): Promise<void> {
  if (!relay.alive()) relay = await relay.restart();
}

/** One request; returns the problems seen (empty = fine). */
async function check(r: Req): Promise<string[]> {
  await ensureRelay();
  const res = await rawHttp(relay.port, wire(r));
  statuses[String(res.status)] = (statuses[String(res.status)] ?? 0) + 1;
  const problems: string[] = [];
  // Give a crash a moment to surface.
  if (res.status === 0) await new Promise((x) => setTimeout(x, 100));
  if (!relay.alive()) problems.push(`relay exited (${relay.exitCode ?? relay.exitSignal}): ${relay.logs.slice(-3).join(" | ").slice(0, 300)}`);
  else if (res.status === 0 && res.end !== "closed") problems.push(`no response (${res.end})`);
  else if (res.status !== 0 && !HTTP_STATUSES.has(res.status)) problems.push(`status ${res.status} ${jsonError(res.body) ?? ""}`);
  const err = jsonError(res.body);
  if (err !== undefined && !HTTP_ERRORS.has(err)) problems.push(`error "${err}"`);
  return problems;
}

const property = (filter: (r: Req) => boolean) =>
  fc.asyncProperty(requests.filter(filter), async (r) => {
    const problems = await check(r);
    if (problems.length > 0) throw new Error(`${JSON.stringify(r)}: ${problems.join("; ")}`);
  });

beforeAll(async () => {
  relay = await RelayProcess.start({ limits: { httpPerIpPerMinute: 1_000_000_000, connectsPerIpPerMinute: 1_000_000_000 } });
});

afterAll(async () => {
  await relay?.dispose();
});

/** The F-1 repros: targets the WHATWG URL parser refuses relative to the relay's base. */
const F1_TARGETS = ["//", "///", "http://[", "http://[::1", "//[::1"];

describe("input validation: HTTP request targets", () => {
  // Was FINDINGS.md F-1 (fixed before launch: every request-target parse is guarded).
  it("no request target crashes the relay or yields an undocumented status or error", async () => {
    announce("http-targets (all targets)");
    await ensureRelay();
    const logsFrom = relay.logs.length;
    await fc.assert(property(() => true), { seed: FUZZ_SEED, numRuns: FUZZ_RUNS });
    expect(relay.alive()).toBe(true);
    expect(relay.errorLogs().filter((l) => relay.logs.indexOf(l) >= logsFrom)).toEqual([]);
  });

  // F-1 by hand, on every listener: the public port as a plain request and as
  // a WebSocket upgrade, and the metrics listener (plain, and with Upgrade
  // headers, which it has no upgrade handler for).
  it("the F-1 repros (`//`, `http://[`, ...) get a clean 400 on every listener and never take the relay down", async () => {
    await ensureRelay();
    const logsFrom = relay.logs.length;
    const results: string[] = [];
    const problems: string[] = [];
    for (const target of F1_TARGETS) {
      for (const [listener, port, upgrade] of [
        ["public", relay.port, false],
        ["public+upgrade", relay.port, true],
        ["metrics", relay.metricsPort, false],
        ["metrics+upgrade", relay.metricsPort, true],
      ] as const) {
        // 500 ms: a listener that answers an Upgrade request may keep the socket open afterwards.
        const res = await rawHttp(port, wire({ method: "GET", target, upgrade }), 500);
        await new Promise((x) => setTimeout(x, 50));
        const alive = relay.alive();
        results.push(`${listener} ${target} -> ${res.status || res.end}${alive ? "" : " (relay exited)"}`);
        if (!alive) {
          problems.push(`${listener} ${target}: relay exited (${relay.exitCode ?? relay.exitSignal})`);
          await ensureRelay();
        } else if (res.status !== 400) problems.push(`${listener} ${target}: status ${res.status} (${res.end})`);
        const err = jsonError(res.body);
        if (err !== undefined && err !== "bad-request") problems.push(`${listener} ${target}: error "${err}"`);
      }
    }
    console.log(`FUZZ F-1 repros: ${results.join("; ")}`);
    expect(problems).toEqual([]);
    expect(relay.errorLogs().filter((l) => relay.logs.indexOf(l) >= logsFrom)).toEqual([]);
  });

  it("every target the URL parser accepts gets a documented answer and the relay stays up", async () => {
    announce("http-targets (parseable targets)");
    await ensureRelay();
    for (const k of Object.keys(statuses)) delete statuses[k];
    const logsFrom = relay.logs.length;
    await fc.assert(property((r) => !urlThrows(r.target)), { seed: FUZZ_SEED, numRuns: FUZZ_RUNS });
    console.log(`FUZZ http-targets: statuses ${JSON.stringify(statuses)}`);
    expect(relay.alive()).toBe(true);
    expect(await relay.healthz()).toBe(200);
    expect(relay.errorLogs().filter((l) => relay.logs.indexOf(l) >= logsFrom)).toEqual([]);
  });
});
