// Copyright 2026 Ix Infrastructure Inc.
//
// Malformed, truncated, mutated and oversized WebSocket frames against a relay
// process on 127.0.0.1, on an authenticated and an unauthenticated connection.
// After every frame: the process is alive, every frame the relay sent is a
// documented one with a documented error code, and the connection either still
// answers a probe or closed with a documented close code.

import fc from "fast-check";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { WebSocket, type RawData } from "ws";
import { authSig, makeCap, makeDoc, type Device } from "../../src/__tests__/helpers.js";
import { newDevice, sendFrame } from "../harness/load.js";
import { RelayProcess } from "../harness/relay-process.js";
import { announce, FUZZ_RUNS, FUZZ_SEED, WS_CLOSE_CODES, WS_ERROR_CODES, WS_FRAME_TYPES } from "./fuzz-util.js";

const FRAME_BYTES = 96 * 1024;
const BIG = 1_000_000_000;
const limits = {
  framesPerConnPerMinute: BIG,
  connectsPerIpPerMinute: BIG,
  authsPerIpPerMinute: BIG,
  newDevicesPerIpPerDay: BIG,
  linkOpsPerIpPerMinute: BIG,
  sendsPerMinute: BIG,
  sendBytesPerConnPerMinute: BIG,
  sendBytesPerIpPerMinute: BIG,
  sourceMaxBytes: BIG,
  identityPublishPerIssPerHour: BIG,
  identityPublishPerIpPerHour: BIG,
  revokesPerConnPerMinute: BIG,
  revokesPerIssPerHour: BIG,
  linkOpenPerIssPerHour: BIG,
  linkOpenPerIpPerHour: BIG,
  maxConnectionsPerIp: 1000,
  frameBytes: FRAME_BYTES,
};

// ---------------------------------------------------------------------------
// A raw client that records every frame and the close code

class FuzzConn {
  frames: Record<string, unknown>[] = [];
  nonJson: string[] = [];
  closeCode: number | undefined;
  hello!: Record<string, unknown>;
  private wake?: () => void;

  private constructor(readonly ws: WebSocket) {
    ws.on("message", (d: RawData) => {
      const text = String(d);
      try {
        this.frames.push(JSON.parse(text) as Record<string, unknown>);
      } catch {
        this.nonJson.push(text.slice(0, 200));
      }
      this.wake?.();
    });
    ws.on("close", (code) => {
      this.closeCode = code;
      this.wake?.();
    });
    ws.on("error", () => {});
  }

  static async open(url: string): Promise<FuzzConn> {
    const ws = new WebSocket(url);
    const c = new FuzzConn(ws);
    await new Promise<void>((resolve, reject) => {
      ws.once("open", () => resolve());
      ws.once("error", reject);
    });
    c.hello = await c.until((f) => f.t === "hello");
    return c;
  }

  get isOpen(): boolean {
    return this.ws.readyState === WebSocket.OPEN;
  }

  /** Resolves with the first recorded frame matching `pred`, or undefined once the socket closes or time runs out. */
  async until(pred: (f: Record<string, unknown>) => boolean, timeoutMs = 3000): Promise<Record<string, unknown>> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const f = this.frames.find(pred);
      if (f) return f;
      if (this.closeCode !== undefined || Date.now() > deadline) return undefined as never;
      await new Promise<void>((r) => {
        this.wake = r;
        setTimeout(r, 50);
      });
    }
  }

  async closed(timeoutMs = 3000): Promise<number | undefined> {
    const deadline = Date.now() + timeoutMs;
    while (this.closeCode === undefined && Date.now() < deadline) await new Promise((r) => setTimeout(r, 10));
    return this.closeCode;
  }
}

// ---------------------------------------------------------------------------
// Inputs

interface Payload {
  data: string | Buffer;
  binary: boolean;
  kind: string;
}

const FRAME_TYPES = ["auth", "send", "ack", "revoke", "identity", "link-open", "link-put", "link-get", "env", "hello", "ok", ""];
const KEYS = ["t", "id", "cert", "sig", "to", "tdid", "env", "cap", "pow", "rids", "capid", "doc", "lid", "slot", "data"];

/** Valid frames to mutate; filled in once the relay is up. */
const templates: string[] = [];

const jsonText = fc.json({ maxDepth: 4 }).map((data): Payload => ({ data, binary: false, kind: "json" }));

const structured = fc
  .record({
    t: fc.oneof(fc.constantFrom(...FRAME_TYPES), fc.string({ maxLength: 40 })),
    id: fc.option(fc.oneof(fc.string({ maxLength: 200 }), fc.integer(), fc.constant(null)), { nil: undefined }),
    fields: fc.dictionary(fc.constantFrom(...KEYS), fc.jsonValue({ maxDepth: 3 }), { maxKeys: 6 }),
  })
  .map(({ t, id, fields }): Payload => {
    const f: Record<string, unknown> = { ...fields, t };
    if (id !== undefined) f.id = id;
    return { data: JSON.stringify(f), binary: false, kind: "structured" };
  });

const mutated = fc
  .record({
    template: fc.nat(),
    op: fc.constantFrom("truncate", "replace", "insert", "duplicate"),
    at: fc.nat(),
    junk: fc.string({ maxLength: 16, unit: "binary" }),
  })
  .map(({ template, op, at, junk }): Payload => {
    const s = templates[template % templates.length];
    const i = at % (s.length + 1);
    const out =
      op === "truncate" ? s.slice(0, i) : op === "replace" ? s.slice(0, i) + junk + s.slice(i + junk.length) : op === "insert" ? s.slice(0, i) + junk + s.slice(i) : s.slice(0, i) + s.slice(i / 2);
    return { data: out, binary: false, kind: `mutated-${op}` };
  });

const oversized = fc.integer({ min: 1, max: 4096 }).map((extra): Payload => ({ data: "x".repeat(FRAME_BYTES + extra), binary: false, kind: "oversized" }));

const nearLimit = fc.integer({ min: 0, max: 2048 }).map(
  (short): Payload => ({ data: JSON.stringify({ t: "send", id: "n", to: "p:x", tdid: "d_x", env: "a".repeat(FRAME_BYTES - 80 - short) }), binary: false, kind: "near-limit" }),
);

const binary = fc.uint8Array({ maxLength: 512 }).map((b): Payload => ({ data: Buffer.from(b), binary: true, kind: "binary" }));

const deep = fc.integer({ min: 1, max: 40_000 }).map((n): Payload => ({ data: `${"[".repeat(n)}${"]".repeat(n)}`, binary: false, kind: "deep" }));

const fakeJws = fc
  .tuple(fc.base64String({ maxLength: 200 }), fc.base64String({ maxLength: 400 }), fc.base64String({ maxLength: 100 }), fc.constantFrom("send", "auth", "identity"))
  .map(([h, p, s, t]): Payload => {
    const jws = `${h}.${p}.${s}`.replace(/=/g, "");
    const f = t === "send" ? { t, id: "j", to: "p:x", tdid: "d_x", env: jws, cap: jws } : t === "auth" ? { t, cert: jws, sig: s } : { t, id: "j", doc: jws };
    return { data: JSON.stringify(f), binary: false, kind: "fake-jws" };
  });

const payloads = fc.oneof(
  { arbitrary: jsonText, weight: 2 },
  { arbitrary: structured, weight: 4 },
  { arbitrary: mutated, weight: 4 },
  { arbitrary: fakeJws, weight: 2 },
  { arbitrary: binary, weight: 1 },
  { arbitrary: deep, weight: 1 },
  { arbitrary: nearLimit, weight: 1 },
  { arbitrary: oversized, weight: 1 },
);

// ---------------------------------------------------------------------------

let relay: RelayProcess;
let device: Device;
let authed: FuzzConn;
let unauth: FuzzConn;
const kinds: Record<string, number> = {};
const closes: Record<string, number> = {};

async function openAuthed(): Promise<FuzzConn> {
  const c = await FuzzConn.open(relay.url);
  c.ws.send(JSON.stringify({ t: "auth", id: "a", cert: device.cert, sig: authSig(device, String(c.hello.relay), String(c.hello.nonce)) }));
  const ok = await c.until((f) => f.id === "a");
  if (ok?.t !== "ok") throw new Error(`fuzz: auth failed ${JSON.stringify(ok)}`);
  c.frames = [];
  return c;
}

let probeN = 0;

/** Sends one payload on `conn`, then a probe; returns the problems seen (empty = fine). */
async function exercise(conn: FuzzConn, p: Payload, isAuthed: boolean): Promise<string[]> {
  const problems: string[] = [];
  conn.frames = [];
  conn.ws.send(p.data, { binary: p.binary });
  const id = `probe-${probeN++}`;
  if (conn.isOpen) conn.ws.send(JSON.stringify({ t: "zz-probe", id }));
  const reply = await conn.until((f) => f.id === id);
  if (reply) {
    const want = isAuthed ? "bad-request" : "auth-required";
    if (reply.t !== "error" || reply.code !== want) problems.push(`probe answered ${JSON.stringify(reply)}`);
  } else {
    const code = await conn.closed();
    closes[String(code)] = (closes[String(code)] ?? 0) + 1;
    if (code === undefined) problems.push("no probe reply and no close");
    else if (!WS_CLOSE_CODES.has(code)) problems.push(`closed with undocumented code ${code}`);
  }
  for (const f of conn.frames) {
    if (!WS_FRAME_TYPES.has(String(f.t))) problems.push(`undocumented frame ${JSON.stringify(f).slice(0, 200)}`);
    if (f.t === "error" && !WS_ERROR_CODES.has(f.code as never)) problems.push(`undocumented error code ${String(f.code)}`);
  }
  if (conn.nonJson.length > 0) problems.push(`non-JSON frame ${conn.nonJson[0]}`);
  return problems;
}

beforeAll(async () => {
  relay = await RelayProcess.start({ limits });
  device = newDevice(relay);
  const rcpt = newDevice(relay);
  // Templates: one valid frame of each kind.
  const cap = makeCap(rcpt, relay.nowSec()).jws;
  templates.push(
    JSON.stringify({ ...sendFrame(device, rcpt, { cap }), id: "s" }),
    JSON.stringify({ t: "identity", id: "i", doc: makeDoc(device.identity, relay.nowSec(), { devices: [device.did] }).jws }),
    JSON.stringify({ t: "ack", id: "k", rids: ["AAAAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBBBB"] }),
    JSON.stringify({ t: "link-put", id: "l", lid: "abcdefghijklmnopqrstuvwxyz", slot: "req", data: "hello" }),
    JSON.stringify({ t: "auth", id: "a", cert: device.cert, sig: "A".repeat(86) }),
    JSON.stringify({ t: "revoke", id: "r", capid: "AAAAAAAAAAAAAAAAAAAAAA" }),
  );
  authed = await openAuthed();
  unauth = await FuzzConn.open(relay.url);
});

afterAll(async () => {
  authed?.ws.terminate();
  unauth?.ws.terminate();
  await relay?.dispose();
});

describe("input validation: WebSocket frames", () => {
  it("malformed, truncated, mutated and oversized frames never crash the relay or yield undocumented answers", async () => {
    announce("ws-frames");
    await fc.assert(
      fc.asyncProperty(payloads, async (p) => {
        kinds[p.kind] = (kinds[p.kind] ?? 0) + 1;
        if (!authed.isOpen) authed = await openAuthed();
        if (!unauth.isOpen) unauth = await FuzzConn.open(relay.url);
        const problems = [...(await exercise(authed, p, true)), ...(await exercise(unauth, p, false))];
        if (!relay.alive()) problems.push(`relay exited (${relay.exitCode ?? relay.exitSignal})`);
        if (problems.length > 0) throw new Error(`${p.kind}: ${problems.join("; ")}`);
      }),
      { seed: FUZZ_SEED, numRuns: FUZZ_RUNS, endOnFailure: true },
    );
    console.log(`FUZZ ws-frames: inputs by kind ${JSON.stringify(kinds)}; closes ${JSON.stringify(closes)}`);
    expect(relay.alive()).toBe(true);
    expect(await relay.healthz()).toBe(200);
    // Caught handler failures are bugs too, even when the process survives them.
    expect(relay.errorLogs()).toEqual([]);
  });
});
