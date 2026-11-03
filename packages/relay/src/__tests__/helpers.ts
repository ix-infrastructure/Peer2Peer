// Copyright 2026 Ix Infrastructure Inc.
//
// Test fixtures: v3 objects minted with real Ed25519 keys (so the relay's
// checks run for real), an in-process relay with a fake clock and captured
// logs, and a small WebSocket test client.

import { createCipheriv, randomBytes as nodeRandom } from "node:crypto";
import { b64uEncode, randomBytes, signJws } from "@peer2peer/core";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { WebSocket } from "ws";
import { makeConfig, type RelayConfig, type RelayLimits } from "../config.js";
import {
  createRelayCrypto,
  didFromSpk,
  jwsHash,
  userIdFromIk,
  TYP_CAP,
  TYP_DEVICE,
  TYP_IDENTITY,
  TYP_MSG,
  type RelayCrypto,
} from "../crypto.js";
import { createLogger } from "../log.js";
import { Relay } from "../server.js";
import { MemoryStore, type Store } from "../store.js";

export const RELAY_URL = "wss://relay.test/v3";
export const DAY = 24 * 3600;
export const T0 = Date.UTC(2026, 9, 21, 12, 0, 0);

export const crypto = createRelayCrypto();

// ---------------------------------------------------------------------------
// Identities, devices, objects

export interface Identity {
  ikSecret: Uint8Array;
  ik: Uint8Array;
  userId: string;
}

export function makeIdentity(): Identity {
  const ikSecret = randomBytes(32);
  const ik = ed25519.getPublicKey(ikSecret);
  return { ikSecret, ik, userId: userIdFromIk(ik) };
}

export interface Device {
  identity: Identity;
  spkSecret: Uint8Array;
  spk: Uint8Array;
  kpk: Uint8Array;
  did: string;
  cert: string;
}

export interface CertOverrides {
  iat?: number;
  exp?: number;
  did?: string;
  iss?: string;
  label?: string;
  signWith?: Uint8Array;
  /** Fields added to the payload as is (forward compatibility tests). */
  extra?: Record<string, unknown>;
}

export function signCert(identity: Identity, spk: Uint8Array, kpk: Uint8Array, nowSec: number, o: CertOverrides = {}): string {
  const iat = o.iat ?? nowSec - 60;
  const payload: Record<string, unknown> = {
    iss: o.iss ?? identity.userId,
    ik: b64uEncode(identity.ik),
    did: o.did ?? didFromSpk(spk),
    spk: b64uEncode(spk),
    kpk: b64uEncode(kpk),
    iat,
    exp: o.exp ?? iat + 89 * DAY,
  };
  if (o.label !== undefined) payload.label = o.label;
  Object.assign(payload, o.extra ?? {});
  return signJws(TYP_DEVICE, "ik", payload, o.signWith ?? identity.ikSecret);
}

export function makeDevice(identity: Identity, nowSec: number, o: CertOverrides = {}, spkSecret = randomBytes(32)): Device {
  const spk = ed25519.getPublicKey(spkSecret);
  const kpk = x25519.getPublicKey(randomBytes(32));
  return { identity, spkSecret, spk, kpk, did: didFromSpk(spk), cert: signCert(identity, spk, kpk, nowSec, o) };
}

export function authSig(device: Device, relay: string, nonce: string): string {
  return b64uEncode(ed25519.sign(crypto.relayAuthMessage(relay, nonce), device.spkSecret));
}

/** AES-GCM "sealing" of a plaintext, so stored envelopes carry real ciphertext. */
export function seal(plaintext: string): string {
  const key = nodeRandom(32);
  const iv = nodeRandom(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(plaintext, "utf8"), c.final(), c.getAuthTag()]);
  return b64uEncode(new Uint8Array(ct));
}

export interface EnvelopeOptions {
  kind?: string;
  sid?: string;
  plaintext?: string;
  /** Pads `ct` to make a large envelope. */
  padTo?: number;
  overrides?: Record<string, unknown>;
  signWith?: Uint8Array;
  kid?: string;
  nowMs?: number;
  seq?: number;
}

let seqCounter = 1;

export function makeEnvelope(from: Device, to: { userId: string; did: string }, o: EnvelopeOptions = {}): string {
  const kind = o.kind ?? "msg";
  let ct = seal(o.plaintext ?? "hello");
  if (o.padTo !== undefined && ct.length < o.padTo) ct += "A".repeat(o.padTo - ct.length);
  const payload = {
    v: 3,
    from: from.identity.userId,
    fdid: from.did,
    fcert: from.cert,
    to: to.userId,
    tdid: to.did,
    own: from.identity.userId,
    sid: o.sid ?? (kind === "contact" ? "~contact" : "s_test"),
    seq: o.seq ?? seqCounter++,
    ts: o.nowMs ?? T0,
    n: b64uEncode(randomBytes(24)),
    epk: b64uEncode(x25519.getPublicKey(randomBytes(32))),
    ct,
    kind,
    ...o.overrides,
  };
  return signJws(TYP_MSG, o.kid ?? from.did, payload, o.signWith ?? from.spkSecret);
}

export interface CapOptions {
  sub?: string;
  relays?: string[];
  kinds?: string[];
  uses?: number;
  iat?: number;
  exp?: number;
  capid?: string;
  iss?: string;
  /** Fields added to the payload as is (forward compatibility tests). */
  extra?: Record<string, unknown>;
}

export function makeCap(issuerDevice: Device, nowSec: number, o: CapOptions = {}): { jws: string; capid: string } {
  const capid = o.capid ?? b64uEncode(randomBytes(16));
  const iat = o.iat ?? nowSec - 60;
  const payload: Record<string, unknown> = {
    iss: o.iss ?? issuerDevice.identity.userId,
    sub: o.sub ?? "*",
    cert: issuerDevice.cert,
    capid,
    relays: o.relays ?? [RELAY_URL],
    kinds: o.kinds ?? ["*"],
    iat,
    exp: o.exp ?? iat + 30 * DAY,
  };
  if (o.uses !== undefined) payload.uses = o.uses;
  Object.assign(payload, o.extra ?? {});
  return { jws: signJws(TYP_CAP, issuerDevice.did, payload, issuerDevice.spkSecret), capid };
}

export interface DocOptions {
  ver?: number;
  prev?: string | null;
  merge?: string;
  relays?: string[];
  devices?: string[];
  /** null omits the field. */
  keyholders?: string[] | null;
  iat?: number;
  name?: string;
}

export function makeDoc(identity: Identity, nowSec: number, o: DocOptions = {}): { jws: string; hash: string } {
  const ver = o.ver ?? 1;
  const iat = o.iat ?? nowSec - 60;
  const devices = o.devices ?? [];
  const payload: Record<string, unknown> = {
    iss: identity.userId,
    ik: b64uEncode(identity.ik),
    ver,
    prev: o.prev === undefined ? null : o.prev,
    name: o.name ?? "tester",
    relays: o.relays ?? [RELAY_URL],
    devices,
    keyholders: o.keyholders === undefined ? devices.slice(0, 1) : o.keyholders,
    iat,
    exp: iat + 29 * DAY,
    by: devices[0] ?? "d_aaaaaaaaaaaaaaaaaaaaaaaaaa",
  };
  if (o.merge !== undefined) payload.merge = o.merge;
  if (payload.keyholders === null) delete payload.keyholders;
  const jws = signJws(TYP_IDENTITY, "ik", payload, identity.ikSecret);
  return { jws, hash: jwsHash(jws) };
}

// ---------------------------------------------------------------------------
// In-process relay

export interface Clock {
  t: number;
  now: () => number;
  advance(ms: number): void;
}

export function makeClock(t = T0): Clock {
  const c: Clock = {
    t,
    now: () => c.t,
    advance: (ms: number) => {
      c.t += ms;
    },
  };
  return c;
}

export interface TestRelay {
  relay: Relay;
  port: number;
  /** ws://127.0.0.1:<port>/v3: what the test client dials. */
  url: string;
  http: string;
  clock: Clock;
  logs: string[];
  store: Store;
  nowSec: () => number;
  close(): Promise<void>;
}

export interface StartOptions {
  limits?: Partial<RelayLimits>;
  config?: Partial<Omit<RelayConfig, "limits">>;
  store?: Store;
  crypto?: RelayCrypto;
  clock?: Clock;
}

export async function startRelay(o: StartOptions = {}): Promise<TestRelay> {
  const clock = o.clock ?? makeClock();
  const logs: string[] = [];
  const config = makeConfig(crypto, { relayUrl: RELAY_URL, logLevel: "debug", ...o.config, limits: o.limits });
  const store = o.store ?? new MemoryStore();
  const relay = new Relay({
    config,
    store,
    crypto: o.crypto ?? crypto,
    now: clock.now,
    logger: createLogger({ level: "debug", sink: (l) => logs.push(l), now: clock.now }),
  });
  const port = await relay.listen();
  const path = new URL(config.relayUrl).pathname;
  return {
    relay,
    port,
    url: `ws://127.0.0.1:${port}${path}`,
    http: `http://127.0.0.1:${port}`,
    clock,
    logs,
    store,
    nowSec: () => Math.floor(clock.t / 1000),
    close: () => relay.close(),
  };
}

// ---------------------------------------------------------------------------
// WebSocket test client

export type Frame = Record<string, any>;

export class TestClient {
  readonly frames: Frame[] = [];
  private waiters: { pred: (f: Frame) => boolean; resolve: (f: Frame) => void; reject: (e: Error) => void }[] = [];
  hello!: Frame;
  closeCode: number | undefined;
  readonly closed: Promise<number>;

  private constructor(readonly ws: WebSocket) {
    this.closed = new Promise((resolve) => {
      ws.on("close", (code) => {
        this.closeCode = code;
        for (const w of this.waiters) w.reject(new Error(`socket closed (${code}) while waiting`));
        this.waiters = [];
        resolve(code);
      });
    });
    ws.on("message", (data) => {
      const f = JSON.parse(String(data)) as Frame;
      const i = this.waiters.findIndex((w) => w.pred(f));
      if (i >= 0) {
        const [w] = this.waiters.splice(i, 1);
        w.resolve(f);
      } else {
        this.frames.push(f);
      }
    });
    ws.on("error", () => {});
  }

  static async connect(url: string, headers?: Record<string, string>): Promise<TestClient> {
    const ws = new WebSocket(url, { headers });
    const c = new TestClient(ws);
    const hello = c.next((f) => f.t === "hello");
    await new Promise<void>((resolve, reject) => {
      ws.once("open", () => resolve());
      ws.once("error", reject);
      ws.once("unexpected-response", (_req, res) => reject(new Error(`HTTP ${res.statusCode}`)));
    });
    c.hello = await hello;
    return c;
  }

  /** Resolves with the first queued or future frame matching `pred`. */
  next(pred: (f: Frame) => boolean = () => true, timeoutMs = 2000): Promise<Frame> {
    const i = this.frames.findIndex(pred);
    if (i >= 0) return Promise.resolve(this.frames.splice(i, 1)[0]);
    return new Promise((resolve, reject) => {
      const w = {
        pred,
        resolve: (f: Frame) => {
          clearTimeout(timer);
          resolve(f);
        },
        reject: (e: Error) => {
          clearTimeout(timer);
          reject(e);
        },
      };
      const timer = setTimeout(() => {
        this.waiters = this.waiters.filter((x) => x !== w);
        reject(new Error("timed out waiting for a frame"));
      }, timeoutMs);
      this.waiters.push(w);
    });
  }

  send(f: Frame | string): void {
    this.ws.send(typeof f === "string" ? f : JSON.stringify(f));
  }

  /** Sends a frame carrying `id` and resolves with the reply that echoes it. */
  async request(f: Frame): Promise<Frame> {
    const id = f.id ?? `r${Math.random().toString(36).slice(2)}`;
    const reply = this.next((x) => x.id === id);
    this.send({ ...f, id });
    return reply;
  }

  async auth(device: Device, relay = this.hello.relay as string): Promise<Frame> {
    const reply = this.next((f) => f.t === "ok" || f.t === "error");
    this.send({ t: "auth", cert: device.cert, sig: authSig(device, relay, this.hello.nonce) });
    return reply;
  }

  /** Collects `env` frames for `ms` milliseconds. */
  async drainEnvs(ms = 150): Promise<Frame[]> {
    await sleep(ms);
    const envs = this.frames.filter((f) => f.t === "env");
    for (const e of envs) this.frames.splice(this.frames.indexOf(e), 1);
    return envs;
  }

  close(): Promise<number> {
    this.ws.close();
    return this.closed;
  }
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Connects and authenticates `device`. */
export async function authed(r: TestRelay, device: Device): Promise<TestClient> {
  const c = await TestClient.connect(r.url);
  const ok = await c.auth(device);
  if (ok.t !== "ok") throw new Error(`auth failed: ${JSON.stringify(ok)}`);
  return c;
}

/** Finds a PoW nonce for `env` (test sizes only: bits ≤ 12). */
export function solvePow(env: string, bits: number): string {
  const bytes = new TextEncoder().encode(env);
  for (let i = 0; ; i++) {
    const nonce = new Uint8Array(8);
    new DataView(nonce.buffer).setUint32(4, i);
    if (crypto.powOk(bytes, nonce, bits)) return b64uEncode(nonce);
  }
}
