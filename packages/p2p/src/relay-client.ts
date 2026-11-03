// Copyright 2026 Ix Infrastructure Inc.
//
// The relay client (docs/protocol.md §5): one WebSocket per relay, the §5.2
// hello check and device-signature auth, request/reply by `id`, and a pool
// over all of the user's relays (1–5) that
//  - receives from every one of them (each delivery is handed to one
//    serial handler and acked on the connection it came from once handled;
//    multi-relay copies are deduplicated by the receiver's replay window);
//  - sends each envelope to up to 3 of the recipient's relays, with a cap
//    or, for a cap-less `contact`, proof of work, and reports which relays
//    took it ("delivered via N relays");
//  - publishes identity documents (back-filling a relay that is behind),
//    revokes caps, and runs the pre-auth link mailbox operations;
//  - reconnects with backoff (1 s → 30 s) when asked to (`watch`).
// The HTTP document API (§5.6) is here too: head, tips and chain fetches.

import { AsyncLocalStorage } from "node:async_hooks";
import { get as httpGet } from "node:http";
import { get as httpsGet } from "node:https";
import type { LookupFunction } from "node:net";
import WebSocket from "ws";
import { checkHelloRelay, signRelayAuth, solvePow, MAX_RELAY_FRAME_BYTES } from "@peer2peer/core/v3";
import type { Transport, TransportResolver } from "./config.js";
import { CliError } from "./errors.js";
import { PRIVATE_RESOLVE_MARK } from "./shortcode.js";
import { debug, hostKey, step, type Progress } from "./progress.js";

export interface DeviceAuth {
  cert: string;
  signingSecretKey: Uint8Array;
  /** Members-only relays: an admission key from a redeemed code, by relay (sent in `auth.admit`). */
  admits?: Readonly<Record<string, string>>;
  /** The relay admitted this identity with the key: it isn't needed again. */
  onAdmitted?: (relay: string) => void;
}

/** A members-only relay's circle (its auth reply): members push newer versions to it. */
export interface RelayCircle {
  cid: string;
  ver: number;
}

export interface Hello {
  relay: string;
  nonce: string;
  pow: number;
  limits?: Record<string, number>;
}

export type Frame = Record<string, unknown> & { t: string };

/** Close codes the relay uses (packages/relay CLOSE). */
export const CLOSE_AUTH_FAILED = 4001;
/** The device certificate expired: reconnect with a renewed one (R4-L1). */
export const CLOSE_CERT_EXPIRED = 4003;

const REQUEST_TIMEOUT_MS = 15_000;
/** How long a short command waits for a relay's closing frame on its way out (pre-release review L1). */
export const CLOSE_WAIT_MS = 1000;

/** review M2: a relay's error code, as far as we repeat it: `[a-z-]{1,32}`, else "relay-error". */
export function relayCode(v: unknown): string {
  return typeof v === "string" && /^[a-z-]{1,32}$/.test(v) ? v : "relay-error";
}

export class RelayConnection {
  private ws?: WebSocket;
  hello?: Hello;
  authed = false;
  /** Authenticated, but only for identity publishes (see packages/relay ConnAuth.restricted). */
  restricted = false;
  /** Set by a members-only relay that follows a circle: which, and the version it holds (0: none yet). */
  circle?: RelayCircle;
  /**
   * The relay said `caught-up` (§5.4): everything stored for this mailbox when it authenticated
   * has been delivered on this connection. Relays from before it never say so.
   */
  caughtUp = false;
  closeCode?: number;
  private pending = new Map<string, { resolve: (f: Frame) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>();
  private nextId = 1;
  private closedResolve!: (code: number) => void;
  readonly closed: Promise<number>;

  constructor(
    readonly relay: string,
    readonly transport: Transport,
    private readonly opts: {
      auth?: DeviceAuth;
      /** Accept a restricted connection (a device the relay's document doesn't list yet: §2.7 restore). */
      allowRestricted?: boolean;
      timeoutMs: number;
      /** Per request (default 15 s). */
      requestTimeoutMs?: number;
      progress?: Progress;
      /** Appended to the connect step's label, e.g. " (relay 1/2)". */
      what?: string;
      /** Resolves the host the socket dials (a code's relay: privateGuardLookup). */
      lookup?: import("node:net").LookupFunction;
      /** Remember an unreachable host for the rest of the command (not in `watch`, which retries). */
      rememberUnreachable?: boolean;
      onEnv?: (rid: string, env: string, conn: RelayConnection) => void;
      onCaughtUp?: (conn: RelayConnection) => void;
      onClose?: (code: number, conn: RelayConnection) => void;
    },
  ) {
    this.closed = new Promise((r) => (this.closedResolve = r));
  }

  get isOpen(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  /** Dials, checks `hello.relay` against the canonical URL (H5), and authenticates when a device is given. */
  open(): Promise<void> {
    return step(this.opts.progress, `connecting to ${this.relay}${this.opts.what ?? ""}`, () => this.openInner());
  }

  private async openInner(): Promise<void> {
    const ws = new WebSocket(this.transport.ws, {
      handshakeTimeout: this.opts.timeoutMs,
      maxPayload: 2 * MAX_RELAY_FRAME_BYTES,
      perMessageDeflate: false,
      ...(this.opts.lookup ? { lookup: this.opts.lookup } : {}),
      // A short command on its way out waits for the relay's closing frame (so the acks it sent
      // are read before the socket goes), but not ws's default 30 s if the relay never answers.
      ...(this.opts.rememberUnreachable !== false ? { closeTimeout: CLOSE_WAIT_MS } : {}),
    });
    this.ws = ws;
    let helloResolve!: (h: Frame) => void;
    const helloP = new Promise<Frame>((r) => (helloResolve = r));
    ws.on("message", (data, isBinary) => {
      if (isBinary) return;
      let f: Frame;
      try {
        f = JSON.parse(String(data)) as Frame;
      } catch {
        return;
      }
      if (typeof f !== "object" || f === null || typeof f.t !== "string") return;
      if (f.t === "hello" && !this.hello) return helloResolve(f);
      if (f.t === "env" && typeof f.rid === "string" && typeof f.env === "string") {
        this.opts.onEnv?.(f.rid, f.env, this);
        return;
      }
      // Sent once after `ok`, behind the backlog. It only ends a wait early: a relay that lies
      // about it can do no more than one that withholds envelopes.
      if (f.t === "caught-up" && f.id === undefined) {
        this.caughtUp = true;
        this.opts.onCaughtUp?.(this);
        return;
      }
      const id = typeof f.id === "string" ? f.id : undefined;
      const p = id !== undefined ? this.pending.get(id) : undefined;
      if (p) {
        this.pending.delete(id!);
        clearTimeout(p.timer);
        p.resolve(f);
      }
    });
    ws.on("error", () => {});
    ws.on("close", (code) => {
      this.closeCode = code;
      this.authed = false;
      for (const p of this.pending.values()) {
        clearTimeout(p.timer);
        p.reject(new CliError("network", `relay ${this.relay} closed the connection (${code})`));
      }
      this.pending.clear();
      this.closedResolve(code);
      this.opts.onClose?.(code, this);
    });
    const timeout = <T>(p: Promise<T>, what: string) =>
      Promise.race([
        p,
        new Promise<T>((_, reject) => setTimeout(() => reject(new CliError("timeout", `${this.relay}: timed out ${what} (after ${Math.round(this.opts.timeoutMs / 1000)}s)`)), this.opts.timeoutMs).unref()),
        this.closed.then((code) => {
          throw new CliError(code === CLOSE_AUTH_FAILED ? "auth_failed" : "network", `${this.relay}: connection closed (${code}) ${what}`);
        }),
      ]);
    const { key, port } = hostKey(this.transport.ws);
    // One clear message when the relay can't be reached at all (no answer to the TCP/TLS dial, a
    // refusal, no route, no DNS), remembered for the rest of the command (see Progress.unreachable).
    let dialed = false;
    const unreachable = (why: string) => {
      const e = new CliError("unreachable", `can't reach ${this.relay} (${why}: check your network or firewall)`);
      if (!dialed && this.opts.rememberUnreachable !== false) this.opts.progress?.unreachable?.set(key, e);
      return e;
    };
    let dialTimer: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        new Promise<void>((resolve, reject) => {
          ws.once("open", () => resolve());
          ws.once("error", (e) => {
            const code = (e as NodeJS.ErrnoException).code ?? "";
            if (code === "ECONNREFUSED") reject(unreachable(`connection refused on port ${port}`));
            else if (code === "ENOTFOUND" || code === "EAI_AGAIN") reject(unreachable(`can't resolve ${new URL(this.transport.ws).hostname}`));
            else if (["EHOSTUNREACH", "ENETUNREACH", "ETIMEDOUT", "EHOSTDOWN"].includes(code) || /handshake has timed out/i.test(e.message)) {
              reject(unreachable(`no response on port ${port} after ${Math.round(this.opts.timeoutMs / 1000)}s`));
            } else reject(new CliError("network", `${this.relay}: ${e.message}`));
          });
          ws.once("unexpected-response", (_req, res) => reject(new CliError("network", `${this.relay}: HTTP ${res.statusCode}`)));
        }),
        new Promise<never>((_, reject) => {
          dialTimer = setTimeout(() => reject(unreachable(`no response on port ${port} after ${Math.round(this.opts.timeoutMs / 1000)}s`)), this.opts.timeoutMs);
          dialTimer.unref();
        }),
      ]).finally(() => {
        // The dial is settled: a late timer or socket error must not record this relay as unreachable
        // for the rest of the command (Progress.unreachable) although it answered.
        dialed = true;
        if (dialTimer) clearTimeout(dialTimer);
      });
      const h = await timeout(helloP, "waiting for hello");
      if (typeof h.relay !== "string" || typeof h.nonce !== "string") throw new CliError("bad_relay", `${this.relay}: malformed hello`);
      // §5.2 step 2 (review H5): the relay must name the URL we meant to reach.
      try {
        checkHelloRelay(h.relay, this.relay);
      } catch {
        throw new CliError("relay_mismatch", `${this.relay} introduced itself as another relay; closing`);
      }
      this.hello = { relay: h.relay, nonce: h.nonce, pow: typeof h.pow === "number" ? h.pow : 0, limits: h.limits as Record<string, number> | undefined };
      if (this.opts.auth) {
        const sig = signRelayAuth(this.hello.relay, this.hello.nonce, this.opts.auth.signingSecretKey);
        const admit = this.opts.auth.admits?.[this.relay];
        const r = await timeout(this.request({ t: "auth", cert: this.opts.auth.cert, sig, ...(admit ? { admit } : {}) }), "authenticating");
        if (r.t === "error" && r.code === "not-member") {
          throw new CliError("not_member", `${this.relay} is members-only and doesn't admit this identity: ask a member for an invite code, or its operator to add your userId`);
        }
        if (r.t !== "ok") throw new CliError("auth_failed", `${this.relay} refused this device (${relayCode(r.code ?? r.t)})`);
        if (r.admitted !== undefined) this.opts.auth.onAdmitted?.(this.relay);
        const c = r.circle as { cid?: unknown; ver?: unknown } | undefined;
        if (c && typeof c.cid === "string" && typeof c.ver === "number") this.circle = { cid: c.cid, ver: c.ver };
        if (r.restricted === true && !this.opts.allowRestricted) {
          throw new CliError("auth_failed", `${this.relay} refused this device (not listed in your identity document)`);
        }
        this.restricted = r.restricted === true;
        this.authed = true;
      }
    } catch (e) {
      this.close();
      throw e;
    }
  }

  /** Sends a frame with an `id` and resolves with the reply echoing it. */
  request(frame: Frame, timeoutMs = this.opts.requestTimeoutMs ?? REQUEST_TIMEOUT_MS): Promise<Frame> {
    // The label names the relay and the frame type only (never its contents).
    return step(this.opts.progress, `waiting for ${this.relay} to answer ${frame.t}`, () => this.requestInner(frame, timeoutMs));
  }

  private requestInner(frame: Frame, timeoutMs: number): Promise<Frame> {
    const id = `c${this.nextId++}`;
    return new Promise<Frame>((resolve, reject) => {
      if (!this.isOpen) return reject(new CliError("network", `relay ${this.relay} is not connected`));
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new CliError("timeout", `${this.relay}: no reply to ${frame.t} after ${Math.round(timeoutMs / 1000)}s`));
      }, timeoutMs);
      timer.unref();
      this.pending.set(id, { resolve, reject, timer });
      this.ws!.send(JSON.stringify({ ...frame, id }));
    });
  }

  /** Fire-and-forget (the relay does not reply to `ack`). */
  send(frame: Frame): void {
    if (this.isOpen) this.ws!.send(JSON.stringify(frame));
  }

  close(): void {
    try {
      this.ws?.close();
    } catch {
      // already closed
    }
  }
}

export interface SendTarget {
  relay: string;
  /** The recipient's cap naming this relay; without one only `contact` goes, with PoW. */
  cap?: string;
}

export interface SendResult {
  /** Relays that answered `sent`. */
  sent: string[];
  /**
   * `written`: the envelope went out on the connection before this failed (the relay answered
   * an error, or the reply never came), so it may have been stored all the same. Without it the
   * envelope never left this client (no connection, no capability).
   */
  errors: { relay: string; code: string; written?: boolean }[];
}

export type EnvelopeHandler = (env: string, relay: string) => Promise<"ack" | "keep">;

/** The pool whose envelope handler is running (App.connect uses it: pre-release review M1). */
export const handlerPool = new AsyncLocalStorage<RelayPool>();

export interface PoolOptions {
  /** The user's own relays: connected for receiving. */
  relays: readonly string[];
  transport: TransportResolver;
  /** Read on every (re)connection, so a renewed certificate is used (R4-L1). */
  auth: DeviceAuth | (() => DeviceAuth | Promise<DeviceAuth>);
  /**
   * A relay refused this device (R4-L2): "retry" (with backoff, e.g. the device was linked
   * during a fork and isn't in every branch yet) or "fatal" (revoked). Default: fatal.
   */
  onAuthRefused?: (relay: string) => Promise<"retry" | "fatal">;
  timeoutMs: number;
  /** Per request (default 15 s). */
  requestTimeoutMs?: number;
  progress?: Progress;
  /** How long a drain waits, past its own bound, for handlers already running (default 10 s). */
  handlerGraceMs?: number;
  /** With `reconnect` (a watch): first wait before an envelope answered "keep" is handled again (default 2 s). */
  keepRetryMs?: number;
  onEnvelope?: EnvelopeHandler;
  /** The lookup a connection to `relay` dials through (App.guardRelays: privateGuardLookup), if any. */
  lookupFor?: (relay: string) => import("node:net").LookupFunction | undefined;
  /** Reconnect own relays with backoff (watch). */
  reconnect?: boolean;
  log?: (msg: string) => void;
  /** Every own relay refused this device (revoked): nothing to reconnect to. */
  onFatal?: (reason: string) => void;
  allowRestricted?: boolean;
  /** Every new authenticated connection (own or a recipient's relay). */
  onAuthed?: (conn: RelayConnection) => void;
}

const BACKOFF_MS = [1000, 2000, 4000, 8000, 16000, 30000];
/** §5.8: each envelope goes to at most this many of the recipient's relays. */
export const MAX_SEND_RELAYS = 3;
/** A watch's first wait before handling an envelope it kept again (RelayPool.retryKept). */
export const KEEP_RETRY_MS = 2000;
/** How many times a watch handles a kept envelope again on the same connection. */
export const KEEP_RETRIES = 10;
/** How long a drain waits, past its own bound, for envelope handlers already running. */
export const DRAIN_HANDLER_GRACE_MS = 10_000;

export class RelayPool {
  private readonly conns = new Map<string, RelayConnection>();
  private readonly connecting = new Map<string, Promise<RelayConnection>>();
  private readonly own: Set<string>;
  private readonly fatal = new Set<string>();
  private readonly attempts = new Map<string, number>();
  /** At most one pending reconnect per relay (timers used to double on every failure). */
  private readonly pending = new Map<string, NodeJS.Timeout>();
  /** Connection attempts made, per relay (for diagnostics and tests). */
  readonly dials = new Map<string, number>();
  /** The last failure per own relay, cleared on success. */
  readonly lastError = new Map<string, string>();
  private closing = false;
  private queue: Promise<unknown> = Promise.resolve();
  private inflight = 0;
  private lastEnvAt = 0;
  private timers = new Set<NodeJS.Timeout>();
  /** Envelope handlers queued or running. */
  get busy(): boolean {
    return this.inflight > 0;
  }

  /** stopHandling(): the process is exiting; envelopes not started yet are left on the relays. */
  private stopped = false;

  /**
   * The command gave up on its handlers (App.close past its grace): nothing more is started, so
   * nothing more is claimed and then cut off by the exit. Not acked: the relays keep them. The
   * abandoned handlers send nothing more either (sendEnvelope refuses): their claims went back
   * and the envelope is applied again elsewhere, so a send now (a circle want's answer) would go
   * out twice (pre-release re-review F1).
   */
  stopHandling(): void {
    this.stopped = true;
  }

  /** Wakes a drain waiting on the queue or on a relay's `caught-up`. */
  private wakers = new Set<() => void>();

  constructor(private readonly opts: PoolOptions) {
    this.own = new Set(opts.relays);
  }

  /** Every open, authenticated connection (own relays and recipients'). */
  authedConnections(): RelayConnection[] {
    return [...this.conns.values()].filter((c) => c.authed && c.isOpen);
  }

  /** Own relays currently authenticated. */
  get connected(): string[] {
    return [...this.own].filter((r) => this.conns.get(r)?.authed);
  }

  /** Connects to every own relay. Resolves when each has succeeded or failed. */
  async connect(): Promise<{ connected: string[]; failed: { relay: string; error: string }[] }> {
    const failed: { relay: string; error: string }[] = [];
    const all = [...this.own];
    await Promise.all(
      all.map(async (r, i) => {
        try {
          await this.ensure(r, ` (relay ${i + 1}/${all.length})`);
        } catch (e) {
          failed.push({ relay: r, error: (e as Error).message });
          if ((e as CliError).code === "auth_failed") await this.refused(r);
          else this.scheduleReconnect(r);
        }
      }),
    );
    this.checkFatal();
    return { connected: this.connected, failed };
  }

  /** A relay refused this device: retried with backoff when the app says so (R4-L2), else fatal. */
  private async refused(relay: string): Promise<void> {
    const verdict = this.opts.onAuthRefused ? await this.opts.onAuthRefused(relay).catch(() => "fatal" as const) : "fatal";
    if (verdict === "retry" && this.opts.reconnect) {
      this.scheduleReconnect(relay);
      return;
    }
    this.fatal.add(relay);
    this.checkFatal();
  }

  private checkFatal(): void {
    if (this.own.size > 0 && [...this.own].every((r) => this.fatal.has(r))) {
      this.opts.onFatal?.("every relay refused this device: it may have been revoked");
    }
  }

  private scheduleReconnect(relay: string): void {
    if (!this.opts.reconnect || this.closing || !this.own.has(relay) || this.fatal.has(relay)) return;
    if (this.pending.has(relay) || this.connecting.has(relay)) return;
    const n = this.attempts.get(relay) ?? 0;
    this.attempts.set(relay, n + 1);
    const wait = BACKOFF_MS[Math.min(n, BACKOFF_MS.length - 1)];
    const t = setTimeout(() => {
      this.timers.delete(t);
      this.pending.delete(relay);
      if (this.closing) return;
      this.ensure(relay).then(
        () => this.attempts.set(relay, 0),
        (e) => {
          if ((e as CliError).code === "auth_failed") void this.refused(relay);
          else this.scheduleReconnect(relay);
        },
      );
    }, wait);
    this.timers.add(t);
    this.pending.set(relay, t);
  }

  /** An authenticated connection to `relay` (own or a recipient's), opened on demand. */
  ensure(relay: string, what = ""): Promise<RelayConnection> {
    // A closed pool never dials again: a handler that outlived its command (still sending an
    // answer, say) would otherwise open a connection nobody closes, as this device, and take
    // envelopes meant for the next command or the running watch (pre-release review: a want answered,
    // and acked, by a dead process).
    if (this.closing) return Promise.reject(new CliError("closing", "this command closed its relay connections"));
    const have = this.conns.get(relay);
    if (have?.authed && have.isOpen) return Promise.resolve(have);
    const inflight = this.connecting.get(relay);
    if (inflight) return inflight;
    // Found unreachable earlier in this command: fail at once (watch keeps retrying with backoff).
    if (!this.opts.reconnect) {
      const known = this.opts.progress?.unreachable?.get(hostKey(this.opts.transport(relay).ws).key);
      if (known) return Promise.reject(known);
    }
    const p = (async () => {
      this.dials.set(relay, (this.dials.get(relay) ?? 0) + 1);
      let opened = false;
      const auth = typeof this.opts.auth === "function" ? await this.opts.auth() : this.opts.auth;
      const lookup = this.opts.lookupFor?.(relay);
      const conn = new RelayConnection(relay, this.opts.transport(relay), {
        auth,
        ...(lookup ? { lookup } : {}),
        allowRestricted: this.opts.allowRestricted,
        timeoutMs: this.opts.timeoutMs,
        requestTimeoutMs: this.opts.requestTimeoutMs,
        progress: this.opts.progress,
        what,
        rememberUnreachable: !this.opts.reconnect,
        onEnv: (rid, env, c) => this.onEnv(rid, env, c),
        onCaughtUp: () => this.onCaughtUp(),
        onClose: (code, c) => {
          if (this.conns.get(relay) === c) this.conns.delete(relay);
          // A connection that never opened is handled by the caller (one reconnect, not two).
          if (this.closing || !opened) return;
          if (code === CLOSE_AUTH_FAILED && this.own.has(relay)) {
            this.opts.log?.(`${relay} closed this device's connection: not allowed`);
            void this.refused(relay);
            return;
          }
          if (code === CLOSE_CERT_EXPIRED && this.own.has(relay)) {
            this.opts.log?.(`${relay}: this device's certificate expired; reconnecting with a renewed one`);
            this.scheduleReconnect(relay);
            return;
          }
          if (this.own.has(relay)) {
            this.opts.log?.(`${relay} disconnected (${code}); reconnecting`);
            this.scheduleReconnect(relay);
          }
        },
      });
      try {
        await conn.open();
        opened = true;
        this.lastError.delete(relay);
      } catch (e) {
        this.lastError.set(relay, (e as Error).message);
        throw e;
      } finally {
        this.connecting.delete(relay);
      }
      this.conns.set(relay, conn);
      this.opts.onAuthed?.(conn);
      return conn;
    })();
    this.connecting.set(relay, p);
    return p;
  }

  private onEnv(rid: string, env: string, conn: RelayConnection, retry = 0): void {
    this.lastEnvAt = Date.now();
    this.inflight++;
    const run = async () => {
      if (this.stopped) {
        this.inflight--;
        this.wake();
        return;
      }
      let verdict: "ack" | "keep" = "ack";
      try {
        const handle = this.opts.onEnvelope;
        if (handle) verdict = await handlerPool.run(this, () => handle(env, conn.relay));
      } catch (e) {
        this.opts.log?.(`handling an envelope from ${conn.relay} failed: ${(e as Error).message}`);
        verdict = "keep";
      } finally {
        this.inflight--;
        this.lastEnvAt = Date.now();
      }
      if (verdict === "ack") conn.send({ t: "ack", rids: [rid] });
      else this.retryKept(rid, env, conn, retry);
      this.wake();
    };
    this.queue = this.queue.then(run, run);
  }

  /**
   * A long-lived pool (a watch) handles an envelope it answered "keep" again later, on the same
   * connection. A relay sends each envelope once per connection (and again only to one that
   * authenticates), so an envelope a watch kept because another process held its claim was
   * never seen by that watch again: if the holder then exited without finishing, nothing on the
   * device applied it until some command connected (pre-release review M-A). Backs off from
   * KEEP_RETRY_MS (doubling, at most a minute), KEEP_RETRIES times, while the connection lasts.
   */
  private retryKept(rid: string, env: string, conn: RelayConnection, retry: number): void {
    if (!this.opts.reconnect || this.closing || this.stopped || retry >= KEEP_RETRIES) return;
    const wait = Math.min(60_000, (this.opts.keepRetryMs ?? KEEP_RETRY_MS) * 2 ** retry);
    const t = setTimeout(() => {
      this.timers.delete(t);
      if (this.closing || this.stopped || !conn.isOpen || this.conns.get(conn.relay) !== conn) return;
      this.onEnv(rid, env, conn, retry + 1);
    }, wait);
    t.unref?.();
    this.timers.add(t);
  }

  /**
   * The backlog: what the relays delivered before the last of them said `caught-up`. Envelopes
   * are handled in arrival order, and a relay sends `caught-up` after its backlog, so the queue
   * as it stands then ends with the backlog. `backlogHandled` turns true when that much of the
   * queue is through; envelopes arriving live after it don't hold the drain (pre-release soak: during a
   * burst of statuses a short command's drain never saw the queue empty and ran to its 5 s cap).
   */
  private backlogTail?: Promise<unknown>;
  private backlogHandled = false;

  private onCaughtUp(): void {
    if (this.caughtUp) {
      const tail = this.queue;
      this.backlogTail = tail;
      this.backlogHandled = false;
      void tail.then(() => {
        if (this.backlogTail !== tail) return;
        this.backlogHandled = true;
        this.wake();
      });
    }
    this.wake();
  }

  private wake(): void {
    const ws = [...this.wakers];
    this.wakers.clear();
    for (const w of ws) w();
  }

  /** Resolves after `ms`, or sooner when a handler finishes or a relay says `caught-up`. */
  private nap(ms: number): Promise<void> {
    return new Promise((resolve) => {
      const done = () => {
        clearTimeout(t);
        this.wakers.delete(done);
        resolve();
      };
      const t = setTimeout(done, ms);
      this.wakers.add(done);
    });
  }

  /**
   * Every own relay this pool is connected to said `caught-up` (§5.4): nothing more is queued for
   * this device on them, beyond what is already being handled.
   */
  get caughtUp(): boolean {
    const live = [...this.own].map((r) => this.conns.get(r)).filter((c): c is RelayConnection => c !== undefined && c.authed && c.isOpen);
    return live.length > 0 && live.every((c) => c.caughtUp);
  }

  /**
   * Waits until no envelope has arrived (or is being handled) for `quietMs`, at most `maxMs`.
   *
   * `backlog`: this is the drain right after connecting, for what was queued while this device
   * was away. Then the wait ends as soon as every connected own relay has said `caught-up`
   * (§5.4) and everything it delivered was handled; a relay from before that is waited out as
   * above. Without it (a command waiting for answers to arrive live), the quiet period applies.
   */
  async drain(quietMs: number, maxMs: number, opts: { backlog?: boolean } = {}): Promise<void> {
    const start = Date.now();
    let backlogDone = false;
    await step(this.opts.progress, "receiving what your relays queued for this device", async () => {
      for (;;) {
        const now = Date.now();
        // A `caught-up` that came before its connection was registered: take the queue now.
        if (opts.backlog && this.caughtUp && !this.backlogTail) this.onCaughtUp();
        if (opts.backlog && this.caughtUp && (this.inflight === 0 || this.backlogHandled)) {
          backlogDone = true;
          break;
        }
        if (this.inflight === 0 && now - Math.max(this.lastEnvAt, start) >= quietMs) break;
        if (now - start >= maxMs) break;
        await this.nap(Math.max(1, Math.min(50, quietMs, maxMs - (now - start))));
      }
    });
    // The backlog is handled: what arrived live meanwhile is handled as it comes, not waited for.
    if (backlogDone || this.inflight === 0) return;
    // Handling an envelope can take network round trips (each bounded); waiting for the rest of
    // the queue is bounded too, so a backlog never stalls a command without a word.
    const left = Math.max(0, maxMs - (Date.now() - start)) + (this.opts.handlerGraceMs ?? DRAIN_HANDLER_GRACE_MS);
    let done = false;
    await step(this.opts.progress, `handling ${this.inflight} queued message(s)`, () =>
      Promise.race([
        this.queue.then(() => {
          done = true;
        }),
        new Promise<void>((r) => setTimeout(r, left).unref()),
      ]),
    );
    if (!done) this.opts.log?.(`still handling ${this.inflight} queued message(s) from your relays; going on (they stay queued until handled)`);
  }

  /** Sends one envelope to up to 3 recipient relays (§5.8). */
  async sendEnvelope(env: string, to: string, tdid: string, kind: string, targets: readonly SendTarget[]): Promise<SendResult> {
    if (this.stopped) throw new CliError("closing", "this command gave up on its envelope handlers: not sending");
    const res: SendResult = { sent: [], errors: [] };
    await Promise.all(
      targets.slice(0, MAX_SEND_RELAYS).map(async (t) => {
        let written = false;
        try {
          const conn = await this.ensure(t.relay);
          const frame: Frame = { t: "send", to, tdid, env };
          if (t.cap) frame.cap = t.cap;
          else if (kind !== "contact") throw new CliError("no_cap", "no capability for this relay");
          else if ((conn.hello?.pow ?? 0) > 0) {
            // Synchronous and possibly slow: always say so first (it blocks every timer).
            const bits = conn.hello!.pow;
            if (bits >= 12 || this.opts.progress?.debug) {
              this.opts.progress?.log(`no capability for ${t.relay}: solving its ${bits}-bit proof of work (this can take a while)…`);
              // Let the notice reach the terminal first (TTY writes are asynchronous on Windows).
              await new Promise((r) => setTimeout(r, 20));
            }
            const t0 = Date.now();
            frame.pow = solvePow(env, bits);
            debug(this.opts.progress, `proof of work for ${t.relay}: ${Date.now() - t0}ms`);
          }
          // From here the frame goes onto an open connection (request refuses a closed one first).
          written = conn.isOpen;
          const r = await conn.request(frame);
          if (r.t === "sent") res.sent.push(t.relay);
          else res.errors.push({ relay: t.relay, code: relayCode(r.code ?? r.t), written: true });
        } catch (e) {
          res.errors.push({ relay: t.relay, code: (e as CliError).code ?? "network", ...(written ? { written: true } : {}) });
        }
      }),
    );
    return res;
  }

  /** `{"t":"identity"}` to one relay; back-fills `history` (oldest first) on `identity-gap`. */
  async publishIdentity(relay: string, doc: string, history: readonly string[] = []): Promise<string> {
    return publishOver(await this.ensure(relay), doc, history);
  }

  /**
   * The same, over a fresh restricted-capable connection: for a relay whose held document
   * doesn't list this device yet (after a restore, R4-M2). Identity publishes only.
   */
  async publishIdentityRestricted(relay: string, doc: string, history: readonly string[] = []): Promise<string> {
    const auth = typeof this.opts.auth === "function" ? await this.opts.auth() : this.opts.auth;
    const conn = new RelayConnection(relay, this.opts.transport(relay), { auth, allowRestricted: true, timeoutMs: this.opts.timeoutMs, progress: this.opts.progress });
    try {
      await conn.open();
      return await publishOver(conn, doc, history);
    } finally {
      conn.close();
    }
  }

  /** `{"t":"revoke","capid"}` to every relay the cap names; returns the relays that confirmed. */
  async revoke(capid: string, relays: readonly string[]): Promise<string[]> {
    const ok: string[] = [];
    await Promise.all(
      relays.map(async (r) => {
        try {
          const conn = await this.ensure(r);
          const reply = await conn.request({ t: "revoke", capid });
          if (reply.t === "ok") ok.push(r);
        } catch {
          // unreachable relay: the cap still expires on its own
        }
      }),
    );
    return ok;
  }

  close(): void {
    this.closing = true;
    this.pending.clear();
    for (const t of this.timers) clearTimeout(t);
    this.timers.clear();
    for (const c of this.conns.values()) c.close();
    this.conns.clear();
  }
}

/** `{"t":"identity"}` on a connection; back-fills `history` (oldest first) on `identity-gap` (§2.5). */
export async function publishOver(conn: RelayConnection, doc: string, history: readonly string[] = []): Promise<string> {
  let r = await conn.request({ t: "identity", doc });
  if (r.t === "error" && r.code === "identity-gap" && history.length > 0) {
    for (const h of history) await conn.request({ t: "identity", doc: h });
    r = await conn.request({ t: "identity", doc });
  }
  return r.t === "ok" ? "ok" : relayCode(r.code ?? r.t);
}

/** An unauthenticated connection for the pre-auth link mailbox (§5.7). */
export async function openLinkConnection(
  relay: string,
  transport: TransportResolver,
  timeoutMs: number,
  progress?: Progress,
  opts: { lookup?: import("node:net").LookupFunction } = {},
): Promise<RelayConnection> {
  const c = new RelayConnection(relay, transport(relay), { timeoutMs, progress, ...(opts.lookup ? { lookup: opts.lookup } : {}) });
  await c.open();
  return c;
}

export async function linkPut(conn: RelayConnection, lid: string, slot: "req" | "resp", data: string): Promise<void> {
  const r = await conn.request({ t: "link-put", lid, slot, data });
  if (r.t !== "ok") throw new CliError("link_failed", `link mailbox refused the ${slot} (${relayCode(r.code ?? r.t)})`);
}

/** The entries of a slot, or undefined when the mailbox is gone. */
export async function linkGet(conn: RelayConnection, lid: string, slot: "req" | "resp"): Promise<string[] | undefined> {
  const r = await conn.request({ t: "link-get", lid, slot });
  if (r.t === "link" && Array.isArray(r.entries)) return r.entries.filter((x): x is string => typeof x === "string");
  if (r.t === "error" && r.code === "not-found") return undefined;
  if (r.t === "error" && r.code === "rate-limited") return [];
  throw new CliError("link_failed", `link-get failed (${relayCode(r.code ?? r.t)})`);
}

// ---------------------------------------------------------------------------
// P4 short-code invite mailboxes

/** Puts a sealed invite (authenticated connection); resolves with the expiry the relay set (seconds). */
export async function invitePut(conn: RelayConnection, lid: string, blob: string, ttlSec: number, admit?: string): Promise<number> {
  // `admit`: on a members-only relay, the code also admits whoever redeems it (open relays ignore it).
  const r = await conn.request({ t: "invite-put", lid, blob, ttl: ttlSec, ...(admit ? { admit } : {}) });
  if (r.t !== "ok") throw new CliError("not_published", `${conn.relay} refused the invite (${relayCode(r.code ?? r.t)})`, { code: relayCode(r.code ?? r.t) });
  return typeof r.exp === "number" ? r.exp : Math.floor(Date.now() / 1000) + ttlSec;
}

/** Takes the invite under `lid` (single use); undefined when there is none. */
export async function inviteGet(conn: RelayConnection, lid: string): Promise<string | undefined> {
  const r = await conn.request({ t: "invite-get", lid });
  if (r.t === "invite" && typeof r.blob === "string") return r.blob;
  if (r.t === "error" && r.code === "not-found") return undefined;
  if (r.t === "error" && r.code === "rate-limited") throw new CliError("rate_limited", `${conn.relay} is rate-limiting invite lookups from your network: try again in a few minutes`);
  throw new CliError("network", `${conn.relay}: invite-get failed (${relayCode(r.code ?? r.t)})`);
}

/** The lids this user holds open on the relay, and those it evicted to make room (not yet expired). */
export async function inviteList(conn: RelayConnection): Promise<{ lids: string[]; evicted: string[] }> {
  const r = await conn.request({ t: "invite-list" });
  const strs = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
  if (r.t === "invites" && Array.isArray(r.lids)) return { lids: strs(r.lids), evicted: strs(r.evicted) };
  throw new CliError("network", `${conn.relay}: invite-list failed (${relayCode(r.code ?? r.t)})`);
}

/** Deletes an open invite; false when the relay held none under `lid`. */
export async function inviteDel(conn: RelayConnection, lid: string): Promise<boolean> {
  const r = await conn.request({ t: "invite-del", lid });
  if (r.t === "ok") return true;
  if (r.t === "error" && r.code === "not-found") return false;
  throw new CliError("network", `${conn.relay}: invite-del failed (${relayCode(r.code ?? r.t)})`);
}

// ---------------------------------------------------------------------------
// §5.6 document API

/** review L6: a relay's document API answer is at most this big (64 tips or chain entries of ≤ 16 KiB, with room). */
export const MAX_HTTP_BODY_BYTES = 2 * 1024 * 1024;

/** Reads a response body, refusing more than `max` bytes. */
export async function readCapped(res: Response, max: number): Promise<string> {
  const len = Number(res.headers.get("content-length") ?? "0");
  if (len > max) throw new CliError("network", "relay answer too large");
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => {});
      throw new CliError("network", "relay answer too large");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function getJson(url: string, timeoutMs: number, progress?: Progress, what = "identity documents", lookup?: LookupFunction): Promise<Record<string, unknown> | undefined> {
  const known = progress?.unreachable?.get(hostKey(url).key);
  if (known) throw known;
  return step(progress, `fetching ${what} from ${new URL(url).origin}`, () => (lookup ? getJsonGuarded(url, timeoutMs, lookup) : getJsonInner(url, timeoutMs)));
}

/**
 * getJsonInner through node:http(s) with `lookup` (a code's relay: privateGuardLookup), so the
 * address the name resolves to is checked and dialed as checked. No redirects are followed.
 */
function getJsonGuarded(url: string, timeoutMs: number, lookup: LookupFunction): Promise<Record<string, unknown> | undefined> {
  const get = url.startsWith("https:") ? httpsGet : httpGet;
  return new Promise((resolve, reject) => {
    let done = false;
    // One overall deadline, as fetch's abort had: a relay that trickles bytes can't hold the command.
    const deadline = setTimeout(() => {
      req.destroy();
      fail(new CliError("timeout", `${url}: no answer after ${Math.round(timeoutMs / 1000)}s`));
    }, timeoutMs);
    deadline.unref();
    const settle = () => {
      done = true;
      clearTimeout(deadline);
    };
    const fail = (e: Error) => {
      if (done) return;
      settle();
      reject(e instanceof CliError ? e : new CliError(e.message.includes(PRIVATE_RESOLVE_MARK) ? "private_relay" : "network", `${url}: ${e.message}`));
    };
    const req = get(url, { lookup, agent: false, timeout: timeoutMs, headers: { accept: "application/json" } }, (res) => {
      if (res.statusCode === 404) {
        res.resume();
        settle();
        return resolve(undefined);
      }
      if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return fail(new CliError("network", `${url}: HTTP ${res.statusCode ?? "?"}`));
      }
      const chunks: Buffer[] = [];
      let total = 0;
      res.on("data", (c: Buffer) => {
        total += c.length;
        if (total > MAX_HTTP_BODY_BYTES) {
          req.destroy();
          fail(new CliError("network", "relay answer too large"));
        } else chunks.push(c);
      });
      res.on("end", () => {
        if (done) return;
        try {
          const v = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
          settle();
          resolve(v);
        } catch (e) {
          fail(e as Error);
        }
      });
      res.on("error", fail);
    });
    req.on("timeout", () => {
      req.destroy();
      fail(new CliError("timeout", `${url}: no answer after ${Math.round(timeoutMs / 1000)}s`));
    });
    req.on("error", fail);
  });
}

async function getJsonInner(url: string, timeoutMs: number): Promise<Record<string, unknown> | undefined> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  t.unref();
  try {
    const res = await fetch(url, { signal: ctl.signal, headers: { accept: "application/json" } });
    if (res.status === 404) return undefined;
    if (!res.ok) throw new CliError("network", `${url}: HTTP ${res.status}`);
    return JSON.parse(await readCapped(res, MAX_HTTP_BODY_BYTES)) as Record<string, unknown>;
  } catch (e) {
    if (e instanceof CliError) throw e;
    if (ctl.signal.aborted) throw new CliError("timeout", `${url}: no answer after ${Math.round(timeoutMs / 1000)}s`);
    throw new CliError("network", `${url}: ${(e as Error).message}`);
  } finally {
    clearTimeout(t);
  }
}

/** GET /.well-known/p2p-relay.json from the relay's host (undefined: 404, an older relay). */
export async function fetchRelayInfo(t: Transport, timeoutMs: number, progress?: Progress): Promise<Record<string, unknown> | undefined> {
  return getJson(new URL("/.well-known/p2p-relay.json", t.http).toString(), timeoutMs, progress, "the relay's features");
}

const strList = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

export async function fetchTips(t: Transport, userId: string, timeoutMs: number, progress?: Progress, lookup?: LookupFunction): Promise<string[]> {
  const j = await getJson(`${t.http}/identity/${encodeURIComponent(userId)}/tips`, timeoutMs, progress, `${userId}'s identity`, lookup);
  return j ? strList(j.tips) : [];
}

export async function fetchChain(t: Transport, userId: string, to: string, n: number, timeoutMs: number, progress?: Progress, lookup?: LookupFunction): Promise<string[]> {
  const j = await getJson(`${t.http}/identity/${encodeURIComponent(userId)}/chain?to=${encodeURIComponent(to)}&n=${n}`, timeoutMs, progress, `${userId}'s identity history`, lookup);
  return j ? strList(j.docs) : [];
}

export const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
