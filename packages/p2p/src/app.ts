// Copyright 2026 Ix Infrastructure Inc.
//
// The CLI's working context. Daemon-free: every command builds an App, opens
// the stores, connects to the relays only if it needs to, does its work and
// closes. Only `watch` stays connected.
//
// What lives here: loading this device's keys, identity-document handling
// (fetch from relays and fill gaps, §2.5/§5.6; build, sign and publish the
// next version of our own), sealing and delivering envelopes (§4.1, §5.4,
// §5.8), finding caps, resolving addresses and petnames, and syncing state to
// the user's other devices.

import { personTokenOk } from "./projects.js";
import { confirmOnTty } from "./tty-confirm.js";
import { hostname, userInfo } from "node:os";
import {
  addIdentityVersion,
  b64uDecode,
  b64uEncode,
  capAllowsKind,
  CircleChain,
  createCap,
  createDeviceCert,
  createIdentityDoc,
  decodeTyped,
  deviceKeysV3FromSecrets,
  displayAddress,
  displayFingerprint,
  getIdentityView,
  MAX_DEVICES,
  mergeFields,
  mergePrevTip,
  scheduledWriter,
  refreshIdentity as coreRefreshIdentity,
  type IdentityFetcher,
  IdentityChain,
  identityKeyFromSeed,
  isUserId,
  isValidName,
  nowSec,
  P2PError,
  peekIdentityDoc,
  canonicalRelayUrl,
  sealEnvelopeV3,
  storeCertResolver,
  storeSignerContext,
  TYP3,
  verifyDeviceCertV3,
  type CreateIdentityDocParams,
  type DeviceKeysV3,
  type DeviceSignerV3,
  type EnvelopeKindV3,
  type IdentityKey,
  type IdentityView,
  type RotationStatement,
  type SignerContext,
  type StoredCapV3,
  type TrustStoreV3,
  verifyRotationSignatures,
} from "@peer2peer/core/v3";
import { FileDocBackend, FileTrustStoreV3, type LockOptions } from "@peer2peer/core/v3/node";
import { OverlayDocBackend, ReadOnlyTrustStoreV3 } from "./readonly.js";
import { basename, join } from "node:path";
import {
  deviceInfoEnabled,
  readFileConfig,
  resolveHome,
  transportResolver,
  tunables,
  type Env,
  type FileConfig,
  type TransportResolver,
  type Tunables,
} from "./config.js";
import { CliError } from "./errors.js";
import { fetchChain, fetchTips, handlerPool, RelayPool, type EnvelopeHandler, type RelayConnection } from "./relay-client.js";
import type { LookupFunction } from "node:net";
import { isOwnRelay, privateGuardLookup } from "./shortcode.js";
import type { SelectSpec } from "./prompt/picker.js";
import type { Pretty } from "./pretty.js";
import { RELAY_FEATURE_LENIENT_IDENTITY, relaysSupport } from "./relay-info.js";
import { CLI_CAPS } from "./features.js";
import { VERSION } from "./version.js";

import { CliState, type KeysDoc, type SelfDoc } from "./state.js";
import { debug, makeProgress, step, type Progress } from "./progress.js";
import type { ExtensionRegistry } from "./extensions.js";

/** refreshDeviceInfo: at most one publish an hour to bring `dinfo` current, and a minute after one that failed. */
const DEVICE_INFO_EVERY_MS = 3600_000;
const DEVICE_INFO_RETRY_MS = 60_000;


/** A redeemed code's admission key is kept this long (codes live at most 7 days). */
const ADMIT_KEEP_MS = 8 * 86_400_000;
/** One `circle-put` frame: at most this many versions and about this many bytes (relay frames are 96 KiB). */
const CIRCLE_PUSH_MAX_VERSIONS = 64;
const CIRCLE_PUSH_MAX_BYTES = 80 * 1024;
export interface Io {
  /** Human output (stdout). */
  out(s: string): void;
  /** Diagnostics (stderr). */
  err(s: string): void;
  /** Asks the user; undefined when there is no terminal. */
  prompt?: (question: string) => Promise<string>;
  /** Asks without echoing what is typed (the backup phrase, review N-L3). */
  promptSecret?: (question: string) => Promise<string>;
  /**
   * Reads all of stdin. `implicit`: the user didn't ask for stdin (e.g. `send` with no text), so
   * an inherited stdin that never ends (PowerShell, an IDE task) must not hang the command: give
   * up with "" when nothing arrives within a few seconds.
   */
  readStdin?: (opts?: { implicit?: boolean }) => Promise<string>;
  /**
   * An interactive picker (prompt/tty.ts): the values chosen, or undefined when cancelled. Only set
   * when stdin and stdout are a terminal, CI and --no-input are unset and no agent runs the command.
   */
  select?: (spec: SelectSpec) => Promise<string[] | undefined>;
  /** stdout is a terminal: human output may use pretty.ts (colour only when `color`). */
  pretty?: Pretty;
}

export interface AppOptions {
  env: Env;
  io: Io;
  /**
   * `p2p doctor`: the stores read the home but every write stays in memory (readonly.ts), so
   * nothing in P2P_HOME changes, not even after a bounded step times out and finishes later.
   */
  readOnly?: boolean;
}

/** Days before a certificate's or document's expiry at which it is renewed. */
export const RENEW_CERT_WITHIN_SEC = 30 * 86_400;
/** How long closing waits for envelope handlers still running. */
export const CLOSE_GRACE_MS = 3000;
/** refreshIdentity: a `fetched` time this recent is left as it is (see there). */
const FETCHED_SLACK_MS = 5000;
export const REPUBLISH_DOC_WITHIN_SEC = 7 * 86_400;

export interface Delivery {
  userId: string;
  /** Devices an envelope was sealed to. */
  devices: number;
  /** Distinct relays that accepted at least one copy. */
  relays: string[];
  /** `written`: it went out on the wire before failing (see SendResult). */
  errors?: { did: string; relay: string; code: string; written?: boolean }[];
  /**
   * Copies sealed but accepted by no relay, as sealed (outbox.ts can send these same envelopes
   * later: the recipient's replay window drops a second copy), with the relays and caps they
   * were for and why each relay failed.
   */
  unsent?: { did: string; env: string; targets: { relay: string; cap?: string }[]; codes: string[] }[];
}

const CAP_PRIORITY = (c: { kinds: string[] }) => (c.kinds[0] === "*" ? 0 : 1);

export class App {
  /** The person's front end vouched for this command (P2P_PERSON_TOKEN, checked once and removed: projects.ts). */
  front = false;
  /** The person's "yes" on their controlling terminal (tty-confirm.ts); cli.ts may stand another in (tests). */
  confirmTty: (question: string) => Promise<boolean> = confirmOnTty;
  readonly env: Env;
  readonly io: Io;
  readonly home: string;
  readonly state: CliState;
  readonly store: TrustStoreV3 & { readonly dir: string };
  readonly readOnly: boolean;
  readonly file: FileConfig;
  readonly transport: TransportResolver;
  readonly tun: Tunables;
  keys?: KeysDoc;
  self?: SelfDoc;
  device?: DeviceKeysV3;
  ik?: IdentityKey;
  pool?: RelayPool;
  /** Slow-step notices and P2P_DEBUG step logs (stderr). */
  readonly progress: Progress;
  /** Aborted by the command deadline (cli.ts): stops new network steps (progress.step). */
  readonly abort = new AbortController();
  /**
   * Set once an identity publish may have been stored by a relay: one accepted, or one went out
   * and its answer never came (timeout, dropped connection). A restore must not wipe after that
   * (review L1). Definite refusals (a relay's error code) and relays never reached don't set it.
   */
  publishMaybeStored = false;
  /** Handles envelopes delivered while connected (set by inbound.ts). */
  onEnvelope?: EnvelopeHandler;
  /** Runs after connectAndDrain (set by inbound.ts: finishes short-code circle joins). */
  afterDrain?: () => Promise<unknown>;
  /** Runs when every relay refused this device and our own document turned out rotated (set by inbound.ts: the alert). */
  onIdentityRotated?: () => Promise<unknown>;
  /** The session this process is the `p2p watch` of (running.ts). */
  watching?: string;
  /** close() is giving up on envelope handlers still running (set by inbound.ts: abandonInFlight). */
  onAbandon?: () => Promise<unknown>;
  /** close() is waiting for the pool's handlers. */
  private closing = false;
  private discovered = new Map<string, { p: Promise<IdentityView | undefined>; at: number; found?: boolean }>();
  private readonly refusedVerdicts = new Map<string, { at: number; verdict: "retry" | "fatal" }>();
  /** The relays as of the last connect (for `ls --json`). */
  relayStatus?: { listed: string[]; connected: string[]; failed: { url: string; reason: string }[] };
  warnings: string[] = [];
  /** Accept restricted relay connections (only `backup restore`, before its new device is listed). */
  allowRestricted = false;
  /** Installed extensions (extensions.ts): render inbound `x:<ns>.*` kinds. Absent: fallbacks only. */
  extensions?: ExtensionRegistry;

  constructor(opts: AppOptions) {
    this.env = opts.env;
    this.io = opts.io;
    this.home = resolveHome(opts.env);
    // An embedder holding the person token is a front end (the CLI's main() checks and removes it first,
    // then sets this from its own check).
    this.front = personTokenOk(this.env, this.home);
    // Progress and P2P_DEBUG lines go to stderr (never secrets: see progress.ts).
    this.progress = { ...makeProgress(opts.env, (m) => opts.io.err(`p2p: ${m}`)), signal: this.abort.signal };
    this.readOnly = opts.readOnly === true;
    // P2P_DEBUG: lock waits and hold times of both stores, for tail-latency work (bench/README.md).
    const lockOpts: Partial<LockOptions> = this.progress.debug
      ? { onLock: lockLogger(this.progress), onLockWait: ({ dir, waitedMs, holderPid }) => debug(this.progress, `lock ${basename(dir)}: still waiting after ${waitedMs}ms (held by pid ${holderPid ?? "?"})`) }
      : {};
    this.state = new CliState(this.home, this.progress, this.readOnly ? new OverlayDocBackend(new FileDocBackend(join(this.home, "cli"))) : undefined, lockOpts);
    this.store = this.readOnly ? new ReadOnlyTrustStoreV3(join(this.home, "v3")) : new FileTrustStoreV3(join(this.home, "v3"), lockOpts);
    this.file = readFileConfig(this.home);
    this.transport = transportResolver(opts.env, this.file);
    this.tun = tunables(opts.env);
  }

  /** Loads this device's keys. With `require`, a missing identity is an error. */
  async load(require = true): Promise<boolean> {
    const keys = await this.state.get("keys");
    const self = await this.state.get("self");
    if (!keys || !self) {
      if (require) throw new CliError("no_identity", "no identity here yet: run `p2p init` (or `p2p link join` / `p2p backup restore`)");
      return false;
    }
    this.setKeys(keys, self);
    return true;
  }

  setKeys(keys: KeysDoc, self: SelfDoc): void {
    this.keys = keys;
    this.self = self;
    this.device = deviceKeysV3FromSecrets(keys.userId, b64uDecode(keys.spk, 32), b64uDecode(keys.kpk, 32));
    this.ik = keys.ik ? identityKeyFromSeed(b64uDecode(keys.ik, 32)) : undefined;
  }

  get userId(): string {
    return this.keys!.userId;
  }

  get did(): string {
    return this.keys!.did;
  }

  get relays(): string[] {
    return this.self!.relays;
  }

  get isKeyholder(): boolean {
    return this.ik !== undefined;
  }

  requireKeyholder(what: string): IdentityKey {
    if (!this.ik) throw new CliError("not_keyholder", `${what} needs a key-holding device (§2.2); this device doesn't hold the identity key`);
    return this.ik;
  }

  signer(): DeviceSignerV3 {
    return { userId: this.userId, did: this.did, signingSecretKey: this.device!.signingSecretKey };
  }

  warn(msg: string): void {
    this.warnings.push(msg);
    this.io.err(`warning: ${msg}`);
  }

  // -------------------------------------------------------------------------
  // Relays

  /** Connects to every own relay (receiving whatever is queued). At least one must answer. */
  async connect(opts: { reconnect?: boolean; onFatal?: (r: string) => void; allowNone?: boolean } = {}): Promise<RelayPool> {
    if (this.pool) return this.pool;
    // An envelope handler of a pool already closed (one that outlived close's grace) must not
    // open a new pool that nobody closes: it would take deliveries meant for the next command and
    // spend them in a process on its way out (pre-release review M1).
    const from = handlerPool.getStore();
    if (from !== undefined && from !== this.pool) throw new CliError("closing", "this command closed its relay connections");
    const pool = new RelayPool({
      relays: this.relays,
      transport: this.transport,
      lookupFor: (r) => this.guardedLookup(r),
      // Re-read on every reconnect: a long-running watch picks up a certificate renewed by another
      // process (keys on disk) or published in our own document (R4-L1).
      auth: async () => {
        await this.reloadCert().catch(() => {});
        const admits = await this.pendingAdmits();
        return {
          cert: this.keys!.cert,
          signingSecretKey: this.device!.signingSecretKey,
          ...(admits ? { admits, onAdmitted: (relay: string) => void this.forgetAdmit(relay).catch(() => {}) } : {}),
        };
      },
      onAuthed: (conn) => {
        if (!conn.circle) return;
        const p = this.syncRelayCircle(conn).catch((e: unknown) => debug(this.progress, `circle push to ${conn.relay}: ${(e as Error).message}`));
        this.circlePushes.add(p);
        void p.finally(() => this.circlePushes.delete(p));
      },
      onAuthRefused: (relay) => this.authRefusedVerdict(relay),
      timeoutMs: this.tun.connectTimeoutMs,
      requestTimeoutMs: this.tun.requestTimeoutMs,
      progress: this.progress,
      onEnvelope: (env, relay) => (this.onEnvelope ? this.onEnvelope(env, relay) : Promise.resolve("keep" as const)),
      reconnect: opts.reconnect,
      keepRetryMs: Number(this.env.P2P_KEEP_RETRY_MS ?? "") || undefined,
      log: (m) => this.io.err(m),
      onFatal: opts.onFatal,
      allowRestricted: this.allowRestricted,
    });
    this.pool = pool;
    const r = await pool.connect();
    this.relayStatus = { listed: [...this.relays], connected: r.connected, failed: r.failed.map((f) => ({ url: f.relay, reason: f.error })) };
    for (const f of r.failed) this.io.err(f.error.startsWith("can't reach") ? `p2p: ${f.error}` : `relay ${f.relay}: ${f.error}`);
    if (r.connected.length === 0 && !opts.allowNone && !opts.reconnect) {
      if (r.failed.length > 0 && r.failed.every((f) => /is members-only/.test(f.error))) {
        throw new CliError("not_member", "every relay of yours is members-only and doesn't admit this identity: ask a member for an invite code, or the operator to add your userId");
      }
      const revoked = r.failed.some((f) => /refused this device/.test(f.error));
      if (revoked) await this.throwIfRotated();
      throw new CliError(revoked ? "device_revoked" : "no_relay", revoked ? "every relay refused this device: it may have been revoked" : "could not reach any of your relays");
    }
    if (this.self && (this.self.unpublished?.length || Object.keys(this.self.refusedPublish ?? {}).length)) await this.retryUnpublished();
    // Best effort, quietly: a document just created isn't on the relays yet (the next command retries).
    await this.refreshDeviceInfo().catch(() => undefined);
    return pool;
  }

  // -------------------------------------------------------------------------
  // Members-only relays

  /** circle-puts started when a members-only relay connection authenticated: close waits for them (bounded). */
  private readonly circlePushes = new Set<Promise<void>>();

  /** Admission keys from redeemed codes not used yet (by relay), or undefined when there are none. */
  private async pendingAdmits(): Promise<Record<string, string> | undefined> {
    const cur = (await this.state.get("admits")) ?? {};
    const live = Object.entries(cur).filter(([, a]) => Date.now() - a.at < ADMIT_KEEP_MS);
    return live.length > 0 ? Object.fromEntries(live.map(([r, a]) => [r, a.key])) : undefined;
  }

  /** Keeps a redeemed code's admission key for `relay` until that relay admits us with it. */
  async saveAdmit(relay: string, key: string): Promise<void> {
    await this.state.update("admits", (cur = {}) => {
      const keep = Object.fromEntries(Object.entries(cur).filter(([, a]) => Date.now() - a.at < ADMIT_KEEP_MS));
      return { next: { ...keep, [relay]: { key, at: Date.now() } }, result: undefined };
    });
  }

  private async forgetAdmit(relay: string): Promise<void> {
    await this.state.update("admits", (cur = {}) => {
      if (!cur[relay]) return { result: undefined };
      const { [relay]: _used, ...rest } = cur;
      return { next: rest, result: undefined };
    });
  }

  /**
   * A members-only relay that follows a circle said which version it holds: when we hold that
   * circle further along, push the rest (`circle-put`), so additions and removals take effect
   * there at once. The relay verifies every version itself; its refusals change nothing here.
   *
   * A chain names every member: it goes only to one of our OWN relays (listed in our identity
   * document), and only for a circle we are a member of. Any other relay (a recipient's, or one
   * that names a circle id it shouldn't know) gets nothing, whatever cid it asks for.
   */
  async syncRelayCircle(conn: RelayConnection): Promise<void> {
    const rc = conn.circle;
    if (!rc || !conn.authed || conn.restricted) return;
    if (!this.relays.includes(conn.relay)) return;
    const rec = await this.store.getCircle(rc.cid);
    if (!rec || !rec.joinedByMe) return;
    const chain = CircleChain.fromStored(rec.chain);
    if (!chain.head.members.includes(this.userId)) return;
    if (chain.head.ver <= rc.ver) return;
    // From version 1 when the relay holds none (only an allowlisted member may seed it).
    const versions = chain.versionsFrom(rc.ver === 0 ? 1 : rc.ver + 1);
    let batch: string[] = [];
    let bytes = 0;
    const flush = async () => {
      if (batch.length === 0) return;
      const r = await conn.request({ t: "circle-put", versions: batch });
      batch = [];
      bytes = 0;
      if (r.t !== "ok") throw new CliError("circle_push", `refused (${typeof r.code === "string" ? r.code : r.t})`);
      if (typeof r.ver === "number") conn.circle = { cid: rc.cid, ver: r.ver };
    };
    for (const v of versions) {
      if (batch.length >= CIRCLE_PUSH_MAX_VERSIONS || (batch.length > 0 && bytes + v.length > CIRCLE_PUSH_MAX_BYTES)) await flush();
      batch.push(v);
      bytes += v.length;
    }
    await flush();
  }

  /** After this owner published a version of `cid`: every open members-only relay connection that follows it. */
  async pushCircleToRelays(cid: string): Promise<void> {
    for (const conn of this.pool?.authedConnections() ?? []) {
      if (conn.circle?.cid !== cid) continue;
      await this.syncRelayCircle(conn).catch((e: unknown) => debug(this.progress, `circle push to ${conn.relay}: ${(e as Error).message}`));
    }
  }

  private refreshingDeviceInfo = false;
  /** Set while `init` publishes the first document: nothing to bring current until it is on the relays. */
  deviceInfoDeferred = false;

  /**
   * docs/compatibility.md: keeps this device's entry in the identity document (`dinfo`) current
   * after an upgrade, or removes it when the user opted out: a key holder publishes the next version
   * when the entry differs from what this client is. At most once an hour, and not when every relay
   * wouldn't store it anyway (an entry is only ever published to relays that list identity.lenient).
   */
  async refreshDeviceInfo(): Promise<boolean> {
    if (this.readOnly || this.refreshingDeviceInfo || this.deviceInfoDeferred || !this.keys || !this.isKeyholder || !this.self) return false;
    const view = await this.view(this.userId);
    if (!view || view.head.rotation) return false;
    const want = deviceInfoEnabled(this.env, this.home) ? { caps: [...CLI_CAPS], client: VERSION } : undefined;
    const have = view.head.dinfo?.[this.did];
    if (JSON.stringify(have ?? null) === JSON.stringify(want ?? null)) return false;
    if (Date.now() - (this.self.deviceInfoAt ?? 0) < DEVICE_INFO_EVERY_MS) return false;
    if (want && !have && !(await relaysSupport(this, view.relays, RELAY_FEATURE_LENIENT_IDENTITY))) return false;
    this.refreshingDeviceInfo = true;
    try {
      await this.publishNext(() => undefined);
      await this.updateSelf((s) => ({ ...s, deviceInfoAt: Date.now() }));
      return true;
    } catch (e) {
      // Tried: again in a minute, not on every command.
      await this.updateSelf((s) => ({ ...s, deviceInfoAt: Date.now() - DEVICE_INFO_EVERY_MS + DEVICE_INFO_RETRY_MS }));
      throw e;
    } finally {
      this.refreshingDeviceInfo = false;
    }
  }

  /**
   * §2.8: every relay refused this device. When our own document's final
   * version carries a rotation (relays serve documents publicly), the
   * identity moved without this device: say so, and how to re-link.
   */
  async throwIfRotated(): Promise<void> {
    await this.refreshIdentity(this.userId, this.relays, { force: true, quiet: true }).catch(() => undefined);
    const to: string[] = [];
    for (const s of (await this.view(this.userId))?.rotations ?? []) {
      try {
        const r = verifyRotationSignatures(s);
        if (r.from === this.userId) to.push(r.to);
      } catch {
        // not a valid statement
      }
    }
    if (to.length === 0) return;
    // A rotation this device didn't publish is raised (§2.8) even though nothing can be drained now.
    await this.onIdentityRotated?.().catch(() => undefined);
    throw new CliError(
      "identity_rotated",
      `your identity moved to a new key (${to.join(" and ")}${to.length > 1 ? ": more than one rotation, someone else holds your old key" : ""}) and this device didn't follow.${this.isKeyholder ? " If you didn't start that, someone holds your identity key: contest it with `p2p identity rotate --contest` (your friends then see a conflict). If you did:" : ""} Re-link it: run \`p2p link start\` on a device of the new identity, then here \`p2p link join <code> --rotated\``,
      { to },
    );
  }

  /** Connects and handles everything queued for this device. */
  async connectAndDrain(): Promise<RelayPool> {
    const pool = await this.connect();
    await pool.drain(this.tun.drainQuietMs, this.tun.drainMaxMs, { backlog: true });
    if (this.afterDrain) await this.afterDrain().catch((e) => this.io.err(`p2p: ${(e as Error).message}`));
    // afterDrain may have moved this device to its identity's new key (§2.8): connect as that one.
    return this.pool ?? (await this.connect());
  }

  async close(): Promise<void> {
    if (this.pool && !this.closing) {
      const pool = this.pool;
      // The pool stays this app's while handlers still running finish: what they send goes out
      // on it, and nothing opens a second one (connect refuses while closing).
      this.closing = true;
      try {
        // Bounded: a command never hangs on its way out.
        if (this.circlePushes.size > 0) await Promise.race([Promise.allSettled([...this.circlePushes]), new Promise((r) => setTimeout(r, CLOSE_GRACE_MS).unref())]);
        await Promise.race([pool.drain(0, 0).catch(() => {}), new Promise((r) => setTimeout(r, CLOSE_GRACE_MS).unref())]);
        // Handlers still running past the grace: the process exits under them. Their claims go
        // back uncounted, so the next command or the watch applies those envelopes in full.
        if (pool.busy) {
          pool.stopHandling();
          // Bounded too: giving claims back waits on the store's lock, and an exit never hangs on it.
          if (this.onAbandon) await Promise.race([this.onAbandon().catch(() => undefined), new Promise((r) => setTimeout(r, CLOSE_GRACE_MS).unref())]);
        }
      } finally {
        this.pool = undefined;
        this.closing = false;
        pool.close();
      }
    }
  }

  // -------------------------------------------------------------------------
  // Identity documents (§2.5, §5.6)

  ownView(): Promise<IdentityView> {
    return getIdentityView(this.store, this.userId).then((v) => {
      if (!v) throw new CliError("no_identity", "this device holds no identity document for its user");
      return v;
    });
  }

  async view(userId: string): Promise<IdentityView | undefined> {
    return getIdentityView(this.store, userId);
  }

  /**
   * Network I/O for core's refreshIdentity (§5.6), per relay so core can cap
   * each relay's answer on its own: `tips` and the `chain` walk
   * (`/v3/identity/<id>/chain?to=&n=`) on every listed relay (at most 5).
   */
  fetcher(): IdentityFetcher {
    const t = this.tun.connectTimeoutMs;
    const perRelay = async (relays: readonly string[], get: (r: string) => Promise<string[]>): Promise<Record<string, string[]>> => {
      const list = [...new Set(relays)].slice(0, 5);
      const answers = await Promise.all(list.map((r) => get(r).catch(() => [] as string[])));
      return Object.fromEntries(list.map((r, i) => [r, answers[i]]));
    };
    return {
      tips: (userId, relays) => perRelay(relays, (r) => fetchTips(this.transport(r), userId, t, this.progress, this.guardedLookup(r))),
      chain: (userId, relays, to, n) => perRelay(relays, (r) => fetchChain(this.transport(r), userId, to, n, t, this.progress, this.guardedLookup(r))),
    };
  }

  /**
   * Refreshes `userId` from the relays (core refreshIdentity: chain rules,
   * gap filling, automatic jumps only over unanchored history). This is the
   * only way an identity enters the store: bundled documents never do.
   * Failures leave the held view (or none) and are reported as a warning.
   */
  async refreshIdentity(userId: string, relays: readonly string[], opts: { force?: boolean; quiet?: boolean; strict?: boolean } = {}): Promise<IdentityView | undefined> {
    const fetched = (await this.state.get("fetched"))?.[userId];
    const fresh = fetched !== undefined && Date.now() - fetched < this.tun.docRefreshSec * 1000;
    if (fresh && !opts.force && !opts.strict) return this.view(userId);
    const held = await this.view(userId);
    const list = [...new Set([...(held?.relays ?? []), ...relays])];
    if (list.length === 0) {
      if (opts.strict) throw new CliError("refresh_failed", `no relays to refresh ${userId} from`);
      return held;
    }
    try {
      const v = await step(this.progress, `refreshing ${userId}'s identity document from ${list.join(", ")}`, () => coreRefreshIdentity(this.store, userId, this.fetcher(), { relays: list }));
      if (v.incomplete) {
        if (opts.strict) throw new CliError("refresh_failed", "refreshing the identity document was cut short; try again");
        // Cut short by core's work bound: the head may be stale. Not refreshed; don't act on it as fresh.
        if (!opts.quiet) this.warn(`refreshing ${await this.addressOf(userId)}'s identity document was cut short; using what was held before (try again)`);
        return held;
      }
      // Recorded moments ago by another p2p process of this home (a watch and a command refresh
      // the same people in a burst): no write. Only ever leaves the time a little older, so the
      // next refresh comes no later.
      const now = Date.now();
      const last = (await this.state.get("fetched"))?.[userId];
      if (last === undefined || last < now - FETCHED_SLACK_MS) await this.state.update("fetched", (cur = {}) => ({ next: { ...cur, [userId]: Math.max(cur[userId] ?? 0, now) }, result: undefined }));
      return v;
    } catch (e) {
      if (!(e instanceof P2PError)) throw e;
      // Strict callers (publishing our own next version) must not build on a head they couldn't confirm.
      if (opts.strict) throw new CliError("refresh_failed", `couldn't confirm the current identity document on the relays (${e.reason}): not publishing on a possibly stale head`);
      if (e.reason === "chain-broken" && held && !opts.quiet) {
        this.warn(`${await this.addressOf(userId)}'s newest identity document doesn't connect to the history held here (§2.5 history gap); keeping the held one`);
      }
      return held;
    }
  }

  /** Relays a (bundled, unverified) identity document lists: only a hint for where to refresh from. */
  static relaysOf(docJws: string | undefined): string[] {
    if (!docJws) return [];
    try {
      return peekIdentityDoc(docJws).relays;
    } catch {
      return [];
    }
  }

  /** The view of `userId`, refreshed from the relays its document lists (or `hint`, then ours, when unknown). */
  async viewFor(userId: string, opts: { refresh?: boolean; hint?: readonly string[] } = {}): Promise<IdentityView | undefined> {
    const held = await this.view(userId);
    if (held && opts.refresh === false) return held;
    const relays = held ? held.relays : [...(opts.hint ?? []), ...this.relays];
    return (await this.refreshIdentity(userId, relays)) ?? held;
  }

  /** Relays someone else named (a code's, a pasted link's): their names are checked where they resolve, on every WebSocket and HTTP connection. */
  private guarded = new Set<string>();

  /** From now on in this process, connections to these relays (documents over HTTP, the pool's WebSockets) go through privateGuardLookup. */
  guardRelays(relays: readonly string[]): void {
    for (const r of relays) {
      // Decided now: the user's own relays are left out, and a relay guarded now stays guarded for the
      // rest of the command even if it becomes theirs meanwhile (a code join's new identity on the code's relay).
      if (isOwnRelay(r, this.self?.relays ?? [])) continue;
      try {
        this.guarded.add(canonicalRelayUrl(r));
      } catch {
        // not a relay URL: nothing is fetched from it
      }
    }
  }

  private guardedLookup(relay: string): LookupFunction | undefined {
    if (this.guarded.size === 0) return undefined;
    try {
      return this.guarded.has(canonicalRelayUrl(relay)) ? privateGuardLookup() : undefined;
    } catch {
      return undefined;
    }
  }

  /** Signer resolution for core verifiers, finding unknown identities on the relays (once per process). */
  signerCtx(hint: readonly string[] = []): SignerContext {
    return storeSignerContext(this.store, {
      resolveIdentity: (u) => this.discover(u, hint),
    });
  }

  discover(userId: string, hint: readonly string[] = []): Promise<IdentityView | undefined> {
    if (!isUserId(userId)) return Promise.resolve(undefined);
    // Found identities are cached for the process; misses only for P2P_DISCOVER_RETRY_SEC.
    const hit = this.discovered.get(userId);
    if (hit && (hit.found !== false || Date.now() - hit.at < this.tun.discoverRetrySec * 1000)) return hit.p;
    const entry: { p: Promise<IdentityView | undefined>; at: number; found?: boolean } = { at: Date.now(), p: Promise.resolve(undefined) };
    entry.p = (async () => {
      const v = (await this.view(userId)) ?? (await this.refreshIdentity(userId, [...hint, ...(this.self?.relays ?? [])], { force: true, quiet: true }));
      entry.found = v !== undefined;
      return v;
    })();
    this.discovered.set(userId, entry);
    return entry.p;
  }

  /** History of our own chain up to (and including) `hash`, oldest first, for back-filling relays. */
  async ownHistory(hash: string): Promise<string[]> {
    const stored = await this.store.getIdentity(this.userId);
    if (!stored) return [];
    return IdentityChain.fromStored(stored)
      .ancestors(hash)
      .map((d) => d.jws);
  }

  /** Publishes `doc` (already in our chain) to `relays`; remembers the ones that didn't take it. */
  async publishDoc(doc: string, relays: readonly string[]): Promise<{ ok: string[]; failed: { relay: string; code: string }[] }> {
    const pool = this.pool ?? (await this.connect({ allowNone: true }));
    const peek = peekIdentityDoc(doc);
    const history = peek.prev ? await this.ownHistory(peek.prev) : [];
    const ok: string[] = [];
    const failed: { relay: string; code: string }[] = [];
    await Promise.all(
      relays.map(async (r) => {
        try {
          let code: string;
          try {
            code = await pool.publishIdentity(r, doc, history);
          } catch (e) {
            // A relay whose held document doesn't list this device yet (after a restore):
            // identity publishes go over a restricted connection (R4-M2).
            if ((e as CliError).code !== "auth_failed") throw e;
            code = await pool.publishIdentityRestricted(r, doc, history);
          }
          if (code === "ok") {
            ok.push(r);
            this.publishMaybeStored = true;
          } else failed.push({ relay: r, code });
        } catch (e) {
          const code = (e as CliError).code ?? "network";
          failed.push({ relay: r, code });
          // Unknown outcome: the document may have reached the relay.
          if (code !== "unreachable") this.publishMaybeStored = true;
        }
      }),
    );
    await this.updateSelf((s) => recordPublishOutcome(s, ok, failed, Date.now()));
    return { ok, failed };
  }

  /** On connect: relays that failed transiently, and outright refusals whose backoff has passed. */
  async retryUnpublished(): Promise<void> {
    const view = await this.view(this.userId);
    if (!view || !this.self) return;
    const list = relaysToRetry(this.self, Date.now(), this.tun.refusedPublishRetrySec * 1000);
    if (list.length === 0) return;
    this.self = { ...this.self, unpublished: [] };
    await this.publishDoc(view.head.jws, list).catch(() => {});
  }

  /** Publishes our current head again to every relay it lists (R4-M2: `p2p identity republish`). */
  async republish(): Promise<{ ver: number; ok: string[]; failed: { relay: string; code: string }[] }> {
    await this.connect({ allowNone: true });
    await this.refreshIdentity(this.userId, this.relays, { force: true, quiet: true });
    const view = await this.ownView();
    const r = await this.publishDoc(view.head.jws, view.relays);
    return { ver: view.head.ver, ...r };
  }

  /** Takes a newer certificate for this device from disk (another process renewed it) or our own document. */
  private async reloadCert(): Promise<void> {
    const keys = await this.state.get("keys");
    if (keys && keys.did === this.did && certExp(keys.cert) > certExp(this.keys!.cert)) this.keys = { ...this.keys!, cert: keys.cert };
    await this.adoptCertFromDoc();
  }

  /**
   * R4-L2: a relay refused this device. Refresh our own document: if some branch still lists
   * this device (e.g. it was linked during a fork, so it isn't in the intersection yet), retry
   * later with backoff; if none does, it was revoked.
   */
  async authRefusedVerdict(relay: string): Promise<"retry" | "fatal"> {
    // A hostile relay can refuse on every dial: refresh at most once per P2P_REFUSED_REFRESH_SEC
    // per relay, and reuse the verdict in between.
    const last = this.refusedVerdicts.get(relay);
    if (last && Date.now() - last.at < this.tun.refusedRefreshSec * 1000) return last.verdict;
    await this.refreshIdentity(this.userId, this.relays, { force: true, quiet: true });
    const view = await this.view(this.userId);
    const verdict = view && view.tips.some((t) => t.devices.includes(this.did)) ? "retry" : "fatal";
    this.refusedVerdicts.set(relay, { at: Date.now(), verdict });
    return verdict;
  }

  async updateSelf(fn: (s: SelfDoc) => SelfDoc): Promise<SelfDoc> {
    const next = await this.state.update("self", (cur) => {
      const n = fn(cur ?? this.self!);
      return { next: n, result: n };
    });
    this.self = next;
    return next;
  }

  /**
   * Builds, signs and publishes the next version of our identity document
   * (§2.5): fetches the head from every listed relay first and builds on the
   * newest, keeps the device certificates current, and records what this
   * device added (compromise detection).
   */
  async publishNext(
    change: (p: CreateIdentityDocParams) => void,
    opts: {
      restoring?: boolean;
      /** §2.8 step 6: the old identity's final version: no devices, no key holders, carrying the statement (P3). */
      rotation?: RotationStatement;
    } = {},
  ): Promise<{ doc: string; ver: number; ok: string[]; failed: { relay: string; code: string }[]; merged: number }> {
    const ik = this.requireKeyholder("Publishing the identity document");
    // §2.5: build on the newest head the relays hold, or not at all (review H2: a stale key holder
    // republishing blind could fork the identity).
    await this.refreshIdentity(this.userId, this.relays, { force: true, strict: true });
    let view = await this.ownView();
    // What the tips list before any merge: a merge keeps only the intersection (§2.5), so devices
    // only one branch listed are re-added below unless they were revoked (review N-H1).
    const unionDevices = [...new Set(view.tips.flatMap((t) => t.devices))];
    const preTips = view.tips.map((t) => t.hash);
    const unionKeyholders = [...new Set(view.tips.flatMap((t) => t.keyholders))];
    const allCerts = [...new Set(view.tips.flatMap((t) => t.certs ?? []))];
    const merges: string[] = [];
    // §2.5 fork resolution: merge pairwise until one tip remains. Each merge names the higher tip
    // as prev (mergePrevTip), keeps the intersection of devices and key holders, and is published
    // `by` one of its key holders: this device when it is one, else the scheduled writer (the
    // lowest did among the common key holders). The identity key signs either way.
    while (view.tips.length > 1) {
      const [a, b] = view.tips;
      const f = mergeFields(a, b);
      const by = f.keyholders.includes(this.did) ? this.did : scheduledWriter(f.keyholders);
      if (f.devices.length > 0 && !by) {
        throw new CliError(
          "fork_unmergeable",
          "your identity document is forked and the branches share no key holder, so it can't be merged (§2.5). A lost key holder may be publishing: rotate your identity (`p2p identity rotate`, §2.8)",
        );
      }
      const prev = mergePrevTip(a, b).prev;
      const m = createIdentityDoc(ik, {
        ...f,
        by: by ?? this.did,
        certs: allCerts.filter((c) => f.devices.includes(certDid(c) ?? "")),
        ...(prev.proofs ? { proofs: [...prev.proofs] } : {}),
        ...(prev.profile ? { profile: { ...prev.profile } } : {}),
      });
      if ((await addIdentityVersion(this.store, m)).status === "gap") throw new CliError("internal", "the merge does not chain onto the held tips");
      // R3-L2: `by` is nominal on a merge (a common key holder, maybe another device: §2.5 only
      // requires it to be one of the version's key holders). This device records the merge as its
      // own, so its "versions I didn't publish" check never flags it. Another device of ours sees a
      // pure intersection of its parents, which adds no device, relay or proof, so core's
      // detectUnpublishedVersion doesn't alert on it either.
      await this.store.recordPublished({ hash: peekIdentityDoc(m).hash });
      merges.push(m);
      view = await this.ownView();
    }
    const head = view.head;
    const stored = await this.store.getIdentity(this.userId);
    // Only devices a merge dropped come back: never one revoked along the head's ancestry, nor one
    // core denies after a history jump.
    const plan = stored && merges.length > 0 ? planReadd(IdentityChain.fromStored(stored), preTips, unionDevices, view.devices, head.hash, stored.denied ?? []) : { readd: [], skipped: [] };
    for (const d of plan.skipped) this.warn(`device ${d} was dropped by the merge of your identity document's branches; link it again (this device's copy of the history can't prove it wasn't revoked)`);
    const readd = plan.readd;
    const devices = [...view.devices, ...readd].slice(0, MAX_DEVICES);
    const keyholders = [...view.keyholders, ...unionKeyholders.filter((d) => readd.includes(d) && devices.includes(d))];
    if (!opts.restoring && (!devices.includes(this.did) || !keyholders.includes(this.did))) {
      throw new CliError("device_revoked", "this device is no longer a listed key holder of your identity: it can't publish (only identity rotation, §2.8, replaces a lost key holder's key; run it from a listed key holder)");
    }
    const p: CreateIdentityDocParams = {
      ver: head.ver + 1,
      prev: head.hash,
      name: head.name,
      relays: [...head.relays],
      devices,
      keyholders,
      by: this.did,
      certs: [...new Set([...(head.certs ?? []), ...allCerts])],
      ...(head.proofs ? { proofs: [...head.proofs] } : {}),
      ...(head.profile ? { profile: { ...head.profile } } : {}),
    };
    change(p);
    p.by = this.did;
    // docs/compatibility.md: this device's caps and version (`dinfo`), when the user opted in and every
    // relay stores documents with fields it doesn't know; the entries of devices still listed carry
    // over. Off, the document carries none, so clients from before protocol 3.1 can read it.
    if (!opts.rotation && deviceInfoEnabled(this.env, this.home) && (await relaysSupport(this, [...new Set([...p.relays, ...head.relays])], RELAY_FEATURE_LENIENT_IDENTITY))) {
      const kept = Object.fromEntries(Object.entries(head.dinfo ?? {}).filter(([did]) => p.devices.includes(did)));
      p.dinfo = { ...kept, [this.did]: { caps: [...CLI_CAPS], client: VERSION } };
    } else {
      delete p.dinfo;
    }
    if (opts.rotation) {
      // The final version lists nobody: relays then refuse every old did, and nothing may follow it.
      p.devices = [];
      p.keyholders = [];
      delete p.certs;
      p.rotation = opts.rotation;
    } else {
      if (!p.keyholders.includes(this.did)) throw new CliError("usage", "this device can't drop itself as a key holder");
      p.certs = await this.currentCerts(ik, p.devices, p.certs ?? []);
    }
    const doc = createIdentityDoc(ik, p);
    const added = await addIdentityVersion(this.store, doc);
    if (added.status === "gap") throw new CliError("internal", "the new version does not chain onto the held head");
    await this.store.recordPublished({
      hash: peekIdentityDoc(doc).hash,
      devices: p.devices.filter((d) => !head.devices.includes(d)),
      relays: p.relays.filter((r) => !head.relays.includes(r)),
    });
    const targets = [...new Set([...p.relays, ...head.relays])];
    for (const m of merges) await this.publishDoc(m, targets);
    const r = await this.publishDoc(doc, targets);
    await this.updateSelf((s) => ({ ...s, relays: p.relays, name: p.name }));
    return { doc, ver: p.ver, ...r, merged: merges.length };
  }

  /** One certificate per listed device: renewed when within 30 days of expiry (key holders renew, §2.3). */
  private async currentCerts(ik: IdentityKey, devices: readonly string[], certs: readonly string[]): Promise<string[]> {
    const out: string[] = [];
    const now = nowSec();
    for (const d of devices) {
      const candidates = certs.filter((c) => certDid(c) === d);
      if (d === this.did) candidates.push(this.keys!.cert);
      const stored = await this.store.getDeviceCert(d);
      if (stored) candidates.push(stored.jws);
      let best: { jws: string; exp: number; spk: Uint8Array; kpk: Uint8Array; label?: string } | undefined;
      for (const c of candidates) {
        try {
          const v = verifyDeviceCertV3(c, { now });
          if (v.iss !== this.userId) continue;
          if (!best || v.exp > best.exp) best = { jws: c, exp: v.exp, spk: v.signingPublicKey, kpk: v.agreementPublicKey, label: v.label };
        } catch {
          // expired or malformed: maybe another candidate
        }
      }
      if (!best) continue;
      if (best.exp - now <= RENEW_CERT_WITHIN_SEC) {
        const renewed = createDeviceCert(ik, { signingPublicKey: best.spk, agreementPublicKey: best.kpk, ...(best.label ? { label: best.label } : {}) });
        best = { ...best, jws: renewed };
        if (d === this.did) await this.adoptCert(renewed);
      }
      out.push(best.jws);
    }
    return out;
  }

  /** Switches this device to a newer certificate for itself (renewal keeps did, spk and kpk). */
  async adoptCert(cert: string): Promise<void> {
    const v = verifyDeviceCertV3(cert);
    if (v.did !== this.did || v.iss !== this.userId) return;
    if (v.exp <= certExp(this.keys!.cert)) return;
    const keys = await this.state.update("keys", (k) => {
      const n = { ...(k ?? this.keys!), cert };
      return { next: n, result: n };
    });
    this.keys = keys;
    await this.store.putDeviceCert({ userId: this.userId, did: this.did, exp: v.exp, jws: cert });
  }

  /** A non-key-holding device takes a renewed certificate from its own document (§2.3 renewal by sync or document). */
  async adoptCertFromDoc(): Promise<void> {
    const view = await this.view(this.userId);
    if (!view) return;
    for (const t of view.tips) {
      for (const c of t.certs ?? []) {
        if (certDid(c) === this.did) await this.adoptCert(c).catch(() => {});
      }
    }
  }

  // -------------------------------------------------------------------------
  // Names

  async nameOf(userId: string): Promise<string> {
    const v = await this.view(userId);
    return v?.head.name ?? "?";
  }

  /** `<petname or name>@<fp>` (§2.1: always with the fingerprint). */
  async addressOf(userId: string): Promise<string> {
    if (!isUserId(userId)) return userId;
    const pet = await this.store.getPetname(userId);
    return displayAddress(userId, await this.nameOf(userId), pet);
  }

  /**
   * A userId from what the user typed: a userId, a petname, a display
   * address `name@xxxx-xxxx-xxxx-xxxx`, or a name when it is unique among
   * known identities. Decisions always use the full userId (§2.1).
   */
  async resolveUser(input: string): Promise<string> {
    const s = input.trim();
    if (isUserId(s)) return s;
    if (s === "me" || s === "self") return this.userId;
    const pets = await this.store.listPetnames();
    const byPet = Object.entries(pets).filter(([, p]) => p === s);
    if (byPet.length === 1) return byPet[0][0];
    const known = await this.store.listIdentities();
    const at = /^(.+)@([a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4})$/.exec(s);
    if (at) {
      const hits: string[] = [];
      for (const u of known) {
        if (displayFingerprint(u) !== at[2]) continue;
        const name = await this.nameOf(u);
        if (pets[u] === at[1] || name === at[1]) hits.push(u);
      }
      if (hits.length === 1) return hits[0];
      if (hits.length > 1) throw new CliError("ambiguous", `${s} matches more than one identity`, { candidates: hits });
      throw new CliError("not_found", `no known identity is ${s}`);
    }
    if (isValidName(s)) {
      const hits: string[] = [];
      for (const u of known) if ((await this.nameOf(u)) === s) hits.push(u);
      if (hits.length === 1) return hits[0];
      if (hits.length > 1) {
        throw new CliError("ambiguous", `more than one known identity is called ${s}: use name@fingerprint, the userId, or a petname`, {
          candidates: await Promise.all(hits.map(async (u) => ({ userId: u, address: await this.addressOf(u) }))),
        });
      }
    }
    throw new CliError("not_found", `no known identity matches ${s}`);
  }

  // -------------------------------------------------------------------------
  // Capabilities (§5.3)

  /** A cap minted by this device for our own mailboxes (any of our devices may issue one for itself). */
  selfCap(): string {
    return createCap(this.device!, this.keys!.cert, { purpose: "friend", sub: this.userId, relays: this.relays, ttlSec: 7 * 86_400 });
  }

  /** Caps we hold that let us reach `to` with `kind`, by relay (best first). */
  async capsFor(to: string, kind: string, extra: readonly string[] = []): Promise<Map<string, string>> {
    const now = nowSec();
    const cands: { jws: string; relays: string[]; kinds: string[]; exp: number }[] = [];
    if (to === this.userId) {
      const c = this.selfCap();
      cands.push({ jws: c, relays: this.relays, kinds: ["*"], exp: now + 7 * 86_400 });
    }
    for (const c of await this.store.listCapsHeld(to)) {
      if (c.sub === this.userId || c.sub === "*") cands.push({ jws: c.jws, relays: c.relays, kinds: c.kinds, exp: c.exp });
    }
    const joinCaps = [...extra];
    // Co-member caps only while both of us are in the circle (§5.3: they are for co-members).
    for (const rec of await this.store.listCircles()) {
      if (!rec.joinedByMe) continue;
      const s = rec.statements[to];
      if (s?.op === "join" && CircleChain.fromStored(rec.chain).head.members.includes(to)) {
        const cap = joinCapOf(s.jws);
        if (cap) joinCaps.push(cap);
      }
    }
    for (const j of joinCaps) {
      const p = capPeek(j);
      if (p && p.iss === to && (p.sub === "*" || p.sub === this.userId)) cands.push({ jws: j, relays: p.relays, kinds: p.kinds, exp: p.exp });
    }
    const usable = cands.filter((c) => c.exp > now + 60 && capAllowsKind(c.kinds, kind)).sort((a, b) => CAP_PRIORITY(a) - CAP_PRIORITY(b) || b.exp - a.exp);
    const out = new Map<string, string>();
    for (const c of usable) for (const r of c.relays) if (!out.has(r)) out.set(r, c.jws);
    return out;
  }

  /** Records a cap this device issued, so it can be revoked later (§5.3). */
  async recordIssued(capJws: string): Promise<StoredCapV3> {
    const p = capPeek(capJws)!;
    const c: StoredCapV3 = { capid: p.capid, iss: p.iss, sub: p.sub, relays: p.relays, kinds: p.kinds, exp: p.exp, jws: capJws };
    await this.store.addCapIssued(c);
    return c;
  }

  /** Sends `revoke` for each cap to every relay it names. */
  async revokeCaps(caps: readonly StoredCapV3[]): Promise<number> {
    if (caps.length === 0) return 0;
    const pool = this.pool ?? (await this.connect({ allowNone: true }));
    let n = 0;
    for (const c of caps) if ((await pool.revoke(c.capid, c.relays)).length > 0) n++;
    return n;
  }

  // -------------------------------------------------------------------------
  // Delivery (§4.1, §5.4, §5.8)

  /**
   * Seals `plaintext` to every current device of `to` and sends each copy to
   * up to 3 of their relays. Our own devices are reached with a cap this
   * device mints; others with a held cap, or PoW for a cap-less `contact`.
   */
  async deliver(
    to: string,
    kind: EnvelopeKindV3,
    session: { own: string; sid: string },
    plaintext: object,
    opts: {
      refresh?: boolean;
      extraCaps?: readonly string[];
      hint?: readonly string[];
      onlyDevices?: readonly string[];
      /** Called with each copy's device and seq once they are known, before any copy goes out. */
      beforeSend?: (copies: { did: string; seq: number }[]) => Promise<void>;
    } = {},
  ): Promise<Delivery> {
    const pool = this.pool ?? (await this.connect());
    const { targets, outgoing, errors, sealed } = await this.sealCopies(to, kind, session, plaintext, opts);
    const sentVia = new Set<string>();
    const results = await Promise.all(outgoing.map(({ d, env }) => pool.sendEnvelope(env, to, d, kind, targets)));
    const unsent: NonNullable<Delivery["unsent"]> = [];
    for (const [i, res] of results.entries()) {
      for (const r of res.sent) sentVia.add(r);
      for (const e of res.errors) errors.push({ did: outgoing[i].d, relay: e.relay, code: e.code, ...(e.written ? { written: true } : {}) });
      if (res.sent.length === 0) unsent.push({ did: outgoing[i].d, env: outgoing[i].env, targets, codes: res.errors.map((e) => e.code) });
    }
    return { userId: to, devices: sealed, relays: [...sentVia], ...(errors.length > 0 ? { errors } : {}), ...(unsent.length > 0 ? { unsent } : {}) };
  }

  /**
   * Seals `plaintext` for `to` exactly as deliver does (the same devices, a fresh seq each, the same
   * relays and caps) and sends nothing: copies for the outbox to send later (outbox.ts).
   */
  async seal(
    to: string,
    kind: EnvelopeKindV3,
    session: { own: string; sid: string },
    plaintext: object,
    opts: { onlyDevices?: readonly string[]; beforeSend?: (copies: { did: string; seq: number }[]) => Promise<void> } = {},
  ): Promise<{ did: string; env: string; targets: { relay: string; cap?: string }[] }[]> {
    const { targets, outgoing } = await this.sealCopies(to, kind, session, plaintext, opts);
    return outgoing.map(({ d, env }) => ({ did: d, env, targets }));
  }

  private async sealCopies(
    to: string,
    kind: EnvelopeKindV3,
    session: { own: string; sid: string },
    plaintext: object,
    opts: { refresh?: boolean; extraCaps?: readonly string[]; hint?: readonly string[]; onlyDevices?: readonly string[]; beforeSend?: (copies: { did: string; seq: number }[]) => Promise<void> },
  ): Promise<{ targets: { relay: string; cap?: string }[]; outgoing: { d: string; env: string }[]; errors: NonNullable<Delivery["errors"]>; sealed: number }> {
    const view = to === this.userId ? await this.ownView() : await this.viewFor(to, { refresh: opts.refresh, hint: opts.hint });
    if (!view) throw new CliError("unknown_user", `no identity document for ${to}: can't find their devices or relays`);
    // This device only when named in onlyDevices (a message to another session of ours here, or a
    // receipt for one): sealed to itself and sent through a relay like any other copy.
    const devices = view.devices.filter((d) => (to !== this.userId || d !== this.did || opts.onlyDevices?.includes(d) === true) && (!opts.onlyDevices || opts.onlyDevices.includes(d)));
    const relays = orderRelays(view.head.relays, view.relays).slice(0, 3);
    const caps = await this.capsFor(to, kind, opts.extraCaps);
    const resolveCert = storeCertResolver(this.store);
    const errors: NonNullable<Delivery["errors"]> = [];
    // Certificates first (each verified, as before), then one seq block for every copy, then the
    // copies go out together: one round trip for all of the recipient's devices, not one each.
    const ready: { d: string; kpk: Uint8Array }[] = [];
    for (const d of devices) {
      const certJws = await resolveCert(to, d);
      if (!certJws) {
        errors.push({ did: d, relay: "", code: "no-cert" });
        continue;
      }
      try {
        ready.push({ d, kpk: verifyDeviceCertV3(certJws, { identityDoc: { iss: view.iss, ik: view.ik, devices: view.devices } }).agreementPublicKey });
      } catch (e) {
        errors.push({ did: d, relay: "", code: (e as P2PError).reason ?? "bad-cert" });
      }
    }
    const seqs = ready.length > 0 ? await this.state.nextSeqs(session.own, session.sid, ready.length) : [];
    if (opts.beforeSend && ready.length > 0) await opts.beforeSend(ready.map((r, i) => ({ did: r.d, seq: seqs[i] })));
    const targets = relays.map((r) => ({ relay: r, cap: caps.get(r) })).filter((t) => t.cap !== undefined || kind === "contact");
    const outgoing: { d: string; env: string }[] = [];
    for (const [i, { d, kpk }] of ready.entries()) {
      const env = sealEnvelopeV3({
        from: this.userId,
        fdid: this.did,
        fcert: this.keys!.cert,
        to,
        tdid: d,
        own: session.own,
        sid: session.sid,
        seq: seqs[i],
        ts: Date.now(),
        kind,
        plaintext,
        sender: { signingSecretKey: this.device!.signingSecretKey, agreementSecretKey: this.device!.agreementSecretKey },
        recipientKpk: kpk,
      });
      if (targets.length === 0) errors.push({ did: d, relay: "", code: "no-cap" });
      else outgoing.push({ d, env });
    }
    return { targets, outgoing, errors, sealed: ready.length };
  }

  /** Delivers to our other devices, when there are any (sync, §4.3). */
  async syncOwn(body: Record<string, unknown>): Promise<Delivery | undefined> {
    const view = await this.view(this.userId);
    if (!view || view.devices.filter((d) => d !== this.did).length === 0) return undefined;
    try {
      return await this.deliver(this.userId, "sync", { own: this.userId, sid: "~sync" }, body);
    } catch (e) {
      this.io.err(`sync to your other devices failed: ${(e as Error).message}`);
      return undefined;
    }
  }
}

/**
 * Does the held history cover every branch back to their common ancestor?
 * (Each version above the common ancestry has its parents held.) Only then
 * is revokedAlong complete for those branches (R3-M3).
 */
export function branchesCovered(chain: IdentityChain, tips: readonly string[]): boolean {
  if (tips.length < 2) return true;
  const ancestry = tips.map((t) => new Set(chain.ancestors(t).map((v) => v.hash)));
  const common = ancestry.reduce((a, b) => new Set([...a].filter((x) => b.has(x))));
  if (common.size === 0) return false;
  for (const anc of ancestry) {
    for (const h of anc) {
      if (common.has(h)) continue;
      const v = chain.get(h);
      if (!v) return false;
      if (v.prev !== null && !chain.has(v.prev)) return false;
      if (v.merge !== undefined && !chain.has(v.merge)) return false;
    }
  }
  return true;
}

/**
 * After merging `tips` into `head`: the devices to re-add (listed by some
 * pre-merge tip, dropped by the merge, not revoked along the head's
 * ancestry, not denied after a jump), but only when the held history covers
 * every branch; otherwise they are `skipped` (fail closed, R3-M3).
 */
export function planReadd(
  chain: IdentityChain,
  tips: readonly string[],
  unionDevices: readonly string[],
  mergedDevices: readonly string[],
  head: string,
  denied: readonly string[],
): { readd: string[]; skipped: string[] } {
  const revoked = chain.revokedAlong(head);
  const cands = unionDevices.filter((d) => !mergedDevices.includes(d) && !revoked.has(d) && !denied.includes(d));
  if (cands.length === 0) return { readd: [], skipped: [] };
  return branchesCovered(chain, tips) ? { readd: cands, skipped: [] } : { readd: [], skipped: cands };
}

/** Publish failures worth retrying on every connect; anything else is an outright refusal. */
export const TRANSIENT_PUBLISH_CODES: readonly string[] = ["network", "auth_failed", "identity-gap"];

/**
 * After a publish: transient failures go to `unpublished` (retried on every connect); outright
 * refusals (e.g. `forbidden`) are timestamped in `refusedPublish` (retried at most hourly, or by an
 * explicit `p2p identity republish`); relays that took it are cleared from both.
 */
export function recordPublishOutcome(s: SelfDoc, ok: readonly string[], failed: readonly { relay: string; code: string }[], now: number): SelfDoc {
  const refused: Record<string, number> = { ...(s.refusedPublish ?? {}) };
  for (const r of ok) delete refused[r];
  const unpublished: string[] = [];
  for (const f of failed) {
    if (TRANSIENT_PUBLISH_CODES.includes(f.code)) {
      unpublished.push(f.relay);
      delete refused[f.relay];
    } else refused[f.relay] = now;
  }
  const out: SelfDoc = { ...s, unpublished };
  if (Object.keys(refused).length > 0) out.refusedPublish = refused;
  else delete out.refusedPublish;
  return out;
}

/** The relays to retry on connect: transient failures, and refusals older than `backoffMs`. */
export function relaysToRetry(s: SelfDoc, now: number, backoffMs: number): string[] {
  const due = Object.entries(s.refusedPublish ?? {})
    .filter(([, at]) => now - at >= backoffMs)
    .map(([r]) => r);
  return [...new Set([...(s.unpublished ?? []), ...due])];
}

/** The relays a document lists, head's first, then any other tip's. */
export function orderRelays(head: readonly string[], all: readonly string[]): string[] {
  return [...new Set([...head, ...all])];
}

export function certDid(jws: string): string | undefined {
  try {
    const d = decodeTyped(jws, TYP3.device).payload.did;
    return typeof d === "string" ? d : undefined;
  } catch {
    return undefined;
  }
}

export function certExp(jws: string): number {
  try {
    const e = decodeTyped(jws, TYP3.device).payload.exp;
    return typeof e === "number" ? e : 0;
  } catch {
    return 0;
  }
}

export interface CapPeek {
  iss: string;
  sub: string;
  capid: string;
  relays: string[];
  kinds: string[];
  exp: number;
}

/** A cap's payload, unverified (for routing our own sends; the relay and the issuer verify). */
export function capPeek(jws: string): CapPeek | undefined {
  try {
    const p = decodeTyped(jws, TYP3.cap).payload;
    if (typeof p.iss !== "string" || typeof p.sub !== "string" || typeof p.capid !== "string" || typeof p.exp !== "number") return undefined;
    const relays = Array.isArray(p.relays) ? p.relays.filter((x): x is string => typeof x === "string") : [];
    const kinds = Array.isArray(p.kinds) ? p.kinds.filter((x): x is string => typeof x === "string") : [];
    return { iss: p.iss, sub: p.sub, capid: p.capid, relays, kinds, exp: p.exp };
  } catch {
    return undefined;
  }
}

/** The co-member cap a join statement carries (§3.3, review M3). */
export function joinCapOf(statementJws: string): string | undefined {
  try {
    const cap = decodeTyped(statementJws, TYP3.join).payload.cap;
    return typeof cap === "string" ? cap : undefined;
  } catch {
    return undefined;
  }
}

/** A default display name from the OS user: `[a-z0-9._-]{1,32}`, else "me". */
export function defaultName(): string {
  let n: string;
  try {
    n = userInfo().username.toLowerCase().replace(/[^a-z0-9._-]/g, "").slice(0, 32);
  } catch {
    n = "";
  }
  return isValidName(n) ? n : "me";
}

/** A device label: the host name, sanitized and capped at 64. */
export function defaultLabel(): string {
  const h = hostname().replace(/[^\w.-]/g, "").slice(0, 64);
  return h || "device";
}

export function newKeysDoc(userId: string, device: DeviceKeysV3, cert: string, ik?: IdentityKey): KeysDoc {
  return {
    v: 1,
    userId,
    did: device.did,
    spk: b64uEncode(device.signingSecretKey),
    kpk: b64uEncode(device.agreementSecretKey),
    cert,
    ...(ik ? { ik: b64uEncode(ik.secretKey) } : {}),
  };
}

/** P2P_DEBUG lines for a store lock that was waited for or held long enough to matter. */
function lockLogger(p: Progress): NonNullable<LockOptions["onLock"]> {
  return ({ dir, waitedMs, attempts, heldMs }) => {
    if (waitedMs >= 10 || heldMs >= 50) debug(p, `lock ${basename(dir)}: waited ${waitedMs}ms (${attempts} tries), held ${heldMs}ms`);
  };
}
