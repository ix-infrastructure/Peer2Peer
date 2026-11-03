// Copyright 2026 Ix Infrastructure Inc.
//
// Who may release (or decline) a held message: the person, never the model.
// The local socket is reachable by anything running as the user, the
// model's own commands included (Codex's sandbox lets them open Unix
// sockets), and process ancestry proves nothing (setsid plus a double fork
// reparents a daemon to init). What a sandboxed command can't escape is the
// sandbox itself, so a release rests on it:
//   1. a nonce file: `p2p codex release` first writes a file into
//      P2P_HOME/codex/confirm/ (0600) named by the hash of a secret it keeps,
//      then sends the secret; the bridge accepts only a fresh (< 60 s),
//      matching file, owned by this user, in real (not symlinked) folders,
//      and deletes it. Reading the folder isn't enough to spend it;
//   2. P2P_HOME out of the sandbox's reach: the bridge checks P2P_HOME is
//      outside every writable root of the session's trusted turn context
//      (Bridge.releaseReach). Inside one, under danger-full-access, or with
//      unknown roots, releases over the socket are refused outright;
//   3. a second factor when the bridge has a terminal (Codex's own window):
//      a one-time code printed only there, typed back into the command.
// Plus rate limits with backoff, so nothing can spam banners or guess
// codes, kept apart: requests without a valid nonce (or from a Codex
// descendant) never push the person's own releases into backoff. And a
// refusal for callers the OS shows descend from Codex (cheap, never
// sufficient on its own).

import { createHash, randomBytes, randomInt } from "node:crypto";
import { chmodSync, closeSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeFileSync, writeSync } from "node:fs";
import { join } from "node:path";

const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const CODE_TTL_MS = 2 * 60_000;
const MAX_TRIES = 3;
export const NONCE_TTL_MS = 60_000;
/** Requests (challenges and confirmations) allowed per minute, across all held items. */
export const RATE_PER_MINUTE = 5;
const BACKOFF_BASE_MS = 2_000;
const BACKOFF_MAX_MS = 15 * 60_000;
/** Requests without a valid nonce (or from a Codex descendant) a minute: counted apart from the person's. */
const STRANGER_PER_MINUTE = 30;

export type GateAnswer = { ok: true } | { ok: false; needsCode?: true; reason: string };
export type Nonce = { secret: string };

export interface GateDeps {
  /** A writer for this bridge's terminal, or null when it has none. */
  tty: () => ((text: string) => void) | null;
  /** Whether that pid descends from Codex (or this bridge). */
  descends: (pid: number) => Promise<boolean>;
  /** Whether releases over the socket can be trusted at all (P2P_HOME out of the sandbox's reach). */
  reach: () => { ok: true } | { ok: false; reason: string };
  /** Checks and consumes the person's nonce file. */
  nonce: (op: string, id: string, nonce: Nonce | undefined) => boolean;
  now: () => number;
  code?: () => string;
  /** Requests a minute (default RATE_PER_MINUTE). */
  ratePerMinute?: number;
}

/** A writer for `path` (default: the controlling terminal), or null when it can't be opened. */
export function ttyWriter(path: string | undefined): () => ((text: string) => void) | null {
  return () => {
    const target = path?.trim() || (process.platform === "win32" ? "" : "/dev/tty");
    if (!target) return null;
    let fd: number;
    try {
      fd = openSync(target, "a");
    } catch {
      return null;
    }
    return (text: string) => {
      try {
        writeSync(fd, text);
      } finally {
        closeSync(fd);
      }
    };
  };
}

export function newCode(): string {
  let out = "";
  for (let i = 0; i < 6; i++) out += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
  return out;
}

export function confirmDir(home: string): string {
  return join(home, "codex", "confirm");
}

const SECRET_RE = /^[0-9a-f]{64}$/;

/** The nonce file's name, derived from the secret the CLI keeps: a folder listing (or the file) never reveals the secret. */
export function nonceFileName(secret: string): string {
  return `${createHash("sha256").update(`p2p-codex-nonce:${secret}`).digest("hex")}.nonce`;
}

/** P2P_HOME/codex and its confirm/ folder are real folders, not symbolic links (which could lead the file anywhere). */
function confirmDirIsReal(home: string): boolean {
  for (const dir of [join(home, "codex"), confirmDir(home)]) {
    try {
      const st = lstatSync(dir);
      if (st.isSymbolicLink() || !st.isDirectory()) return false;
    } catch {
      return false;
    }
  }
  return true;
}

/**
 * `p2p codex release|decline`, before each request: a nonce file in
 * P2P_HOME/codex/confirm/ (folder 0700, file 0600) naming the operation and
 * the held id. Its name is a hash of a secret only this process keeps and
 * sends over the socket, so a sandboxed process that can read the folder
 * still can't present it (and so can't spend it). The bridge consumes it.
 */
export function writeNonce(home: string, op: string, id: string): Nonce {
  const dir = confirmDir(home);
  for (const d of [join(home, "codex"), dir]) {
    try {
      if (lstatSync(d).isSymbolicLink()) throw new Error(`${d} is a symbolic link: refusing to write a confirmation there`);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    }
  }
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    chmodSync(dir, 0o700);
  } catch {}
  const secret = randomBytes(32).toString("hex");
  const name = nonceFileName(secret);
  const tmp = join(dir, `.${name}.tmp`);
  writeFileSync(tmp, JSON.stringify({ op, id }), { mode: 0o600 });
  renameSync(tmp, join(dir, name));
  return { secret };
}

/**
 * The bridge's check: the file the secret names exists in a real (not
 * symlinked) P2P_HOME/codex/confirm, is a regular file owned by this user,
 * is fresh, and holds this operation and this id. It is deleted either way.
 */
export function consumeNonce(home: string, op: string, id: string, nonce: Nonce | undefined, now: number): boolean {
  if (!nonce || typeof nonce.secret !== "string" || !SECRET_RE.test(nonce.secret)) return false;
  if (!confirmDirIsReal(home)) return false;
  const file = join(confirmDir(home), nonceFileName(nonce.secret));
  try {
    const st = lstatSync(file);
    if (!st.isFile() || st.isSymbolicLink()) return false;
    if (typeof process.getuid === "function" && st.uid !== process.getuid()) return false;
    if (now - st.mtimeMs > NONCE_TTL_MS || st.mtimeMs - now > 5_000) return false;
    const v = JSON.parse(readFileSync(file, "utf8")) as { op?: unknown; id?: unknown };
    return v.op === op && v.id === id;
  } catch {
    return false;
  } finally {
    rmSync(file, { force: true });
  }
}

/** A sliding-window rate limit with exponential backoff after failures. */
class Limiter {
  private recent: number[] = [];
  private failures = 0;
  private blockedUntil = 0;

  constructor(
    private readonly perMinute: number,
    private readonly now: () => number,
  ) {}

  /** Why a request must wait, or undefined (and the request is counted). */
  take(): string | undefined {
    const now = this.now();
    if (now < this.blockedUntil) return `too many failed attempts: wait ${Math.ceil((this.blockedUntil - now) / 1000)} s`;
    this.recent = this.recent.filter((at) => now - at < 60_000);
    if (this.recent.length >= this.perMinute) return `at most ${this.perMinute} release or decline requests a minute: wait a moment`;
    this.recent.push(now);
    return undefined;
  }

  fail(): void {
    this.failures += 1;
    if (this.failures >= 2) this.blockedUntil = this.now() + Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** (this.failures - 2));
  }

  succeed(): void {
    this.failures = 0;
    this.blockedUntil = 0;
  }
}

export class PersonGate {
  private readonly challenges = new Map<string, { code: string; exp: number; tries: number }>();
  /** The person's requests (they came with a valid nonce): code failures back off here. */
  private readonly person: Limiter;
  /** Everything else (no valid nonce, or a Codex descendant): counted apart, so it never delays the person. */
  private readonly stranger: Limiter;

  constructor(private readonly deps: GateDeps) {
    this.person = new Limiter(deps.ratePerMinute ?? RATE_PER_MINUTE, deps.now);
    this.stranger = new Limiter(STRANGER_PER_MINUTE, deps.now);
  }

  /**
   * Checks one release/decline request. `what` is how the terminal line
   * names the message (the sender, and a one-line preview, which only the
   * person's Codex window shows); `peer` finds the caller's pid where the OS
   * says; `nonce` carries the secret naming the person's nonce file.
   */
  async check(op: "release" | "decline", id: string, code: string | undefined, what: string, peer: () => Promise<number | undefined>, nonce: Nonce | undefined): Promise<GateAnswer> {
    const reach = this.deps.reach();
    if (!reach.ok) return { ok: false, reason: reach.reason };
    if (!this.deps.nonce(op, id, nonce)) {
      const wait = this.stranger.take();
      this.stranger.fail();
      return { ok: false, reason: wait ?? `refused: no fresh confirmation file from \`p2p codex ${op}\` (it writes one in P2P_HOME/codex/confirm; run it yourself, with the same P2P_HOME as Codex)` };
    }
    const pid = await peer();
    if (pid !== undefined && (await this.deps.descends(pid))) {
      this.stranger.fail();
      return { ok: false, reason: `refused: this ${op} came from a process Codex started (possibly the model's own command). Run \`p2p codex ${op}\` in a separate terminal, outside Codex.` };
    }
    const wait = this.person.take();
    if (wait) return { ok: false, reason: wait };
    const write = this.deps.tty();
    // No terminal: the nonce file, which only something outside the sandbox can write, is enough.
    if (!write) {
      this.person.succeed();
      return { ok: true };
    }
    const now = this.deps.now();
    const key = `${op}:${id}`;
    const have = this.challenges.get(key);
    if (code !== undefined && have) {
      if (have.exp > now && have.code === code.trim().toUpperCase()) {
        this.challenges.delete(key);
        this.person.succeed();
        return { ok: true };
      }
      have.tries += 1;
      if (have.tries >= MAX_TRIES || have.exp <= now) this.challenges.delete(key);
      this.person.fail();
      return { ok: false, reason: have.exp <= now ? "that code expired: run the command again for a new one" : "wrong code" };
    }
    const fresh = (this.deps.code ?? newCode)();
    this.challenges.set(key, { code: fresh, exp: now + CODE_TTL_MS, tries: 0 });
    try {
      write(`\r\n[Peer2Peer] To ${op} ${what}: type ${fresh} into \`p2p codex ${op}\` in a separate terminal (valid 2 minutes). Never paste it into Codex.\r\n`);
    } catch {
      this.challenges.delete(key);
      return { ok: false, reason: "couldn't show a confirmation code in the Codex window" };
    }
    return { ok: false, needsCode: true, reason: "type the code shown in your Codex window" };
  }
}
