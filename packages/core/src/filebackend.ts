// Copyright 2026 Ix Infrastructure Inc.
//
// The file DocBackend shared by the v2 and v3 trust stores: one `<name>.json`
// per document, written atomically (temp file, fsync, rename, directory
// fsync) under a 0700 directory, with a cross-process lockfile
// (docs/protocol-v2.md C7, C14). Node-only.

import { constants as fsConstants, promises as fs } from "node:fs";
import { homedir, hostname } from "node:os";
import { join } from "node:path";
import { randomBytes } from "./crypto.js";
import { b64uEncode } from "./encoding.js";
import type { DocBackend } from "./docbackend.js";

export const DIR_MODE = 0o700;
export const FILE_MODE = 0o600;

export function defaultTrustDir(): string {
  return join(homedir(), ".ix", "p2p");
}

/**
 * One `<name>.json` per document under `dir`. The directory is created 0700
 * (and tightened to 0700 if it exists); files are written 0600 to a temp file,
 * fsynced, and renamed over the target.
 */
export class FileDocBackend implements DocBackend {
  private ready?: Promise<void>;
  private readonly lockOpts: LockOptions;

  constructor(
    readonly dir: string = defaultTrustDir(),
    lockOpts: Partial<LockOptions> = {},
  ) {
    this.lockOpts = { timeoutMs: LOCK_TIMEOUT_MS, staleMs: LOCK_STALE_MS, refreshMs: LOCK_REFRESH_MS, ...lockOpts };
  }

  private ensureDir(): Promise<void> {
    this.ready ??= (async () => {
      await fs.mkdir(this.dir, { recursive: true, mode: DIR_MODE });
      await fs.chmod(this.dir, DIR_MODE);
    })();
    return this.ready;
  }

  async read(name: string) {
    let text: string;
    try {
      text = await fs.readFile(join(this.dir, `${name}.json`), "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw e;
    }
    return JSON.parse(text);
  }

  async remove(name: string) {
    await fs.rm(join(this.dir, `${name}.json`), { force: true });
  }

  async write(name: string, value: unknown) {
    await this.ensureDir();
    const target = join(this.dir, `${name}.json`);
    const tmp = join(this.dir, `.${name}.json.${process.pid}.${b64uEncode(randomBytes(6))}.tmp`);
    const fh = await fs.open(tmp, "wx", FILE_MODE);
    try {
      await fh.writeFile(JSON.stringify(value));
      await fh.sync();
    } catch (e) {
      // A failed write (a full disk: retried, so it repeats) must not leave its temp file behind.
      await fh.close().catch(() => {});
      await fs.rm(tmp, { force: true }).catch(() => {});
      throw e;
    }
    await fh.close();
    try {
      await fs.rename(tmp, target);
    } catch (e) {
      await fs.rm(tmp, { force: true });
      throw e;
    }
    // Make the rename itself durable.
    try {
      const dh = await fs.open(this.dir, "r");
      try {
        await dh.sync();
      } finally {
        await dh.close();
      }
    } catch {
      // Some platforms can't fsync a directory; the data file itself is synced.
    }
  }

  /**
   * Cross-process lock: an exclusive-create `.lock` file in the store
   * directory holding `{pid, host, token}`.
   *  - Release removes the lock only if it still carries our token.
   *  - The holder refreshes the lock's mtime every `refreshMs`, so a live
   *    holder's lock never looks old.
   *  - A lock is broken only when its holder is gone: same host and the pid
   *    is dead (`process.kill(pid, 0)`), or, when the pid can't be checked
   *    (another host, or unreadable content), it is older than `staleMs`.
   *  - Breaking is serialised on a second lock (`.lock.break`) and the lock
   *    is re-read and re-judged under it before removal, so only a dead lock
   *    is ever removed: nobody else can create `.lock` while it exists.
   *  - The lock appears with its content (LockCreator): its body is written
   *    to a temp file that is hard-linked into place, or, without hard links,
   *    copied into place exclusively. Created empty and then written, a
   *    process that exited in between (a command's exit while a handler still
   *    ran) left an empty lock that held every p2p process of the home for
   *    LOCK_STALE_MS. An empty lock (only an older client makes one now) is
   *    judged like any unreadable one: by LOCK_STALE_MS. A shorter rule would
   *    let a stalled creator, or a file server whose clock is behind, look
   *    dead while it holds the lock (pre-release review M-B).
   */
  async withLock<T>(fn: () => Promise<T>): Promise<T> {
    await this.ensureDir();
    const lock = join(this.dir, ".lock");
    const token = b64uEncode(randomBytes(16));
    const body = JSON.stringify({ pid: process.pid, host: hostname(), token });
    const t0 = Date.now();
    const deadline = t0 + this.lockOpts.timeoutMs;
    let attempt = 0;
    let nextWaitNote = 1000;
    const created = new LockCreator(lock, body);
    for (; ; attempt++) {
      try {
        await created.create();
        break;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
        if (await this.breakIfStale(lock)) continue;
        if (Date.now() > deadline) throw new Error(`trust store ${this.dir} is locked`, { cause: e });
        if (this.lockOpts.onLockWait && Date.now() - t0 >= nextWaitNote) {
          nextWaitNote += 1000;
          this.lockOpts.onLockWait({ dir: this.dir, waitedMs: Date.now() - t0, holderPid: (await readLock(lock))?.pid });
        }
        await sleep(Math.min(5 * 2 ** attempt, 50));
      }
    }
    const refresh = setInterval(() => {
      void (async () => {
        if ((await readLock(lock))?.token === token) {
          const t = new Date();
          await fs.utimes(lock, t, t).catch(() => {});
        }
      })();
    }, this.lockOpts.refreshMs);
    refresh.unref?.();
    const got = Date.now();
    try {
      return await fn();
    } finally {
      clearInterval(refresh);
      if ((await readLock(lock))?.token === token) await fs.rm(lock, { force: true });
      this.lockOpts.onLock?.({ dir: this.dir, waitedMs: got - t0, attempts: attempt + 1, heldMs: Date.now() - got });
    }
  }

  /** Is the lock whose content is `raw` and mtime `mtimeMs` held by someone gone? */
  private isStale(raw: string, mtimeMs: number): boolean {
    const held = parseLock(raw);
    if (held && held.host === hostname()) return !pidAlive(held.pid);
    return Date.now() - mtimeMs > this.lockOpts.staleMs;
  }

  /**
   * Breaks `lock` if its holder is gone; true when the caller should retry at
   * once. Breakers serialise on a second lock (`.lock.break`) and re-check
   * the lock under it, so a lock acquired after another breaker removed the
   * dead one is never broken by mistake.
   */
  private async breakIfStale(lock: string): Promise<boolean> {
    const peek = await statRead(lock);
    if (!peek) return true; // released meanwhile
    if (!this.isStale(peek.raw, peek.mtimeMs)) return false;
    const breaker = `${lock}.break`;
    try {
      const fh = await fs.open(breaker, "wx", FILE_MODE);
      try {
        await fh.writeFile(JSON.stringify({ pid: process.pid, host: hostname(), token: "break" }));
      } finally {
        await fh.close();
      }
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      // Another breaker is at work. If it died mid-break, clear its marker.
      const b = await statRead(breaker);
      if (b && this.isStale(b.raw, b.mtimeMs)) await fs.rm(breaker, { force: true });
      return false;
    }
    try {
      const now = await statRead(lock);
      if (now && now.raw === peek.raw && this.isStale(now.raw, now.mtimeMs)) await fs.rm(lock, { force: true });
    } finally {
      await fs.rm(breaker, { force: true });
    }
    return true;
  }
}

/**
 * Link errors that mean "no hard links here" (some network filesystems; FAT and exFAT, where
 * Windows reports EISDIR): copy the lock into place instead.
 */
const NO_LINKS = new Set(["EPERM", "ENOTSUP", "EOPNOTSUPP", "ENOSYS", "EXDEV", "EMLINK", "EISDIR"]);

/**
 * Creates `lock` holding `body`, or fails with EEXIST. While `lock` exists nothing is written;
 * otherwise the body goes to a temp file that is hard-linked to `lock` (a link never replaces an
 * existing file) and removed again at once, so the lock is never seen empty and a temp file only
 * exists for the moment of one attempt. Where hard links aren't supported, the temp file is
 * copied to `lock` exclusively (COPYFILE_EXCL), so the lock still appears with its body.
 */
class LockCreator {
  private links = true;

  constructor(
    private readonly lock: string,
    private readonly body: string,
  ) {}

  /**
   * The lock holds our body (our token): on NFS a retransmitted link or create can succeed on
   * the server and still answer EEXIST, and then the lock is ours (pre-release review L2).
   */
  private async ours(): Promise<boolean> {
    return (await fs.readFile(this.lock, "utf8").catch(() => "")) === this.body;
  }

  async create(): Promise<void> {
    if (this.links) {
      // Held (the usual case while waiting): EEXIST without touching the disk.
      if (await fs.lstat(this.lock).then(() => true, () => false)) throw Object.assign(new Error(`EEXIST: ${this.lock}`), { code: "EEXIST" });
      const tmp = `${this.lock}.${process.pid}.${b64uEncode(randomBytes(6))}.tmp`;
      try {
        await fs.writeFile(tmp, this.body, { mode: FILE_MODE, flag: "wx" });
        await fs.link(tmp, this.lock);
        return;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === "EEXIST" && (await this.ours())) return;
        if (!NO_LINKS.has((e as NodeJS.ErrnoException).code ?? "")) throw e;
        this.links = false;
      } finally {
        await fs.rm(tmp, { force: true }).catch(() => {});
      }
    }
    // No hard links: the body is still in place when the lock appears. COPYFILE_EXCL creates the
    // lock only if it doesn't exist (EEXIST otherwise) and copies the body in the same call.
    const tmp = `${this.lock}.${process.pid}.${b64uEncode(randomBytes(6))}.tmp`;
    try {
      await fs.writeFile(tmp, this.body, { mode: FILE_MODE, flag: "wx" });
      await fs.copyFile(tmp, this.lock, fsConstants.COPYFILE_EXCL);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EEXIST" && (await this.ours())) return;
      throw e;
    } finally {
      await fs.rm(tmp, { force: true }).catch(() => {});
    }
  }
}

async function statRead(path: string): Promise<{ raw: string; mtimeMs: number } | undefined> {
  try {
    const [raw, st] = await Promise.all([fs.readFile(path, "utf8"), fs.stat(path)]);
    return { raw, mtimeMs: st.mtimeMs };
  } catch {
    return undefined;
  }
}

interface LockBody {
  pid: number;
  host: string;
  token: string;
}

function parseLock(raw: string): LockBody | undefined {
  try {
    const v = JSON.parse(raw) as LockBody;
    return typeof v.pid === "number" && typeof v.host === "string" && typeof v.token === "string" ? v : undefined;
  } catch {
    return undefined;
  }
}

async function readLock(lock: string): Promise<LockBody | undefined> {
  return parseLock(await fs.readFile(lock, "utf8").catch(() => ""));
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export const LOCK_TIMEOUT_MS = 10_000;
export const LOCK_STALE_MS = 30_000;
export const LOCK_REFRESH_MS = 5_000;

export interface LockOptions {
  /** How long to wait for the lock before failing. */
  timeoutMs: number;
  /** Age after which a lock whose holder can't be checked is broken. */
  staleMs: number;
  /** How often a holder refreshes the lock's mtime. */
  refreshMs: number;
  /**
   * Diagnostics: called after every locked section with how long the lock took to get and was
   * held (the CLI logs it under P2P_DEBUG). Never given the lock's content.
   */
  onLock?: (info: { dir: string; waitedMs: number; attempts: number; heldMs: number }) => void;
  /** Diagnostics: called about once a second while waiting for the lock, with the holder's pid when readable. */
  onLockWait?: (info: { dir: string; waitedMs: number; holderPid?: number }) => void;
}
