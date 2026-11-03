// Copyright 2026 Ix Infrastructure Inc.
//
// Read-only views of a P2P home, for `p2p doctor`: every document is read
// from disk on first use, and every write (an identity refresh, a "fetched"
// stamp, a discovered identity) lands in memory only and is gone when the
// process ends. Nothing takes the cross-process lock or creates a file, so a
// diagnosis never changes the home it diagnoses, even when one of its bounded
// steps times out and finishes later.

import { TrustStoreV3, type DocBackend } from "@peer2peer/core/v3";
import { FileDocBackend } from "@peer2peer/core/v3/node";

/** Reads fall through to `base` until a document is written; writes stay in memory. */
export class OverlayDocBackend implements DocBackend {
  private readonly docs = new Map<string, string>();
  private chain: Promise<unknown> = Promise.resolve();

  constructor(private readonly base: DocBackend) {}

  private readonly removed = new Set<string>();

  async read(name: string): Promise<unknown> {
    const mine = this.docs.get(name);
    if (mine !== undefined) return JSON.parse(mine);
    if (this.removed.has(name)) return undefined;
    return this.base.read(name);
  }

  /** In memory only, like write: the base is never touched. */
  async remove(name: string): Promise<void> {
    this.docs.delete(name);
    this.removed.add(name);
  }

  async write(name: string, value: unknown): Promise<void> {
    this.docs.set(name, JSON.stringify(value));
  }

  /** In-process only: never the on-disk lock (taking it would create the lock file). */
  withLock<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.chain.then(fn, fn);
    this.chain = run.catch(() => {});
    return run;
  }
}

/** A trust store over `<dir>` that never writes to it. */
export class ReadOnlyTrustStoreV3 extends TrustStoreV3 {
  constructor(readonly dir: string) {
    super(new OverlayDocBackend(new FileDocBackend(dir)));
  }
}
