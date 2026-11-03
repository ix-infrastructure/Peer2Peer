// Copyright 2026 Ix Infrastructure Inc.
//
// The JSON-document backend interface every trust store (v2 and v3) is built
// on, and its in-memory implementation. Pure: no Node-only APIs.

/** A key/value backend of JSON documents. */
export interface DocBackend {
  read(name: string): Promise<unknown | undefined>;
  write(name: string, value: unknown): Promise<void>;
  /** Deletes a document (nothing when it doesn't exist). Optional: a backend without it keeps an emptied document. */
  remove?(name: string): Promise<void>;
  /** Runs `fn` holding a lock shared with other processes using the same store, if any. */
  withLock?<T>(fn: () => Promise<T>): Promise<T>;
}

/** In-memory backend: deep-copies through JSON so callers can't alias state. */
export class MemoryDocBackend implements DocBackend {
  private readonly docs = new Map<string, string>();
  async read(name: string) {
    const v = this.docs.get(name);
    return v === undefined ? undefined : JSON.parse(v);
  }
  async write(name: string, value: unknown) {
    this.docs.set(name, JSON.stringify(value));
  }
  async remove(name: string) {
    this.docs.delete(name);
  }
}
