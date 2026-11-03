// Copyright 2026 Ix Infrastructure Inc.
//
// `@peer2peer/core/v3/node`: the file-backed v3 trust store. Node-only (file
// I/O and the cross-process lock), kept out of the pure `@peer2peer/core/v3`
// entry point. It reuses the v2 FileDocBackend: a 0700 directory, 0600 files
// written atomically, and the lockfile rules (docs/protocol-v2.md C7).

import { homedir } from "node:os";
import { join } from "node:path";
import { FileDocBackend, type LockOptions } from "../filebackend.js";
import { TrustStoreV3 } from "./store.js";

export { FileDocBackend, DIR_MODE, FILE_MODE, LOCK_REFRESH_MS, LOCK_STALE_MS, LOCK_TIMEOUT_MS, type LockOptions } from "../filebackend.js";

/** The default v3 store directory: `~/.p2p/v3`. */
export function defaultTrustDirV3(): string {
  return join(homedir(), ".p2p", "v3");
}

export class FileTrustStoreV3 extends TrustStoreV3 {
  constructor(
    readonly dir: string = defaultTrustDirV3(),
    lockOpts: Partial<LockOptions> = {},
  ) {
    super(new FileDocBackend(dir, lockOpts));
  }
}
