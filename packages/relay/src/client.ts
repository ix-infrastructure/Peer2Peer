// Copyright 2026 Ix Infrastructure Inc.
//
// The one client-side rule that belongs next to the relay (docs/protocol.md
// §5.2 step 2, review H5): before answering `hello`, a client MUST compare
// `hello.relay` with the canonical form of the URL it actually dialled, and
// close the connection when they differ. Otherwise a relay could relay the
// client's auth signature to a different relay that names itself differently.
//
// The relay signs nothing; this helper exists so clients and the relay's own
// tests share one implementation of the check.

import type { RelayCrypto } from "./crypto.js";

/** True when `helloRelay` is exactly the canonical form of `dialledUrl`. */
export function helloMatchesDialled(crypto: RelayCrypto, dialledUrl: string, helloRelay: unknown): boolean {
  if (typeof helloRelay !== "string") return false;
  let dialled: string;
  try {
    dialled = crypto.canonicalRelayUrl(dialledUrl);
  } catch {
    return false;
  }
  return helloRelay === dialled;
}
