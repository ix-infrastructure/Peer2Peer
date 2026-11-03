// Copyright 2026 Ix Infrastructure Inc.
//
// Canonical relay URLs (docs/protocol.md §5.1). Every relay URL in an
// identity document, a capability or a `hello` is in this form:
//  - scheme `wss`;
//  - host lowercased, as an IDNA A-label;
//  - port omitted when it is 443;
//  - path exactly as configured, without a trailing `/` (default `/v3`);
//  - no query, fragment or userinfo.
// WHATWG URL parsing (available in every JS runtime) does the IDNA and
// lowercasing for the special `wss` scheme.

import { fail } from "../errors.js";

export const DEFAULT_RELAY_PATH = "/v3";

/** Canonicalises a relay URL, or throws `bad-relay-url`. Idempotent. */
export function canonicalRelayUrl(url: string): string {
  if (typeof url !== "string" || url.length > 2048) fail("bad-relay-url", "relay URL must be a string");
  if (url.includes("?") || url.includes("#")) fail("bad-relay-url", "relay URL must have no query or fragment");
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return fail("bad-relay-url", `not a URL: ${url}`);
  }
  if (u.protocol !== "wss:") fail("bad-relay-url", "relay URL scheme must be wss");
  if (u.username !== "" || u.password !== "") fail("bad-relay-url", "relay URL must have no userinfo");
  if (u.hostname === "") fail("bad-relay-url", "relay URL needs a host");
  let path = u.pathname;
  while (path.endsWith("/")) path = path.slice(0, -1);
  if (path === "") path = DEFAULT_RELAY_PATH;
  // `u.port` is "" for the scheme default (443).
  return `wss://${u.hostname}${u.port !== "" ? `:${u.port}` : ""}${path}`;
}

export function isCanonicalRelayUrl(url: unknown): url is string {
  if (typeof url !== "string") return false;
  try {
    return canonicalRelayUrl(url) === url;
  } catch {
    return false;
  }
}

/** §2.4: the relay part of a link code is the canonical URL without `wss://`. */
export function relayLinkPart(relay: string): string {
  return canonicalRelayUrl(relay).slice("wss://".length);
}

/** Inverse of relayLinkPart. */
export function relayFromLinkPart(part: string): string {
  if (typeof part !== "string" || part === "" || part.includes("://")) fail("bad-relay-url", "bad relay part");
  return canonicalRelayUrl(`wss://${part}`);
}

/**
 * The HTTPS base of a relay's document API (§5.6): `https://<host[:port]>`
 * plus the relay path, e.g. `wss://r.example/v3` -> `https://r.example/v3`.
 */
export function relayHttpsBase(relay: string): string {
  return `https://${canonicalRelayUrl(relay).slice("wss://".length)}`;
}
