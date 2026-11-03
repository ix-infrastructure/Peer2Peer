// Copyright 2026 Ix Infrastructure Inc.
//
// Which failures while handling an envelope are worth another attempt (inbound.ts, review M-A).

import { CliError } from "./errors.js";

/**
 * Failures worth another attempt (review M-A), still bounded by the attempt limit and the
 * per-envelope timeout: clearly local and transient (this command closing, a lock timeout, a full
 * disk), or a transient network failure (a dropped connection, an unreachable relay, a timeout),
 * so a short Wi-Fi drop doesn't lose a friend's accept. Everything else (a bug, a validation
 * failure, any other CliError) is final at once.
 */
const TRANSIENT_ERRNO = new Set([
  "ENOSPC", "EBUSY", "EAGAIN", "EMFILE", "ENFILE", "EDQUOT",
  "ECONNRESET", "ETIMEDOUT", "ECONNREFUSED", "EHOSTUNREACH", "ENETUNREACH", "EAI_AGAIN", "EPIPE", "ECONNABORTED",
]);
const TRANSIENT_CLI = new Set(["closing", "network", "timeout", "unreachable", "no_relay"]);
export function isTransient(e: unknown): boolean {
  if (e instanceof CliError) return TRANSIENT_CLI.has(e.code);
  if (!(e instanceof Error)) return false;
  if (/ is locked$/.test(e.message)) return true; // a state or trust store lock timeout (FileDocBackend)
  if (/socket hang up|socket (has been )?closed|other side closed|fetch failed/i.test(e.message)) return true;
  const code = (e as NodeJS.ErrnoException).code ?? ((e as { cause?: NodeJS.ErrnoException }).cause?.code);
  return typeof code === "string" && TRANSIENT_ERRNO.has(code);
}
