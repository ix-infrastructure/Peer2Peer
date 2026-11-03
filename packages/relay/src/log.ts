// Copyright 2026 Ix Infrastructure Inc.
//
// Structured JSON logs, one object per line.
//
// Privacy rule: the relay never logs envelope contents, capabilities,
// certificates, link data or raw IP addresses. Identifiers (userIds, dids,
// IPs) appear only at debug level, and only through redact(), which keeps a
// short salted hash: enough to correlate lines, not to recover the id.

import { b64uEncode, randomBytes, sha256 } from "@peer2peer/core";
import type { LogLevel } from "./config.js";

export type LogFields = Record<string, string | number | boolean | undefined>;

export interface Logger {
  debug(msg: string, fields?: LogFields): void;
  info(msg: string, fields?: LogFields): void;
  warn(msg: string, fields?: LogFields): void;
  error(msg: string, fields?: LogFields): void;
  /** True when debug lines are emitted, so callers can skip computing them. */
  readonly debugEnabled: boolean;
}

const ORDER: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

export interface LoggerOptions {
  level?: LogLevel;
  /** Receives each line (without the newline). Default: stdout. */
  sink?: (line: string) => void;
  now?: () => number;
}

export function createLogger(opts: LoggerOptions = {}): Logger {
  const min = ORDER[opts.level ?? "info"];
  const sink = opts.sink ?? ((line: string) => process.stdout.write(`${line}\n`));
  const now = opts.now ?? Date.now;
  const emit = (level: LogLevel) => (msg: string, fields?: LogFields) => {
    if (ORDER[level] < min) return;
    sink(JSON.stringify({ ts: new Date(now()).toISOString(), level, msg, ...fields }));
  };
  return {
    debug: emit("debug"),
    info: emit("info"),
    warn: emit("warn"),
    error: emit("error"),
    debugEnabled: min <= ORDER.debug,
  };
}

// A per-process salt, so a redacted id in one relay's logs can't be matched
// against another relay's logs or a precomputed table of userIds.
const SALT = b64uEncode(randomBytes(16));
const enc = new TextEncoder();

/** A 12-character salted hash of an identifier, for debug-level correlation only. */
export function redact(id: string): string {
  return `h:${b64uEncode(sha256(enc.encode(`${SALT}|${id}`))).slice(0, 12)}`;
}
