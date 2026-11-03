// Copyright 2026 Ix Infrastructure Inc.
//
// One error type for everything the CLI reports. `code` is the machine
// readable `error` of `--json` output; core rejections keep their reason.

import { P2PError } from "@peer2peer/core/v3";

export class CliError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly extra: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "CliError";
  }
}

export function usage(message: string): CliError {
  return new CliError("usage", message);
}

/** `{error, reason}` for any failure (plus the CliError's extra fields). */
export function toErrorJson(err: unknown): Record<string, unknown> {
  if (err instanceof CliError) return { error: err.code, reason: err.message, ...err.extra };
  if (err instanceof P2PError) return { error: err.reason, reason: err.message };
  const e = err as { code?: unknown; message?: unknown } | null;
  if (e && typeof e.message === "string") return { error: "internal", reason: e.message };
  return { error: "internal", reason: String(err) };
}
