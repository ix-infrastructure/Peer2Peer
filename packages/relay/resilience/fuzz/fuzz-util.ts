// Copyright 2026 Ix Infrastructure Inc.
//
// Shared settings for the fast-check input-validation tests. The seed and
// run count are fixed (override with FUZZ_SEED / FUZZ_RUNS) and printed, so
// any failure can be replayed exactly.

import { connect } from "node:net";
import type { ErrorCode } from "../../src/server.js";
import { CLOSE } from "../../src/server.js";

export const FUZZ_SEED = Number(process.env.FUZZ_SEED ?? 20261021);
export const FUZZ_RUNS = Number(process.env.FUZZ_RUNS ?? 1000);

export function announce(name: string, runs = FUZZ_RUNS): void {
  console.log(`FUZZ ${name}: seed=${FUZZ_SEED} runs=${runs} (replay: FUZZ_SEED=${FUZZ_SEED} FUZZ_RUNS=${runs})`);
}

/** Every `code` an `error` frame may carry (server.ts ErrorCode). */
export const WS_ERROR_CODES: ReadonlySet<ErrorCode> = new Set<ErrorCode>([
  "undeliverable",
  "rate-limited",
  "too-large",
  "bad-envelope",
  "bad-request",
  "auth-required",
  "auth-failed",
  "bad-identity",
  "identity-gap",
  "forbidden",
  "not-found",
  "full",
  "exists",
]);

/** Frame types the relay sends. */
export const WS_FRAME_TYPES: ReadonlySet<string> = new Set(["hello", "ok", "sent", "error", "link", "env"]);

/**
 * Clean close codes: the relay's own (server.ts CLOSE), plus ws's 1009 (frame
 * over maxPayload) and 1007 (invalid UTF-8 in a text frame).
 */
export const WS_CLOSE_CODES: ReadonlySet<number> = new Set<number>([...Object.values(CLOSE), 1007, 1009]);

/** The `error` values the HTTP routes document; 500 `internal` is a caught bug, not one of them. */
export const HTTP_ERRORS: ReadonlySet<string> = new Set(["not-found", "bad-request", "rate-limited", "method-not-allowed", "upgrade-required"]);
export const HTTP_STATUSES: ReadonlySet<number> = new Set([101, 200, 400, 404, 405, 426, 429, 431, 503, 505]);

export interface RawResponse {
  status: number;
  body: string;
  raw: string;
  /** "closed" when the peer closed, "timeout" when it didn't answer in time. */
  end: "closed" | "timeout" | "error";
}

/** Writes `request` verbatim on a fresh TCP connection to 127.0.0.1:`port` and reads until close. */
export function rawHttp(port: number, request: string | Buffer, timeoutMs = 2000): Promise<RawResponse> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let done = false;
    const finish = (end: RawResponse["end"]) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock.destroy();
      const raw = Buffer.concat(chunks).toString("latin1");
      const m = /^HTTP\/1\.[01] (\d{3})/.exec(raw);
      const sep = raw.indexOf("\r\n\r\n");
      resolve({ status: m ? Number(m[1]) : 0, body: sep >= 0 ? raw.slice(sep + 4) : "", raw, end });
    };
    const sock = connect(port, "127.0.0.1", () => sock.write(request));
    sock.on("data", (d) => {
      chunks.push(d);
      // A 101 never closes by itself; one is enough to judge.
      if (/^HTTP\/1\.1 101/.test(Buffer.concat(chunks).toString("latin1"))) finish("closed");
    });
    sock.on("close", () => finish("closed"));
    sock.on("error", () => finish("error"));
    const timer = setTimeout(() => finish("timeout"), timeoutMs);
  });
}

/** The JSON `error` of a chunked or plain response body, if there is one. */
export function jsonError(body: string): string | undefined {
  const m = /\{"error":"([^"]*)"\}/.exec(body);
  return m?.[1];
}
