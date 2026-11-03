#!/usr/bin/env node
// Copyright 2026 Ix Infrastructure Inc.
//
// p2p-relay: run an open Peer2Peer v3 relay. Configuration comes from env vars
// and/or a JSON file named by RELAY_CONFIG; see docs/run-a-relay.md.

import { watchFile } from "node:fs";
import { loadConfig } from "./config.js";
import { createRelayCrypto } from "./crypto.js";
import { createLogger } from "./log.js";
import { Relay } from "./server.js";
import { MemoryStore } from "./store.js";
import { SqliteStore } from "./sqlite-store.js";

async function main(): Promise<void> {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    process.stdout.write(
      "p2p-relay: open Peer2Peer v3 relay\n\n" +
        "Env: RELAY_URL (wss://host/v3), PORT (8080), HOST (0.0.0.0), DB_PATH (./relay.db or :memory:),\n" +
        "     POW_BITS (0), OPERATOR_CONTACT, RELAY_NAME, RELAY_POLICY, TRUST_PROXY (proxy hops, 0),\n" +
        "     METRICS_PORT (9464, or off), METRICS_HOST (127.0.0.1), METRICS_TOKEN, LOG_LEVEL, DEBUG_STATS (off),\n" +
        "     LIMIT_* (e.g. LIMIT_MAILBOX_ENVELOPES), RELAY_CONFIG (path to a JSON file),\n" +
        "     RELAY_PRESET (small: a 2 GB board), SQLITE_WAL_LIMIT_BYTES, SQLITE_JOURNAL_SIZE_LIMIT_BYTES,\n" +
        "     SQLITE_CHECKPOINT_INTERVAL_MS\n" +
        "Members-only: RELAY_ALLOW (userIds), RELAY_ALLOW_FILE (one per line, !<userId> denies; SIGHUP reloads),\n" +
        "     RELAY_DENY (userIds never admitted),\n" +
        "     RELAY_ALLOW_CIRCLE (c_…), RELAY_INVITE_ADMIT_SEC (604800; 0: invites admit nobody)\n",
    );
    return;
  }
  const crypto = createRelayCrypto();
  const config = loadConfig(crypto);
  const log = createLogger({ level: config.logLevel });
  if (!process.env.RELAY_URL && !process.env.RELAY_CONFIG) {
    log.warn("RELAY_URL is not set; clients will reject this relay unless they dial exactly this URL", { relay: config.relayUrl });
  }
  const store = config.dbPath === ":memory:" ? new MemoryStore() : new SqliteStore(config.dbPath, { ...config.storage, warn: (msg, fields) => log.warn(msg, fields) });
  if (config.preset) log.info("relay preset", { preset: config.preset });
  const relay = new Relay({ config, store, crypto, logger: log });
  await relay.listen();

  let stopping = false;
  const stop = (signal: string) => {
    if (stopping) return;
    stopping = true;
    log.info("shutting down", { signal });
    relay.close().then(
      () => process.exit(0),
      (e: unknown) => {
        log.error("shutdown failed", { error: (e as Error).message });
        process.exit(1);
      },
    );
  };
  // Members-only: SIGHUP (and any change to RELAY_ALLOW_FILE) re-reads the allowlist
  // (RELAY_CONFIG's `allow` and the allow file's lines; env vars are fixed for the
  // process). Anyone removed is disconnected at once. A bad file keeps the current list.
  const reload = (why: string) => {
    try {
      const next = loadConfig(crypto);
      if (next.allowCircle !== config.allowCircle) log.warn("RELAY_ALLOW_CIRCLE changes need a restart; kept the current circle");
      // Never fail open: turning members-only off takes a restart.
      if (next.allow === undefined && config.allowCircle === undefined && relay.members.enabled) {
        log.warn("the reloaded config has no allowlist; opening the relay needs a restart, so the current list stays");
        return;
      }
      relay.setAllow(next.allow, next.deny ?? []);
      log.info("allowlist reloaded", { on: why, allowlisted: next.allow?.length ?? 0 });
    } catch (e) {
      log.error("allowlist reload failed; kept the current one", { on: why, error: (e as Error).message });
    }
  };
  process.on("SIGHUP", () => reload("SIGHUP"));
  // The allow file is also polled (works through Docker bind mounts), so an edit takes effect within seconds.
  if (config.allowFile) {
    const file = config.allowFile;
    watchFile(file, { interval: 2000, persistent: false }, (cur, prev) => {
      if (cur.mtimeMs === prev.mtimeMs && cur.size === prev.size) return;
      // An empty (or vanished) file is more likely a write in progress than an intent: SIGHUP applies one.
      if (cur.size === 0) return log.warn("the allow file is empty or gone; send SIGHUP to apply that", { file });
      reload("allow-file-change");
    });
  }
  process.on("SIGTERM", () => stop("SIGTERM"));
  process.on("SIGINT", () => stop("SIGINT"));
}

main().catch((e: unknown) => {
  process.stderr.write(`${JSON.stringify({ level: "error", msg: "relay failed to start", error: (e as Error).message })}\n`);
  process.exit(1);
});
