// Copyright 2026 Ix Infrastructure Inc.
//
// The relay process the resilience suite forks: bin.ts, plus a clock offset
// the parent moves forward over the IPC channel (to compress time without
// waiting for rate-limit windows), and a ready message carrying the bound
// ports. Configuration is the same env as production (LIMIT_*, DB_PATH, ...).
// The parent always sets HOST=127.0.0.1, PORT=0 and METRICS_HOST=127.0.0.1.
//
// No uncaughtException handler on purpose: a crash must end the process, so
// the test sees it.

import { loadConfig } from "../../src/config.js";
import { createRelayCrypto } from "../../src/crypto.js";
import { createLogger } from "../../src/log.js";
import { Relay } from "../../src/server.js";
import { SqliteStore } from "../../src/sqlite-store.js";

type ParentMsg = { t: "advance"; id: number; ms: number } | { t: "sweep"; id: number };

let offsetMs = Number(process.env.RESILIENCE_CLOCK_OFFSET_MS ?? 0);
const now = (): number => Date.now() + offsetMs;

const send = (m: Record<string, unknown>): void => {
  if (process.send) process.send(m);
};

const crypto = createRelayCrypto();
const config = loadConfig(crypto);
if (config.host !== "127.0.0.1" || config.metricsHost !== "127.0.0.1") {
  throw new Error("resilience relay must bind 127.0.0.1 only");
}
const log = createLogger({ level: config.logLevel, now });
const store = new SqliteStore(config.dbPath);
const relay = new Relay({ config, store, crypto, logger: log, now });
const port = await relay.listen();

process.on("message", (raw: unknown) => {
  const m = raw as ParentMsg;
  if (m.t === "advance") {
    offsetMs += m.ms;
    send({ t: "ack", id: m.id, offsetMs });
  } else if (m.t === "sweep") {
    const t0 = performance.now();
    void relay.sweep().then(() => send({ t: "ack", id: m.id, ms: performance.now() - t0 }));
  }
});

let stopping = false;
const stop = (): void => {
  if (stopping) return;
  stopping = true;
  relay.close().then(
    () => process.exit(0),
    () => process.exit(1),
  );
};
process.on("SIGTERM", stop);
// The parent died: never outlive it.
process.on("disconnect", stop);

send({ t: "ready", port, metricsPort: relay.metricsPort, pid: process.pid });
