// Copyright 2026 Ix Infrastructure Inc.
//
// Which of this device's sessions ran under a `p2p watch` and has ended. A watch writes
// `<home>/cursors/<sid>.watch` ({pid, started}) when it starts and marks it `ended` when it stops;
// a session whose watch was killed instead is ended once that process is gone (or a later process
// has its pid). A laptop asleep keeps its watches: not ended. A session that never ran a watch
// (only short commands, as in scripts) has no marker and is never called ended.
//
// Used when a message arrives for one of this device's sessions: if that session has ended (with
// `/exit`, or `/clear` started a new one), the message is also logged as one addressed to no
// session, so the user's current session holds it for Deliver (onSessionEnvelope).

import { readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { App } from "./app.js";
import { processStartMs } from "./procstart.js";
import { SID_RE } from "./sessions.js";

const STARTED = Math.round(Date.now() - process.uptime() * 1000);
/** Start times compare to the second (ps), with room for clock rounding. */
const START_SLACK_MS = 2500;

/** Only a valid session id names a file here (pre-release review O4): never a path. */
const markerPath = (app: App, sid: string) => {
  if (!SID_RE.test(sid) || sid === "." || sid === "..") throw new Error(`not a session id: ${JSON.stringify(sid.slice(0, 40))}`);
  return join(app.home, "cursors", `${sid}.watch`);
};

export async function markRunning(app: App, sid: string): Promise<void> {
  await mkdir(join(app.home, "cursors"), { recursive: true, mode: 0o700 });
  await writeFile(markerPath(app, sid), JSON.stringify({ pid: process.pid, started: STARTED }), { mode: 0o600 });
}

export async function unmarkRunning(app: App, sid: string): Promise<void> {
  try {
    const m = JSON.parse(readFileSync(markerPath(app, sid), "utf8")) as { pid?: number; started?: number };
    if (m.pid === process.pid) await writeFile(markerPath(app, sid), JSON.stringify({ ...m, ended: Date.now() }), { mode: 0o600 });
  } catch {
    // none
  }
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** Did session `sid` of this device run under a watch that is gone now? */
export function sessionEnded(app: App, sid: string): boolean {
  if (!SID_RE.test(sid) || sid === "." || sid === "..") return false;
  if (app.watching === sid) return false;
  let m: { pid?: unknown; started?: unknown; ended?: unknown };
  try {
    m = JSON.parse(readFileSync(markerPath(app, sid), "utf8")) as typeof m;
  } catch {
    return false; // never ran a watch here
  }
  if (typeof m.ended === "number") return true;
  if (typeof m.pid !== "number" || !Number.isSafeInteger(m.pid) || m.pid <= 0) return false;
  if (m.pid === process.pid) return false;
  if (!alive(m.pid)) return true;
  if (typeof m.started !== "number") return false;
  const started = processStartMs(m.pid);
  return started !== undefined && Math.abs(started - m.started) >= START_SLACK_MS;
}
