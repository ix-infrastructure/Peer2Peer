// Copyright 2026 Ix Infrastructure Inc.
//
// The person's own confirmation, read from the controlling terminal (`/dev/tty`, `CONIN$` on
// Windows), never from stdin or a flag: a process an agent detached from any terminal (`setsid`,
// `(sh x.sh &)`, a daemon) can't answer it, whatever its environment says. Not airtight: an agent
// that spawns a pseudo-terminal from a script can (docs/security/threat-model.md).

import { closeSync, openSync, readSync, writeSync } from "node:fs";

/** Asks `question` on the controlling terminal; true only for "yes". No terminal: false. */
export async function confirmOnTty(question: string): Promise<boolean> {
  let inFd: number | undefined;
  let outFd: number | undefined;
  try {
    if (process.platform === "win32") {
      inFd = openSync("CONIN$", "r");
      outFd = openSync("CONOUT$", "w");
    } else {
      inFd = openSync("/dev/tty", "r+");
      outFd = inFd;
    }
  } catch {
    return false;
  }
  try {
    writeSync(outFd, `${question} Type yes to go on: `);
    const buf = Buffer.alloc(1);
    let answer = "";
    for (let i = 0; i < 64; i++) {
      const n = readSync(inFd, buf, 0, 1, null);
      if (n <= 0) break;
      const c = buf.toString("utf8");
      if (c === "\n" || c === "\r") break;
      answer += c;
    }
    return answer.trim().toLowerCase() === "yes";
  } catch {
    return false;
  } finally {
    try {
      closeSync(inFd);
      if (outFd !== inFd) closeSync(outFd);
    } catch {
      // closed
    }
  }
}
