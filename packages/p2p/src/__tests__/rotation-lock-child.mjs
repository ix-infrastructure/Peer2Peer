// Copyright 2026 Ix Infrastructure Inc.
//
// rotation-lock.test.ts: one process trying to take the rotation lock of argv[2], logging to argv[3] while it holds
// it. Uses the built module (npm test builds first).

import { appendFileSync } from "node:fs";
import process from "node:process";
import { setTimeout as sleep } from "node:timers/promises";
import { withRotationLock } from "../../dist/rotation-lock.js";

const [home, log] = process.argv.slice(2);
try {
  await withRotationLock(home, async () => {
    appendFileSync(log, "in\n");
    await sleep(500);
    appendFileSync(log, "out\n");
  });
} catch (e) {
  if (e?.code !== "rotation_in_progress") {
    process.stderr.write(`${e?.stack ?? e}\n`);
    process.exit(2);
  }
}
