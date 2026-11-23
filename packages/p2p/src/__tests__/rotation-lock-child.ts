// Copyright 2026 Ix Infrastructure Inc.
//
// rotation-lock.test.ts: one process trying to take the rotation lock of argv[2], logging to argv[3] while it holds
// it. Waits for the start barrier (argv[3].go) after saying it is ready (argv[3].ready.<pid>), so every process
// tries at once. The test bundles this file from source (esbuild), so it always runs the current code.

import { appendFileSync, existsSync, writeFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import { withRotationLock } from "../rotation-lock.js";

async function main(): Promise<void> {
  const [home, log] = process.argv.slice(2);
  writeFileSync(`${log}.ready.${process.pid}`, "");
  while (!existsSync(`${log}.go`)) await sleep(5);
  try {
    await withRotationLock(home, async () => {
      appendFileSync(log, "in\n");
      await sleep(2000);
      appendFileSync(log, "out\n");
    });
  } catch (e) {
    if ((e as { code?: string }).code !== "rotation_in_progress") {
      process.stderr.write(`${(e as Error).stack ?? String(e)}\n`);
      process.exit(2);
    }
  }
}

void main();
