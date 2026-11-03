// Copyright 2026 Ix Infrastructure Inc.
//
// Fault injection for the soak harness, preloaded into every `p2p` child it
// starts (`node --import faults.mjs <p2p> ...`). It changes nothing unless the
// harness's variables ask for it:
//
//   SOAK_SKEW_MS   this process's clock runs this far ahead (or behind): Date and
//                  Date.now are shifted, and so are the start times `ps` reports
//                  for other processes (procstart.ts), as a skewed system clock
//                  would shift both.
//   SOAK_FAULT_DIR where the markers below are kept (one directory per device).
//
// Content markers, matched in what the client writes to its state documents
// (the core FileDocBackend writes each document through FileHandle.writeFile):
//
//   SOAK-CRASH-<n>   the first time this device writes a document containing it,
//                    the process kills itself with SIGKILL: a crash between
//                    receiving a message and applying it (kill -9 mid-apply).
//                    A marker file makes it happen once per device.
//   SOAK-POISON-<n>  every write containing it fails with ENOSPC: an envelope whose
//                    application fails every time (a poison envelope), which the
//                    client must give up on after its attempt limit.

import { existsSync, writeFileSync, mkdirSync } from "node:fs";
import fsp from "node:fs/promises";
import cp from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { join } from "node:path";
import { tmpdir } from "node:os";

const skew = Number(process.env.SOAK_SKEW_MS ?? "0") || 0;
if (skew !== 0) {
  const RealDate = Date;
  class SkewedDate extends RealDate {
    constructor(...args) {
      if (args.length === 0) super(RealDate.now() + skew);
      else super(...args);
    }
    static now() {
      return RealDate.now() + skew;
    }
  }
  globalThis.Date = SkewedDate;
  // procstart.ts asks `ps -o lstart=` for another process's start time: shift it the same way.
  const realExecFileSync = cp.execFileSync;
  cp.execFileSync = function (file, args, ...rest) {
    const out = realExecFileSync.call(this, file, args, ...rest);
    if (file === "ps" && Array.isArray(args) && args.includes("lstart=")) {
      const t = RealDate.parse(String(out).trim());
      if (Number.isFinite(t)) return new RealDate(t + skew).toUTCString();
    }
    return out;
  };
  syncBuiltinESMExports();
}

const faultDir = process.env.SOAK_FAULT_DIR;
if (faultDir) {
  const CRASH = /SOAK-CRASH-(\d+)/;
  const POISON = /SOAK-POISON-\d+/;
  const probe = await fsp.open(join(tmpdir(), `.soak-probe-${process.pid}`), "w");
  const proto = Object.getPrototypeOf(probe);
  await probe.close();
  await fsp.rm(join(tmpdir(), `.soak-probe-${process.pid}`), { force: true });
  const realWriteFile = proto.writeFile;
  proto.writeFile = async function (data, ...rest) {
    if (typeof data === "string") {
      if (POISON.test(data)) {
        const e = new Error("ENOSPC: no space left on device, write (soak poison)");
        e.code = "ENOSPC";
        throw e;
      }
      const m = CRASH.exec(data);
      if (m) {
        const marker = join(faultDir, `crashed-${m[1]}`);
        if (!existsSync(marker)) {
          mkdirSync(faultDir, { recursive: true });
          writeFileSync(marker, JSON.stringify({ pid: process.pid, argv: process.argv.slice(2, 4), at: Date.now() }));
          process.kill(process.pid, "SIGKILL");
          await new Promise(() => {});
        }
      }
    }
    return realWriteFile.call(this, data, ...rest);
  };
}
