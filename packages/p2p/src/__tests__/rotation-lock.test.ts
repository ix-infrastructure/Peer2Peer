// Copyright 2026 Ix Infrastructure Inc.
//
// #99: the rotation lock. A reused pid doesn't hold it for good, a stale lock is taken over by exactly one run,
// `--plan` / `--cancel` take it too, and every refusal names the lock file.

import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { processStartMs } from "../procstart.js";
import { rotationLockOf, withRotationLock } from "../rotation-lock.js";
import { rotateCancel, rotatePlan } from "../rotation.js";
import type { App } from "../app.js";

const homes: string[] = [];
const home = () => {
  const h = mkdtempSync(join(tmpdir(), "p2p-rotlock-"));
  homes.push(h);
  return h;
};
afterEach(() => {
  for (const h of homes.splice(0)) rmSync(h, { recursive: true, force: true });
});

/** The child process, bundled from source here (never a possibly stale dist/). */
let childDir: string;
let child: string;
beforeAll(async () => {
  childDir = mkdtempSync(join(tmpdir(), "p2p-rotlock-child-"));
  child = join(childDir, "child.mjs");
  await build({ entryPoints: [fileURLToPath(new URL("./rotation-lock-child.ts", import.meta.url))], bundle: true, platform: "node", format: "esm", target: "node22", outfile: child, logLevel: "silent" });
}, 60_000);
afterAll(() => {
  rmSync(childDir, { recursive: true, force: true });
});

/** The pid of a process that has exited. */
async function deadPid(): Promise<number> {
  const c = spawn(process.execPath, ["-e", ""], { stdio: "ignore" });
  await new Promise((r) => c.once("exit", r));
  return c.pid!;
}

const tick = () => new Promise((r) => setTimeout(r, 5));
const errOf = (p: Promise<unknown>) => p.then(() => undefined, (e: unknown) => e as { code?: string; message: string });

describe("#99: rotation lock", () => {
  it("records pid, process start time and a run id; removed after the run", async () => {
    const h = home();
    const file = rotationLockOf(h);
    const seen = await withRotationLock(h, async () => JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>);
    expect(seen.pid).toBe(process.pid);
    expect(typeof seen.run).toBe("string");
    expect(typeof seen.at).toBe("number");
    expect(typeof seen.started).toBe("number");
    const os = processStartMs(process.pid);
    if (os !== undefined) expect(Math.abs((seen.started as number) - os)).toBeLessThan(2500);
    expect(existsSync(file)).toBe(false);
  });

  it("a live run's lock refuses, naming the lock file and saying to delete it if nothing is rotating", async () => {
    const h = home();
    const file = rotationLockOf(h);
    let inner: { code?: string; message: string } | undefined;
    await withRotationLock(h, async () => {
      inner = await errOf(withRotationLock(h, async () => "ran"));
    });
    expect(inner?.code).toBe("rotation_in_progress");
    expect(inner?.message).toMatch(/another .* run is in progress/);
    expect(inner?.message).toContain(`delete ${file}`);
  });

  it.skipIf(process.platform !== "linux" && process.platform !== "darwin")("a lock whose pid now belongs to another process (another start time) is taken over", async () => {
    const h = home();
    const file = rotationLockOf(h);
    // This process is alive, but the lock records a start time it never had: a dead run whose pid was reused.
    writeFileSync(file, `${JSON.stringify({ pid: process.pid, started: 1, run: "0".repeat(32), at: 1 })}\n`);
    expect(await withRotationLock(h, async () => "ran")).toBe("ran");
    expect(existsSync(file)).toBe(false);
  });

  it("a lock from an older build (just a pid) is taken over once that process is gone, and refuses while it runs", async () => {
    const h = home();
    const file = rotationLockOf(h);
    writeFileSync(file, `${await deadPid()}\n`);
    expect(await withRotationLock(h, async () => "ran")).toBe("ran");
    writeFileSync(file, `${process.pid}\n`);
    expect((await errOf(withRotationLock(h, async () => "ran")))?.message).toContain(file);
    expect(readFileSync(file, "utf8")).toBe(`${process.pid}\n`);
  });

  it("content no build wrote is left alone; the error names the file", async () => {
    const h = home();
    const file = rotationLockOf(h);
    writeFileSync(file, "not a lock\n");
    const e = await errOf(withRotationLock(h, async () => "ran"));
    expect(e?.code).toBe("rotation_in_progress");
    expect(e?.message).toContain(`delete ${file}`);
    expect(readFileSync(file, "utf8")).toBe("not a lock\n");
  });

  it("an empty lock (a run that died before writing it) refuses while fresh, and is taken over after a minute", async () => {
    const h = home();
    const file = rotationLockOf(h);
    writeFileSync(file, "");
    const e = await errOf(withRotationLock(h, async () => "ran"));
    expect(e?.code).toBe("rotation_in_progress");
    expect(e?.message).toContain(`delete ${file}`);
    const old = (Date.now() - 120_000) / 1000;
    utimesSync(file, old, old);
    expect(await withRotationLock(h, async () => "ran")).toBe("ran");
    expect(existsSync(file)).toBe(false);
  });

  it("a symbolic link or a FIFO at the lock's path is never followed or waited on; the error names the file", async () => {
    const h = home();
    const file = rotationLockOf(h);
    const target = join(h, "elsewhere");
    writeFileSync(target, `${await deadPid()}\n`);
    symlinkSync(target, file);
    const e = await errOf(withRotationLock(h, async () => "ran"));
    expect(e?.code).toBe("rotation_in_progress");
    expect(e?.message).toContain(`delete ${file}`);
    expect(readFileSync(target, "utf8")).toMatch(/^\d+\n$/);
    if (process.platform !== "win32") {
      rmSync(file);
      execFileSync("mkfifo", [file]);
      const f = await errOf(withRotationLock(h, async () => "ran"));
      expect(f?.code).toBe("rotation_in_progress");
      expect(f?.message).toContain(`${file} isn't a regular file`);
    }
  });

  it("a takeover marker a dead run left behind refuses naming the file, and is swept once the lock is taken", async () => {
    const h = home();
    const file = rotationLockOf(h);
    const stale = `${JSON.stringify({ pid: await deadPid(), run: "a".repeat(32), at: 1 })}\n`;
    writeFileSync(file, stale);
    // A run that died mid-takeover of this stale lock: its marker is still there.
    const marker = `${file}.${createHash("sha256").update(stale).digest("hex").slice(0, 32)}.takeover`;
    writeFileSync(marker, "{}\n");
    const e = await errOf(withRotationLock(h, async () => "ran"));
    expect(e?.message).toContain(`delete ${file}`);
    // The user deletes the lock as told: the next run takes it and sweeps the marker.
    rmSync(file);
    expect(await withRotationLock(h, async () => "ran")).toBe("ran");
    expect(readdirSync(h)).toEqual([]);
  });

  it("concurrent takeovers of a stale lock leave exactly one owner", async () => {
    for (let round = 0; round < 10; round++) {
      const h = home();
      const file = rotationLockOf(h);
      writeFileSync(file, `${JSON.stringify({ pid: await deadPid(), run: "f".repeat(32), at: 1 })}\n`);
      let inside = 0;
      let most = 0;
      const run = () =>
        withRotationLock(h, async () => {
          inside++;
          most = Math.max(most, inside);
          for (let i = 0; i < 5; i++) await tick();
          inside--;
          return "ran";
        }).then(
          () => "ran",
          (e: { code?: string }) => e.code,
        );
      const results = await Promise.all([run(), run(), run(), run()]);
      expect(most).toBe(1);
      expect(results.filter((r) => r === "ran")).toHaveLength(1);
      expect(results.filter((r) => r !== "ran").every((r) => r === "rotation_in_progress")).toBe(true);
      // Nothing left behind: no lock, no takeover marker.
      expect(readdirSync(h)).toEqual([]);
    }
  });

  it("concurrent takeovers from separate processes leave exactly one owner", async () => {
    const h = home();
    const file = rotationLockOf(h);
    writeFileSync(file, `${JSON.stringify({ pid: await deadPid(), run: "e".repeat(32), at: 1 })}\n`);
    const logs = home();
    const log = join(logs, "owners.log");
    const kids = Array.from({ length: 4 }, () => spawn(process.execPath, [child, h, log], { stdio: ["ignore", "ignore", "inherit"] }));
    const exits = kids.map((k) => new Promise<number | null>((r) => k.once("exit", r)));
    // Start barrier: every child is ready before any tries.
    const deadline = Date.now() + 30_000;
    while (readdirSync(logs).filter((n) => n.startsWith("owners.log.ready.")).length < kids.length) {
      if (Date.now() > deadline) throw new Error("children never got ready");
      await tick();
    }
    writeFileSync(`${log}.go`, "");
    expect(await Promise.all(exits)).toEqual([0, 0, 0, 0]);
    expect(readFileSync(log, "utf8").trim().split("\n")).toEqual(["in", "out"]);
    expect(existsSync(file)).toBe(false);
  }, 60_000);

  it("rotatePlan and rotateCancel take the lock (refused while another run holds it, before touching any state)", async () => {
    const h = home();
    const file = rotationLockOf(h);
    const app = { home: h } as unknown as App;
    await withRotationLock(h, async () => {
      await expect(rotatePlan(app, { exclude: ["d_x"] })).rejects.toMatchObject({ code: "rotation_in_progress" });
      await expect(rotateCancel(app)).rejects.toMatchObject({ code: "rotation_in_progress" });
      expect(existsSync(file)).toBe(true);
    });
    // Free: rotateCancel runs (nothing to drop here) and leaves no lock behind.
    expect(await rotateCancel(app)).toEqual({ cancelled: false });
    expect(existsSync(file)).toBe(false);
  });
});
