// Copyright 2026 Ix Infrastructure Inc.
//
// #99: the rotation lock. A reused pid doesn't hold it for good, a stale lock is taken over by exactly one run, and
// `--plan` / `--cancel` take it too.

import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { processStart, rotationLockOf, withRotationLock } from "../rotation-lock.js";
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

/** The pid of a process that has exited. */
async function deadPid(): Promise<number> {
  const c = spawn(process.execPath, ["-e", ""], { stdio: "ignore" });
  await new Promise((r) => c.once("exit", r));
  return c.pid!;
}

const tick = () => new Promise((r) => setTimeout(r, 5));

describe("#99: rotation lock", () => {
  it("records pid, process start time and a run id; removed after the run", async () => {
    const h = home();
    const file = rotationLockOf(h);
    const seen = await withRotationLock(h, async () => JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>);
    expect(seen.pid).toBe(process.pid);
    expect(typeof seen.run).toBe("string");
    expect(typeof seen.at).toBe("number");
    if (process.platform !== "win32") expect(seen.start).toBe(await processStart(process.pid));
    expect(existsSync(file)).toBe(false);
  });

  it("a live run's lock refuses, naming the lock file and saying to delete it if nothing is rotating", async () => {
    const h = home();
    const file = rotationLockOf(h);
    let inner: unknown;
    await withRotationLock(h, async () => {
      inner = await withRotationLock(h, async () => "ran").catch((e: unknown) => e);
    });
    expect((inner as { code?: string }).code).toBe("rotation_in_progress");
    expect((inner as Error).message).toMatch(/another .* run is in progress/);
    expect((inner as Error).message).toContain(file);
    expect((inner as Error).message).toMatch(/delete/);
  });

  it.skipIf(process.platform === "win32")("a lock whose pid now belongs to another process (another start time) is taken over", async () => {
    const h = home();
    const file = rotationLockOf(h);
    // This process is alive, but the lock records a start time it never had: a dead run whose pid was reused.
    writeFileSync(file, `${JSON.stringify({ pid: process.pid, start: "ps:Thu Jan  1 00:00:00 1970", run: "0".repeat(32), at: 1 })}\n`);
    expect(await withRotationLock(h, async () => "ran")).toBe("ran");
    expect(existsSync(file)).toBe(false);
  });

  it("a lock from an older build (just a pid) is taken over once that process is gone, and refuses while it runs", async () => {
    const h = home();
    const file = rotationLockOf(h);
    writeFileSync(file, `${await deadPid()}\n`);
    expect(await withRotationLock(h, async () => "ran")).toBe("ran");
    writeFileSync(file, `${process.pid}\n`);
    await expect(withRotationLock(h, async () => "ran")).rejects.toMatchObject({ code: "rotation_in_progress" });
    expect(readFileSync(file, "utf8")).toBe(`${process.pid}\n`);
  });

  it("content no build wrote is left alone", async () => {
    const h = home();
    const file = rotationLockOf(h);
    writeFileSync(file, "not a lock\n");
    await expect(withRotationLock(h, async () => "ran")).rejects.toMatchObject({ code: "rotation_in_progress" });
    expect(readFileSync(file, "utf8")).toBe("not a lock\n");
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
    // The built module (npm test builds first, as for the dist/bin.js tests).
    const mod = fileURLToPath(new URL("../../dist/rotation-lock.js", import.meta.url));
    expect(existsSync(mod), "build p2p first (npm run build)").toBe(true);
    const log = join(h, "..", `${h.split("/").pop()}-owners.log`);
    homes.push(log);
    const script = [
      `const { withRotationLock } = await import(${JSON.stringify(mod)});`,
      `const { appendFileSync } = await import("node:fs");`,
      `try { await withRotationLock(${JSON.stringify(h)}, async () => { appendFileSync(${JSON.stringify(log)}, "in\\n"); await new Promise((r) => setTimeout(r, 500)); appendFileSync(${JSON.stringify(log)}, "out\\n"); }); } catch (e) { if (e.code !== "rotation_in_progress") { console.error(e); process.exit(2); } }`,
    ].join("\n");
    const kids = Array.from({ length: 4 }, () => spawn(process.execPath, ["--input-type=module", "-e", script], { stdio: ["ignore", "ignore", "inherit"] }));
    const codes = await Promise.all(kids.map((k) => new Promise<number | null>((r) => k.once("exit", r))));
    expect(codes).toEqual([0, 0, 0, 0]);
    const lines = readFileSync(log, "utf8").trim().split("\n");
    expect(lines).toEqual(["in", "out"]);
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
