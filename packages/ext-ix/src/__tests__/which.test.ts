// Copyright 2026 Ix Infrastructure Inc.
//
// L1: `ix` and `git` are resolved to absolute paths through PATH's absolute
// entries before they run with cwd = a repository, so a program planted in a
// cloned repo (Windows looks in the cwd first) never runs.

import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { whichAbsolute } from "../which.js";
import { cleanupTmp, tmp } from "./harness.js";

afterAll(() => cleanupTmp());

function prog(dir: string, name: string): string {
  mkdirSync(dir, { recursive: true });
  const p = join(dir, name);
  writeFileSync(p, "#!/bin/sh\n");
  chmodSync(p, 0o755);
  return p;
}

describe("whichAbsolute", () => {
  it("skips relative and empty PATH entries (the cwd) and finds the absolute one", () => {
    const good = tmp("which-good-");
    const real = prog(good, "ix");
    // A repo that plants its own `ix`, reachable through ".", "" and "bin" PATH entries.
    const repo = tmp("which-repo-");
    prog(repo, "ix");
    prog(join(repo, "bin"), "ix");
    const before = process.cwd();
    process.chdir(repo);
    try {
      expect(whichAbsolute("ix", { PATH: `.::bin:${good}` }, "darwin")).toBe(real);
      expect(whichAbsolute("ix", { PATH: ".:bin:" }, "darwin")).toBeUndefined();
      // A relative program name with a separator is never resolved against the cwd.
      expect(whichAbsolute("./ix", { PATH: good }, "darwin")).toBeUndefined();
      expect(whichAbsolute("bin/ix", { PATH: good }, "darwin")).toBeUndefined();
    } finally {
      process.chdir(before);
    }
  });

  it("Windows: PATHEXT and ';', still absolute entries only", () => {
    const good = tmp("which-win-");
    const exe = prog(good, "git.EXE");
    expect(whichAbsolute("git", { PATH: `.;relative;${good}`, PATHEXT: ".COM;.EXE" }, "win32")).toBe(exe);
    expect(whichAbsolute("git", { PATH: ".;relative", PATHEXT: ".EXE" }, "win32")).toBeUndefined();
  });

  it("an absolute IX_BIN is used as given, when it runs", () => {
    const good = tmp("which-abs-");
    const p = prog(good, "my-ix");
    expect(whichAbsolute(p, {}, "darwin")).toBe(p);
    expect(whichAbsolute(join(good, "missing"), {}, "darwin")).toBeUndefined();
  });
});
