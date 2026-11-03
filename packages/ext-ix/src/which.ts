// Copyright 2026 Ix Infrastructure Inc.
//
// Resolving a program (`ix`, `git`) to an absolute path through PATH before
// running it with `cwd` set to a repository. On Windows, CreateProcess looks
// in the current directory before PATH, so a cloned repo carrying `ix.exe` or
// `git.exe` would run instead; resolving first, from absolute PATH entries
// only, closes that. Relative and empty PATH entries (which also mean "the
// current directory") are skipped.

import { accessSync, constants, statSync } from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";

export function whichAbsolute(name: string, env: Record<string, string | undefined> = process.env, platform: NodeJS.Platform = process.platform): string | undefined {
  if (isAbsolute(name)) return isRunnable(name, platform) ? name : undefined;
  // A name with a separator is a relative path: never resolved against a cwd.
  if (/[\\/]/.test(name)) return undefined;
  const win = platform === "win32";
  const sep = win ? ";" : delimiter;
  const path = env.PATH ?? env.Path ?? "";
  const exts = win ? (env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean) : [""];
  const hasExt = win && exts.some((e) => name.toLowerCase().endsWith(e.toLowerCase()));
  for (const dir of path.split(sep)) {
    const d = dir.trim().replace(/^"|"$/g, "");
    if (d === "" || !isAbsolute(d)) continue;
    for (const ext of hasExt ? [""] : exts) {
      const p = join(d, name + ext);
      if (isRunnable(p, platform)) return p;
    }
  }
  return undefined;
}

function isRunnable(p: string, platform: NodeJS.Platform): boolean {
  try {
    if (!statSync(p).isFile()) return false;
    if (platform !== "win32") accessSync(p, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}
