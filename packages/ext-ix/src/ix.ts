// Copyright 2026 Ix Infrastructure Inc.
//
// Running the local Ix CLI (`ix`, or IX_BIN). Always by argv with no shell,
// with a timeout and an output cap; every argument that came from a peer has
// been validated against a strict pattern first (subgraph.ts), and never
// starts with "-", so it can't be read as an option.
//
// Commands this extension uses (Ix CLI 0.12; output shapes in SPEC.md §6):
//   ix --version                                   is Ix installed
//   ix impact <target> --format json [--kind k] [--path p] [--depth n] [--limit n]
//   ix around <path> --format json [--limit n]     callers / users / tests / importers of a file
//   ix note show <id> --json                       read a note (Ix Pro memory layer)
//   ix note [--tag t] [--session s] [--actor a] --json   < text   write a note (user-consented import only)
//   ix overview <file> --format llm                resolve a subgraph: one file
//   ix inventory --kind file --path <prefix> --format llm --limit n    a directory
//   ix context <symbol> --format llm [--kind k] [--path p]             a symbol
//   ix subsystems --target <region> --format llm   an architecture region
//   ix status --format json [--root <dir>]          is a checkout mapped (footprint)
//   ix around <path>:<start>-<end> --format json    the definitions an edit touched, and their dependents (footprint)
//   ix overview <file> --format json               a file's key items (footprint, coarse fallback)

import { execFile } from "node:child_process";
import { IxExtError } from "./text.js";
import { whichAbsolute } from "./which.js";

export interface IxResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface IxRunner {
  run(argv: readonly string[], opts?: { stdin?: string; timeoutMs?: number; cwd?: string }): Promise<IxResult>;
}

export const IX_TIMEOUT_MS = 30_000;
const MAX_OUTPUT = 8 * 1024 * 1024;

/** Lines the CLI prints about its own plugins, not about the request. */
const NOISE = /^ix: failed to load [^\n]*$/gm;

export function ixRunner(opts: { env?: Record<string, string | undefined>; cwd?: string } = {}): IxRunner {
  const env = { ...process.env, ...opts.env } as NodeJS.ProcessEnv;
  const name = env.IX_BIN?.trim() || "ix";
  // Absolute, from PATH's absolute entries: never a program planted in the repo (cwd).
  const bin = whichAbsolute(name, env);
  return {
    run: (argv, o = {}) =>
      new Promise((resolve, reject) => {
        if (!bin) return reject(new IxExtError("ix_missing", `Ix isn't installed (no \`${name}\` on PATH): https://github.com/ix-infrastructure/Ix`));
        const child = execFile(
          bin,
          [...argv],
          { cwd: o.cwd ?? opts.cwd, env, timeout: o.timeoutMs ?? IX_TIMEOUT_MS, killSignal: "SIGKILL", maxBuffer: MAX_OUTPUT, windowsHide: true },
          (err, stdout, stderr) => {
            const e = err as (NodeJS.ErrnoException & { code?: unknown; killed?: boolean }) | null;
            if (e && e.code === "ENOENT") return reject(new IxExtError("ix_missing", `Ix isn't installed (no \`${bin}\` on PATH): https://github.com/ix-infrastructure/Ix`));
            if (e && e.killed) return reject(new IxExtError("ix_timeout", `ix ${argv[0] ?? ""} took longer than ${Math.round((o.timeoutMs ?? IX_TIMEOUT_MS) / 1000)} s`));
            const code = e ? (typeof e.code === "number" ? e.code : 1) : 0;
            resolve({ code, stdout: String(stdout), stderr: String(stderr).replace(NOISE, "").trim() });
          },
        );
        if (o.stdin !== undefined) child.stdin?.end(o.stdin);
        else child.stdin?.end();
      }),
  };
}

/** Whether `ix` runs at all (cached per runner). */
const availability = new WeakMap<IxRunner, Promise<boolean>>();
export function ixAvailable(ix: IxRunner): Promise<boolean> {
  let p = availability.get(ix);
  if (!p) {
    p = ix.run(["--version"], { timeoutMs: 10_000 }).then(
      (r) => r.code === 0,
      () => false,
    );
    availability.set(ix, p);
  }
  return p;
}

/** Runs and parses JSON output; a failure is an IxExtError naming the command. */
export async function ixJson(ix: IxRunner, argv: readonly string[]): Promise<unknown> {
  const r = await ix.run(argv);
  if (r.code !== 0) throw new IxExtError("ix_failed", `ix ${argv[0]} failed (exit ${r.code})${r.stderr ? `: ${r.stderr.slice(0, 300)}` : ""}`);
  try {
    return JSON.parse(r.stdout);
  } catch {
    throw new IxExtError("ix_failed", `ix ${argv[0]} didn't print JSON`);
  }
}
