// Copyright 2026 Ix Infrastructure Inc.

import { afterEach, expect, it, vi } from "vitest";
import { main } from "../cli.js";
import { CLI_CAPS, PROTO_MINOR } from "../features.js";
import { VERSION } from "../version.js";

afterEach(() => { process.exitCode = 0; });

async function version(args: string[]) {
  const out: string[] = [];
  const err: string[] = [];
  const makeApp = vi.fn(() => { throw new Error("version must not open an application"); });
  const code = await main(args, {
    env: { P2P_EXTENSIONS: "not-an-installed-extension" },
    io: { out: (s) => out.push(s), err: (s) => err.push(s) },
    makeApp,
  });
  expect(makeApp).not.toHaveBeenCalled();
  expect(err).toEqual([]);
  expect(code).toBe(0);
  return out;
}

it("reports protocol and capabilities as one JSON object without identity or extension loading", async () => {
  const out = await version(["version", "--json"]);
  expect(out).toHaveLength(1);
  expect(JSON.parse(out[0])).toEqual({ version: VERSION, protocol: "p2p/v3", protoMinor: PROTO_MINOR, caps: CLI_CAPS, node: process.version });
});

it("prints readable version and capabilities on separate lines", async () => {
  const out = await version(["version"]);
  expect(out.join("\n").split("\n")).toEqual([
    `p2p ${VERSION} · protocol 3.${PROTO_MINOR} · node ${process.version}`,
    CLI_CAPS.join(", "),
  ]);
});
