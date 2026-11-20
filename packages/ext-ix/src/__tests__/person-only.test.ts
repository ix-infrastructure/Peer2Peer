// Copyright 2026 Ix Infrastructure Inc.
//
// `p2p ix import`, `ix resolve` and `ix config <setting>` are the person's (the CLI's PERSON_ONLY
// gate, packages/p2p/src/cli.ts): refused inside an agent's session however the command line is
// spelled, run with the person's front-end token. A bare `ix config` only reads.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { cleanupTmp, extensionDir, fakeIx, startRelay, User, type FakeIx, type TestRelay } from "./harness.js";

const R = "wss://relay.ext-ix-person-only.test/v3";

let relay: TestRelay;
let ix: FakeIx;
let ann: User;
let agent: User;

describe("ext-ix person-only commands", () => {
  beforeAll(async () => {
    relay = await startRelay(R);
    ix = fakeIx();
    const transport = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    const ext = extensionDir();
    ann = new User("ann", transport, { P2P_EXTENSION_PATH: ext, P2P_EXTENSIONS: "ix", ...ix.env() });
    await ann.ok(["init", "--name", "ann", "--relay", R, "--yes"]);
    // The same home, from an agent's shell: its variables, and no token.
    agent = new User("ann-agent", transport, { ...ann.extraEnv, P2P_HOME: ann.home, P2P_PERSON_TOKEN: "", CLAUDECODE: "1" });
  });
  afterAll(async () => {
    await relay?.close().catch(() => {});
    cleanupTmp();
  });

  it("refused inside an agent's session", async () => {
    for (const argv of [
      ["ix", "import", "abcdef12", "--yes"],
      ["ix", "resolve", "abcdef12", "--yes"],
      ["ix", "config", "names=plain"],
      ["ix", "config", "--circle", "c_x", "names=plain"],
    ]) {
      const r = await agent.run(argv);
      expect(r.json?.error, argv.join(" ")).toBe("refused");
      expect(String(r.json?.reason), argv.join(" ")).toMatch(/only you run it/);
    }
  });

  it("a bare `ix config` reads, from anywhere; the person's token changes it", async () => {
    expect((await agent.ok(["ix", "config"])).config).toBeDefined();
    expect((await ann.ok(["ix", "config", "names=plain"])).config.names).toBe("plain");
    expect((await agent.ok(["ix", "config"])).config.names).toBe("plain");
    expect((await ann.ok(["ix", "config", "names=auto"])).config.names).toBeUndefined();
    // Past the gate with the token: the command's own checks answer (no such event here).
    expect((await ann.run(["ix", "import", "abcdef12", "--yes"])).json?.error).toBe("not_found");
    expect((await ann.run(["ix", "resolve", "abcdef12", "--yes"])).json?.error).toBe("not_found");
  });
});
