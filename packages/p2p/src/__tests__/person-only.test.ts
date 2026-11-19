// Copyright 2026 Ix Infrastructure Inc.
//
// Person-only commands (cli.ts PERSON_ONLY): the ones that touch the identity key, the identity
// document or the person's own setup run only for the person (their front end's token, or their
// "yes" on their own terminal), never from inside an agent's session. The agent guards in the
// front ends read command lines; this gate is the CLI's own, decided from the command it parsed,
// so the way an agent spells the line (a name built at run time, a script it wrote) can't matter.
// Internal maintenance (`p2p watch` renewing the document) is not a command and keeps working.

import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { main } from "../cli.js";
import { maintain } from "../watch.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-person-only.test/v3";

type How = "agent" | "token" | "yes" | "no";

describe("person-only commands", () => {
  let relay: TestRelay;
  let tr: Record<string, string>;
  const users: User[] = [];
  let ann: User;
  let ben: User;
  let cid = "";
  let benId = "";
  beforeAll(async () => {
    relay = await startRelay(R, { limits: { identityPublishPerIpPerHour: 100_000, newDevicesPerIpPerDay: 100_000, newDevicesPerIpv4PerDay: 100_000 } });
    tr = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    ann = mk("po-ann");
    ben = mk("po-ben");
    await ann.ok(["init", "--name", "ann", "--relay", R, "--yes"]);
    benId = (await ben.ok(["init", "--name", "ben", "--relay", R, "--yes"])).userId as string;
    const inv = await ann.ok(["invite", "--link", "--no-circle"]);
    await ben.ok(["accept", inv.link]);
    await ann.ok(["friends"]);
    cid = (await ann.ok(["circle", "create", "team"])).cid as string;
  }, 60_000);
  afterAll(async () => {
    await relay?.close();
    for (const u of users) u.cleanup();
  });
  function mk(name: string): User {
    const u = new User(name, tr, { P2P_DEFAULT_RELAYS: R });
    users.push(u);
    return u;
  }

  /**
   * Runs `p2p <argv> --json` on `u`'s home as: an agent's session (its variables, no token; its
   * terminal would even say yes), the person's front end (the token), or the person at a terminal
   * (no token) answering yes or no. Says whether the terminal was asked.
   */
  async function as(u: User, how: How, argv: string[], stdin?: string) {
    const env =
      how === "agent" ? { ...u.env, P2P_PERSON_TOKEN: "", CLAUDECODE: "1" } : how === "token" ? u.env : { ...u.env, P2P_PERSON_TOKEN: "" };
    const out: string[] = [];
    let asked = false;
    const code = await main([...argv, "--json"], {
      env,
      io: { out: (l) => out.push(l), err: () => {}, ...(stdin !== undefined ? { readStdin: async () => stdin } : {}) },
      confirmTty: async () => {
        asked = true;
        return how !== "no";
      },
    });
    process.exitCode = 0;
    let json: Record<string, unknown> = {};
    try {
      json = JSON.parse(out.at(-1) ?? "{}") as Record<string, unknown>;
    } catch {
      // not JSON
    }
    return { code, json, asked };
  }

  /** Each gated command: refused in an agent's session (even with a terminal yes), and at a terminal on "no"; past the gate with the token or a terminal yes. */
  const gated = (): { argv: string[]; stdin?: string }[] => [
    { argv: ["backup", "show"] },
    { argv: ["backup", "restore", "--relay", R], stdin: "not a phrase" },
    { argv: ["identity", "rotate", "--resume"] },
    { argv: ["identity", "rotate", "--plan", "--backup-file", join(tmpdir(), "po-never-written.txt")] },
    { argv: ["identity", "rotate", "--plan", "--exclude", "d_nope"] },
    { argv: ["identity", "rotate", "--cancel"] },
    { argv: ["identity", "rotate", "--yes", "--backup-file", join(tmpdir(), "po-never-written.txt")] },
    { argv: ["identity", "rotate", "--resend"] },
    { argv: ["identity", "republish"] },
    { argv: ["identity", "dispute", "nope", "--neither"] },
    { argv: ["devices", "revoke", "d_nope"] },
    { argv: ["relays", "add", "wss://relay-other.test/v3"] },
    { argv: ["relays", "remove", "wss://relay-other.test/v3"] },
    { argv: ["trust", "remove", "nobody@0000"] },
    { argv: ["invites", "revoke", "ZZZZ"] },
    { argv: ["remove", "nobody@0000"] },
    { argv: ["unfriend", "nobody@0000"] },
    { argv: ["circle", "propose", "c_nope", "rename", "x"] },
    { argv: ["circle", "transfer", "c_nope", "nobody@0000"] },
    { argv: ["circle", "hold", "c_nope", "on"] },
    { argv: ["extensions", "disable", "ix"] },
    { argv: ["receipts", "off"] },
    { argv: ["setup", "--print-backup"] },
    { argv: ["setup", "--backup-file", join(tmpdir(), "po-never-written.txt")] },
  ];

  it("refused inside an agent's session, whatever its terminal would answer, and nothing is shown", async () => {
    for (const { argv, stdin } of gated()) {
      const r = await as(ann, "agent", argv, stdin);
      expect(r.json.error, argv.join(" ")).toBe("refused");
      expect(String(r.json.reason), argv.join(" ")).toMatch(/only you run it.*inside an agent's session/);
      expect(r.asked, argv.join(" ")).toBe(false);
      expect(r.json.phrase, argv.join(" ")).toBeUndefined();
      expect(r.json.backup, argv.join(" ")).toBeUndefined();
    }
  });

  it("refused at a terminal when the person doesn't say yes", async () => {
    for (const { argv, stdin } of gated()) {
      // A restore outside an agent's session takes the phrase itself as the person's proof (below).
      if (argv[1] === "restore") continue;
      const r = await as(ann, "no", argv, stdin);
      expect(r.json.error, argv.join(" ")).toBe("refused");
      expect(r.asked, argv.join(" ")).toBe(true);
    }
  });

  it("past the gate with the person's token, or their terminal yes", async () => {
    // A user of its own: these really run (a relay added, receipts turned off, ...).
    const u = mk("po-pass");
    await u.ok(["init", "--name", "pass", "--relay", R, "--yes"]);
    for (const how of ["token", "yes"] as const) {
      for (const { argv, stdin } of gated()) {
        // A restore needs a fresh home and a real phrase, a setup reveal or a rotation's backup writes the
        // phrase to a file, and `--yes` rotates: those run in full in the tests below.
        if (argv[0] === "setup" || argv[0] === "backup" || argv.includes("--backup-file") || argv.includes("--yes")) continue;
        const r = await as(u, how, argv, stdin);
        expect(r.json.error, `${how}: ${argv.join(" ")}: ${JSON.stringify(r.json)}`).not.toBe("refused");
        expect(r.asked, argv.join(" ")).toBe(how === "yes");
      }
    }
  });

  it("backup show: the phrase only for the person; the person's yes or token shows it", async () => {
    const kh = mk("po-kh");
    await kh.ok(["init", "--name", "kh", "--relay", R, "--yes"]);
    const tok = await as(kh, "token", ["backup", "show"]);
    expect(tok.code).toBe(0);
    expect(String(tok.json.phrase).split(" ")).toHaveLength(24);
    const yes = await as(kh, "yes", ["backup", "show"]);
    expect(yes.json.phrase).toBe(tok.json.phrase);
    // And restore with it, on a fresh home, as the person.
    const fresh = mk("po-restore");
    const rr = await as(fresh, "agent", ["backup", "restore", "--relay", R], String(tok.json.phrase));
    expect(rr.json.error).toBe("refused");
    // Outside an agent's session, on a fresh home (no person token there yet), the phrase is the proof:
    // nothing more is asked, and a wrong phrase is the restore's own error.
    const headless = await as(mk("po-headless"), "no", ["backup", "restore", "--relay", R], "not a phrase");
    expect(headless.asked).toBe(false);
    expect(headless.json.error).not.toBe("refused");
    const ok = await as(fresh, "token", ["backup", "restore", "--relay", R, "--keep-devices"], String(tok.json.phrase));
    expect(ok.code, JSON.stringify(ok.json)).toBe(0);
  });

  it("setup reveals an existing identity's phrase only to the person; a plain setup stays open", async () => {
    expect((await as(ann, "agent", ["setup"])).code).toBe(0);
    expect((await as(ann, "agent", ["setup", "--no-backup"])).code).toBe(0);
    const tok = await as(ann, "token", ["setup", "--print-backup"]);
    expect(tok.code).toBe(0);
    expect(String((tok.json.backup as { phrase?: string })?.phrase).split(" ")).toHaveLength(24);
  });

  it("reads stay open in an agent's session: receipts, circle hold <cid>, a bare rotate --plan", async () => {
    expect((await as(ann, "agent", ["receipts"])).code).toBe(0);
    const hold = await as(ann, "agent", ["circle", "hold", cid]);
    expect(hold.json.error).not.toBe("refused");
    const plan = await as(ann, "agent", ["identity", "rotate", "--plan"]);
    expect(plan.code, JSON.stringify(plan.json)).toBe(0);
    expect(plan.json.backup).toBeUndefined();
    // Accepting it is the person's (and dropping it: an agent can't swap the plan the person reviewed).
    expect((await as(ann, "agent", ["identity", "rotate", "--resume", "--yes"])).json.error).toBe("refused");
    expect((await as(ann, "agent", ["identity", "rotate", "--cancel"])).json.error).toBe("refused");
    expect((await as(ann, "token", ["identity", "rotate", "--cancel"])).json.cancelled).toBe(true);
  });

  it("the person's settings change with the token: receipts off/on, circle hold", async () => {
    expect((await as(ann, "token", ["receipts", "off"])).json.receipts).toBe(false);
    expect((await as(ann, "agent", ["receipts"])).json.receipts).toBe(false);
    expect((await as(ann, "token", ["receipts", "on"])).json.receipts).toBe(true);
    expect((await as(ann, "token", ["circle", "hold", cid, "on"])).json.hold).toBe(true);
    expect((await as(ann, "agent", ["circle", "hold", cid, "off"])).json.error).toBe("refused");
    expect((await ann.ok(["circle", "hold", cid])).hold).toBe(true);
  });

  it("the CLI's spelling doesn't matter: a name built at run time, or a script, is refused the same", async () => {
    const bin = fileURLToPath(new URL("../../dist/bin.js", import.meta.url));
    const dir = mkdtempSync(join(tmpdir(), "po-bin-"));
    try {
      const shim = join(dir, "p2p");
      writeFileSync(shim, `#!/bin/sh\nexec "${process.execPath}" "${bin}" "$@"\n`);
      chmodSync(shim, 0o755);
      const script = join(dir, "x.sh");
      writeFileSync(script, `#!/bin/sh\nY=p2\n\${Y}p backup show --json\n`);
      const env: NodeJS.ProcessEnv = { PATH: `${dir}:${process.env.PATH ?? ""}`, ...ann.env, CLAUDECODE: "1" };
      delete env.P2P_PERSON_TOKEN;
      for (const argv of [["-c", 'X=p2; ${X}p backup show --json'], [script]]) {
        const r = spawnSync("sh", argv, { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
        expect(r.status, argv.join(" ")).toBe(1);
        expect(r.stdout, argv.join(" ")).toMatch(/"error":"refused"/);
        expect(r.stdout).not.toMatch(/"phrase"/);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("auto-renewal still runs inside an agent's session: `p2p watch` maintenance republishes the document itself", async () => {
    const u = mk("po-renew");
    await u.ok(["init", "--name", "renew", "--relay", R, "--yes"]);
    const before = (await u.ok(["whoami"])).doc as { ver: number; exp: number };
    const real = Date.now.bind(Date);
    // Three days before the document expires: inside the renewal window.
    const skew = (before.exp - 3 * 86_400) * 1000 - real();
    const spy = vi.spyOn(Date, "now").mockImplementation(() => real() + skew);
    try {
      const app = await u.app();
      // The watcher a front end starts runs inside the agent's session, without the token.
      (app as { env: Record<string, string | undefined> }).env = { ...app.env, P2P_PERSON_TOKEN: "", CLAUDECODE: "1" };
      app.front = false;
      try {
        await app.load();
        await maintain(app);
      } finally {
        await app.close();
      }
      const after = (await as(u, "agent", ["whoami"])).json.doc as { ver: number; exp: number };
      expect(after.ver).toBeGreaterThan(before.ver);
      expect(after.exp).toBeGreaterThan(before.exp);
    } finally {
      spy.mockRestore();
    }
  });

  it("a front end's typed commands still work: the token runs the mod's /peers relays, rotate plan and remove paths", async () => {
    // What the Claude mod runs for typed /peers (hooks/backend.ts), with the person token.
    const plan = await as(ann, "token", ["identity", "rotate", "--plan", "--backup-file"]);
    expect(plan.code, JSON.stringify(plan.json)).toBe(0);
    expect((await as(ann, "token", ["identity", "rotate", "--cancel"])).json.cancelled).toBe(true);
    const add = await as(ann, "token", ["relays", "add", R]);
    expect(add.json.error).not.toBe("refused");
    const rm = await as(ann, "token", ["remove", benId]);
    expect(rm.code, JSON.stringify(rm.json)).toBe(0);
  });
});
