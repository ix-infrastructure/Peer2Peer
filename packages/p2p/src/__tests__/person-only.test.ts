// Copyright 2026 Ix Infrastructure Inc.
//
// Person-only commands (cli.ts PERSON_ONLY): the ones that touch the identity key, the identity
// document or the person's own setup run only for the person (their front end's token, or their
// "yes" on their own terminal), never from inside an agent's session. The agent guards in the
// front ends read command lines; this gate is the CLI's own, decided from the command it parsed,
// so the way an agent spells the line (a name built at run time, a script it wrote) can't matter.
// Internal maintenance (`p2p watch` renewing the document) is not a command and keeps working.

import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { App } from "../app.js";
import { main, type ProgramDeps } from "../cli.js";
import { homeFilesOwn, identityHere, personToken, personTokenFile, personTokenOk, personSaltFile } from "../projects.js";
import { maintain } from "../watch.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-person-only.test/v3";
const R2 = "wss://relay-person-only-2.test/v3";
const R3 = "wss://relay-person-only-3.test/v3";
const R4 = "wss://relay-person-only-4.test/v3";

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
    { argv: ["circle", "leave", "c_nope"] },
    { argv: ["held", "decline", "nope"] },
    { argv: ["block", "nobody@0000"] },
    { argv: ["petname", "nobody@0000", "x"] },
    { argv: ["profile", "set", "--bio", "set by whom?"] },
    { argv: ["proof", "add", "github", "nobody"] },
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

describe("the gate holds against a home made of links, a shadowed ps, and an unreadable process tree", () => {
  let relay: TestRelay;
  let tr: Record<string, string>;
  const users: User[] = [];
  const dirs: string[] = [];
  let ann: User;
  beforeAll(async () => {
    relay = await startRelay(R2, { limits: { identityPublishPerIpPerHour: 100_000, newDevicesPerIpPerDay: 100_000, newDevicesPerIpv4PerDay: 100_000 } });
    tr = { [R2]: `ws://127.0.0.1:${relay.port}/v3` };
    ann = new User("po2-ann", tr, { P2P_DEFAULT_RELAYS: R2 });
    users.push(ann);
    await ann.ok(["init", "--name", "ann", "--relay", R2, "--yes"]);
  }, 60_000);
  afterAll(async () => {
    (globalThis as { __p2pTestAncestry?: string }).__p2pTestAncestry = undefined;
    await relay?.close();
    for (const u of users) u.cleanup();
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });
  const tmp = (p: string) => {
    const d = mkdtempSync(join(tmpdir(), p));
    dirs.push(d);
    return d;
  };
  const run = async (env: Record<string, string | undefined>, argv: string[], yes = false) => {
    const out: string[] = [];
    const code = await main([...argv, "--json"], { env, io: { out: (l) => out.push(l), err: () => {} }, confirmTty: async () => yes });
    process.exitCode = 0;
    return { code, json: JSON.parse(out.at(-1) ?? "{}") as Record<string, unknown> };
  };

  it("the person token is derived: a person.key written by anything else never verifies, and the derived one does", () => {
    const real = ann.personToken;
    expect(real).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(personTokenOk({ P2P_PERSON_TOKEN: real }, ann.home)).toBe(true);
    // Overwritten with a value of someone else's choosing: neither it nor the old one verifies.
    const planted = randomBytes(32).toString("base64url");
    writeFileSync(personTokenFile(ann.home), planted);
    expect(personTokenOk({ P2P_PERSON_TOKEN: planted }, ann.home)).toBe(false);
    expect(personTokenOk({ P2P_PERSON_TOKEN: real }, ann.home)).toBe(false);
    // The CLI writes the derived one back (the next command), and it verifies again.
    expect(personToken(ann.home)).toBe(real);
    expect(personTokenOk({ P2P_PERSON_TOKEN: real }, ann.home)).toBe(true);
  });

  it("a home made of symbolic links to the identity's files, with a token of the agent's choosing, is never the person's", async () => {
    const h = tmp("po-linked-");
    mkdirSync(join(h, "cli"), { recursive: true, mode: 0o700 });
    for (const f of ["keys.json", "self.json"]) symlinkSync(join(ann.home, "cli", f), join(h, "cli", f));
    symlinkSync(join(ann.home, "v3"), join(h, "v3"));
    const mine = randomBytes(32).toString("base64url");
    writeFileSync(personTokenFile(h), mine, { mode: 0o600 });
    expect(homeFilesOwn(h)).toBe(false);
    expect(personTokenOk({ P2P_PERSON_TOKEN: mine }, h)).toBe(false);
    const env = { ...ann.env, P2P_HOME: h, P2P_PERSON_TOKEN: mine, CLAUDECODE: "1" };
    const r = await run(env, ["backup", "show"]);
    expect(r.code).toBe(1);
    expect(["refused", "person_token_stale"]).toContain(r.json.error);
    expect(r.json.phrase).toBeUndefined();
    // Nothing that verifies was written into that home for the agent to read.
    expect(readFileSync(personTokenFile(h), "utf8")).toBe(mine);
    expect(existsSync(personSaltFile(h))).toBe(false);
  });

  it("hard links to the identity's files don't make a home the person's either", async () => {
    const h = tmp("po-hard-");
    mkdirSync(join(h, "cli"), { recursive: true, mode: 0o700 });
    try {
      for (const f of ["keys.json", "self.json"]) linkSync(join(ann.home, "cli", f), join(h, "cli", f));
    } catch {
      return; // another file system: hard links can't be made here
    }
    const mine = randomBytes(32).toString("base64url");
    writeFileSync(personTokenFile(h), mine, { mode: 0o600 });
    writeFileSync(personSaltFile(h), randomBytes(32).toString("base64url"), { mode: 0o600 });
    expect(homeFilesOwn(h)).toBe(false);
    expect(personTokenOk({ P2P_PERSON_TOKEN: mine }, h)).toBe(false);
    const r = await run({ ...ann.env, P2P_HOME: h, P2P_PERSON_TOKEN: mine, CLAUDECODE: "1" }, ["backup", "show"]);
    expect(r.json.phrase).toBeUndefined();
    expect(readFileSync(personTokenFile(h), "utf8")).toBe(mine);
    // And the real home's own files are untouched (one link each again once these go).
    rmSync(join(h, "cli"), { recursive: true, force: true });
    expect(homeFilesOwn(ann.home)).toBe(true);
  });

  it("an unreadable process tree fails closed: refused without the token, even with a terminal yes; the token still works", async () => {
    const g = globalThis as { __p2pTestAncestry?: string };
    g.__p2pTestAncestry = "unknown";
    try {
      const noToken = { ...ann.env, P2P_PERSON_TOKEN: "" };
      for (const argv of [["backup", "show"], ["receipts", "off"], ["backup", "restore", "--relay", R2], ["invite", "--no-circle"]]) {
        const r = await run(noToken, argv, true);
        expect(r.json.error, argv.join(" ")).toBe("refused");
        expect(String(r.json.reason), argv.join(" ")).toMatch(/couldn't read its process tree|inside an agent's session/);
      }
      expect((await run(ann.env, ["backup", "show"])).code).toBe(0);
      // Reads stay open.
      expect((await run(noToken, ["receipts"])).code).toBe(0);
    } finally {
      g.__p2pTestAncestry = undefined;
    }
  });

  it("the process tree is read without PATH: a `ps` put first on PATH is never run", async () => {
    const bin = fileURLToPath(new URL("../../dist/bin.js", import.meta.url));
    const fake = tmp("po-fakeps-");
    const marker = join(fake, "ran");
    writeFileSync(join(fake, "ps"), `#!/bin/sh\necho ran > "${marker}"\necho "1 sh"\n`);
    chmodSync(join(fake, "ps"), 0o755);
    const env: NodeJS.ProcessEnv = { ...ann.env, PATH: `${fake}:${process.env.PATH ?? ""}` };
    delete env.P2P_PERSON_TOKEN;
    // Detached: no terminal to answer, so whatever the tree says the command is refused; the point is which ps ran.
    const stdout = await new Promise<string>((done) => {
      const c = spawn(process.execPath, [bin, "backup", "show", "--json"], { env, detached: true, stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      c.stdout.on("data", (d) => (out += String(d)));
      c.on("close", () => done(out));
    });
    expect(stdout).toMatch(/"error":"refused"/);
    expect(existsSync(marker)).toBe(false);
  });

  it("ancestry walks fail closed: an unreadable step or a loop is unknown, the root is none, an agent anywhere is agent", async () => {
    const real = await vi.importActual<typeof import("../ancestry.js")>("../ancestry.js");
    const tree: Record<number, { ppid: number; comm: string; args?: string }> = {
      30: { ppid: 20, comm: "/bin/zsh" },
      20: { ppid: 10, comm: "/usr/local/bin/claude" },
      10: { ppid: 1, comm: "launchd" },
      40: { ppid: 41, comm: "node", args: "node /x/node_modules/@openai/codex/bin/codex.js" },
      50: { ppid: 50, comm: "sh" },
      60: { ppid: 10, comm: "sh" },
    };
    const read = (pid: number) => {
      const p = tree[pid];
      if (!p) throw new Error("gone");
      return { ppid: p.ppid, comm: p.comm, args: () => p.args ?? "" };
    };
    expect(real.walkAncestry(30, read)).toBe("agent");
    expect(real.walkAncestry(40, read)).toBe("agent");
    expect(real.walkAncestry(60, read)).toBe("none");
    expect(real.walkAncestry(50, read)).toBe("unknown");
    expect(real.walkAncestry(99, read)).toBe("unknown");
    expect(real.PS_PATHS.every((p) => p.startsWith("/"))).toBe(true);
  });
});

describe("p2p invites inside an agent's session", () => {
  let relay: TestRelay;
  let u: User;
  beforeAll(async () => {
    relay = await startRelay(R3);
    u = new User("po3", { [R3]: `ws://127.0.0.1:${relay.port}/v3` }, { P2P_DEFAULT_RELAYS: R3 });
    await u.ok(["init", "--name", "po3", "--relay", R3, "--yes"]);
  }, 60_000);
  afterAll(async () => {
    await relay?.close();
    u?.cleanup();
  });

  it("cuts live codes (JSON and text) without the token; the person sees them whole", async () => {
    const code = String((await u.ok(["invite", "--no-circle"])).code);
    expect(code.length).toBeGreaterThan(8);
    const out: string[] = [];
    const agentEnv = { ...u.env, P2P_PERSON_TOKEN: "", CLAUDECODE: "1" };
    await main(["invites", "--json"], { env: agentEnv, io: { out: (l) => out.push(l), err: () => {} } });
    await main(["invites"], { env: agentEnv, io: { out: (l) => out.push(l), err: () => {} } });
    process.exitCode = 0;
    const j = JSON.parse(out[0]) as { invites: { code: string; status: string; redacted?: boolean }[]; redacted?: boolean };
    expect(j.redacted).toBe(true);
    expect(j.invites[0].status).toBe("open");
    expect(j.invites[0].redacted).toBe(true);
    expect(out.join("\n")).not.toContain(code);
    expect(out.join("\n")).not.toContain(code.slice(-6));
    const whole = (await u.ok(["invites"])) as { invites: { code: string }[]; redacted?: boolean };
    expect(whole.redacted).toBeUndefined();
    expect(whole.invites[0].code).toBe(code);
  });
});

describe("a token checked at the start never carries over to a home that changes under the command", () => {
  let relay: TestRelay;
  const users: User[] = [];
  const dirs: string[] = [];
  let ann: User;
  beforeAll(async () => {
    relay = await startRelay(R4, { limits: { identityPublishPerIpPerHour: 100_000, newDevicesPerIpPerDay: 100_000, newDevicesPerIpv4PerDay: 100_000 } });
    ann = new User("po4-ann", { [R4]: `ws://127.0.0.1:${relay.port}/v3` }, { P2P_DEFAULT_RELAYS: R4 });
    users.push(ann);
    await ann.ok(["init", "--name", "ann", "--relay", R4, "--yes"]);
  }, 60_000);
  afterAll(async () => {
    await relay?.close();
    for (const u of users) u.cleanup();
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });
  /** A fresh-looking home with a token of the agent's choosing in it. */
  const plantedHome = () => {
    const h = mkdtempSync(join(tmpdir(), "po-planted-"));
    dirs.push(h);
    mkdirSync(join(h, "cli"), { recursive: true, mode: 0o700 });
    const mine = randomBytes(32).toString("base64url");
    writeFileSync(personTokenFile(h), mine, { mode: 0o600 });
    return { h, mine };
  };
  const run = async (env: Record<string, string | undefined>, argv: string[], makeApp?: ProgramDeps["makeApp"]) => {
    const out: string[] = [];
    const code = await main([...argv, "--json"], { env, io: { out: (l) => out.push(l), err: () => {} }, confirmTty: async () => false, ...(makeApp ? { makeApp } : {}) });
    process.exitCode = 0;
    return { code, json: JSON.parse(out.at(-1) ?? "{}") as Record<string, unknown> };
  };

  it("an interrupted-follow folder of links to the real identity is never moved in, and the phrase is never shown", async () => {
    const { h, mine } = plantedHome();
    const follow = join(h, "rotation", "follow");
    mkdirSync(follow, { recursive: true, mode: 0o700 });
    writeFileSync(join(follow, "linked.json"), "{}");
    symlinkSync(join(ann.home, "cli"), join(follow, "cli"));
    symlinkSync(join(ann.home, "v3"), join(follow, "v3"));
    const r = await run({ ...ann.env, P2P_HOME: h, P2P_PERSON_TOKEN: mine, CLAUDECODE: "1" }, ["backup", "show"]);
    expect(r.code).toBe(1);
    expect(r.json.phrase).toBeUndefined();
    // The links stayed where they were: nothing of the real home was moved into this one.
    expect(existsSync(join(h, "cli", "keys.json"))).toBe(false);
    expect(lstatSync(join(follow, "cli")).isSymbolicLink()).toBe(true);
    expect(identityHere(ann.home)).toBe(true);
  });

  it("files dropped into the home after the token was checked: the token goes, and the gate refuses", async () => {
    for (const how of ["symlink", "copy"] as const) {
      const { h, mine } = plantedHome();
      // Between main()'s check and the command's gates: the identity's files appear in the home.
      const makeApp: ProgramDeps["makeApp"] = (env, io) => {
        for (const f of ["keys.json", "self.json"]) {
          if (how === "symlink") symlinkSync(join(ann.home, "cli", f), join(h, "cli", f));
          else copyFileSync(join(ann.home, "cli", f), join(h, "cli", f));
        }
        if (how === "symlink") symlinkSync(join(ann.home, "v3"), join(h, "v3"));
        return new App({ env, io });
      };
      const r = await run({ ...ann.env, P2P_HOME: h, P2P_PERSON_TOKEN: mine, CLAUDECODE: "1" }, ["backup", "show"], makeApp);
      expect(r.json.error, how).toBe("refused");
      expect(r.json.phrase, how).toBeUndefined();
    }
  });

  it("the keys a command loads must be the ones the token derives (App.load), unless the command made them", async () => {
    const app = await ann.app();
    try {
      app.front = true;
      app.frontToken = randomBytes(32).toString("base64url");
      await expect(app.load()).rejects.toMatchObject({ code: "refused" });
      expect(app.front).toBe(false);
      app.front = true;
      app.frontToken = ann.personToken;
      await expect(app.load()).resolves.toBe(true);
      // A home that had no identity when the token was checked keeps no token for keys it didn't make.
      app.frontFresh = true;
      await expect(app.load()).rejects.toMatchObject({ code: "refused" });
      app.front = true;
      app.identityMadeHere = true;
      await expect(app.load()).resolves.toBe(true);
    } finally {
      await app.close();
    }
  });

  it("a home of links says why the token isn't taken there", async () => {
    const h = mkdtempSync(join(tmpdir(), "po-dotfiles-"));
    dirs.push(h);
    symlinkSync(join(ann.home, "cli"), join(h, "cli"));
    const r = await run({ ...ann.env, P2P_HOME: h, P2P_PERSON_TOKEN: ann.personToken }, ["whoami"]);
    expect(r.json.error).toBe("refused");
    expect(String(r.json.reason)).toMatch(/symbolic link.*point P2P_HOME at the real folder/);
  });

  it("ancestry: a nested PID namespace is unknown; another user's (or a hidden) process ends the walk as none", async () => {
    const real = await vi.importActual<typeof import("../ancestry.js")>("../ancestry.js");
    expect(real.nestedPidNamespace("Name:\tnode\nNSpid:\t4242\t7\n")).toBe(true);
    expect(real.nestedPidNamespace("Name:\tnode\nNSpid:\t4242\n")).toBe(false);
    expect(real.nestedPidNamespace("Name:\tnode\n")).toBe(false);
    const read = (pid: number) => {
      if (pid === 30) return { ppid: 20, comm: "bash", args: () => "" };
      throw new real.OtherUsersProcess();
    };
    expect(real.walkAncestry(30, read)).toBe("none");
  });
});
