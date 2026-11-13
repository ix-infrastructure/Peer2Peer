// Copyright 2026 Ix Infrastructure Inc.
//
// Issue #70: a person.key planted on a home before it holds an identity must not keep standing in
// for the person once an identity exists. The CLI replaces it whenever an identity is first created
// or restored on a home (init, setup, join, link join, backup restore), and refuses a token that
// isn't the home's (`person_token_stale`) before doing anything, so a front end reads it again.
// The test users' homes are seeded with a person.key before any identity exists: exactly the
// planted key of the issue.

import { lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { main } from "../cli.js";
import { linkJoin, linkStart } from "../identity.js";
import { personTokenFile, personTokenOk, renewPersonToken } from "../projects.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-person-token.test/v3";
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

describe("the person token is replaced when an identity is created or restored (#70)", () => {
  let relay: TestRelay;
  let tr: Record<string, string>;
  const users: User[] = [];
  const dirs: string[] = [];
  beforeAll(async () => {
    relay = await startRelay(R, { limits: { identityPublishPerIpPerHour: 100_000, newDevicesPerIpPerDay: 100_000, newDevicesPerIpv4PerDay: 100_000 } });
    tr = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
  });
  afterAll(async () => {
    await relay?.close();
    for (const u of users) u.cleanup();
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });
  const mk = (name: string) => {
    const u = new User(name, tr, { P2P_DEFAULT_RELAYS: R });
    users.push(u);
    return u;
  };

  /** Runs `p2p <argv> --json` on `u`'s home with `token` as P2P_PERSON_TOKEN (nothing else of the person's). */
  const withToken = async (u: User, token: string, argv: string[]) => {
    const out: string[] = [];
    const code = await main([...argv, "--json"], { env: { ...u.env, P2P_PERSON_TOKEN: token }, io: { out: (l) => out.push(l), err: () => {} }, confirmTty: async () => false });
    process.exitCode = 0;
    return { code, json: JSON.parse(out.at(-1) ?? "null") as Record<string, unknown> };
  };

  /** The planted key no longer counts, the home's new one does, and a command given the planted one does nothing. */
  async function plantedNoLongerCounts(u: User, planted: string) {
    const now = u.personToken;
    expect(now).toMatch(TOKEN_RE);
    expect(now).not.toBe(planted);
    expect(personTokenOk({ P2P_PERSON_TOKEN: planted }, u.home)).toBe(false);
    expect(personTokenOk({ P2P_PERSON_TOKEN: now }, u.home)).toBe(true);
    expect(statSync(personTokenFile(u.home)).mode & 0o777).toBe(0o600);
    // A widening command with the planted token: refused before anything runs (no invite is made).
    const stale = await withToken(u, planted, ["invite", "--no-circle"]);
    expect(stale.code).toBe(1);
    expect(stale.json.error).toBe("person_token_stale");
    expect(String(stale.json.reason)).not.toContain(planted);
    expect((await u.ok(["invites"])).invites).toHaveLength(0);
    // Reads too: every command refuses a token that isn't this home's.
    expect((await withToken(u, planted, ["whoami"])).json.error).toBe("person_token_stale");
    // The home's own token works.
    expect((await withToken(u, now, ["whoami"])).code).toBe(0);
  }

  it("init", async () => {
    const u = mk("pt-init");
    const planted = u.personToken;
    await u.ok(["init", "--name", "ptinit", "--relay", R, "--yes"]);
    await plantedNoLongerCounts(u, planted);
  });

  it("setup (a new identity)", async () => {
    const u = mk("pt-setup");
    const planted = u.personToken;
    await u.ok(["setup", "--name", "ptsetup", "--relay", R, "--no-backup"]);
    await plantedNoLongerCounts(u, planted);
    // Run again on a home that already holds the identity: nothing is created, the token stays.
    const now = u.personToken;
    await u.ok(["setup"]);
    expect(u.personToken).toBe(now);
  });

  it("join on a fresh home (join's create): the planted token still lets that one command run, then no longer counts", async () => {
    const alice = mk("pt-alice");
    await alice.ok(["init", "--name", "ptalice", "--relay", R, "--yes"]);
    const code = (await alice.ok(["invite", "--no-circle"])).code as string;
    const ben = mk("pt-ben");
    const planted = ben.personToken;
    // The token is checked when the command starts, before the identity exists (the mod's first run).
    const j = await withToken(ben, planted, ["join", "--confirmed", "--wait", "0", "--name", "ptben", code]);
    expect(j.code, JSON.stringify(j.json)).toBe(0);
    await plantedNoLongerCounts(ben, planted);
  });

  it("link join", async () => {
    const a = mk("pt-link1");
    await a.ok(["init", "--name", "ptlink", "--relay", R, "--yes"]);
    const b = mk("pt-link2");
    const planted = b.personToken;
    const aa = await a.app();
    await aa.load();
    const bb = await b.app();
    try {
      const st = await linkStart(aa, { keyholder: false });
      const j = await linkJoin(bb, st.code);
      await Promise.all([st.wait(async (req) => req.compareCode === j.compareCode), j.wait()]);
    } finally {
      await aa.close();
      await bb.close();
    }
    await plantedNoLongerCounts(b, planted);
  });

  it("backup restore", async () => {
    const a = mk("pt-restore1");
    await a.ok(["init", "--name", "ptrestore", "--relay", R, "--yes"]);
    const phrase = (await a.ok(["backup", "show"])).phrase as string;
    const b = mk("pt-restore2");
    const planted = b.personToken;
    await b.ok(["backup", "restore", "--relay", R], { stdin: phrase });
    await plantedNoLongerCounts(b, planted);
  });

  it("a token given to a home with an identity but no person.key is refused, and the next command makes a fresh one", async () => {
    const u = mk("pt-gone");
    await u.ok(["init", "--name", "ptgone", "--relay", R, "--yes"]);
    const before = u.personToken;
    rmSync(personTokenFile(u.home));
    expect((await withToken(u, before, ["whoami"])).json.error).toBe("person_token_stale");
    // That refused run made nothing; a run without a token makes the home's token as before.
    expect(u.personToken).toBe("");
    const out: string[] = [];
    expect(await main(["whoami", "--json"], { env: { ...u.env, P2P_PERSON_TOKEN: "" }, io: { out: (l) => out.push(l), err: () => {} } })).toBe(0);
    process.exitCode = 0;
    expect(u.personToken).toMatch(TOKEN_RE);
    expect(u.personToken).not.toBe(before);
  });

  it("renewPersonToken: a fresh 0600 file, a planted symlink replaced (never followed), a directory in the way removed", () => {
    const home = mkdtempSync(join(tmpdir(), "p2p-pt-"));
    dirs.push(home);
    mkdirSync(join(home, "cli"), { recursive: true });
    const outside = join(home, "outside.txt");
    writeFileSync(outside, "untouched");
    symlinkSync(outside, personTokenFile(home));
    const t = renewPersonToken(home);
    expect(t).toMatch(TOKEN_RE);
    expect(lstatSync(personTokenFile(home)).isSymbolicLink()).toBe(false);
    expect(statSync(personTokenFile(home)).mode & 0o777).toBe(0o600);
    expect(readFileSync(personTokenFile(home), "utf8")).toBe(t);
    expect(readFileSync(outside, "utf8")).toBe("untouched");
    // Each call makes a new one.
    expect(renewPersonToken(home)).not.toBe(t);
    // A directory where the file goes.
    rmSync(personTokenFile(home));
    mkdirSync(join(personTokenFile(home), "x"), { recursive: true });
    const d = renewPersonToken(home);
    expect(readFileSync(personTokenFile(home), "utf8")).toBe(d);
    // No temporary file is left beside it.
    expect(readdirSync(join(home, "cli"))).toEqual(["person.key"]);
  });
});
