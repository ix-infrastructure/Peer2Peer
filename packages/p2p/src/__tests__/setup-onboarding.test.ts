// Copyright 2026 Ix Infrastructure Inc.
//
// `p2p setup` at a person's terminal asks how they're joining before any key is made: link this
// device to an identity they already have (`link join`, inline), redeem an invite (`join`,
// inline), or start a new identity (on their group's relay: there is no default relay). The
// backup question comes only once an identity exists. Scripts, --json, CI and agents see the old
// behaviour, with a no_relays error that names all three ways in.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Io } from "../app.js";
import { main } from "../cli.js";
import { noRelaysReason, p2pCommand } from "../identity.js";
import { alongside, startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-setup-onboarding.test/v3";

describe("p2p setup: how are you joining?", () => {
  let relay: TestRelay;
  let tr: Record<string, string>;
  const users: User[] = [];
  const dirs: string[] = [];
  beforeAll(async () => {
    relay = await startRelay(R);
    tr = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
  }, 30_000);
  afterAll(async () => {
    await relay?.close();
    for (const u of users) u.cleanup();
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });
  /** A fresh home with no identity and no default relay (PATH without Ix: its offer is asked last). */
  const fresh = (env: Record<string, string> = {}) => {
    const home = mkdtempSync(join(tmpdir(), "p2p-setup-"));
    dirs.push(home);
    return { home, env: { P2P_HOME: home, P2P_RELAY_TRANSPORT: JSON.stringify(tr), P2P_LINK_POLL_MS: "100", P2P_CONNECT_TIMEOUT_MS: "3000", PATH: "/nonexistent-p2p-test", ...env } };
  };
  /** Whether the home holds an identity (`p2p whoami` succeeds). */
  const hasIdentity = async (home: string) => {
    const code = await main(["whoami", "--json"], { env: { P2P_HOME: home, P2P_RELAY_TRANSPORT: JSON.stringify(tr) }, io: { out: () => {}, err: () => {} } });
    process.exitCode = 0;
    return code === 0;
  };

  /**
   * Runs `p2p <argv>` at a terminal whose answers are `answers` (each prompt takes the next).
   * `when` records, for each question, whether an identity existed when it was asked.
   */
  async function runAt(
    env: Record<string, string | undefined>,
    argv: string[],
    answers: string[] | null,
    o: { front?: boolean; ops?: Record<string, unknown>; confirmTty?: (q: string) => Promise<boolean> } = {},
  ) {
    const lines = { out: [] as string[], err: [] as string[] };
    const asked: string[] = [];
    const outAt: number[] = [];
    const io: Io = {
      out: (s) => lines.out.push(s),
      err: (s) => lines.err.push(s),
      ...(answers ? { prompt: async (q: string) => (asked.push(q), outAt.push(lines.out.length), answers.shift() ?? "") } : {}),
    };
    const code = await main(argv, {
      env,
      io,
      front: o.front ?? true,
      confirmTty: o.confirmTty ?? (async () => true),
      ...(o.ops ? { ops: o.ops as never } : {}),
    });
    process.exitCode = 0;
    // What had been printed before each question.
    const before = (i: number) => lines.out.slice(0, outAt[i]).join("\n");
    return { code, out: lines.out.join("\n"), err: lines.err.join("\n"), asked, before, transcript: [...lines.out, ...lines.err].join("\n") };
  }

  it("the no_relays error names the three ways in (link, invite, --relay), with p2p.cmd on Windows", () => {
    const m = noRelaysReason("/h");
    expect(m).toContain("p2p link start");
    expect(m).toContain("link join <code>");
    expect(m).toContain("join <invite link or code>");
    expect(m).toContain("--relay wss://");
    expect(m).toContain("/h/config.json");
    expect(noRelaysReason("/h", "win32")).toContain("`p2p.cmd link join <code>`");
    expect(noRelaysReason("/h", "win32")).toContain("`p2p.cmd join <invite");
    expect(p2pCommand("linux")).toBe("p2p");
  });

  it("[l] runs link join inline with the code typed: no identity is made here, and no backup is asked", async () => {
    const f = fresh();
    const calls: string[] = [];
    const linkJoin = async (_app: unknown, code: string) => {
      calls.push(code);
      return { compareCode: "tiger-maple-42", did: "did:p2p:dev", wait: async () => ({ address: "ana@abcd", did: "did:p2p:dev", keyholder: false }) };
    };
    const init = async () => {
      throw new Error("init must not run on the link path");
    };
    const r = await runAt(f.env, ["setup"], ["l", "  p2p-link:SECRET@relay.example  "], { ops: { linkJoin, init } });
    expect(r.code, r.err).toBe(0);
    expect(calls).toEqual(["p2p-link:SECRET@relay.example"]);
    expect(r.asked).toEqual(["Choose l, i or n: ", "Link code: "]);
    expect(r.before(1)).toContain("On your other device run:  p2p link start");
    expect(r.before(1)).toContain("/peers link start");
    expect(r.out).toContain("Compare code: tiger-maple-42");
    expect(r.out).toContain("This device is now ana@abcd");
    expect(r.transcript).not.toMatch(/Choose f, p or s|backup phrase/);
  });

  it("[l] is the same validation as `p2p link join`: a bad code is refused, nothing is made", async () => {
    const f = fresh();
    const r = await runAt(f.env, ["setup"], ["l", "not-a-link-code"]);
    expect(r.code).toBe(1);
    expect(r.err).toContain("that is not a link code");
    expect(r.asked).toEqual(["Choose l, i or n: ", "Link code: "]);
    expect(await hasIdentity(f.home)).toBe(false);
  });

  it("[l] and [i] keep the person-only gate: without a front end's token the terminal 'yes' is asked, and a no stops it", async () => {
    const f = fresh();
    const asked: string[] = [];
    let linked = false;
    const r = await runAt(f.env, ["setup"], ["l", "p2p-link:x@y"], {
      front: false,
      confirmTty: async (q) => (asked.push(q), false),
      ops: { linkJoin: async () => ((linked = true), undefined) },
    });
    expect(r.code).toBe(1);
    expect(asked).toEqual(["p2p link join changes who reaches you."]);
    expect(r.err).toContain("refused");
    expect(linked).toBe(false);
    // Refused before the code is asked for.
    expect(r.asked).toEqual(["Choose l, i or n: "]);

    const g = fresh();
    const gAsked: string[] = [];
    const j = await runAt(g.env, ["setup"], ["i", "x"], { front: false, confirmTty: async (q) => (gAsked.push(q), false) });
    expect(j.code).toBe(1);
    expect(gAsked).toEqual(["p2p join changes who reaches you."]);
    expect(await hasIdentity(g.home)).toBe(false);
  });

  it("[i] redeems the invite inline: the identity is made on the inviter's relay, then the backup is asked", async () => {
    const alice = new User("alice", tr, { P2P_DEFAULT_RELAYS: R });
    users.push(alice);
    await alice.ok(["setup", "--name", "alice", "--no-backup"]);
    const inv = await alice.ok(["invite", "--no-circle"]);
    const f = fresh();
    const r = await alongside(runAt(f.env, ["setup", "--name", "bob"], ["i", inv.code, "y", "s", ""], { confirmTty: async () => true }), () => alice.ok(["invites"]));
    expect(r.code, r.err).toBe(0);
    expect(r.asked[0]).toBe("Choose l, i or n: ");
    expect(r.asked[1]).toBe("Invite link or code: ");
    // The same "who made it, what it joins" confirmation as `p2p join`.
    expect(r.asked[2]).toMatch(/alice@[\s\S]*Join\? \[y\/N\] $/);
    // No relay question: the code carries the relay.
    expect(r.asked).not.toContain("Relay URL (wss://…): ");
    const b = r.asked.indexOf("Choose f, p or s: ");
    expect(b).toBeGreaterThan(1);
    expect(r.before(b)).toMatch(/Created bob@/);
    expect(r.out).toMatch(/You and alice@\S+ are friends/);
    expect(r.out).toContain(`relays  ${R}`);
    expect(r.err).toContain("no backup yet");
  });

  it("[n] asks for the group's relay (refusing anything but wss://), then creates the identity, then asks about the backup", async () => {
    const f = fresh();
    const r = await runAt(f.env, ["setup", "--name", "nora"], ["n", "https://relay.example", "ws://relay.example", R, "s", ""]);
    expect(r.code, r.err).toBe(0);
    expect(r.asked.slice(0, 5)).toEqual(["Choose l, i or n: ", "Relay URL (wss://…): ", "Relay URL (wss://…): ", "Relay URL (wss://…): ", "Choose f, p or s: "]);
    expect(r.err.match(/A relay URL starts with wss:\/\//g)).toHaveLength(2);
    // The backup question comes only after the identity exists.
    expect(r.before(4)).toMatch(/Created nora@/);
    expect(r.before(1)).toContain("no default relay");
    expect(r.out).toContain(`relays  ${R}`);
  });

  it("[n] with a relay already given (--relay, P2P_DEFAULT_RELAYS) asks no relay; a bare host means wss://", async () => {
    const f = fresh({ P2P_DEFAULT_RELAYS: R });
    const r = await runAt(f.env, ["setup", "--name", "nell"], ["n", "s", ""]);
    expect(r.code, r.err).toBe(0);
    expect(r.asked.slice(0, 2)).toEqual(["Choose l, i or n: ", "Choose f, p or s: "]);

    const g = fresh();
    const seen: string[][] = [];
    const setup = async (_a: unknown, o: { relays?: string[] }) => {
      seen.push(o.relays ?? []);
      return { created: true, address: "x@y", relays: o.relays ?? [], userId: "u", did: "d", fingerprint: "f" };
    };
    const b = await runAt(g.env, ["setup", "--no-backup"], ["n", "relay.example.org"], { ops: { setup } });
    expect(b.code, b.err).toBe(0);
    expect(seen).toEqual([["wss://relay.example.org/v3"]]);
  });

  it("the backup question is never asked when no identity gets made (cancelled, or no relay)", async () => {
    const f = fresh();
    const r = await runAt(f.env, ["setup"], ["n", "", "", ""]);
    expect(r.code).toBe(1);
    expect(r.asked).not.toContain("Choose f, p or s: ");
    expect(await hasIdentity(f.home)).toBe(false);
    const g = fresh();
    const x = await runAt(g.env, ["setup"], ["x", "y", "z"]);
    expect(x.code).toBe(1);
    expect(x.err).toContain("cancelled");
    expect(x.asked).toEqual(["Choose l, i or n: ", "Choose l, i or n: ", "Choose l, i or n: "]);
  });

  it("an agent's session is never asked: no relay → the no_relays error naming all three ways, and nothing is made", async () => {
    const f = fresh({ CLAUDECODE: "1" });
    let linked = false;
    const r = await runAt(f.env, ["setup"], ["l", "p2p-link:x@y", "f"], { front: false, ops: { linkJoin: async () => ((linked = true), undefined) } });
    expect(r.code).toBe(1);
    expect(r.asked).toEqual([]);
    expect(linked).toBe(false);
    expect(r.err).toContain("no_relays");
    expect(r.err).toContain("link start");
    expect(r.err).toContain("join <invite link or code>");
    expect(r.err).toContain("--relay wss://");
    expect(await hasIdentity(f.home)).toBe(false);
  });

  it("--json, CI and no terminal are unchanged: never asked; no relay → the same no_relays error", async () => {
    for (const [env, argv, answers] of [
      [fresh().env, ["setup", "--json"], ["l"]],
      [fresh({ CI: "1" }).env, ["setup"], ["l"]],
      [fresh().env, ["setup"], null],
    ] as const) {
      const r = await runAt(env, [...argv], answers ? [...answers] : null);
      expect(r.code).toBe(1);
      expect(r.asked).toEqual([]);
      expect(r.transcript).toContain("no_relays");
      expect(r.transcript).toContain("link join <code>");
    }
    // With a relay, a script's setup still just creates the identity.
    const g = fresh({ P2P_DEFAULT_RELAYS: R });
    const ok = await runAt(g.env, ["setup", "--json", "--name", "scr", "--no-backup"], ["l"]);
    expect(ok.code, ok.err).toBe(0);
    expect(ok.asked).toEqual([]);
    expect(JSON.parse(ok.out.split("\n").at(-1) ?? "{}")).toMatchObject({ created: true, relays: [R] });
  });

  it("an existing identity: nothing is asked about joining", async () => {
    const f = fresh({ P2P_DEFAULT_RELAYS: R });
    expect((await runAt(f.env, ["setup", "--name", "eve", "--no-backup", "--json"], null)).code).toBe(0);
    const r = await runAt(f.env, ["setup"], ["l", ""]);
    expect(r.code, r.err).toBe(0);
    expect(r.asked).not.toContain("Choose l, i or n: ");
    expect(r.out).toContain("Already set up: eve@");
  });
});
