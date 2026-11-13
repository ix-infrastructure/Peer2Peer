// Copyright 2026 Ix Infrastructure Inc.
//
// `p2p setup` at a person's terminal asks how they're joining before any key is made: link this
// device to an identity they already have (`link join`, inline), redeem an invite (`join`,
// inline), or start a new identity (on their group's relay: there is no default relay). The
// backup question comes only once an identity exists. Scripts, --json, CI and agents see the old
// behaviour, with a no_relays error that names all three ways in.

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Io } from "../app.js";
import { main } from "../cli.js";
import { linkJoin, linkStart, noRelaysReason, p2pCommand } from "../identity.js";
import { App } from "../app.js";
import { personTokenOk } from "../projects.js";
import { alongside, startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-setup-onboarding.test/v3";
// A relay on a private address (as a team relay on a LAN or Tailscale would be), served by a local test relay.
const RP = "wss://10.0.0.5:8443/v3";
// More relays for the link tests: a relay rate-limits link mailboxes per address.
const RL = ["wss://relay-setup-link-1.test/v3", "wss://relay-setup-link-2.test/v3", "wss://relay-setup-link-3.test/v3"];

describe("p2p setup: how are you joining?", () => {
  let relay: TestRelay;
  let rp: TestRelay;
  const rl: TestRelay[] = [];
  let tr: Record<string, string>;
  const users: User[] = [];
  const dirs: string[] = [];
  beforeAll(async () => {
    relay = await startRelay(R);
    rp = await startRelay(RP);
    tr = { [R]: `ws://127.0.0.1:${relay.port}/v3`, [RP]: `ws://127.0.0.1:${rp.port}/v3` };
    for (const u of RL) {
      const t = await startRelay(u);
      rl.push(t);
      tr[u] = `ws://127.0.0.1:${t.port}/v3`;
    }
  }, 30_000);
  afterAll(async () => {
    await relay?.close();
    await rp?.close();
    for (const t of rl) await t.close();
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
    let confirmed: unknown;
    const linkJoin = async (_app: unknown, code: string) => {
      calls.push(code);
      return {
        compareCode: "tiger-maple-42",
        did: "did:p2p:dev",
        wait: async (confirm: unknown) => ((confirmed = confirm), { address: "ana@abcd", did: "did:p2p:dev", keyholder: false }),
      };
    };
    const init = async () => {
      throw new Error("init must not run on the link path");
    };
    const r = await runAt(f.env, ["setup"], ["l", "  p2p-link:SECRET@relay.example  "], { ops: { linkJoin, init } });
    expect(r.code, r.err).toBe(0);
    expect(calls).toEqual(["p2p-link:SECRET@relay.example"]);
    // The identity is confirmed before anything is kept.
    expect(typeof confirmed).toBe("function");
    expect(r.before(1)).toContain("Only type a code shown on YOUR OWN other device. A code from anyone else makes this device theirs.");
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
  /** A key-holding user whose device shows a link code (`p2p link start`), answering the new device with `yes`. */
  async function linkFrom(relayUrl = R) {
    const alice = new User("alice", tr, { P2P_DEFAULT_RELAYS: relayUrl });
    users.push(alice);
    const me = await alice.ok(["setup", "--name", "alice", "--no-backup"]);
    const a = await alice.app();
    await a.load(true);
    const start = await linkStart(a, {});
    return { alice, me, start, done: start.wait(async () => true).finally(() => a.close()) };
  }

  it("[l] with a real link: the identity is shown (address and fingerprint) and kept only on the person's terminal yes", async () => {
    const { me, start, done } = await linkFrom();
    const f = fresh();
    const asked: string[] = [];
    const r = await runAt(f.env, ["setup"], ["l", start.code], { confirmTty: async (q) => (asked.push(q), true) });
    await done;
    expect(r.code, r.err).toBe(0);
    // The gate (no identity here yet, so even a front end's token doesn't stand in), then the identity.
    expect(asked[0]).toBe("p2p link join changes who reaches you.");
    expect(asked).toHaveLength(2);
    expect(asked[1]).toContain(`This device would become ${me.address} (fingerprint ${me.fingerprint})`);
    expect(asked[1]).toContain("Is this your identity?");
    expect(r.out).toContain(`This device is now ${me.address}`);
    expect(await hasIdentity(f.home)).toBe(true);
  });

  it("[l]: a no to 'Is this your identity?' keeps nothing on this device", async () => {
    const { start, done } = await linkFrom(RL[2]);
    const f = fresh();
    const r = await runAt(f.env, ["setup"], ["l", start.code], { confirmTty: async (q) => !q.includes("Is this your identity?") });
    await done;
    expect(r.code).toBe(1);
    expect(r.err).toContain("link_declined");
    expect(r.err).toContain("nothing was kept on this device");
    expect(await hasIdentity(f.home)).toBe(false);
  });

  it("`p2p link join` asks the same: a no keeps nothing; --expect-fingerprint lets a script name the identity it expects", async () => {
    const one = await linkFrom();
    const f = fresh();
    const asked: string[] = [];
    const no = await runAt(f.env, ["link", "join", one.start.code], null, { confirmTty: async (q) => (asked.push(q), !q.includes("Is this your identity?")) });
    await one.done;
    expect(no.code).toBe(1);
    expect(asked.at(-1)).toContain(`fingerprint ${one.me.fingerprint}`);
    expect(no.err).toContain("link_declined");
    expect(await hasIdentity(f.home)).toBe(false);

    const two = await linkFrom(RL[0]);
    const g = fresh();
    const wrong = await runAt(g.env, ["link", "join", two.start.code, "--expect-fingerprint", "aaaa-bbbb-cccc-dddd", "--json"], null, { confirmTty: async () => true });
    await two.done;
    expect(wrong.code).toBe(1);
    expect(wrong.out).toContain("link_declined");
    expect(await hasIdentity(g.home)).toBe(false);

    const three = await linkFrom(RL[1]);
    const h = fresh();
    const right = await runAt(h.env, ["link", "join", three.start.code, "--expect-fingerprint", three.me.fingerprint, "--json"], null, { confirmTty: async (q) => q.startsWith("p2p link join ") });
    await three.done;
    expect(right.code, right.err).toBe(0);
    expect(await hasIdentity(h.home)).toBe(true);
  });

  it("[l] says which options linking ignores", async () => {
    const f = fresh();
    const r = await runAt(f.env, ["setup", "--name", "x", "--print-backup"], ["l", "not-a-link-code"]);
    expect(r.code).toBe(1);
    expect(r.out).toContain("(--name, --print-backup are ignored when linking");
  });

  it("an invite pasted at [l] is joined as an invite (with its own confirmation); a link code pasted at [i] is refused", async () => {
    const alice = new User("alice", tr, { P2P_DEFAULT_RELAYS: R });
    users.push(alice);
    await alice.ok(["setup", "--name", "alice", "--no-backup"]);
    const inv = await alice.ok(["invite", "--no-circle"]);
    const f = fresh();
    const r = await alongside(runAt(f.env, ["setup", "--name", "bea"], ["l", inv.code, "y", "s", ""]), () => alice.ok(["invites"]));
    expect(r.code, r.err).toBe(0);
    expect(r.err).toContain("That is an invite from someone, not a link code from your own device");
    expect(r.asked[2]).toMatch(/Join\? \[y\/N\] $/);
    expect(r.out).toMatch(/You and alice@\S+ are friends/);

    const g = fresh();
    const x = await runAt(g.env, ["setup"], ["i", `p2p-link:${"a".repeat(26)}@relay.example/v3`]);
    expect(x.code).toBe(1);
    expect(x.err).toContain("that is a device link code, not an invite");
    expect(x.err).toContain("one from anyone else makes this device theirs");
    expect(await hasIdentity(g.home)).toBe(false);
  });

  it("[i] through the real gate: without a front end's token, the terminal yes lets it join", async () => {
    const alice = new User("alice", tr, { P2P_DEFAULT_RELAYS: R });
    users.push(alice);
    await alice.ok(["setup", "--name", "alice", "--no-backup"]);
    const inv = await alice.ok(["invite", "--no-circle"]);
    const f = fresh();
    const gate: string[] = [];
    const r = await alongside(runAt(f.env, ["setup", "--name", "cal"], ["i", inv.code, "y", "s", ""], { front: false, confirmTty: async (q) => (gate.push(q), true) }), () => alice.ok(["invites"]));
    expect(r.code, r.err).toBe(0);
    expect(gate).toEqual(["p2p join changes who reaches you."]);
    expect(r.out).toMatch(/You and alice@\S+ are friends/);
    // Created by the join, then the backup hint and the question.
    expect(r.err).toContain("save a backup with `p2p backup show`");
  });

  it("[i] with an invite on a private-address relay: refused with how to opt in (setup --allow-private-relay), which then joins", async () => {
    const alice = new User("alice", tr, { P2P_DEFAULT_RELAYS: RP });
    users.push(alice);
    await alice.ok(["setup", "--name", "alice", "--no-backup"]);
    const inv = await alice.ok(["invite", "--no-circle"]);
    const f = fresh();
    const no = await runAt(f.env, ["setup"], ["i", inv.code]);
    expect(no.code).toBe(1);
    expect(no.err).toContain("private_relay");
    expect(no.err).toContain("--allow-private-relay");
    expect(await hasIdentity(f.home)).toBe(false);
    const yes = await alongside(runAt(f.env, ["setup", "--allow-private-relay", "--name", "dee"], ["i", inv.code, "y", "s", ""]), () => alice.ok(["invites"]));
    expect(yes.code, yes.err).toBe(0);
    expect(yes.out).toMatch(/You and alice@\S+ are friends/);
  });

  it("a link code on a private-address relay is refused before anything connects, unless the person opts in or it is their own relay", async () => {
    const code = `p2p-link:${"a".repeat(26)}@10.0.0.5:8443/v3`;
    const f = fresh();
    const app = new App({ env: f.env, io: { out: () => {}, err: () => {} } });
    try {
      await expect(linkJoin(app, code)).rejects.toMatchObject({ code: "private_relay" });
    } finally {
      await app.close();
    }
    // Opted in, or the person's own relay: it connects (and the relay answers: no such link mailbox).
    for (const env of [{ ...f.env, P2P_ALLOW_PRIVATE_RELAY: "1" }, { ...f.env, P2P_DEFAULT_RELAYS: RP }]) {
      const a = new App({ env, io: { out: () => {}, err: () => {} } });
      try {
        await expect(linkJoin(a, code)).rejects.toMatchObject({ code: "link_failed" });
      } finally {
        await a.close();
      }
    }
    expect(await hasIdentity(f.home)).toBe(false);
  });

  it("on a home with no identity, a person token doesn't stand in for the person on link join or setup's link and join", async () => {
    // A person.key planted on a fresh home, and the matching token.
    const f = fresh();
    const token = "A".repeat(43);
    mkdirSync(join(f.home, "cli"), { recursive: true });
    writeFileSync(join(f.home, "cli", "person.key"), token, { mode: 0o600 });
    expect(personTokenOk({ P2P_PERSON_TOKEN: token }, f.home)).toBe(true);
    const run = async (argv: string[], env: Record<string, string>, answers: string[] | null) => {
      const gate: string[] = [];
      let used = false;
      const lines: string[] = [];
      const code = await main(argv, {
        env: { ...f.env, P2P_PERSON_TOKEN: token, ...env },
        io: { out: (s) => lines.push(s), err: (s) => lines.push(s), ...(answers ? { prompt: async () => answers.shift() ?? "" } : {}) },
        confirmTty: async (q) => (gate.push(q), false),
        ops: { linkJoin: async () => ((used = true), undefined), joinCode: async () => ((used = true), undefined) } as never,
      });
      process.exitCode = 0;
      return { code, gate, used, text: lines.join("\n") };
    };
    const linkCode = `p2p-link:${"a".repeat(26)}@relay.example/v3`;
    // Inside an agent's session: refused outright.
    const agent = await run(["link", "join", linkCode], { CLAUDECODE: "1" }, null);
    expect(agent.code).toBe(1);
    expect(agent.text).toContain("only you run it");
    expect(agent.used).toBe(false);
    // Anywhere else: the person's terminal yes is asked (here: no).
    for (const [argv, answers, what] of [
      [["link", "join", linkCode], null, "p2p link join changes who reaches you."],
      [["setup"], ["l", linkCode], "p2p link join changes who reaches you."],
      [["setup"], ["i", "relay.example/K7QM-3XPD-9TWA-HF2N-6RJC"], "p2p join changes who reaches you."],
    ] as const) {
      const r = await run([...argv], {}, answers ? [...answers] : null);
      expect(r.code, r.text).toBe(1);
      expect(r.gate).toEqual([what]);
      expect(r.used).toBe(false);
    }
    expect(await hasIdentity(f.home)).toBe(false);
  });

  it("the no-backup warning comes whenever this device is the only key holder and the phrase was never shown", async () => {
    const f = fresh({ P2P_DEFAULT_RELAYS: R });
    const first = await runAt(f.env, ["setup", "--name", "solo", "--no-backup"], null);
    expect(first.code, first.err).toBe(0);
    expect(first.err).toContain("warning: no backup yet");
    // Not just when it was created: every setup until the phrase is shown.
    const again = await runAt(f.env, ["setup"], null);
    expect(again.err).toContain("warning: no backup yet");
    expect((await runAt(f.env, ["backup", "show"], null)).code).toBe(0);
    const after = await runAt(f.env, ["setup"], null);
    expect(after.err).not.toContain("no backup yet");
  });
});
