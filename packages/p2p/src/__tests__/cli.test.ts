// Copyright 2026 Ix Infrastructure Inc.
//
// Argument parsing and the --json / exit-code contract, with the command
// functions replaced by fakes (no stores, no relays).

import { afterEach, describe, expect, it, vi } from "vitest";
import type { App, Io } from "../app.js";
import { main, type Ops } from "../cli.js";
import { CliError } from "../errors.js";

function stubApp(): App {
  return {
    keys: undefined,
    load: async () => true,
    close: async () => {},
    connect: async () => ({ drain: async () => {} }),
    connectAndDrain: async () => ({}),
    addressOf: async (u: string) => `addr(${u})`,
  } as unknown as App;
}

async function run(argv: string[], ops: Partial<Ops>, io: Partial<Io> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const code = await main(argv, {
    env: {},
    io: { out: (s) => out.push(s), err: (s) => err.push(s), ...io },
    ops,
    makeApp: () => stubApp(),
    // The person's "yes" on their terminal (tty-confirm.ts), for the commands that widen sharing.
    confirmTty: async () => true,
  });
  process.exitCode = 0;
  let json: any;
  try {
    json = JSON.parse(out.at(-1) ?? "");
  } catch {
    json = undefined;
  }
  return { code, out, err, json };
}

afterEach(() => {
  process.exitCode = 0;
});

describe("p2p argument parsing", () => {
  it("send joins positional words, and reads stdin when there are none", async () => {
    const sendMessage = vi.fn(async (_a: App, o: { text: string; to: string; fromSession: string; notifyWhenIdle?: boolean }) => ({
      delivered: true,
      to: { userId: "u", address: "a", own: "u", sid: "s", ref: "abcdef" },
      relays: 2,
      devices: 1,
      echo: o,
    }));
    const r = await run(["send", "--from-session", "s1", "--to", "bob", "hello", "there", "--json"], { sendMessage } as never);
    expect(r.code).toBe(0);
    expect(sendMessage.mock.calls[0][1]).toEqual({ fromSession: "s1", to: "bob", text: "hello there", notifyWhenIdle: undefined });
    expect(r.json.relays).toBe(2);
    await run(["send", "--from-session", "s1", "--to", "bob", "--notify-when-idle"], { sendMessage } as never, { readStdin: async () => "unused" });
    expect(sendMessage.mock.calls[1][1]).toMatchObject({ text: "", notifyWhenIdle: true });
    await run(["send", "--from-session", "s1", "--to", "bob"], { sendMessage } as never, { readStdin: async () => "from stdin\n" });
    expect(sendMessage.mock.calls[2][1].text).toBe("from stdin");
  });

  it("status takes repeatable --file and validates --state", async () => {
    const sendStatus = vi.fn(async () => ({ status: { state: "busy", label: "x" }, roster: { sid: "s", ref: "abcdef", ver: 1, vis: "private", parts: [] }, delivered: [], failed: [] }));
    const r = await run(["status", "--session", "s1", "--state", "busy", "--file", "a.ts", "--file", "b/c.ts", "--summary", "hi", "--json"], { sendStatus } as never);
    expect(r.code).toBe(0);
    expect((sendStatus.mock.calls[0] as unknown[])[1]).toMatchObject({ session: "s1", state: "busy", files: ["a.ts", "b/c.ts"], summary: "hi" });
    const bad = await run(["status", "--session", "s1", "--state", "sleeping"], { sendStatus } as never);
    expect(bad.code).toBe(1);
    const missing = await run(["status", "--state", "idle"], { sendStatus } as never);
    expect(missing.code).toBe(1);
    expect(sendStatus).toHaveBeenCalledTimes(1);
  });

  it("--json failures print {error, reason} and exit 1", async () => {
    const accept = vi.fn(async () => {
      throw new CliError("undelivered", "delivered via 0 relays", { delivered: false });
    });
    const r = await run(["accept", "p2p://invite/x", "--json"], { accept } as never);
    expect(r.code).toBe(1);
    expect(r.json).toEqual({ error: "undelivered", reason: "delivered via 0 relays", delivered: false });
    const h = await run(["accept", "p2p://invite/x"], { accept } as never);
    expect(h.code).toBe(1);
    expect(h.out).toEqual([]);
    expect(h.err.join("\n")).toMatch(/p2p: undelivered: delivered via 0 relays/);
  });

  it("init refuses to run without a terminal unless --yes", async () => {
    const init = vi.fn(async () => ({ userId: "u", address: "a@b", fingerprint: "f", did: "d", relays: ["wss://r/v3"], published: ["wss://r/v3"], failed: [] }));
    const r = await run(["init", "--json"], { init } as never);
    expect(r.code).toBe(1);
    expect(r.json.error).toBe("usage");
    const ok = await run(["init", "--yes", "--name", "carol", "--relay", "wss://a/v3", "--relay", "wss://b/v3", "--json"], { init } as never);
    expect(ok.code).toBe(0);
    expect(init.mock.calls[0]).toEqual([expect.anything(), { name: "carol", relays: ["wss://a/v3", "wss://b/v3"] }]);
    expect(ok.err.join("")).toMatch(/warning: Only this device holds your identity key/);
    expect(ok.json.backupShown).toBe(false);
  });

  it("subcommands get their own --json (positional options)", async () => {
    const revokeDevice = vi.fn(async (_a: App, did: string) => ({ revoked: did, ver: 3, capsReissued: 0, rejoined: [] }));
    const devices = vi.fn(async () => []);
    const r = await run(["devices", "revoke", "d_abc", "--json"], { revokeDevice, devices } as never);
    expect(r.json).toEqual({ revoked: "d_abc", ver: 3, capsReissued: 0, rejoined: [] });
    expect(devices).not.toHaveBeenCalled();
    const l = await run(["devices", "--json"], { revokeDevice, devices } as never);
    expect(l.json).toEqual({ devices: [] });
  });

  it("circle commands pass their arguments through", async () => {
    const propose = vi.fn(async (_a: App, cid: string, op: string, arg: string) => ({ cid, op, applied: true, ver: 4, arg }));
    const r = await run(["circle", "propose", "c_x", "rename", "new name", "--json"], { propose } as never);
    expect(propose.mock.calls[0].slice(1)).toEqual(["c_x", "rename", "new name"]);
    expect(r.json.ver).toBe(4);
    const joinFromLink = vi.fn(async () => ({ status: "waiting", cid: "c", name: "n", owner: "o", ownerAddress: "o", founder: "o", ownershipChanged: false, policy: "open", asked: ["o"], answered: [] }));
    const j = await run(["circle", "join", "p2p://circle/x", "--wait", "0", "--json"], { joinFromLink } as never);
    expect(j.code).toBe(0);
    expect((joinFromLink.mock.calls[0] as unknown[])[2]).toMatchObject({ waitSec: 0 });
    const circleLink = vi.fn(async () => ({ cid: "c", link: "p2p://circle/x", web: "https://ix-infra.com/p2p/c#x", policy: "invite" }));
    const inv = await run(["circle", "invite", "c", "--link", "--json"], { circleLink } as never);
    expect(inv.json.link).toBe("p2p://circle/x");
    const noTarget = await run(["circle", "invite", "c", "--json"], { circleLink } as never);
    expect(noTarget.json.error).toBe("usage");
  });

  it("session roster collects --add/--remove", async () => {
    const roster = vi.fn(async () => ({ sid: "s", ref: "abcdef", ver: 2, vis: "private", parts: [] }));
    await run(["session", "roster", "s1", "--add", "a", "--add", "b", "--remove", "c", "--private", "--json"], { roster } as never);
    expect((roster.mock.calls[0] as unknown[]).slice(1)).toEqual(["s1", { add: ["a", "b"], remove: ["c"], private: true, json: true }]);
  });

  it("petname needs a name or --clear; watch needs a valid session", async () => {
    const petname = vi.fn(async () => ({ userId: "u", petname: null, address: "a" }));
    expect((await run(["petname", "bob", "--json"], { petname } as never)).json.error).toBe("usage");
    await run(["petname", "bob", "--clear", "--json"], { petname } as never);
    expect((petname.mock.calls[0] as unknown[])[2]).toBeUndefined();
    const watch = vi.fn(async () => 0);
    const w = await run(["watch", "--session", "bad id!", "--jsonl"], { watch } as never);
    expect(w.code).toBe(1);
    expect(w.err.join("")).toMatch(/p2p watch: usage/);
    expect(watch).not.toHaveBeenCalled();
  });

  it("unknown commands and --help exit as expected", async () => {
    expect((await run(["frobnicate"], {})).code).toBe(1);
    expect((await run(["--help"], {})).code).toBe(0);
    expect((await run(["--version"], {})).code).toBe(0);
  });
});

describe("p2p identity rotate (§2.8)", () => {
  const result = { from: "p2p:old", to: "p2p:new", address: "sam@x", fingerprint: "x", did: "d_n", step: "done", devices: { followed: [], offline: [], excluded: [] }, friends: { invited: 0, failed: [] }, circles: [], proofs: [], warnings: [] };

  it("passes its options; needs --yes without a terminal; the plan never goes to stdout with --json", async () => {
    const rotate = vi.fn(async (_a: App, o: Record<string, unknown>) => {
      if (!o.yes && o.confirm) await (o.confirm as (p: unknown) => Promise<boolean>)({ from: "p2p:old", address: "sam@x", follow: [], excluded: [], friends: 0, owned: 0, memberOf: 0 });
      return result;
    });
    const r = await run(["identity", "rotate", "--yes", "--exclude", "d_lost", "--exclude", "d_gone", "--keep-keyholders", "--wait", "5", "--backup-file", "--json"], { rotate } as never);
    expect(r.code).toBe(0);
    expect(rotate.mock.calls[0][1]).toMatchObject({ yes: true, exclude: ["d_lost", "d_gone"], keepKeyholders: true, waitSec: 5, backupFileDefault: true });
    await run(["identity", "rotate", "--resume", "--backup-file", "/tmp/x.txt", "--json"], { rotate } as never);
    expect(rotate.mock.calls[1][1]).toMatchObject({ resume: true, backupFile: "/tmp/x.txt" });
    await run(["identity", "rotate", "--resume", "--yes", "--invite", "p2p:mal", "--invite", "pat", "--keep", "d_tab", "--json"], { rotate } as never);
    expect(rotate.mock.calls[2][1]).toMatchObject({ invite: ["p2p:mal", "pat"], keep: ["d_tab"] });
    // Without a terminal, no confirmation is offered: rotate then refuses to go past the plan (needs_confirmation).
    await run(["identity", "rotate", "--json"], { rotate } as never);
    expect(rotate.mock.calls[3][1].confirm).toBeUndefined();
    expect(rotate.mock.calls[3][1].yes).toBeUndefined();
    const asked = await run(["identity", "rotate", "--json"], { rotate } as never, { prompt: async () => "y" });
    expect(asked.code).toBe(0);
    expect(asked.out).toHaveLength(1);
    expect(asked.err.join("\n")).toContain("Rotating sam@x");
  });

  it("--plan, --cancel, --resend and --contest go to their operations", async () => {
    const plan = { from: "p2p:old", address: "sam@x", to: "p2p:new", newFingerprint: "dddd-dddd-dddd-dddd", follow: [{ did: "d_a", label: "laptop", keyholder: false }], excluded: [], friends: 1, owned: 0, memberOf: 0, contest: false };
    const rotatePlan = vi.fn(async (_a: App, _o: Record<string, unknown>) => plan);
    const rotateCancel = vi.fn(async () => ({ cancelled: true, to: "p2p:new" }));
    const rotateResend = vi.fn(async () => ({ sent: 2, failed: [], remaining: 0, throttled: false }));
    const rotate = vi.fn(async (_a: App, _o: Record<string, unknown>) => ({ from: "p2p:old", to: "p2p:new", address: "sam@x", fingerprint: "x", did: "d", step: "done", contest: true, devices: { followed: [], offline: [], excluded: [] }, friends: { invited: 0, failed: [] }, circles: [], proofs: [], warnings: [] }));
    const ops = { rotatePlan, rotateCancel, rotateResend, rotate } as never;
    const p = await run(["identity", "rotate", "--plan", "--exclude", "d_a", "--backup-file", "--json"], ops);
    expect(p.json).toMatchObject({ plan: true, newFingerprint: "dddd-dddd-dddd-dddd" });
    expect(rotatePlan.mock.calls[0][1]).toMatchObject({ exclude: ["d_a"], backupFileDefault: true });
    expect((await run(["identity", "rotate", "--cancel", "--json"], ops)).json).toEqual({ cancelled: true, to: "p2p:new" });
    expect((await run(["identity", "rotate", "--resend", "--json"], ops)).json.sent).toBe(2);
    await run(["identity", "rotate", "--contest", "--yes", "--json"], ops);
    expect(rotate.mock.calls[0][1]).toMatchObject({ contest: true, yes: true });
  });

  it("identity follow and circle hold", async () => {
    const followHeld = vi.fn(async (_a: App, _id: string) => ({ userId: "p2p:new", address: "sam@x", did: "d_n", from: "p2p:old", keyholder: false }));
    const setCircleHold = vi.fn(async (_a: App, cid: string, on: boolean | undefined) => ({ cid, hold: on ?? false }));
    expect((await run(["identity", "follow", "f0000000000000001", "--json"], { followHeld } as never)).json.userId).toBe("p2p:new");
    expect(followHeld.mock.calls[0][1]).toBe("f0000000000000001");
    expect((await run(["circle", "hold", "c_x", "on", "--json"], { setCircleHold } as never)).json).toEqual({ cid: "c_x", hold: true });
    expect((await run(["circle", "hold", "c_x", "maybe", "--json"], { setCircleHold } as never)).json.error).toBe("usage");
  });

  it("link join --rotated goes to the re-link path", async () => {
    const relinkRotated = vi.fn(async () => ({ compareCode: "abcd", did: "d_x", wait: async () => ({ userId: "p2p:new", address: "sam@x", did: "d_x", keyholder: false, from: "p2p:old" }) }));
    const linkJoin = vi.fn();
    const r = await run(["link", "join", "p2p-link:x@relay", "--rotated", "--json"], { relinkRotated, linkJoin } as never);
    expect(r.code).toBe(0);
    expect(relinkRotated).toHaveBeenCalledTimes(1);
    expect(linkJoin).not.toHaveBeenCalled();
  });
});
