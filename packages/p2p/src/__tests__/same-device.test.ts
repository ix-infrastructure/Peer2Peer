// Copyright 2026 Ix Infrastructure Inc.
//
// Messages to a named session on this same device (roadmap #6 item 1): a local UI (or one agent
// session) can message another session of yours here. The message is sealed to this device and goes
// through a relay like one to your other devices, so every receive-side check applies as it does for
// those: the envelope's signature and replay window, the receiving session's roster, the project
// bound it carries (a private session's message makes the receiving session private), the
// agent-context rules on who may send as which session. A bare `--to <you>` never reaches this
// device's sessions, and a session can't message itself.

import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { main } from "../cli.js";
import { sessionRef } from "../sessions.js";
import { alongside, sleep, startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-same-device.test/v3";
let relay: TestRelay;
let ann: User;
let ben: User;
const ids: Record<string, string> = {};
let root: string;
const repo: Record<string, string> = {};
let team: string;

function gitRepo(dir: string, remote: string): string {
  mkdirSync(join(dir, ".git"), { recursive: true });
  writeFileSync(join(dir, ".git", "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(dir, ".git", "config"), `[core]\n\tbare = false\n[remote "origin"]\n\turl = ${remote}\n`);
  return dir;
}

/** `u` working in `dir` (P2P_WORKDIR, as the mod and the Codex bridge pass it). */
function inDir(u: User, dir: string, extra: Record<string, string> = {}): User {
  const v = Object.create(u) as User;
  Object.defineProperty(v, "env", { get: () => ({ ...u.env, P2P_WORKDIR: dir, ...extra }) });
  return v;
}

type Ev = { id: string; kind: string; toSession?: string; data: Record<string, any> };
async function events(u: User): Promise<Ev[]> {
  const app = await u.app();
  await app.load();
  try {
    return ((await app.state.get("events"))?.items ?? []) as Ev[];
  } finally {
    await app.close();
  }
}

/**
 * The p2p.message events for `sid` with `text`, after a drain (`ls`); a few drains, as a running
 * watch would keep handling deliveries (the sending command may have been handling the copy for
 * this device when it closed: the relay keeps it for the next one).
 */
async function got(u: User, sid: string, text: string): Promise<Ev[]> {
  for (let i = 0; ; i++) {
    await u.ok(["ls"]);
    const hits = (await events(u)).filter((e) => e.kind === "p2p.message" && e.toSession === sid && e.data.text === text);
    if (hits.length > 0 || i >= 10) return hits;
    await sleep(200);
  }
}

describe("same-device sends", () => {
  beforeAll(async () => {
    root = realpathSync(mkdtempSync(join(tmpdir(), "p2p-same-device-")));
    repo.S = gitRepo(join(root, "shared"), "git@github.com:acme/shared.git");
    repo.P = gitRepo(join(root, "secret"), "git@github.com:acme/secret.git");
    relay = await startRelay(R);
    const t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    ann = new User("ann", t);
    ben = new User("ben", t);
    for (const u of [ann, ben]) {
      u.autoShareProject = false;
      ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
    }
    team = (await ann.ok(["circle", "create", "team"])).cid;
    const inv = await ann.ok(["invite", "ben"]);
    const j = await alongside(ben.run(["join", "--confirmed", inv.code, "--wait", "12"]), () => ann.ok(["invites"]));
    expect(j.code).toBe(0);
    for (let i = 0; i < 10; i++) {
      await ann.ok(["invites"]);
      if ((await ben.ok(["circle", "ls"])).circles.some((c: { cid: string; joined?: boolean }) => c.cid === team && c.joined)) break;
    }
    await inDir(ann, repo.S).ok(["project", "share", team, "--person", ids.ben]);
    // Ben's live session, shared back with ann.
    await ben.ok(["project", "share", "--add", "--person", ids.ann]);
    await ben.ok(["status", "--session", "bs1", "--state", "idle", "--label", "ben"]);
    // Two of ann's sessions on the one device, both in the shared project.
    for (const sid of ["s1", "s2"]) await inDir(ann, repo.S).ok(["status", "--session", sid, "--state", "idle", "--label", sid, "--cap", "receipts.v1"]);
  }, 120_000);

  afterAll(async () => {
    await relay?.close().catch(() => {});
    ann?.cleanup();
    ben?.cleanup();
    rmSync(root, { recursive: true, force: true });
  });

  it("two sessions on one device message each other both ways, by /sid or [ref]", async () => {
    const a = await inDir(ann, repo.S).ok(["send", "--from-session", "s1", "--to", `${ids.ann}/s2`, "--stdin"], { stdin: "s1 to s2" });
    expect(a).toMatchObject({ delivered: true, to: { own: ids.ann, sid: "s2", ref: sessionRef(ids.ann, "s2") }, devices: 1 });
    const inS2 = await got(ann, "s2", "s1 to s2");
    expect(inS2).toHaveLength(1);
    expect(inS2[0].data.from).toMatchObject({ userId: ids.ann, self: true });
    // Where it came from, from this device's own record (nothing on the wire): an agent session, s1.
    expect(inS2[0].data).toMatchObject({ own: ids.ann, sid: "s2", via: "agent", fromRef: sessionRef(ids.ann, "s1") });
    // Only the ref: never the sending session's id, never a stamp of the own-agents setting.
    expect(inS2[0].data.fromSid).toBeUndefined();
    expect(inS2[0].data.ownTrusted).toBeUndefined();
    const b = await inDir(ann, repo.S).ok(["send", "--from-session", "s2", "--to", `${ids.ann} [${sessionRef(ids.ann, "s1")}]`, "--stdin"], { stdin: "s2 back to s1" });
    expect(b).toMatchObject({ delivered: true, to: { sid: "s1" } });
    expect(await got(ann, "s1", "s2 back to s1")).toHaveLength(1);
    // Nobody else saw either message.
    await ben.ok(["ls"]);
    expect(JSON.stringify(await events(ben))).not.toMatch(/s1 to s2|s2 back to s1/);
  });

  it("the person's own terminal session (tui) reaches a named session here too", async () => {
    // `p2p send` typed at a terminal with no --from-session (a picker and a prompt make it one).
    const out: string[] = [];
    const err: string[] = [];
    const code = await main(["send", "--to", `${ids.ann}/s2`, "from the terminal"], { env: inDir(ann, repo.S).env, io: { out: (l) => out.push(l), err: (l) => err.push(l), select: async () => [], prompt: async () => "" } });
    process.exitCode = 0;
    expect(code, err.join("\n")).toBe(0);
    expect(out.join("\n")).toMatch(new RegExp(`Sent to .*\\[${sessionRef(ids.ann, "s2")}\\]: delivered via 1 relay`));
    const [ev] = await got(ann, "s2", "from the terminal");
    // The person's own terminal: `via: "person"`, the one own-session origin an auto-approving session delivers.
    expect(ev?.data).toMatchObject({ via: "person", fromRef: sessionRef(ids.ann, "tui") });
  });

  it("a bare --to <you> never fans out to this device's sessions: it goes where it went before", async () => {
    // No other device and no session named: as before, into the sending session for your other
    // devices, of which there are none here. Neither s2 nor any other session here gets it.
    const r = await inDir(ann, repo.S).run(["send", "--from-session", "s1", "--to", ids.ann, "--stdin"], { stdin: "bare self" });
    expect(r.json).toMatchObject({ error: "undelivered", to: { own: ids.ann, sid: "s1" } });
    await ann.ok(["ls"]);
    expect((await events(ann)).filter((e) => e.data.text === "bare self")).toEqual([]);
  });

  it("a session can't message itself, by /sid or [ref]", async () => {
    for (const to of [`${ids.ann}/s1`, `${ids.ann} [${sessionRef(ids.ann, "s1")}]`]) {
      const r = await inDir(ann, repo.S).run(["send", "--from-session", "s1", "--to", to, "--stdin"], { stdin: "loop" });
      expect(r.code, to).toBe(1);
      expect(r.json, to).toMatchObject({ error: "self_send", delivered: false });
    }
    await ann.ok(["ls"]);
    expect((await events(ann)).some((e) => e.data.text === "loop")).toBe(false);
  });

  it("a session that isn't live, or never was, is refused as for any user", async () => {
    const r = await inDir(ann, repo.S).run(["send", "--from-session", "s1", "--to", `${ids.ann}/nobody`, "--stdin"], { stdin: "x" });
    expect(r.json).toMatchObject({ error: "not_found" });
  });

  it("a private project's session may message a shared one here, which then stays private: it can't carry it out", async () => {
    await inDir(ann, repo.P).ok(["status", "--session", "p1", "--state", "idle", "--label", "p1"]);
    await inDir(ann, repo.S).ok(["status", "--session", "s3", "--state", "idle", "--label", "s3"]);
    // s3 reaches ben before.
    expect((await inDir(ann, repo.S).ok(["send", "--from-session", "s3", "--to", `${ids.ben}/bs1`, "--stdin"], { stdin: "before" })).delivered).toBe(true);
    const sent = await inDir(ann, repo.P).ok(["send", "--from-session", "p1", "--to", `${ids.ann}/s3`, "--stdin"], { stdin: "the secret, to launder" });
    expect(sent.delivered).toBe(true);
    expect(await got(ann, "s3", "the secret, to launder")).toHaveLength(1);
    // The receiving session took the sender's bound: private now, for good.
    const after = await inDir(ann, repo.S).ok(["status", "--session", "s3", "--state", "idle", "--label", "s3"]);
    expect(after.roster.vis).toBe("private");
    expect(after.project.why).toMatch(/a private session of yours sent it a message/);
    const r = await inDir(ann, repo.S).run(["send", "--from-session", "s3", "--to", `${ids.ben}/bs1`, "--stdin"], { stdin: "laundered" });
    expect(r.json).toMatchObject({ error: "not_shared" });
    // The private session itself still reaches nobody outside, and ben can't name it.
    expect((await inDir(ann, repo.P).run(["send", "--from-session", "p1", "--to", `${ids.ben}/bs1`, "--stdin"], { stdin: "x" })).json).toMatchObject({ error: "not_shared" });
    expect((await ben.run(["send", "--from-session", "bs1", "--to", `${ids.ann}/p1`, "--stdin"], { stdin: "x" })).json).toMatchObject({ error: "not_found" });
    await ben.ok(["ls"]);
    expect(JSON.stringify(await events(ben))).not.toMatch(/secret, to launder|laundered/);
  });

  it("an agent sends only as its own registered session: never as tui, never as another session here", async () => {
    const agent = inDir(ann, repo.S, { P2P_PERSON_TOKEN: "", CLAUDECODE: "1" });
    for (const args of [
      ["send", "--from-session", "tui", "--to", `${ids.ann}/s2`, "--stdin"],
      // s1 is registered (its front end used the token): an agent's shell can't speak for it.
      ["send", "--from-session", "s1", "--to", `${ids.ann}/s2`, "--stdin"],
      // Nor make up a session to send from.
      ["send", "--from-session", "made-up", "--to", `${ids.ann}/s2`, "--stdin"],
    ]) {
      const r = await agent.run(args, { stdin: "smuggled" });
      expect(r.code, args.join(" ")).toBe(1);
      expect(["refused", "usage"], `${args.join(" ")}: ${r.out}`).toContain(r.json?.error);
    }
    // No --from-session (as the person) from inside an agent's session, even with a picker and a prompt.
    const err: string[] = [];
    const code = await main(["send", "--to", `${ids.ann}/s2`, "smuggled"], { env: agent.env, io: { out: () => {}, err: (l) => err.push(l), select: async () => [], prompt: async () => "smuggled" } });
    process.exitCode = 0;
    expect(code).toBe(1);
    expect(err.join("\n")).toMatch(/sends as you, from your own terminal/);
    await ann.ok(["ls"]);
    expect((await events(ann)).some((e) => e.data.text === "smuggled")).toBe(false);
  });

  it("receipts come back from a session here, private ones included (a held message says so)", async () => {
    await inDir(ann, repo.P).ok(["status", "--session", "p2", "--state", "idle", "--label", "p2", "--cap", "receipts.v1"]);
    const sent = await inDir(ann, repo.S).ok(["send", "--from-session", "s2", "--to", `${ids.ann}/p2`, "--stdin"], { stdin: "will be held" });
    expect(sent.receipts).toBe("requested");
    const [ev] = await got(ann, "p2", "will be held");
    expect(ev?.data.receipt).toBe(true);
    const r = await inDir(ann, repo.P).ok(["receipt", ev!.id, "--from-session", "p2", "--outcome", "held"]);
    expect(r).toMatchObject({ sent: true, outcome: "held" });
    let back: Ev[] = [];
    for (let i = 0; i < 10 && back.length === 0; i++) {
      await ann.ok(["ls"]);
      back = (await events(ann)).filter((e) => e.kind === "p2p.receipt" && e.data.receiptId === sent.receiptId);
      if (back.length === 0) await sleep(200);
    }
    expect(back).toHaveLength(1);
    expect(back[0]).toMatchObject({ toSession: "s2", data: { outcome: "held" } });
  });

  it("--notify-when-idle to a session here fires when it next goes busy → idle", async () => {
    await inDir(ann, repo.S).ok(["status", "--session", "s4", "--state", "busy", "--label", "s4"]);
    await inDir(ann, repo.S).ok(["send", "--from-session", "s1", "--to", `${ids.ann}/s4`, "--notify-when-idle"]);
    await inDir(ann, repo.S).ok(["status", "--session", "s4", "--state", "idle", "--label", "s4"]);
    const idle = (await events(ann)).filter((e) => e.kind === "p2p.idle" && e.toSession === "s1" && e.data.sid === "s4");
    expect(idle).toHaveLength(1);
    expect(idle[0].data).toMatchObject({ reason: "idle", from: { userId: ids.ann, self: true } });
  });

  it("L1: a receipt is reported only by the session's front end, never an agent's shell", async () => {
    const agent = inDir(ann, repo.S, { P2P_PERSON_TOKEN: "", CLAUDECODE: "1" });
    const r = await agent.run(["receipt", "p2p.message:whatever", "--from-session", "s2", "--outcome", "shown"]);
    expect(r.json).toMatchObject({ error: "refused" });
    // Outside an agent, without the token: a session a front end registered is still its alone.
    const script = inDir(ann, repo.S, { P2P_PERSON_TOKEN: "" });
    expect((await script.run(["receipt", "p2p.message:whatever", "--from-session", "s2", "--outcome", "shown"])).json).toMatchObject({ error: "refused" });
    // The front end (its token): goes on (nothing asked for this id, so nothing is sent).
    expect(await inDir(ann, repo.S).ok(["receipt", "p2p.message:whatever", "--from-session", "s2", "--outcome", "shown"])).toMatchObject({ sent: false, reason: "not-asked" });
  });

  it("H1/M2: `p2p own-agents` is the person's alone, and front ends ask it at delivery time (`check <did>`)", async () => {
    const agent = inDir(ann, repo.S, { P2P_PERSON_TOKEN: "", CLAUDECODE: "1" });
    const app = await ann.app();
    await app.load();
    const here = app.did;
    await app.close();
    const laptop = "d_" + "l".repeat(26);
    const desk = "d_" + "k".repeat(26);
    const check = async (did: string) => (await ann.ok(["own-agents", "check", did])).deliver as boolean;
    for (const args of [["own-agents", "deliver"], ["own-agents", "deliver", "--devices", "all-other"]]) {
      expect((await agent.run(args)).json, args.join(" ")).toMatchObject({ error: "refused" });
    }
    expect(await ann.ok(["own-agents"])).toMatchObject({ ownAgents: "hold", devices: [] });
    expect(await check(here)).toBe(false);
    try {
      // Only some other devices: their sessions get through, this device's agent sessions stay held.
      expect(await ann.ok(["own-agents", "deliver", "--devices", laptop])).toMatchObject({ ownAgents: "hold", devices: [laptop] });
      expect(await check(laptop)).toBe(true);
      expect(await check(desk)).toBe(false);
      expect(await check(here)).toBe(false);
      expect((await ann.run(["own-agents", "deliver", "--devices", here])).json).toMatchObject({ error: "usage" });
      expect(await ann.ok(["own-agents", "deliver", "--devices", "all-other"])).toMatchObject({ devices: "all-other" });
      expect(await check(desk)).toBe(true);
      expect(await check(here)).toBe(false);
      // Everything, this device included.
      await ann.ok(["own-agents", "deliver"]);
      expect(await check(here)).toBe(true);
      // Nothing is stamped on the events themselves.
      await inDir(ann, repo.S).ok(["send", "--from-session", "s1", "--to", `${ids.ann}/s2`, "--stdin"], { stdin: "trusted agent" });
      const [ev] = await got(ann, "s2", "trusted agent");
      expect(ev?.data.via).toBe("agent");
      expect(ev?.data.ownTrusted).toBeUndefined();
      // Turning it back off never needs the person, and clears both.
      expect((await agent.run(["own-agents", "hold"])).json).toMatchObject({ ownAgents: "hold", devices: [] });
      expect(await check(desk)).toBe(false);
    } finally {
      await ann.ok(["own-agents", "hold"]);
    }
  });

  it("L4: after a private session's text reached your terminal session, a send from there to someone else warns", async () => {
    await inDir(ann, repo.P).ok(["status", "--session", "p3", "--state", "idle", "--label", "p3"]);
    const app = await ann.app();
    await app.load();
    try {
      // The person's terminal posts statuses as `tui` (p2p tui does): live here.
      await app.state.update("peers", (cur = {}) => ({ next: { ...cur, [`${app.userId}|tui`]: { own: app.userId, sid: "tui", did: app.did, ts: Date.now(), status: { state: "idle", label: "tui" }, self: true } }, result: undefined }));
    } finally {
      await app.close();
    }
    await inDir(ann, repo.P).ok(["send", "--from-session", "p3", "--to", `${ids.ann}/tui`, "--stdin"], { stdin: "private notes" });
    await got(ann, "tui", "private notes");
    const out: string[] = [];
    const code = await main(["send", "--to", `${ids.ben}/bs1`, "passing it on"], { env: inDir(ann, repo.S).env, io: { out: (l) => out.push(l), err: () => {}, select: async () => [], prompt: async () => "" } });
    process.exitCode = 0;
    expect(code).toBe(0);
    // A warning, never a refusal: the person decides.
    expect(out.join("\n")).toMatch(/note: a private session of yours sent text to this terminal session lately/);
  });
});
