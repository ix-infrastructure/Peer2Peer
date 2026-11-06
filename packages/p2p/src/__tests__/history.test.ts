// Copyright 2026 Ix Infrastructure Inc.
//
// Message history (history.ts, docs/concepts.md "Message history"), normal flows and adversarially:
// what is kept (in and out, extension fallbacks, once each), who may read it (the person's inbox
// only by the person; a session only its own, within its projects; a spoofed or unregistered
// session id refused; nothing from inside an agent's session without the front end's token),
// retention and the size cap, and no plaintext on disk.

import { mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { main } from "../cli.js";
import { assertHistoryReader, historyKeyFile, historySettings, parseSince, readHistory, recordHistory, type HistoryRec } from "../history.js";
import { projectOf } from "../projects.js";
import { sendExtension } from "../sessions.js";
import { startRelay, User, type TestRelay } from "./harness.js";
import { Tui } from "../tui/tui.js";
import { initialUi, messagesSorted, onKey } from "../tui/model.js";
import { frameText } from "../tui/frame.js";
import { render } from "../tui/view.js";
import { FakeTerminal } from "../tui/__tests__/fixtures.js";

const R = "wss://relay-history.test/v3";
let relay: TestRelay;
let ann: User;
let ben: User;
let cat: User;
const ids: Record<string, string> = {};
let root: string;
let transport: Record<string, string>;
const repo: Record<string, string> = {};

function gitRepo(dir: string, remote: string): string {
  mkdirSync(join(dir, ".git"), { recursive: true });
  writeFileSync(join(dir, ".git", "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(dir, ".git", "config"), `[core]\n\tbare = false\n[remote "origin"]\n\turl = ${remote}\n`);
  return dir;
}

function inDir(u: User, dir: string): User {
  const v = Object.create(u) as User;
  Object.defineProperty(v, "env", { get: () => ({ ...u.env, P2P_WORKDIR: dir }) });
  return v;
}

/** `p2p <args> --json` as someone other than the person's front end: no token, with `env` on top. */
async function as(u: User, env: Record<string, string | undefined>, args: string[], yes = false): Promise<{ code: number; json: any; out: string }> {
  const out: string[] = [];
  const code = await main([...args, "--json"], { env: { ...u.env, P2P_PERSON_TOKEN: "", ...env }, io: { out: (l) => out.push(l), err: () => {} }, confirmTty: async () => yes });
  process.exitCode = 0;
  return { code, json: JSON.parse(out.at(-1) ?? "null"), out: out.join("\n") };
}

const texts = (r: { messages: { text: string }[] }) => r.messages.map((m) => m.text);

/** Every file under `dir`, as bytes. */
function filesUnder(dir: string): { path: string; data: Buffer }[] {
  const out: { path: string; data: Buffer }[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...filesUnder(p));
    else if (e.isFile()) out.push({ path: p, data: readFileSync(p) });
  }
  return out;
}

describe("message history", () => {
  beforeAll(async () => {
    root = realpathSync(mkdtempSync(join(tmpdir(), "p2p-history-")));
    repo.S = gitRepo(join(root, "shared"), "git@github.com:acme/shared.git");
    repo.P = gitRepo(join(root, "secret"), "git@github.com:acme/secret.git");
    repo.Q = gitRepo(join(root, "bens"), "git@github.com:acme/bens.git");
    relay = await startRelay(R, { limits: { connectsPerIpPerMinute: 100_000, authsPerIpPerMinute: 100_000, authsPerIpv4PerMinute: 100_000, httpPerIpPerMinute: 100_000 } });
    const t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    transport = t;
    ann = new User("ann", t);
    ben = new User("ben", t);
    cat = new User("cat", t);
    for (const u of [ann, ben, cat]) {
      u.autoShareProject = false;
      ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
    }
    await ben.ok(["accept", (await ann.ok(["invite", "--link"])).link]);
    await ann.ok(["friends"]);
    await cat.ok(["accept", (await ann.ok(["invite", "--link"])).link]);
    await ann.ok(["friends"]);
    // Ann shares S with ben; P stays private. Ben shares his own project with ann.
    await inDir(ann, repo.S).ok(["project", "share", "--person", ids.ben]);
    await inDir(ben, repo.Q).ok(["project", "share", "--person", ids.ann]);
    // Live, registered sessions (their front end's token): ann's s1 in S, her p1 in P, ben's b1.
    await inDir(ann, repo.S).ok(["status", "--session", "s1", "--state", "busy", "--label", "s1"]);
    await inDir(ann, repo.P).ok(["status", "--session", "p1", "--state", "busy", "--label", "p1"]);
    await inDir(ben, repo.Q).ok(["status", "--session", "b1", "--state", "busy", "--label", "b1"]);
    await ann.ok(["ls"]);
    await ben.ok(["ls"]);
  }, 120_000);

  afterAll(async () => {
    await relay?.close().catch(() => {});
    for (const u of [ann, ben, cat]) u?.cleanup();
    rmSync(root, { recursive: true, force: true });
  });

  it("keeps messages in and out, per session, and the person sees all of them", async () => {
    expect((await inDir(ben, repo.Q).ok(["send", "--from-session", "b1", "--to", `${ids.ann}/s1`, "--stdin"], { stdin: "hello s1 from ben" })).delivered).toBe(true);
    await ann.ok(["ls"]);
    expect((await inDir(ann, repo.S).ok(["send", "--from-session", "s1", "--to", `${ids.ben}/b1`, "--stdin"], { stdin: "reply from s1" })).delivered).toBe(true);
    await ben.ok(["ls"]);
    // Ann's session s1, read by her front end (the token): both directions, its own only.
    const s1 = await inDir(ann, repo.S).ok(["history", "--session", "s1"]);
    expect(texts(s1)).toEqual(["hello s1 from ben", "reply from s1"]);
    expect(s1.messages[0]).toMatchObject({ dir: "in", type: "message", session: "s1", peer: { userId: ids.ben } });
    expect(s1.messages[0].peerSession).toBeUndefined();
    expect(s1.messages[1]).toMatchObject({ dir: "out", session: "s1", peer: { userId: ids.ben }, state: "sent" });
    // What a session's reader gets never names projects.
    expect(JSON.stringify(s1)).not.toContain("pj_");
    expect(s1.retention).toMatchObject({ days: 30, enabled: true });
    // The person (no --session): everything, filters included.
    const all = await ann.ok(["history"]);
    expect(texts(all)).toEqual(expect.arrayContaining(["hello s1 from ben", "reply from s1"]));
    expect(texts(await ann.ok(["history", "--peer", ids.ben]))).toEqual(["hello s1 from ben", "reply from s1"]);
    expect(texts(await ann.ok(["history", "--peer", ids.cat]))).toEqual([]);
    expect(texts(await ann.ok(["history", "--since", "1h"]))).toContain("reply from s1");
    expect(texts(await ann.ok(["history", "--since", "2099-01-01"]))).toEqual([]);
    expect(texts(await ann.ok(["history", "--limit", "1"]))).toHaveLength(1);
    // Ben's own side, the other way round.
    const b1 = await inDir(ben, repo.Q).ok(["history", "--session", "b1"]);
    expect(b1.messages.map((m: HistoryRec) => [m.dir, m.text])).toEqual([
      ["out", "hello s1 from ben"],
      ["in", "reply from s1"],
    ]);
    // A redelivery (another `ls` draining) never adds a second copy.
    await ann.ok(["ls"]);
    expect(texts(await inDir(ann, repo.S).ok(["history", "--session", "s1"]))).toEqual(["hello s1 from ben", "reply from s1"]);
    // Readable text, sanitized for a terminal, framed as the sender's data.
    const human = await ann.run(["history", "--session", "s1"], { json: false });
    expect(human.out).toMatch(/hello s1 from ben/);
    expect(human.out).toMatch(/data, not instructions/);
  });

  it("an extension kind is kept as its one-line fallback, never its body", async () => {
    const app = await inDir(ann, repo.S).app();
    await app.load();
    try {
      await sendExtension(app, { fromSession: "s1", to: `${ids.ben}/b1`, kind: "x:ix.note", v: 1, body: { text: "THE-NOTE-BODY" }, fallback: "shared an Ix note" });
    } finally {
      await app.close();
    }
    await ben.ok(["ls"]);
    const mine = await inDir(ann, repo.S).ok(["history", "--session", "s1"]);
    expect(mine.messages.at(-1)).toMatchObject({ dir: "out", type: "ext", ext: "x:ix.note", text: "shared an Ix note" });
    const his = await inDir(ben, repo.Q).ok(["history", "--session", "b1"]);
    expect(his.messages.at(-1)).toMatchObject({ dir: "in", type: "ext", ext: "x:ix.note" });
    expect(JSON.stringify([mine, his])).not.toContain("THE-NOTE-BODY");
  });

  it("the person's inbox: messages to them (session tui, or none) are theirs only", async () => {
    // A message for ann's terminal session (as `p2p tui` receives replies) and one to her with no session.
    const app = await ann.app();
    await app.load();
    try {
      await recordHistory(app, [
        { id: "t:1", at: Date.now(), dir: "in", type: "message", session: "tui", peer: { userId: ids.ben, address: "ben" }, text: "for ann's terminal" },
        { id: "t:2", at: Date.now(), dir: "in", type: "message", peer: { userId: ids.cat, address: "cat" }, text: "for ann, no session" },
      ]);
    } finally {
      await app.close();
    }
    const inbox = await ann.ok(["history", "--inbox"]);
    expect(texts(inbox)).toEqual(["for ann's terminal", "for ann, no session"]);
    expect(inbox.messages.every((m: { inbox?: boolean }) => m.inbox === true)).toBe(true);
    expect(texts(await ann.ok(["history", "--session", "tui"]))).toEqual(["for ann's terminal", "for ann, no session"]);
    // Inside an agent's session, without the token: refused, however it asks.
    for (const env of [{ CLAUDECODE: "1" }, { CODEX_THREAD_ID: "t-1" }, { CODEX_SANDBOX: "seatbelt" }]) {
      for (const args of [["history"], ["history", "--inbox"], ["history", "--session", "tui"], ["history", "--peer", ids.cat]]) {
        const r = await as(ann, env, args, true);
        expect(r.json?.error, `${JSON.stringify(env)} ${args.join(" ")}`).toBe("refused");
        expect(r.out).not.toContain("for ann");
      }
    }
    // Outside any agent's session, without the token: only after the person's "yes" on the terminal.
    expect((await as(ann, {}, ["history", "--inbox"], false)).json.error).toBe("refused");
    const yes = await as(ann, {}, ["history", "--inbox"], true);
    expect(yes.code).toBe(0);
    expect(texts(yes.json)).toContain("for ann, no session");
    // A session (even a registered one, through its front end) never reads the person's inbox.
    const s1 = await inDir(ann, repo.S).ok(["history", "--session", "s1"]);
    expect(JSON.stringify(s1)).not.toContain("for ann");
  });

  it("a session reads only its own history: never another session's, never another project's", async () => {
    // Messages into p1 (the private project's session) and s1.
    const app = await ann.app();
    await app.load();
    const pP = projectOf(repo.P).id;
    const pS = projectOf(repo.S).id;
    try {
      await recordHistory(app, [
        { id: "p:1", at: Date.now(), dir: "in", type: "message", session: "p1", peer: { userId: app.userId, address: "me", self: true }, text: "PRIVATE-PROJECT-SECRET", projects: [pP] },
        { id: "s:9", at: Date.now(), dir: "out", type: "message", session: "s1", peer: { userId: ids.ben, address: "ben" }, text: "shared project note", projects: [pS] },
      ]);
    } finally {
      await app.close();
    }
    const s1 = await inDir(ann, repo.S).ok(["history", "--session", "s1"]);
    expect(texts(s1)).toContain("shared project note");
    expect(JSON.stringify(s1)).not.toContain("PRIVATE-PROJECT-SECRET");
    const p1 = await inDir(ann, repo.P).ok(["history", "--session", "p1"]);
    expect(texts(p1)).toEqual(["PRIVATE-PROJECT-SECRET"]);
    expect(JSON.stringify(p1)).not.toContain("shared project note");
    // Filters can't widen a session's view: --peer and --since apply within its own records only.
    expect(JSON.stringify(await inDir(ann, repo.S).ok(["history", "--session", "s1", "--peer", ids.ann]))).not.toContain("PRIVATE-PROJECT-SECRET");
  });

  it("a spoofed or unregistered session id is refused; an agent's shell reads no session's history", async () => {
    // Through the front end's token, a session id no front end registered.
    for (const sid of ["never-used", "b1", "s1x"]) {
      const r = await ann.run(["history", "--session", sid]);
      expect(r.json?.error, sid).toBe("refused");
    }
    // A bad session id is a usage error, never a lookup.
    expect((await ann.run(["history", "--session", "../../etc"])).json?.error).toBe("usage");
    // Inside an agent's session without the token: refused even for a registered session, yes or not.
    for (const env of [{ CLAUDECODE: "1" }, { CODEX_TOOL_CALL_ID: "call_1" }]) {
      const r = await as(inDir(ann, repo.S), env, ["history", "--session", "s1"], true);
      expect(r.json?.error).toBe("refused");
      expect(r.out).not.toContain("hello s1");
    }
    // A detached script (no agent, no terminal): refused.
    expect((await as(inDir(ann, repo.S), {}, ["history", "--session", "s1"], false)).json?.error).toBe("refused");
  });

  it("the TUI's Messages screen shows the history: every session's, or (h) the inbox only, peer text cleaned", async () => {
    const app = await ann.app();
    await app.load();
    try {
      await recordHistory(app, [{ id: "t:hostile", at: Date.now(), dir: "in", type: "message", session: "tui", peer: { userId: ids.ben, address: "ben\u001b]0;pwned\u0007" }, text: "evil\u001b[31mRED‮ text" }]);
      const tui = new Tui(app, { term: new FakeTerminal(), version: "test", noWatch: true });
      await tui.loadMessages();
      const rows = tui.data.messages;
      expect(rows.find((m) => m.text.includes("reply from s1"))).toMatchObject({ dir: "out", inbox: false, note: "from your session s1" });
      const hostile = rows.find((m) => m.id === "t:hostile")!;
      expect(hostile).toMatchObject({ inbox: true });
      expect(hostile.text).not.toMatch(/[\u001b\u0007‮]/);
      expect(hostile.who).not.toMatch(/[\u001b\u0007]/);
      let ui = onKey(initialUi(), tui.data, { name: "3", ch: "3" }).ui;
      const all = messagesSorted(tui.data, ui).length;
      ui = onKey(ui, tui.data, { name: "h", ch: "h" }).ui;
      expect(ui.inboxOnly).toBe(true);
      const inbox = messagesSorted(tui.data, ui);
      expect(inbox.length).toBeLessThan(all);
      expect(inbox.every((m) => m.inbox !== false)).toBe(true);
      expect(frameText(render(ui, tui.data, 120, 40, Date.now()))).not.toContain("reply from s1");
    } finally {
      await app.close();
    }
  });

  it("a session id that comes back in another project doesn't see what the earlier one had", async () => {
    const app = await ann.app();
    await app.load();
    try {
      // "reused" worked in the private project and got a message there...
      await app.state.update("sessionProjects", (cur = {}) => ({ next: { ...cur, reused: { projects: { [projectOf(repo.P).id]: { name: "secret" } }, registered: true, at: Date.now() } }, result: undefined }));
      await recordHistory(app, [{ id: "r:1", at: Date.now(), dir: "in", type: "message", session: "reused", peer: { userId: app.userId, address: "me", self: true }, text: "FROM-THE-PRIVATE-RUN", projects: [projectOf(repo.P).id] }]);
      expect(texts(await readHistory(app, await assertHistoryReader(app, "reused")))).toEqual(["FROM-THE-PRIVATE-RUN"]);
      // ...then its binding ended (TTL) and a session with the same id started in the shared one.
      await app.state.update("sessionProjects", (cur = {}) => ({ next: { ...cur, reused: { projects: { [projectOf(repo.S).id]: { name: "shared" } }, registered: true, at: Date.now() } }, result: undefined }));
      expect(texts(await readHistory(app, await assertHistoryReader(app, "reused")))).toEqual([]);
      // The person still sees it.
      expect(texts(await readHistory(app, { person: true }, { session: "reused" }))).toEqual(["FROM-THE-PRIVATE-RUN"]);
    } finally {
      await app.close();
    }
  });

  it("is sealed at rest: no message text, peer name or session in any history file; altered or swapped segments don't open", async () => {
    const canary = "CANARY-plaintext-7f3a91";
    await inDir(ben, repo.Q).ok(["send", "--from-session", "b1", "--to", `${ids.ann}/s1`, "--stdin"], { stdin: canary });
    await ann.ok(["ls"]);
    expect(texts(await inDir(ann, repo.S).ok(["history", "--session", "s1"]))).toContain(canary);
    const files = filesUnder(join(ann.home, "cli")).filter((f) => /\/history[^/]*\.json$/.test(f.path));
    expect(files.length).toBeGreaterThanOrEqual(2);
    for (const f of files) {
      const s = f.data.toString("utf8");
      for (const needle of [canary, "hello s1 from ben", "for ann", ids.ben, ids.ann, "\"session\"", "\"text\"", "x:ix.note"]) expect(s.includes(needle), `${f.path}: ${needle}`).toBe(false);
      expect(JSON.parse(s)).toMatchObject({ v: 1, alg: "c20p1305" });
    }
    // The key: 0600, its own file.
    expect(readFileSync(historyKeyFile(ann.home), "utf8").trim()).toMatch(/^[A-Za-z0-9_-]{43}$/);
    if (process.platform !== "win32") {
      const { statSync } = await import("node:fs");
      expect(statSync(historyKeyFile(ann.home)).mode & 0o777).toBe(0o600);
    }
    // A segment altered on disk, or another segment's bytes put in its place, doesn't open: its
    // records are gone, nothing else breaks, and nothing forged appears.
    const seg = files.find((f) => /history-\d+\.json$/.test(f.path))!;
    const sealed = JSON.parse(seg.data.toString("utf8"));
    const flipped = { ...sealed, c: sealed.c.slice(0, -4) + (sealed.c.endsWith("AAAA") ? "BBBB" : "AAAA") };
    writeFileSync(seg.path, JSON.stringify(flipped));
    const after = await ann.ok(["history"]);
    expect(texts(after)).not.toContain(canary);
    writeFileSync(seg.path, seg.data);
    expect(texts(await ann.ok(["history"]))).toContain(canary);
    const index = files.find((f) => /\/history\.json$/.test(f.path))!;
    writeFileSync(seg.path, index.data);
    expect((await ann.run(["history"])).code).toBe(0);
    writeFileSync(seg.path, seg.data);
  });

  it("retention and the size cap: pruned on write, from config.json", async () => {
    const u = new User("pruner", transport);
    try {
      await u.ok(["init", "--name", "pruner", "--relay", R, "--yes"]);
      writeFileSync(join(u.home, "config.json"), JSON.stringify({ history: { retentionDays: 2, maxBytes: 64 * 1024 } }));
      const app = await u.app();
      await app.load();
      try {
        expect(historySettings(app)).toMatchObject({ enabled: true, retentionDays: 2, maxBytes: 64 * 1024 });
        const now = Date.now();
        const day = 86_400_000;
        const rec = (id: string, at: number, text = id): HistoryRec => ({ id, at, dir: "in", type: "message", session: "x", peer: { userId: app.userId, address: "me" }, text });
        await recordHistory(app, [rec("old-5d", now - 5 * day), rec("old-3d", now - 3 * day), rec("new-1d", now - day), rec("now", now)], now);
        expect(texts(await readHistory(app, { person: true }))).toEqual(["new-1d", "now"]);
        // On disk too: what is past retention was removed, not only hidden.
        const disk = (await app.state.backend.read("history-1")) as { c: string };
        expect(disk).toBeTruthy();
        // A day later, a write prunes "new-1d" as well (now 2 days old).
        await recordHistory(app, [rec("later", now + day + 1000)], now + day + 1000);
        expect(texts(await readHistory(app, { person: true }, {}, now + day + 1000))).toEqual(["now", "later"]);
        // The size cap: 1 KiB records, far past 64 KiB, keep the newest within it.
        const big = "x".repeat(1024);
        for (let i = 0; i < 200; i += 20) await recordHistory(app, Array.from({ length: 20 }, (_, j) => rec(`b${i + j}`, now + day + 2000 + i + j, `${i + j} ${big}`)), now + day + 2000 + i);
        const left = await readHistory(app, { person: true }, { limit: 1000 }, now + day + 3000);
        const bytes = left.messages.reduce((n, m) => n + Buffer.byteLength(JSON.stringify(m)), 0);
        expect(bytes).toBeLessThanOrEqual(64 * 1024 + 2048);
        expect(left.messages.at(-1)!.text.startsWith("199 ")).toBe(true);
        expect(left.messages.some((m) => m.text.startsWith("0 "))).toBe(false);
        // A key that was replaced (deleted, then made anew): what it sealed can't be read, and the next
        // write removes it from disk rather than leaving it to outlive retention.
        const before = filesUnder(join(u.home, "cli")).filter((f) => /history-\d+\.json$/.test(f.path)).map((f) => f.path);
        expect(before.length).toBeGreaterThan(0);
        rmSync(historyKeyFile(u.home));
        await recordHistory(app, [rec("after-new-key", now + day + 3500)], now + day + 3500);
        const after = filesUnder(join(u.home, "cli")).filter((f) => /history-\d+\.json$/.test(f.path)).map((f) => f.path);
        expect(after).toHaveLength(1);
        expect(before).not.toContain(after[0]);
        expect(texts(await readHistory(app, { person: true }, { limit: 1000 }, now + day + 3500))).toEqual(["after-new-key"]);
        // Off: nothing more is kept.
        writeFileSync(join(u.home, "config.json"), JSON.stringify({ history: { enabled: false } }));
        await recordHistory(app, [rec("while-off", now + day + 4000)], now + day + 4000);
        expect(texts(await readHistory(app, { person: true }, { limit: 1000 }, now + day + 4000))).not.toContain("while-off");
      } finally {
        await app.close();
      }
      // --clear deletes it all, the key included; only the person may.
      writeFileSync(join(u.home, "config.json"), "{}");
      expect((await as(u, { CLAUDECODE: "1" }, ["history", "--clear"], true)).json?.error).toBe("refused");
      const cleared = await u.ok(["history", "--clear"]);
      expect(cleared.cleared).toBeGreaterThan(0);
      expect(filesUnder(join(u.home, "cli")).some((f) => /history/.test(f.path))).toBe(false);
      expect(texts(await u.ok(["history"]))).toEqual([]);
    } finally {
      u.cleanup();
    }
  });

  it("P2P_HISTORY=0 records nothing; --since parses durations and dates", async () => {
    const off = new User("quiet", transport, { P2P_HISTORY: "0" });
    try {
      await off.ok(["init", "--name", "quiet", "--relay", R, "--yes"]);
      const app = await off.app();
      await app.load();
      try {
        await recordHistory(app, [{ id: "q", at: Date.now(), dir: "in", type: "message", peer: { userId: app.userId, address: "me" }, text: "nope" }]);
      } finally {
        await app.close();
      }
      expect(filesUnder(join(off.home, "cli")).some((f) => /history/.test(f.path))).toBe(false);
      expect((await off.ok(["history"])).retention.enabled).toBe(false);
    } finally {
      off.cleanup();
    }
    const now = Date.UTC(2026, 10, 5, 12);
    expect(parseSince("30m", now)).toBe(now - 30 * 60_000);
    expect(parseSince("2w", now)).toBe(now - 14 * 86_400_000);
    expect(parseSince("2026-11-01", now)).toBe(Date.UTC(2026, 10, 1));
    expect(() => parseSince("yesterday", now)).toThrow(/--since/);
  });
});
