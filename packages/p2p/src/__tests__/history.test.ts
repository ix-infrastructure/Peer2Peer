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
import { assertHistoryReader, historyKeyFile, historySettings, parseSince, readHistory, recordEvents, recordHistory, UNBOUND, type HistoryRec } from "../history.js";
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

  it("a session id that comes back in another project, or with a binding made anew, doesn't see what the earlier one had (M2)", async () => {
    const app = await ann.app();
    await app.load();
    const pP = projectOf(repo.P).id;
    const pS = projectOf(repo.S).id;
    const bind = (projects: Record<string, { name: string }>, since: number) =>
      app.state.update("sessionProjects", (cur = {}) => ({ next: { ...cur, reused: { projects, registered: true as const, since, at: Date.now() } }, result: undefined }));
    try {
      const t0 = Date.now();
      // "reused" worked in the private project and got a message there...
      await bind({ [pP]: { name: "secret" } }, t0 - 1000);
      await recordHistory(app, [{ id: "r:1", at: t0, dir: "in", type: "message", session: "reused", peer: { userId: app.userId, address: "me", self: true }, text: "FROM-THE-PRIVATE-RUN", projects: [pP] }]);
      expect(texts(await readHistory(app, await assertHistoryReader(app, "reused")))).toEqual(["FROM-THE-PRIVATE-RUN"]);
      // ...then its binding ended (TTL) and one with the same id began in the shared project...
      await bind({ [pS]: { name: "shared" } }, t0 + 1000);
      expect(texts(await readHistory(app, await assertHistoryReader(app, "reused")))).toEqual([]);
      // ...or even in the same project again: a binding made anew inherits nothing from before it began.
      await bind({ [pP]: { name: "secret" } }, t0 + 1000);
      expect(texts(await readHistory(app, await assertHistoryReader(app, "reused")))).toEqual([]);
      // A binding from before `since` existed shows nothing.
      await app.state.update("sessionProjects", (cur = {}) => ({ next: { ...cur, reused: { projects: { [pP]: { name: "secret" } }, registered: true as const, at: Date.now() } }, result: undefined }));
      expect(texts(await readHistory(app, await assertHistoryReader(app, "reused")))).toEqual([]);
      // Records with no projects, or UNBOUND (the binding was missing or unreadable when recorded), never reach a session.
      await bind({ [pP]: { name: "secret" } }, t0 - 1000);
      await recordHistory(app, [
        { id: "r:2", at: t0 + 1, dir: "in", type: "message", session: "reused", peer: { userId: app.userId, address: "me", self: true }, text: "NO-PROJECTS" },
        { id: "r:3", at: t0 + 2, dir: "in", type: "message", session: "reused", peer: { userId: app.userId, address: "me", self: true }, text: "UNBOUND-REC", projects: [UNBOUND] },
      ]);
      expect(texts(await readHistory(app, await assertHistoryReader(app, "reused")))).toEqual(["FROM-THE-PRIVATE-RUN"]);
      // The person still sees all of it.
      expect(texts(await readHistory(app, { person: true }, { session: "reused" }))).toEqual(["FROM-THE-PRIVATE-RUN", "NO-PROJECTS", "UNBOUND-REC"]);
    } finally {
      await app.close();
    }
  });

  it("a message into a session with no binding here is recorded UNBOUND; the time kept is when it arrived, the sender's apart (M2, L3)", async () => {
    const app = await ann.app();
    await app.load();
    try {
      const sent = Date.now() - 3 * 3_600_000;
      const ev = { n: 1, id: "p2p.message:unbound-1", at: sent, kind: "p2p.message", toSession: "nobind-1", own: app.userId, sid: "nobind-1", data: { from: { userId: ids.ben, address: "ben", did: "d", self: false }, own: app.userId, sid: "nobind-1", ref: "abcabc", text: "INTO-AN-UNBOUND-SESSION" } };
      const before = Date.now();
      await recordEvents(app, [ev]);
      const rec = (await readHistory(app, { person: true }, { session: "nobind-1" })).messages[0] as HistoryRec;
      expect(rec).toMatchObject({ text: "INTO-AN-UNBOUND-SESSION", sentAt: sent });
      // Kept by when it arrived here, not by the sender's clock (a sender can't backdate it past retention or --since).
      expect(rec.at).toBeGreaterThanOrEqual(before);
      // Whatever binding that id gets later, even one that began long before, a session never sees it.
      await app.state.update("sessionProjects", (cur = {}) => ({ next: { ...cur, "nobind-1": { projects: { [projectOf(repo.S).id]: { name: "shared" } }, registered: true as const, since: 0, at: Date.now() } }, result: undefined }));
      expect(texts(await readHistory(app, await assertHistoryReader(app, "nobind-1")))).toEqual([]);
      // What the person sees never names projects either.
      expect(JSON.stringify(await readHistory(app, { person: true }, { session: "nobind-1" }))).not.toContain(UNBOUND);
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
        expect(filesUnder(join(u.home, "cli")).filter((f) => /\/history-\d+\.json$/.test(f.path))).toHaveLength(1);
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
        // A key that was replaced (deleted, then made anew): what it sealed can't be opened. The next
        // write sets it aside (history.bad-*), never deletes it silently and never overwrites it, and
        // the set-aside files go once past retention (L6).
        const before = filesUnder(join(u.home, "cli")).filter((f) => /\/history-\d+\.json$/.test(f.path)).map((f) => f.path);
        expect(before.length).toBeGreaterThan(0);
        rmSync(historyKeyFile(u.home));
        await recordHistory(app, [rec("after-new-key", now + day + 3500)], now + day + 3500);
        const after = filesUnder(join(u.home, "cli")).filter((f) => /\/history-\d+\.json$/.test(f.path)).map((f) => f.path);
        expect(after, JSON.stringify({ before, after })).toHaveLength(1);
        expect(before).not.toContain(after[0]);
        // Neither the index nor its copy opens: no segment is trusted, every one is set aside (with both).
        const aside = filesUnder(join(u.home, "cli")).filter((f) => /history\.bad-\d{13}-history(-\d+|-mark)?\.json$/.test(f.path));
        expect(aside.length).toBe(before.length + 2);
        expect(texts(await readHistory(app, { person: true }, { limit: 1000 }, now + day + 3500))).toEqual(["after-new-key"]);
        await recordHistory(app, [rec("way-later", now + 40 * day)], now + 40 * day);
        expect(filesUnder(join(u.home, "cli")).some((f) => /history\.bad-/.test(f.path))).toBe(false);
        // Off: nothing more is kept.
        writeFileSync(join(u.home, "config.json"), JSON.stringify({ history: { enabled: false } }));
        await recordHistory(app, [rec("while-off", now + day + 4000)], now + day + 4000);
        expect(texts(await readHistory(app, { person: true }, { limit: 1000 }, now + day + 4000))).not.toContain("while-off");
      } finally {
        await app.close();
      }
      // --clear deletes it all, the key included; only the person may.
      writeFileSync(join(u.home, "config.json"), "{}");
      // The event log p2p watch reads holds message text too: --clear purges it there (L5), keeping the rest.
      const ea = await u.app();
      await ea.load();
      try {
        await ea.state.addEvents([
          { id: "p2p.message:clear-1", at: Date.now(), kind: "p2p.message", data: { text: "EVENT-LOG-TEXT" } },
          { id: "p2p.ext:clear-2", at: Date.now(), kind: "p2p.ext", data: { fallback: "EVENT-LOG-EXT" } },
          { id: "p2p.friend:keep", at: Date.now(), kind: "p2p.friend", data: {} },
        ]);
      } finally {
        await ea.close();
      }
      expect((await as(u, { CLAUDECODE: "1" }, ["history", "--clear"], true)).json?.error).toBe("refused");
      expect(readFileSync(join(u.home, "cli", "events.json"), "utf8")).toContain("EVENT-LOG-TEXT");
      const cleared = await u.ok(["history", "--clear"]);
      expect(cleared.cleared).toBeGreaterThan(0);
      expect(cleared.events).toBe(2);
      const log = readFileSync(join(u.home, "cli", "events.json"), "utf8");
      expect(log).not.toMatch(/EVENT-LOG-TEXT|EVENT-LOG-EXT/);
      expect(log).toContain("p2p.friend:keep");
      expect(filesUnder(join(u.home, "cli")).some((f) => /history/.test(f.path))).toBe(false);
      expect(texts(await u.ok(["history"]))).toEqual([]);
    } finally {
      u.cleanup();
    }
  });

  it("copy-on-write: a crash between the segment and the index write keeps the newest records; reads under the lock see no false damage (N2)", async () => {
    const u = new User("crash", transport);
    try {
      await u.ok(["init", "--name", "crash", "--relay", R, "--yes"]);
      const app = await u.app();
      await app.load();
      const errs: string[] = [];
      (app.io as { err: (s: string) => void }).err = (m) => errs.push(m);
      const rec = (id: string): HistoryRec => ({ id, at: Date.now(), dir: "in", type: "message", session: "x", peer: { userId: app.userId, address: "me" }, text: id });
      const dir = join(u.home, "cli");
      const snap = () => new Map(readdirSync(dir).filter((x) => x.startsWith("history")).map((x) => [x, readFileSync(join(dir, x))] as const));
      try {
        await recordHistory(app, [rec("a")]);
        const before = snap();
        await recordHistory(app, [rec("b")]);
        const after = snap();
        // The crash: the new segment was written, the index (and its copy) never was, the old version wasn't removed.
        const fresh = [...after.keys()].filter((x) => !before.has(x));
        expect(fresh).toHaveLength(1);
        for (const [x, data] of before) writeFileSync(join(dir, x), data);
        for (const x of fresh) writeFileSync(join(dir, x), after.get(x)!);
        const r = await readHistory(app, { person: true });
        expect(texts(r)).toEqual(["a", "b"]);
        expect(r.unreadable).toBeUndefined();
        await recordHistory(app, [rec("c")]);
        expect(texts(await readHistory(app, { person: true }))).toEqual(["a", "b", "c"]);
        // The superseded versions are gone from disk: one segment, the index and its copy, the key.
        expect(readdirSync(dir).filter((x) => /^history-\d+\.json$/.test(x))).toHaveLength(1);
        // A reader racing writers in another process (another App on this home) never sees a removed old version as damage.
        const other = await u.app();
        await other.load();
        try {
          const writes = (async () => {
            for (let i = 0; i < 25; i++) await recordHistory(other, [rec(`w${i}`)]);
          })();
          const reads: number[] = [];
          for (let i = 0; i < 25; i++) reads.push((await readHistory(app, { person: true }, { limit: 1000 })).unreadable ?? 0);
          await writes;
          expect(reads.every((n) => n === 0)).toBe(true);
          expect(texts(await readHistory(app, { person: true }, { limit: 1000 }))).toHaveLength(28);
        } finally {
          await other.close();
        }
        expect(errs.join("\n")).not.toMatch(/couldn't be opened/);
      } finally {
        await app.close();
      }
    } finally {
      u.cleanup();
    }
  });

  it("no older copy comes back: a restored pruned or superseded segment, a damaged index, both index and its copy (N1, L6)", async () => {
    const u = new User("damage", transport);
    try {
      await u.ok(["init", "--name", "damage", "--relay", R, "--yes"]);
      const app = await u.app();
      await app.load();
      const errs: string[] = [];
      (app.io as { err: (s: string) => void }).err = (m) => errs.push(m);
      const rec = (id: string): HistoryRec => ({ id, at: Date.now(), dir: "in", type: "message", session: "x", peer: { userId: app.userId, address: "me" }, text: id });
      const dir = join(u.home, "cli");
      const segs = () => readdirSync(dir).filter((x) => /^history-\d+\.json$/.test(x));
      try {
        await recordHistory(app, [rec("one")]);
        const [v1] = segs();
        const v1data = readFileSync(join(dir, v1));
        await recordHistory(app, [rec("two")]);
        expect(segs()).not.toContain(v1);
        // The superseded version put back (as a backup restore or a rollback would): never adopted, removed.
        writeFileSync(join(dir, v1), v1data);
        const r1 = await readHistory(app, { person: true });
        expect(texts(r1)).toEqual(["one", "two"]);
        expect(segs()).not.toContain(v1);
        // A segment past retention, pruned, then put back: the same.
        // (Its number is below `next` whatever it holds.)
        writeFileSync(join(dir, v1), v1data);
        await recordHistory(app, [rec("three")]);
        expect(texts(await readHistory(app, { person: true }))).toEqual(["one", "two", "three"]);
        expect(segs()).not.toContain(v1);
        // A listed segment damaged on disk: not shown (counted), set aside at the next write, never overwritten.
        const [cur] = segs();
        const curData = readFileSync(join(dir, cur));
        writeFileSync(join(dir, cur), "{not json");
        const damaged = await readHistory(app, { person: true });
        expect(texts(damaged)).toEqual([]);
        expect(damaged.unreadable).toBe(1);
        await recordHistory(app, [rec("four")]);
        expect(errs.join("\n")).toMatch(new RegExp(`${cur.replace(".json", "")} couldn't be opened \\(not readable\\); set aside as history\\.bad-`));
        expect(texts(await readHistory(app, { person: true }))).toEqual(["four"]);
        // That older copy put back, now unlisted below `next`: not adopted either.
        writeFileSync(join(dir, cur), curData);
        expect(texts(await readHistory(app, { person: true }))).toEqual(["four"]);
        // A damaged index: its copy stands in, and still nothing older comes back.
        await recordHistory(app, [rec("five")]);
        writeFileSync(join(dir, "history.json"), "{}");
        writeFileSync(join(dir, v1), v1data);
        await recordHistory(app, [rec("six")]);
        expect(texts(await readHistory(app, { person: true }))).toEqual(["four", "five", "six"]);
        // Both the index and its copy damaged: no segment is trusted (any could be an older copy): all set aside.
        writeFileSync(join(dir, "history.json"), "{}");
        writeFileSync(join(dir, "history-mark.json"), "{}");
        writeFileSync(join(dir, v1), v1data);
        await recordHistory(app, [rec("seven")]);
        expect(texts(await readHistory(app, { person: true }))).toEqual(["seven"]);
        expect(readdirSync(dir).filter((x) => x.startsWith("history.bad-")).length).toBeGreaterThanOrEqual(4);
      } finally {
        await app.close();
      }
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
