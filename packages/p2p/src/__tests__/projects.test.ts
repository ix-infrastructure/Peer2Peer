// Copyright 2026 Ix Infrastructure Inc.
//
// Project boundaries (projects.ts, docs/concepts.md "Projects", threat model "Project
// boundaries"), adversarially: a session in a private project reaches nobody but this user's own
// devices (status, ls, summary, extension state, messages out), a shared project works as before,
// nothing in a repository widens anything, a session that touched a private project stays private,
// messages to the user are never routed into a session its projects keep from the sender, and a
// roster signed elsewhere can't widen a private session on this device.

import { mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createRosterV3 } from "@peer2peer/core/v3";
import { assertPersonForWidening, isAgentProcess, personToken, takePersonToken, normalizeRemote, projectOf, PRIVATE_MARKER, assertMayReach, agentEnv } from "../projects.js";
import { main } from "../cli.js";
import { isAgentScript } from "../ancestry.js";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { linkJoin, linkStart } from "../identity.js";
import { receiving } from "../inbound.js";
import { publishExtensionState } from "../xstate.js";
import { routableSessions, sendExtension, sendStatus, sessionAudience } from "../sessions.js";
import { alongside, startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-projects.test/v3";
let relay: TestRelay;
let ann: User;
let ben: User;
let cat: User;
let dan: User;
let eve: User;
let team: string;
const ids: Record<string, string> = {};
let root: string;
let transport: Record<string, string>;
/** Repositories: shared (S), private (P), a second clone of S's remote (C), a third (Q). */
const repo: Record<string, string> = {};

/** A git working tree made of files alone (projects.ts never runs git). */
function gitRepo(dir: string, remote?: string): string {
  mkdirSync(join(dir, ".git"), { recursive: true });
  writeFileSync(join(dir, ".git", "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(dir, ".git", "config"), `[core]\n\tbare = false\n${remote ? `[remote "origin"]\n\turl = ${remote}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n` : ""}`);
  return dir;
}

/** A linked worktree of `main` at `dir`, as `git worktree add` lays it out. */
function worktree(main: string, dir: string, name: string): string {
  const gd = join(main, ".git", "worktrees", name);
  mkdirSync(gd, { recursive: true });
  writeFileSync(join(gd, "commondir"), "../..\n");
  writeFileSync(join(gd, "HEAD"), "ref: refs/heads/wt\n");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, ".git"), `gitdir: ${gd}\n`);
  return dir;
}

/** `u` working in `dir` (P2P_WORKDIR, as the mod and the Codex bridge pass it), and optionally more folders. */
function inDir(u: User, dir: string, extra: string[] = []): User {
  const v = Object.create(u) as User;
  Object.defineProperty(v, "env", { get: () => ({ ...u.env, P2P_WORKDIR: dir, ...(extra.length ? { P2P_PROJECT_DIRS: extra.join(":") } : {}) }) });
  return v;
}

async function events(u: User): Promise<{ kind: string; toSession?: string; data: Record<string, any> }[]> {
  const app = await u.app();
  await app.load();
  try {
    return ((await app.state.get("events"))?.items ?? []) as never;
  } finally {
    await app.close();
  }
}

describe("project identity (projects.ts projectOf)", () => {
  let d: string;
  beforeAll(() => {
    d = realpathSync(mkdtempSync(join(tmpdir(), "p2p-projid-")));
  });
  afterAll(() => rmSync(d, { recursive: true, force: true }));

  it("subfolders, linked worktrees and symlinks of one clone are one project", () => {
    const main = gitRepo(join(d, "app"), "git@github.com:acme/app.git");
    mkdirSync(join(main, "src", "deep"), { recursive: true });
    const wt = worktree(main, join(d, "app-wt"), "app-wt");
    mkdirSync(join(wt, "pkg"), { recursive: true });
    symlinkSync(join(main, "src"), join(d, "link"));
    const id = projectOf(main).id;
    expect(projectOf(join(main, "src", "deep")).id).toBe(id);
    expect(projectOf(join(wt, "pkg")).id).toBe(id);
    expect(projectOf(join(d, "link")).id).toBe(id);
    // A file, and a path not there yet, belong to the nearest folder that is.
    writeFileSync(join(main, "src", "a.ts"), "x");
    expect(projectOf(join(main, "src", "a.ts")).id).toBe(id);
    expect(projectOf(join(main, "src", "new", "b.ts")).id).toBe(id);
    expect(projectOf(main)).toMatchObject({ kind: "git", name: "app", remote: "github.com/acme/app" });
    expect(projectOf(wt).root).toBe(wt);
  });

  it("another clone of the same remote is another project; no git: the folder's real path", () => {
    const a = gitRepo(join(d, "one"), "https://github.com/acme/lib.git");
    const b = gitRepo(join(d, "two"), "https://github.com/acme/lib.git");
    expect(projectOf(a).remote).toBe(projectOf(b).remote);
    expect(projectOf(a).id).not.toBe(projectOf(b).id);
    mkdirSync(join(d, "plain", "sub"), { recursive: true });
    expect(projectOf(join(d, "plain")).kind).toBe("dir");
    expect(projectOf(join(d, "plain", "sub")).id).not.toBe(projectOf(join(d, "plain")).id);
  });

  it("remote URLs are normalised, credentials never kept", () => {
    expect(normalizeRemote("https://user:ghp_secret123@GitHub.com/Acme/App.git")).toBe("github.com/Acme/App");
    expect(normalizeRemote("git@github.com:Acme/App.git")).toBe("github.com/Acme/App");
    expect(normalizeRemote("ssh://git@github.com:22/Acme/App/")).toBe("github.com/Acme/App");
    const r = gitRepo(join(d, "cred"), "https://x-access-token:ghs_TOPSECRET@github.com/acme/cred.git");
    expect(JSON.stringify(projectOf(r))).not.toContain("TOPSECRET");
  });

  it("a .git that is a symlink is followed; one that can't be read makes its own folder project, never the parent's", () => {
    const outer = gitRepo(join(d, "outer"), "git@github.com:acme/outer.git");
    const real = gitRepo(join(d, "elsewhere-git"), "git@github.com:acme/inner.git");
    mkdirSync(join(outer, "linked"), { recursive: true });
    symlinkSync(join(real, ".git"), join(outer, "linked", ".git"));
    expect(projectOf(join(outer, "linked")).remote).toBe("github.com/acme/inner");
    expect(projectOf(join(outer, "linked")).id).not.toBe(projectOf(outer).id);
    // A broken symlink, an unreadable gitdir: line, an empty file: this folder alone, kind dir.
    for (const [name, make] of [
      ["broken", (dir: string) => symlinkSync(join(d, "nowhere", ".git"), join(dir, ".git"))],
      ["no-gitdir", (dir: string) => writeFileSync(join(dir, ".git"), "not a gitdir line\n")],
      ["huge", (dir: string) => writeFileSync(join(dir, ".git"), `gitdir: ${"x".repeat(300 * 1024)}`)],
    ] as const) {
      const dir = join(outer, name);
      mkdirSync(dir, { recursive: true });
      make(dir);
      const r = projectOf(join(dir));
      expect(r.kind, name).toBe("dir");
      expect(r.root, name).toBe(dir);
      expect(r.id, name).not.toBe(projectOf(outer).id);
    }
  });

  it("the person token is checked once and taken out of the environment, so no child inherits it (N1)", () => {
    const home = mkdtempSync(join(tmpdir(), "p2p-tok-"));
    try {
      const t = personToken(home);
      // Made exclusively, and the same on the next call.
      expect(personToken(home)).toBe(t);
      const env: Record<string, string | undefined> = { P2P_PERSON_TOKEN: t, PATH: "/bin" };
      process.env.P2P_PERSON_TOKEN = t;
      expect(takePersonToken(env, home)).toBe(true);
      expect(env.P2P_PERSON_TOKEN).toBeUndefined();
      expect(process.env.P2P_PERSON_TOKEN).toBeUndefined();
      expect(takePersonToken({ P2P_PERSON_TOKEN: "x".repeat(43) }, home)).toBe(false);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  it("agent detection: the variables Claude Code and Codex set, and executables by name only (no false positives)", () => {
    for (const k of ["CLAUDECODE", "CLAUDE_CODE_CHILD_SESSION", "CODEX_TOOL_CALL_ID", "CODEX_CI", "CODEX_THREAD_ID", "CODEX_SESSION_ID", "CODEX_SANDBOX"]) expect(agentEnv({ [k]: "1" }), k).toBe(true);
    // A person's own shell: Codex's config variables, an API key, a profile.
    expect(agentEnv({ CODEX_HOME: "/home/x/.codex", CODEX_API_KEY: "sk-x", CODEX_PROFILE: "work", PATH: "/bin" })).toBe(false);
    expect(isAgentProcess("/Users/x/.local/bin/claude")).toBe(true);
    expect(isAgentProcess("/opt/homebrew/bin/codex")).toBe(true);
    expect(isAgentProcess("claude")).toBe(true);
    // A tmux session named codex, an editor on a file named claude: neither is the agent.
    expect(isAgentProcess("tmux")).toBe(false);
    expect(isAgentProcess("/usr/bin/vim")).toBe(false);
    expect(isAgentProcess("node")).toBe(false);
  });

  it("a committed .p2p-private marks the repository private", () => {
    const r = gitRepo(join(d, "marked"), "https://github.com/acme/marked");
    expect(projectOf(r).repoPrivate).toBeUndefined();
    writeFileSync(join(r, PRIVATE_MARKER), "");
    expect(projectOf(r).repoPrivate).toBe(true);
  });
});

describe("project boundaries", () => {
  beforeAll(async () => {
    root = realpathSync(mkdtempSync(join(tmpdir(), "p2p-projects-")));
    repo.S = gitRepo(join(root, "shared"), "git@github.com:acme/shared.git");
    repo.P = gitRepo(join(root, "secret"), "git@github.com:acme/secret.git");
    // A clone of the same remote as S, somewhere else, carrying files that claim sharing.
    repo.C = gitRepo(join(root, "clone-of-shared"), "https://github.com/acme/shared.git");
    repo.Q = gitRepo(join(root, "other"), "git@github.com:acme/other.git");
    // Five users on one address (127.0.0.1) make about 110 connections a minute here, so the relay's
    // per-address limits (120 connections a minute) are raised, as in the other many-user suites. At the
    // default, a faster machine crossed the limit and a refused `ls` showed an older status (release dry run).
    relay = await startRelay(R, { limits: { connectsPerIpPerMinute: 100_000, authsPerIpPerMinute: 100_000, authsPerIpv4PerMinute: 100_000, httpPerIpPerMinute: 100_000 } });
    const t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    transport = t;
    ann = new User("ann", t);
    ben = new User("ben", t);
    cat = new User("cat", t);
    dan = new User("dan", t);
    eve = new User("eve", t);
    for (const u of [ann, ben, cat, dan, eve]) {
      u.autoShareProject = false;
      ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
    }
    team = (await ann.ok(["circle", "create", "team"])).cid;
    await ann.ok(["circle", "default", team]);
    // Ben joins ann's circle with her code: friends, the circle, and it becomes his default.
    const inv = await ann.ok(["invite", "ben"]);
    const j = await alongside(ben.run(["join", "--confirmed", inv.code, "--wait", "12"]), () => ann.ok(["invites"]));
    expect(j.code).toBe(0);
    for (let i = 0; i < 10; i++) {
      await ann.ok(["invites"]);
      if ((await ben.ok(["circle", "ls"])).circles.some((c: { cid: string; joined?: boolean }) => c.cid === team && c.joined)) break;
    }
    // Cat is only ann's friend.
    await cat.ok(["accept", (await ann.ok(["invite", "--link"])).link]);
    await ann.ok(["friends"]);
    await eve.ok(["accept", (await ann.ok(["invite", "--link"])).link]);
    await ann.ok(["friends"]);
    // Ben's own session, in his own project, shared with the circle: a live session ann's could message.
    await inDir(ben, repo.Q).ok(["project", "share", team]);
    await inDir(ben, repo.Q).ok(["status", "--session", "bs1", "--state", "busy", "--label", "ben"]);
    // Ann shares S with the circle; P stays as it is (never shared: private).
    await inDir(ann, repo.S).ok(["project", "share", team]);
  }, 120_000);

  afterAll(async () => {
    await relay?.close().catch(() => {});
    for (const u of [ann, ben, cat, dan, eve]) u?.cleanup();
    rmSync(root, { recursive: true, force: true });
  });

  it("a session in a private project is never visible to the circle: no status, no ls row, no summary", async () => {
    const st = await inDir(ann, repo.P).ok(["status", "--session", "p1", "--state", "busy", "--label", "secret", "--summary", "Rewriting the billing secrets", "--file", "src/keys.ts"]);
    expect(st.roster).toMatchObject({ vis: "private", parts: [] });
    expect(st.delivered).toEqual([]);
    expect(st.status.summary).toBeUndefined();
    expect(st.project).toMatchObject({ policy: "private", projects: [{ name: "secret" }] });
    expect(st.project.why).toMatch(/isn't shared \(projects are private until you share them\)/);
    const ls = await ben.ok(["ls", "--all"]);
    expect(ls.peers.some((p: { own: string; sid: string }) => p.own === ids.ann && p.sid === "p1")).toBe(false);
    expect(JSON.stringify(ls)).not.toContain("billing");
    // Who it reaches, as an extension sees it: nobody.
    const app = await inDir(ann, repo.P).app();
    await app.load();
    try {
      expect(await sessionAudience(app, "p1")).toMatchObject({ vis: "private", people: 0, members: [] });
    } finally {
      await app.close();
    }
  });

  it("a shared project works as before: status, summary and files reach the circle, messages go both ways", async () => {
    const st = await inDir(ann, repo.S).ok(["status", "--session", "s1", "--state", "busy", "--label", "shared", "--summary", "Fixing the login form", "--file", "src/login.ts"]);
    expect(st.roster).toMatchObject({ vis: "circle", circle: team });
    expect(st.delivered.map((d: { userId: string }) => d.userId)).toEqual([ids.ben]);
    expect(st.project).toMatchObject({ policy: "shared", circles: [team] });
    const row = (await ben.ok(["ls"])).peers.find((p: { own: string; sid: string }) => p.own === ids.ann && p.sid === "s1");
    expect(row).toMatchObject({ summary: "Fixing the login form", files: ["src/login.ts"] });
    const sent = await inDir(ben, repo.Q).ok(["send", "--from-session", "bs1", "--to", `${ids.ann}/s1`, "--stdin"], { stdin: "hi from ben" });
    expect(sent.delivered).toBe(true);
    const back = await inDir(ann, repo.S).ok(["send", "--from-session", "s1", "--to", `${ids.ben}/bs1`, "--stdin"], { stdin: "hi back" });
    expect(back.delivered).toBe(true);
    // Cat is ann's friend but not in the circle the project shares: refused.
    const toCat = await inDir(ann, repo.S).run(["send", "--from-session", "s1", "--to", ids.cat, "--stdin"], { stdin: "x" });
    expect(toCat.json).toMatchObject({ error: "not_shared" });
  });

  it("an agent in a private session can't send anything out: p2p send, extension kinds, offline copies", async () => {
    const before = (await events(ben)).length;
    // To ben's live session, and to ben with no session named.
    for (const to of [`${ids.ben}/bs1`, ids.ben]) {
      const r = await inDir(ann, repo.P).run(["send", "--from-session", "p1", "--to", to, "--stdin"], { stdin: "the secret plan" });
      expect(r.code).toBe(1);
      expect(r.json.error).toBe("not_shared");
      // The error says how the person widens it, never a flag for the caller.
      expect(r.json.reason).toMatch(/Only the person can widen this, by sharing the project secret themselves: `p2p project share <circle or friend>`/);
      expect(r.json.reason).not.toMatch(/--force|--allow|--override/);
    }
    // An extension kind (ix note, subgraph and impact go this way) from the same session.
    const app = await inDir(ann, repo.P).app();
    await app.load();
    // This App speaks as the front end (as its token would make it).
    app.front = true;
    try {
      await expect(sendExtension(app, { fromSession: "p1", to: ids.ben, kind: "x:ix.note", v: 1, body: { text: "the secret plan" }, fallback: "a note" })).rejects.toMatchObject({ code: "not_shared" });
      // Its extension state (an Ix footprint) reaches nobody.
      const pub = await publishExtensionState(app, { fromSession: "p1", kind: "x:ix.footprint", v: 1, body: { files: ["src/keys.ts"] }, fallback: "footprint", ttl: 60 });
      expect([...pub.delivered, ...pub.skipped].map((x) => x.userId)).not.toContain(ids.ben);
      // Your own devices are always allowed.
      await expect(assertMayReach(app, "p1", app.userId)).resolves.toBeUndefined();
    } finally {
      await app.close();
    }
    await ben.ok(["ls"]);
    const got = (await events(ben)).slice(before);
    expect(JSON.stringify(got)).not.toContain("secret plan");
    // The shared session's state does reach the circle.
    const sapp = await inDir(ann, repo.S).app();
    await sapp.load();
    sapp.front = true;
    try {
      const pub = await publishExtensionState(sapp, { fromSession: "s1", kind: "x:ix.footprint", v: 1, body: { files: ["src/login.ts"] }, fallback: "footprint", ttl: 60 });
      expect([...pub.delivered, ...pub.skipped].map((x) => x.userId)).toContain(ids.ben);
    } finally {
      await sapp.close();
    }
  });

  it("after a cd from a private project to a shared one, the session stays private until it ends", async () => {
    const a = await inDir(ann, repo.P).ok(["status", "--session", "m1", "--state", "busy", "--label", "m", "--summary", "private work"]);
    expect(a.roster.vis).toBe("private");
    const b = await inDir(ann, repo.S).ok(["status", "--session", "m1", "--state", "busy", "--label", "m", "--summary", "now in shared"]);
    expect(b.roster).toMatchObject({ vis: "private" });
    expect(b.delivered).toEqual([]);
    expect(b.project.projects.map((p: { name: string }) => p.name).sort()).toEqual(["secret", "shared"]);
    expect(b.project.why).toMatch(/secret isn't shared/);
    const r = await inDir(ann, repo.S).run(["send", "--from-session", "m1", "--to", `${ids.ben}/bs1`, "--stdin"], { stdin: "smuggled" });
    expect(r.json).toMatchObject({ error: "not_shared" });
    // The other way: shared first, then a file of the private project touched (P2P_PROJECT_DIRS, the mod's
    // --project-dir): from then on, private.
    const c = await inDir(ann, repo.S).ok(["status", "--session", "m2", "--state", "busy", "--label", "m2"]);
    expect(c.delivered.map((d: { userId: string }) => d.userId)).toEqual([ids.ben]);
    const d = await inDir(ann, repo.S, [join(repo.P, "src")]).ok(["status", "--session", "m2", "--state", "busy", "--label", "m2", "--summary", "read the secret"]);
    expect(d.roster.vis).toBe("private");
    expect(d.delivered).toEqual([]);
    // A later status from the shared folder alone doesn't undo it, nor does an explicit roster change.
    expect((await inDir(ann, repo.S).ok(["status", "--session", "m2", "--state", "idle", "--label", "m2"])).roster.vis).toBe("private");
    const widen = await inDir(ann, repo.S).run(["session", "roster", "m2", "--circle", team]);
    expect(widen.json).toMatchObject({ error: "not_shared" });
    const add = await inDir(ann, repo.S).run(["session", "roster", "m2", "--add", ids.ben]);
    expect(add.json).toMatchObject({ error: "not_shared" });
    // Subagents report through their session: the same id, the same boundary (`--agents-json`).
    const ag = await inDir(ann, repo.S).ok(["status", "--session", "m2", "--state", "busy", "--label", "m2", "--agents-json", JSON.stringify([{ id: "x1", type: "Explore", task: "t", state: "running", files: ["src/x.ts"], at: 1 }])]);
    expect(ag.delivered).toEqual([]);
  });

  it("a session working in two shared projects reaches only who both share", async () => {
    const two = gitRepo(join(root, "two"), "git@github.com:acme/two.git");
    await inDir(ann, two).ok(["project", "share", "--person", ids.cat]);
    // Shared with the circle, and with cat alone: nobody in common.
    const st = await inDir(ann, repo.S, [two]).ok(["status", "--session", "i1", "--state", "busy", "--label", "i"]);
    expect(st.roster.vis).toBe("private");
    expect(st.project.why).toMatch(/share nobody in common/);
    // Both shared with the circle: the circle.
    await inDir(ann, two).ok(["project", "share", "--add", team]);
    const st2 = await inDir(ann, repo.S, [two]).ok(["status", "--session", "i2", "--state", "busy", "--label", "i"]);
    expect(st2.roster).toMatchObject({ vis: "circle", circle: team });
  });

  it("a cloned repository can't widen anything: files claiming sharing are ignored, its marker only narrows", async () => {
    // Every file a repository might use to claim a share, committed in the clone.
    mkdirSync(join(repo.C, ".p2p", "cli"), { recursive: true });
    const claim = JSON.stringify({ v: 1, share: { circles: [team] }, projects: { any: { share: { circles: [team], people: [ids.ben] } } } });
    for (const f of [".p2p-project.json", ".peer2peer.json", ".p2p-shared", join(".p2p", "projects.json"), join(".p2p", "cli", "projects.json"), ".p2p.json"]) writeFileSync(join(repo.C, f), claim);
    // Same remote as the shared project, another clone: its own project, unmapped, private.
    const st = await inDir(ann, repo.C).ok(["status", "--session", "c1", "--state", "busy", "--label", "clone"]);
    expect(st.roster.vis).toBe("private");
    expect(st.delivered).toEqual([]);
    expect((await inDir(ann, repo.C).ok(["project", "show"])).project).toMatchObject({ policy: "private", why: "unmapped" });
    // A committed .p2p-private in the shared project's own tree: private at once, and sharing it is refused.
    writeFileSync(join(repo.S, PRIVATE_MARKER), "");
    try {
      const m = await inDir(ann, repo.S).ok(["status", "--session", "k1", "--state", "busy", "--label", "k"]);
      expect(m.roster.vis).toBe("private");
      expect(m.project.why).toMatch(/asks to stay private/);
      const share = await inDir(ann, repo.S).run(["project", "share", team]);
      expect(share.json).toMatchObject({ error: "repo_private" });
    } finally {
      rmSync(join(repo.S, PRIVATE_MARKER));
    }
    // The policy lives only in the user's state, never as a file in the repository.
    expect(readdirSync(repo.S)).toEqual([".git"]);
  });

  it("a message to the user is never routed into a session whose projects keep the sender out", async () => {
    // Eve: ann's friend, whose own project is shared with ann. She has never seen a session of ann's.
    const eapp = await inDir(eve, repo.Q).ok(["project", "share", "--person", ids.ann]);
    expect(eapp.project.policy).toBe("shared");
    await inDir(eve, repo.Q).ok(["status", "--session", "es1", "--state", "idle", "--label", "eve"]);
    // Ann: p1 live and private; s3 live and shared with cat only (another project).
    const catOnly = gitRepo(join(root, "cat-only"), "git@github.com:acme/cat-only.git");
    await inDir(ann, catOnly).ok(["project", "share", "--person", ids.cat]);
    await inDir(ann, repo.P).ok(["status", "--session", "p1", "--state", "idle", "--label", "secret"]);
    await inDir(ann, catOnly).ok(["status", "--session", "s3", "--state", "idle", "--label", "cat"]);
    // Eve sees no live session of ann's, so her message goes into her own session, for ann.
    await eve.ok(["ls"]);
    const sent = await inDir(eve, repo.Q).ok(["send", "--from-session", "es1", "--to", ids.ann, "--stdin"], { stdin: "for ann, no session" });
    expect(sent.to).toMatchObject({ own: ids.eve, sid: "es1" });
    await ann.ok(["ls"]);
    const ev = (await events(ann)).filter((e) => e.kind === "p2p.message" && e.data.text === "for ann, no session");
    expect(ev).toHaveLength(1);
    expect(ev[0].toSession).toBeUndefined();
    // Only her own terminal (p2p tui) may hold it: none of her live sessions reaches eve.
    expect(ev[0].data.routable).toEqual(["tui"]);
    for (const sid of ["p1", "s3"]) {
      const lines = await ann.watch(sid, 600);
      expect(lines.some((l) => l.text === "for ann, no session"), sid).toBe(false);
    }
    // A live session in a project shared with eve may hold the next one; the others still may not.
    const withEve = gitRepo(join(root, "with-eve"), "git@github.com:acme/with-eve.git");
    await inDir(ann, withEve).ok(["project", "share", "--person", ids.eve]);
    await inDir(ann, withEve).ok(["status", "--session", "s4", "--state", "idle", "--label", "eve"]);
    const app = await ann.app();
    await app.load();
    try {
      const r = await routableSessions(app, ids.eve);
      expect(r).toEqual(expect.arrayContaining(["tui", "s4"]));
      expect(r).not.toContain("p1");
      expect(r).not.toContain("s3");
    } finally {
      await app.close();
    }
  });

  it("a reply to a session that has since gone private isn't routed into it", async () => {
    // s4 (shared with eve) speaks to eve's session, then touches the private project.
    await inDir(ann, join(root, "with-eve")).ok(["send", "--from-session", "s4", "--to", `${ids.eve}/es1`, "--stdin"], { stdin: "question" });
    await inDir(ann, join(root, "with-eve"), [repo.P]).ok(["status", "--session", "s4", "--state", "idle", "--label", "eve"]);
    // Eve's reply straight into s4 (its last shared status is still live for her) is dropped by ann's device.
    await eve.ok(["ls"]);
    await inDir(eve, repo.Q).ok(["send", "--from-session", "es1", "--to", `${ids.ann}/s4`, "--stdin"], { stdin: "reply into s4" });
    // And once s4's status ages out for her, a reply in her own session (the one s4 spoke to) isn't routed to s4.
    const eapp = await eve.app();
    await eapp.load();
    await eapp.state.update("peers", (cur = {}) => ({ next: Object.fromEntries(Object.entries(cur).filter(([, v]) => v.own !== ids.ann)), result: undefined }));
    await eapp.close();
    await inDir(eve, repo.Q).ok(["send", "--from-session", "es1", "--to", ids.ann, "--stdin"], { stdin: "reply in es1" });
    await ann.ok(["ls"]);
    const all = await events(ann);
    expect(all.some((e) => e.data.text === "reply into s4")).toBe(false);
    const reply = all.filter((e) => e.kind === "p2p.message" && e.data.text === "reply in es1");
    expect(reply).toHaveLength(1);
    expect(reply[0].toSession).toBeUndefined();
    expect(reply[0].data.routable).not.toContain("s4");
    const lines = await ann.watch("s4", 600);
    expect(lines.some((l) => l.text === "reply in es1" || l.text === "reply into s4")).toBe(false);
  });

  it("a roster signed elsewhere (another device of ours, an older client) can't widen a private session here", async () => {
    await inDir(ann, repo.P).ok(["status", "--session", "p2", "--state", "idle", "--label", "secret"]);
    const aapp = await ann.app();
    await aapp.load();
    const held = await aapp.store.getRoster(aapp.userId, "p2");
    // A wider roster for p2 at a higher version, signed by ann's identity: what an older client of hers could sign.
    const wide = createRosterV3(aapp.signer(), { sid: "p2", ver: (held?.ver ?? 1) + 5, vis: "circle", circle: team, parts: [] });
    await aapp.close();
    const bapp = await ben.app();
    await bapp.load();
    try {
      await bapp.connectAndDrain();
      const d = await bapp.deliver(ids.ann, "msg", { own: ids.ann, sid: "p2" }, { text: "in through a wider roster", roster: wide });
      expect(d.relays.length).toBeGreaterThan(0);
    } finally {
      await bapp.close();
    }
    await ann.ok(["ls"]);
    expect((await events(ann)).some((e) => e.data.text === "in through a wider roster")).toBe(false);
    // And p2's own roster, as this device signs it, is still private.
    expect((await inDir(ann, repo.P).ok(["status", "--session", "p2", "--state", "idle", "--label", "secret"])).roster.vis).toBe("private");
  });

  it("migration: a default circle no longer shares anything, and says so once", async () => {
    // Dan relied on his default circle: he joins the circle with a code (it becomes his default).
    const inv = await ann.ok(["invite", "dan"]);
    const j = await alongside(dan.run(["join", "--confirmed", inv.code, "--wait", "12"]), () => ann.ok(["invites"]));
    expect(j.code).toBe(0);
    // A circle with two members asks a second one to confirm it; approving it is the person's step.
    if (j.json.circle?.status === "needs-approval") await alongside(dan.ok(["held", "approve", j.json.circle.held, "--yes"]), () => ann.ok(["invites"]));
    for (let i = 0; i < 10; i++) {
      await ann.ok(["invites"]);
      if ((await dan.ok(["circle", "ls"])).circles.some((c: { cid: string; joined?: boolean }) => c.cid === team && c.joined)) break;
    }
    await dan.ok(["circle", "default", team]);
    const proj = gitRepo(join(root, "dan-app"), "git@github.com:dan/app.git");
    const first = await inDir(dan, proj).ok(["status", "--session", "d1", "--state", "busy", "--label", "app", "--summary", "dan's work"]);
    expect(first.roster.vis).toBe("private");
    expect(first.delivered).toEqual([]);
    const notice = (first.warnings ?? []).find((w: string) => w.startsWith("project boundaries:"));
    expect(notice).toMatch(/sessions no longer follow your default circle/);
    expect(notice).toContain(`p2p project share ${team}`);
    // Once per device.
    const again = await inDir(dan, proj).ok(["status", "--session", "d1", "--state", "busy", "--label", "app"]);
    expect((again.warnings ?? []).some((w: string) => w.startsWith("project boundaries:"))).toBe(false);
    const other = await inDir(dan, gitRepo(join(root, "dan-two"))).ok(["status", "--session", "d2", "--state", "busy", "--label", "two"]);
    expect((other.warnings ?? []).some((w: string) => w.startsWith("project boundaries:"))).toBe(false);
    // The quick way: `p2p project share` with nothing named shares this project with the default circle.
    const shared = await inDir(dan, proj).ok(["project", "share"]);
    expect(shared.project.circles.map((c: { cid: string }) => c.cid)).toEqual([team]);
    const now = await inDir(dan, proj).ok(["status", "--session", "d1", "--state", "busy", "--label", "app", "--summary", "dan's work"]);
    expect(now.roster).toMatchObject({ vis: "circle", circle: team });
    expect(now.delivered.map((d: { userId: string }) => d.userId).sort()).toEqual([ids.ann, ids.ben].sort());
  });

  it("the person's own session (tui) is never bound, and a script or agent naming it is refused", async () => {
    const r = await inDir(ann, repo.P).run(["send", "--from-session", "tui", "--to", ids.ben, "--stdin"], { stdin: "x" });
    expect(r.code).toBe(1);
    expect(r.json.reason).toMatch(/session tui is your own terminal's/);
    const s = await inDir(ann, repo.P).run(["status", "--session", "tui", "--state", "busy"]);
    expect(s.code).toBe(1);
    expect(s.json.reason).toMatch(/session tui is your own terminal's/);
  });

  it("a private repository nested inside a shared one, or reached through a symlink, binds as itself (H1)", async () => {
    const nested = gitRepo(join(repo.S, "vendor", "secret-lib"), "git@github.com:acme/secret-lib.git");
    try {
      // A folder under the session's own: no longer skipped by anyone.
      const a = await inDir(ann, repo.S, [join(nested, "src")]).ok(["status", "--session", "n1", "--state", "busy", "--label", "n"]);
      expect(a.roster.vis).toBe("private");
      expect(a.project.projects.map((x: { name: string }) => x.name)).toContain("secret-lib");
      // A status file inside it binds it too.
      const b = await inDir(ann, repo.S).ok(["status", "--session", "n2", "--state", "busy", "--label", "n", "--file", "vendor/secret-lib/keys.ts"]);
      expect(b.roster.vis).toBe("private");
      expect(b.delivered).toEqual([]);
      // A symlink inside the shared repository to the private one.
      symlinkSync(repo.P, join(repo.S, "secret-link"));
      const c = await inDir(ann, repo.S, [join(repo.S, "secret-link")]).ok(["status", "--session", "n3", "--state", "busy", "--label", "n"]);
      expect(c.roster.vis).toBe("private");
      expect(c.project.projects.map((x: { name: string }) => x.name)).toContain("secret");
    } finally {
      rmSync(join(repo.S, "vendor"), { recursive: true, force: true });
      rmSync(join(repo.S, "secret-link"), { force: true });
    }
  });

  it("more folders than the cap, or a front end that says it dropped some: private, never the first N (M1)", async () => {
    const many = Array.from({ length: 600 }, (_, i) => join(repo.S, `d${i}`));
    const a = await inDir(ann, repo.S, many).ok(["status", "--session", "o1", "--state", "busy", "--label", "o"]);
    expect(a.roster.vis).toBe("private");
    // Said as its own cause: too many folders, not a project count or an unresolved path.
    expect(a.project.why).toMatch(/more folders than Peer2Peer keeps track of/);
    expect(a.project.causes).toEqual(["folders"]);
    // --project-dir past the cap, and a front end's --project-dirs-over (the Codex bridge's).
    const flags = many.flatMap((x) => ["--project-dir", x]);
    expect((await inDir(ann, repo.S).ok(["status", "--session", "o3", "--state", "busy", "--label", "o", ...flags])).roster.vis).toBe("private");
    expect((await inDir(ann, repo.S).ok(["status", "--session", "o4", "--state", "busy", "--label", "o", "--project-dirs-over"])).roster.vis).toBe("private");
    const over = Object.create(ann) as User;
    Object.defineProperty(over, "env", { get: () => ({ ...ann.env, P2P_WORKDIR: repo.S, P2P_PROJECT_DIRS_OVER: "1" }) });
    expect((await over.ok(["status", "--session", "o2", "--state", "busy", "--label", "o"])).roster.vis).toBe("private");
  });

  it("inside an agent's session, nothing widens sharing, however p2p is reached (H4)", async () => {
    // An interpreter wrapper (python -c subprocess.run([...])) reaches the CLI with the agent's
    // environment (or, scrubbed, its process ancestry): the CLI itself refuses.
    const agent = Object.create(ann) as User;
    Object.defineProperty(agent, "env", { get: () => ({ ...ann.env, P2P_WORKDIR: repo.P, P2P_PERSON_TOKEN: "", CLAUDECODE: "1" }) });
    for (const args of [["project", "share", team], ["circle", "default", team], ["session", "roster", "s1", "--add", ids.cat], ["invite", "x"], ["trust", "add", ids.ben]]) {
      const r = await agent.run(args);
      expect(r.code, args.join(" ")).toBe(1);
      expect(r.json.error, args.join(" ")).toBe("refused");
    }
    expect((await inDir(ann, repo.P).ok(["project", "show"])).project.policy).toBe("private");
    // Reads, and narrowing, still work there.
    expect((await agent.run(["project", "show"])).code).toBe(0);
    expect((await agent.run(["project", "private"])).code).toBe(0);
    // The person's front end (its token) may.
    const yes = async () => true;
    await expect(assertPersonForWidening({ env: { CLAUDECODE: "1" }, front: true }, "project share", yes)).resolves.toBeUndefined();
    await expect(assertPersonForWidening({ env: { CLAUDECODE: "1" }, front: false }, "project share", yes)).rejects.toThrow(/only you run it/);
    // Outside an agent's session: the person's terminal "yes", never a flag.
    await expect(assertPersonForWidening({ env: {}, front: false }, "project share", async () => false)).rejects.toThrow(/confirm it with "yes" on your own terminal/);
    await expect(assertPersonForWidening({ env: {}, front: false }, "project share", yes)).resolves.toBeUndefined();
  });

  it("only a session's front end speaks for it: an agent's shell never, a registered session never without the token (N2)", async () => {
    const agent = Object.create(ann) as User;
    Object.defineProperty(agent, "env", { get: () => ({ ...ann.env, P2P_WORKDIR: repo.S, P2P_PERSON_TOKEN: "", CLAUDECODE: "1" }) });
    // A made-up session id, or the front end's own: refused from an agent's shell either way.
    const ok = await inDir(ann, repo.S).ok(["status", "--session", "front-1", "--state", "busy", "--label", "f"]);
    expect(ok.roster.vis).toBe("circle");
    for (const args of [
      ["status", "--session", "fake-1", "--state", "busy", "--label", "f", "--summary", "smuggled summary"],
      ["send", "--from-session", "fake-2", "--to", `${ids.ben}/bs1`, "--stdin"],
      ["send", "--from-session", "front-1", "--to", `${ids.ben}/bs1`, "--stdin"],
      ["status", "--session", "front-1", "--state", "idle", "--label", "hijacked"],
    ]) {
      const r = await agent.run(args, { stdin: "smuggled" });
      expect(r.json?.error, `${args.join(" ")}: ${r.out} ${r.err}`).toBe("refused");
    }
    // Outside any agent's session, without the token: a registered session is still the front end's,
    // not even to narrow it.
    const script = Object.create(ann) as User;
    Object.defineProperty(script, "env", { get: () => ({ ...ann.env, P2P_WORKDIR: repo.S, P2P_PERSON_TOKEN: "" }) });
    for (const args of [["send", "--from-session", "front-1", "--to", `${ids.ben}/bs1`, "--stdin"], ["status", "--session", "front-1", "--state", "idle", "--label", "x"]]) {
      expect((await script.run(args, { stdin: "x" })).json?.error, args.join(" ")).toBe("refused");
    }
    const narrow = await script.run(["session", "roster", "front-1", "--private"]);
    expect(narrow.json?.error).toBe("refused");
    expect(JSON.stringify(await ben.ok(["ls"]))).not.toContain("hijacked");
  });

  it("a session nobody used yet needs the person's terminal yes for a status, an extension send or state, not only a send (M1)", async () => {
    const out: string[] = [];
    const env = { ...ann.env, P2P_WORKDIR: repo.S, P2P_PERSON_TOKEN: "" };
    const run = async (args: string[], yes: boolean) => {
      const code = await main([...args, "--json"], { env, io: { out: (l) => out.push(l), err: () => {} }, confirmTty: async () => yes });
      process.exitCode = 0;
      return { code, json: JSON.parse(out.at(-1) ?? "{}") };
    };
    expect((await run(["status", "--session", "fresh-st", "--state", "busy", "--label", "f"], false)).json.error).toBe("refused");
    expect((await run(["status", "--session", "fresh-st", "--state", "busy", "--label", "f"], true)).code).toBe(0);
    // Once used, the same session goes on without asking again.
    expect((await run(["status", "--session", "fresh-st", "--state", "idle", "--label", "f"], false)).code).toBe(0);
    // An extension's state from a new session (an Ix footprint), through the App directly.
    const app = await inDir(ann, repo.S).app();
    await app.load();
    app.front = false;
    app.confirmTty = async () => false;
    try {
      await expect(publishExtensionState(app, { fromSession: "fresh-xs", kind: "x:ix.footprint", v: 1, body: {}, fallback: "fp", ttl: 60 })).rejects.toMatchObject({ code: "refused" });
      await expect(sendExtension(app, { fromSession: "fresh-xe", to: ids.ben, kind: "x:ix.note", v: 1, body: {}, fallback: "n" })).rejects.toMatchObject({ code: "refused" });
    } finally {
      await app.close();
    }
  });

  it("npm-installed Claude Code and Codex count as agents by their script path, not a word on the line (M1)", () => {
    expect(isAgentScript("node /usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js --resume x")).toBe(true);
    expect(isAgentScript("node --max-old-space-size=4096 /home/u/.npm/_npx/1/node_modules/@openai/codex/bin/codex.js")).toBe(true);
    expect(isAgentScript("node /work/scripts/build.js --label @anthropic-ai/claude-code")).toBe(false);
    expect(isAgentScript("node /work/claude-code-notes/index.js")).toBe(false);
  });

  it("a process detached from every terminal can't widen anything or send as the person, whatever it claims (H4-H6 residual)", async () => {
    // A child p2p, detached (setsid): no controlling terminal, no token, no agent variables.
    const bin = fileURLToPath(new URL("../../dist/bin.js", import.meta.url));
    const env: NodeJS.ProcessEnv = { PATH: process.env.PATH ?? "", ...ann.env, P2P_PERSON_TOKEN: "", P2P_WORKDIR: repo.P };
    delete env.P2P_PERSON_TOKEN;
    const runDetached = (args: string[]) =>
      new Promise<{ code: number; out: string }>((done) => {
        const c = spawn(process.execPath, [bin, ...args, "--json"], { env, detached: true, stdio: ["ignore", "pipe", "pipe"] });
        let out = "";
        let err = "";
        c.stdout.on("data", (d) => (out += String(d)));
        c.stderr.on("data", (d) => (err += String(d)));
        c.on("close", (code) => done({ code: code ?? 1, out: out || err }));
      });
    for (const args of [["project", "share", team, "--no-input"], ["circle", "default", team], ["send", "--from-session", "brand-new", "--to", ids.ben, "x"]]) {
      const r = await runDetached(args);
      expect(r.code, args.join(" ")).toBe(1);
      expect(r.out, args.join(" ")).toMatch(/"error":"refused"/);
    }
    expect((await inDir(ann, repo.P).ok(["project", "show"])).project.policy).toBe("private");
  });

  it("a pseudo-terminal inside an agent's session doesn't make it the person (H6)", async () => {
    const out: string[] = [];
    const err: string[] = [];
    const env = { ...ann.env, P2P_WORKDIR: repo.P, P2P_PERSON_TOKEN: "", CODEX_THREAD_ID: "thread-x" };
    // A picker and a prompt, as `script` or `expect` would give it: still refused.
    const code = await main(["send", "--to", ids.ben, "pty smuggle"], { env, io: { out: (l) => out.push(l), err: (l) => err.push(l), select: async () => [ids.ben], prompt: async () => "pty smuggle" } });
    process.exitCode = 0;
    expect(code).toBe(1);
    expect(err.join("\n")).toMatch(/sends as you, from your own terminal/);
  });

  it("own-device laundering: a message from a private session of yours makes the receiving session private, for good (M3)", async () => {
    // A second device of ann's (a linked home), as on another machine.
    const ann2 = new User("ann2", transport);
    ann2.autoShareProject = false;
    const a = await ann.app();
    await a.load();
    receiving(a);
    const start = await linkStart(a, {});
    const b = await ann2.app();
    const joined = await linkJoin(b, start.code, { label: "desk" });
    await Promise.all([start.wait(async (req) => req.compareCode === joined.compareCode), joined.wait()]);
    await a.close();
    await b.close();
    try {
      // s7, on the first device: live, shared with the circle; its status reaches ann2 too.
      expect((await inDir(ann, repo.S).ok(["status", "--session", "s7", "--state", "idle", "--label", "s7"])).roster.vis).toBe("circle");
      await ann2.ok(["ls"]);
      // On ann2, a session in a project nobody shared (private) messages s7.
      const priv = gitRepo(join(root, "desk-secret"), "git@github.com:acme/desk-secret.git");
      await inDir(ann2, priv).ok(["status", "--session", "o7", "--state", "busy", "--label", "o7"]);
      const sent = await inDir(ann2, priv).ok(["send", "--from-session", "o7", "--to", `${ids.ann}/s7`, "--stdin"], { stdin: "the secret, to launder" });
      expect(sent.delivered).toBe(true);
      await ann.ok(["ls"]);
      // s7 got it, and is private from now on: it can't carry it on to ben.
      const after = await inDir(ann, repo.S).ok(["status", "--session", "s7", "--state", "idle", "--label", "s7"]);
      expect(after.roster.vis).toBe("private");
      expect(after.project.why).toMatch(/a private session of yours sent it a message/);
      const r = await inDir(ann, repo.S).run(["send", "--from-session", "s7", "--to", `${ids.ben}/bs1`, "--stdin"], { stdin: "laundered" });
      expect(r.json).toMatchObject({ error: "not_shared" });
    } finally {
      ann2.cleanup();
    }
  });

  it("a bounded session won't message your own session on a device whose client can't honour the bound (M3)", async () => {
    const app = await ann.app();
    await app.load();
    try {
      // Another device of ann's, an older client: its session's status has no projects.v1.
      await app.state.update("peers", (cur = {}) => ({ next: { ...cur, [`${app.userId}|old-dev-sess`]: { own: app.userId, sid: "old-dev-sess", did: "d_olderdevice00000000000000", ts: Date.now(), status: { state: "idle", label: "old", caps: ["proto.3.1"] } } }, result: undefined }));
    } finally {
      await app.close();
    }
    const r = await inDir(ann, repo.P).run(["send", "--from-session", "p1", "--to", `${ids.ann}/old-dev-sess`, "--stdin"], { stdin: "x" });
    expect(r.json).toMatchObject({ error: "not_shared" });
    expect(r.json.reason).toMatch(/doesn't keep project boundaries: update Peer2Peer there/);
  });

  it("a narrowed session leaves a blank private status with those it no longer reaches (LOW)", async () => {
    await inDir(ann, repo.S).ok(["status", "--session", "r1", "--state", "busy", "--label", "visible", "--summary", "shared work"]);
    expect((await ben.ok(["ls"])).peers.find((x: { sid: string }) => x.sid === "r1")).toMatchObject({ summary: "shared work" });
    await inDir(ann, repo.S, [repo.P]).ok(["status", "--session", "r1", "--state", "busy", "--label", "visible", "--summary", "now private"]);
    const row = (await ben.ok(["ls", "--all"])).peers.find((x: { own: string; sid: string }) => x.own === ids.ann && x.sid === "r1");
    expect(row).toMatchObject({ label: "private", state: "idle" });
    expect(row.summary).toBeUndefined();
    expect(JSON.stringify(row)).not.toContain("now private");
  });

  it("a blank private status that doesn't go out is said, never swallowed", async () => {
    await inDir(ann, repo.S).ok(["status", "--session", "r2", "--state", "busy", "--label", "visible"]);
    const app = await inDir(ann, repo.S, [repo.P]).app();
    await app.load();
    receiving(app);
    // Ben's relay refuses the blank status (as a relay at its limit would).
    const deliver = app.deliver.bind(app);
    app.deliver = async (to, kind, ...rest) => {
      if (to === ids.ben && kind === "status") throw new Error("relay refused (rate-limited)");
      return deliver(to, kind, ...rest);
    };
    try {
      const r = await sendStatus(app, { session: "r2", state: "busy", label: "visible" });
      expect(r.roster.vis).toBe("private");
      expect(r.warnings?.join("\n")).toMatch(/blank private status didn't reach ben@.*relay refused \(rate-limited\)/);
    } finally {
      await app.close();
    }
  });

  it("project commands: show, ls, share (circles you joined, friends), private", async () => {
    const show = (await inDir(ann, repo.S).ok(["project", "show"])).project;
    expect(show).toMatchObject({ name: "shared", kind: "git", remote: "github.com/acme/shared", policy: "shared", circles: [{ cid: team, joined: true }] });
    const ls = (await ann.ok(["project", "ls"])).projects;
    expect(ls.map((p: { name: string }) => p.name)).toEqual(expect.arrayContaining(["shared", "two", "cat-only"]));
    // Listed only as private (the agent test narrowed it), never as shared.
    expect(ls.find((p: { name: string }) => p.name === "secret")?.policy ?? "private").toBe("private");
    expect((await inDir(ann, repo.P).run(["project", "share", "c_notacircle0000000000000000"])).code).toBe(1);
    const stranger = await inDir(cat, repo.P).run(["project", "share", "--person", ids.ben]);
    expect(stranger.json).toMatchObject({ error: "usage" });
    expect(stranger.json.reason).toMatch(/isn't your friend/);
    const priv = await inDir(ann, repo.Q).ok(["project", "private"]);
    expect(priv.project).toMatchObject({ policy: "private" });
    expect(priv.project.why).toBeUndefined();
    const human = await inDir(ann, repo.P).run(["project", "show"], { json: false });
    expect(human.out).toMatch(/^secret {2}private {2}\(github\.com\/acme\/secret\)/);
    // The policy is in the user's state, not anywhere a repository could write.
    const state = readFileSync(join(ann.home, "cli", "projects.json"), "utf8");
    expect(state).toContain(projectOf(repo.S).id);
  });
});
