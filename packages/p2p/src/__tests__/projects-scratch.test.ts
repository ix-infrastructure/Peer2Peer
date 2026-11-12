// Copyright 2026 Ix Infrastructure Inc.
//
// A long Claude Code session was refused because it "worked in more than 16 projects", most of them
// Claude Code's own scratch: its background tasks' output, the tool results it saved, its job
// folder. Two rules, adversarially: the cap is 64 (a storage bound: the ceiling is still the
// intersection of every project's policy), and this session's own scratch, matched by its exact id
// on real paths, is the session, not a project. Another session's folders, the shared memory folder,
// a lookalike name, a symlink or `..` out, a repository or `.p2p-private` in it, all still bind.

import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { hasDotDot, MAX_SESSION_PROJECTS, physicalPath, PRIVATE_MARKER, SCRATCH_ENV, scratchRoot, sessionScratch } from "../projects.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-projects-scratch.test/v3";
const UID = process.getuid?.() ?? 0;
const SLUG = "-home-u-src";

function gitRepo(dir: string, remote?: string): string {
  mkdirSync(join(dir, ".git"), { recursive: true });
  writeFileSync(join(dir, ".git", "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(dir, ".git", "config"), `[core]\n\tbare = false\n${remote ? `[remote "origin"]\n\turl = ${remote}\n` : ""}`);
  return dir;
}

/** A Claude Code session id (a UUID, as Claude Code names its folders). */
const sidOf = (n: number) => `${n.toString(16).padStart(8, "0")}-0b12-44d8-977c-705a1cdb2537`;

/** Claude Code's folders for session `csid`, under a fake config dir and temporary root. */
interface Scratch {
  csid: string;
  /** `<tmp>/claude-<uid>/<slug>/<csid>` */
  tasks: string;
  /** `<config>/projects/<slug>/<csid>` */
  session: string;
  /** `<config>/jobs/<csid's first 8>` */
  job: string;
  env: string;
}

describe("a session's own scratch: the folders it is matched by (sessionScratch, scratchRoot)", () => {
  let d: string;
  beforeAll(() => {
    d = realpathSync(mkdtempSync(join(tmpdir(), "p2p-scratch-unit-")));
  });
  afterAll(() => rmSync(d, { recursive: true, force: true }));

  it("takes this user's real folders, by this session's exact id", () => {
    const cfg = join(d, "cfg");
    const csid = sidOf(1);
    mkdirSync(join(d, "tmp", `claude-${UID}`), { recursive: true });
    mkdirSync(join(cfg, "projects"), { recursive: true });
    mkdirSync(join(cfg, "jobs", csid.slice(0, 8)), { recursive: true });
    const s = sessionScratch(JSON.stringify({ sid: csid, tmp: [join(d, "tmp"), join(d, "nowhere")], config: cfg, job: join(cfg, "jobs", csid.slice(0, 8)) }));
    expect(s).toEqual({ sid: csid, bases: [join(d, "tmp", `claude-${UID}`), join(cfg, "projects")], jobs: [join(cfg, "jobs", csid.slice(0, 8))] });
    const base = join(cfg, "projects");
    // Only `<base>/<one folder>/<this id>` and below.
    expect(scratchRoot(join(base, SLUG, csid), s!)).toBe(join(base, SLUG, csid));
    expect(scratchRoot(join(base, SLUG, csid, "tool-results"), s!)).toBe(join(base, SLUG, csid));
    expect(scratchRoot(join(base, "-other-slug", csid, "subagents"), s!)).toBe(join(base, "-other-slug", csid));
    for (const p of [
      base,
      join(base, SLUG),
      join(base, SLUG, "memory"),
      join(base, SLUG, sidOf(2)),
      join(base, SLUG, `${csid}-x`),
      join(base, SLUG, `${csid}x`),
      join(base, SLUG, csid.slice(0, 35)),
      join(base, csid),
      join(base, csid, "x"),
      join(cfg, "jobs"),
      join(cfg, "jobs", sidOf(2).slice(0, 8)),
      join(cfg, "jobs", `${csid.slice(0, 8)}x`),
      join(d, "elsewhere", SLUG, csid),
    ]) {
      expect([p, scratchRoot(p, s!)]).toEqual([p, undefined]);
    }
  });

  it("widening: refuses what isn't Claude Code's (an id's shape, a job of another id, a job folder elsewhere, a symlinked folder, junk)", () => {
    const cfg = join(d, "cfg2");
    const csid = sidOf(3);
    mkdirSync(join(cfg, "projects"), { recursive: true });
    mkdirSync(join(cfg, "jobs", "deadbeef"), { recursive: true });
    mkdirSync(join(d, "other-jobs", csid.slice(0, 8)), { recursive: true });
    for (const raw of [undefined, "", "not json", "[]", "null", JSON.stringify({ sid: "../x", config: cfg }), JSON.stringify({ sid: "short", config: cfg }), JSON.stringify({ sid: csid, config: "relative/cfg" })]) {
      expect([raw, sessionScratch(raw)]).toEqual([raw, undefined]);
    }
    // A job folder whose name isn't the start of this session's id, or that isn't in <config>/jobs: none.
    expect(sessionScratch(JSON.stringify({ sid: csid, config: cfg, job: join(cfg, "jobs", "deadbeef") }))?.jobs).toEqual([]);
    expect(sessionScratch(JSON.stringify({ sid: csid, config: cfg, job: join(d, "other-jobs", csid.slice(0, 8)) }))?.jobs).toEqual([]);
    expect(sessionScratch(JSON.stringify({ sid: csid, config: cfg, job: join(cfg, "jobs", csid.slice(0, 8), "..", "deadbeef") }))?.jobs).toEqual([]);
    // A per-user temporary folder (or projects folder) that is a symlink to somewhere else: not taken.
    const target = join(d, "real-target");
    mkdirSync(target, { recursive: true });
    mkdirSync(join(d, "tmp3"), { recursive: true });
    symlinkSync(target, join(d, "tmp3", `claude-${UID}`));
    const cfg3 = join(d, "cfg3");
    mkdirSync(cfg3, { recursive: true });
    symlinkSync(target, join(cfg3, "projects"));
    expect(sessionScratch(JSON.stringify({ sid: csid, tmp: [join(d, "tmp3")], config: cfg3 }))).toBeUndefined();
    // Another name than Claude Code's own (`claude-<uid>`) in the temporary root: not taken.
    mkdirSync(join(d, "tmp4", `claude-${UID + 1}`), { recursive: true });
    expect(sessionScratch(JSON.stringify({ sid: csid, tmp: [join(d, "tmp4")] }))).toBeUndefined();
  });

  it("walks a path as the file system does: `link/..` is the link's target's parent, not the link's", () => {
    mkdirSync(join(d, "pw", "a", "pub"), { recursive: true });
    mkdirSync(join(d, "pw", "a", "secret"), { recursive: true });
    mkdirSync(join(d, "pw", "scratch"), { recursive: true });
    symlinkSync(join(d, "pw", "a", "pub"), join(d, "pw", "scratch", "l"));
    // Raw strings: path.join would collapse the `..` before the code under test sees it.
    expect(physicalPath(`${d}/pw/scratch/l/../secret/key.txt`)).toBe(`${d}/pw/a/secret/key.txt`);
    expect(physicalPath(`${d}/pw/scratch/./x/../y`)).toBe(`${d}/pw/scratch/y`);
    expect(physicalPath(`${d}/pw/scratch/l/x`)).toBe(`${d}/pw/a/pub/x`);
    expect(hasDotDot(`${d}/pw/scratch/l/../secret`)).toBe(true);
    expect(hasDotDot(`${d}/pw/scratch/..`)).toBe(true);
    expect(hasDotDot(`${d}/pw/scratch/..x/x..`)).toBe(false);
  });
});

describe("a session's own scratch and the 64-project cap, end to end", () => {
  let relay: TestRelay;
  let ann: User;
  let cat: User;
  let team: string;
  let root: string;
  let cfg: string;
  let tmp: string;
  let work: string;
  let secret: string;
  const cats: { id: string } = { id: "" };
  let annId = "";
  let catSession = "";
  let n = 100;

  /** `u` working in `dir`, with the folders its front end reports and the scratch it names. */
  function inDir(u: User, dir: string, extra: string[] = [], scratch?: string): User {
    const v = Object.create(u) as User;
    Object.defineProperty(v, "env", {
      get: () => ({ ...u.env, P2P_WORKDIR: dir, ...(extra.length ? { P2P_PROJECT_DIRS: extra.join(":") } : {}), ...(scratch ? { [SCRATCH_ENV]: scratch } : {}) }),
    });
    return v;
  }

  /** A new Claude Code session's folders, made as Claude Code makes them. */
  function scratch(): Scratch {
    const csid = sidOf(n++);
    const tasks = join(tmp, `claude-${UID}`, SLUG, csid);
    const session = join(cfg, "projects", SLUG, csid);
    const job = join(cfg, "jobs", csid.slice(0, 8));
    mkdirSync(join(tasks, "tasks"), { recursive: true });
    writeFileSync(join(tasks, "tasks", "b96f26ph3.output"), "x");
    mkdirSync(join(session, "tool-results"), { recursive: true });
    mkdirSync(join(session, "subagents"), { recursive: true });
    writeFileSync(join(session, "tool-results", "r1.txt"), "x");
    mkdirSync(join(job, "tmp", "sbthome"), { recursive: true });
    return { csid, tasks, session, job, env: JSON.stringify({ sid: csid, tmp: [tmp], config: cfg, job }) };
  }

  let sess = 0;
  /** A fresh session working in the shared repository, with these extra paths and scratch: its project view. */
  async function bind(extra: string[], sc?: Scratch, dir = work) {
    return (await inDir(ann, dir, extra, sc?.env).ok(["status", "--session", `s${sess++}`, "--state", "busy", "--label", "s"])).project;
  }

  beforeAll(async () => {
    root = realpathSync(mkdtempSync(join(tmpdir(), "p2p-scratch-e2e-")));
    cfg = join(root, "claude-config");
    tmp = join(root, "tmp");
    mkdirSync(join(cfg, "projects", SLUG, "memory"), { recursive: true });
    writeFileSync(join(cfg, "projects", SLUG, "memory", "MEMORY.md"), "x");
    mkdirSync(join(tmp, `claude-${UID}`), { recursive: true });
    work = gitRepo(join(root, "work"), "git@github.com:acme/work.git");
    secret = gitRepo(join(root, "secret"), "git@github.com:acme/secret.git");
    mkdirSync(join(secret, "lib"), { recursive: true });
    writeFileSync(join(secret, "key.txt"), "k");
    relay = await startRelay(R, { limits: { connectsPerIpPerMinute: 100_000, authsPerIpPerMinute: 100_000, authsPerIpv4PerMinute: 100_000, httpPerIpPerMinute: 100_000 } });
    const t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    ann = new User("ann", t);
    cat = new User("cat", t);
    for (const u of [ann, cat]) {
      u.autoShareProject = false;
      const id = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
      if (u === cat) cats.id = id;
      else annId = id;
    }
    team = (await ann.ok(["circle", "create", "team"])).cid;
    await cat.ok(["accept", (await ann.ok(["invite", "--link"])).link]);
    await ann.ok(["friends"]);
    await inDir(ann, work).ok(["project", "share", team, "--person", cats.id]);
    const catDir = gitRepo(join(root, "cat-work"), "git@github.com:cat/work.git");
    await cat.ok(["friends"]);
    await inDir(cat, catDir).ok(["project", "share", "--person", annId]);
    await inDir(cat, catDir).ok(["status", "--session", "cs1", "--state", "busy", "--label", "cat"]);
    catSession = `${cats.id}/cs1`;
    await ann.ok(["ls"]);
  }, 120_000);

  afterAll(async () => {
    await relay?.close().catch(() => {});
    for (const u of [ann, cat]) u?.cleanup();
    rmSync(root, { recursive: true, force: true });
  });

  it("the reported case: this session's task output, saved tool results, subagents and job folder bind no project; it still sends", async () => {
    const s = scratch();
    const paths = [join(s.tasks, "tasks", "b96f26ph3.output"), join(s.tasks, "tasks"), join(s.session, "tool-results"), join(s.session, "subagents", "agent-1.jsonl"), join(s.job, "tmp"), join(s.job, "tmp", "sbthome"), join(s.job, "tmp", "not-yet.md")];
    const sid = `rc${sess++}`;
    const u = inDir(ann, work, paths, s.env);
    const st = (await u.ok(["status", "--session", sid, "--state", "busy", "--label", "i"])).project;
    expect(st).toMatchObject({ policy: "shared", circles: [team], people: [cats.id] });
    expect(st.projects.map((p: { name: string }) => p.name)).toEqual(["work"]);
    expect((await u.run(["send", "--from-session", sid, "--to", catSession, "--stdin"], { stdin: "hi" })).json.error).toBeUndefined();
    // The same paths without the scratch named (an older mod): each is a folder project, unshared, as before.
    const before = await bind(paths);
    expect(before.policy).toBe("private");
    expect(before.causes).toContain("unshared");
  });

  it("widening: another session's folders, the shared memory folder, transcripts and lookalike names still bind", async () => {
    const s = scratch();
    const other = scratch();
    for (const p of [
      join(other.tasks, "tasks", "b96f26ph3.output"),
      join(other.session, "tool-results"),
      join(other.job, "tmp"),
      join(cfg, "projects", SLUG, "memory", "MEMORY.md"),
      join(cfg, "projects", SLUG, `${other.csid}.jsonl`),
      join(cfg, "projects", SLUG, `${s.csid}.jsonl`),
      join(cfg, "projects", SLUG),
      join(tmp, `claude-${UID}`, SLUG),
    ]) {
      const st = await bind([p], s);
      expect([p, st.policy, st.causes]).toEqual([p, "private", ["unshared"]]);
    }
    // Lookalikes of this session's folder: a suffix, a longer id, the id one level too high.
    for (const name of [`${s.csid}-x`, `${s.csid}x`]) mkdirSync(join(cfg, "projects", SLUG, name, "tool-results"), { recursive: true });
    mkdirSync(join(cfg, "projects", s.csid), { recursive: true });
    for (const p of [join(cfg, "projects", SLUG, `${s.csid}-x`, "tool-results"), join(cfg, "projects", SLUG, `${s.csid}x`, "tool-results"), join(cfg, "projects", s.csid)]) {
      const st = await bind([p], s);
      expect([p, st.policy]).toEqual([p, "private"]);
    }
  });

  it("widening: a symlink out of the scratch, or a `..` through one, binds its real target", async () => {
    // A folder link, read through.
    const a = scratch();
    symlinkSync(secret, join(a.tasks, "tasks", "out"));
    const viaDir = await bind([join(a.tasks, "tasks", "out", "key.txt")], a);
    expect(viaDir.policy).toBe("private");
    expect(viaDir.projects.map((p: { name: string }) => p.name).sort()).toEqual(["secret", "work"]);
    // A file link, its folder named (as the Read tool's path reaches the CLI).
    const b = scratch();
    symlinkSync(join(secret, "key.txt"), join(b.session, "tool-results", "k.txt"));
    const viaFile = await bind([join(b.session, "tool-results")], b);
    expect(viaFile.projects.map((p: { name: string }) => p.name).sort()).toEqual(["secret", "work"]);
    // `link/..`: the shell goes to the link's target's parent; the path, as written, lands in the scratch.
    const c = scratch();
    mkdirSync(join(c.job, "tmp", "deep"), { recursive: true });
    symlinkSync(join(secret, "lib"), join(c.job, "tmp", "deep", "sub"));
    const viaDots = await bind([join(c.job, "tmp", "deep", "sub", "..", "key.txt")], c);
    expect(viaDots.projects.map((p: { name: string }) => p.name).sort()).toEqual(["secret", "work"]);
    // A dangling link still binds where it points.
    const e = scratch();
    symlinkSync(join(secret, "gone", "x"), join(e.tasks, "tasks", "dangling"));
    expect((await bind([join(e.tasks, "tasks")], e)).projects.map((p: { name: string }) => p.name).sort()).toEqual(["secret", "work"]);
    // A link into another of this session's scratch folders, which links out: that one's links bind too.
    const h = scratch();
    symlinkSync(join(h.session, "tool-results"), join(h.tasks, "tasks", "results"));
    symlinkSync(secret, join(h.session, "tool-results", "out"));
    expect((await bind([join(h.tasks, "tasks")], h)).projects.map((p: { name: string }) => p.name).sort()).toEqual(["secret", "work"]);
    // `..` out of the scratch, no link: where it lands.
    const f = scratch();
    const g = scratch();
    const out = await bind([join(f.tasks, "tasks", "..", "..", g.csid, "tasks")], f);
    expect(out.policy).toBe("private");
    expect(out.projects).toHaveLength(2);
  });

  it("widening: a repository, a .p2p-private, a path naming .git and a folder with a policy, inside the scratch, still bind", async () => {
    const s = scratch();
    // A clone made in the scratch keeps its identity (its remote): a private repository stays private.
    const clone = gitRepo(join(s.job, "tmp", "clone"), "git@github.com:acme/secret.git");
    const c = await bind([join(clone, "src")], s);
    expect(c.policy).toBe("private");
    expect(c.projects.map((p: { name: string }) => p.name).sort()).toEqual(["secret", "work"]);
    // A .p2p-private in a scratch folder.
    mkdirSync(join(s.tasks, "quiet"), { recursive: true });
    writeFileSync(join(s.tasks, "quiet", PRIVATE_MARKER), "");
    const q = await bind([join(s.tasks, "quiet")], s);
    expect(q).toMatchObject({ policy: "private", causes: ["repo-private"] });
    // A command that names a .git (it may have just removed one).
    mkdirSync(join(s.session, "tool-results", "was-a-repo"), { recursive: true });
    const g = await bind([join(s.session, "tool-results", "was-a-repo", ".git")], s);
    expect(g.policy).toBe("private");
    // A scratch folder the person made private themselves.
    const own = join(s.tasks, "tasks");
    await inDir(ann, own).ok(["project", "private"]);
    expect((await bind([own], s)).policy).toBe("private");
  });

  it("widening: a scratch named by something other than its front end, or a per-user folder that is a symlink, binds as before", async () => {
    // An agent's shell (no person token) can't speak for a session at all, scratch or not.
    const s = scratch();
    const agent = Object.create(inDir(ann, work, [join(s.tasks, "tasks")], s.env)) as User;
    const base = inDir(ann, work, [join(s.tasks, "tasks")], s.env);
    Object.defineProperty(agent, "env", { get: () => ({ ...base.env, P2P_PERSON_TOKEN: "", CLAUDECODE: "1" }) });
    const r = await agent.run(["status", "--session", "agent-s", "--state", "busy", "--label", "a"]);
    expect([r.code, r.json.error]).toEqual([1, "refused"]);
    // Claude Code's per-user temporary folder replaced by a symlink into a project: not scratch.
    const fakeTmp = join(root, "fake-tmp");
    const inside = join(root, "inside");
    mkdirSync(join(inside, SLUG, s.csid, "tasks"), { recursive: true });
    mkdirSync(fakeTmp, { recursive: true });
    symlinkSync(inside, join(fakeTmp, `claude-${UID}`));
    const env = JSON.stringify({ sid: s.csid, tmp: [fakeTmp] });
    const st = (await inDir(ann, work, [join(fakeTmp, `claude-${UID}`, SLUG, s.csid, "tasks")], env).ok(["status", "--session", `s${sess++}`, "--state", "busy", "--label", "s"])).project;
    expect(st.policy).toBe("private");
  });

  it("widening: `<scratch>/link/../sibling/…` binds the sibling of the link's target, not a folder in the scratch", async () => {
    // The link points at the shared repository; its parent's other child is the private one. The
    // file system reads <root>/secret/key.txt; a textual `..` would land in the scratch.
    const s = scratch();
    symlinkSync(work, join(s.tasks, "tasks", "l"));
    const raw = `${s.tasks}/tasks/l/../secret/key.txt`;
    const st = await bind([raw], s);
    expect(st.policy).toBe("private");
    expect(st.projects.map((p: { name: string }) => p.name).sort()).toEqual(["secret", "work"]);
  });

  it("widening: `<covered folder>/link/../x` under a --subfolders share binds where the file system lands, not the covered folder", async () => {
    const pub = join(root, "pubdir");
    mkdirSync(pub, { recursive: true });
    await inDir(ann, pub).ok(["project", "share", team, "--person", cats.id, "--subfolders"]);
    symlinkSync(join(secret, "lib"), join(pub, "l"));
    const raw = `${pub}/l/../key.txt`;
    const st = await bind([raw], undefined, pub);
    expect(st.policy).toBe("private");
    expect(st.projects.map((p: { name: string }) => p.name).sort()).toEqual(["pubdir", "secret"]);
  });

  it("widening: a folder in the scratch with a `.git` that can't be read still binds", async () => {
    const s = scratch();
    mkdirSync(join(s.tasks, "half"), { recursive: true });
    writeFileSync(join(s.tasks, "half", ".git"), "not a gitdir line\n");
    const st = await bind([join(s.tasks, "half", "x.txt")], s);
    expect(st.policy).toBe("private");
    expect(st.projects.map((p: { name: string }) => p.name).sort()).toEqual(["half", "work"]);
  });

  it(`a session in 17 to ${MAX_SESSION_PROJECTS} projects gets their intersection, and is private as soon as one is private or unshared`, async () => {
    expect(MAX_SESSION_PROJECTS).toBe(64);
    const repos: string[] = [];
    for (let i = 0; i < MAX_SESSION_PROJECTS - 1; i++) {
      const r = gitRepo(join(root, "many", `p${i}`), `git@github.com:acme/p${i}.git`);
      await inDir(ann, r).ok(["project", "share", team, "--person", cats.id]);
      repos.push(r);
    }
    // 17 projects (with `work`), and the full 64: every one shares the circle and cat, so the session does.
    for (const k of [16, MAX_SESSION_PROJECTS - 1]) {
      const st = await bind(repos.slice(0, k));
      expect([k, st.projects.length, st.policy, st.circles, st.people]).toEqual([k, k + 1, "shared", [team], [cats.id]]);
    }
    // One of them shares cat alone: the intersection is cat alone.
    const narrow = gitRepo(join(root, "narrow"), "git@github.com:acme/narrow.git");
    await inDir(ann, narrow).ok(["project", "share", "--person", cats.id]);
    const n1 = await bind([...repos.slice(0, MAX_SESSION_PROJECTS - 2), narrow]);
    expect([n1.projects.length, n1.policy, n1.circles, n1.people]).toEqual([MAX_SESSION_PROJECTS, "shared", [], [cats.id]]);
    // One made private, or one never shared: private, though 63 others are shared.
    const priv = gitRepo(join(root, "priv"), "git@github.com:acme/priv.git");
    await inDir(ann, priv).ok(["project", "private"]);
    const p1 = await bind([...repos.slice(0, MAX_SESSION_PROJECTS - 2), priv]);
    expect([p1.projects.length, p1.policy, p1.causes]).toEqual([MAX_SESSION_PROJECTS, "private", ["private"]]);
    const unshared = gitRepo(join(root, "unshared"), "git@github.com:acme/unshared.git");
    const u1 = await bind([...repos.slice(0, 20), unshared]);
    expect([u1.policy, u1.causes]).toEqual(["private", ["unshared"]]);
    // A private one among 17, sent from: refused.
    const sid = `cap${sess++}`;
    const u = inDir(ann, work, [...repos.slice(0, 15), priv]);
    await u.ok(["status", "--session", sid, "--state", "busy", "--label", "c"]);
    expect((await u.run(["send", "--from-session", sid, "--to", catSession, "--stdin"], { stdin: "x" })).json.error).toBe("not_shared");
    // Past the cap: private for good, and the refusal lists 16 names, then how many more.
    const over = await inDir(ann, work, [...repos, narrow]);
    const osid = `cap${sess++}`;
    expect((await over.ok(["status", "--session", osid, "--state", "busy", "--label", "c"])).project.causes).toContain("projects");
    const refused = await over.run(["send", "--from-session", osid, "--to", catSession, "--stdin"], { stdin: "x" });
    expect(refused.json.reason).toMatch(/more than 64 projects/);
    expect(refused.json.reason).toMatch(/ and 48 more,/);
  }, 120_000);
});
