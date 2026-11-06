// Copyright 2026 Ix Infrastructure Inc.
//
// Project boundaries without the noise (issue #45), adversarially. A device file (`2>/dev/null`) is
// no project; a shared folder outside git covers its subfolders, but never past a nested repository,
// a `.p2p-private`, a folder with its own policy, or a folder whose `.git` the path itself names
// (a command that may have just removed it); a policy a covered subfolder gets later still narrows
// a session bound before. Each cause of a private session has its own reason and remedy, and
// `p2p session show` lists them for the person only.

import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { dirProjectId, MAX_SESSION_PROJECTS, PRIVATE_MARKER, projectOf, pseudoPath, type ProjectsDoc } from "../projects.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-projects-folders.test/v3";

function gitRepo(dir: string, remote?: string): string {
  mkdirSync(join(dir, ".git"), { recursive: true });
  writeFileSync(join(dir, ".git", "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(dir, ".git", "config"), `[core]\n\tbare = false\n${remote ? `[remote "origin"]\n\turl = ${remote}\n` : ""}`);
  return dir;
}

/** A policies document sharing (or making private) these folders. */
function docOf(shared: string[], priv: string[] = []): ProjectsDoc {
  const projects: ProjectsDoc["projects"] = {};
  for (const root of shared) projects[dirProjectId(root)] = { name: "x", root, share: { circles: ["c_team"], people: [] }, at: 1 };
  for (const root of priv) projects[dirProjectId(root)] = { name: "x", root, share: "private", at: 1 };
  return { v: 1, projects };
}

describe("folder projects: a shared folder covers its subfolders, never past a boundary (projectOf)", () => {
  let d: string;
  let src: string;
  beforeAll(() => {
    d = realpathSync(mkdtempSync(join(tmpdir(), "p2p-folders-")));
    src = join(d, "src");
    mkdirSync(join(src, "tmp", "deep"), { recursive: true });
  });
  afterAll(() => rmSync(d, { recursive: true, force: true }));

  it("~/src shared covers ~/src/tmp and below, and a file not written yet there", () => {
    const doc = docOf([src]);
    for (const p of [join(src, "tmp"), join(src, "tmp", "deep"), join(src, "tmp", "new", "file.ts")]) expect(projectOf(p, doc), p).toMatchObject({ id: dirProjectId(src), kind: "dir", root: src });
    // Without the policies (sharing, `project share` in it): the folder itself.
    expect(projectOf(join(src, "tmp")).root).toBe(join(src, "tmp"));
    // No policy anywhere above: the folder itself, as before (private until shared).
    expect(projectOf(join(src, "tmp"), docOf([])).root).toBe(join(src, "tmp"));
  });

  it("widening: a nested git repository is always its own project, never the shared folder's", () => {
    const repo = gitRepo(join(src, "secret-repo"), "git@github.com:acme/secret.git");
    mkdirSync(join(repo, "lib"), { recursive: true });
    const doc = docOf([src]);
    for (const p of [repo, join(repo, "lib"), join(repo, "lib", "new.ts")]) expect(projectOf(p, doc), p).toMatchObject({ kind: "git", name: "secret" });
    // A .git that can't be read as one (a dangling file) stops the walk too.
    mkdirSync(join(src, "odd"), { recursive: true });
    writeFileSync(join(src, "odd", ".git"), "not a gitdir line");
    expect(projectOf(join(src, "odd"), doc).root).toBe(join(src, "odd"));
  });

  it("widening: a .p2p-private in a folder, or above it, keeps it private whatever covers it", () => {
    const priv = join(src, "priv");
    mkdirSync(join(priv, "inner"), { recursive: true });
    writeFileSync(join(priv, PRIVATE_MARKER), "");
    // A subfolder shared on its own below the marker doesn't lift it either.
    const doc = docOf([src, join(priv, "inner")]);
    expect(projectOf(priv, doc)).toMatchObject({ root: priv, repoPrivate: true });
    expect(projectOf(join(priv, "inner"), doc)).toMatchObject({ repoPrivate: true });
    // A marker at the shared folder itself: all of it.
    const top = join(d, "marked");
    mkdirSync(join(top, "a"), { recursive: true });
    writeFileSync(join(top, PRIVATE_MARKER), "");
    expect(projectOf(join(top, "a"), docOf([top]))).toMatchObject({ repoPrivate: true });
  });

  it("widening: a subfolder with its own policy is its own project (a private one stays private)", () => {
    const own = join(src, "own");
    mkdirSync(join(own, "x"), { recursive: true });
    const doc = docOf([src], [own]);
    expect(projectOf(join(own, "x"), doc)).toMatchObject({ id: dirProjectId(own), root: own });
    expect(projectOf(join(src, "tmp"), doc).root).toBe(src);
  });

  it("widening: a path that names a folder's .git or marker (rm -rf x/.git, x/.g*, x/{.git,a}) never lets a shared folder cover it", () => {
    const gone = join(src, "was-a-repo");
    mkdirSync(join(gone, "lib"), { recursive: true });
    const doc = docOf([src]);
    // Its .git is gone (removed by the very command that named it): the folder stays its own.
    for (const named of [join(gone, ".git"), join(gone, ".git", "config"), join(gone, PRIVATE_MARKER), join(gone, ".g*"), join(gone, "[.]git"), join(gone, "{.git,lib}")]) {
      expect(projectOf(named, doc), named).toMatchObject({ id: dirProjectId(gone), root: gone });
    }
    // A named marker in a folder that doesn't exist yet: its existing parent is the project, not the share above.
    expect(projectOf(join(src, "tmp", "nope", ".git"), doc).root).toBe(join(src, "tmp"));
    // A glob that can't match a dotfile (*.log), or a brace without a choice, still follows the share.
    expect(projectOf(join(src, "tmp", "*.log"), doc).root).toBe(src);
    expect(projectOf(join(src, "tmp", "${X}"), doc).root).toBe(src);
  });

  it("widening: a symlink into a private folder elsewhere is that folder, never the shared one it sits in", () => {
    const outside = join(d, "outside-secret");
    mkdirSync(outside, { recursive: true });
    symlinkSync(outside, join(src, "link"));
    expect(projectOf(join(src, "link"), docOf([src])).root).toBe(outside);
  });

  it("device and pseudo files are no project; a path through /proc to a real file is (Linux)", () => {
    if (process.platform === "win32") return;
    expect(pseudoPath("/dev/null")).toBe(true);
    expect(pseudoPath("/dev/zero")).toBe(true);
    // A folder in /dev, a path that isn't there, a regular file: not skipped (each binds as usual).
    expect(pseudoPath("/dev")).toBe(false);
    expect(pseudoPath("/dev/nope/x")).toBe(false);
    expect(pseudoPath(join(src, "tmp"))).toBe(false);
    // Widening: a link in a folder that points at /dev/null is named there: its folder binds.
    symlinkSync("/dev/null", join(src, "tmp", "null-link"));
    expect(pseudoPath(join(src, "tmp", "null-link"))).toBe(false);
    if (process.platform === "linux") {
      expect(pseudoPath("/proc/self/status")).toBe(true);
      // /proc/self/cwd and /proc/<pid>/root lead out of /proc: what they reach binds.
      writeFileSync(join(src, "tmp", "f.txt"), "x");
      expect(pseudoPath(`/proc/self/root${join(src, "tmp", "f.txt")}`)).toBe(false);
    }
  });
});

describe("folder projects and private reasons, end to end", () => {
  let relay: TestRelay;
  let ann: User;
  let cat: User;
  let team: string;
  let root: string;
  let src: string;
  let secret: string;
  const cats: { id: string } = { id: "" };
  let annId = "";
  /** Cat's live session, which ann's sessions may reach when their projects share cat. */
  let catSession = "";

  /** `u` working in `dir`, with more folders its front end reports, and what it says it dropped. */
  function inDir(u: User, dir: string, extra: string[] = [], over?: string): User {
    const v = Object.create(u) as User;
    Object.defineProperty(v, "env", { get: () => ({ ...u.env, P2P_WORKDIR: dir, ...(extra.length ? { P2P_PROJECT_DIRS: extra.join(":") } : {}), ...(over ? { P2P_PROJECT_DIRS_OVER: over } : {}) }) });
    return v;
  }

  beforeAll(async () => {
    root = realpathSync(mkdtempSync(join(tmpdir(), "p2p-folders-e2e-")));
    src = join(root, "src");
    mkdirSync(join(src, "tmp"), { recursive: true });
    mkdirSync(join(src, "hooks"), { recursive: true });
    mkdirSync(join(src, "types"), { recursive: true });
    secret = gitRepo(join(root, "secret"), "git@github.com:acme/secret.git");
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
    // The non-git folder ~/src, shared with the circle and with cat.
    await inDir(ann, src).ok(["project", "share", team, "--person", cats.id]);
    // Cat's own live session, shared with ann.
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

  it("a session in ~/src/tmp (and its mod's hooks/ and types/) is covered by ~/src's share: one project, shared", async () => {
    const st = await inDir(ann, join(src, "tmp"), [join(src, "hooks"), join(src, "types")]).ok(["status", "--session", "f1", "--state", "busy", "--label", "f"]);
    expect(st.project).toMatchObject({ policy: "shared", circles: [team], projects: [{ name: "src" }] });
    expect(st.project.projects).toHaveLength(1);
  });

  it("2>/dev/null is no project: no `dev`, and the session stays shared", async () => {
    const st = await inDir(ann, join(src, "tmp"), ["/dev/null", "/dev/zero"]).ok(["status", "--session", "f2", "--state", "busy", "--label", "f"]);
    expect(st.project.projects.map((p: { name: string }) => p.name)).toEqual(["src"]);
    expect(st.project.policy).toBe("shared");
  });

  it("widening: writing a new file into a private repo binds it, though the file isn't there yet", async () => {
    const st = await inDir(ann, join(src, "tmp"), [join(secret, "not", "yet", "there.ts")]).ok(["status", "--session", "f3", "--state", "busy", "--label", "f"]);
    expect(st.project.policy).toBe("private");
    expect(st.project.projects.map((p: { name: string }) => p.name).sort()).toEqual(["secret", "src"]);
  });

  it("widening: a policy a covered subfolder gets later narrows a session bound before it", async () => {
    const later = join(src, "later");
    mkdirSync(join(later, "x"), { recursive: true });
    const st = await inDir(ann, join(later, "x")).ok(["status", "--session", "f4", "--state", "busy", "--label", "f"]);
    expect(st.project).toMatchObject({ policy: "shared", projects: [{ name: "src" }] });
    // The person makes ~/src/later private after the session read it under ~/src's share.
    await inDir(ann, later).ok(["project", "private"]);
    const again = await inDir(ann, join(src, "hooks")).ok(["status", "--session", "f4", "--state", "busy", "--label", "f"]);
    expect(again.project).toMatchObject({ policy: "private" });
    expect(again.project.why).toMatch(/later is private/);
    expect((await inDir(ann, join(src, "hooks")).run(["send", "--from-session", "f4", "--to", catSession, "--stdin"], { stdin: "x" })).json.error).toBe("not_shared");
    // A session that never worked in it still reaches ~/src's audience.
    expect((await inDir(ann, join(src, "hooks")).ok(["status", "--session", "f5", "--state", "busy", "--label", "f"])).project.policy).toBe("shared");
  });

  it("Ian's case: ~5 projects, `$T/…` paths and 2>/dev/null: refused for the unresolved path, never with the 16-projects text", async () => {
    // What the mod hands the CLI for that session: its folders (5 projects), /dev/null, and that a path
    // ($T/x) couldn't be resolved.
    const repos = ["a", "b", "c", "d"].map((n) => gitRepo(join(root, `r-${n}`), `git@github.com:acme/${n}.git`));
    for (const r of repos) await inDir(ann, r).ok(["project", "share", team, "--person", cats.id]);
    const u = inDir(ann, join(src, "tmp"), [...repos, "/dev/null", join(src, "hooks")], "unresolved");
    const st = await u.ok(["status", "--session", "ian", "--state", "busy", "--label", "ian"]);
    expect(st.project.projects).toHaveLength(5);
    expect(st.project.projects.map((p: { name: string }) => p.name)).not.toContain("dev");
    expect(st.project.causes).toEqual(["unresolved"]);
    const r = await u.run(["send", "--from-session", "ian", "--to", catSession, "--stdin"], { stdin: "hi" });
    expect(r.json.error).toBe("not_shared");
    expect(r.json.reason).toMatch(/couldn't resolve/);
    expect(r.json.reason).toMatch(/start a new session/);
    expect(r.json.reason).not.toMatch(/more than 16 projects|512 folders|sharing each|by sharing/);
    expect(r.json.project).toMatchObject({ causes: ["unresolved"], sticky: true });
  });

  it("each cause has its own reason: the project cap, the folder cap, a dropped front end", async () => {
    // More than MAX_SESSION_PROJECTS projects.
    const many = Array.from({ length: MAX_SESSION_PROJECTS + 1 }, (_, i) => gitRepo(join(root, "many", `p${i}`)));
    const a = inDir(ann, join(src, "tmp"), many);
    expect((await a.ok(["status", "--session", "cap", "--state", "busy", "--label", "c"])).project.causes).toContain("projects");
    const r = await a.run(["send", "--from-session", "cap", "--to", catSession, "--stdin"], { stdin: "hi" });
    expect(r.json.reason).toMatch(new RegExp(`more than ${MAX_SESSION_PROJECTS} projects`));
    expect(r.json.reason).toMatch(/start a new session/);
    expect(r.json.reason).not.toMatch(/sharing each|by sharing/);
    // An older front end's bare "over", and the Codex bridge's flag with its reason.
    const front = await inDir(ann, join(src, "tmp"), [], "1").ok(["status", "--session", "fr", "--state", "busy", "--label", "c"]);
    expect(front.project).toMatchObject({ policy: "private", causes: ["front"] });
    expect(front.project.why).toMatch(/front end couldn't keep track/);
    const flag = await inDir(ann, join(src, "tmp")).ok(["status", "--session", "fl", "--state", "busy", "--label", "c", "--project-dirs-over=folders"]);
    expect(flag.project.causes).toEqual(["folders"]);
    // A word the CLI doesn't know still makes it private (as the front end), never nothing.
    expect((await inDir(ann, join(src, "tmp"), [], "bogus").ok(["status", "--session", "bg", "--state", "busy", "--label", "c"])).project.causes).toEqual(["front"]);
    // A project that's only unshared keeps the share hint (sharing it would help).
    const p = await inDir(ann, secret).run(["send", "--from-session", "sec", "--to", catSession, "--stdin"], { stdin: "x" });
    expect(p.json.reason).toMatch(/by sharing the project secret themselves/);
  });

  it("p2p session show: the person sees a session's projects, policies and reasons; an agent is refused", async () => {
    const v = await ann.ok(["session", "show", "ian"]);
    expect(v.session).toMatchObject({ sid: "ian", policy: "private", reasons: [{ cause: "unresolved" }] });
    expect(v.session.remedy).toMatch(/start a new session/);
    expect(v.session.projects.map((p: { name: string }) => p.name).sort()).toEqual(["a", "b", "c", "d", "src"]);
    expect(v.session.projects.find((p: { name: string }) => p.name === "src")).toMatchObject({ kind: "dir", root: src, policy: "shared", under: [join(src, "hooks"), join(src, "tmp")].sort() });
    // Human output too.
    const h = await ann.run(["session", "show", "ian"], { json: false });
    expect(h.out).toMatch(/private because/);
    // An agent (its environment, without the front end's token) reads no session's bindings, not even its own.
    const agent = Object.create(ann) as User;
    Object.defineProperty(agent, "env", { get: () => ({ ...ann.env, P2P_PERSON_TOKEN: "", CLAUDECODE: "1" }) });
    for (const sid of ["ian", "f1"]) {
      const r = await agent.run(["session", "show", sid]);
      expect(r.code).toBe(1);
      expect(r.json.error).toBe("refused");
      expect(JSON.stringify(r.json)).not.toContain(src);
    }
  });
});
