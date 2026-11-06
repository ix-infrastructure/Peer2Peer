// Copyright 2026 Ix Infrastructure Inc.
//
// Project boundaries without the noise (issue #45), adversarially. A device file (`2>/dev/null`) is
// no project; a shared folder outside git covers its subfolders, but never past a nested repository,
// a `.p2p-private`, a folder with its own policy, or a folder whose `.git` the path itself names
// (a command that may have just removed it); a policy a covered subfolder gets later still narrows
// a session bound before. Each cause of a private session has its own reason and remedy, and
// `p2p session show` lists them for the person only.

import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { braceChoice, broadRoot, dirProjectId, MAX_SESSION_PROJECTS, NESTED_SCAN_ENTRIES, nestedBoundaries, PRIVATE_MARKER, projectOf, pseudoPath, type ProjectsDoc } from "../projects.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-projects-folders.test/v3";

function gitRepo(dir: string, remote?: string): string {
  mkdirSync(join(dir, ".git"), { recursive: true });
  writeFileSync(join(dir, ".git", "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(dir, ".git", "config"), `[core]\n\tbare = false\n${remote ? `[remote "origin"]\n\turl = ${remote}\n` : ""}`);
  return dir;
}

/** A policies document sharing (or making private) these folders; `covers`: shared with --subfolders. */
function docOf(shared: string[], priv: string[] = [], covers = true): ProjectsDoc {
  const projects: ProjectsDoc["projects"] = {};
  for (const root of shared) projects[dirProjectId(root)] = { name: "x", root, share: { circles: ["c_team"], people: [] }, ...(covers ? { covers: true as const } : {}), at: 1 };
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

  it("~/src shared with --subfolders covers ~/src/tmp and below, and a file not written yet in ~/src itself", () => {
    const doc = docOf([src]);
    for (const p of [join(src, "tmp"), join(src, "tmp", "deep"), join(src, "new-file.ts")]) expect(projectOf(p, doc), p).toMatchObject({ id: dirProjectId(src), kind: "dir", root: src });
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
    expect(projectOf(own, doc)).toMatchObject({ id: dirProjectId(own), root: own });
    // Below it, the private policy (which doesn't cover) stops the walk: its own folder, never shared, never ~/src's.
    expect(projectOf(join(own, "x"), doc)).toMatchObject({ id: dirProjectId(join(own, "x")), root: join(own, "x") });
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

describe("folder projects after the #49 review: gone folders, opt-in coverage, bare repositories", () => {
  let d: string;
  let src: string;
  beforeAll(() => {
    d = realpathSync(mkdtempSync(join(tmpdir(), "p2p-folders-review-")));
    src = join(d, "src");
    mkdirSync(join(src, "team"), { recursive: true });
  });
  afterAll(() => rmSync(d, { recursive: true, force: true }));

  it("widening (H2): a repository cloned into a covered folder, read, then deleted, is never covered from above", () => {
    // ~/src shared with --subfolders, ~/src/team has no policy; a clone in ~/src/team/tmp.
    const doc = docOf([src]);
    const clone = gitRepo(join(src, "team", "tmp"), "git@github.com:acme/secret.git");
    writeFileSync(join(clone, "key.txt"), "k");
    expect(projectOf(join(clone, "key.txt"), doc)).toMatchObject({ kind: "git", name: "secret" });
    rmSync(clone, { recursive: true, force: true });
    // What the front end reported before the delete (the folder, a file in it, the marker it found):
    // after it, each binds the nearest existing folder exactly, never ~/src.
    for (const p of [clone, join(clone, "key.txt"), join(clone, "lib", "deep"), join(clone, ".git")]) {
      expect(projectOf(p, doc), p).toMatchObject({ id: dirProjectId(join(src, "team")), root: join(src, "team") });
    }
    // A missing path whose nearest existing folder has a policy of its own binds that one.
    expect(projectOf(join(src, "gone", "x.ts"), doc).root).toBe(src);
    // A pattern in an existing folder still follows the share (its folder is there).
    expect(projectOf(join(src, "team", "*.md"), doc).root).toBe(src);
  });

  it("widening (H3): a policy without covers (every one from before --subfolders) is for that folder alone", () => {
    mkdirSync(join(src, "team", "a"), { recursive: true });
    const legacy = docOf([src], [], false);
    expect(projectOf(join(src, "team", "a"), legacy).root).toBe(join(src, "team", "a"));
    expect(projectOf(src, legacy).root).toBe(src);
    // A folder in between with a policy that doesn't cover stops the walk: the folder itself.
    const doc = docOf([src]);
    doc.projects[dirProjectId(join(src, "team"))] = { name: "team", root: join(src, "team"), share: { circles: ["c_other"], people: [] }, at: 1 };
    expect(projectOf(join(src, "team", "a"), doc).root).toBe(join(src, "team", "a"));
  });

  it("widening (M3): a bare repository, or one whose config says bare = true, is its own git project", () => {
    const doc = docOf([src]);
    const bare = join(src, "secret.git");
    mkdirSync(join(bare, "objects"), { recursive: true });
    mkdirSync(join(bare, "refs", "heads"), { recursive: true });
    writeFileSync(join(bare, "HEAD"), "ref: refs/heads/main\n");
    writeFileSync(join(bare, "config"), '[core]\n\tbare = true\n[remote "origin"]\n\turl = git@github.com:acme/bare-secret.git\n');
    for (const p of [bare, join(bare, "objects"), join(bare, "refs", "heads")]) expect(projectOf(p, doc), p).toMatchObject({ kind: "git", name: "bare-secret", root: bare });
    const cfgOnly = join(src, "cfg-only");
    mkdirSync(cfgOnly, { recursive: true });
    writeFileSync(join(cfgOnly, "config"), "[core]\n  bare = true\n");
    expect(projectOf(cfgOnly, doc)).toMatchObject({ kind: "git", root: cfgOnly });
    // A folder with a .git file (a worktree or submodule) is its own project, read or not.
    const wt = join(src, "wt");
    mkdirSync(wt, { recursive: true });
    writeFileSync(join(wt, ".git"), `gitdir: ${join(d, "nowhere")}\n`);
    expect(projectOf(wt, doc).root).toBe(wt);
    // A folder named like a repository (`x.repo`) is named as itself (M4): its own project, not its parent's.
    const dotted = gitRepo(join(src, "secret.repo"));
    expect(projectOf(dotted, doc)).toMatchObject({ kind: "git", root: dotted });
  });

  it("H3: subfolder coverage is refused for a home, temporary or system folder (an exact share is fine)", () => {
    for (const r of ["/", homedir(), dirname(homedir()), "/Users", "/home", "/home/someone", "/tmp", "/private/tmp", "/var", "/var/folders", "/var/folders/ab", "/var/folders/ab/cd/T", tmpdir(), "/usr", "/Volumes/disk", "/mnt/data"]) {
      expect(broadRoot(r), r).toBeDefined();
    }
    expect(broadRoot("/srv/www", { HOME: "/srv/www/me" })).toBeDefined();
    expect(broadRoot(src)).toBeUndefined();
    expect(broadRoot(join(homedir(), "src"))).toBeUndefined();
    expect(broadRoot("/tmp/project")).toBeUndefined();
  });

  it("linear on hostile input (CodeQL js/polynomial-redos): a brace with many commas", () => {
    const t = performance.now();
    expect(braceChoice(`{{,${",".repeat(50_000)}`)).toBe(false);
    expect(performance.now() - t).toBeLessThan(100);
    expect(projectOf(join(src, "team", `{{,${",".repeat(50_000)}`), docOf([src])).root).toBe(src);
    // Same answers as before: a choice inside one pair of braces, nothing across braces.
    for (const [c, want] of [["{.git,a}", true], ["{a..z}", true], ["x{a,b}y", true], ["{a}", false], ["{a,{b}", false], ["{,", false], ["a,b}", false], ["{a,}", true]] as const) expect([c, braceChoice(c)]).toEqual([c, want]);
  });

  it("H3: the nested repositories and .p2p-private folders below a covering share are listed, bounded", () => {
    const top = join(d, "scan");
    gitRepo(join(top, "a", "repo1"));
    mkdirSync(join(top, "b", "c"), { recursive: true });
    writeFileSync(join(top, "b", PRIVATE_MARKER), "");
    const bare = join(top, "b", "c", "bare.git");
    mkdirSync(join(bare, "objects"), { recursive: true });
    mkdirSync(join(bare, "refs"), { recursive: true });
    writeFileSync(join(bare, "HEAD"), "ref: refs/heads/main\n");
    const n = nestedBoundaries(top);
    expect(n.repos.sort()).toEqual([join(top, "a", "repo1"), bare].sort());
    expect(n.private).toEqual([join(top, "b")]);
    expect(n.capped).toBe(false);
    const wide = join(d, "wide");
    mkdirSync(wide, { recursive: true });
    for (let i = 0; i <= NESTED_SCAN_ENTRIES; i++) writeFileSync(join(wide, `f${i}`), "");
    expect(nestedBoundaries(wide).capped).toBe(true);
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
    await inDir(ann, src).ok(["project", "share", team, "--person", cats.id, "--subfolders"]);
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

  it("H3: covering is opt-in (--subfolders); refused for a temporary or system folder; nested repositories are listed", async () => {
    // Shared without --subfolders: that folder alone, as before; a session in a subfolder stays private.
    const exact = join(root, "exact");
    mkdirSync(join(exact, "sub"), { recursive: true });
    const shared = await inDir(ann, exact).ok(["project", "share", team]);
    expect(shared.project.covers).toBeUndefined();
    expect((await inDir(ann, join(exact, "sub")).ok(["status", "--session", "ex1", "--state", "busy", "--label", "e"])).project.policy).toBe("private");
    expect((await inDir(ann, exact).ok(["status", "--session", "ex2", "--state", "busy", "--label", "e"])).project.policy).toBe("shared");
    // --subfolders on a folder that holds the temporary folder, or a system one: refused, nothing stored.
    for (const dir of ["/tmp", "/usr"]) {
      const r = await ann.run(["project", "share", team, "--subfolders", "--dir", dir]);
      expect([dir, r.code, r.json.error]).toEqual([dir, 1, "usage"]);
      expect(r.json.message ?? r.json.reason ?? "").toMatch(/can't cover its subfolders/);
    }
    // The nested repositories and .p2p-private folders below are named in a warning.
    const wide = join(root, "wide");
    gitRepo(join(wide, "inner-repo"));
    mkdirSync(join(wide, "quiet"), { recursive: true });
    writeFileSync(join(wide, "quiet", PRIVATE_MARKER), "");
    const w = await inDir(ann, wide).ok(["project", "share", team, "--subfolders"]);
    expect(w.project.covers).toBe(true);
    expect(w.warnings.join("\n")).toContain(join(wide, "inner-repo"));
    expect(w.warnings.join("\n")).toContain(join(wide, "quiet"));
    // Widening: a session a covering share reached in a subfolder goes private when the share stops covering.
    mkdirSync(join(wide, "sub"), { recursive: true });
    expect((await inDir(ann, join(wide, "sub")).ok(["status", "--session", "cv1", "--state", "busy", "--label", "c"])).project.policy).toBe("shared");
    await inDir(ann, wide).ok(["project", "share", team]);
    expect((await inDir(ann, wide).ok(["status", "--session", "cv1", "--state", "busy", "--label", "c"])).project.policy).toBe("private");
    // `--add` keeps the coverage it had.
    await inDir(ann, wide).ok(["project", "share", team, "--subfolders"]);
    expect((await inDir(ann, wide).ok(["project", "share", "--add", "--person", cats.id])).project.covers).toBe(true);
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
