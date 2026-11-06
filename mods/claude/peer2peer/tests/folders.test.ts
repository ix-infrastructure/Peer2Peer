// Copyright 2026 Ix Infrastructure Inc.
//
// Project boundaries without the noise (issue #45), in the mod: which paths a shell command names.
// A device file isn't one; a variable expands only with the value the model's shell has; a program
// (sed, jq, awk, perl -e, sh -c) isn't a path, though the paths written in it are; an unresolved
// path in a first segment still makes the session private, with its own reason; a command that
// may remove a `.git` names it, so a shared folder never covers that folder afterwards. And
// /peers session, typed only.

import { describe, expect, test } from 'claude-code/testing'

import { isMutating, parsePeersArgs, sessionShowText, shellPaths, toolPathsAll } from '../hooks/lib'
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
    expect(sp('cat $CLAUDE_JOB_DIR/tmp/x ${CLAUDE_JOB_DIR}/y.txt', { CLAUDE_JOB_DIR: JOB })).toEqual({ paths: [`${JOB}/tmp/x`, JOB], over: false })
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
    expect(cd.paths).toEqual(expect.arrayContaining(['/work/api', '/work/api/sub', '/work/api/lib']))
    // ~user, ~+ and ~- are folders the mod doesn't know.
    for (const cmd of ['cat ~root/.ssh/id', 'ls ~+/x', 'cat ~-/k']) expect([cmd, sp(cmd).over]).toEqual([cmd, true])
    // A word that only mentions the name elsewhere ($HOME/source/x, a quoted "$HOME") is still known.
    expect(sp('cat $HOME/source/x.txt').paths).toEqual(['/home/u/source'])
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
    expect(sp('echo "$(cat /work/secret/k.txt)"').paths).toEqual(['/work/secret'])
    expect(sp('x=$(cat `ls /work/deep/a.txt`)').paths).toEqual(['/work/deep'])
  })

  test('sed, jq, awk and inline code are programs, not paths; the paths written inside them still bind', () => {
    expect(sp("sed -i 's#a/b#c/d#g' src/x.ts")).toEqual({ paths: ['/w/r/src'], over: false })
    // (A bare file name is the session's own folder, bound already: no path of its own.)
    expect(sp("sed -e 's|/usr/lib|/opt/lib|' -e 's/x/y/' conf.txt")).toEqual({ paths: [], over: false })
    expect(sp("jq -r '.a/b | .c' data.json")).toEqual({ paths: [], over: false })
    expect(sp("jq --arg k v -f ./prog.jq ../in.json").paths).toEqual(['/w/r', '/w'])
    expect(sp("awk -F: '{print $1/2}' /etc/passwd")).toEqual({ paths: ['/etc/passwd'], over: false })
    // The paths written inside: sed's r command, python's open, sh -c.
    expect(sp("sed 'r /work/secret/keys.txt' notes.txt").paths).toContain('/work/secret')
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
