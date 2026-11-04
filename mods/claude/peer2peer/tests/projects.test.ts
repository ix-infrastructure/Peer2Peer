// Copyright 2026 Ix Infrastructure Inc.
//
// Project boundaries in the mod (the CLI enforces them: packages/p2p/src/projects.ts). The mod's
// part: only the person changes a project's policy (/peers project share|private typed, never the
// model's shell), the model's shell speaks only for this session, folders the session works in
// outside its own reach p2p (P2P_PROJECT_DIRS), a private session makes no summary model call,
// the one-time notice reaches the person, and a message for no session is held only where the CLI
// says its sender may reach.

import { describe, expect, test } from 'claude-code/testing'

import { isMutating, isUnder, mutatingP2PVerb, p2pSessionArgs, parsePeersArgs, pickHolder, routableOf, shellPaths, shellTokens, toolPaths, uncheckableShell } from '../hooks/lib'
import { BEN_ID, NOW_MS, flag, gather, message, ran, settle, sidOf, slash, start, typed, world, type World } from './world'

/** Every folder handed to the CLI so far (each goes once: the CLI keeps it bound). */
const handed = (w: World, verb = 'status') => ran(w, verb).flatMap(r => (r.env?.P2P_PROJECT_DIRS ?? '').split(':').filter(Boolean))

const PRIVATE = { sid: 'x', ref: 'ffffff', ver: 1, vis: 'private', parts: [] }

describe('project boundaries: guards (lib)', () => {
  test('`p2p project share|private` is the person\'s: refused from the shell; show and ls only read', () => {
    expect(mutatingP2PVerb('p2p project share c_team')).toBe('project share')
    expect(mutatingP2PVerb('p2p project share --person ben@bbbb-bbbb-bbbb-bbbb')).toBe('project share')
    expect(mutatingP2PVerb('cd ~/work/api && p2p project private')).toBe('project private')
    expect(mutatingP2PVerb('bash -c "p2p project share"')).toBe('project share')
    expect(mutatingP2PVerb('p2p project show --json')).toBe(null)
    expect(mutatingP2PVerb('p2p project ls')).toBe(null)
  })

  test('/peers project share and private are typed only; show and ls aren\'t', () => {
    expect(parsePeersArgs('project')).toEqual({ verb: 'project', args: ['show'] })
    expect(parsePeersArgs('project share c_team --person ben --add')).toEqual({ verb: 'project', args: ['share', 'c_team', '--person=ben', '--add'] })
    expect(isMutating(parsePeersArgs('project share'))).toBe(true)
    expect(isMutating(parsePeersArgs('project private'))).toBe(true)
    expect(isMutating(parsePeersArgs('project'))).toBe(false)
    expect(isMutating(parsePeersArgs('project ls'))).toBe(false)
    expect(parsePeersArgs('project share --force')).toMatchObject({ verb: 'usage' })
    expect(parsePeersArgs('project delete')).toMatchObject({ verb: 'usage' })
  })

  test('the session ids a shell command hands p2p', () => {
    expect(p2pSessionArgs('p2p send --from-session=abc --to ben hi')).toEqual(['abc'])
    expect(p2pSessionArgs('p2p send --from-session abc --to ben hi')).toEqual(['abc'])
    expect(p2pSessionArgs("p2p ix overlaps --session 'xyz'")).toEqual(['xyz'])
    expect(p2pSessionArgs('git log --session abc')).toEqual([])
  })

  test('the folders a tool call works on', () => {
    expect(toolPaths({ tool: 'Read', file_path: '/elsewhere/secret/a.ts' })).toEqual(['/elsewhere/secret/a.ts'])
    expect(toolPaths({ tool: 'Grep', path: 'C:\\work\\other' })).toEqual(['C:\\work\\other'])
    expect(toolPaths({ tool: 'Read', file_path: 'src/a.ts' })).toEqual([])
    expect(isUnder('/work/web/src/a.ts', '/work/web')).toBe(true)
    expect(isUnder('/work/web2/a.ts', '/work/web')).toBe(false)
  })

  test('a message for no session is held only among the sessions the CLI names', () => {
    const board = [
      { sid: 'private-repo', isPrivate: false, activeAt: 2, seenAt: NOW_MS },
      { sid: 'shared-repo', isPrivate: false, activeAt: 1, seenAt: NOW_MS },
    ]
    expect(pickHolder(board, NOW_MS, 90_000).holder).toBe('private-repo')
    expect(pickHolder(board, NOW_MS, 90_000, ['tui', 'shared-repo']).holder).toBe('shared-repo')
    expect(pickHolder(board, NOW_MS, 90_000, ['tui'])).toEqual({ noticeBy: undefined })
    expect(routableOf({ routable: ['a', 3, 'b'] })).toEqual(['a', 'b'])
    expect(routableOf({})).toBeUndefined()
  })
})

describe('project boundaries: the mod', () => {
  test('the model\'s shell can\'t share a project, nor speak for another session', async ($, on) => {
    const w = world(on)
    await start($, w)
    const share = await $.tool.call({ tool: 'Bash', tool_use_id: 'p1', command: 'p2p project share c_team' } as never)
    expect(JSON.stringify(share)).toMatch(/only they run it, with the \/peers command \(\/peers project|a project share, which only your user runs/)
    const other = await $.tool.call({ tool: 'Bash', tool_use_id: 'p2', command: 'cd ../shared && p2p send --from-session=made-up --to ben "the plan"' } as never)
    expect(JSON.stringify(other)).toContain('speaks only for this session')
    const own = await $.tool.call({ tool: 'Bash', tool_use_id: 'p3', command: `p2p send --from-session=${sidOf(w)} --to ben hi` } as never)
    expect(JSON.stringify(own)).not.toContain('speaks only for this session')
    expect(ran(w, 'project')).toEqual([])
  })

  test('/peers project share runs only when typed, in this session\'s folder', async ($, on) => {
    const w = world(on)
    await start($, w)
    const fromModel = await slash($, 'peers', 'project share c_team', 'model')
    expect(fromModel.text).toContain('Only what your user types')
    expect(ran(w, 'project')).toEqual([])
    await slash($, 'peers', 'project share c_team --person ben')
    const runs = ran(w, 'project', 'share')
    expect(runs.map(r => r.argv)).toContainEqual(['p2p', 'project', 'share', '--person=ben', '--json', '--', 'c_team'])
    expect(runs[0]?.env?.P2P_WORKDIR).toBe('/work/web')
    await slash($, 'peers', 'project')
    expect(ran(w, 'project', 'show').length).toBe(1)
  })

  test('a private session makes no summary model call (nobody would see it)', async ($, on) => {
    const w = world(on, { statusRoster: PRIVATE })
    w.cli['session roster'] = { body: { roster: PRIVATE } }
    await start($, w)
    await typed($, 'please fix the login validation bug')
    await gather(w)
    expect(w.modelCalls).toBe(0)
    expect(flag(ran(w, 'status').at(-1)?.argv ?? [], 'summary')).toBeUndefined()
  })

  test('the one-time notice reaches the person as a toast, pointing at /peers project share', async ($, on) => {
    const note = 'project boundaries: sessions no longer follow your default circle (c_team). Each project is private until you share it, so this session in web is seen only by your own devices. To share web with that circle, run `p2p project share c_team` in it (or /peers project share in Claude Code); `p2p project ls` lists what you shared'
    const w = world(on, { statusWarnings: [note] })
    await start($, w)
    await settle(w, () => w.toasts.some(t => t.includes('Project boundaries')))
    const toast = w.toasts.find(t => t.includes('Project boundaries')) ?? ''
    expect(toast).toContain('/peers project share c_team')
    expect(toast).not.toContain('`p2p project share')
  })

  test('a file read or changed outside this session\'s folder binds its project (P2P_PROJECT_DIRS)', async ($, on) => {
    const w = world(on, { gitTop: '/work/web' })
    await start($, w)
    await $.turn.start({ text: 'work', turnId: 't1' } as never)
    await $.tool.call({ tool: 'Read', tool_use_id: 'r1', file_path: '/work/secret/keys.ts' } as never)
    await $.tool.call({ tool: 'Read', tool_use_id: 'r2', file_path: '/work/web/src/a.ts' } as never)
    await $.turn.complete({ turnId: 't1', answer: '', durationMs: 1, isAborted: false, reason: 'answer' } as never)
    await settle(w, () => handed(w).includes('/work/secret') && handed(w).includes('/work/web/src'))
    const dirs = handed(w)
    // Inside its own folder too (a nested repository is its own project: the CLI decides by real path).
    expect(dirs).toEqual(expect.arrayContaining(['/work/secret', '/work/web/src']))
    // Every later p2p run of this session carries it: a send included.
    await $.session.send({ to: `${BEN_ID}`, text: 'hi' } as never).catch(() => undefined)
    // Never handed twice.
    expect(dirs.filter(x => x === '/work/secret')).toHaveLength(1)
  })

  test('a message for no session that the CLI routes elsewhere is not held here', async ($, on) => {
    const w = world(on)
    await start($, w)
    await slash($, 'peers', 'circle c_team')
    w.emit(message(w, { id: 'nr-1', toSession: undefined, own: BEN_ID, sid: 'ben-old', ref: 'eeeeee', text: 'not for a private project', routable: ['tui', 'some-other-session'] }))
    await gather(w)
    expect(w.statuses.at(-1)).not.toContain('held')
    w.emit(message(w, { id: 'nr-2', toSession: undefined, own: BEN_ID, sid: 'ben-old', ref: 'eeeeee', text: 'for this one', routable: ['tui', sidOf(w)] }))
    await gather(w)
    expect(w.statuses.at(-1)).toContain('1 held')
  })

  test('a shell command reading a private path binds it (H2): absolute, ~ and .. paths', async ($, on) => {
    const w = world(on, { gitTop: '/work/web' })
    await start($, w)
    await $.tool.call({ tool: 'Bash', tool_use_id: 'b1', command: 'cat /work/secret/keys.ts | head -5' } as never)
    await $.tool.call({ tool: 'Bash', tool_use_id: 'b2', command: "grep -r token ../other-repo/src && ls '~/notes'" } as never)
    await settle(w, () => handed(w).includes('/work/other-repo/src'))
    const dirs = handed(w)
    // A file's folder; a folder as named.
    expect(dirs).toEqual(expect.arrayContaining(['/work/secret', '/work/other-repo/src']))
    // A relative search root (Grep, Glob) resolves against where the session is.
    expect(toolPaths({ tool: 'Grep', pattern: 'x', path: '../third' }, '/work/web')).toEqual(['/work/third'])
  })

  test('a resumed conversation stays bound to the folders it worked in (H3)', async ($, on) => {
    const w = world(on, { gitTop: '/work/web', store: { 'dirs:claude-session-1': { dirs: ['/work/secret'], over: false, at: 1 } } })
    await start($, w)
    await settle(w, () => ran(w, 'status').length > 0)
    expect(handed(w)).toContain('/work/secret')
  })

  test('past the folder cap the CLI is told to keep it private, never the first N (M1)', async ($, on) => {
    const many = Array.from({ length: 600 }, (_, i) => `/work/many/d${i}`)
    const w = world(on, { gitTop: '/work/web', store: { 'dirs:claude-session-1': { dirs: many, over: false, at: 1 } } })
    await start($, w)
    await settle(w, () => ran(w, 'status').length > 0)
    expect(ran(w, 'status').at(-1)?.env?.P2P_PROJECT_DIRS_OVER).toBe('1')
  })
})

describe('project boundaries: the shell guard (H4, H5)', () => {
  test('words are read as the shell reads them: quoting can\'t hide a session id', () => {
    expect(shellTokens("p2p send --from-session=''x1 --to b")).toEqual(['p2p', 'send', '--from-session=x1', '--to', 'b'])
    expect(shellTokens('a "b c"d $\'e\\\'f\' g\\ h')).toEqual(['a', 'b cd', "e'f", 'g h'])
    expect(p2pSessionArgs("p2p send --from-session=''x1 --to ben hi")).toEqual(['x1'])
    expect(p2pSessionArgs('p2p send --from-session "x"1 --to ben hi')).toEqual(['x1'])
    expect(p2pSessionArgs('p2p send --from-\\session x1')).toEqual(['x1'])
    expect(shellPaths('cat /a/b ../c ~/d e', '/w/r', '/home/u')).toEqual({ paths: ['/a/b', '/w/c', '/home/u/d'], over: false })
    // $HOME and $PWD expand; any other expansion in a path can't be resolved: private.
    expect(shellPaths('cat $HOME/notes/a.md ${PWD}/../x', '/w/r', '/home/u')).toEqual({ paths: ['/home/u/notes', '/w/x'], over: false })
    expect(shellPaths('cat $SECRET_DIR/keys', '/w/r', '/home/u').over).toBe(true)
    expect(shellPaths('cat "$(echo /secret)/k"', '/w/r', '/home/u').over).toBe(true)
    // Relative ones resolve against the folder (a symlink in it binds its target's project, in the CLI).
    expect(shellPaths('cat link/inside.txt', '/w/r').paths).toEqual(['/w/r/link'])
    // Past the per-command cap: private, never the first N.
    expect(shellPaths(Array.from({ length: 300 }, (_, i) => `/p${i}/x`).join(' '), '/w/r').over).toBe(true)
    // Padding can't push a session id past what is read.
    expect(p2pSessionArgs(`p2p ${'x '.repeat(6000)} --from-session fake --to ben hi`)).toEqual(['fake'])
  })

  test('interpreter code, pseudo-terminals and project shares on a line naming p2p are refused', () => {
    for (const cmd of [
      'python3 -c \'import subprocess; subprocess.run(["p2p","project","share","c_team"])\'',
      'node -e \'require("child_process").execSync("p2p project share")\'',
      'perl -e \'system("p2p", "send", "--to", "ben", "x")\'',
      'script -q /dev/null p2p send --to ben x',
      'expect -c \'spawn p2p send --to ben\'',
      'unbuffer p2p tui',
      'echo "project share" | xargs p2p',
    ]) expect([cmd, uncheckableShell(cmd) !== null || mutatingP2PVerb(cmd) !== null]).toEqual([cmd, true])
    expect(uncheckableShell('python3 -c "print(1)"')).toBe(null)
  })

  test('the model\'s shell can\'t speak for a made-up session however it quotes it', async ($, on) => {
    const w = world(on)
    await start($, w)
    const r = await $.tool.call({ tool: 'Bash', tool_use_id: 'q1', command: "p2p send --from-session=''fake --to ben hi" } as never)
    expect(JSON.stringify(r)).toContain('speaks only for this session')
  })
})
