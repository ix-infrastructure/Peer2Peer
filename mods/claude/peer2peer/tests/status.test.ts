// Copyright 2026 Ix Infrastructure Inc.

import { describe, expect, test } from 'claude-code/testing'
import type { Engine } from 'claude-code/testing'
import type { On } from 'claude-code'

import type { PeerRow } from '../types'
import { cleanSummary, isNonAnswer, isStatusFile } from '../hooks/lib'
import { BEN, BEN_ADDR, flag, flags, gather, lastStatus, message, ran, settle, sidOf, start, typed, world } from './world'

describe('status summaries that are not status lines', () => {
  test('refusals, meta replies, questions and long replies are not published', () => {
    const garbage = [
      "I can't tell what tasks 1, 2, 3, 5 and '852' refer to from this message alone, so the status line would have to guess.",
      "I don't have enough context to write a status.",
      'I cannot determine the task.',
      "I'm not sure what the user is working on.",
      'Sorry, the request is unclear.',
      'Unfortunately there is no codebase work here.',
      'The request only mentions numbers, so there is nothing to summarise.',
      'Your message refers to tasks I cannot see.',
      'Which repository is this about?',
      'Could you clarify the task?',
      'Fixing login. Updating tests. Refactoring the router. Writing docs.',
      'Fixing login.\nUpdating tests.\nRefactoring the router.',
      'Without more context this is a guess.',
      // Review L1.
      'Sorry, I need more detail about which tasks you mean.',
      "Unfortunately I can't see which files are involved.",
      'Unclear what you want summarized here.',
      'Unclear what the work is.',
      'No clear work to summarize.',
      'No code changes to describe yet.',
      'The request asks about tasks 1, 2 and 3 without saying what they are.',
      'Your request is just a list of numbers.',
      'Summarizing is hard: it names things I cannot see.',
      // pre-release re-review L3.
      'The status line would need more detail.',
      'Status line would need more context to be useful.',
      // Meta talk with a first-person subject, anywhere in the line.
      'Hard to say: I only see your message, not the tasks it names.',
      'Nothing to report, since my status line would have to guess.',
      'Probably refactoring, but I would have to guess from the prompt.',
    ]
    for (const g of garbage) {
      expect(isNonAnswer(g), g).toBe(true)
      expect(cleanSummary(g), g).toBeUndefined()
    }
  })

  test('ordinary status lines pass, including ones about request handling in the code', () => {
    const good = [
      'Fixing the login form validation in src/login.tsx.',
      'Fixing the request parser in api/handler.ts. Adding tests for empty bodies.',
      'Refactoring the prompt builder and its message templates.',
      'Adding retry to the relay client (relay-client.ts).',
      'Implementing the x:ix.footprint state kind in ext-ix.',
      // Review M-c: lines the first version froze.
      'Adding the status line renderer to the mod band.',
      'Fixing the status-line overflow in narrow terminals.',
      'Fixing how the parser refers to imported symbols.',
      'Adding more context to relay error messages.',
      'Validating your request body in api/handler.ts.',
      'Ensuring the prompt is trimmed before the model call.',
      'Handling the request is too large error in the relay.',
      'Refactoring auth. Adding tests. Updating docs.',
      'I/O retries: adding backoff to the relay client.',
      "Sorry-path handling in checkout: fixing refunds.",
      "Can't-retry list for relay errors: adding 429 handling.",
      "Adding a 'my account' page to the web app.",
      'Unclear-state recovery for the sync loop.',
      // Review L1: openings that read like refusals but are work.
      'Status line: fixing the login form.',
      'Unfortunately-named flag cleanup: renaming --unsafe in the CLI.',
      'Sorry page redesign for checkout errors.',
      'Unfortunately the CI job flakes on node 22; pinning the image.',
      'Your request handler now validates content types.',
      'The request parser drops empty headers; fixing it in api/http.ts.',
      'The prompt builder gains a token budget.',
      'No-op migrations removed from the schema tool.',
      'Status line rendering for narrow terminals in the mod.',
      // pre-release re-review L3: these must pass.
      'My parser refactor: splitting the status line module.',
      'The request is now validated before routing in api/router.ts.',
      'Status line is now cached between renders.',
      'The request was being retried twice; fixing the backoff.',
      'The prompt is trimmed before the model call.',
      'No work-stealing in the scheduler yet: adding it to pool.ts.',
      'No task-queue changes; reworking the relay drain.',
      'We cannot see a reason for the flake; bisecting CI.',
    ]
    for (const g of good) {
      expect(isNonAnswer(g), g).toBe(false)
      expect(cleanSummary(g), g).toBe(g)
    }
  })
})

describe('status files', () => {
  test('background worktrees and .git are never working-on files', () => {
    expect(isStatusFile('src/a.ts')).toBe(true)
    expect(isStatusFile('.claude/settings.json')).toBe(true)
    expect(isStatusFile('.github/workflows/ci.yml')).toBe(true)
    expect(isStatusFile('.claude/worktrees/agent-a1b2/packages/codex-bridge/x.ts')).toBe(false)
    expect(isStatusFile('.Claude/Worktrees/agent-x/y.ts')).toBe(false)
    expect(isStatusFile('.git/config')).toBe(false)
    expect(isStatusFile('.git')).toBe(false)
  })
})

const BUSY_BEN: PeerRow = { ...BEN, repo: 'web', state: 'busy', summary: 'Refactoring the login form validation.', files: ['src/login.tsx', 'src/validate.ts'] }
const BEN_SESSION = `p2p:${BEN_ADDR}/api [a1b2c3]`

const edit = (path: string, id = 'e1') => ({ tool: 'Edit', tool_use_id: id, file_path: path, old_string: 'a', new_string: 'b' }) as never
const done = { turnId: 't1', answer: '', durationMs: 1, isAborted: false, reason: 'answer' } as never

describe('peer2peer working-on status', () => {
  test('a prompt becomes the shared status line, and edits become shared repo-relative files', async ($, on) => {
    const w = world(on, { gitTop: '/work/web' })
    await start($, w)
    await typed($, 'please fix the login validation bug')
    await settle(w, () => flag(lastStatus(w), 'summary') !== undefined)
    expect(w.modelCalls).toBe(1)
    expect(flag(lastStatus(w), 'summary')).toBe('Fixing the login form validation.')

    await $.turn.start({ text: 'work', turnId: 't1' } as never)
    await $.tool.call(edit('/work/web/src/validate.ts'))
    await $.tool.call(edit('/elsewhere/secret.ts', 'e2'))
    await $.turn.complete(done)
    await settle(w, () => flags(lastStatus(w), 'file').length > 0)
    expect(flags(lastStatus(w), 'file')).toEqual(['src/validate.ts'])
    expect(flag(lastStatus(w), 'state')).toBe('idle')
  })

  test('only the main session\'s edits count: not a subagent\'s, not a background worktree\'s, not .git', async ($, on) => {
    const w = world(on, { gitTop: '/work/web' })
    await start($, w)
    await $.turn.start({ text: 'work', turnId: 't1' } as never)
    // A subagent's loop (its tool calls carry `agentId`), as a background builder's are.
    await $.tool.call({ ...(edit('/work/web/packages/codex-bridge/src/a.ts', 's1') as object), agentId: 'agent-builder-1' } as never)
    // The main session editing inside an agent's worktree or .git still isn't its work.
    await $.tool.call(edit('/work/web/.claude/worktrees/agent-a1b2/packages/codex-bridge/src/b.ts', 'e1'))
    await $.tool.call(edit('/work/web/.git/config', 'e2'))
    await $.tool.call(edit('/work/web/src/main.ts', 'e3'))
    await $.turn.complete(done)
    await settle(w, () => flags(lastStatus(w), 'file').length > 0)
    expect(flags(lastStatus(w), 'file')).toEqual(['src/main.ts'])
  })

  test('a subagent\'s tool round never drains what waits for the main loop (agentId reaches the hook)', async ($, on) => {
    const w = world(on, { gitTop: '/work/web' })
    await start($, w)
    await $.turn.start({ text: 'work', turnId: 't1' } as never)
    w.emit({ kind: 'p2p.message', id: 'm1', at: 1, from: { userId: BEN.own, did: 'd', address: BEN_ADDR, self: false }, own: BEN.own, sid: BEN.sid, ref: BEN.ref, toSession: flag(w.spawns[0] ?? [], 'session'), text: 'hi' })
    await settle(w, () => w.notices.length > 0)
    const sub = await $.tool.call({ tool: 'Read', tool_use_id: 'r1', file_path: '/x', agentId: 'agent-builder-1' } as never)
    expect((sub.context ?? []).join('\n')).not.toContain('cross-session-message')
    const main = await $.tool.call({ tool: 'Read', tool_use_id: 'r2', file_path: '/x' } as never)
    expect((main.context ?? []).join('\n')).toContain('cross-session-message')
  })

  test('peers\' activity rides beside a prompt only when it changed', async ($, on) => {
    const w = world(on, { gitTop: '/work/web' })
    w.peers = [BUSY_BEN]
    await start($, w)
    await typed($, 'first')
    await typed($, 'second')
    expect(w.contexts[0]?.join('\n')).toContain('Refactoring the login form validation.')
    expect(w.contexts[1] ?? []).toEqual([])

    w.peers = [{ ...BUSY_BEN, summary: 'Now writing tests for the login form.' }]
    await w.clock.advance(60_000)
    await settle(w, () => false)
    await typed($, 'third')
    expect(w.contexts[2]?.join('\n')).toContain('Now writing tests for the login form.')
  })

  test('a status arriving on the watch updates the activity too', async ($, on) => {
    const w = world(on, { gitTop: '/work/web' })
    w.peers = []
    await start($, w)
    w.emit({
      kind: 'p2p.status',
      id: 's1',
      at: 1,
      from: { userId: BEN.own, did: 'd', address: BEN_ADDR, self: false },
      own: BEN.own,
      sid: BEN.sid,
      ref: BEN.ref,
      status: { state: 'busy', label: 'api', repo: 'web', summary: 'Tuning the cache.', files: ['src/cache.ts'] },
      live: true,
    })
    await settle(w, () => false)
    await typed($, 'go')
    expect(w.contexts.at(-1)?.join('\n')).toContain(`${BEN_SESSION} (busy, repo web): Tuning the cache. Files: src/cache.ts.`)
  })

  test('a conflict found mid-turn reaches the model at its next tool round', async ($, on) => {
    const w = world(on, { gitTop: '/work/web' })
    w.peers = []
    await start($, w)
    await $.turn.start({ text: 'work', turnId: 't1' } as never)
    await $.tool.call(edit('/work/web/src/login.tsx'))
    w.peers = [BUSY_BEN]
    await w.clock.advance(60_000)
    await settle(w, () => false)
    const ran2 = await $.tool.call(edit('/work/web/src/other.ts', 'e2'))
    expect((ran2.context ?? []).join('\n')).toContain(`POTENTIAL CONFLICT with ${BEN_SESSION}: you both changed src/login.tsx.`)
  })

  test('P2P_IX_SEMANTIC_CONFLICTS=1: ext-ix\'s connected-file conflicts reach the model at its next tool round', async ($, on) => {
    const w = world(on, { gitTop: '/work/web', env: { P2P_IX_SEMANTIC_CONFLICTS: '1' } })
    w.peers = []
    const message = `possible semantic conflict with ${BEN_ADDR}: your change to src/login.tsx affects src/api.ts they're editing (it calls into src/login.tsx)`
    w.cli['ix conflicts'] = { body: { conflicts: [{ peer: { address: BEN_ADDR, own: BEN.own, sid: BEN.sid, ref: BEN.ref }, mine: 'src/login.tsx', theirs: 'src/api.ts', direction: 'mine-affects-theirs', via: ['caller'], message }], errors: [] } }
    await start($, w)
    await $.turn.start({ text: 'work', turnId: 't1' } as never)
    await $.tool.call(edit('/work/web/src/login.tsx'))
    w.peers = [{ ...BUSY_BEN, files: ['src/api.ts'] }]
    await w.clock.advance(60_000)
    await settle(w, () => ran(w, 'ix', 'conflicts').length > 0)
    expect(flag(ran(w, 'ix', 'conflicts')[0]!.argv, 'session')).toBeDefined()
    await settle(w, () => false)
    const ran2 = await $.tool.call(edit('/work/web/src/other.ts', 'e2'))
    expect((ran2.context ?? []).join('\n')).toContain(`POSSIBLE SEMANTIC CONFLICT: ${message}.`)
    // Raised once.
    await w.clock.advance(60_000)
    await settle(w, () => false)
    const ran3 = await $.tool.call(edit('/work/web/src/login.tsx', 'e3'))
    expect((ran3.context ?? []).join('\n')).not.toContain('POSSIBLE SEMANTIC CONFLICT')
  })

  test('semantic conflicts are off by default: ext-ix is never asked', async ($, on) => {
    const w = world(on, { gitTop: '/work/web' })
    w.peers = []
    await start($, w)
    await $.turn.start({ text: 'work', turnId: 't1' } as never)
    await $.tool.call(edit('/work/web/src/login.tsx'))
    w.peers = [{ ...BUSY_BEN, files: ['src/api.ts'] }]
    await w.clock.advance(60_000)
    await settle(w, () => false)
    expect(ran(w, 'ix')).toEqual([])
  })

  test('a conflict found after the last tool round waits for the next prompt, never starting a turn', async ($, on) => {
    const w = world(on, { gitTop: '/work/web' })
    w.peers = []
    await start($, w)
    await $.turn.start({ text: 'work', turnId: 't1' } as never)
    await $.tool.call(edit('/work/web/src/login.tsx'))
    w.peers = [BUSY_BEN]
    await w.clock.advance(60_000)
    await settle(w, () => false)
    await $.turn.complete(done)
    await settle(w, () => false)
    expect(w.submits).toEqual([])
    await typed($, 'next thing')
    expect(w.contexts.at(-1)?.join('\n')).toContain(`POTENTIAL CONFLICT with ${BEN_SESSION}`)
  })

  test('a peer\'s message, a task notification or the SDK does not change the status', async ($, on) => {
    const w = world(on)
    w.peers = [BUSY_BEN]
    await start($, w)
    await $.prompt.submit({ text: 'from a peer', origin: { kind: 'peer' } } as never)
    await $.prompt.submit({ text: 'task done', origin: { kind: 'task-notification' } } as never)
    await $.prompt.submit({ text: 'sdk turn', origin: { kind: 'sdk' } } as never)
    await settle(w, () => false)
    expect(w.modelCalls).toBe(0)
    expect(w.contexts.every(c => (c ?? []).length === 0)).toBe(true)
  })

  test('a prompt through Remote Control (bridge) counts as typed', async ($, on) => {
    const w = world(on)
    await start($, w)
    await $.prompt.submit({ text: 'fix the bug', origin: { kind: 'bridge' } } as never)
    await settle(w, () => w.modelCalls > 0)
    expect(w.modelCalls).toBe(1)
  })

  test('P2P_SHARE_STATUS=0 shares neither a status nor files', async ($, on) => {
    const w = world(on, { gitTop: '/work/web', env: { P2P_SHARE_STATUS: '0' } })
    await start($, w)
    await typed($, 'please fix the login validation bug')
    await $.turn.start({ text: 'work', turnId: 't1' } as never)
    await $.tool.call(edit('/work/web/src/validate.ts'))
    await $.turn.complete(done)
    await settle(w, () => false)
    expect(w.modelCalls).toBe(0)
    expect(ran(w, 'status').length).toBeGreaterThan(0)
    expect(ran(w, 'status').some(r => r.argv.some(a => a.startsWith('--summary') || a.startsWith('--file')))).toBe(false)
  })

  test('IX_PEERS_SHARE_STATUS=0 is still honoured', async ($, on) => {
    const w = world(on, { gitTop: '/work/web', env: { IX_PEERS_SHARE_STATUS: '0' } })
    await start($, w)
    await typed($, 'please fix it')
    await $.turn.start({ text: 'work', turnId: 't1' } as never)
    await $.tool.call(edit('/work/web/src/validate.ts'))
    await $.turn.complete(done)
    await settle(w, () => false)
    expect(w.modelCalls).toBe(0)
    expect(ran(w, 'status').some(r => r.argv.some(a => a.startsWith('--summary') || a.startsWith('--file')))).toBe(false)
  })

  test('a summarizer non-answer (a refusal, a question, talk about the request) keeps the status there was', async ($, on) => {
    const opts = { status: 'Fixing the login form validation in src/login.tsx.' }
    const w = world(on, opts)
    await start($, w)
    await typed($, 'fix the login form')
    await settle(w, () => flag(lastStatus(w), 'summary') !== undefined)
    expect(flag(lastStatus(w), 'summary')).toBe('Fixing the login form validation in src/login.tsx.')
    // The live bug: this went out as a teammate's status.
    opts.status = "I can't tell what tasks 1, 2, 3, 5 and '852' refer to from this message alone, so the status line would have to guess. Could you say which tasks you mean?"
    const before = w.modelCalls
    await typed($, 'do 1, 2, 3, 5 and 852')
    await settle(w, () => w.modelCalls > before)
    await settle(w, () => false)
    const summaries = ran(w, 'status').map(r => flag(r.argv, 'summary')).filter(Boolean)
    expect(summaries.every(line => line === 'Fixing the login form validation in src/login.tsx.')).toBe(true)
    expect(JSON.stringify(w.runs)).not.toContain("can't tell")
  })

  test('chat with no work keeps the status there was', async ($, on) => {
    const w = world(on, { status: 'none' })
    await start($, w)
    await typed($, 'thanks!')
    await settle(w, () => w.modelCalls > 0)
    await settle(w, () => false)
    expect(ran(w, 'status').some(r => r.argv.some(a => a.startsWith('--summary')))).toBe(false)
  })

  test('L4: an absolute path in the model\'s line never reaches the status', async ($, on) => {
    const w = world(on, { status: 'Fixing /Users/sam/work/web/src/login.tsx and C:\\Users\\sam\\x.ts validation.' })
    await start($, w)
    await typed($, 'go')
    await settle(w, () => flag(lastStatus(w), 'summary') !== undefined)
    expect(flag(lastStatus(w), 'summary')).toBe('Fixing and validation.')
  })

  test('L2: a peer rotating subsets of the same files raises the conflict once', async ($, on) => {
    const w = world(on)
    w.peers = []
    await start($, w)
    await $.turn.start({ text: 'work', turnId: 't1' } as never)
    await $.tool.call(edit('/work/web/src/a.ts'))
    await $.tool.call(edit('/work/web/src/b.ts', 'e2'))
    const contexts: string[] = []
    for (const [i, set] of [['src/a.ts', 'src/b.ts'], ['src/b.ts'], ['src/a.ts'], ['src/b.ts', 'src/a.ts']].entries()) {
      w.peers = [{ ...BUSY_BEN, files: set }]
      await w.clock.advance(60_000)
      await settle(w, () => false)
      const r = await $.tool.call({ tool: 'Read', tool_use_id: `r${i}`, file_path: '/x' } as never)
      contexts.push((r.context ?? []).join('\n'))
    }
    expect(contexts.filter(c => c.includes('POTENTIAL CONFLICT')).length).toBe(1)
  })

  test('the summary is capped at 200 characters and cleaned', async ($, on) => {
    const w = world(on, { status: `"Fixing\u202e ${'x'.repeat(300)}"` })
    await start($, w)
    await typed($, 'go')
    await settle(w, () => flag(lastStatus(w), 'summary') !== undefined)
    const line = flag(lastStatus(w), 'summary') ?? ''
    expect(line.length).toBe(200)
    expect(line.startsWith('Fixing x')).toBe(true)
    expect(line.endsWith('…')).toBe(true)
  })
})

describe('Windows (a user\'s repo showed as C:\\Users\\dev\\work\\Sandbox)', () => {
  test('the repo and label are the toplevel\'s last segment; files use /', async ($, on) => {
    const w = world(on, { cwd: 'C:\\Users\\dev\\work\\Sandbox\\src', gitTop: 'C:/Users/dev/work/Sandbox' })
    await start($, w)
    expect(flag(lastStatus(w), 'repo')).toBe('Sandbox')
    expect(flag(lastStatus(w), 'label')).toBe('sandbox')

    await $.turn.start({ text: 'work', turnId: 't1' } as never)
    await $.tool.call(edit('C:\\Users\\dev\\work\\Sandbox\\src\\app\\main.ts'))
    await $.tool.call(edit('C:\\Users\\dev\\Elsewhere\\secret.ts', 'e2'))
    await $.turn.complete(done)
    await settle(w, () => flags(lastStatus(w), 'file').length > 0)
    expect(flags(lastStatus(w), 'file')).toEqual(['src/app/main.ts'])
  })

  test('L4: outside git, nothing names the folder: no repo, the neutral label', async ($, on) => {
    const w = world(on, { cwd: 'C:\\Users\\dev\\work\\Sandbox', gitTop: null })
    await start($, w)
    expect(flag(lastStatus(w), 'repo')).toBeUndefined()
    expect(flag(lastStatus(w), 'label')).toBe('session')
    expect(lastStatus(w).join(' ')).not.toContain('Sandbox')
  })

  test('git failing in the repo (not on PATH, or Windows\' safe.directory): the repo is found by its .git, and names the label', async ($, on) => {
    const w = world(on, { cwd: 'C:\\Users\\dev\\work\\Sandbox\\src', gitTop: null, repoProbe: { root: 'C:\\Users\\dev\\work\\Sandbox', branch: 'feat/login' } })
    await start($, w)
    expect(flag(lastStatus(w), 'repo')).toBe('Sandbox')
    expect(flag(lastStatus(w), 'label')).toBe('sandbox')
    expect(flag(lastStatus(w), 'branch')).toBe('feat/login')
    // The probe ran with the session's directory as its argument.
    const probe = w.runs.find(r => r.argv[0] === 'node' && r.argv[1] === '-e')
    expect(probe?.argv.at(-1)).toBe('C:\\Users\\dev\\work\\Sandbox\\src')

    await $.turn.start({ text: 'work', turnId: 't1' } as never)
    await $.tool.call(edit('C:\\Users\\dev\\work\\Sandbox\\src\\app.ts'))
    await $.turn.complete(done)
    await settle(w, () => flags(lastStatus(w), 'file').length > 0)
    expect(flags(lastStatus(w), 'file')).toEqual(['src/app.ts'])
  })

  test('a probe answer that isn\'t an absolute path names nothing', async ($, on) => {
    const w = world(on, { cwd: 'C:\\Users\\dev\\x', gitTop: null, repoProbe: { root: 'relative\\x' } })
    await start($, w)
    expect(flag(lastStatus(w), 'repo')).toBeUndefined()
    expect(flag(lastStatus(w), 'label')).toBe('session')
  })
})

describe('the roster a status went out with', () => {
  test('a session made private before its user joined the default circle is known as shared once the CLI says so', async ($, on) => {
    const w = world(on, { gitTop: '/work/web', statusRoster: { sid: 'x', ref: 'ffffff', ver: 2, vis: 'circle', circle: 'c_team', parts: [] } })
    w.cli['session roster'] = { body: { roster: { sid: 'x', ref: 'ffffff', ver: 1, vis: 'private', parts: [] } } }
    await start($, w)
    await typed($, 'hello there')
    await settle(w, () => false)
    // Shared now, so a message sent to the person rather than a session waits here (L-A), as in
    // any non-private session; while it was believed private, the sender got "not delivered".
    w.emit(message(w, { id: 'un-r1', toSession: undefined, own: BEN.own, sid: 'ben-old', ref: 'eeeeee' }))
    await gather(w)
    expect(w.statuses.at(-1)).toContain('1 held')
  })
})

// Two Claude sessions on one machine share one identity and one P2P_HOME (here, the one fake CLI
// both runs post through), and one module can serve both. Each test drives two engine sessions,
// `web` and `api`, through one module, switching the session id the engine reports; every one of
// these failed before per-session state (a status, agents, busy/idle, the mode the hold rule reads,
// the session's end) was kept per engine session.
describe('two sessions sharing one P2P_HOME', () => {
  type Opts = { gitTop: string; cwd: string; status: string }
  const twoSessions = async ($: Engine, on: On, apiMode = 'default') => {
    const opts: Opts = { gitTop: '/work/web', cwd: '/work/web', status: 'Fixing the web login form.' }
    const w = world(on, opts)
    const as = (session: 'web' | 'api') => {
      w.sessionId = `claude-session-${session}`
      opts.gitTop = opts.cwd = `/work/${session}`
      opts.status = session === 'web' ? 'Fixing the web login form.' : 'Adding the api rate limiter.'
    }
    as('web')
    await start($, w)
    const web = sidOf(w)
    as('api')
    await $.session.start({ cwd: '/work/api', surface: 'terminal', isInteractive: true })
    await settle(w, () => w.spawns.length >= 2)
    await $.classic.SessionStart({ source: 'startup', permission_mode: apiMode } as never)
    await $.classic.UserPromptSubmit({ prompt: 'hello', permission_mode: apiMode, source: 'user' } as never)
    const api = sidOf(w)
    expect(api).not.toBe(web)
    const sent = (sid: string) => ran(w, 'status').filter(r => flag(r.argv, 'session') === sid)
    const agentsOf = (r: { stdin?: string } | undefined): { task?: string; files?: string[] }[] => {
      try {
        return r?.stdin ? (JSON.parse(r.stdin) as { task?: string; files?: string[] }[]) : []
      } catch {
        return []
      }
    }
    // Both runs post on their own 60 s timers.
    const tick = async () => {
      await w.clock.advance(60_000)
      await settle(w, () => false)
    }

    return { w, as, web, api, sent, agentsOf, tick }
  }
  const edit = async ($: Engine, path: string, id: string) => {
    await $.turn.start({ text: 'work', turnId: id } as never)
    await $.tool.call({ tool: 'Edit', tool_use_id: id, file_path: path, old_string: 'a', new_string: 'b' } as never)
    await $.turn.complete({ turnId: id, answer: '', durationMs: 1, isAborted: false, reason: 'answer' } as never)
  }

  test('each session\'s status carries only its own label, summary and files', async ($, on) => {
    const { as, web, api, sent, tick } = await twoSessions($, on)
    // Interleaved: the web session's prompt and edit come after the api session started.
    as('web')
    await typed($, 'fix the login form')
    await edit($, '/work/web/src/login.tsx', 'w1')
    as('api')
    await typed($, 'add a rate limiter')
    await edit($, '/work/api/src/limit.ts', 'a1')
    await tick()

    expect(sent(web).length).toBeGreaterThan(0)
    expect(sent(api).length).toBeGreaterThan(0)
    for (const r of sent(api)) {
      expect(flag(r.argv, 'label')).toBe('api')
      expect([undefined, 'Adding the api rate limiter.']).toContain(flag(r.argv, 'summary'))
      for (const f of flags(r.argv, 'file')) expect(f).toBe('src/limit.ts')
    }
    for (const r of sent(web)) {
      expect(flag(r.argv, 'label')).toBe('web')
      expect([undefined, 'Fixing the web login form.']).toContain(flag(r.argv, 'summary'))
      for (const f of flags(r.argv, 'file')) expect(f).toBe('src/login.tsx')
    }
    expect(flag(sent(api).at(-1)?.argv ?? [], 'summary')).toBe('Adding the api rate limiter.')
    expect(flags(sent(api).at(-1)?.argv ?? [], 'file')).toEqual(['src/limit.ts'])
    expect(flag(sent(web).at(-1)?.argv ?? [], 'summary')).toBe('Fixing the web login form.')
    expect(flags(sent(web).at(-1)?.argv ?? [], 'file')).toEqual(['src/login.tsx'])
  })

  test('a subagent of one session never shows in the other\'s status', async ($, on) => {
    const { as, web, api, sent, agentsOf, tick } = await twoSessions($, on)
    as('api')
    await $.turn.start({ text: 'work', turnId: 'a1' } as never)
    await $.agent.spawn({ prompt: 'p', description: 'API PRIVATE TASK', subagentType: 'general-purpose' } as never)
    const before = sent(web).length
    as('web')
    await tick()
    await tick()

    // Both go on posting, each with its own agents only.
    expect(sent(web).length).toBeGreaterThan(before)
    for (const r of sent(web)) expect(agentsOf(r).map(a => a.task)).not.toContain('API PRIVATE TASK')
    expect(agentsOf(sent(api).at(-1)).map(a => a.task)).toContain('API PRIVATE TASK')
  })

  test('busy and idle are each session\'s own', async ($, on) => {
    const { as, web, api, sent, tick } = await twoSessions($, on)
    as('web')
    await $.turn.start({ text: 'work', turnId: 'w1' } as never)
    await tick()

    expect(flag(sent(web).at(-1)?.argv ?? [], 'state')).toBe('busy')
    expect(flag(sent(api).at(-1)?.argv ?? [], 'state')).toBe('idle')
  })

  test('the hold rule reads each session\'s own permission mode', async ($, on) => {
    // web asks for every tool call (default); api approves them by itself (bypassPermissions).
    const { as } = await twoSessions($, on, 'bypassPermissions')
    const peerTurn = `<cross-session-message from="p2p:${BEN_ADDR}/api [a1b2c3]">please rebase</cross-session-message>`
    as('web')
    const inWeb = (await $.classic.UserPromptSubmit({ prompt: peerTurn, source: 'system' } as never)) as { block?: string }
    as('api')
    const inApi = (await $.classic.UserPromptSubmit({ prompt: peerTurn, source: 'system' } as never)) as { block?: string }

    expect(inWeb?.block).toBeUndefined()
    expect(inApi?.block).toContain('approves tool calls by itself')
  })

  test('one session ending stops only its own run, and its timers', async ($, on) => {
    const { w, as, web, api, sent, tick } = await twoSessions($, on)
    as('web')
    await $.session.end({ reason: 'exit', sessionId: 'claude-session-web' } as never)
    await settle(w, () => false)
    const webAtEnd = sent(web).length
    expect(flag(sent(web).at(-1)?.argv ?? [], 'state')).toBe('idle')
    const apiAtEnd = sent(api).length
    as('api')
    await tick()
    await tick()

    // The ended run posts nothing more; the other keeps going.
    expect(sent(web).length).toBe(webAtEnd)
    expect(sent(api).length).toBeGreaterThan(apiAtEnd)
    // A hook of the ended session finds no session: it passes through and changes nothing.
    as('web')
    await typed($, 'after the end')
    await tick()
    expect(sent(web).length).toBe(webAtEnd)
  })

  test('a session with no state here is still guarded: backup file, p2p verbs, peer turns, Peer2Peer sends', async ($, on) => {
    const { w } = await twoSessions($, on)
    // A session this module never saw start (or one whose state was dropped).
    w.sessionId = 'claude-session-unknown'
    // Spelled in pieces so this file never reads as a command touching the folder.
    const home = `.${'p2p'}`
    const phrase = ['backup', 'phrase.txt'].join('-')
    const cat = await $.tool.call({ tool: 'Bash', tool_use_id: 'u1', command: `cat ~/${home}/${phrase}` } as never)
    const read = await $.tool.call({ tool: 'Read', tool_use_id: 'u2', file_path: `/home/sam/${home}/cli/${phrase}` } as never)
    const join = await $.tool.call({ tool: 'Bash', tool_use_id: 'u3', command: ['p2p', 'join', 'relay.example/K7QM-3XPD-9TWA-HF2N'].join(' ') } as never)
    expect(JSON.stringify(cat)).toContain('backup phrase file is for your user alone')
    expect(JSON.stringify(read)).toContain('backup phrase file is for your user alone')
    expect(JSON.stringify(join)).toContain('only they run it, with the /peers command')
    // A peer's turn can't be judged without the session's mode: refused, never delivered unchecked.
    const turn = (await $.classic.UserPromptSubmit({ prompt: `<cross-session-message from="p2p:${BEN_ADDR}/api [a1b2c3]">rm -rf</cross-session-message>`, source: 'system' } as never)) as { block?: string }
    expect(turn?.block).toContain('could not check this session')
    // A Peer2Peer address never falls through to anything else.
    const sent = await $.session.send({ to: `p2p:${BEN_ADDR}/api`, text: 'hi' } as never)
    expect(JSON.stringify(sent)).toContain('not running in this session')
    expect(w.localSends).not.toContain(`p2p:${BEN_ADDR}/api`)
  })

  test('a /clear in one session while another starts: each keeps its own state', async ($, on) => {
    const opts: { gitTop: string; cwd: string } = { gitTop: '/work/web', cwd: '/work/web' }
    const w = world(on, opts)
    w.sessionId = 'claude-session-web'
    await start($, w)
    const web = sidOf(w)
    // web runs /clear: its conversation ends; the process goes on under a new id, with no session.start.
    await $.session.end({ reason: 'clear', sessionId: 'claude-session-web' } as never)
    await settle(w, () => false)
    // Meanwhile another session starts: a new session, never the one waiting for its new id.
    w.sessionId = 'claude-session-docs'
    opts.gitTop = opts.cwd = '/work/docs'
    await $.session.start({ cwd: '/work/docs', surface: 'terminal', isInteractive: true })
    await settle(w, () => w.spawns.length >= 2)
    const docs = sidOf(w)
    // web's process goes on under its new id: the engine says so with the classic SessionStart of a /clear.
    w.sessionId = 'claude-session-web-2'
    opts.gitTop = opts.cwd = '/work/web'
    await $.classic.SessionStart({ source: 'clear', permission_mode: 'default' } as never)
    await w.clock.advance(1_500)
    await settle(w, () => w.spawns.length >= 3)
    const web2 = sidOf(w)
    expect(new Set([web, docs, web2]).size).toBe(3)
    w.sessionId = 'claude-session-docs'
    opts.gitTop = opts.cwd = '/work/docs'
    await w.clock.advance(60_000)
    await settle(w, () => false)

    const labels = (sid: string) => [...new Set(ran(w, 'status').filter(r => flag(r.argv, 'session') === sid).map(r => flag(r.argv, 'label')))]
    expect(labels(docs)).toEqual(['docs'])
    expect(labels(web2)).toEqual(['web'])
    // And the web session's hooks are its own again: its prompt is web's status.
    w.sessionId = 'claude-session-web-2'
    await typed($, 'fix the login form')
    await settle(w, () => ran(w, 'status').some(r => flag(r.argv, 'session') === web2 && flag(r.argv, 'summary') !== undefined))
    expect([...new Set(ran(w, 'status').filter(r => flag(r.argv, 'summary') !== undefined).map(r => flag(r.argv, 'session')))]).toEqual([web2])
  })

  test('a subagent loop reporting its own session id is still its spawner\'s: credited, and guarded', async ($, on) => {
    const { w, as, api, sent, agentsOf, tick } = await twoSessions($, on)
    w.spawnIds = ['E-api']
    as('api')
    await $.turn.start({ text: 'work', turnId: 'a1' } as never)
    await $.agent.spawn({ prompt: 'p', description: 'Tune the limiter', subagentType: 'general-purpose' } as never)
    // Its tool rounds arrive under a sidechain id the module never saw start.
    w.sessionId = 'claude-session-api-sidechain'
    await $.tool.call({ tool: 'Edit', tool_use_id: 's1', file_path: '/work/api/src/limit.ts', old_string: 'a', new_string: 'b', agentId: 'E-api' } as never)
    const join = await $.tool.call({ tool: 'Bash', tool_use_id: 's2', command: ['p2p', 'join', 'relay.example/K7QM'].join(' '), agentId: 'E-api' } as never)
    expect(JSON.stringify(join)).toContain('only they run it, with the /peers command')
    as('api')
    await tick()

    const [agent] = agentsOf(sent(api).at(-1))
    expect(agent?.task).toBe('Tune the limiter')
    expect(agent?.files).toEqual(['src/limit.ts'])
  })
})
