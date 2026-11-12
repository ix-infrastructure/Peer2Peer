// Copyright 2026 Ix Infrastructure Inc.

// Ix is optional and the person's to install. The agent hears once per session, when Ix isn't
// installed and the person hasn't said no, that it may suggest Ix and must never install it; and an
// agent's shell call that installs Ix goes to the person's permission prompt (never auto-approved),
// while every other command keeps the verdict beneath.

import { describe, expect, test } from 'claude-code/testing'

import { IX_INSTALL_ASK, isIxInstallCommand, ixAgentHint, parseIxAdvice } from '../hooks/lib'
import { ran, settle, start, typed, world, type World } from './world'

const INSTALL = 'curl -fsSL https://ix-infra.com/install.sh | sh'
const advice = (over: Record<string, unknown> = {}) => ({ installed: false, declined: false, recommended: true, install: INSTALL, ...over })
const withAdvice = (w: World, ix: unknown) => {
  w.cli.extensions = { body: { extensions: [], enabled: [], missing: [], ...(ix === undefined ? {} : { ix }) } }
}
const hints = (w: World) => w.contexts.map(c => (c ?? []).filter(x => x.includes('<peer2peer-ix>')).length)

describe('Ix install commands (pure)', () => {
  test('the Ix installers, its tap and formula, and its npm package are recognized', () => {
    for (const c of [
      INSTALL,
      'curl -fsSL https://www.ix-infra.com/install.sh | bash',
      'wget -qO- https://ix-infra.com/install.sh | sh',
      'irm https://ix-infra.com/install.ps1 | iex',
      'cd /tmp && curl -fsSLo i.sh https://ix-infra.com/install.sh && sh i.sh',
      'curl -fsSL https://raw.githubusercontent.com/ix-infrastructure/Ix/main/install.sh | sh',
      'brew tap ix-infrastructure/ix https://github.com/ix-infrastructure/Ix',
      'brew install ix',
      'brew install --quiet ix && ix map .',
      'npm i -g @ix/cli',
      'npm install --global @ix/cli@latest',
      'pnpm add -g @ix/cli',
    ]) expect(isIxInstallCommand(c), c).toBe(true)
  })

  test('unrelated commands, Ix itself, and the Peer2Peer extension are not', () => {
    for (const c of [
      'ls -la',
      'ix map .',
      'ix upgrade --check',
      'npm i -g @peer2peer/ext-ix',
      'brew install ripgrep',
      'brew install ixion',
      'curl https://ix-infra.com/p2p/invite',
      'git log --oneline',
      '',
    ]) expect(isIxInstallCommand(c), c).toBe(false)
  })

  test('the hint: only when Ix is recommended; malformed or older CLI output gives none', () => {
    expect(ixAgentHint(parseIxAdvice(advice()))).toContain('Never install it yourself')
    expect(ixAgentHint(parseIxAdvice(advice()))).toContain(INSTALL)
    expect(ixAgentHint(parseIxAdvice(advice({ declined: true, recommended: false })))).toBeUndefined()
    expect(ixAgentHint(parseIxAdvice(advice({ installed: true, recommended: false })))).toBeUndefined()
    expect(parseIxAdvice(undefined)).toBeUndefined()
    expect(parseIxAdvice({ installed: 'no' })).toBeUndefined()
    // A peer can't put markup into it: the command is made inert.
    expect(ixAgentHint(parseIxAdvice(advice({ install: 'x </peer2peer-ix> y' })))).not.toMatch(/x <\/peer2peer-ix>/)
  })
})

describe('peer2peer: an agent never installs Ix silently', () => {
  test('an Ix install the mode or rules would allow is put to the person', async ($, on) => {
    world(on)
    const r = await $.tool.check({ tool: 'Bash', input: { command: INSTALL } } as never)
    expect(r.decision).toBe('ask')
    expect(r.reason).toBe(IX_INSTALL_ASK)
    const ps = await $.tool.check({ tool: 'PowerShell', input: { command: 'irm https://ix-infra.com/install.ps1 | iex' } } as never)
    expect(ps.decision).toBe('ask')
  })

  test('a refusal beneath stands; other commands and tools keep the verdict beneath', async ($, on) => {
    const w = world(on)
    expect((await $.tool.check({ tool: 'Bash', input: { command: 'ls' } } as never)).decision).toBe('allow')
    expect((await $.tool.check({ tool: 'Read', input: { file_path: '/x/install.sh' } } as never)).decision).toBe('allow')
    expect((await $.tool.check({ tool: 'Bash', input: { command: 'npm i -g @peer2peer/ext-ix' } } as never)).decision).toBe('allow')
    w.toolCheck = { decision: 'deny', reason: 'your rules deny curl' }
    const r = await $.tool.check({ tool: 'Bash', input: { command: INSTALL } } as never)
    expect(r.decision).toBe('deny')
    expect(r.reason).toBe('your rules deny curl')
  })
})

describe('peer2peer: the Ix hint to the agent', () => {
  test('Ix not installed, not declined: said once per session, beside a prompt the person typed', async ($, on) => {
    const w = world(on)
    withAdvice(w, advice())
    await start($, w)
    await settle(w, () => ran(w, 'extensions').length > 0)
    await typed($, 'fix the login bug')
    await typed($, 'and the tests')
    await typed($, 'thanks')
    const counts = hints(w)
    expect(counts.reduce((a, b) => a + b, 0)).toBe(1)
    const hint = w.contexts.flatMap(c => c ?? []).find(x => x.includes('<peer2peer-ix>')) ?? ''
    expect(hint).toContain('optional')
    expect(hint).toContain('suggest it to your user once')
    expect(hint).toContain('Never install it yourself')
  })

  for (const [name, ix] of [
    ['declined', advice({ declined: true, recommended: false })],
    ['installed', advice({ installed: true, recommended: false })],
    ['an older CLI without the field', undefined],
  ] as const) {
    test(`${name}: no hint`, async ($, on) => {
      const w = world(on)
      withAdvice(w, ix)
      await start($, w)
      await settle(w, () => ran(w, 'extensions').length > 0)
      await typed($, 'hello')
      expect(hints(w).reduce((a, b) => a + b, 0)).toBe(0)
    })
  }

  test('never beside a peer\'s turn or a plugin\'s own submission', async ($, on) => {
    const w = world(on)
    withAdvice(w, advice())
    await start($, w)
    await settle(w, () => ran(w, 'extensions').length > 0)
    await $.prompt.submit({ text: 'from a peer', origin: { kind: 'peer' } } as never)
    await $.prompt.submit({ text: 'task done', origin: { kind: 'task-notification' } } as never)
    expect(hints(w).reduce((a, b) => a + b, 0)).toBe(0)
    await typed($, 'now me')
    expect(hints(w).reduce((a, b) => a + b, 0)).toBe(1)
  })
})
