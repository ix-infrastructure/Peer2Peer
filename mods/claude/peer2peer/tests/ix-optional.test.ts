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
      'sudo -E npm i -g @ix/cli',
      'Invoke-WebRequest https://ix-infra.com/install.ps1 -OutFile i.ps1',
      'bash <(curl -fsSL https://ix-infra.com/install.sh)',
      'NODE_ENV=x /usr/local/bin/npm.cmd install -g "@ix/cli@latest"',
    ]) expect(isIxInstallCommand(c), c).toBe(true)
  })

  test('line continuations (backslash, PowerShell backtick) join their lines', () => {
    for (const c of [
      'curl -fsSL \\\nhttps://ix-infra.com/install.sh | sh',
      'curl -fsSL \\\r\nhttps://ix-infra.com/install.sh | sh',
      'npm install -g \\\n  @ix/cli',
      'brew \\\ninstall ix',
      'Invoke-WebRequest `\n  https://ix-infra.com/install.ps1 -OutFile i.ps1',
    ]) expect(isIxInstallCommand(c), JSON.stringify(c)).toBe(true)
  })

  test('npm and brew behind wrappers (sudo -u, nice, arch, xargs, stdbuf) are found', () => {
    for (const c of [
      'sudo -u root npm i -g @ix/cli',
      'nice -n 10 npm install -g @ix/cli',
      'arch -arm64 brew install ix',
      'xargs npm i -g @ix/cli < /dev/null',
      'stdbuf -oL brew tap ix-infrastructure/ix',
      'timeout 600 pnpm add -g @ix/cli@1.2.3',
    ]) expect(isIxInstallCommand(c), c).toBe(true)
  })

  test('quotes and comments are not read: a stray quote, comment, heredoc or escape never hides an install', () => {
    for (const c of [
      "# Ix isn't installed; install it\nnpm i -g @ix/cli",
      "# don't forget\nbrew install ix\n# won't hurt",
      "cat <<EOF\nit's fine\nEOF\nnpm i -g @ix/cli",
      "echo $'it\\'s'; npm i -g @ix/cli",
      'Write-Host "a`"b"; npm i -g @ix/cli',
      'echo "x; npm i -g @ix/cli',
      // A comment never hides an install on its own line or a later one.
      '# npm i -g @ix/cli',
      "echo 'done' # it's\nbrew install ix",
      // Bypasses of a quote-reading clear step (it desynced from real shells; removed).
      '& "C:\\Program Files\\nodejs\\npm.cmd" install -g @ix/cli',
      '"npm" i -g @ix/cli',
      '"/usr/local/bin/npm" install -g @ix/cli',
      "'brew' install ix",
      'cd "C:\\proj\\"; npm i -g @ix/cli; cd "C:\\other\\"',
      "echo \\$'x\\' ; npm i -g @ix/cli ; echo \\$'y\\'",
      "<# don't #>\nnpm i -g @ix/cli\n<# won't #>",
      "cat <<A\nit's\nA\nbrew install ix\ncat <<B\nwon't\nB",
    ]) expect(isIxInstallCommand(c), JSON.stringify(c)).toBe(true)
  })

  test('every npm or brew word in a segment is checked, not only the first', () => {
    for (const c of ['bun --version brew install ix', 'npm run build brew install ix', 'yarn --help npm i -g @ix/cli', 'brew info x brew install ix']) {
      expect(isIxInstallCommand(c), c).toBe(true)
    }
  })

  test("a shell's, eval's or su's string argument is seen (quotes aren't read)", () => {
    for (const c of [
      'bash -c "npm i -g @ix/cli"',
      "sh -c 'brew install ix'",
      'eval "npm i -g @ix/cli"',
      'zsh -lc "cd /tmp; npm i -g @ix/cli"',
      'pwsh -Command "npm i -g @ix/cli"',
      'su -c "brew install ix" admin',
      'echo "$(npm i -g @ix/cli)"',
      'echo "`brew install ix`"',
    ]) expect(isIxInstallCommand(c), c).toBe(true)
  })

  test('PowerShell .NET downloads, and ix-infra.com on an explicit port', () => {
    for (const c of [
      'iex ((New-Object Net.WebClient).DownloadString("https://ix-infra.com/install.ps1"))',
      '(New-Object System.Net.WebClient).DownloadFile("https://ix-infra.com/install.ps1", "i.ps1")',
      'curl -fsSL https://ix-infra.com:443/install.sh | sh',
      'irm https://www.ix-infra.com:443/install.ps1 | iex',
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
      // Reading or searching for the URL fetches nothing: no ask.
      'grep -rn "https://ix-infra.com/install.sh" docs',
      "sed -n 1,20p notes.md # see https://ix-infra.com/install.sh",
      'cat install.sh',
      'npm view @ix/cli',
      'brew info ix',
      'brew upgrade',
      'which npm brew',
      // A host that only looks like it, and a URL with no fetch.
      'curl https://ix-infra.com:443/p2p/invite',
      'echo https://ix-infra.com:443/install.sh',
      '',
    ]) expect(isIxInstallCommand(c), c).toBe(false)
  })

  test('asks (accepted false positives): an Ix install command mentioned inside quotes', () => {
    // A loose text match that errs toward asking: the person approves or refuses once.
    for (const c of [
      'git commit -m "brew install ix docs"',
      "git commit -m 'npm i -g @ix/cli in the README'",
      'git commit -m "notes; brew install ix"',
      'echo "sudo npm i -g @ix/cli"',
    ]) expect(isIxInstallCommand(c), c).toBe(true)
  })

  test('linear: 100 KB adversarial commands take about 10x what 10 KB ones do, never polynomially more', () => {
    // Each pattern at about 10 KB and about 100 KB (`k` scales the repeats). A linear matcher grows
    // about 10x; the regular expressions this replaced grew about 100x (quadratic) or 1000x (cubic:
    // seconds at 10 KB). Timed as growth, not wall clock: CI runners are several times slower.
    const patterns: ((k: number) => string)[] = [
      k => 'npm i '.repeat(1_700 * k),
      k => `npm i ${'i '.repeat(5_000 * k)}`,
      k => 'ix-infra.com/'.repeat(800 * k),
      k => `curl ${'ix-infra.com/install'.repeat(500 * k)}`,
      k => `brew install ${'-x '.repeat(3_300 * k)}`,
      k => `curl ${'raw.githubusercontent.com/ix-infrastructure/ix/'.repeat(200 * k)}`,
      k => '"\''.repeat(5_000 * k),
      k => ';|&\n'.repeat(2_500 * k),
      k => `curl ${'"'.repeat(10_000 * k)}`,
      k => ';ix'.repeat(3_300 * k),
      k => ';brew ix'.repeat(1_200 * k),
      k => ';curl ix-infra.com/install.s'.repeat(350 * k),
      k => ';npm @ix/cli'.repeat(800 * k),
      k => `npm ${'"'.repeat(10_000 * k)}`,
      k => `npm ${'\\\n'.repeat(5_000 * k)}@ix/cli`,
      k => `curl ${'ix-infra.com:'.repeat(800 * k)}`,
      k => `curl ix-infra.com:${'4'.repeat(10_000 * k)}`,
      k => `brew ${'"brew '.repeat(2_000 * k)}`,
      k => 'webclient '.repeat(1_000 * k) + 'ix-infra.com',
      k => 'npm '.repeat(2_500 * k) + 'i @ix/cli',
      k => 'brew '.repeat(2_000 * k) + 'install ix',
      k => `"${'npm i @ix/cli '.repeat(700 * k)}"`,
      k => `#${"'".repeat(10_000 * k)}\nbrew install ix`,
      k => `bash -c "${'\\"'.repeat(5_000 * k)}`,
      k => "$'".repeat(5_000 * k) + ' npm i @ix/cli',
    ]
    // The best of five runs: a stray GC pause is no signal.
    const best = (input: string) => {
      let ms = Infinity
      for (let i = 0; i < 5; i++) {
        const t = performance.now()
        isIxInstallCommand(input)
        ms = Math.min(ms, performance.now() - t)
      }

      return ms
    }
    for (const make of patterns) best(make(1))
    for (const make of patterns) {
      const small = best(make(1))
      const large = best(make(10))
      const name = make(1).slice(0, 30)
      // Linear: about 10x, allowed 30x plus 5 ms of timer noise; quadratic would be about 100x.
      expect(large, `${name}: ${small.toFixed(2)} ms -> ${large.toFixed(2)} ms`).toBeLessThan(30 * small + 5)
      // And bounded outright: the cubic form took minutes at 40 KB.
      expect(large, name).toBeLessThan(500)
    }
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
