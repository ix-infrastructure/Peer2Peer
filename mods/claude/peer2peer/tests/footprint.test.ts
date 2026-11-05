// Copyright 2026 Ix Infrastructure Inc.

// This session's Ix footprint (ext-ix x:ix.footprint): after an edit the mod
// runs `p2p ix footprint --publish`, 10 s after the last edit and at most every
// 30 s, only with the extension loaded and sharing on; without Ix it stops
// after one answer, saying nothing; and what the command prints never reaches
// the model.

import { describe, expect, test } from 'claude-code/testing'
import type { Engine } from 'claude-code/testing'

import { mutatingP2PVerb, touchesP2PSettings, uncheckableShell } from '../hooks/lib'
import { flag, growth, ran, settle, sidOf, start, world, type World } from './world'

const MARK = 'FOOTPRINT-BODY-MARKER'
const LOADED = { body: { extensions: [{ ns: 'ix', name: '@peer2peer/ext-ix', version: '0.1.0', commands: ['footprint'] }], enabled: ['ix'] } }
const PUBLISHED = { body: { published: true, footprint: { actors: [{ a: 'main', changed: { symbols: [{ k: `src/a.ts#${MARK}` }] } }] }, fallback: `Ix footprint: ${MARK}`, delivered: [] } }

const postEdit = ($: Engine, tool = 'Edit') => $.classic.PostToolUse({ tool_name: tool, tool_input: { file_path: '/work/web/src/a.ts' }, tool_response: {}, permission_mode: 'default' } as never)
const footprints = (w: World) => ran(w, 'ix', 'footprint')

async function loaded($: Engine, w: World) {
  w.cli.extensions = LOADED
  w.cli['ix footprint'] = PUBLISHED
  await start($, w)
  await settle(w, () => ran(w, 'extensions').length > 0)
}

async function advance(w: World, ms: number) {
  await w.clock.advance(ms)
  await settle(w, () => false)
}

describe('peer2peer: the Ix footprint', () => {
  test('debounced: 10 s after the last edit, then at most every 30 s', async ($, on) => {
    const w = world(on)
    await loaded($, w)
    await postEdit($)
    await advance(w, 4_000)
    await postEdit($, 'Write')
    await advance(w, 9_000)
    expect(footprints(w)).toHaveLength(0)
    await advance(w, 1_500)
    expect(footprints(w)).toHaveLength(1)
    const argv = footprints(w)[0]!.argv
    expect(argv).toEqual(expect.arrayContaining(['ix', 'footprint', '--publish', '--json']))
    expect(argv.some(a => a.startsWith('--session='))).toBe(true)
    // The status it reads goes out first.
    const statusAt = w.runs.findLastIndex(r => r.argv.includes('status'))
    expect(statusAt).toBeLessThan(w.runs.findIndex(r => r.argv.includes('footprint')))
    // Another edit right away: its debounce ends 12 s after the run, inside the 30 s gap.
    await advance(w, 2_000)
    await postEdit($)
    await advance(w, 15_000)
    expect(footprints(w)).toHaveLength(1)
    await advance(w, 14_000)
    expect(footprints(w)).toHaveLength(2)
    // Reads that aren't edits don't trigger it.
    await postEdit($, 'Read')
    await advance(w, 40_000)
    expect(footprints(w)).toHaveLength(2)
  })

  test('kept alive: republished about every 5 minutes with no edits', async ($, on) => {
    const w = world(on)
    await loaded($, w)
    await postEdit($)
    await advance(w, 11_000)
    expect(footprints(w)).toHaveLength(1)
    await advance(w, 5 * 60_000 + 6_000)
    expect(footprints(w)).toHaveLength(2)
  })

  test('without Ix: one run, then never again, and nothing shown to anyone', async ($, on) => {
    const w = world(on)
    await loaded($, w)
    w.cli['ix footprint'] = { exitCode: 1, body: { error: 'ix_missing', reason: "Ix isn't installed" } }
    await postEdit($)
    await advance(w, 11_000)
    expect(footprints(w)).toHaveLength(1)
    for (let i = 0; i < 3; i++) {
      await postEdit($)
      await advance(w, 40_000)
    }
    await advance(w, 6 * 60_000)
    expect(footprints(w)).toHaveLength(1)
    const said = JSON.stringify([w.toasts, w.notices, w.submits, w.contexts])
    expect(said).not.toMatch(/Ix isn't installed|ix_missing|footprint/i)
  })

  for (const [what, opts, isLoaded] of [
    ['without the extension', {}, false],
    ['with P2P_IX_FOOTPRINT=0', { env: { P2P_IX_FOOTPRINT: '0' } }, true],
    ['with status sharing off', { env: { P2P_SHARE_STATUS: '0' } }, true],
  ] as const) {
    test(`not ${what}`, async ($, on) => {
      const w = world(on, opts)
      if (isLoaded) w.cli.extensions = LOADED
      w.cli['ix footprint'] = PUBLISHED
      await start($, w)
      await settle(w, () => ran(w, 'extensions').length > 0)
      await postEdit($)
      await advance(w, 40_000)
      expect(footprints(w)).toHaveLength(0)
    })
  }

  test('the footprint never reaches the model', async ($, on) => {
    const w = world(on)
    await loaded($, w)
    await $.turn.start({ text: 'work', turnId: 't1' } as never)
    await $.tool.call({ tool: 'Edit', tool_use_id: 'e1', file_path: '/work/web/src/a.ts', old_string: 'a', new_string: 'b' } as never)
    await postEdit($)
    await advance(w, 11_000)
    expect(footprints(w)).toHaveLength(1)
    const next = await $.tool.call({ tool: 'Edit', tool_use_id: 'e2', file_path: '/work/web/src/b.ts', old_string: 'a', new_string: 'b' } as never)
    expect((next.context ?? []).join('\n')).not.toContain(MARK)
    expect(JSON.stringify([w.submits, w.contexts, w.toasts, w.notices, w.statuses])).not.toContain(MARK)
  })
  test('each session has its own trigger: its own debounce, gap and stop', async ($, on) => {
    const opts = { gitTop: '/work/web', cwd: '/work/web' }
    const w = world(on, opts)
    w.cli.extensions = LOADED
    w.cli['ix footprint'] = PUBLISHED
    w.sessionId = 'claude-session-web'
    await start($, w)
    await settle(w, () => ran(w, 'extensions').length > 0)
    const web = sidOf(w)
    w.sessionId = 'claude-session-api'
    opts.gitTop = opts.cwd = '/work/api'
    await $.session.start({ cwd: '/work/api', surface: 'terminal', isInteractive: true })
    await settle(w, () => w.spawns.length >= 2)
    await $.classic.SessionStart({ source: 'startup', permission_mode: 'default' } as never)
    await settle(w, () => ran(w, 'extensions').length > 1)
    const api = sidOf(w)
    expect(api).not.toBe(web)
    const runsFor = (sid: string) => footprints(w).filter(r => flag(r.argv, 'session') === sid)
    // web edits; 5 s later api edits: each fires 10 s after its own edit, for its own session only.
    w.sessionId = 'claude-session-web'
    await postEdit($)
    await advance(w, 5_000)
    w.sessionId = 'claude-session-api'
    await postEdit($)
    await advance(w, 5_500)
    expect([runsFor(web).length, runsFor(api).length]).toEqual([1, 0])
    await advance(w, 5_000)
    expect([runsFor(web).length, runsFor(api).length]).toEqual([1, 1])
    // api's next run finds no Ix: it stops for its run; web keeps going.
    w.cli['ix footprint'] = { exitCode: 1, body: { error: 'ix_missing', reason: 'no' } }
    await postEdit($)
    await advance(w, 40_000)
    expect(runsFor(api).length).toBe(2)
    w.cli['ix footprint'] = PUBLISHED
    await postEdit($)
    await advance(w, 40_000)
    expect(runsFor(api).length).toBe(2)
    w.sessionId = 'claude-session-web'
    await postEdit($)
    await advance(w, 40_000)
    expect(runsFor(web).length).toBe(2)
  })
  test('H1: the model can\'t publish, pick plain names or change footprint settings from its shell', async ($, on) => {
    const refused = [
      'p2p ix config names=plain',
      'p2p ix config --circle c_team names=plain',
      'p2p ix footprint --publish',
      'p2p ix footprint --session s1 --publish --names plain --force',
      'P2P_IX_FOOTPRINT_NAMES=plain p2p ix footprint --publish',
      'p2p ix footprint --names=plain',
      'p2p ix footprint --force',
      'bash -c "p2p ix footprint --publish"',
      'node /x/bin/p2p.mjs ix config names=plain',
    ]
    for (const c of refused) expect(mutatingP2PVerb(c), c).not.toBeNull()
    // Computing and printing only stays allowed.
    expect(mutatingP2PVerb('p2p ix footprint --session s1 --json')).toBeNull()
    expect(mutatingP2PVerb('p2p ix footprint')).toBeNull()
    const w = world(on)
    await loaded($, w)
    const r = await $.tool.call({ tool: 'Bash', tool_use_id: 'b1', command: 'p2p ix config --circle c_team names=plain' } as never)
    expect(r.deny).toMatch(/only your user runs it/)
    const p = await $.tool.call({ tool: 'Bash', tool_use_id: 'b2', command: 'P2P_IX_FOOTPRINT_NAMES=plain p2p ix footprint --publish --force' } as never)
    expect(p.deny).toMatch(/only your user runs it/)
    expect(ran(w, 'ix', 'config')).toEqual([])
  })
  test('M-a: no tool may read or change p2p settings or an extension store (default and custom P2P_HOME)', async ($, on) => {
    const home = '/home/sam/.p2p'
    const touching = [
      { tool: 'Write', file_path: `${home}/ext/ix.json`, content: '{"config":{"names":"plain"}}' },
      { tool: 'Edit', file_path: `${home}/ext/ix.json`, old_string: 'hmac', new_string: 'plain' },
      { tool: 'Read', file_path: `${home}/config.json` },
      { tool: 'Bash', command: `jq '.config.names="plain"' ${home}/ext/ix.json > /tmp/x && mv /tmp/x ${home}/ext/ix.json` },
      { tool: 'Bash', command: 'python3 -c "import json; p=\'~/.p2p/ext/ix.json\'"' },
      { tool: 'Write', file_path: '/srv/p2phome/ext/ix.json', content: '{}' },
      { tool: 'Edit', file_path: '/srv/p2phome/config.json', old_string: 'a', new_string: 'b' },
    ]
    for (const t of touching) expect(touchesP2PSettings(t, ['/srv/p2phome']), JSON.stringify(t)).toBe(true)
    expect(touchesP2PSettings({ tool: 'Write', file_path: '/work/web/src/config.json' }, ['/srv/p2phome'])).toBe(false)
    expect(touchesP2PSettings({ tool: 'Read', file_path: '/work/web/ext/index.ts' }, ['/srv/p2phome'])).toBe(false)
    const w = world(on, { env: { P2P_HOME: '/srv/p2phome' } })
    await loaded($, w)
    for (const t of touching) {
      const r = await $.tool.call({ ...t, tool_use_id: 'm1' } as never)
      expect(r.deny, JSON.stringify(t)).toMatch(/settings and its extensions' stores/)
    }
  })

  test('M-b: shell forms the guard can\'t read are refused; ordinary commands pass', async ($, on) => {
    const refused = [
      'echo "p2p ix config names=plain" | sh',
      'p2p ls | /bin/zsh -s',
      '/usr/local/bin/p2p ls | sh',

      'bash <<< "p2p ix config names=plain"',
      'sh -s p2p < cmds.txt',
      'node /x/bin/p2p.mjs --help | bash',
      'cat /srv/p2phome/cmds | sh',
      "bash <<'EOF'\np2p ix config names=plain\nEOF",
      'echo "ix config names=plain" | xargs p2p',
      'printf "%s\\n" ix | xargs -n1 node /x/bin/p2p.mjs',
      '$(echo p2p) ix config names=plain',
      '`which p2p` ix footprint --publish',
      'P=p2p; $P ix config names=plain',
      'python3 -c "import subprocess; subprocess.run([\'p2p\', \'ix\', \'config\', \'names=plain\'])"',
      'node -e "cp.execSync(\'p2p ix footprint --publish\')"',
      "perl -e 'system(\"p2p ix footprint --names plain\")'",
      "ruby -e 'system(\"p2p\", \"ix\", \"config\")'",
    ]
    for (const c of refused) expect(uncheckableShell(c, ['/srv/p2phome']), c).not.toBeNull()
    const fine = [
      'npm test | tee out.log',
      'git log --oneline | head -5',
      'shasum -a 256 file | cut -d" " -f1',
      'p2p ls --json',
      '"$P2P_BIN" ix footprint --session s1',
      'python3 -c "print(1)"',
      'node -e "console.log(process.version)"',
      'echo $HOME',
      'ssh -T git@github.com',
      'git push -u origin main',
      // A pipe or here-string into a shell is ordinary work unless the line names p2p.
      'curl -fsSL https://example.com/install.sh | sh',
      'echo foo | bash',
      'bash <<< "make test"',
      'sh -s < setup.sh',
      // The documented limit: an encoded payload names nothing, so the guard can't see it (plain
      // names still need the person's signed setting).
      'echo cDJwIGl4IGNvbmZpZyBuYW1lcz1wbGFpbg== | base64 -d | sh',
      // Review L3: p2p as a path segment is not the CLI.
      'cd packages/p2p && $NPM test',
      'cd packages/p2p && npm test',
      'npm --prefix packages/p2p run build',
      'cat packages/p2p/package.json | jq .version',
      'cat scripts/install.sh | bash',
      'node packages/p2p/scripts/bundle.mjs --check',
      'git diff origin/main -- packages/p2p | head',
      'ls mods/claude/peer2peer/hooks | sh -c cat',
    ]
    for (const c of fine) expect(uncheckableShell(c, ['/srv/p2phome']), c).toBeNull()
    // Over 16 KiB, refused only when it names p2p; and no quadratic rescans.
    expect(uncheckableShell(`echo ${'x'.repeat(17000)}`)).toBeNull()
    expect(uncheckableShell(`p2p ls # ${'x'.repeat(17000)}`)).toMatch(/too long/)
    // No quadratic rescans: the cost from n to 4n, against this machine itself (about 4 when linear).
    const g = growth((n) => {
      uncheckableShell(`p2p ls; ${'a=1 '.repeat(n / 4)}`)
      uncheckableShell(`p2p ls; ${'$('.repeat(n / 2)}`)
    }, 2000)
    expect(g.ratio).toBeLessThan(9)
    expect(g.totalMs).toBeLessThan(10_000)
    const w = world(on)
    await loaded($, w)
    const r = await $.tool.call({ tool: 'Bash', tool_use_id: 'b1', command: 'echo "p2p ix config names=plain" | sh' } as never)
    expect(r.deny).toMatch(/can't be checked \(a shell reading its script from a pipe, on a line that names p2p\)/)
    const ok = await $.tool.call({ tool: 'Bash', tool_use_id: 'b2', command: 'curl -fsSL https://example.com/install.sh | sh' } as never)
    expect(ok.deny).toBeUndefined()
  })

  test('no_hmac_key (git slow, a shallow clone) backs off exponentially instead of stopping', async ($, on) => {
    const w = world(on)
    await loaded($, w)
    w.cli['ix footprint'] = { exitCode: 1, body: { error: 'no_hmac_key', reason: 'shallow clone' } }
    await postEdit($)
    await advance(w, 11_000)
    expect(footprints(w)).toHaveLength(1)
    // Edits during the hold don't run it early: the first retry waits a minute.
    await postEdit($)
    await advance(w, 50_000)
    expect(footprints(w)).toHaveLength(1)
    await advance(w, 15_000)
    expect(footprints(w)).toHaveLength(2)
    // The next waits two minutes.
    await advance(w, 100_000)
    expect(footprints(w)).toHaveLength(2)
    await advance(w, 25_000)
    expect(footprints(w)).toHaveLength(3)
    // Once it works, normal spacing again.
    w.cli['ix footprint'] = PUBLISHED
    await advance(w, 245_000)
    expect(footprints(w)).toHaveLength(4)
    await postEdit($)
    await advance(w, 31_000)
    expect(footprints(w)).toHaveLength(5)
  })
})
