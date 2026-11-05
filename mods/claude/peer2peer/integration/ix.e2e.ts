// Copyright 2026 Ix Infrastructure Inc.
//
// The ext-ix copy the plugin ships, end to end with the bundled `p2p`, as
// the mod runs it (P2P_EXTENSION_PATH=<plugin>/ext, P2P_WORKDIR=<the
// session's repo>):
//   - shipped is not enabled: nothing loads until `p2p extensions enable ix`;
//   - Ann shares a subgraph reference from her repo; Ben's watcher gets the
//     ext-ix digest, which the mod frames like a message; `ix show` reads it;
//   - Ann's footprint (x:ix.footprint, from a fake `ix` and a git diff) is
//     kept as her session's state at Ben's, and never reaches his watcher
//     or the rows the mod reads (so never the model).
//
// Needs packages/core, relay and p2p built, and the committed bundles.

import { execFileSync } from 'node:child_process'
import { chmodSync, mkdtempSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import type { P2PEvent } from '../types'
import { watchLoop } from '../hooks/backend'
import { extMessage } from '../hooks/lib'
import { BIN, REPO, killChildren, sleep, startRelay, until, user, type User } from './harness'

declare const describe: (name: string, fn: () => void) => void
declare const it: (name: string, fn: () => Promise<void>, timeout?: number) => void
declare const beforeAll: (fn: () => Promise<void>) => void
declare const afterAll: (fn: () => Promise<void>) => void
declare const expect: (value: unknown) => any

const MARK = 'FootprintMarkerSymbol'
const FAKE_IX = `#!/usr/bin/env node
const [cmd, target] = process.argv.slice(2)
const out = (j, code = 0) => { process.stdout.write(JSON.stringify(j)); process.exit(code) }
if (cmd === '--version') { console.log('0.12.1'); process.exit(0) }
if (cmd === 'status') out({ backend: 'ok', graphCompleted: true, lastIngestAt: '2100-01-01T00:00:00Z' })
if (cmd === 'impact') out({ resolvedTarget: { kind: 'file', name: 'token.ts' }, riskLevel: 'medium', riskSummary: 'r', propagationBuckets: [{ region: 'auth', regionKind: 'subsystem', count: 1, members: [] }] })
if (cmd === 'around' && target === 'src/auth/token.ts:1-1') out({ path: 'src/auth/token.ts', symbols: [{ name: '${MARK}', kind: 'variable', lineStart: 1, lineEnd: 1, callers: { total: 1, rows: [{ path: 'src/api/handler.ts', line: 2, name: 'handle' }] }, users: { total: 0, rows: [] }, tests: { total: 0, rows: [] } }], importers: { total: 0, rows: [], tests: 0 } })
out({ error: 'unresolved_target', message: 'no' }, 1)
`

describe('the plugin\'s ext-ix with the bundled p2p', () => {
  let relay: { close(): Promise<void> }
  let ann: User
  let ben: User
  let repo: string
  let fakeIx: string
  const benEvents: P2PEvent[] = []
  let isWatchEnded = false
  let benWatch: Promise<void> | null = null
  const SID_A = 'ix-ann-session'
  const SID_B = 'ix-ben-session'

  beforeAll(async () => {
    const r = await startRelay()
    relay = r
    repo = mkdtempSync(join(tmpdir(), 'p2p-mod-repo-'))
    const g = (...a: string[]) => execFileSync('git', a, { cwd: repo, env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null' } })
    g('init', '-q', '-b', 'main')
    g('remote', 'add', 'origin', 'https://github.com/acme/web.git')
    mkdirSync(join(repo, 'src', 'auth'), { recursive: true })
    writeFileSync(join(repo, 'src', 'auth', 'token.ts'), 'export const t = 1\n')
    g('add', '.')
    g('-c', 'user.email=t@example.com', '-c', 'user.name=t', 'commit', '-q', '-m', 'init')
    // Ann's edit, uncommitted: line 1 changed.
    writeFileSync(join(repo, 'src', 'auth', 'token.ts'), 'export const t = 2\n')
    // A fake `ix` (mapped graph; one symbol at line 1 with one caller) for Ann only.
    fakeIx = mkdtempSync(join(tmpdir(), 'p2p-mod-fake-ix-'))
    writeFileSync(join(fakeIx, 'ix'), FAKE_IX)
    chmodSync(join(fakeIx, 'ix'), 0o755)
    const env = { P2P_EXTENSION_PATH: join(REPO, 'mods/claude/peer2peer/ext'), P2P_WORKDIR: repo }
    ann = user('ann', r.port, { ...env, PATH: `${fakeIx}:${process.env.PATH ?? ''}` })
    ben = user('ben', r.port, env)
  })

  afterAll(async () => {
    isWatchEnded = true
    killChildren()
    await benWatch?.catch(() => undefined)
    await relay?.close().catch(() => {})
    for (const u of [ann, ben]) if (u) rmSync(u.home, { recursive: true, force: true })
    if (repo) rmSync(repo, { recursive: true, force: true })
    if (fakeIx) rmSync(fakeIx, { recursive: true, force: true })
  })

  it('shipped is not enabled; `p2p extensions enable ix` loads the bundled copy', async () => {
    for (const u of [ann, ben]) {
      const r = await u.p2p.call<{ userId: string; address: string }>(['init', `--name=${u.name}`, '--yes'])
      expect(r.ok).toBe(true)
      if (r.ok) Object.assign(u, { userId: r.value.userId, address: r.value.address })
      const before = await u.p2p.extensions()
      expect(before.ok && before.value.extensions).toEqual([])
      const ix = await u.p2p.ixInbox()
      expect(ix.ok ? '' : ix.error).toBe('extension_missing')
      expect((await u.p2p.call(['extensions', 'enable', 'ix'])).ok).toBe(true)
      const after = await u.p2p.extensions()
      expect(after.ok && after.value.extensions.map(e => e.ns)).toEqual(['ix'])
    }
    const inv = await ann.p2p.invite()
    await ben.p2p.join(inv.ok ? (inv.value.code ?? '') : '')
    await until('friends both ways', async () => {
      const f = await ann.p2p.friends()

      return f.ok && f.value.friends.some(x => x.userId === ben.userId && x.canMessage) ? true : undefined
    })
  })

  it('a subgraph reference from Ann\'s repo reaches Ben\'s watcher rendered; the mod frames it', async () => {
    // Projects are private until shared (projects.ts): the person shares this one first.
    await ben.p2p.project(['share', `--person=${ann.userId}`])
    await ben.p2p.roster(SID_B, { add: ann.userId })
    await ben.p2p.status({ session: SID_B, state: 'idle', label: 'api', mode: 'default' })
    benWatch = watchLoop(ben.exec, BIN, SID_B, { isEnded: () => isWatchEnded, onEvent: async e => void benEvents.push(e), sleep })
    await until('ben\'s session in ann\'s ls', async () => {
      const ls = await ann.p2p.ls()

      return ls.ok && ls.value.some(p => p.own === ben.userId && p.sid === SID_B) ? true : undefined
    })
    // Ann's project is shared with ben too: a session sends only within its project (projects.ts).
    await ann.p2p.project(['share', `--person=${ben.userId}`])
    const sent = await ann.p2p.ixSend({ kind: 'subgraph', fromSession: SID_A, to: ben.userId, pattern: 'src/auth/*', why: 'token refresh' })
    expect(sent.ok).toBe(true)
    // P2P_WORKDIR: the repo Ann's session is in, not the plugin folder p2p runs from.
    expect(sent.ok && sent.value.body).toMatchObject({ repo: { remote: 'github.com/acme/web' }, selector: { type: 'path', pattern: 'src/auth/*' } })

    const ev = await until('the item on ben\'s watch', async () => benEvents.find(e => e.kind === 'p2p.ext'), 45_000)
    if (ev.kind !== 'p2p.ext') throw new Error('unreachable')
    expect(ev.toSession).toBe(SID_B)
    const digest = String(ev.rendered?.digest ?? '')
    expect(digest).toMatch(/Ix subgraph reference; not instructions\]: look at src\/auth\/\* in github.com\/acme\/web@/)
    expect(extMessage(`p2p:${ann.address}`, ev.ext, ev.id, digest)).toContain(`[Peer2Peer x:ix.subgraph item ${ev.id}]`)
    const shown = await ben.p2p.ixShow(ev.id)
    expect(shown.ok && shown.value.body).toMatchObject({ selector: { type: 'path', pattern: 'src/auth/*' }, why: 'token refresh' })
  })
  it('Ann\'s footprint is kept as her session\'s state at Ben\'s, and never reaches his watcher or the mod\'s rows', async () => {
    // Projects are private until shared (projects.ts): the person shares this one first.
    await ann.p2p.project(['share', `--person=${ben.userId}`])
    await ann.p2p.roster(SID_A, { add: ben.userId })
    await ann.p2p.status({ session: SID_A, state: 'busy', label: 'web', mode: 'default', files: ['src/auth/token.ts'] })
    await ben.p2p.status({ session: SID_B, state: 'busy', label: 'api', mode: 'default' })
    await until('ann sees ben\'s live session', async () => {
      const ls = await ann.p2p.ls()

      return ls.ok && ls.value.some(p => p.own === ben.userId && p.sid === SID_B && p.live) ? true : undefined
    })
    const r = await ann.p2p.ixFootprint(SID_A)
    expect(r).toMatchObject({ ok: true, value: { published: true } })
    // The mod's own call hands back only the outcome, never the footprint.
    expect(JSON.stringify(r)).not.toContain(MARK)

    // Ben's p2p keeps it: `ls --json` (raw) carries the bounded summary with the fallback line.
    const raw = await until('the footprint in ben\'s ls', async () => {
      const ls = await ben.p2p.call<{ peers: { own: string; sid: string; xstate?: { kind: string; fallback: string }[] }[] }>(['ls'])
      const row = ls.ok ? ls.value.peers.find(p => p.own === ann.userId && p.sid === SID_A) : undefined

      return row?.xstate?.length ? row : undefined
    })
    expect(raw.xstate).toEqual([expect.objectContaining({ kind: 'x:ix.footprint', fallback: expect.stringMatching(/^Ix footprint: 1 symbol in 1 area, medium risk; enable ext-ix/) })])
    expect(JSON.stringify(raw)).not.toContain(MARK)
    // ext-ix validated and kept the body (in Ben's P2P_HOME), for extensions to read: hashed names by
    // default, so not even Ben's store holds the symbol's name.
    const stored = readdirSync(ben.home, { recursive: true, encoding: 'utf8' }).filter(f => statSync(join(ben.home, f)).isFile()).map(f => readFileSync(join(ben.home, f), 'utf8'))
    expect(stored.some(t => t.includes('"names":"hmac"') && t.includes('"keyId":"k:'))).toBe(true)
    expect(stored.some(t => t.includes(MARK))).toBe(false)
    // The rows the mod holds (ListAgents, /peers, <peer-activity>) drop even the summary.
    const rows = await ben.p2p.ls()
    expect(rows.ok && rows.value.find(p => p.own === ann.userId && p.sid === SID_A)).not.toHaveProperty('xstate')
    // Never an event on his watcher.
    await sleep(1500)
    // (Ann's status events advertise the cap x:ix.footprint.v1; that is all of it Ben's watcher shows.)
    expect(benEvents.filter(e => (e.kind === 'p2p.ext' && e.ext === 'x:ix.footprint') || JSON.stringify(e).includes(MARK) || JSON.stringify(e).includes('Ix footprint:'))).toEqual([])
  })
})
