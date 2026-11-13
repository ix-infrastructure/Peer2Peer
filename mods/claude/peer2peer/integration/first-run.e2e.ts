// Copyright 2026 Ix Infrastructure Inc.
//
// A fresh install, as the mod runs it (PR #30 review R1): no `p2p` state at all, no token seeded,
// p2p run from inside Claude Code (CLAUDECODE=1). The person's typed /peers join and /peers accept
// widen sharing, so the CLI wants the person token; the mod makes it itself (PERSON_TOKEN_SCRIPT,
// the code its readPersonToken runs) before any typed command. Without it they are refused.

import { existsSync, readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'

import { modPersonToken, startRelay, user, type User } from './harness'

declare const describe: (name: string, fn: () => void) => void
declare const it: (name: string, fn: () => Promise<void>, timeout?: number) => void
declare const beforeAll: (fn: () => Promise<void>) => void
declare const afterAll: (fn: () => Promise<void>) => void
declare const expect: (value: unknown) => any

describe('first run through the mod: join and accept on a fresh install', () => {
  let relay: { port: number; close(): Promise<void> }
  const made: User[] = []

  beforeAll(async () => {
    relay = await startRelay()
  })

  afterAll(async () => {
    await relay?.close().catch(() => {})
    for (const u of made) rmSync(u.home, { recursive: true, force: true })
  })

  it('without the token a typed join is refused; with the one the mod makes, join and accept work', async () => {
    const ann = user('ann', relay.port)
    made.push(ann)
    expect((await ann.p2p.setup('ann')).ok).toBe(true)
    const inv = await ann.p2p.invite('first')
    expect(inv.ok).toBe(true)
    if (!inv.ok) return
    const code = inv.value.code ?? ''

    // Ben: a fresh home, nothing seeded.
    const bare = user('ben', relay.port, {}, { token: false })
    made.push(bare)
    expect(existsSync(join(bare.home, 'cli', 'person.key'))).toBe(false)
    const refused = await bare.p2p.joinPreview(code)
    expect(refused.ok ? 'ok' : refused.error).toBe('refused')
    // What the mod does before any typed /peers command: make the token (exclusively), then pass it.
    const ben = user('ben', relay.port, {}, { home: bare.home })
    const first = modPersonToken(bare.home)
    expect(first).toMatch(/^[A-Za-z0-9_-]{43}$/)
    const preview = await ben.p2p.joinPreview(code)
    expect(preview.ok).toBe(true)
    const joined = await ben.p2p.join(code)
    expect(joined.ok ? 'joined' : `${joined.error}: ${joined.reason}`).toBe('joined')
    // #70: the join made the identity, so the CLI replaced person.key; the token the mod made before
    // no longer counts. The mod's next widening command is refused as stale, reads the file again and
    // runs once more.
    expect(readFileSync(join(bare.home, 'cli', 'person.key'), 'utf8')).not.toBe(first)
    const next = await ben.p2p.call<{ code?: string }>(['invite', '--no-circle'])
    expect(next.ok ? 'invited' : `${next.error}: ${next.reason}`).toBe('invited')

    // Accept, on another fresh home: a long link.
    const link = await ann.p2p.call<{ link: string }>(['invite', '--link'])
    expect(link.ok).toBe(true)
    if (!link.ok) return
    const carolBare = user('carol', relay.port, {}, { token: false })
    made.push(carolBare)
    expect((await carolBare.p2p.setup('carol')).ok).toBe(true)
    const no = await carolBare.p2p.accept(link.value.link)
    expect(no.ok ? 'ok' : no.error).toBe('refused')
    const carol = user('carol', relay.port, {}, { home: carolBare.home })
    const yes = await carol.p2p.accept(link.value.link)
    expect(yes.ok ? 'accepted' : `${yes.error}: ${yes.reason}`).toBe('accepted')
  }, 120_000)
})
