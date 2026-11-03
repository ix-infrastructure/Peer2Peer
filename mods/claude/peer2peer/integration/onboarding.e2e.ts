// Copyright 2026 Ix Infrastructure Inc.
//
// The low-friction path, end to end, through the mod's backend layer: two
// fresh homes run `p2p setup`, one makes a short invite code, the other runs
// `p2p join <code>` (friends, circle, default in one step), and then the two
// sessions see each other. The CLI side (setup, short codes, join, the
// bundled bin/p2p.mjs) is the feat/short-invites PR: until a CLI with
// `setup` is built, this file skips itself and says so.

import { rmSync } from 'node:fs'

import type { P2PEvent, PeerRow } from '../types'
import { watchLoop } from '../hooks/backend'
import { BIN, killChildren, nodeExec, sleep, startRelay, until, user, type User } from './harness'

declare const describe: { skipIf: (cond: boolean) => (name: string, fn: () => void) => void }
declare const it: (name: string, fn: () => Promise<void>, timeout?: number) => void
declare const beforeAll: (fn: () => Promise<void>) => void
declare const afterAll: (fn: () => Promise<void>) => void
declare const expect: (value: unknown) => any

// The CLI's own command list (an unknown `setup --help` would print the top-level help and exit 0).
const probe = await nodeExec({}).run([...BIN, '--help'], { timeoutMs: 15_000 }).catch(() => ({ exitCode: 1, stdout: '' }))
const hasSetup = probe.exitCode === 0 && /^\s+setup\b/m.test(probe.stdout) && /^\s+join\b/m.test(probe.stdout)
if (!hasSetup) console.warn(`onboarding.e2e: skipped: ${BIN.join(' ')} has no \`setup\` (needs the feat/short-invites CLI)`)

describe.skipIf(!hasSetup)('onboarding: setup, invite, join, and the sessions see each other', () => {
  let relay: { close(): Promise<void> }
  let ann: User
  let ben: User
  const SID_A = 'onboard-ann'
  const SID_B = 'onboard-ben'
  const annEvents: P2PEvent[] = []
  let isWatchEnded = false

  beforeAll(async () => {
    const r = await startRelay()
    relay = r
    ann = user('ann', r.port)
    ben = user('ben', r.port)
  })

  afterAll(async () => {
    isWatchEnded = true
    killChildren()
    await relay?.close().catch(() => {})
    for (const u of [ann, ben]) if (u) rmSync(u.home, { recursive: true, force: true })
  })

  it('a fresh home has no identity; setup makes one and writes the backup phrase to a 0600 file', async () => {
    for (const u of [ann, ben]) {
      const before = await u.p2p.whoami()
      expect(before.ok ? '' : before.error).toBe('no_identity')
      const r = await u.p2p.setup(u.name)
      expect(r.ok).toBe(true)
      if (!r.ok) return
      Object.assign(u, { userId: r.value.userId, address: r.value.address })
      expect(r.value.address).toMatch(new RegExp(`^${u.name}@[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}$`))
      expect(Boolean(r.value.backup?.file || r.value.backup?.phrase)).toBe(true)
      // Idempotent: a second setup keeps the identity.
      const again = await u.p2p.setup(u.name)
      expect(again.ok && again.value.userId).toBe(r.value.userId)
    }
  })

  it('invite makes a short code; join friends in one step; the inviter is told who joined, with the remove command', async () => {
    // Ann's session is watching, as the mod's run does.
    void watchLoop(ann.exec, BIN, SID_A, { isEnded: () => isWatchEnded, onEvent: async e => void annEvents.push(e), sleep })
    const inv = await ann.p2p.invite('pairing')
    expect(inv.ok).toBe(true)
    if (!inv.ok) return
    const code = inv.value.code ?? ''
    // Crockford base32 groups of four: 16 characters, or 20 after a pre-release review.
    expect(code).toMatch(/\/[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3,4}$/)
    expect(inv.value.label).toBe('pairing')
    expect(inv.value.uses).toBe(1)
    expect(typeof inv.value.expiresAt).toBe('number')
    const joined = await ben.p2p.join(code)
    expect(joined.ok).toBe(true)
    if (!joined.ok) return
    expect(joined.value.friend.userId).toBe(ann.userId)
    // No circle to join here (Ann has no default circle): an explicit null, not a missing key.
    expect(joined.value.circle).toBe(null)
    const event = await until('the join notice on ann\'s watch', async () => annEvents.find(e => e.kind === 'p2p.joined'), 45_000)
    if (event.kind !== 'p2p.joined') throw new Error('unreachable')
    expect(event.from.userId).toBe(ben.userId)
    expect(event.label).toBe('pairing')
    expect(event.remove).toBe(`p2p remove ${ben.userId}`)
    // The non-secret id the mod matches auto-share on, exactly (review L1).
    expect(typeof inv.value.lid).toBe('string')
    expect(event.lid).toBe(inv.value.lid)
  })

  it('then the two sessions see each other', async () => {
    // What the mod does: the joiner shares its session with the inviter (no circle), and the
    // inviter's session that made the code shares itself with whoever redeemed it.
    const shared = await ben.p2p.roster(SID_B, { add: ann.userId })
    expect(shared.ok).toBe(true)
    const back = await ann.p2p.roster(SID_A, { add: ben.userId })
    expect(back.ok).toBe(true)
    for (const [u, sid] of [[ann, SID_A], [ben, SID_B]] as const) await u.p2p.status({ session: sid, state: 'idle', label: u.name })
    const sees = (u: User, other: User, sid: string) =>
      until(`${u.name} sees ${other.name}'s session`, async () => {
        const ls = await u.p2p.ls()
        if (ls.ok && ls.value.some((p: PeerRow) => p.own === other.userId && p.sid === sid)) return true
        await u.p2p.status({ session: u === ann ? SID_A : SID_B, state: 'idle', label: u.name })

        return undefined
      })
    await sees(ben, ann, SID_A)
    await sees(ann, ben, SID_B)
  })
})
