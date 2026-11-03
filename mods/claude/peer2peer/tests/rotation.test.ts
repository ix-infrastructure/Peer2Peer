// Copyright 2026 Ix Infrastructure Inc.
//
// §2.8 identity rotation in the mod: `/peers rotate` (typed only) shows the
// plan first, the new fingerprint and the devices that would follow, for
// the person to drop devices and press Rotate (no secret in what the model
// reads); the CLI's held items: friends' "moved to a new key", this user's
// own identity moving (followed only on Accept), never approved by the mod,
// a conflict said plainly; and the status-line alert for a rotation this
// device didn't publish.

import { describe, expect, test } from 'claude-code/testing'
import type { Engine } from 'claude-code/testing'

import { isMutating, mutatingP2PVerb, parseEvent, parsePeersArgs, rotationAlertText, statusLine } from '../hooks/lib'
import { ANA_ADDR, ANA_ID, BEN_ADDR, BEN_ID, ME_ADDR, ME_ID, NOW_MS, from, ran, settle, slash, start, world } from './world'

const mountBand = ($: Engine) => $.ui.mount({ plugin: 'peer2peer', surface: 'terminal', component: 'AbovePrompt', props: {} } as never)

const bandText = async (ui: Awaited<ReturnType<typeof mountBand>>) => {
  const found = (await ui.findAll({ type: 'Text' } as never)) as { text?: string }[]

  return found.map(one => one.text ?? '').join('\n')
}

const NEW_ID = `p2p:${'d'.repeat(52)}`
const NEW_ADDR = 'sam@dddd-dddd-dddd-dddd'
const NEW_FP = 'dddd-dddd-dddd-dddd'
const NEW_BACKUP = '/home/sam/.p2p/backup-phrase-dddddddddddddddd.txt'
const PROOF_JWS = 'eyJhbGciOiJFZERTQSJ9.eyJwcm9vZiI6MX0.c2ln'

const PLAN = {
  plan: true,
  from: ME_ID,
  address: ME_ADDR,
  to: NEW_ID,
  newFingerprint: NEW_FP,
  follow: [
    { did: 'd_LAPTOP', label: 'laptop', keyholder: false },
    { did: 'd_STOLEN', label: 'old phone', keyholder: true },
  ],
  excluded: [{ did: 'd_THIEF', label: 'tablet', keyholder: false, labelTrusted: false, why: "added by a version you didn't publish" }],
  friends: 2,
  friendsOptIn: [{ userId: BEN_ID, address: BEN_ADDR, why: "made by a device the plan drops (added by a version you didn't publish)", invited: false }],
  owned: 1,
  memberOf: 0,
  contest: false,
  backup: { file: NEW_BACKUP },
}

const ROTATED = {
  from: ME_ID,
  to: NEW_ID,
  address: NEW_ADDR,
  fingerprint: NEW_FP,
  did: 'd_NEW',
  step: 'done',
  devices: { followed: [{ did: 'd_LAPTOP', newDid: 'd_LAPTOP2', label: 'laptop' }], offline: [], excluded: [{ did: 'd_STOLEN', label: 'old phone' }] },
  friends: { invited: 2, failed: [] },
  circles: [{ cid: 'c_team', name: 'team', role: 'owner', status: 'done' }],
  proofs: [{ kind: 'github', claim: 'sam', publish: `Replace the content of your gist https://gist.github.com/sam/1 with:\n${PROOF_JWS}` }],
  finalVer: 7,
  backup: { file: NEW_BACKUP },
  warnings: [],
}

describe('/peers rotate', () => {
  test('typed: shows the plan (new fingerprint, devices), the person drops the stolen one and presses Rotate; no secret reaches the model', async ($, on) => {
    const w = world(on)
    w.cli['identity rotate'] = { body: PLAN }
    await start($, w)
    const ui = await mountBand($)
    const out = await slash($, 'peers', 'rotate')

    // The plan only: nothing is published, nothing accepted.
    expect(ran(w, 'identity', 'rotate').map(r => r.argv)).toEqual([['p2p', 'identity', 'rotate', '--plan', '--backup-file', '--json']])
    expect(out.text).toContain('Nothing changes until you do')
    expect(out.text).not.toContain(NEW_BACKUP)
    expect(out.text).not.toContain('backup-phrase')
    const band = await bandText(ui)
    expect(band).toContain(NEW_FP)
    expect(band).toContain('laptop')
    expect(band).toContain('old phone (key holder): follows')
    // pre-release re-review N2/L1: a device this device didn't list is dropped by default, its label untrusted.
    expect(band).toContain("unverified label: tablet: DROPPED (added by a version you didn't publish)")
    expect(band).toContain(NEW_BACKUP)
    // Drop the stolen phone, then Rotate: only now is the plan accepted, with --exclude.
    await ui.press({ key: 'drop-d_STOLEN' })
    expect(await bandText(ui)).toContain('old phone (key holder): DROPPED')
    w.cli['identity rotate'] = { body: ROTATED }
    await ui.press({ key: 'rotate-accept' })
    await settle(w, () => ran(w, 'identity', 'rotate').length > 1 && w.toasts.some(t => t.includes(NEW_ADDR)))
    expect(ran(w, 'identity', 'rotate').at(-1)?.argv).toEqual(['p2p', 'identity', 'rotate', '--resume', '--yes', '--wait=240', '--exclude=d_STOLEN', '--json'])
    expect(w.toasts.find(t => t.includes(NEW_ADDR))).toContain('1 dropped device was revoked first')
    const after = await bandText(ui)
    expect(after).toContain(PROOF_JWS)
    expect(after).not.toContain('DROPPED')
    // Nothing of it reached the model.
    expect(w.submits).toEqual([])
    // The new backup file is guarded like setup's.
    const read = await $.tool.call({ tool: 'Read', tool_use_id: 'r1', file_path: NEW_BACKUP } as never)
    expect(read.isError || read.deny !== undefined).toBe(true)
  })

  test('a device the plan dropped by default follows only on an explicit Keep (--keep)', async ($, on) => {
    const w = world(on)
    w.cli['identity rotate'] = { body: PLAN }
    await start($, w)
    const ui = await mountBand($)
    await slash($, 'peers', 'rotate')
    await ui.press({ key: 'drop-d_THIEF' })
    expect(await bandText(ui)).toContain('unverified label: tablet: follows')
    w.cli['identity rotate'] = { body: ROTATED }
    await ui.press({ key: 'rotate-accept' })
    await settle(w, () => ran(w, 'identity', 'rotate').length > 1)
    expect(ran(w, 'identity', 'rotate').at(-1)?.argv).toEqual(['p2p', 'identity', 'rotate', '--resume', '--yes', '--wait=240', '--keep=d_THIEF', '--json'])
  })

  test('a friendship this device can\'t vouch for is invited only on an explicit Invite (--invite)', async ($, on) => {
    const w = world(on)
    w.cli['identity rotate'] = { body: PLAN }
    await start($, w)
    const ui = await mountBand($)
    await slash($, 'peers', 'rotate')
    expect(await bandText(ui)).toContain(`friend ${BEN_ADDR}: NOT invited (made by a device the plan drops (added by a version you didn't publish))`)
    await ui.press({ key: `invite-${BEN_ID}` })
    expect(await bandText(ui)).toContain(`friend ${BEN_ADDR}: INVITED (you chose to)`)
    w.cli['identity rotate'] = { body: ROTATED }
    await ui.press({ key: 'rotate-accept' })
    await settle(w, () => ran(w, 'identity', 'rotate').length > 1)
    expect(ran(w, 'identity', 'rotate').at(-1)?.argv).toEqual(['p2p', 'identity', 'rotate', '--resume', '--yes', '--wait=240', `--invite=${BEN_ID}`, '--json'])
  })

  test('settling a dispute on a device without the key is refused loudly; the alert stays', async ($, on) => {
    const w = world(on)
    w.cli['identity dispute'] = { exitCode: 1, body: { error: 'needs_keyholder', reason: 'settle this on a device that holds your identity key' } }
    await start($, w)
    const ui = await mountBand($)
    w.emit({ kind: 'p2p.alert', id: 'ev-k', at: NOW_MS, from: from(ME_ID, ME_ADDR), what: 'rotation-dispute' })
    const choices = [{ userId: ANA_ID, address: ANA_ADDR }, { userId: BEN_ID, address: BEN_ADDR, approved: true }]
    w.emit({ kind: 'p2p.held', id: 'ev-kh', at: NOW_MS, from: from(ME_ID, ME_ADDR), held: { id: 'd0000009', type: 'rotation-dispute', old: { userId: ME_ID, address: ME_ADDR }, choices, conflict: true } })
    await settle(w, () => w.toasts.some(t => t.includes('CONTESTED')))
    await ui.press({ key: 'keep-held:d0000009:0' })
    await settle(w, () => w.toasts.some(t => t.includes('not settled')))
    expect(w.toasts.find(t => t.includes('not settled'))).toContain('holds your identity key')
    expect(w.statuses.at(-1)).toContain('ALERT')
  })

  test('Cancel drops the plan; no --yes ever runs without the plan having been shown', async ($, on) => {
    const w = world(on)
    w.cli['identity rotate'] = { body: PLAN }
    await start($, w)
    const ui = await mountBand($)
    await slash($, 'peers', 'rotate')
    w.cli['identity rotate'] = { body: { cancelled: true } }
    await ui.press({ key: 'rotate-cancel' })
    await settle(w, () => ran(w, 'identity', 'rotate').length > 1)
    expect(ran(w, 'identity', 'rotate').at(-1)?.argv).toEqual(['p2p', 'identity', 'rotate', '--cancel', '--json'])
    expect(ran(w, 'identity', 'rotate').some(r => r.argv.includes('--yes'))).toBe(false)
    expect(await bandText(ui)).not.toContain(NEW_FP)
  })

  test('not typed: refused, nothing runs; `resume` never accepts a plan (it shows it); a failure reads as its reason', async ($, on) => {
    const w = world(on)
    await start($, w)
    const refused = await slash($, 'peer2peer', 'rotate', 'peer')
    expect(refused.text).toContain('Only what your user types at the prompt')
    expect(ran(w, 'identity', 'rotate')).toEqual([])
    // An interrupted rotation finishes; a plan not accepted yet is shown again instead.
    w.cli['identity rotate'] = { body: { ...ROTATED, backup: undefined, proofs: [] } }
    const resumed = await slash($, 'peers', 'rotate resume')
    expect(ran(w, 'identity', 'rotate').at(-1)?.argv).toEqual(['p2p', 'identity', 'rotate', '--resume', '--wait=240', '--json'])
    expect(resumed.text).toContain(`you are now ${NEW_ADDR}`)
    w.cli['identity rotate'] = { exitCode: 1, body: { error: 'needs_confirmation', reason: 'accept the rotation plan first' } }
    const planned = await slash($, 'peers', 'rotate resume')
    expect(ran(w, 'identity', 'rotate').at(-1)?.argv).toEqual(['p2p', 'identity', 'rotate', '--plan', '--backup-file', '--json'])
    expect(planned.text).toContain('Rotation failed')
    expect((await slash($, 'peer2peer', 'rotate now please')).text).toContain('Usage:')
  })

  test('the model can\'t run it through a shell either', () => {
    expect(mutatingP2PVerb('p2p identity rotate --yes')).toBe('identity rotate')
    expect(mutatingP2PVerb('bash -c "p2p identity rotate --resume"')).toBe('identity rotate')
    expect(mutatingP2PVerb('p2p identity follow f1234567')).toBe('identity follow')
    expect(mutatingP2PVerb('p2p circle hold c_x on')).toBe('circle hold')
    expect(parsePeersArgs('rotate')).toEqual({ verb: 'rotate' })
    expect(parsePeersArgs('rotate resume')).toEqual({ verb: 'rotate', resume: true })
    expect(isMutating({ verb: 'rotate' })).toBe(true)
  })
})

describe('held rotation items', () => {
  test('a friend\'s rotation is held with Accept/Decline; Accept runs p2p held approve, nothing reaches the model', async ($, on) => {
    const w = world(on)
    w.cli['held approve'] = { body: { type: 'rotation', from: BEN_ID, to: ANA_ID, friend: { userId: ANA_ID, address: ANA_ADDR } } }
    await start($, w)
    const ui = await mountBand($)
    w.emit({ kind: 'p2p.held', id: 'ev-r', at: NOW_MS, from: from(ANA_ID, ANA_ADDR), held: { id: 'r0000001', type: 'rotation', exp: 9, old: { userId: BEN_ID, address: BEN_ADDR } } })
    await settle(w, () => w.toasts.some(t => t.includes('moved to a new key')))

    expect(w.toasts.some(t => t.includes(`${BEN_ADDR} moved to a new key (${ANA_ADDR})`))).toBe(true)
    expect(await bandText(ui)).toContain('moved to a new key')
    expect(ran(w, 'held', 'approve')).toEqual([])
    await ui.press({ key: 'accept-held:r0000001' })
    await settle(w, () => ran(w, 'held', 'approve').length > 0)
    expect(ran(w, 'held', 'approve')[0]?.argv).toEqual(['p2p', 'held', 'approve', '--json', '--', 'r0000001'])
    await settle(w, () => w.toasts.some(t => t.includes('under their new key')))
    expect(w.submits).toEqual([])
  })

  test('this user\'s own identity moving: held with the new fingerprint and the device; followed only on Accept', async ($, on) => {
    const w = world(on)
    w.cli['held approve'] = { body: { type: 'rotation-follow', userId: NEW_ID, address: NEW_ADDR, did: 'd_N', from: ME_ID, keyholder: false } }
    await start($, w)
    const ui = await mountBand($)
    w.emit({ kind: 'p2p.held', id: 'ev-f', at: NOW_MS, from: from(NEW_ID, NEW_ADDR), held: { id: 'f0000001', type: 'rotation-follow', newFingerprint: NEW_FP, device: 'd_KH', deviceLabel: 'desk', old: { userId: ME_ID, address: ME_ADDR } } })
    await settle(w, () => w.toasts.some(t => t.includes('Your identity is moving')))
    const band = await bandText(ui)
    expect(band).toContain(`Your identity is moving to ${NEW_FP}, started by your device "desk"`)
    expect(band).toContain('p2p identity rotate --contest')
    // Nothing follows by itself.
    expect(ran(w, 'held', 'approve')).toEqual([])
    await ui.press({ key: 'accept-held:f0000001' })
    await settle(w, () => w.toasts.some(t => t.includes('moved with your identity')))
    expect(ran(w, 'held', 'approve')[0]?.argv).toEqual(['p2p', 'held', 'approve', '--json', '--', 'f0000001'])
    expect(w.submits).toEqual([])
  })

  test('a conflict is said plainly; an admin\'s rights wait; a rotated member\'s circle request declined runs p2p held decline', async ($, on) => {
    const w = world(on)
    await start($, w)
    const ui = await mountBand($)
    w.emit({ kind: 'p2p.held', id: 'ev-x', at: NOW_MS, from: from(ANA_ID, ANA_ADDR), held: { id: 'r0000002', type: 'rotation', old: { userId: BEN_ID, address: BEN_ADDR }, conflict: true } })
    await settle(w, () => w.toasts.some(t => t.includes('CONFLICT')))
    expect(w.toasts.find(t => t.includes('CONFLICT'))).toContain(`more than one new key claims to be ${BEN_ADDR}`)
    w.emit({ kind: 'p2p.held', id: 'ev-a', at: NOW_MS, from: from(ANA_ID, ANA_ADDR), held: { id: 's0000002', type: 'rotation-join', cid: 'c_team', reason: 'admin', old: { userId: BEN_ID, address: BEN_ADDR } } })
    await settle(w, () => w.toasts.some(t => t.includes('was an admin')))
    w.emit({ kind: 'p2p.held', id: 'ev-j', at: NOW_MS, from: from(ANA_ID, ANA_ADDR), held: { id: 's0000001', type: 'rotation-join', cid: 'c_team', old: { userId: BEN_ID, address: BEN_ADDR } } })
    await settle(w, () => w.toasts.some(t => t.includes('take their place')))
    await ui.press({ key: 'decline-held:s0000001' })
    await settle(w, () => ran(w, 'held', 'decline').length > 0)
    expect(ran(w, 'held', 'decline')[0]?.argv).toEqual(['p2p', 'held', 'decline', '--json', '--', 's0000001'])
    expect(ran(w, 'held', 'approve')).toEqual([])
    expect(w.submits).toEqual([])
  })

  test('an approved move now contested: suspended, an alert, and Keep one / Neither on the person\'s press', async ($, on) => {
    const w = world(on)
    w.cli['identity dispute'] = { body: { keep: ANA_ID, rejected: [BEN_ID] } }
    await start($, w)
    const ui = await mountBand($)
    w.emit({ kind: 'p2p.alert', id: 'ev-d', at: NOW_MS, from: from(ME_ID, ME_ADDR), what: 'rotation-dispute' })
    const choices = [{ userId: ANA_ID, address: ANA_ADDR }, { userId: BEN_ID, address: BEN_ADDR, approved: true }]
    w.emit({ kind: 'p2p.held', id: 'ev-dh', at: NOW_MS, from: from(ME_ID, ME_ADDR), held: { id: 'd0000001', type: 'rotation-dispute', old: { userId: ME_ID, address: ME_ADDR }, choices, conflict: true } })
    await settle(w, () => w.toasts.some(t => t.includes('CONTESTED')))
    expect(w.statuses.at(-1)).toContain('ALERT')
    const band = await bandText(ui)
    expect(band).toContain('CONTESTED')
    expect(band).toContain('suspended')
    await ui.press({ key: 'keep-held:d0000001:0' })
    await settle(w, () => ran(w, 'identity', 'dispute').length > 0)
    expect(ran(w, 'identity', 'dispute')[0]?.argv).toEqual(['p2p', 'identity', 'dispute', `--keep=${ANA_ID}`, '--json', '--', 'd0000001'])
    w.emit({ kind: 'p2p.held', id: 'ev-dh2', at: NOW_MS, from: from(ME_ID, ME_ADDR), held: { id: 'd0000002', type: 'rotation-dispute', old: { userId: ME_ID, address: ME_ADDR }, choices, conflict: true } })
    await settle(w, () => false)
    await ui.press({ key: 'neither-held:d0000002' })
    await settle(w, () => ran(w, 'identity', 'dispute').length > 1)
    expect(ran(w, 'identity', 'dispute')[1]?.argv).toEqual(['p2p', 'identity', 'dispute', '--neither', '--json', '--', 'd0000002'])
    expect(ran(w, 'held', 'approve')).toEqual([])
    expect(w.submits).toEqual([])
    expect(mutatingP2PVerb('p2p identity dispute d1 --neither')).toBe('identity dispute')
  })

  test('a rotation this device didn\'t publish raises a status-line alert (and a toast)', async ($, on) => {
    const w = world(on)
    await start($, w)
    w.emit({ kind: 'p2p.alert', id: 'ev-al', at: NOW_MS, from: from(ME_ID, ME_ADDR, true), what: 'rotation', to: NEW_ID, fingerprint: NEW_FP, keyholder: true, contest: 'p2p identity rotate --contest' })
    await settle(w, () => (w.statuses.at(-1) ?? '').includes('ALERT'))
    expect(w.statuses.at(-1)).toContain(`your identity is being moved to ${NEW_FP}`)
    expect(w.statuses.at(-1)).toContain('p2p identity rotate --contest')
    expect(w.toasts.some(t => t.includes('Peer2Peer ALERT'))).toBe(true)
    expect(w.submits).toEqual([])
  })

  test('watch lines and the alert text: the new types parse; malformed ones are dropped', () => {
    const f = { userId: ANA_ID, address: ANA_ADDR }
    expect(parseEvent(JSON.stringify({ kind: 'p2p.held', id: 'h', at: 1, from: f, held: { id: 'r1', type: 'rotation', old: { userId: ME_ID, address: ME_ADDR } } }))?.kind).toBe('p2p.held')
    expect(parseEvent(JSON.stringify({ kind: 'p2p.held', id: 'h', at: 1, from: f, held: { id: 'f1', type: 'rotation-follow', newFingerprint: NEW_FP } }))?.kind).toBe('p2p.held')
    expect(parseEvent(JSON.stringify({ kind: 'p2p.held', id: 'h', at: 1, from: f, held: { id: 'r1', type: 'rotation', old: 'p2p:x' } }))).toBeNull()
    expect(parseEvent(JSON.stringify({ kind: 'p2p.alert', id: 'a', at: 1, from: f, what: 'rotation' }))?.kind).toBe('p2p.alert')
    expect(parseEvent(JSON.stringify({ kind: 'p2p.alert', id: 'a', at: 1, from: f }))).toBeNull()
    // Only a well-formed fingerprint is repeated; the line comes first.
    expect(rotationAlertText({ fingerprint: '<b>x</b>', keyholder: false })).toContain('moved to a new key')
    expect(statusLine({ isCliMissing: false, identity: { state: 'ok' } as never, relays: { up: 1, total: 1, down: [] }, online: 3, held: 0, alert: 'x' })).toBe('p2p: ALERT: x')
  })
})
