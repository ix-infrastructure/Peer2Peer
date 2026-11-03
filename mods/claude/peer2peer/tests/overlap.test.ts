// Copyright 2026 Ix Infrastructure Inc.

// Footprint overlaps (ext-ix SPEC §9) in the mod: high and medium overlaps
// reach the model as POSSIBLE CONFLICT lines at its next tool round, low ones
// never; each once per change in its key; peers without a footprint fall back
// to the `ix conflicts` check; nothing of a peer's footprint body reaches the
// model, only the derived line.

import { describe, expect, test } from 'claude-code/testing'
import type { Engine } from 'claude-code/testing'

import { ANA, ANA_ADDR, BEN, BEN_ADDR, ran, settle, start, world, type World } from './world'

const LOADED = { body: { extensions: [{ ns: 'ix', name: '@peer2peer/ext-ix', version: '0.1.0', commands: ['footprint', 'overlaps'] }], enabled: ['ix'] } }
const BODY_MARK = 'PEER-FOOTPRINT-BODY-TEXT'
const peer = { address: BEN_ADDR, own: BEN.own, sid: BEN.sid, ref: BEN.ref }
const ana = { address: ANA_ADDR, own: ANA.own, sid: ANA.sid, ref: ANA.ref }
const ov = (severity: 'high' | 'medium' | 'low', tier: string, what: string, key = what, who = peer) => ({
  peer: who,
  mine: 'main',
  theirs: 'a2',
  tier,
  severity,
  direction: 'both',
  via: { key: `h:${'x'.repeat(22)}` },
  key: JSON.stringify([who.own, tier, 'both', key]),
  message: `POSSIBLE CONFLICT (${severity}, ${tier}) with ${who.address} [agent a2]: ${what}`,
  // Anything else the CLI might carry is never read: a body, or the person's readable detail.
  body: { actors: [{ changed: { files: [BODY_MARK] } }] },
  detail: `DETAIL-${BODY_MARK}`,
})
const edit = (id: string, path = '/work/web/src/a.ts') => ({ tool: 'Edit', tool_use_id: id, file_path: path, old_string: 'a', new_string: 'b' }) as never

async function busy($: Engine, w: World) {
  w.cli.extensions = LOADED
  await start($, w)
  await settle(w, () => ran(w, 'extensions').length > 0)
  await $.turn.start({ text: 'work', turnId: 't1' } as never)
  await $.tool.call(edit('e0'))
}

async function tick(w: World) {
  await w.clock.advance(61_000)
  await settle(w, () => false)
}

describe('peer2peer: footprint overlaps', () => {
  test('high and medium reach the model at its next tool round; low never; nothing of the body', async ($, on) => {
    const w = world(on)
    w.peers = [{ ...BEN, repo: 'web', state: 'busy' }, { ...ANA, repo: 'web', state: 'busy' }]
    w.cli['ix overlaps'] = { body: { overlaps: [ov('high', 'same symbol', 'you both change src/a.ts#f'), ov('medium', 'same file', 'you both edit src/b.ts (different symbols)', 'b', ana), ov('low', 'same area', 'you both work in auth', 'c', ana)], fallback: [], [BODY_MARK]: BODY_MARK } }
    await busy($, w)
    await tick(w)
    await settle(w, () => ran(w, 'ix', 'overlaps').length > 0)
    const r = await $.tool.call(edit('e1'))
    const ctx = (r.context ?? []).join('\n')
    expect(ctx).toContain('<peer-activity')
    expect(ctx).toContain(`POSSIBLE CONFLICT (high, same symbol) with ${BEN_ADDR}`)
    expect(ctx).toContain('POSSIBLE CONFLICT (medium, same file)')
    expect(ctx).not.toContain('same area')
    expect(JSON.stringify([w.submits, w.contexts])).not.toContain(BODY_MARK)
    // Never as a turn of its own.
    expect(w.submits).toEqual([])
  })

  test('each overlap once per change in its key', async ($, on) => {
    const w = world(on)
    w.peers = [{ ...BEN, repo: 'web', state: 'busy' }]
    w.cli['ix overlaps'] = { body: { overlaps: [ov('high', 'same symbol', 'you both change src/a.ts#f')], fallback: [] } }
    await busy($, w)
    await tick(w)
    const first = await $.tool.call(edit('e1'))
    expect((first.context ?? []).join('\n')).toContain('you both change src/a.ts#f')
    // Same overlap again: not raised again.
    await tick(w)
    const again = await $.tool.call(edit('e2'))
    expect((again.context ?? []).join('\n')).not.toContain('POSSIBLE CONFLICT')
    // A changed key (another symbol, or a higher tier): raised, once the peer's 10 minutes are up.
    w.cli['ix overlaps'] = { body: { overlaps: [ov('high', 'same symbol', 'you both change src/a.ts#g')], fallback: [] } }
    await tick(w)
    const early = await $.tool.call(edit('e2b'))
    expect((early.context ?? []).join('\n')).not.toContain('POSSIBLE CONFLICT')
    for (let i = 0; i < 9; i++) await tick(w)
    const changed = await $.tool.call(edit('e3'))
    expect((changed.context ?? []).join('\n')).toContain('you both change src/a.ts#g')
    expect(ran(w, 'ix', 'overlaps').length).toBeGreaterThanOrEqual(3)
  })

  test('peers without a footprint: the ix around check rides along (P2P_IX_SEMANTIC_CONFLICTS=1)', async ($, on) => {
    const w = world(on, { env: { P2P_IX_SEMANTIC_CONFLICTS: '1' } })
    w.peers = [{ ...BEN, repo: 'web', state: 'busy', files: ['src/api.ts'] }]
    const c = { peer, mine: 'src/a.ts', theirs: 'src/api.ts', direction: 'mine-affects-theirs', via: ['caller'], message: `possible semantic conflict with ${BEN_ADDR}: your change to src/a.ts affects src/api.ts they're editing` }
    w.cli['ix overlaps'] = { body: { overlaps: [], fallback: [c] } }
    await busy($, w)
    await tick(w)
    const r = await $.tool.call(edit('e1'))
    expect((r.context ?? []).join('\n')).toContain('POSSIBLE SEMANTIC CONFLICT: possible semantic conflict')
    expect(ran(w, 'ix', 'overlaps').every(x => x.argv.includes('--fallback'))).toBe(true)
    // One check, not two: `ix conflicts` isn't asked separately.
    expect(ran(w, 'ix', 'conflicts')).toEqual([])
  })

  test('an ext-ix without overlaps: the ix conflicts check stands alone', async ($, on) => {
    const w = world(on, { env: { P2P_IX_SEMANTIC_CONFLICTS: '1' } })
    w.peers = [{ ...BEN, repo: 'web', state: 'busy', files: ['src/api.ts'] }]
    w.cli['ix overlaps'] = { exitCode: 1, body: { error: 'usage', reason: "unknown command 'overlaps'" } }
    w.cli['ix conflicts'] = { body: { conflicts: [{ peer, mine: 'src/a.ts', theirs: 'src/api.ts', direction: 'mine-affects-theirs', via: ['caller'], message: 'possible semantic conflict with x' }], errors: [] } }
    await busy($, w)
    await tick(w)
    await tick(w)
    expect(ran(w, 'ix', 'overlaps')).toHaveLength(1)
    expect(ran(w, 'ix', 'conflicts').length).toBeGreaterThan(0)
  })

  test('not without ext-ix, and not while idle', async ($, on) => {
    const w = world(on)
    w.peers = [{ ...BEN, repo: 'web', state: 'busy' }]
    await start($, w)
    await tick(w)
    expect(ran(w, 'ix', 'overlaps')).toEqual([])
  })
  test('M1: a peer cycling session or agent ids (new keys each time) gets one line per 10 minutes; 3 in all', async ($, on) => {
    const w = world(on)
    w.peers = [{ ...BEN, repo: 'web', state: 'busy' }, { ...ANA, repo: 'web', state: 'busy' }]
    let n = 0
    const cycle = () => {
      n++
      w.cli['ix overlaps'] = { body: { overlaps: [ov('high', 'same symbol', `you both change x${n}`, `k${n}`), ov('high', 'same symbol', `ana ${n}`, `a${n}`, ana)], fallback: [] } }
    }
    cycle()
    await busy($, w)
    const seen: string[] = []
    for (let i = 0; i < 9; i++) {
      await tick(w)
      const r = await $.tool.call(edit(`c${i}`))
      seen.push(...(r.context ?? []).join('\n').split('\n').filter(l => l.startsWith('POSSIBLE CONFLICT')))
      cycle()
    }
    // Over ~9 minutes: one line for each peer user, not one per cycled id.
    expect(seen.filter(l => l.includes(BEN_ADDR))).toHaveLength(1)
    expect(seen.filter(l => l.includes(ANA_ADDR))).toHaveLength(1)
    expect(ran(w, 'ix', 'overlaps').length).toBeGreaterThanOrEqual(9)
  })
})
