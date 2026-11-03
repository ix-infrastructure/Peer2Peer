// Copyright 2026 Ix Infrastructure Inc.

// Extension state kinds (§4.3, cap xstate.v1; footprint P2) never reach the
// model: the CLI never logs one as an event, a `p2p.ext` line that carries
// `state` is dropped anyway (no toast, no delivery), and the `xstate`
// summaries `p2p ls --json` adds are dropped before the mod holds a row, so
// ListAgents, /peers and <peer-activity> can't show them.

import { describe, expect, test } from 'claude-code/testing'

import { parseEvent } from '../hooks/lib'
import { BEN, BEN_ADDR, BEN_ID, from, gather, NOW_MS, settle, sidOf, slash, start, world, type World } from './world'

const MARK = 'FOOTPRINT-STATE-LINE'
const extLine = (toSession: string) => ({
  kind: 'p2p.ext',
  id: 'p2p.ext:state001',
  at: NOW_MS,
  from: from(BEN_ID, BEN_ADDR),
  own: BEN_ID,
  sid: BEN.sid,
  ref: BEN.ref,
  rule: 'owner',
  toSession,
  ext: 'x:ix.footprint',
  fallback: `${BEN_ADDR}: ${MARK}`,
  rendered: { digest: `[data from peer ${BEN_ADDR}]: ${MARK}` },
})
const stateEvent = (w: World) => ({ ...extLine(sidOf(w)), state: { ttl: 600 } })
const withState = { ...BEN, repo: 'web', summary: 'Refactoring login.', xstate: [{ kind: 'x:ix.footprint', at: NOW_MS, expiresAt: NOW_MS + 600_000, fallback: MARK, bytes: 40 }] }

describe('peer2peer: extension state kinds never reach the model', () => {
  test('a p2p.ext line carrying state is not an event', () => {
    expect(parseEvent(JSON.stringify({ ...extLine('s'), state: { ttl: 600 } }))).toBeNull()
    expect(parseEvent(JSON.stringify(extLine('s')))).not.toBeNull()
  })

  test('one arriving on the watch stream is neither delivered nor toasted', async ($, on) => {
    const w = world(on)
    await start($, w)
    w.emit(stateEvent(w))
    await gather(w)
    expect(w.submits).toEqual([])
    expect(w.toasts.filter(t => t.includes(MARK))).toEqual([])
    expect(w.notices.filter(t => t.includes(MARK))).toEqual([])
  })

  test('ls rows\' xstate summaries reach neither ListAgents, /peers nor <peer-activity>', async ($, on) => {
    const w = world(on)
    w.peers = [withState as never]
    await start($, w)
    const listed = await $.tool.call({ tool: 'ListAgents', tool_use_id: 't1' })
    const listing = (listed.result as { listing: string }).listing
    expect(listing).toContain('Refactoring login.')
    expect(listing).not.toContain(MARK)
    const peersOut = (await slash($, 'peers', '')) as { text: string }
    expect(peersOut.text).toContain('Refactoring login.')
    expect(peersOut.text).not.toContain(MARK)
    await $.turn.start({ text: 'work', turnId: 't1' } as never)
    await w.clock.advance(60_000)
    await settle(w, () => false)
    const next = await $.tool.call({ tool: 'Edit', tool_use_id: 'e1', file_path: '/work/web/src/a.ts', old_string: 'a', new_string: 'b' } as never)
    const context = (next.context ?? []).join('\n')
    expect(context).not.toContain(MARK)
    expect(JSON.stringify(w.submits) + JSON.stringify(w.contexts)).not.toContain(MARK)
  })
})
