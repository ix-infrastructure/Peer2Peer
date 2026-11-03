// Copyright 2026 Ix Infrastructure Inc.

// §4.3 status caps in the mod: `status` passes the caller's caps to the CLI as
// --cap=value, and `understands()` asks whether a peer session's client
// understands one.

import { describe, expect, test } from 'claude-code/testing'
import { P2P, type Exec } from '../hooks/backend'
import { understands } from '../hooks/lib'

function fakeExec(stdout: string): { exec: Exec; calls: string[][] } {
  const calls: string[][] = []
  const exec: Exec = {
    async run(argv) {
      calls.push([...argv])

      return { exitCode: 0, stdout, stderr: '' }
    },
    spawn: () => {
      throw new Error('spawn is not used here')
    },
  }

  return { exec, calls }
}

describe('status caps', () => {
  test('status passes caps through as --cap=value', async () => {
    const f = fakeExec(JSON.stringify({ delivered: [], failed: [] }))
    await new P2P(f.exec, ['p2p']).status({ session: 's', state: 'busy', label: 'web', caps: ['agents.v1', 'x:ix.footprint.v1'] })
    expect(f.calls[0]).toEqual(['p2p', 'status', '--session=s', '--state=busy', '--label=web', '--cap=agents.v1', '--cap=x:ix.footprint.v1', '--json'])
  })

  test('understands: only a listed cap; an older client (no caps) or a malformed list understands nothing', () => {
    expect(understands({ caps: ['status.tolerant.v1', 'agents.v1'] }, 'agents.v1')).toBe(true)
    expect(understands({ caps: ['agents.v1'] }, 'agents.v2')).toBe(false)
    expect(understands({}, 'agents.v1')).toBe(false)
    expect(understands(undefined, 'agents.v1')).toBe(false)
    expect(understands({ caps: 'agents.v1' }, 'agents.v1')).toBe(false)
  })
})
