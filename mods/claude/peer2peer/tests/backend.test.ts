// Copyright 2026 Ix Infrastructure Inc.

// The backend layer over a fake Exec: argv shapes, stdin, JSON and error
// parsing, notify-when-idle, and the watch loop's restart rules.

import { describe, expect, test } from 'claude-code/testing'

import type { P2PEvent } from '../types'
import type { Chunk, Exec, RunResult } from '../hooks/backend'
import { P2P, watchLoop } from '../hooks/backend'
import { BEN, BEN_ADDR, BEN_ID } from './world'

type Call = { argv: readonly string[]; stdin?: string; timeoutMs?: number }

function fakeExec(answer: (argv: readonly string[]) => RunResult | Error, streams: (() => AsyncGenerator<Chunk, unknown>)[] = []) {
  const calls: Call[] = []
  const spawned: (readonly string[])[] = []
  const exec: Exec = {
    run: async (argv, init) => {
      calls.push({ argv, ...(init?.stdin !== undefined ? { stdin: init.stdin } : {}), ...(init?.timeoutMs !== undefined ? { timeoutMs: init.timeoutMs } : {}) })
      const a = answer(argv)
      if (a instanceof Error) throw a

      return a
    },
    spawn: argv => {
      spawned.push(argv)
      const next = streams.shift()
      if (!next) throw new Error('spawn ENOENT')

      return next()
    },
  }

  return { exec, calls, spawned }
}

const ok = (body: object, stderr = ''): RunResult => ({ exitCode: 0, stdout: `${JSON.stringify(body)}\n`, stderr })
const fail = (body: object): RunResult => ({ exitCode: 1, stdout: `${JSON.stringify(body)}\n`, stderr: '' })
const sendResult = { delivered: true, to: { userId: BEN_ID, address: BEN_ADDR, own: BEN_ID, sid: BEN.sid, ref: BEN.ref }, relays: 2, devices: 1 }

describe('backend: calls', () => {
  test('--json goes before --, so a positional can never be read as a flag', async () => {
    const f = fakeExec(() => ok({ held: [] }))
    const p = new P2P(f.exec, ['p2p'])
    await p.heldApprove('--yes')
    await p.roster('sid-1', { add: '--evil' })
    expect(f.calls[0]?.argv).toEqual(['p2p', 'held', 'approve', '--json', '--', '--yes'])
    expect(f.calls[1]?.argv).toEqual(['p2p', 'session', 'roster', '--add=--evil', '--json', '--', 'sid-1'])
  })

  test('ixConflicts asks ext-ix with --session=, and keeps only well-formed rows', async () => {
    const good = { peer: { address: BEN_ADDR, own: BEN_ID, sid: BEN.sid, ref: BEN.ref }, mine: 'src/a.ts', theirs: 'src/b.ts', direction: 'mine-affects-theirs', via: ['caller'], message: 'possible semantic conflict with ben' }
    const f = fakeExec(() => ok({ conflicts: [good, { message: 1 }, null], errors: [] }))
    const p = new P2P(f.exec, ['p2p'])
    const r = await p.ixConflicts('-sid')
    expect(f.calls[0]?.argv).toEqual(['p2p', 'ix', 'conflicts', '--session=-sid', '--json'])
    expect(r.ok && r.value).toEqual([good])
    const missing = new P2P(fakeExec(() => fail({ error: 'extension_missing', reason: 'install @peer2peer/ext-ix' })).exec, ['p2p'])
    expect(await missing.ixConflicts('s')).toMatchObject({ ok: false, error: 'extension_missing' })
  })

  test('status sends the working-on fields as --opt=value', async () => {
    const f = fakeExec(() => ok({ delivered: [], failed: [] }))
    const p = new P2P(f.exec, ['p2p'])
    await p.status({ session: 's', state: 'busy', label: 'web', repo: 'web', branch: 'main', mode: 'default', summary: '-starts with a dash', files: ['src/a.ts', 'b.md'] })
    expect(f.calls[0]?.argv).toEqual([
      'p2p', 'status', '--session=s', '--state=busy', '--label=web', '--repo=web', '--branch=main', '--mode=default',
      '--summary=-starts with a dash', '--file=src/a.ts', '--file=b.md', '--json',
    ])
  })

  test('send reads the text with --stdin (never on argv); notify-when-idle rides the same call', async () => {
    const f = fakeExec(() => ok(sendResult))
    const p = new P2P(f.exec, ['p2p'])
    const plain = await p.send({ fromSession: 's', to: `${BEN_ID} [a1b2c3]`, text: 'hello\nworld' })
    expect(plain.ok).toBe(true)
    expect(f.calls).toEqual([{ argv: ['p2p', 'send', '--from-session=s', `--to=${BEN_ID} [a1b2c3]`, '--stdin', '--json'], stdin: 'hello\nworld', timeoutMs: 30_000 }])

    await p.send({ fromSession: 's', to: 'ben', text: 'tell me when idle', notifyWhenIdle: true })
    expect(f.calls.length).toBe(2)
    expect(f.calls[1]?.argv).toEqual(['p2p', 'send', '--from-session=s', '--to=ben', '--notify-when-idle', '--stdin', '--json'])
    expect(f.calls[1]?.stdin).toBe('tell me when idle')
    expect(f.calls.every(c => !c.argv.includes('tell me when idle'))).toBe(true)
  })

  test('a failure carries the CLI\'s error and reason; a missing binary says so', async () => {
    const f = fakeExec(argv => (argv[1] === 'ls' ? new Error('spawn p2p ENOENT') : fail({ error: 'ambiguous', reason: 'ben has 2 live sessions', candidates: [{ address: BEN_ADDR, ref: 'a1b2c3' }] })))
    const p = new P2P(f.exec, ['/opt/p2p'])
    const sent = await p.send({ fromSession: 's', to: 'ben', text: 'x' })
    expect(sent).toMatchObject({ ok: false, error: 'ambiguous', reason: 'ben has 2 live sessions' })
    const ls = await p.ls()
    expect(ls).toMatchObject({ ok: false, error: 'cli_missing' })
  })

  test('ls hands back the relays field; a malformed one is dropped', async () => {
    const relays = { listed: ['wss://r1/v3', 'wss://r2/v3'], connected: ['wss://r1/v3'], failed: [{ url: 'wss://r2/v3', reason: 'timeout' }] }
    const f = fakeExec(argv => (argv.includes('--all') ? ok({ peers: [], relays: { listed: 'x' } }) : ok({ peers: [BEN], relays })))
    const p = new P2P(f.exec, ['p2p'])
    const r = await p.ls()
    expect(r.ok && r.value).toEqual([BEN])
    expect(r.relays).toEqual(relays)
  })

  test('/peers circle passes the person\'s flags as flags and the rest after --', async () => {
    const f = fakeExec(() => ok({}))
    const p = new P2P(f.exec, ['p2p'])
    await p.circle(['join', 'p2p://circle/abc', '--yes'])
    expect(f.calls[0]?.argv).toEqual(['p2p', 'circle', 'join', '--yes', '--json', '--', 'p2p://circle/abc'])
    await p.circle(['join', 'p2p://circle/abc', '--wait', '30'])
    expect(f.calls[1]?.argv).toEqual(['p2p', 'circle', 'join', '--wait=30', '--json', '--', 'p2p://circle/abc'])
    await p.circle(['transfer', 'c1', 'ben', '--consent=eyJ.x.y'])
    expect(f.calls[2]?.argv).toEqual(['p2p', 'circle', 'transfer', '--consent=eyJ.x.y', '--json', '--', 'c1', 'ben'])
  })
})

async function* lines(texts: string[], end: { code: number | null; signal: string | null }, stderr?: string): AsyncGenerator<Chunk, unknown> {
  for (const text of texts) yield { stream: 'stdout', text }
  if (stderr) yield { stream: 'stderr', text: stderr }

  return end
}

describe('backend: watch loop', () => {
  test('parses lines across chunks, restarts with backoff on exit, and reports the fatal reason', async () => {
    const message = { kind: 'p2p.message', id: 'e1', at: 1, from: { userId: BEN_ID, did: 'd', address: BEN_ADDR, self: false }, own: BEN_ID, sid: 's', ref: 'a1b2c3', text: 'hi' }
    const line = JSON.stringify(message)
    let ended = false
    const events: P2PEvent[] = []
    const exits: { code: number | null; reason: string; waitMs: number }[] = []
    const sleeps: number[] = []
    const f = fakeExec(() => ok({}), [
      () => lines([line.slice(0, 10), `${line.slice(10)}\nnot json\n`], { code: 1, signal: null }, 'p2p watch: no_identity: no identity here yet\n'),
      () => lines([], { code: 1, signal: null }, 'p2p watch: no_relay: could not reach any of your relays\n'),
      () => lines([`${line}\n`], { code: 0, signal: null }),
    ])
    await watchLoop(f.exec, ['p2p'], 'sid-1', {
      isEnded: () => ended,
      onEvent: async e => {
        events.push(e)
      },
      onExit: end => {
        exits.push(end)
        if (exits.length === 3) ended = true
      },
      sleep: async ms => {
        sleeps.push(ms)
      },
    })

    expect(f.spawned).toEqual([['p2p', 'watch', '--session=sid-1', '--jsonl'], ['p2p', 'watch', '--session=sid-1', '--jsonl'], ['p2p', 'watch', '--session=sid-1', '--jsonl']])
    expect(events.map(e => e.id)).toEqual(['e1', 'e1'])
    expect(exits.map(e => e.reason)).toEqual(['no_identity: no identity here yet', 'no_relay: could not reach any of your relays', 'exited 0'])
    // The first exit after output starts the backoff again; a second exit in a row waits longer.
    expect(sleeps).toEqual([1_000, 2_000])
  })

  test('L3: the run\'s end kills the child and ends the loop, though no line ever comes', async () => {
    let killed = 0
    const trace: string[] = []
    let wake: (() => void) | null = null
    async function* silent(): AsyncGenerator<Chunk, unknown> {
      try {
        // Never yields: a watcher waiting for its next line.
        await new Promise<void>(resolve => {
          wake = resolve
        })
      } finally {
        // (the engine's child would be gone here)
      }

      return { code: null, signal: 'SIGTERM' }
    }
    const signals: (AbortSignal | undefined)[] = []
    const exec: Exec = {
      run: async () => ok({}),
      spawn: (_argv, init) => {
        signals.push(init?.signal)
        const inner = silent()
        // As the engine's stream does: return() kills the child at once.
        const child = {
          next: () => inner.next(),
          throw: (e: unknown) => inner.throw(e),
          return: async (value: unknown) => {
            killed++
            ;(wake as (() => void) | null)?.()
            return inner.return(value)
          },
          [Symbol.asyncIterator]() {
            return this
          },
        } as unknown as AsyncGenerator<Chunk, unknown>

        return child
      },
    }
    const stop = new AbortController()
    const loop = watchLoop(exec, ['p2p'], 's', { isEnded: () => false, onEvent: async () => undefined, sleep: async () => undefined, signal: stop.signal, setChild: c => trace.push(c ? 'child' : 'null'), onExit: e => trace.push('exit:' + e.reason) })
    for (let i = 0; i < 100 && signals.length === 0; i++) await Promise.resolve()
    expect(signals.length).toBe(1)
    stop.abort()
    await loop
    for (let i = 0; i < 5; i++) await Promise.resolve()
    expect(signals[0]).toBe(stop.signal)
    expect(killed).toBeGreaterThan(0)
    expect(trace).toEqual(['child', 'null'])
  })

  test('L3: the backoff resets only after a child stayed up 10 s, not on its first line', async () => {
    const line = JSON.stringify({ kind: 'p2p.contact', id: 'c', at: 1, from: { userId: BEN_ID, did: 'd', address: BEN_ADDR, self: false }, what: 'cap' })
    let clock = 0
    const uptimes = [0, 0, 12_000, 0]
    let n = 0
    const streams = uptimes.map(up => async function* (): AsyncGenerator<Chunk, unknown> {
      yield { stream: 'stdout', text: `${line}\n` }
      clock += up

      return { code: 1, signal: null }
    })
    const f = fakeExec(() => ok({}), streams)
    const sleeps: number[] = []
    await watchLoop(f.exec, ['p2p'], 's', {
      isEnded: () => n >= uptimes.length,
      onEvent: async () => undefined,
      onExit: () => {
        n++
      },
      sleep: async ms => {
        sleeps.push(ms)
      },
      now: () => clock,
    })
    // 1st and 2nd die at once (backoff grows despite their output); the 3rd stayed up, so the 4th starts over.
    expect(sleeps).toEqual([1_000, 2_000, 1_000])
  })

  test('a binary that cannot start backs off like an exit', async () => {
    let n = 0
    const f = fakeExec(() => ok({}), [])
    const exits: { isMissing: boolean }[] = []
    await watchLoop(f.exec, ['p2p'], 's', {
      isEnded: () => n >= 2,
      onEvent: async () => undefined,
      onExit: end => {
        exits.push(end)
        n++
      },
      sleep: async () => undefined,
    })
    expect(exits.every(e => e.isMissing)).toBe(true)
  })
})
