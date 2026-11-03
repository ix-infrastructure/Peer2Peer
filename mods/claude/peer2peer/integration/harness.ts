// Copyright 2026 Ix Infrastructure Inc.
//
// Shared by the integration tests: node's child_process as the mod's Exec,
// temporary P2P homes on the built CLI, an in-process relay.

import { spawn } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import type { Chunk, Exec, RunResult } from '../hooks/backend'
import { P2P } from '../hooks/backend'
// @ts-ignore: built JS, typed by its own package
import { createLogger, createRelayCrypto, makeConfig, MemoryStore, Relay } from '../../../../packages/relay/dist/index.js'

export const REPO = fileURLToPath(new URL('../../../../', import.meta.url))
/** The CLI bundled with the plugin (what users run) when it is built, else packages/p2p's. */
export const BUNDLED = join(REPO, 'mods/claude/peer2peer/bin/p2p.mjs')
export const BIN = [process.execPath, existsSync(BUNDLED) ? BUNDLED : join(REPO, 'packages/p2p/dist/bin.js')]
export const RELAY = 'wss://relay-mod.test/v3'

/** Every watch child, so the end of the test can stop them (as the engine kills a run's child). */
export const children = new Set<ReturnType<typeof spawn>>()

/** Exec over node's child_process: what `$.process` is inside Claude Code. */
export function nodeExec(env: Record<string, string>): Exec {
  const childEnv = { ...process.env, ...env }

  return {
    run: (argv, init) =>
      new Promise<RunResult>((resolve, reject) => {
        const child = spawn(argv[0] as string, argv.slice(1), { env: childEnv, stdio: ['pipe', 'pipe', 'pipe'] })
        let stdout = ''
        let stderr = ''
        const timer = setTimeout(() => child.kill('SIGKILL'), init?.timeoutMs ?? 30_000)
        child.stdout.on('data', d => (stdout += String(d)))
        child.stderr.on('data', d => (stderr += String(d)))
        child.on('error', e => {
          clearTimeout(timer)
          reject(e)
        })
        child.on('close', code => {
          clearTimeout(timer)
          resolve({ exitCode: code ?? 1, stdout, stderr })
        })
        child.stdin.end(init?.stdin ?? '')
      }),
    spawn: argv =>
      (async function* (): AsyncGenerator<Chunk, unknown> {
        const child = spawn(argv[0] as string, argv.slice(1), { env: childEnv, stdio: ['ignore', 'pipe', 'pipe'] })
        children.add(child)
        const queue: Chunk[] = []
        let ended: { code: number | null; signal: string | null } | null = null
        let wake: (() => void) | null = null
        const push = () => {
          wake?.()
          wake = null
        }
        child.stdout.on('data', d => {
          queue.push({ stream: 'stdout', text: String(d) })
          push()
        })
        child.stderr.on('data', d => {
          queue.push({ stream: 'stderr', text: String(d) })
          push()
        })
        child.on('close', (code, signal) => {
          children.delete(child)
          ended = { code, signal }
          push()
        })
        try {
          for (;;) {
            while (queue.length > 0) yield queue.shift() as Chunk
            if (ended) return ended
            await new Promise<void>(resolve => {
              wake = resolve
            })
          }
        } finally {
          if (!ended) child.kill('SIGTERM')
        }
      })(),
  }
}

export type User = { name: string; home: string; p2p: P2P; exec: Exec; userId: string; address: string }

export function user(name: string, port: number, extraEnv: Record<string, string> = {}): User {
  const home = mkdtempSync(join(tmpdir(), `p2p-mod-${name}-`))
  const exec = nodeExec({
    P2P_HOME: home,
    P2P_DEFAULT_RELAYS: RELAY,
    P2P_RELAY_TRANSPORT: JSON.stringify({ [RELAY]: `ws://127.0.0.1:${port}/v3` }),
    P2P_DRAIN_QUIET_MS: '250',
    P2P_DRAIN_MAX_MS: '4000',
    P2P_DOC_REFRESH_SEC: '0',
    P2P_CONNECT_TIMEOUT_MS: '3000',
    ...extraEnv,
  })

  return { name, home, exec, p2p: new P2P(exec, BIN), userId: '', address: '' }
}

export const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))

export async function until<T>(what: string, fn: () => Promise<T | undefined>, ms = 30_000): Promise<T> {
  const end = Date.now() + ms
  for (;;) {
    const v = await fn()
    if (v !== undefined) return v
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`)
    await sleep(300)
  }
}

/** An in-process relay from packages/relay. */
export async function startRelay(url = RELAY): Promise<{ port: number; close(): Promise<void> }> {
  const crypto = createRelayCrypto()
  const r = new Relay({
    config: makeConfig(crypto, { relayUrl: url, logLevel: 'error', powBits: 0 }),
    store: new MemoryStore(),
    crypto,
    logger: createLogger({ level: 'error', sink: () => {} }),
  })
  const port: number = await r.listen()

  return { port, close: () => r.close() }
}

/** Kills every child the tests started (as the engine kills a run's children). */
export function killChildren(): void {
  for (const child of children) child.kill('SIGTERM')
}
