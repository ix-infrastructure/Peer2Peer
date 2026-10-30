// Copyright 2026 Ix Infrastructure Inc.

// The engine beneath the plugin in tests: a fake `p2p` CLI answering from
// memory through `process.run`, a `p2p watch` stream the test feeds through
// `process.spawn`, and the engine events the mod relies on.

import { mock } from 'claude-code/testing'
import type { Engine, MockClock } from 'claude-code/testing'
import type { On, RenderElement } from 'claude-code'

import type { CircleSummary, FriendsInfo, HeldItem, P2PEvent, PeerRow, Whoami } from '../types'

export const ME_ID = `p2p:${'a'.repeat(52)}`
export const BEN_ID = `p2p:${'b'.repeat(52)}`
export const ANA_ID = `p2p:${'c'.repeat(52)}`
export const ME_ADDR = 'sam@aaaa-aaaa-aaaa-aaaa'
export const BEN_ADDR = 'ben@bbbb-bbbb-bbbb-bbbb'
export const ANA_ADDR = 'ana@cccc-cccc-cccc-cccc'
export const RELAYS = ['wss://r1.example/v3', 'wss://r2.example/v3']
export const NOW_MS = Date.UTC(2026, 9, 21, 12, 0, 0)

export const WHOAMI: Whoami = {
  userId: ME_ID,
  name: 'sam',
  address: ME_ADDR,
  fingerprint: 'aaaa-aaaa-aaaa-aaaa',
  did: 'd_THIS',
  keyholder: true,
  relays: RELAYS,
  doc: { ver: 3, exp: NOW_MS / 1000 + 30 * 86_400, freshness: 'fresh', daysPastExp: 0, forked: false, historyGap: false },
  warnings: [],
}

export const BEN: PeerRow = {
  own: BEN_ID,
  sid: 'ben-session-1',
  ref: 'a1b2c3',
  address: BEN_ADDR,
  self: false,
  thisDevice: false,
  live: true,
  ageSec: 5,
  state: 'idle',
  label: 'api',
  repo: 'Api',
  branch: 'main',
  mode: 'default',
  files: [],
}
/** The same person's session on another device. */
export const MY_LAPTOP: PeerRow = { ...BEN, own: ME_ID, sid: 'laptop-1', ref: '7b7b7b', address: ME_ADDR, self: true, label: 'laptop' }
/** Another Claude session on THIS device: the built-in lists it, the mod doesn't. */
export const MY_OTHER_LOCAL: PeerRow = { ...MY_LAPTOP, sid: 'local-2', ref: '0c0c0c', thisDevice: true, label: 'local' }
/** A circle-mate: her session is shared through the circle (the CLI's row `circle`). */
export const ANA: PeerRow = { ...BEN, own: ANA_ID, sid: 'ana-1', ref: 'd4e5f6', address: ANA_ADDR, label: 'web', repo: 'web', rule: 'circle', viewerRule: 'circle', circle: 'c_team' }
export const ALL_RELAYS_UP = { listed: RELAYS, connected: RELAYS, failed: [] }

export const FRIENDS: FriendsInfo = {
  friends: [{ userId: BEN_ID, address: BEN_ADDR, since: 1, direction: 'outgoing', canMessage: true }],
  invites: { outgoing: [], held: 0 },
  blocked: [],
}
export const CIRCLE: CircleSummary = {
  cid: 'c_team',
  name: 'team',
  ver: 2,
  policy: 'invite',
  owner: ANA_ID,
  ownerAddress: ANA_ADDR,
  role: 'member',
  joined: true,
  members: 2,
  standing: 2,
  isDefault: true,
}

export type Run = { argv: readonly string[]; stdin?: string; cwd?: string; env?: Record<string, string> }

export type World = {
  runs: Run[]
  spawns: (readonly string[])[]
  spawnEnvs: (Record<string, string> | undefined)[]
  /** Tools the mod registered for the model. */
  tools: string[]
  /** What core's permission decision answers a `$.tool.check` (default allow). */
  toolCheck: { decision: 'allow' | 'ask' | 'deny'; reason?: string }
  /** The cwd each spawn asked for. */
  spawnCwds: (string | undefined)[]
  submits: string[]
  contexts: (readonly string[] | undefined)[]
  notices: string[]
  toasts: string[]
  statuses: (string | undefined)[]
  localSends: string[]
  coreSends: string[]
  /** What core's SendMessage refused (a `to` with "@"). */
  coreRefused: string[]
  /**
   * `p2p trust`: users trusted by name, members of trusted circles (as `trust ls` last saw them), and
   * who `trust check` says is trusted now (default: both lists).
   */
  trust: { users: string[]; circleMembers: string[]; now?: string[] }
  /** Stands in for core's own delivery: a test can drive `$.session.send` from inside SendMessage. */
  coreDeliver?: (to: string, message: string) => Promise<void | 'error'>
  /** Runs before each process.run is answered (a test can hold a command to see what overlaps). */
  onRun?: (argv: readonly string[]) => Promise<void>
  modelCalls: number
  peers: PeerRow[]
  held: HeldItem[]
  emit: (event: P2PEvent | object) => void
  /** Ends the current watch child with this exit code (and stderr line). */
  endWatch: (code: number, stderr?: string) => void
  clock: MockClock
  sessionId: string
  /** Per-command overrides: `{ exitCode, stdout, stderr }` by the command's first words. */
  cli: Record<string, { exitCode?: number; stdout?: string; stderr?: string; body?: object } | undefined>
  /** Watch children still running (the generator not yet finished). */
  watchersAlive: number
  /** What `$.ui.copy` put on the clipboard. */
  copies: string[]
  /** What `$.agent.list()` answers: this session's subagents and teammates. */
  agentList: { id: string; description: string; type: string; status: string; parentId?: string; teammateId?: string; name?: string }[]
  /** The ids `agent.spawn` answers, in order (`agent-<n>` once these run out). */
  spawnIds: string[]
  /** The prompts subagents were spawned with (what the mod must never send). */
  spawnPrompts: string[]
}

export const PHRASE = 'abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual'
export const BACKUP_FILE = '/home/sam/.p2p/cli/backup-phrase.txt'
export const CODE = 'relay.example/K7QM-3XPD-9TWA-HF2N'

export type WorldOptions = {
  /** The person token the mod's token script prints (none: an empty answer). */
  personToken?: string
  /** What `$.store` holds at the start (other sessions' board entries). */
  store?: Record<string, unknown>
  /** `p2p profile show <name>` answers, by name. */
  profiles?: Record<string, { userId: string; address: string }>
  env?: Record<string, string>
  cwd?: string
  /** The git toplevel (default /work/web); null: not in a git repo. */
  gitTop?: string | null
  status?: string
  localDelivers?: string[]
  isMissing?: boolean
  /** No `p2p` on PATH: the mod falls back to the bundled CLI under node. */
  isNotOnPath?: boolean
  /** `node --version` (default v22.11.0); null: no node on PATH. */
  nodeVersion?: string | null
  /** `p2p --version` on PATH (default 0.0.9: not the bundled 0.1.0). */
  pathVersion?: string
  /** `p2p --help` on PATH: another tool called p2p when false. */
  isPathPeer2Peer?: boolean
  /** `git -C <dir> rev-parse --abbrev-ref HEAD`, by `<dir>` (default `main`). */
  gitBranches?: Record<string, string>
  /** What the mod's no-git repo probe (`node -e`) finds: the repo's root and branch (default: none). */
  repoProbe?: { root: string; branch?: string }
  /** What `status` answers as its `roster` (default: none). */
  statusRoster?: object
  /** Extra rows `p2p circle members` lists (besides Ana the owner and me). */
  circleMembers?: { userId: string; address: string; owner: boolean; admin: boolean; stands: boolean; self: boolean }[]
  /** What `status` answers as its `warnings` (default: none). */
  statusWarnings?: string[]
}

const json = (body: object) => JSON.stringify(body)

/** The command's words, flags and `--` left out: `session roster`, `held approve`, `ls`. */
export const words = (argv: readonly string[]) => {
  const out: string[] = []
  // The bundled CLI runs as `node <plugin>/bin/p2p.mjs <args>`.
  for (const a of argv.slice(argv[0] === 'node' ? 2 : 1)) {
    if (a === '--') break
    if (a.startsWith('-')) continue
    out.push(a)
  }

  return out
}

/** The value of `--name=value` (or `--name value`) in argv. */
export const flag = (argv: readonly string[], name: string): string | undefined => {
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] ?? ''
    if (a.startsWith(`--${name}=`)) return a.slice(name.length + 3)
    if (a === `--${name}`) return argv[i + 1]
  }

  return undefined
}

export const flags = (argv: readonly string[], name: string): string[] =>
  argv.filter(a => a.startsWith(`--${name}=`)).map(a => a.slice(name.length + 3))

export function world(on: On, options: WorldOptions = {}): World {
  const w: World = {
    runs: [],
    spawns: [],
    spawnEnvs: [],
    tools: [],
    toolCheck: { decision: 'allow' },
    spawnCwds: [],
    submits: [],
    contexts: [],
    notices: [],
    toasts: [],
    statuses: [],
    localSends: [],
    coreSends: [],
    trust: { users: [], circleMembers: [] },
    coreRefused: [],
    modelCalls: 0,
    peers: [MY_LAPTOP, MY_OTHER_LOCAL, BEN],
    held: [],
    emit: () => undefined,
    endWatch: () => undefined,
    clock: mock.clock(on, { now: NOW_MS }),
    sessionId: 'claude-session-1',
    cli: {},
    watchersAlive: 0,
    copies: [],
    agentList: [],
    spawnIds: [],
    spawnPrompts: [],
  }
  let queue: string[] = []
  let ending: { code: number; stderr?: string } | null = null
  let wake: (() => void) | null = null
  w.emit = event => {
    queue.push(`${JSON.stringify(event)}\n`)
    wake?.()
  }
  w.endWatch = (code, stderr) => {
    ending = { code, ...(stderr ? { stderr } : {}) }
    wake?.()
  }

  mock.env(on, { P2P_BIN: 'p2p', ...options.env })
  mock.store(on, options.store ?? {})
  on('session.id', () => ({ value: w.sessionId }))
  on('session.cwd', () => ({ value: options.cwd ?? '/work/web' }))
  on('session.start', (_$, e) => ({ cwd: e.cwd }))
  on('session.end', (_$, e) => ({ sessionId: e.sessionId }))
  on('turn.start', (_$, e) => ({ turnId: e.turnId }))
  on('turn.complete', (_$, e) => ({ text: e.answer }))
  on('classic.SessionStart', () => ({}))
  on('classic.UserPromptSubmit', () => ({}))
  on('classic.PostToolUse', () => ({}))
  on('classic.SubagentStop', () => ({}))
  on('classic.WorktreeCreate', () => ({}))
  on('classic.WorktreeRemove', () => ({}))
  let spawned = 0
  on('agent.spawn', (_$, e) => {
    w.spawnPrompts.push(e.prompt)
    const agentId = w.spawnIds[spawned] ?? `agent-${spawned + 1}`
    spawned++

    return { model: 'claude-test', agentId }
  })
  on('agent.list', () => ({ value: w.agentList }) as never)
  on('command.register', (_$, e) => ({ value: { command: e.name } }))
  on('tool.check', () => w.toolCheck as never)
  on('tool.register', (_$, e) => {
    w.tools.push(e.name)

    return { value: { tool: `mcp__peer2peer__${e.name}` } }
  })
  on('command.run', { command: 'peers' }, () => ({ text: 'Local sessions: researcher [3fa9c1]' }))
  on('command.run', { command: 'list-agents' }, () => ({ text: 'Other Claude sessions (1):\n  researcher [3fa9c1]' }))
  on('ui.status', (_$, e) => {
    w.statuses.push((e as { text?: string }).text)

    return { value: undefined }
  })
  on('ui.copy', (_$, e) => {
    w.copies.push(String((e as { text?: unknown }).text))

    return { value: { isCopied: true } } as never
  })
  on('ui.toast', (_$, e) => {
    w.toasts.push(String((e as { text?: unknown }).text ?? JSON.stringify(e)))

    return { value: undefined }
  })
  on('ui.render', ($, e) => {
    const { Box } = $.ui.resolve(e)

    return h(Box, null) as RenderElement
  })
  on('session.append', (_$, e, next) => {
    if (e.message.type === 'system') w.notices.push(JSON.stringify(e.message.content))

    return next(e)
  })
  on('prompt.submit', (_$, e) => {
    w.submits.push(e.text)
    w.contexts.push(e.context)

    return { text: e.text, context: e.context, origin: e.origin }
  })
  on('model.complete', () => {
    w.modelCalls++

    return { value: { isAnswered: true, text: options.status ?? 'Fixing the login form validation.', usage: {} } } as never
  })
  on('process.run', (_$, e) => {
    const answer = () => answerRun(e)

    return w.onRun ? w.onRun(e.argv).then(answer) : answer()
  })
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const answerRun = (e: any) => {
    w.runs.push({ argv: e.argv, ...(e.init?.stdin !== undefined ? { stdin: e.init.stdin } : {}), ...(e.init?.cwd !== undefined ? { cwd: e.init.cwd } : {}), ...(e.init?.env !== undefined ? { env: e.init.env } : {}) })
    const ok = (stdout: string, exitCode = 0, stderr = '') => ({ value: { exitCode, stdout, stderr, isStdoutTruncated: false, isStderrTruncated: false } })
    const [bin] = e.argv
    if (bin === 'git') {
      if (e.argv.includes('--show-toplevel')) return options.gitTop === null ? ok("", 128) : ok(`${options.gitTop ?? "/work/web"}\n`)
      if (e.argv[1] === '-C') return ok(`${options.gitBranches?.[String(e.argv[2])] ?? 'main'}\n`)

      return ok('main\n')
    }
    // The mod's person-token script (lib PERSON_TOKEN_SCRIPT): the token it would print.
    if (bin === 'node' && e.argv[1] === '-e' && String(e.argv.at(-1)).endsWith('person.key')) return ok(options.personToken ?? '')
    if (bin === 'node' && e.argv[1] === '-e') return ok(json(options.repoProbe ?? {}))
    if (bin === 'node' && e.argv[1] === '--version') {
      if (options.nodeVersion === null) throw new Error('spawn node ENOENT')

      return ok(`${options.nodeVersion ?? 'v22.11.0'}\n`)
    }
    if (bin === 'node' && e.argv.length === 3 && e.argv[2] === '--version' && String(e.argv[1]).endsWith('/bin/p2p.mjs')) return ok('0.1.0\n')
    if (bin === 'p2p' && (e.argv[1] === '--version' || e.argv[1] === '--help') && options.isNotOnPath) throw new Error('spawn p2p ENOENT')
    if (bin === 'p2p' && e.argv[1] === '--help') return ok(options.isPathPeer2Peer === false ? 'usage: p2p <torrent>  (some other p2p tool)\n' : 'Usage: p2p [options] [command]\n\nPeer2Peer: an account-free network for AI agent sessions\n')
    if (bin === 'p2p' && e.argv[1] === '--version') return ok(`${options.pathVersion ?? '0.0.9'}\n`)
    if (options.isMissing) throw new Error('spawn p2p ENOENT')
    const cmd = words(e.argv).join(' ')
    // `p2p join --preview` answers on its own key ('join-preview'), so a test can set the join's answer apart.
    if (cmd === 'join' && e.argv.includes('--preview')) {
      const pv = w.cli['join-preview']
      if (pv) return ok(pv.stdout ?? json(pv.body ?? {}), pv.exitCode ?? 0, pv.stderr ?? '')
      return ok(json({ preview: { from: { userId: ANA_ID, address: ANA_ADDR, fingerprint: 'cccc-cccc-cccc-cccc' }, to: null, circles: [{ cid: 'c_team', name: 'team', members: 2, policy: 'invite', owner: ANA_ID, ownerAddress: ANA_ADDR, verified: true, auto: true }], expiresAt: NOW_MS / 1000 + 86_400 } }))
    }
    const over = w.cli[cmd] ?? w.cli[words(e.argv)[0] ?? '']
    if (over) return ok(over.stdout ?? json(over.body ?? {}), over.exitCode ?? 0, over.stderr ?? '')
    switch (cmd) {
      case 'whoami':
        return ok(json(WHOAMI))
      case 'ls':
        return ok(json({ peers: w.peers, relays: ALL_RELAYS_UP }))
      case 'status':
        return ok(json({ status: {}, roster: options.statusRoster ?? {}, delivered: [], failed: [], ...(options.statusWarnings ? { warnings: options.statusWarnings } : {}), bound: true }))
      case 'session roster':
        return ok(json({ roster: { sid: e.argv.at(-1), ref: 'ffffff', ver: 1, vis: e.argv.includes('--private') ? 'private' : 'circle', circle: 'c_team', circleName: 'team', parts: flags(e.argv, 'add').map(u => ({ userId: u, address: u })) } }))
      case 'send': {
        const to = flag(e.argv, 'to') ?? ''
        const peer = w.peers.find(p => to.startsWith(p.own))

        return ok(json({ delivered: true, to: { userId: peer?.own ?? BEN_ID, address: peer?.address ?? BEN_ADDR, own: peer?.own ?? BEN_ID, sid: peer?.sid ?? BEN.sid, ref: peer?.ref ?? BEN.ref }, relays: 2, devices: 1, messageId: 'm1', bound: true }))
      }
      case 'trust ls':
        return ok(json({ users: w.trust.users.map(u => ({ userId: u, address: u === BEN_ID ? BEN_ADDR : u, blocked: false })), circles: w.trust.circleMembers.length ? [{ cid: 'c_team', name: 'team', joined: true, members: w.trust.circleMembers }] : [], trusted: [...w.trust.users, ...w.trust.circleMembers] }))
      case 'trust check': {
        const u = e.argv.at(-1) ?? ''
        const now = w.trust.now ?? [...w.trust.users, ...w.trust.circleMembers]
        return ok(json({ userId: u, trusted: now.includes(u), via: now.includes(u) ? 'user' : null }))
      }
      case 'trust add': {
        const u = e.argv.at(-1) ?? ''
        if (!w.trust.users.includes(u)) w.trust.users.push(u)
        return ok(json({ added: u, kind: 'user', address: u === BEN_ID ? BEN_ADDR : u }))
      }
      case 'trust remove': {
        const u = e.argv.at(-1) ?? ''
        const had = w.trust.users.includes(u)
        w.trust.users = w.trust.users.filter(x => x !== u)
        return ok(json({ removed: had ? u : null, kind: 'user' }))
      }
      case 'receipt':
        return ok(json({ sent: true, outcome: flag(e.argv, 'outcome') }))
      case 'receipts':
      case 'receipts on':
      case 'receipts off':
        return ok(json({ receipts: cmd !== 'receipts off', overridden: false }))
      case 'held':
        return ok(json({ held: w.held }))
      case 'held approve':
        return ok(json({ type: 'invite', friend: { userId: BEN_ID, address: BEN_ADDR } }))
      case 'held decline':
        return ok(json({ declined: e.argv.at(-1), count: 1 }))
      case 'friends':
        return ok(json(FRIENDS))
      case 'circle ls':
        return ok(json({ circles: [CIRCLE] }))
      case 'circle members':
        return ok(json({ circle: CIRCLE, members: [{ userId: ANA_ID, address: ANA_ADDR, owner: true, admin: false, stands: true, self: false }, { userId: ME_ID, address: ME_ADDR, owner: false, admin: false, stands: true, self: true }, ...(options.circleMembers ?? [])] }))
      case 'invite':
        // The short-code shape: explicit nulls, a code that works once.
        return ok(json({ code: CODE, lid: 'lid-k7qm', line: CODE, relay: 'wss://relay.example/v3', label: e.argv.includes('--') ? e.argv.at(-1) : null, to: null, circle: { cid: 'c_team', name: 'team' }, expiresAt: NOW_MS / 1000 + 7 * 86_400, uses: 1 }))
      case 'setup':
        return ok(json({ userId: ME_ID, address: ME_ADDR, fingerprint: 'aaaa-aaaa-aaaa-aaaa', did: 'd_THIS', relays: RELAYS, created: true, published: RELAYS, failed: [], backup: { file: BACKUP_FILE } }))
      case 'join':
        return ok(json({ from: { userId: ANA_ID, address: ANA_ADDR }, friend: { userId: ANA_ID, address: ANA_ADDR }, delivered: { relays: RELAYS, devices: 1 }, circle: { cid: 'c_team', name: 'team', status: 'joined', default: true }, defaultCircle: 'c_team', created: false }))
      case 'profile show': {
        const hit = options.profiles?.[e.argv.at(-1) ?? '']

        return hit ? ok(json({ ...hit, profile: { links: [] } })) : ok(json({ error: 'not_found', reason: 'no known identity' }), 1)
      }
      case 'accept':
        return ok(json({ friend: { userId: BEN_ID, address: BEN_ADDR }, delivered: { relays: ['r'], devices: 1 } }))
      default:
        return ok(json({ ok: true }))
    }
  }
  on('process.spawn', async function* (_$, e, next) {
    w.spawns.push(e.argv)
    w.spawnCwds.push(e.cwd)
    w.spawnEnvs.push(e.env)
    // The engine kills the child when the stream is closed or abandoned.
    next.signal?.addEventListener('abort', () => wake?.())
    if (options.isMissing) throw new Error('spawn p2p ENOENT')
    queue = []
    ending = null
    w.watchersAlive++
    try {
    for (;;) {
      if (next.signal?.aborted) return { value: { code: null, signal: 'SIGTERM' } }
      while (queue.length > 0) yield { stream: 'stdout' as const, text: queue.shift() ?? '' }
      const end = ending as { code: number; stderr?: string } | null
      if (end) {
        if (end.stderr) yield { stream: 'stderr' as const, text: `${end.stderr}\n` }

        return { value: { code: end.code, signal: null } }
      }
      await new Promise<void>(resolve => {
        wake = resolve
      })
    }
    } finally {
      w.watchersAlive--
    }
  })
  on('session.send', (_$, e) => {
    w.localSends.push(e.to)
    if (options.localDelivers?.includes(e.to)) return { isDelivered: true }

    return { isDelivered: false, reason: `No agent or session named ${e.to}.` }
  })
  on('tool.call', { tool: 'ListAgents' }, () => ({ result: { listing: 'researcher [3fa9c1] — idle' } }))
  // Core's SendMessage stands here as a record; the kit cannot raise core's
  // own session.send from it, so tests drive $.session.send directly.
  on('tool.call', { tool: 'SendMessage' }, async (_$, e) => {
    // Claude Code's SendMessage validateInput (2.1.299 through 2.1.306) refuses any `to` with "@"
    // before it delivers anything: a `name@fingerprint` address must never reach it.
    if (String(e.to).includes('@')) {
      w.coreRefused.push(String(e.to))

      return { isError: true, result: 'to must be a bare teammate name — there is only one team per session' } as never
    }
    w.coreSends.push(String(e.to))
    if ((await w.coreDeliver?.(String(e.to), String(e.message ?? ''))) === 'error') return { isError: true, result: 'core failed' } as never

    return { result: `Message sent to ${String(e.to)}.` }
  })
  on('tool.call', { tool: 'Read' }, () => ({ result: { type: 'text', file: { filePath: '/x', content: '', numLines: 0, startLine: 1, totalLines: 0 } } }))
  on('tool.call', { tool: 'Edit' }, () => ({ result: { filePath: '/x' } }) as never)
  on('tool.call', { tool: 'Bash' }, () => ({ result: { stdout: '', stderr: '', interrupted: false } }) as never)

  return w
}

/** Lets an idle session's gathered peer messages start their turn (the 500 ms debounce). */
export async function gather(w: World) {
  await settle(w, () => false)
  await w.clock.advance(600)
  await settle(w, () => false)
}

/** Lets the plugin's background loops (the watch) run until `isDone`. */
export async function settle(w: World, isDone: () => boolean) {
  for (let i = 0; i < 50 && !isDone(); i++) await w.clock.settle()
}

/** The commands the fake CLI ran whose words start with `prefix`. */
export const ran = (w: World, ...prefix: string[]) => w.runs.filter(r => r.argv[0] !== 'git' && prefix.every((p, i) => words(r.argv)[i] === p))

/** A session started in `mode`, as the classic SessionStart reports it. */
/**
 * A session started in `mode`, as the classic SessionStart reports it, and
 * (unless `isConfirmed` is false) a prompt the person typed, whose classic
 * UserPromptSubmit confirms the mode for the hold rule.
 */
export async function start($: Engine, w: World, mode = 'default', isConfirmed = true) {
  await $.session.start({ cwd: '/work/web', surface: 'terminal', isInteractive: true })
  await $.classic.SessionStart({ source: 'startup', permission_mode: mode } as never)
  await settle(w, () => ran(w, 'ls').length > 0 && w.spawns.length > 0)
  if (isConfirmed) await confirmMode($, mode)
  await settle(w, () => false)
}

/** The engine's classic UserPromptSubmit for a prompt the person typed, in `mode`. */
export const confirmMode = ($: Engine, mode: string) => $.classic.UserPromptSubmit({ prompt: 'hello', permission_mode: mode, source: 'user' } as never)

/** The sid the mod generated for its run (from the watch it spawned). */
export const sidOf = (w: World): string => flag(w.spawns.at(-1) ?? [], 'session') ?? ''

/** A prompt as the engine raises it when the person presses Enter. */
export const typed = ($: Engine, text: string) => $.prompt.submit({ text, origin: { kind: 'composer' } } as never)

/** The person typing `/<command> <args>` at the prompt. */
export const slash = ($: Engine, command: string, args: string, kind = 'composer') =>
  $.command.run({ command, args, origin: { kind } as never, presentation: { isFullscreen: false, columns: 120 } })

export const from = (userId: string, address: string, self = false) => ({ userId, did: self ? 'd_OTHER' : 'd_X', address, self })

/** A message from Ben's session to this one. */
export const message = (w: World, over: Record<string, unknown> = {}) => ({
  kind: 'p2p.message',
  id: 'ev-1',
  at: NOW_MS,
  from: from(BEN_ID, BEN_ADDR),
  own: BEN_ID,
  sid: BEN.sid,
  ref: BEN.ref,
  rule: 'owner',
  viewerRule: 'participant-friend',
  toSession: sidOf(w),
  text: 'Migration landed on main.\nPlease rebase.',
  ...over,
})

export const lastStatus = (w: World) => [...ran(w, 'status')].reverse()[0]?.argv ?? []
