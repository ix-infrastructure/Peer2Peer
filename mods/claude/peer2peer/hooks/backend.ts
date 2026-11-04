// Copyright 2026 Ix Infrastructure Inc.

// The mod's backend layer: every call it makes to the `p2p` CLI, over an
// `Exec` that runs a command. In Claude Code, Exec is `$.process`; in the
// integration test (integration/), it is node's child_process. Nothing here
// touches `$` or Node, so both drive exactly the same code.
//
// The mod never handles keys: `p2p` holds the identity and device keys,
// seals and verifies every envelope, and keeps its own state in P2P_HOME.
// Peer-derived positionals always follow `--`, and peer-derived option
// values use `--opt=value`, so neither can be read as a flag.

import type {
  CircleMembers,
  CircleSummary,
  DoctorResult,
  FriendsInfo,
  HeldItem,
  InviteResult,
  JoinPreview,
  IxConflict,
  IxOverlap,
  IxInboxItem,
  IxSendInput,
  IxSent,
  IxShown,
  JoinResult,
  P2PEvent,
  ReceiptOutcome,
  PeerAgent,
  PeerRow,
  RelaysInfo,
  RosterView,
  RotatePlan,
  RotateResult,
  SendResult,
  SetupResult,
  TrustList,
  Whoami,
} from '../types'
import { inert, parseEvent, parseJson, takeLines } from './lib'

export type RunResult = { exitCode: number; stdout: string; stderr: string }
export type Chunk = { stream: 'stdout' | 'stderr'; text: string }
export type ChildEnd = { code: number | null; signal: string | null }

/** Runs commands by argv (no shell). */
export interface Exec {
  run(argv: readonly string[], init?: { stdin?: string; timeoutMs?: number }): Promise<RunResult>
  /**
   * A child's output piece by piece, then how it ended. `return()` kills it,
   * and so does `signal` aborting, where the Exec can take one.
   */
  spawn(argv: readonly string[], init?: { signal?: AbortSignal }): AsyncGenerator<Chunk, unknown>
}

export type Outcome<T> =
  | { ok: true; value: T; stderr: string }
  | { ok: false; error: string; reason: string; stderr: string; value?: unknown }

/** `p2p circle` options that take a value (`--wait 30` is passed on as `--wait=30`). */
const CIRCLE_VALUE_OPTIONS = new Set(['wait', 'consent'])

const TIMEOUT_MS = 30_000
const LONG_TIMEOUT_MS = 90_000
/** How long a rotation waits for the person's other devices to follow, and for all of it. */
const ROTATE_WAIT_SEC = 240
const ROTATE_TIMEOUT_MS = 330_000

export class P2P {
  constructor(
    private readonly exec: Exec,
    /** The `p2p` command, argv[0] first (P2P_BIN, or `p2p` on PATH). */
    readonly bin: readonly string[],
  ) {}

  /** Runs `p2p <args> --json` and parses its one JSON object. Never rejects. */
  async call<T>(args: readonly string[], init: { stdin?: string; timeoutMs?: number } = {}): Promise<Outcome<T>> {
    // `--json` goes before any `--`, so it is always read as the flag.
    const dash = args.indexOf('--')
    const argv = dash < 0 ? [...args, '--json'] : [...args.slice(0, dash), '--json', ...args.slice(dash)]
    let ran: RunResult
    try {
      ran = await this.exec.run([...this.bin, ...argv], { timeoutMs: init.timeoutMs ?? TIMEOUT_MS, ...(init.stdin !== undefined ? { stdin: init.stdin } : {}) })
    } catch (e) {
      return { ok: false, error: 'cli_missing', reason: `could not run ${this.bin.join(' ')}: ${inert(String((e as Error)?.message ?? e))}`, stderr: '' }
    }
    const parsed = parseJson<Record<string, unknown>>(ran.stdout)
    if (ran.exitCode === 0 && parsed !== null) return { ok: true, value: parsed as T, stderr: ran.stderr }
    const error = typeof parsed?.error === 'string' ? parsed.error : ran.exitCode === 0 ? 'unreadable' : 'failed'
    const last = ran.stderr.trim().split('\n').pop() ?? ''
    const reason = typeof parsed?.reason === 'string' ? parsed.reason : last || `p2p ${args[0] ?? ''} exited ${ran.exitCode}`

    return { ok: false, error, reason: inert(reason), stderr: ran.stderr, ...(parsed ? { value: parsed } : {}) }
  }

  whoami(): Promise<Outcome<Whoami>> {
    return this.call<Whoami>(['whoami'])
  }

  /** Live sessions, and which of this user's relays answered (`relays`); without their extension state. */
  async ls(): Promise<Outcome<PeerRow[]> & { relays?: RelaysInfo }> {
    const r = await this.call<{ peers: PeerRow[]; relays?: RelaysInfo }>(['ls'])
    if (!r.ok) return r
    const relays = r.value.relays
    const isRelays = typeof relays === 'object' && relays !== null && Array.isArray(relays.listed) && Array.isArray(relays.connected) && Array.isArray(relays.failed)

    // Extension state (§4.3 "Extension state kinds", `xstate`) is for extensions only: it is never
    // shown to a model, so this mod drops it here and never holds it.
    const peers = Array.isArray(r.value.peers) ? r.value.peers.map(withoutState) : []

    return { ok: true, value: peers, stderr: r.stderr, ...(isRelays ? { relays } : {}) }
  }

  /**
   * `p2p status` for a session. `caps` (§4.3 "Status caps") and `agents`
   * (§4.3 "Status agents", passed on stdin as `--agents-json=-`) never fail
   * the post (review L3): a CLI that refuses them as a usage error (an older
   * `p2p` on PATH) gets the status once more without them.
   */
  async status(o: {
    session: string
    state: 'busy' | 'idle'
    label: string
    repo?: string
    branch?: string
    mode?: string
    summary?: string
    files?: readonly string[]
    /** What this client understands beyond the CLI's own, e.g. `agents.v1`. */
    caps?: readonly string[]
    /** The session's subagents; the CLI sends them only to peers that understand agents.v1. */
    agents?: readonly PeerAgent[]
  }, timeoutMs?: number): Promise<Outcome<{ delivered: unknown[]; failed: { address: string; error: string }[]; roster?: RosterView; warnings?: string[] }>> {
    const args = ['status', `--session=${o.session}`, `--state=${o.state}`, `--label=${o.label}`]
    if (o.repo) args.push(`--repo=${o.repo}`)
    if (o.branch) args.push(`--branch=${o.branch}`)
    if (o.mode) args.push(`--mode=${o.mode}`)
    if (o.summary) args.push(`--summary=${o.summary}`)
    for (const file of o.files ?? []) args.push(`--file=${file}`)
    const extra: string[] = []
    for (const cap of o.caps ?? []) extra.push(`--cap=${cap}`)
    const hasAgents = (o.agents?.length ?? 0) > 0
    if (hasAgents) extra.push('--agents-json=-')
    const init = { ...(timeoutMs !== undefined ? { timeoutMs } : {}), ...(hasAgents ? { stdin: JSON.stringify(o.agents) } : {}) }
    const r = await this.call<{ delivered: unknown[]; failed: { address: string; error: string }[]; roster?: RosterView; warnings?: string[] }>([...args, ...extra], init)
    if (r.ok || extra.length === 0 || r.error !== 'usage') return r

    return this.call(args, timeoutMs !== undefined ? { timeoutMs } : {})
  }

  /** Loaded and enabled extensions (`p2p extensions`). */
  extensions(): Promise<Outcome<{ extensions: { ns: string; name: string; version: string; commands: string[] }[]; enabled: string[] }>> {
    return this.call(['extensions'])
  }

  /** x:ix.* items peers sent (`p2p ix inbox`): ids, kinds, senders and framed digests. */
  async ixInbox(): Promise<Outcome<IxInboxItem[]>> {
    const r = await this.call<{ events: IxInboxItem[] }>(['ix', 'inbox'])
    if (!r.ok) return r

    return { ok: true, value: (Array.isArray(r.value.events) ? r.value.events : []).filter(e => typeof e?.id === 'string' && typeof e.kind === 'string' && typeof e.digest === 'string'), stderr: r.stderr }
  }

  /** One received item in full (`p2p ix show`): a note's framed text and textHash, or the body. */
  ixShow(id: string): Promise<Outcome<IxShown>> {
    return this.call<IxShown>(['ix', 'show', '--', id])
  }

  /**
   * Writes a received note into the local Ix graph. Only for what the person typed, after
   * the mod showed them the full note: `shown` is the textHash of what was shown.
   */
  ixImport(id: string, shown: string): Promise<Outcome<{ imported: boolean; noteId?: string; tag?: string }>> {
    return this.call(['ix', 'import', '--yes', `--shown=${shown}`, '--', id], { timeoutMs: LONG_TIMEOUT_MS })
  }

  /** Opens a received subgraph reference in the local Ix graph. Only for what the person typed. */
  ixResolve(id: string, shown: string): Promise<Outcome<{ command: string[]; output: string; sameRev?: boolean }>> {
    return this.call(['ix', 'resolve', '--yes', `--shown=${shown}`, '--', id], { timeoutMs: LONG_TIMEOUT_MS })
  }

  /** Sends an x:ix.* item from this session (`p2p ix note|subgraph|impact`); peer-chosen values as --opt=value. */
  ixSend(o: IxSendInput): Promise<Outcome<IxSent>> {
    const head = ['ix', o.kind, `--from-session=${o.fromSession}`, `--to=${o.to}`]
    if (o.kind === 'note') {
      const args = [...head, ...(o.tag ? [`--tag=${o.tag}`] : []), ...(o.title ? [`--title=${o.title}`] : []), ...(o.ixNote ? [`--ix-note=${o.ixNote}`] : ['--stdin'])]

      return this.call<IxSent>(args, { timeoutMs: LONG_TIMEOUT_MS, ...(o.ixNote ? {} : { stdin: o.text ?? '' }) })
    }
    if (o.kind === 'subgraph') {
      const sel = o.symbol ? [`--symbol=${o.symbol}`, ...(o.symbolKind ? [`--kind=${o.symbolKind}`] : [])] : o.region ? [`--region=${o.region}`] : []
      const args = [...head, ...sel, ...(o.why ? [`--why=${o.why}`] : []), ...(o.title ? [`--title=${o.title}`] : []), ...(o.pattern ? ['--', o.pattern] : [])]

      return this.call<IxSent>(args, { timeoutMs: LONG_TIMEOUT_MS })
    }
    // A report built earlier and shown to the person is sent exactly (`--body -`): Ix isn't run again.
    if (o.impactBody) return this.call<IxSent>([...head, '--body=-', '--', o.target ?? ''], { timeoutMs: LONG_TIMEOUT_MS, stdin: JSON.stringify(o.impactBody) })
    const args = [...head, ...(o.symbolKind ? [`--kind=${o.symbolKind}`] : []), ...(o.changed ?? []).map(f => `--changed=${f}`), '--', o.target ?? '']

    return this.call<IxSent>(args, { timeoutMs: LONG_TIMEOUT_MS })
  }

  /** Builds an impact report with the local Ix without sending it (`ix impact --dry-run`), to show first. */
  async ixImpactPreview(o: { target: string; symbolKind?: string; changed?: readonly string[] }): Promise<Outcome<Record<string, unknown>>> {
    const r = await this.call<{ body: Record<string, unknown> }>(['ix', 'impact', '--dry-run', ...(o.symbolKind ? [`--kind=${o.symbolKind}`] : []), ...(o.changed ?? []).map(f => `--changed=${f}`), '--', o.target], { timeoutMs: LONG_TIMEOUT_MS })

    return r.ok ? (r.value.body && typeof r.value.body === 'object' ? { ok: true, value: r.value.body, stderr: r.stderr } : { ok: false, error: 'unreadable', reason: 'ix impact --dry-run returned no report', stderr: r.stderr }) : r
  }

  /**
   * Possible semantic conflicts from the Ix extension (`p2p ix conflicts`):
   * live peer sessions changing files connected, in the local Ix graph, to the
   * ones this session's last status lists. `extension_missing` when
   * @peer2peer/ext-ix isn't installed, `ix_missing` without Ix.
   */
  async ixConflicts(sid: string): Promise<Outcome<IxConflict[]>> {
    const r = await this.call<{ conflicts: IxConflict[] }>(['ix', 'conflicts', `--session=${sid}`], { timeoutMs: LONG_TIMEOUT_MS })
    if (!r.ok) return r
    const list = Array.isArray(r.value.conflicts) ? r.value.conflicts : []

    return {
      ok: true,
      value: list.filter(c => typeof c?.message === 'string' && typeof c.peer?.own === 'string' && typeof c.peer?.sid === 'string' && typeof c.mine === 'string' && typeof c.theirs === 'string'),
      stderr: r.stderr,
    }
  }

  /**
   * Overlaps between this session's footprint and live peers' (`p2p ix overlaps`, ext-ix SPEC §9),
   * and with `fallback`, `ix around` conflicts for peers without a footprint. Only the derived,
   * bounded lines come back: never a peer's footprint.
   */
  async ixOverlaps(sid: string, o: { fallback?: boolean } = {}): Promise<Outcome<{ overlaps: IxOverlap[]; fallback: IxConflict[] }>> {
    const r = await this.call<{ overlaps?: unknown; fallback?: unknown }>(['ix', 'overlaps', `--session=${sid}`, ...(o.fallback ? ['--fallback'] : [])], { timeoutMs: LONG_TIMEOUT_MS })
    if (!r.ok) return r
    const str = (v: unknown, max: number) => typeof v === 'string' && v.length <= max
    const peerOk = (p: unknown) => {
      const x = p as Record<string, unknown> | null

      return !!x && str(x.own, 200) && str(x.sid, 200) && str(x.address, 200) && str(x.ref, 64)
    }
    // Only the fields a line needs: never a `detail` (readable names, for a person at a terminal).
    const overlaps = (Array.isArray(r.value.overlaps) ? r.value.overlaps : [])
      .filter((x): x is IxOverlap => {
        const o = x as Record<string, unknown> | null

        return !!o && peerOk(o.peer) && str(o.message, 400) && str(o.key, 2000) && ['high', 'medium', 'low'].includes(String(o.severity))
      })
      .slice(0, 200)
      .map(o => ({ peer: { address: o.peer.address, own: o.peer.own, sid: o.peer.sid, ref: o.peer.ref }, mine: String(o.mine), theirs: String(o.theirs), tier: o.tier, severity: o.severity, direction: o.direction, key: o.key, message: o.message }))
    const fallback = (Array.isArray(r.value.fallback) ? r.value.fallback : []).filter((x): x is IxConflict => {
      const c = x as Record<string, unknown> | null

      return !!c && peerOk(c.peer) && str(c.message, 400) && str(c.theirs, 400)
    }).slice(0, 200)

    return { ok: true, value: { overlaps, fallback }, stderr: '' }
  }

  /**
   * Computes this session's Ix footprint and publishes it as its x:ix.footprint
   * state (`p2p ix footprint --publish`, ext-ix SPEC §8). Only the outcome is
   * returned: the footprint itself is never handed to the mod's callers, so it
   * can't reach the model.
   */
  async ixFootprint(sid: string): Promise<Outcome<{ published: boolean; skipped?: string }>> {
    const r = await this.call<{ published?: unknown; skipped?: unknown }>(['ix', 'footprint', `--session=${sid}`, '--publish'], { timeoutMs: LONG_TIMEOUT_MS })
    if (!r.ok) return { ok: false, error: r.error, reason: r.reason, stderr: '' }

    return { ok: true, value: { published: r.value.published === true, ...(typeof r.value.skipped === 'string' ? { skipped: r.value.skipped } : {}) }, stderr: '' }
  }

  /**
   * Sends `text` with `--stdin`, so it never shows in a process listing,
   * and with `--notify-when-idle` in the same call when asked.
   */
  send(o: { fromSession: string; to: string; text: string; notifyWhenIdle?: boolean }): Promise<Outcome<SendResult>> {
    return this.call<SendResult>(
      ['send', `--from-session=${o.fromSession}`, `--to=${o.to}`, ...(o.notifyWhenIdle ? ['--notify-when-idle'] : []), '--stdin'],
      { stdin: o.text },
    )
  }

  /**
   * `p2p receipt`: what became of a message that asked for a delivery receipt (§4.3). The CLI
   * decides whether one goes out (receipts on, this session not private, once per outcome).
   */
  receipt(o: { eventId: string; fromSession: string; outcome: ReceiptOutcome }): Promise<Outcome<{ sent: boolean; outcome?: string; reason?: string }>> {
    return this.call(['receipt', `--from-session=${o.fromSession}`, `--outcome=${o.outcome}`, '--', o.eventId])
  }

  /** `p2p trust ls`: trusted users and circles, and everyone trusted right now. */
  trustList(): Promise<Outcome<TrustList>> {
    return this.call<TrustList>(['trust', 'ls'])
  }

  /** `p2p trust check`: whether a sender is trusted now, judged from the verified circle state. */
  trustCheck(userId: string): Promise<Outcome<{ userId: string; trusted: boolean; via: string | null }>> {
    return this.call(['trust', 'check', '--', userId])
  }

  /** `p2p trust add|remove <user|circle:cid>`: only ever on the person's own command or button press. */
  trustChange(verb: 'add' | 'remove', target: string): Promise<Outcome<{ added?: string; removed?: string | null; kind: 'user' | 'circle'; address?: string; name?: string }>> {
    return this.call(['trust', verb, '--', target])
  }

  /** `p2p receipts [on|off]`: whether this user sends delivery receipts. */
  receipts(state?: 'on' | 'off'): Promise<Outcome<{ receipts: boolean; overridden: boolean }>> {
    return this.call(['receipts', ...(state ? [state] : [])])
  }

  /** This session's roster; with a change, signs the next version. */
  async roster(sid: string, change: { add?: string; remove?: string; private?: boolean; circle?: string } = {}): Promise<Outcome<RosterView>> {
    const args = ['session', 'roster']
    if (change.add) args.push(`--add=${change.add}`)
    if (change.remove) args.push(`--remove=${change.remove}`)
    if (change.private) args.push('--private')
    if (change.circle) args.push(`--circle=${change.circle}`)
    args.push('--', sid)
    const r = await this.call<{ roster: RosterView }>(args)

    return r.ok ? { ok: true, value: r.value.roster, stderr: r.stderr } : r
  }

  async held(): Promise<Outcome<HeldItem[]>> {
    const r = await this.call<{ held: HeldItem[] }>(['held'])

    return r.ok ? { ok: true, value: Array.isArray(r.value.held) ? r.value.held : [], stderr: r.stderr } : r
  }

  /** `p2p held approve`; `yes` only for the person's own "join anyway" click (no second confirmation). */
  heldApprove(id: string, opts: { yes?: boolean } = {}): Promise<Outcome<Record<string, unknown>>> {
    return this.call(['held', 'approve', ...(opts.yes ? ['--yes'] : []), '--', id], { timeoutMs: LONG_TIMEOUT_MS })
  }

  heldDecline(id: string): Promise<Outcome<{ declined: string; count: number }>> {
    return this.call(['held', 'decline', '--', id])
  }

  friends(): Promise<Outcome<FriendsInfo>> {
    return this.call<FriendsInfo>(['friends'])
  }

  async circles(): Promise<Outcome<CircleSummary[]>> {
    const r = await this.call<{ circles: CircleSummary[] }>(['circle', 'ls'])

    return r.ok ? { ok: true, value: Array.isArray(r.value.circles) ? r.value.circles : [], stderr: r.stderr } : r
  }

  circleMembers(cid: string): Promise<Outcome<CircleMembers>> {
    return this.call<CircleMembers>(['circle', 'members', '--', cid])
  }

  /**
   * `p2p setup [--name=n] --backup-file`: the identity, its relays from the
   * bundled defaults, the backup phrase written to a 0600 file (so the
   * phrase never passes through Claude Code). Run again, setup keeps the
   * identity; a backup file already there is reported, not overwritten.
   */
  async setup(name?: string): Promise<Outcome<SetupResult>> {
    const r = await this.call<SetupResult>(['setup', ...(name ? [`--name=${name}`] : []), '--backup-file'], { timeoutMs: LONG_TIMEOUT_MS })
    const v = r.ok ? null : (r.value as (SetupResult & { error?: string }) | undefined)
    if (!r.ok && r.error === 'exists' && v && typeof v.userId === 'string' && typeof v.address === 'string') {
      const file = /^(.*) already exists/.exec(r.reason)?.[1]

      return { ok: true, value: { ...v, ...(file ? { backup: { file } } : {}) }, stderr: r.stderr }
    }

    return r
  }

  /** `p2p invite [label] [--circle <cid>]…`: a short code `<relay>/<XXXX-XXXX-XXXX-XXXX>` and its web link. */
  invite(label?: string, circles: readonly string[] = []): Promise<Outcome<InviteResult>> {
    return this.call<InviteResult>(['invite', ...circles.map(c => `--circle=${c}`), ...(label ? ['--', label] : [])], { timeoutMs: LONG_TIMEOUT_MS })
  }

  /** `p2p join --preview <code>`: who made it and what it joins; accepts nothing. */
  async joinPreview(code: string, opts: { allowPrivateRelay?: boolean } = {}): Promise<Outcome<JoinPreview>> {
    const r = await this.call<{ preview: JoinPreview }>(['join', '--preview', ...(opts.allowPrivateRelay ? ['--allow-private-relay'] : []), '--', code], { timeoutMs: LONG_TIMEOUT_MS })

    return r.ok ? { ok: true, value: r.value.preview, stderr: r.stderr } : r
  }

  /**
   * `p2p join --confirmed <code>`: after the person saw the preview and pressed Join. Friends with the
   * inviter, joins the code's circles (never with --yes: a circle no second member confirmed waits for
   * its own click).
   */
  join(code: string, opts: { allowPrivateRelay?: boolean } = {}): Promise<Outcome<JoinResult>> {
    return this.call<JoinResult>(['join', '--confirmed', ...(opts.allowPrivateRelay ? ['--allow-private-relay'] : []), '--', code], { timeoutMs: LONG_TIMEOUT_MS })
  }

  /**
   * `p2p doctor [user]`: why sessions are or aren't visible (this device, or whether we can see
   * `user`). Read-only; every network step in it is bounded by the CLI.
   */
  doctor(user?: string): Promise<Outcome<DoctorResult>> {
    return this.call<DoctorResult>(['doctor', ...(user ? ['--', user] : [])], { timeoutMs: LONG_TIMEOUT_MS })
  }

  /** The relays this identity's document lists. */
  relays(): Promise<Outcome<{ relays: string[] }>> {
    return this.call(['relays'])
  }

  /** Adds or removes a relay: publishes the next identity document version. */
  relaysChange(verb: 'add' | 'remove', url: string): Promise<Outcome<{ relays: string[]; ver?: number; failed?: { relay: string }[] }>> {
    return this.call(['relays', verb, '--', url], { timeoutMs: LONG_TIMEOUT_MS })
  }

  /**
   * `p2p identity rotate --plan --backup-file` (§2.8), for the person's own
   * typed `/peers rotate`: makes the new key (its backup phrase goes to a
   * 0600 file, never through Claude Code) and returns the plan, the new
   * fingerprint and the devices that would follow. Nothing is published.
   */
  rotatePlan(): Promise<Outcome<RotatePlan>> {
    return this.call<RotatePlan>(['identity', 'rotate', '--plan', '--backup-file'], { timeoutMs: LONG_TIMEOUT_MS })
  }

  /**
   * Accepts the plan, only ever on the person's own press after seeing it,
   * with the devices they dropped (revoked before any code goes out). The
   * result carries no secret.
   */
  rotate(opts: { exclude?: readonly string[]; keep?: readonly string[]; invite?: readonly string[] } = {}): Promise<Outcome<RotateResult>> {
    return this.call<RotateResult>(
      ['identity', 'rotate', '--resume', '--yes', `--wait=${ROTATE_WAIT_SEC}`, ...(opts.exclude ?? []).map(did => `--exclude=${did}`), ...(opts.keep ?? []).map(did => `--keep=${did}`), ...(opts.invite ?? []).map(u => `--invite=${u}`)],
      { timeoutMs: ROTATE_TIMEOUT_MS },
    )
  }

  /** Settles a contested move to a new key, on the person's own press: keep one identity, or neither. */
  resolveDispute(id: string, keep: string | undefined): Promise<Outcome<{ keep: string | null; rejected: string[] }>> {
    return this.call(['identity', 'dispute', ...(keep ? [`--keep=${keep}`] : ['--neither']), '--', id], { timeoutMs: LONG_TIMEOUT_MS })
  }

  /** Finishes an interrupted rotation, never accepting a plan (that answers `needs_confirmation`). */
  rotateResume(): Promise<Outcome<RotateResult>> {
    return this.call<RotateResult>(['identity', 'rotate', '--resume', `--wait=${ROTATE_WAIT_SEC}`], { timeoutMs: ROTATE_TIMEOUT_MS })
  }

  /** Drops a plan that wasn't accepted (nothing was published). */
  rotateCancel(): Promise<Outcome<{ cancelled: boolean }>> {
    return this.call(['identity', 'rotate', '--cancel'])
  }

  /** Undoes a code redemption: unfriends them and takes them out of the circles the codes added them to. */
  remove(userId: string): Promise<Outcome<Record<string, unknown>>> {
    return this.call(['remove', '--', userId], { timeoutMs: LONG_TIMEOUT_MS })
  }

  accept(link: string): Promise<Outcome<{ friend: { userId: string; address: string } }>> {
    return this.call(['accept', '--', link], { timeoutMs: LONG_TIMEOUT_MS })
  }

  /**
   * `p2p project show|ls|share|private` (projects.ts) in this session's folder (P2P_WORKDIR): who sees
   * sessions working in it. share and private are the person's, typed (lib isMutating); circles and
   * people follow `--`, `--person=` carries a friend.
   */
  project(args: readonly string[]): Promise<Outcome<Record<string, unknown>>> {
    const [verb = 'show', ...rest] = args
    const flags = rest.filter(a => a === '--add' || a.startsWith('--person='))
    const positionals = rest.filter(a => !a.startsWith('--'))

    return this.call(['project', verb, ...flags, ...(positionals.length ? ['--', ...positionals] : [])])
  }

  /** `p2p circle <verb> …` as the person typed it: options stay options, the rest follows `--`. */
  circle(args: readonly string[]): Promise<Outcome<Record<string, unknown>>> {
    const [verb = '', ...rest] = args
    const flags: string[] = []
    const positionals: string[] = []
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i] as string
      const name = /^--([a-z][a-z-]*)(=.*)?$/.exec(a)
      if (name?.[2] !== undefined) flags.push(a)
      else if (name && CIRCLE_VALUE_OPTIONS.has(name[1] as string) && i + 1 < rest.length) flags.push(`${a}=${rest[++i] as string}`)
      else if (/^-[a-z]$/.test(a) || name) flags.push(a)
      else positionals.push(a)
    }

    return this.call(['circle', verb, ...flags, ...(positionals.length > 0 ? ['--', ...positionals] : [])], { timeoutMs: LONG_TIMEOUT_MS })
  }
}

export const WATCH_BACKOFF_MS = [1_000, 2_000, 5_000, 10_000, 30_000]

export type WatchHooks = {
  isEnded: () => boolean
  onEvent: (event: P2PEvent) => Promise<void>
  /** The child is up and printed its first line (or a restart did): failures are over. */
  onHealthy?: () => void
  /** The child exited (or could not start) while the run lives; it restarts after `waitMs`. */
  onExit?: (end: { code: number | null; reason: string; waitMs: number; isMissing: boolean }) => void
  sleep: (ms: number) => Promise<void>
  /** The live child, for the run's end to kill. */
  setChild?: (child: AsyncGenerator<Chunk, unknown> | null) => void
  /**
   * The run's end: the child is killed at once (signal and `return()`) and
   * the loop stops waiting for its next line, which may never come.
   */
  signal?: AbortSignal
  /** The clock (ms), to tell a child that stayed up from one that keeps dying. */
  now?: () => number | Promise<number>
}

/** A child that stayed up this long resets the backoff when it exits. */
export const WATCH_STABLE_MS = 10_000

/**
 * `p2p watch --session <sid> --jsonl` for the life of the run: each JSON
 * line becomes an event; an exit (network, a fatal error, the CLI's crash)
 * restarts it with backoff. Exit codes: 0 when
 * stopped, 1 on a fatal error (no identity, every relay refusing this
 * device), whose last stderr line is reported.
 */
export async function watchLoop(exec: Exec, bin: readonly string[], sid: string, hooks: WatchHooks): Promise<void> {
  let attempt = 0
  const isStopped = () => hooks.isEnded() || hooks.signal?.aborted === true
  const stopped = new Promise<'stopped'>(resolve => {
    if (hooks.signal?.aborted) resolve('stopped')
    hooks.signal?.addEventListener('abort', () => resolve('stopped'), { once: true })
  })
  while (!isStopped()) {
    let buffer = ''
    let stderr = ''
    let code: number | null = null
    let isMissing = false
    const startedAt = (await hooks.now?.()) ?? 0
    try {
      const child = exec.spawn([...bin, 'watch', `--session=${sid}`, '--jsonl'], hooks.signal ? { signal: hooks.signal } : {})
      hooks.setChild?.(child)
      const kill = () => {
        child.return(undefined).catch(() => undefined)
      }
      hooks.signal?.addEventListener('abort', kill, { once: true })
      try {
        for (;;) {
          const step = await Promise.race([child.next(), stopped])
          if (step === 'stopped') {
            kill()
            break
          }
          if (step.done) {
            const end = step.value as Partial<ChildEnd> | undefined
            code = typeof end?.code === 'number' ? end.code : null
            break
          }
          if (isStopped()) {
            kill()
            break
          }
          const chunk = step.value
          if (chunk.stream === 'stderr') {
            stderr = `${stderr}${chunk.text}`.slice(-4_000)
            continue
          }
          if (attempt > 0 || stderr) hooks.onHealthy?.()
          const { lines, rest } = takeLines(buffer + chunk.text)
          buffer = rest
          for (const line of lines) {
            const event = parseEvent(line)
            if (event) await hooks.onEvent(event)
          }
        }
      } finally {
        hooks.signal?.removeEventListener('abort', kill)
      }
    } catch (e) {
      // Cannot start (no `p2p` on PATH): back off and retry like an exit.
      isMissing = true
      stderr = `could not run ${bin.join(' ')}: ${String((e as Error)?.message ?? e)}`
    }
    hooks.setChild?.(null)
    if (isStopped()) return
    // Only a child that stayed up resets the backoff: one that prints a line and dies keeps backing off.
    if (!isMissing && ((await hooks.now?.()) ?? 0) - startedAt >= WATCH_STABLE_MS) attempt = 0
    const waitMs = WATCH_BACKOFF_MS[Math.min(attempt, WATCH_BACKOFF_MS.length - 1)] ?? 30_000
    attempt += 1
    const reason = stderr.trim().split('\n').filter(Boolean).pop() ?? (code === null ? 'stopped' : `exited ${code}`)
    hooks.onExit?.({ code, reason: reason.replace(/^p2p watch:\s*/, ''), waitMs, isMissing })
    if (isStopped()) return
    await Promise.race([hooks.sleep(waitMs), stopped])
  }
}

/** A row without its extension state summaries (`xstate`): the mod never shows them to anyone. */
function withoutState(row: PeerRow): PeerRow {
  if (typeof row !== 'object' || row === null || !('xstate' in row)) return row
  const rest: Record<string, unknown> = { ...row }
  delete rest.xstate

  return rest as PeerRow
}
