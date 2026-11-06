/** A session as `p2p ls --json` lists it (packages/p2p `PeerRow`). */
export type PeerRow = {
  /** The owner's userId (`p2p:<b32>`). */
  own: string
  sid: string
  /** First 6 hex of sha256(own + "/" + sid). */
  ref: string
  /** `<petname or name>@<grouped fingerprint>`, as the CLI shows it. */
  address: string
  /** One of this user's own sessions. */
  self: boolean
  /** One of this user's sessions on THIS device (the built-in reaches those). */
  thisDevice: boolean
  live: boolean
  ageSec: number
  state: 'busy' | 'idle'
  label: string
  repo?: string
  branch?: string
  mode?: string
  summary?: string
  summaryAt?: number
  files: string[]
  /** What the session's client understands (§4.3 "Status caps"); absent from older clients. Use `understands()`. */
  caps?: string[]
  /** Its subagents (§4.3 "Status agents"), validated by the CLI; peer data, shown inert. */
  agents?: PeerAgent[]
  /** How this user is authorised for the session (§4.2): "owner" for our own. */
  rule?: string
  viewerRule?: string
  /** How the session's sender was authorised (the owner, for statuses). */
  senderRule?: string
  /** The circle that gives standing, when the session is shared through one. */
  circle?: string
}

/**
 * One subagent of a session, as `status.agents` carries it (§4.3 "Status
 * agents", cap `agents.v1`) and as this mod sends its own.
 */
export type PeerAgent = {
  /** Session-local ordinal (`a1`, `a2`, …), never the engine's agent id. */
  id: string
  /** The agent that spawned it; absent when the session's main loop did. */
  parent?: string
  type: string
  /** The spawn's short description, at most 80 characters. */
  task: string
  state: 'running' | 'waiting' | 'idle' | 'done' | 'failed'
  /** Repo-relative (relative to its own worktree when `wt`), most recent first, at most 10. */
  files?: string[]
  /** Its edits are in its own git worktree, not yet on the session's branch. */
  wt?: true
  branch?: string
  /** Last activity (ms). */
  at: number
}

/** `p2p ls --json`'s `relays`: this user's relays and which answered. */
export type RelaysInfo = { listed: string[]; connected: string[]; failed: { url: string; reason: string }[] }

/** Who sent a watch event: verified by the CLI from the envelope. */
export type EventFrom = { userId: string; did: string; address: string; self: boolean }

/** The fields every session event carries. */
export type SessionFields = {
  own: string
  sid: string
  ref: string
  rule?: string
  viewerRule?: string
  /** The local session the event is for, when the CLI knows it. */
  toSession?: string
  /**
   * From one of this user's own sessions (the CLI's local record, never the wire): `person` for the
   * person's own terminal session, `agent` for any other (and for every other device: unknown counts as
   * agent). `fromRef` names the sending session on this device. `ownTrusted`: `p2p own-agents deliver`.
   */
  via?: 'person' | 'agent'
  fromRef?: string
  ownTrusted?: boolean
}

export type IdleReason = 'idle' | 'exited' | 'expired'

/**
 * `rotation`: a friend's new identity key, "<friend> moved to a new key" (§2.8).
 * `rotation-join`: a rotated member asking to take its old identity's place in a circle you own.
 */
export type HeldType = 'invite' | 'circle-invite' | 'circle-join' | 'rotation' | 'rotation-join' | 'rotation-follow' | 'rotation-dispute'

/** The status a `p2p.status` line carries (core `displayStatus`, already sanitized). */
export type DisplayStatus = {
  state: 'busy' | 'idle'
  label: string
  repo?: string
  branch?: string
  mode?: string
  summary?: string
  summaryAt?: number
  files: string[]
  caps?: string[]
  agents?: PeerAgent[]
}

/** One line of `p2p watch --session <sid> --jsonl` (packages/p2p README, "watch lines"). */
export type P2PEvent =
  /** `receipt`: the sender asked for delivery receipts (§4.3); report outcomes with `p2p receipt <id>`. */
  | (SessionFields & { kind: 'p2p.message'; id: string; at: number; from: EventFrom; text: string; unclaimedFor?: string; receipt?: boolean })
  /** What became of a message this session sent (§4.3 "Delivery receipts"): `receiptId` is the send's. */
  /** An envelope of a kind this version doesn't know (docs/compatibility.md): surfaced once, as data. */
  | { kind: 'p2p.unknown'; id: string; at: number; from: EventFrom; envKind: string; own?: string; sid?: string; toSession?: string }
  | { kind: 'p2p.receipt'; id: string; at: number; from: EventFrom; receiptId: string; outcome: ReceiptOutcome; own: string; ref: string; toSession?: string }
  | (SessionFields & { kind: 'p2p.idle'; id: string; at: number; from: EventFrom; reason: IdleReason })
  | (SessionFields & { kind: 'p2p.status'; id: string; at: number; from: EventFrom; status: DisplayStatus; live?: boolean })
  | (SessionFields & { kind: 'p2p.roster'; id: string; at: number; from: EventFrom })
  /**
   * An extension kind (x:<ns>.<type>): `fallback` always; `rendered` when the extension is installed
   * (for x:ix.*, `rendered.digest` is one line framed as data from the peer), `extError` when it refused the body.
   */
  | (SessionFields & { kind: 'p2p.ext'; id: string; at: number; from: EventFrom; ext: string; fallback: string; rendered?: { type?: string; digest?: string } & Record<string, unknown>; extError?: string })
  | {
      kind: 'p2p.held'
      id: string
      at: number
      from: EventFrom
      /** `old`: for a rotation, the identity that moved; `conflict`: more than one rotation claims it (neither applies). */
      /** rotation-follow: this user's own identity moving, `newFingerprint` and the key holder (`device`, `deviceLabel`) that started it. */
      held: {
        id: string
        type: HeldType
        cid?: string
        exp?: number
        old?: { userId: string; address: string }
        conflict?: boolean
        reason?: string
        newFingerprint?: string
        device?: string
        deviceLabel?: string
        /** rotation-dispute: the identities that claim `old`; `approved` is the one carried over before (now suspended). */
        choices?: { userId: string; address: string; approved?: boolean }[]
      }
    }
  /** A rotation of this user's own identity that this device didn't publish (§2.8): shown loudly. */
  | { kind: 'p2p.alert'; id: string; at: number; from: EventFrom; what: string; to?: string; fingerprint?: string; by?: string; byLabel?: string; keyholder?: boolean; contest?: string }
  | { kind: 'p2p.friend'; id: string; at: number; from: EventFrom; friend: { userId: string; address: string }; via?: { label?: string; cid?: string; circleName?: string } }
  /** Someone redeemed one of this user's short invite codes; `remove` is the CLI command that undoes it. */
  | { kind: 'p2p.joined'; id: string; at: number; from: EventFrom; label?: string | null; cid?: string | null; circleName?: string | null; circleStatus?: 'added' | 'proposed' | 'failed'; code?: string; lid?: string; codeId?: string; remove?: string }
  | { kind: 'p2p.unfriend'; id: string; at: number; from: EventFrom; peer: string }
  | { kind: 'p2p.contact'; id: string; at: number; from: EventFrom; what: string }
  | { kind: 'p2p.circle'; id: string; at: number; from: EventFrom; event: string; cid?: string; name?: string }
  | { kind: 'p2p.invite-taken'; id: string; at: number; from: EventFrom }

/** `p2p whoami --json`. */
export type Whoami = {
  userId: string
  name: string
  address: string
  fingerprint: string
  did: string
  keyholder: boolean
  relays: string[]
  doc: { ver: number; exp: number; freshness: string; daysPastExp: number; forked: boolean; historyGap: boolean }
  defaultCircle?: string
  warnings: string[]
}

/** `p2p friends --json`. */
export type FriendsInfo = {
  friends: { userId: string; address: string; since: number; direction: 'outgoing' | 'incoming'; canMessage: boolean }[]
  invites: { outgoing: { inv: string; aud: string; exp: number }[]; held: number }
  blocked: { userId: string; address: string }[]
}

/** One row of `p2p circle ls --json`. */
export type CircleSummary = {
  cid: string
  name: string
  ver: number
  policy: string
  owner: string
  ownerAddress: string
  role: 'owner' | 'admin' | 'member' | 'invited' | 'former'
  joined: boolean
  members: number
  standing: number
  frozen?: string
  isDefault: boolean
}

/** `p2p circle members <cid> --json`. */
export type CircleMembers = {
  circle: CircleSummary
  members: { userId: string; address: string; owner: boolean; admin: boolean; stands: boolean; self: boolean }[]
}

/** One row of `p2p held --json`. */
export type HeldItem = {
  id: string
  type: HeldType
  from: string
  at: number
  address: string
  summary: string
  cid?: string
  reason?: string
  /** rotation, rotation-join: the old identity and its address. */
  old?: string
  oldAddress?: string
  /** rotation: the old identity's own final version names this same move. */
  confirmedByDocument?: boolean
  /** rotation-follow: the key holder that started it, and the new identity's fingerprint. */
  device?: string
  deviceLabel?: string
  newFingerprint?: string
  /** rotation-dispute: the identities to choose from. */
  choices?: { userId: string; address: string }[]
}

/** One `p2p doctor` check: ✓ ok, ✗ fail (with a fix), ? unknown (with what would tell). */
export type DoctorCheck = { id: string; status: 'ok' | 'fail' | 'unknown'; title: string; detail: string; fix?: string }

/** `p2p doctor [user] --json`. */
export type DoctorResult = {
  scope: 'device' | 'user'
  version: string
  user?: { input: string; userId?: string; address?: string }
  checks: DoctorCheck[]
  summary: { ok: number; fail: number; unknown: number }
}

/** `p2p identity rotate --plan --json`: what a rotation would do (nothing is published yet). */
export type RotatePlan = {
  plan: true
  from: string
  address: string
  to: string
  newFingerprint: string
  /** `labelTrusted: false`: the label comes only from versions this device didn't publish. */
  follow: { did: string; label: string; keyholder: boolean; labelTrusted?: boolean }[]
  /** `why`: dropped by default (added by a version this device didn't publish, or not seen lately); Keep takes `--keep`. */
  excluded: { did: string; label: string; keyholder?: boolean; labelTrusted?: boolean; why?: string }[]
  /** The friends that get the new identity's invite (exactly those `friendsOptIn` doesn't leave out). */
  friends: number
  /** Friendships this device can't vouch for (made by a device the plan drops, or not verifying now): invited only on Invite (`--invite`). */
  friendsOptIn?: { userId: string; address?: string; why: string; invited?: boolean }[]
  owned: number
  memberOf: number
  contest: boolean
  backup?: { file: string }
}

/** `p2p identity rotate --json` (never carries a secret: link codes stay in the CLI, the backup phrase in its file). */
export type RotateResult = {
  from: string
  to: string
  address: string
  fingerprint: string
  did: string
  step: string
  devices: { followed: { did: string; newDid: string; label: string }[]; offline: { did: string; label: string }[]; excluded: { did: string; label: string }[] }
  friends: { invited: number; failed: string[] }
  circles: { cid: string; name: string; role: string; status: string; reason?: string }[]
  proofs: { kind: string; claim: string; publish: string }[]
  finalVer?: number
  backup?: { file: string }
  warnings: string[]
}

/** `p2p session roster <sid> --json`'s `roster`. */
export type RosterView = {
  sid: string
  ref: string
  ver: number
  vis: 'circle' | 'private'
  circle?: string
  circleName?: string
  parts: { userId: string; address: string }[]
  openCircle?: boolean
}

/** One of `p2p ix inbox --json`'s `events`: `digest` is framed as data from the peer. */
export type IxInboxItem = { id: string; at: number; kind: string; from: { userId: string; address: string; self: boolean }; ref?: string; digest: string; extError?: string; kept: boolean }

/** `p2p ix show --json`: a note's full framed `text` and its `textHash`, or another kind's `framing` and body. */
export type IxShown = {
  event: { id: string; at: number; kind: string; from: { userId: string; address: string; self: boolean }; fallback: string; rendered?: Record<string, unknown> }
  text?: string
  textHash?: string
  bodyHash?: string
  framing?: string
  body?: Record<string, unknown>
}

/** What the mod sends with `p2p ix note|subgraph|impact`. */
export type IxSendInput = {
  kind: 'note' | 'subgraph' | 'impact'
  fromSession: string
  to: string
  /** note: the text (stdin), or an existing Ix note id. */
  text?: string
  ixNote?: string
  tag?: string
  title?: string
  /** subgraph: one of a path pattern, a symbol (with its kind) or a region. */
  pattern?: string
  symbol?: string
  symbolKind?: string
  region?: string
  why?: string
  /** impact: the target, and the files the change touches. */
  target?: string
  changed?: string[]
  /** impact: a report already built (and shown to the person): sent exactly, Ix not run again. */
  impactBody?: Record<string, unknown>
}

/** `p2p ix note|subgraph|impact --json`. */
export type IxSent = { delivered: boolean; to: { userId: string; address: string; own: string; sid: string; ref: string }; relays: number; kind: string; bytes: number; body: Record<string, unknown> }

/** One of `p2p ix conflicts --json`'s `conflicts` (@peer2peer/ext-ix). */
export type IxConflict = {
  peer: { address: string; own: string; sid: string; ref: string }
  mine: string
  theirs: string
  direction: 'mine-affects-theirs' | 'theirs-affects-mine'
  via: ('caller' | 'user' | 'importer' | 'test')[]
  message: string
}

/** One of `p2p ix overlaps --json`'s `overlaps` (@peer2peer/ext-ix): a derived line, never a peer's footprint. */
export type IxOverlap = {
  peer: { address: string; own: string; sid: string; ref: string }
  mine: string
  theirs: string
  tier: 'same-symbol' | 'depends' | 'same-file' | 'same-area' | 'transitive'
  severity: 'high' | 'medium' | 'low'
  direction: 'both' | 'mine-affects-theirs' | 'theirs-affects-mine'
  key: string
  message: string
}

/** `p2p send --json`. */
export type SendResult = {
  delivered: boolean
  to: { userId: string; address: string; own: string; sid: string; ref: string }
  relays: number
  devices: number
  messageId?: string
  notifyWhenIdle?: boolean
  /** Held for later: "offline" (the relays hold it for a session that isn't live), "outbox" (this device does, until a relay is reachable). */
  queued?: true
  state?: 'offline' | 'outbox'
  /** When the target session last posted a status (ms). */
  lastSeen?: number
  /** When it stops being delivered (ms). */
  expiresAt?: number
  /** Delivery receipts: "requested" (they come back as p2p.receipt for `receiptId`) or "unsupported" (an older client, or receipts off there). */
  receipts?: 'requested' | 'unsupported'
  receiptId?: string
}

/** `p2p trust ls --json`. */
export type TrustList = {
  users: { userId: string; address: string; blocked: boolean }[]
  circles: { cid: string; name: string | null; joined: boolean; open?: boolean; members: string[] }[]
  trusted: string[]
}

export type ReceiptOutcome = 'shown' | 'held' | 'declined' | 'expired' | 'ended'

/**
 * What waits above the prompt for the person's Deliver/Decline:
 *  - a `message` from a friend or co-member whose session runs in another
 *    permission mode (or an unknown one): Deliver hands it to the model;
 *  - a `request` the CLI holds (a first contact's friend invite, a circle
 *    invite, a join request): Accept runs `p2p held approve`, Decline
 *    `p2p held decline`. Nothing reaches the model either way.
 */
export type HeldMessage = {
  id: string
  kind: 'message' | 'request' | 'share'
  from: { userId: string; address: string }
  text: string
  heldAt: number
  why: string
  /** message: the `--to` a delivery notice goes back to (the sender's session when known). */
  replyTo?: string
  /** message: `text` is already the framed cross-session message (held past a turn cap). */
  isFramed?: boolean
  /** message: an extension item (x:<ns>.*), not a conversational message: its sender gets no delivery notice. */
  isExt?: boolean
  /**
   * message: the CLI's copy of a message for one of this user's sessions that has ended
   * (`unclaimedFor`). Its sender gets no delivery notice: one would tell them that session ended.
   */
  isUnclaimed?: boolean
  /** message: the CLI event to report delivery receipts for (the sender asked for them). */
  receiptEvent?: string
  /** The held-queue bucket (capHeld) when it isn't the sender's userId: one per sending session of yours. */
  bucket?: string
  /** share: what the model's ix_share would send, once the person presses Send. */
  share?: Omit<IxSendInput, 'fromSession'>
  /** share: SHA-256 of exactly the row text the person reviewed; Send acts only while it still matches. */
  shareHash?: string
  /** request: the CLI's held id. */
  heldId?: string
  /** request: Accept joins even without a second member's confirmation (`held approve --yes`), as the person chose. */
  isJoinAnyway?: boolean
  /** request: an invite code or link the person asked to join (`/peers join`): Join runs it, once they saw what it offers. */
  joinCode?: string
  /** request with joinCode: the person typed --allow-private-relay (Join passes it on). */
  joinAllowPrivateRelay?: boolean
  /** message: the person pressed "Always deliver from …" and the row now asks them to confirm it. */
  isTrustConfirming?: boolean
  heldType?: HeldType
  /** rotation-dispute: one Keep button per identity, and Neither (no Accept/Decline). */
  choices?: { userId: string; address: string }[]
}

/**
 * What waits for the model's next tool round, or for the gathered idle turn:
 * the text the model reads, with who sent it kept beside it (so the turn
 * caps and the hold rule still apply after a hot reload).
 */
export type PendingItem = {
  id: string
  text: string
  /** A <peer-activity> note: rides beside a prompt, never starts a turn. */
  isActivity?: boolean
  /** The peer who sent it; absent for this user's own devices and the mod's own notes. */
  from?: { userId: string; address: string }
  /**
   * This user's own session sent it (another device, or another session on this one): never held
   * by the hold rule, but it may start at most TURNS_FROM_SELF turns per window; past that, `message`
   * waits for Deliver (and its sender's receipt says so).
   */
  fromOwn?: { userId: string; address: string; isAgent?: boolean }
  /** The held message it becomes if the hold rule turns against it before delivery. */
  message?: HeldMessage
  /** The CLI event a `shown` receipt is reported for once the model has it. */
  receiptEvent?: string
}

/**
 * `p2p setup [--name n] --backup-file --json`. The mod asks for the
 * 0600 file, so the phrase never crosses into Claude Code at all; a
 * `backup.phrase` (only with `--print-backup`) would be shown above the
 * prompt alone, never in model context.
 */
export type SetupResult = {
  userId: string
  address: string
  fingerprint?: string
  did?: string
  relays?: string[]
  /** False when an identity was already here (setup is idempotent). */
  created?: boolean
  published?: string[]
  failed?: unknown[]
  backup?: { file?: string; phrase?: string }
}

/**
 * `p2p invite [label] --json` with a short code (feat/short-invites):
 * `code` is `<relay>/<XXXX-XXXX-XXXX-XXXX>`. The pre-short-code shape
 * (`link`, `invite.exp`, `invite.uses`) is read too.
 */
export type InviteResult = {
  code?: string
  /** The code's non-secret local id: the redemption notice carries it, for an exact match. */
  lid?: string
  codeId?: string
  /** The code as one line to paste (the CLI's human form). */
  line?: string
  relay?: string
  link?: string
  label?: string | null
  to?: string | null
  /** Unix seconds. */
  expiresAt?: number
  /** How many people may redeem it (a code works once). */
  uses?: number | null
  circle?: { cid: string; name?: string } | null
  /** Every circle the code joins (multi-circle codes). */
  circles?: { cid: string; name?: string; members?: number }[]
  /** The code as a web link (https://ix-infra.com/p2p/invite#…). */
  web?: string
  /** A message to send someone who may not have Peer2Peer yet: the link, how to install, how to join. */
  message?: string
  /** The code's relay is on a private network: joining it takes --allow-private-relay. */
  privateRelay?: boolean
  invite?: { exp?: number; uses?: number }
}

/** `p2p join --preview --json`: who made the code and what it joins; nothing accepted. */
export type JoinPreview = {
  from: { userId: string; address: string; fingerprint: string }
  to?: string | null
  /** The address the code was made for, when it was made for one person. */
  toAddress?: string
  circles: {
    cid: string
    name: string
    members: number
    policy?: 'invite' | 'open' | string
    owner?: string
    ownerAddress?: string
    /** Signed by the owner it names. */
    verified?: boolean
    /** Joined on the yes (verified, invite-only, run by the inviter); else `note` says why not. */
    auto?: boolean
    note?: 'unverified' | 'open' | 'not-admin' | string
  }[]
  expiresAt?: number
}

/**
 * `p2p join --json -- <code>`: friends with whoever made the code, into
 * their circle, that circle the default, in one step; creates the identity
 * when there is none. The circle `status` says how far the join got.
 */
export type JoinResult = {
  from?: unknown
  friend: { userId: string; address: string }
  delivered?: { relays?: string[] } | null
  circle?: {
    cid: string
    name?: string
    status?: 'joined' | 'already' | 'pending' | 'needs-approval' | 'held'
    /** held: why the circle wasn't joined from the code (its invite, if it comes, is approved on its own). */
    reason?: string
    /** The circle's join policy, when the CLI says (an unknown one counts as open). */
    policy?: 'invite' | 'open' | string
    default?: boolean
    /** needs-approval: the held item that joins anyway on the person's explicit click. */
    held?: string
  } | null
  /** Every circle the code joins (multi-circle codes), the first one first. */
  circles?: NonNullable<JoinResult['circle']>[]
  /** The circle id now the default for new sessions, when join set it. */
  defaultCircle?: string | null
  /** The join created this device's identity. */
  created?: boolean | null
  /** Set when the joiner's only relay was chosen by the code: its host. */
  relayWarning?: string | null
}

/**
 * What the person (and only the person) sees above the prompt: a secret the
 * model must never read (a backup phrase, an invite code), or a join notice
 * with its one-click Remove.
 */
export type Reveal =
  | { id: string; kind: 'backup'; text: string; phrase?: string; file?: string; isConfirmingDelete?: boolean }
  /** `message`: the CLI's install-aware message to paste for someone who may not have Peer2Peer yet. */
  | { id: string; kind: 'invite'; text: string; code: string; message?: string }
  | { id: string; kind: 'joined'; text: string; userId: string; cid?: string; sharedSid?: string }
  | { id: string; kind: 'warning'; text: string }
  /** `/peers rotate`'s plan: the person drops devices (`dropped`), then presses Rotate or Cancel. */
  | {
      id: string
      kind: 'rotate-plan'
      text: string
      newFingerprint: string
      devices: { did: string; label: string; keyholder: boolean; labelTrusted: boolean; why?: string }[]
      dropped: string[]
      /** What the plan dropped by default: keeping one takes an explicit Keep (`--keep`). */
      initiallyDropped: string[]
      /** Friends the plan leaves out unless the person presses Invite (`--invite`). */
      optIn?: { userId: string; address: string; why: string }[]
      invite?: string[]
      isRunning?: boolean
    }

declare module 'claude-code' {
  interface PluginState {
    peer2peer: { held: HeldMessage[]; pending: PendingItem[]; reveals: Reveal[] }
  }
}
