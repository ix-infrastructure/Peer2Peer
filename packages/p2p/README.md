# p2p: the Peer2Peer CLI

`@peer2peer/cli` is the standalone `p2p` command for [Peer2Peer v3](../../docs/protocol.md). It gives you an identity with no account, friends and circles, end-to-end encrypted messages between agent sessions, and live session status. Everything goes over open relays that anyone can run.

It is core software: it never imports Ix or Kartr (`node scripts/check-boundaries.mjs`).

## Two friends in two minutes

You need a relay. Run your own (`npx @peer2peer/relay`, see [run-a-relay.md](../../docs/run-a-relay.md)), or use one your community runs. No relay is built in yet. Tell `p2p` about it once:

```sh
export P2P_DEFAULT_RELAYS=wss://relay.example.org/v3   # 1–5, comma separated
```

**Ann:**

```sh
p2p setup                     # makes your key (name: your OS user); offers to save the backup phrase
p2p invite ben                # prints a one-time code: relay.example.org/K7QM-3XPD-9TWA-HF2N-6RJC
```

Ann sends Ben the line it prints (`Join me on Peer2Peer: p2p join relay.example.org/K7QM-3XPD-9TWA-HF2N-6RJC`).

**Ben** (no setup needed: `join` creates his identity if he has none):

```sh
p2p join relay.example.org/K7QM-3XPD-9TWA-HF2N-6RJC   # you and ann@k7f2-qx9a-3m4n-5p6q are friends
```

If Ann has a default circle (`p2p circle default <cid>`) that she owns or administers, the code joins Ben to it as well, and it becomes his default circle. Ann's client adds him the next time it runs (at once, when a `watch` is running), and tells her `ben@… joined via your code K7QM… ("ben")`. If that isn't who she meant, `p2p remove <userId>` undoes it. The code works once and lives 7 days at most. The long-link form (`p2p invite --link` / `p2p accept <link>`) still works.

**Share a project and talk.** A session is shared with nobody until you share the project it works in (a git repository, or a folder): see [projects](../../docs/concepts.md#projects-project-boundaries).

```sh
# Ben, in his repository (and Ann, in hers: `p2p project share --person ben`):
p2p project share --person ann               # or a circle: p2p project share <cid>
p2p session roster s-ben --add ann
p2p status --session s-ben --state busy --summary "fixing the auth bug" --file src/auth.ts
p2p watch --session s-ben --jsonl            # leave running: one JSON line per event

# Ann:
p2p ls                                       # ● ben@… [3aa0a1] api busy  fixing the auth bug
p2p send --from-session s-ann --to ben "I'm touching src/auth.ts too, let's sync"
```

Ben's `watch` prints the message as a `p2p.message` line. To answer, Ben runs `p2p send --from-session s-ben --to ann …`. With no live session of Ann's to send into, the message goes into Ben's own session, which Ann is on the roster of.

Names aren't unique. `p2p` always shows the fingerprint (`ben@ayrn-mrvm-ughl-gkov`) and decides by full userId. Give people your own names with `p2p petname <user> <name>`.

## Commands

Every command takes `--json`. With it, a command prints exactly one JSON object and exits 0, or prints `{error, reason, …}` and exits 1. `watch` streams JSON lines instead.

**On a terminal** (stdin and stdout both a TTY, no `--json`, `--yes`, `--no-input` or `CI`, and not inside an agent's tool call), a command missing an argument it could take from a list asks for it with a picker: arrow keys or j/k move, space selects, enter confirms, typing filters, Esc or Ctrl-C cancels (exit 1, nothing done). `invite` with no `--circle` picks the circles and the expiry; `join` asks Join/Cancel; `circle default|invite|leave|members`, `held approve|decline`, `remove`, `unfriend`, `block`, `unblock`, `invites revoke`, `send` (recipient, then text) and `trust add|remove` pick what's missing (`trust add` still takes the fingerprint typed). Output on a terminal is laid out (tables, colour for state, relative times; `NO_COLOR`, `FORCE_COLOR` and `TERM=dumb` are respected), and `p2p` alone shows a home screen. Piped or redirected, every command prints and exits exactly as before. `--no-input` (anywhere on the line) turns off pickers and questions on a terminal too.

On a terminal, `p2p` alone and `p2p relays` connect to your own relays (bounded) to show their health; piped, they don't. `send` without `--from-session` sends from the `tui` session, shares that session with the recipient when it isn't yet ("shared session tui with <name>", so the message can land there and replies reach `p2p tui`; undone if the send fails; never with `--from-session` or off a terminal, and an agent's `p2p send` without `--from-session` is refused by the guards; a send from `p2p tui` does the same), and says so ("sent from session tui; replies show in `p2p tui`"). `trust add` lists names (or petnames) only: you type the fingerprint as the person gave it to you. A signal (SIGINT, SIGTERM, SIGHUP) during a picker restores the terminal, then ends the process as the signal would.

**Agents:** the pickers stay off inside Claude Code's and Codex's tool calls (`CLAUDECODE`, `CODEX_THREAD_ID`, `CODEX_SESSION_ID`). That check knows only those two: any other agent or automation that runs `p2p` in a terminal should pass `--no-input` or set `CI=1`.

| Command | What it does |
|---|---|
| `setup [--name n] [--relay url]… [--backup-file [path] \| --print-backup \| --no-backup]` | The friendly `init`: the name defaults to your OS user name, and relays come from the defaults. Interactively it offers to save the backup phrase to a 0600 file (default `<home>/backup-phrase.txt`, never overwritten) or print it. It is idempotent: on a home that already has an identity it changes nothing and reports `created: false`. |
| `init [--name n] [--relay url]… [--yes]` | Creates the identity key and the first device (a key holder), and publishes document v1. It strongly prompts for a backup or a second key holder (§2.5). `--yes` skips the prompt but still warns. |
| `whoami` | Shows your address and grouped fingerprint, devices, relays and document expiry. |
| `backup show` / `backup restore [--relay …] [--keep-devices] [--new-chain]` | The 24-word BIP-39 phrase (§2.7). Restore reads the phrase from a prompt or stdin, never from argv. It makes this device a key holder and, by default, revokes the lost devices. It refuses when the relays can't be read; starting a new history at version 1 takes `--new-chain`, and only when a reachable relay holds no document. It back-fills a relay that's behind. If any listed relay still refuses (or is down), the restore is committed locally but exits **2** with `error: "restore_incomplete"` and the full result (`did`, `ver`, `failed`); fix it with `p2p identity republish`. |
| `identity republish` | Publishes your current identity document again to every relay it lists, over a restricted connection where a relay doesn't list this device yet (after a restore). Relays that failed transiently (`network`, `auth_failed`, `identity-gap`) are retried on every connect. A relay that refused outright (e.g. `forbidden`) is retried automatically at most hourly (`P2P_REFUSED_PUBLISH_RETRY_SEC`), or right away by `identity republish`. |
| `identity rotate [--plan] [--exclude <did>]… [--keep <did>]… [--invite <user>]… [--keep-keyholders] [--wait <s>] [--backup-file [path]] [--yes]` / `--resume` / `--cancel` / `--contest` / `--resend` | Moves you to a new identity key (§2.8): the remedy for a lost or stolen key-holding device. See [Identity rotation](#identity-rotation). |
| `identity follow <id>` | On a device that doesn't hold the identity key: follow a rotation one of your key holders started (it waits in `p2p held`). |
| `identity dispute <id> --keep <user>` / `--neither` | Settle a contested move to a new key: a friend or member you carried over is suspended when another key claims the same old identity. Only on a key holder (`needs_keyholder` elsewhere); the settlement reaches your other devices. |
| `link start [--keyholder] [--expect-compare <code>]` / `link join <code> [--rotated]` | Device linking (§2.4). Shows the `p2p-link:…@relay` code and a QR code, then both sides show a compare code that you confirm. Without a terminal, `--expect-compare` is required: the link proceeds only if the answering device shows that code (the compare code is also in the `--json` output). `--rotated` re-links a device whose identity was rotated while it was offline (its old home is archived in `<home>/rotated/`). |
| `devices` / `devices revoke <did>` | Revoking publishes the next document version. Caps and circle memberships the revoked device signed are re-issued from this one. |
| `profile set --bio … --avatar <url\|image> --link …` / `profile show [user]` | P1 profiles. An image file becomes a `data:` URI of at most 4 KiB. |
| `proof add github <handle> [--gist id]` / `proof add dns <domain>` / `proof verify <user>` | §2.6 proofs. `add` prints exactly what to publish. |
| `invite [label] [--circle cid]… [--no-circle] [--to user] [--ttl-days N] [--relay url] [--web]` | A one-time short code (protocol P4), printed with its web link (`https://ix-infra.com/p2p/invite#<relay>/<CODE>`, the same code; `--web` prints only the link). It friends whoever redeems it and joins them to each `--circle` (up to 5, each one you own or administer, none open; otherwise no code is made) or, by default, to your default circle (when you own or administer it). The label is local only; it is shown when the code is redeemed. `--to` binds the code to one recipient. `--ttl-days` is 1–7 (default 7). |
| `join <code\|link> [--wait s] [--preview] [--confirmed] [--yes] [--name n] [--allow-private-relay]` | Redeems a code or its web link: friends, plus each circle under §3.3. It first shows who the code is from and every circle it joins, and asks once; `--preview` shows that and stops, `--confirmed` says you saw it, `--yes` says yes for scripts (and joins even when no second member could confirm it). Only a verified, invite-only circle the inviter runs is joined on the yes, and only if the circle that arrives is the one shown; anything else waits as a circle invite to approve on its own. The first circle becomes your default only when you have none (never an open one); running sessions stay as they are. A code whose relay is, or resolves to, a loopback, link-local or private address is refused unless you pass `--allow-private-relay` (or set `P2P_ALLOW_PRIVATE_RELAY=1`), for your own relay on your network. With no identity yet, it creates one first, on your default relays. With no default relays, the code's relay is your only one: it warns (`relayWarning` in `--json`), and you should add another with `p2p relays add`. |
| `relays` / `relays add <url>` / `relays remove <url>` | The relays your identity document lists (1–5). Adding or removing publishes the next document version to the old and new relays, sends each friend a fresh friend cap on the new list, and re-signs your circle joins with a fresh co-member cap (`capsReissued`, `rejoined` in `--json`). |
| `invites` / `invites revoke <code>` | Your codes: `open`, `taken` (the relay gave it out, nobody joined yet), `evicted` (the relay dropped it to make room: make a new one), `redeemed` (by whom), `expired` or `revoked`. Revoking deletes the code at the relay, revokes its cap, and refuses its accept even from someone who took it before. |
| `remove <user>` | Undoes a redemption: unfriends them and takes them out of the circles your codes added them to. |
| `invite --link [--to user] [--uses N]` / `accept <link> [--allow-private-relay]` | The long-link form (§3.1). The invite carries your document and a contact-only cap. A link naming a relay on a loopback, link-local or private address is refused unless `--allow-private-relay` (or `P2P_ALLOW_PRIVATE_RELAY=1`). |
| `friends`, `unfriend <user>`, `block <user>`, `unblock <user>`, `petname <user> <name>` | Unfriend and block revoke the caps you issued to that user, at every relay those caps name. Block also re-keys your join in every circle you share with them (fresh co-member cap, old one revoked), so their copy stops reaching your mailbox. Other members get the new cap in the usual bundle. |
| `held` / `held approve <id>` / `held decline <id>` | First contacts, circle invites, (for owners) join requests, and friends or members who moved to a new key (§2.8) waiting for you. |
| `circle create <name> [--open]` | Founds a circle you own. |
| `circle invite <cid> <user>` / `circle invite <cid> --link` | The owner adds the user directly; an admin proposes `add` to the owner. `--link` prints a circle link. |
| `circle join <link> [--wait s] [--yes] [--allow-private-relay]` | Bootstraps the full chain and confirms it with the owner and one other member before joining (§3.3). A link naming a relay on a private address needs the same opt-in as `accept`. |
| `circle leave`, `ls`, `members <cid>`, `propose <cid> add\|remove\|promote\|demote\|rename …`, `transfer <cid> <user>` (`--accept` to consent), `policy <cid> invite\|open`, `default <cid>\|--none` | The rest of circle management. |
| `ls [--all]` (JSON: `peers[]` with `rule`/`viewerRule` (how you're authorised), `senderRule`, `circle`; and `relays: {listed, connected, failed: [{url, reason}]}`) | Live sessions of friends, circle-mates and your other devices, with the sanitized summary and files. A session is live for 150 s after the `ts` of its last status. |
| `send --from-session <sid> --to <user>[/<sid>\|" [ref]"] [--notify-when-idle] [--stdin] [--project-dir d]… [text…\|-]` | Refused (`not_shared`) to anyone outside the session's projects' audience (see `project`). Text comes from the arguments, or from stdin with `--stdin` or a single `-` (stdin is also read when there's no text and no `--notify-when-idle`). A pure `--notify-when-idle` subscription never waits on stdin. The output says how many relays the message was delivered via. A session that isn't live but was seen within the last 24 hours still gets it: the relays hold it until that session reconnects (`queued: true, state: "offline", lastSeen`); with no ref and several such sessions the send is `ambiguous`. When no relay can be reached, the sealed message waits in this device's outbox and `watch` sends it later (`queued: true, state: "outbox"`); either way it expires after 7 days. Any other "via 0" is an error. "Delivered" means a relay has it: when the target session is live and its status advertises `receipts.v1` the message asks for delivery receipts (`receipts: "requested"`, `receiptId`), which come back to the sending session's `watch` as `p2p.receipt` lines (`outcome`: `shown`, `held`, `declined`, `expired` or `ended`); otherwise `receipts: "unsupported"` (an older client, or one with receipts off). |
| `receipt <event> --from-session <sid> --outcome shown\|held\|declined\|expired\|ended` | For the front end that shows messages: what became of a `p2p.message` that carried `receipt: true`. The CLI decides whether a receipt goes out (§4.3 "Delivery receipts"): receipts on, the session not private, each outcome once and nothing after a final one, an ended session's copy only ever as `ended`, at most 30 a minute to one user, a fair share past 120 a minute in all, and never more than 240. `{sent, outcome?, reason?}`, never an error for "nothing to send". |
| `trust ls`, `trust add\|remove <user\|circle:<cid\|name>>`, `trust check <userId>` | Who may message a session that approves its own tool calls without the hold (front ends such as the Claude mod read it). Users by full userId or `name@fingerprint` (resolved by fingerprint; a bare name is refused), circles by id or name, stored in config.json (`trust`, 0600). A trusted circle covers its standing members as its verified state has them when checked, which is anyone its owner or admins add: someone removed from it, or this user leaving it, ends their trust. An open circle can't be trusted (`open_circle`), and a trusted circle that turns open trusts nobody until it is invite-only again. Changes are made under the state lock, so concurrent `trust` and `receipts` changes never lose one. A blocked user is never trusted. `trust ls --json` lists `users`, `circles` (with their current `members`) and everyone `trusted` now. |
| `receipts [on\|off]` | Whether this user sends delivery receipts (on by default; `"receipts": false` in config.json, `P2P_RECEIPTS=0` overrides). On by default, which is a presence signal: statuses advertise `receipts.v1` to everyone who sees them, and a `shown` tells a sender when the message reached the session's model. Off, no receipt goes out and statuses stop advertising `receipts.v1`, so senders see what an older client looks like. |
| `status --session <sid> --state busy\|idle [--summary] [--file]… [--label] [--repo] [--branch] [--mode] [--cap]… [--agents-json <json\|->] [--project-dir d]…` | `--project-dir` (and `P2P_PROJECT_DIRS`, `P2P_WORKDIR`): folders the session works in; each binds it to that project, which only narrows who sees it (a device file such as `/dev/null` binds nothing). `--project-dirs-over[=unresolved,folders,front]` (and `P2P_PROJECT_DIRS_OVER`): the front end couldn't resolve a path, dropped folders past its cap, or lost track; the session is private, and the refusal names the cause (a bare flag or an unknown word is `front`). A private session sends no summary. Sends a `status` envelope to everyone the roster allows. Safe to run every 60 s. A status carries the CLI's own caps (`status.tolerant.v1`, `agents.v1`, `xstate.v1`, `proto.3.1`) and `--cap` adds what the calling client understands. `--agents-json` (a JSON array, `-` reads it from stdin) is the session's subagents (§4.3 "Status agents"): normalized (at most 8, each at most 10 repo-relative files, an 80-character task), sent as `agents` only to users whose live sessions all advertise `agents.v1`, and as a `(+N agents)` summary to everyone else (`delivered[].agents` says which). `P2P_STATUS_CAPS=0` (or `"statusCaps": false` in config.json) opts out, for peers on clients older than the §4.3 "Status caps" amendment: the status then carries only the original fields, and `--cap` is left out with a warning, never an error. `ls --json` rows and watch lines carry each session's `caps` and `agents`. |
| `project share [<circle>…] [--person u]… [--add] [--dir d]`, `project private`, `project ls`, `project show` | Who sees sessions working in a project (a git repository, or a folder): private until shared (see [projects](../../docs/concepts.md#projects-project-boundaries)). `share` with nothing named: a picker on a terminal, else your default circle. A committed `.p2p-private` makes a repository private; nothing in a repository can share it |
| `session show <sid>` | Read only: the session's bound projects, each one's policy (a folder project lists the subfolders it covered), who the session reaches, and every reason it is private with what helps (a share, or a new session when the cause lasts until it ends: a cap, an unresolved path, a dropped front end, `.p2p-private`). Yours only: refused inside an agent's session without the front end's token, so no agent reads another session's bindings. |
| `session roster <sid> [--circle cid\|--private] [--add u]… [--remove u]…` | Who may see and message a session, within what its project shares (`not_shared` past it). Until changed here, a session follows its project's policy (§6), also when that changes after the session started; a running session never moves into an open circle by itself (it stays private, with a warning). |
| `watch --session <sid> --jsonl` | One JSON line per accepted event. Stays connected and reconnects silently. |
| `doctor [<user>]` | Explains, in plain words, why sessions are or aren't visible. See [Doctor](#doctor). |
| `tui [--session <sid>]` | A full-screen terminal UI: people and their sessions, held items, messages, send and health. Interactive only. See [Terminal UI](#terminal-ui). |
| `extensions` / `extensions enable <ns>` / `extensions disable <ns>` | Loaded and enabled extensions; enabling (opt-in) edits `extensions` in config.json. An extension runs with your identity: enable only ones you trust (see [Extensions](#extensions)). |
| `<ns> …` (e.g. `ix note`, `ix subgraph`, `ix impact`) | Commands an enabled extension adds. A registered namespace that isn't enabled answers `{error: "extension_missing"}` with how to install and enable it. |

### `watch` lines

Every line has `kind`, `id`, `at` (ms) and a verified `from: {userId, did, address, self}`. Session events add `own`, `sid`, `ref`, `rule` and `viewerRule`, plus `toSession` when the event is addressed to one of your sessions:

```
{"kind":"p2p.message", …, "text"}                  {"kind":"p2p.status", …, "status":{state,label,summary?,files,…}, "live"}
{"kind":"p2p.idle", …, "reason":"idle"|"exited"|"expired"}
{"kind":"p2p.friend", …, "friend":{userId,address}} {"kind":"p2p.unfriend", …, "peer"}   {"kind":"p2p.contact", …, "what":"cap"}
{"kind":"p2p.held", …, "held":{id,type,old?,conflict?,…}} {"kind":"p2p.circle", …, "event":"version"|"member-joined"|"member-left"|"removed"|"proposal"|"member-rotated"|…, "cid"}
{"kind":"p2p.ext", …, "ext", "fallback", "rendered"?, "extError"?}   {"kind":"p2p.invite-taken", …}
{"kind":"p2p.joined", …, "label"?, "cid"?, "circleName"?, "circleStatus"?, "code":"K7QM…", "lid", "remove":"p2p remove <userId>"}
```

`p2p.joined` is the inviter's notice that one of its codes was redeemed: `from` is the redeemer.

`p2p.ext` is an extension kind (`x:<ns>.<type>`). `fallback` (sanitized, prefixed with the sender's address) is always there. `rendered` is the installed extension's digest of the body, every string sanitized again by `p2p`; `extError` says why there is none (an invalid or newer body). Without the extension the body is never interpreted.

### Short-code JSON

```
p2p setup --json    {userId, address, fingerprint, did, relays, created, published?, failed?, backup?: {file} | {phrase}}
                    (backup.phrase only with --print-backup; no backup key when nothing was saved or printed)
p2p invite --json   {code: "<relay>/K7QM-3XPD-9TWA-HF2N-6RJC", line, relay, label, to: {userId,address}|null,
                     circle: {cid,name}|null, circles, web, expiresAt (unix s), uses: 1, lid,   (lid: the relay lookup id, not secret; the same lid is on p2p.joined)
                     message, privateRelay}   (message: a paste-ready text with install steps and the join lines)
p2p join --json     {from: {userId,address,fingerprint}, friend: {userId,address}, delivered,
                     circle: {cid,name,status: "joined"|"already"|"pending"|"needs-approval",default,held?}|null,
                     defaultCircle: cid|null, created: {userId,address,relays}|null,
                     relayWarning?: "<host>"}   (the created identity's only relay is the code's)
p2p invites --json  {invites: [{code,label,to,circle,createdAt,exp,status,redeemedBy?,redeemedAt?}]}
```

Positional arguments can follow `--` (`p2p invite --json -- ben`, `p2p join --json -- <code>`).

For `--session S`, `watch` prints:
- events of S itself, and events addressed to S (replies in sessions S spoke to, notify-when-idle);
- other people's session events that no local session has claimed;
- every contact, circle and held event.

The cursor (`<home>/cursors/<sid>.cursor`) advances only after a line reaches stdout. Exit codes: 0 on SIGINT, SIGTERM or a closed reader (EPIPE), and 1 on a fatal error (bad usage, no identity, every relay refusing this device).

## Configuration and state

| | |
|---|---|
| `P2P_HOME` | State directory (default `~/.p2p`). The v3 trust store is in `v3/` and the CLI's documents are in `cli/`. Directories are 0700 and files 0600, written atomically under a cross-process lock, so `watch` and other commands can run at once. |
| `P2P_DEFAULT_RELAYS` / `defaultRelays` in `<home>/config.json` / `defaultRelays` in `defaults.json` beside the CLI | Relays for `setup`, `init`, `join` and `backup restore`, in that order of precedence. None are built into the source. The bundled single-file CLI ships a `defaults.json` (empty in the repository, filled in by a deploy step); `P2P_DEFAULTS_FILE` points at another. |
| `P2P_RELAY_TRANSPORT` / `transport` in config.json | Maps a canonical relay URL to the URL actually dialled, e.g. `{"wss://relay.test/v3":"ws://127.0.0.1:8080/v3"}` for a local relay without TLS. The hello check still compares against the canonical URL. |
| `P2P_DEBUG=1` | Logs every network step on stderr: start, end, duration, and which relay. It shows relay URLs, userIds and frame types, never keys, caps, envelopes, codes or phrases. Send this output when reporting a problem. |
| `P2P_CONNECT_TIMEOUT_MS` (10000), `P2P_REQUEST_TIMEOUT_MS` (15000), `P2P_COMMAND_TIMEOUT_SEC` (60), `P2P_SLOW_MS` (3000) | Bounds, in order: each connection stage (dial, hello, auth) and each HTTP document fetch; each relay request; a whole short command (`--wait` adds to it; time spent at a prompt doesn't count; `watch`, device linking, `setup` and `backup restore` are exempt; 0 turns it off); and how long a step may take before it is announced on stderr. |
| `P2P_EXTENSIONS` / `extensions` in config.json, `P2P_EXTENSION_PATH` | Which extensions are enabled (opt-in; registered namespaces only), and the explicit `node_modules` directories they load from. See [Extensions](#extensions). |
| `P2P_EXTENSION_EXCLUDE` | Directories whose insides never count as extension directories, compared by real path (the Claude mod passes the session's repository). |
| `P2P_WORKDIR` | The directory extension commands treat as yours (the repo an Ix command looks at), for a client that runs `p2p` from elsewhere; an existing absolute path, else the process's own. |
| `P2P_DEVICE_INFO` / `deviceInfo` in config.json | Off by default. On, a key-holding device keeps its caps and version in your identity document (`dinfo`), on relays that list `identity.lenient`. Clients from before protocol 3.1 refuse a document with it, so it stays off until the previous two releases are 3.1 (docs/compatibility.md, step 2). |
| `P2P_DRAIN_QUIET_MS`, `P2P_DRAIN_MAX_MS`, `P2P_DOC_REFRESH_SEC`, `P2P_LINK_POLL_MS` | Timing knobs, mostly for tests. |

**Keys.** Device keys, and the identity key on key holders, are kept in a 0600 file in `<home>/cli`. An OS keychain backend is not wired up yet.

**Forks.** When two key holders publish at once, your document forks (§2.5). The next version this CLI publishes first merges the tips, pairwise for three or more, with the intersection of devices and key holders, `by` this device or else the lowest common key holder. It then re-adds any device a merge dropped that wasn't revoked, so a device linked during a fork isn't lost. It re-adds a device only when this device holds each branch's history back to their common ancestor; otherwise it warns you to link that device again rather than guess. A merge's `by` is nominal (a common key holder): the device that wrote it records it as its own, and a merge adds nothing, so no device's "versions I didn't publish" check alerts on it. If the branches share no key holder, it refuses and recommends rotation.

**Lost key holders.** Revoking a device takes it off your document, and relays refuse its did from then on. But a revoked *key-holding* device still has your identity key, so it can sign new devices and versions. `backup restore` and `devices revoke` warn when that is the case. The only real remedy is identity rotation, `p2p identity rotate` (below).

**Certificates and refused relays.** A relay closes a connection whose device certificate expired with code 4003. `watch` reconnects with the renewed certificate, taken from disk or from your identity document, instead of exiting. When a relay refuses this device, the client refreshes your identity document. If some branch still lists the device (for example it was linked during a fork), it retries with backoff; only when none does is the device treated as revoked. That refresh runs at most once a minute per relay (`P2P_REFUSED_REFRESH_SEC`), so a relay that keeps refusing can't make the client re-fetch your document on every dial.

**Fail-closed publishing.** Every new version of your document is built on the head confirmed on your relays. If the refresh fails or is cut short, nothing is published. A device that is no longer a listed key holder never publishes.

**Terminal safety.** Every line `p2p` prints goes through one sanitizer (no escape sequences, bidi or format characters). JSON output escapes them instead. Relay error codes are repeated only when they match `[a-z-]{1,32}`.

**No silent hangs.**
- Every network step is bounded, and any step that takes more than 3 s says what it is doing, e.g. `p2p: connecting to wss://relay.example/v3 (relay 1/2)…` or `p2p: fetching p2p:…'s identity from https://relay.example…`. A step that runs out of time fails with a message naming the relay and the step.
- A relay that can't be reached at all gets one clear line: `p2p: can't reach wss://… (no response on port 443 after 10s: check your network or firewall)`. That covers a firewall silently dropping the connection, as well as a refusal, no route, or no DNS. For the rest of that command, every later connect or document fetch to that host fails at once, instead of waiting out another timeout each.
- The whole command gives up after 60 s, naming the step it was on.
  - It stops starting new network steps, then waits up to 5 s for what is already in flight to settle before exiting.
  - A `send` cut off this way reports `outcome_unknown` ("it may have been delivered; check before resending"), not a plain failure.
  - `setup` and `backup restore` are exempt (each of their steps is still bounded).
  - Once a restore's new document may have reached a relay (one accepted it, or one never answered), a failure never wipes the home: finish with `p2p identity republish`. Only when every relay refused outright is the fresh home cleaned up.
- Waiting for queued messages, a busy state lock ("is another p2p command running?") and a proof of work are announced too.
- A stdin that never ends (PowerShell, an IDE task) doesn't block a command that didn't ask for it. One that did ask says how to end the input.

**Offline peers and an offline sender.**
- *A session seen recently.* A message to a session that isn't live now (no status in the last 150 s) but posted one in the last 24 hours goes to its device's mailbox anyway: relays keep ciphertext for 7 days, and a recipient accepts an envelope up to 7 days old. A day covers a dropped connection or a laptop asleep overnight; a session silent longer has most likely ended, and is refused as before (`not_found`). Only the fingerprint-verified user's own devices get it, through the same caps as a live send. The sender learns nothing new: `lastSeen` is the session's last status, which its `ls --all` shows anyway.
- *The outbox.* When no relay takes a message (this device's network is down, or every relay of the recipient is unreachable), the sealed envelope is kept in `<home>/cli/outbox.json` (0600, under the state lock, like all state). `watch` sends due ones every 15 s with backoff (15 s doubling, at most 30 min), all of them at once when it starts or a relay comes back, and a send from this device sends due ones first. What is resent is the same sealed envelope, so a copy a relay did take is dropped by the recipient's replay window: no message arrives twice. Before every retry an item is checked again, and dropped as `refused` if the recipient was blocked, is no longer a friend or co-member (or, for one of your own sessions, no longer on its roster), no longer lists the device it was sealed to (their document is refreshed once a round when older than the usual bound; when that refresh fails and the held one is stale, the item waits for a later round instead), or rotated their identity. It goes over the relays of their current document, then the ones it was sealed for, each with a cap of this moment, so a recipient who moved relays still gets it. An item expires after 7 days, early when this session has since sent more than 448 other envelopes (the recipient keeps a 512-seq replay window: queuing one already that far behind is refused with `outbox_window`), and early after an hour in which every attempt was answered with a refusal (`relay-error`, `rate-limited`) while this device's own relays worked; timeouts and unreachable relays are an outage, which keeps the 7 days. A recipient gets at most 1/20 of the outbox (10 messages and about 205 KiB), half that while the outbox is more than half full; 200 and 4 MiB in all; past that the send fails (`outbox_full`) rather than dropping another, and a retry round stops at a recipient's first failure, so one recipient can't hold the outbox. Delivered, expired and refused items leave a `p2p.outbox` event (`state`, the recipient, `queuedAt`) for the session that wrote them.
- *On the recipient's side.* A session that reconnects with the same id resumes from its watch's cursor, so it prints whatever arrived for it while it was away. A message for a session of this device that isn't running (its `watch` is gone: `/exit`, or a new session after `/clear`; see `<home>/cursors/<sid>.watch`) is also logged as a `p2p.message` for no session (with `unclaimedFor: <sid>`): the user's other sessions show it, under the same hold and screen rules as any message for no session, and the ended one never shows the copy. The mod sends no delivery notice for such a copy (declined or expired: it would tell the sender that session ended), and no session that is private sends delivery notices at all.

**Newer peers (protocol 3.1, docs/compatibility.md).** Fields this version doesn't know are ignored, unless their object lists them in `crit` (then it is refused). An envelope of a kind it doesn't know is verified, admitted to the replay window and logged, and the session it was for gets one `p2p.unknown` event (`envKind`, the sender) per sender and kind a day (at most 3 a day per sender), when the sender is a friend, a circle-mate or your own device. It never sends a peer anything defined after 3.0 that the peer hasn't advertised (its live status caps, or its device's `dinfo`). Statuses advertise `proto.3.1` (never the exact client version: a status reaches a whole audience, and the version would help single out a device; it rides only in the opt-in `dinfo`), and `ls --json` rows carry each session's `did` and `proto`. Only an unknown kind from your own device, a friend (not unfriended) or a circle-mate is logged (once per sender and kind an hour) or keeps the sender's device certificate.

**Daemon-free.** Each command opens the stores, connects only if it needs to, handles whatever the relays had queued for this device, does its work and exits. Only `watch` stays running. Events are written to a shared log that `watch` prints from, so a message that `p2p ls` happens to pick up still reaches the session's watcher.

## Identity rotation

`p2p identity rotate`, on a key-holding device you still have, moves your identity to a new key (§2.8). It keeps your friends able to verify you at every step:

0. **The plan.** A new identity key is made (nothing is published yet), and you see its fingerprint and the devices that would follow. Drop a lost or stolen device with `--exclude <did>`: it is revoked on the old identity before any link code goes out. A device not listed by a version this device published itself, or not seen in 30 days, is dropped by default and shown with why (its label marked unverified when it came from a version you didn't publish); `--keep <did>` lets it follow anyway. The plan also counts the friends that get your new identity's invite: only friendships whose side of yours was signed by this device or a device that stays in the plan (and, rotating normally, that verify now). Any other one, which a thief's device may have planted, is listed and invited only with `--invite <user>`. Accept interactively, or review with `--plan` and accept with `--resume --yes [--exclude <did>]…`; `--cancel` drops a plan that wasn't accepted. Nothing goes further without that acceptance.
1. A new identity key, and new device keys for this device: rotation re-keys every device, so this device gets a new did.
2. A statement that the old key moved to the new one, signed by both keys.
3. The new identity's first document version, listing only this device, on the same relays. With `--backup-file`, the new key's 24-word phrase goes to a 0600 file (the old phrase no longer restores you).
4. Each of your other devices gets a `sync` from the old identity with the statement and a one-time link code minted by the new identity, for that device alone. It is **held** there, with the new fingerprint and the device that sent it: the device follows only when you say so on it (`p2p identity follow <id>`, or `held approve`). Only a sync from one of your key holders counts, and a key-holding device never follows: it alerts, and offers to contest. The command waits `--wait` seconds (default 600, the code's life) for them. A device that didn't follow in time re-links by hand later: `p2p link start` on a device of the new identity, then `p2p link join <code> --rotated` on it. Devices follow as ordinary devices unless `--keep-keyholders`. A relay holds a few link codes per device at once (4 by default); past that, devices re-link by hand.
5. Every friend gets a fresh invite from the new identity, bound to them, with the statement as proof. Their client holds it as "<you> moved to a new key", and approval needs your old identity's own published final version to carry that same statement (so a statement you never published can't split you from them); approving runs the normal accept and ends the old friendship on their side. In circles you own, the new identity is added, takes ownership by `transfer` (this device holds both keys, so it signs the new owner's consent), and drops the old one. In circles you are a member of, the new identity's join goes to the owner with the statement; the owner's client swaps old for new as a member by itself only once your old final version carries the statement, nothing conflicts, you weren't removed before, and the owner doesn't hold changes (`p2p circle hold`); an admin's rights always wait for the owner's approval. Proofs are re-signed by the new key: the command prints what to put in the gist, or the new DNS TXT record.
6. Last, the old identity publishes its final version, with no devices and the statement in its `rotation` field. It needs a backup of the new key (`--backup-file`) or a key-holding follower first (§2.5): otherwise the command stops with `needs_backup`, resumable. Relays then refuse every old did, and friends who refresh your document (every 10 minutes) see the move with no push.

Then this home becomes the new identity's; the old one is archived in `<home>/rotated/`. Every step is recorded in `<home>/rotation/`, so an interrupted rotation finishes with `p2p identity rotate --resume`; a second rotation can't start meanwhile. Afterwards, `--resend` sends the invite again to friends it didn't reach, at most 50 an hour (or 80% of a relay's advertised per-sender contact limit).

**Security.**
- **A rotation this device didn't publish** (judged by its publish log) raises an alert: a stderr line and a `p2p.alert` watch event. On a key holder, `p2p identity rotate --contest` answers it with a competing rotation (built beside the other final version, so your identity's document carries two), and sends your friends your own: two different rotations from one old identity are a conflict, so their clients apply neither (`held approve` refuses with `rotation_conflict`). They resolve it out of band, with petnames and proofs, and exchange a fresh invite with the real you. A contest drops by default the device that signed the other rotation's final version and every other key holder (any of them could have); `--keep <did>` overrides. Once the other final version is out, relays refuse your old devices, so the contest's final version may not reach them; the invites still make the conflict.
- **An approval that turns out contested.** If you already accepted a friend's move (or your circle swapped them in) and another key then claims the same old identity, the identity you carried over to is suspended at once: no messages, no session access, no circle standing, its caps revoked. You get an alert and a held item; after checking with them out of band, `p2p identity dispute <id> --keep <user>` (or `--neither`) settles it. Your other devices learn the approvals, the suspension and the settlement by `sync`, so each suspends the same identities (they take a settlement from a key holder only). On your key holder, a suspended identity also leaves the circles you own at once (put back if you keep it); elsewhere you are told only a key holder can do that. Once you kept one, a later rotation from the same old identity is held as a new dispute without suspending the one you kept. Another device of yours that reports a dispute is never taken at its word: each device verifies the conflicting statements itself (they come along) and acts only on a conflict it verified; otherwise it notes the report and changes nothing.
- **Known limit: a thief can time a denial of service.** Whoever holds a friend's old key can publish a competing rotation, even one that only sends invites, at any time. Every client that already carried the honest move over then suspends that friend, and on the owner's key holder takes them out of the circles it owns, until the user settles it with `p2p identity dispute <id> --keep <user>`. That is by design: a conflict can't be told apart from a real theft without checking out of band. It costs the thief their stolen key's surprise, not more access. While your own identity is rotating, a friendship synced from another device of yours is taken only if that device is one the plan trusts.
- Rotation can't recover circles whose owner key was compromised: the thief can sign their versions too. Re-create those circles under a new id (§3.3).
- A rotated identity never comes back: nothing may follow its final version, and clients refuse to jump over it. Relays refuse a version on top of it, but don't remember the rotation once they drop the history (a tombstone after 90 expired days, or a replaced unanchored root): someone holding the old identity key could then start a new history there. Clients judge from their own chains, which keep the final version, so that buys nothing against them.

## Extensions

**An extension is code you run with your identity.** When `p2p` loads `@peer2peer/ext-<ns>`, that package executes inside the `p2p` process, with the same access `p2p` has: your `P2P_HOME` (`~/.p2p`), the identity and device keys, the network. `ExtContext` (below) is the API an extension is meant to use; it is **not a sandbox**, and nothing stops a malicious extension from reading your keys. Install and enable only extensions you trust, from a source you trust.

That is why loading is opt-in (`src/extensions.ts`):

- **Which:** only the namespaces registered in docs/protocol.md §8.3 (`ix`, `kartr`), and only those you enabled: `p2p extensions enable ix` (writes `extensions: ["ix"]` to `<home>/config.json`; `p2p extensions disable ix` undoes it), or `P2P_EXTENSIONS=ix` set in your own shell for one environment (`none` turns all off; it overrides config.json; `config` defers to config.json, which is what the Claude mod passes so that only config.json opt-in counts for the `p2p` it runs). Anything else in the list is ignored with a warning. Nothing enabled, nothing loaded, even when a package is installed.
- **Where:** only explicit `node_modules` directories: each `P2P_EXTENSION_PATH` entry (a directory or its `node_modules`), then the CLI's own sibling `node_modules` when the CLI is installed as a package (a global `npm i -g @peer2peer/cli @peer2peer/ext-ix` puts both there). There is no walk-up through parent directories, no `NODE_PATH` and no global folders; the package's entry file must lie inside the package.
- **Announced:** the first time an extension loads from a new location, `p2p` says so on stderr, with the resolved file (`<home>/extension-locations.json` remembers it).
- **How:** the resolved file is loaded with a dynamic `import()` of its URL. That loader is the one computed import `check-boundaries` allows in core (with the committed bundle that inlines it); static and literal-dynamic imports of `@peer2peer/ext-*` stay forbidden, and no core `package.json` may list one.
- **Degrading:** an enabled extension that isn't installed, a bad directory, or a broken or incompatible package is a warning; the rest still load, nothing fails, and its kinds show their fallback.

The contract (`P2PExtension`, exported from `@peer2peer/cli` for extension authors):

| | |
|---|---|
| `api: 1, ns, name, version` | `ns` must match the package name. |
| `receive({kind, v, body, fallback, from, session})` → `{ok: true, rendered, keep?}` or `{ok: false, reason}` | Validates, sanitizes and renders an inbound `x:<ns>.*` body. It must not act on it (protocol §4.3). `rendered` (≤16 KiB, strings re-sanitized) goes into the `p2p.ext` event. `keep` (≤24 KiB) is stored in the local event log only (`watch` never prints `_`-fields) for a later action the user starts. A throw or an oversized digest falls back. |
| `commands: [{name, args?, description, options?, run(ctx, args, opts)}]` | Declared as data; `p2p` builds `p2p <ns> <name>`, adds `--json`, and owns output and exit codes. An error with a `code` keeps it. |

`run` gets an `ExtContext`: `send({fromSession, to, kind, v, body, fallback})` for kinds of its own namespace (through the ordinary §4.2 session path, at most 24 KiB of `{v, body}`, a 1–200 character fallback required), `events()` (the events it rendered, with what it kept), `peers()` / `ownStatus(sid)` (the status table), `audience(sid)` (who an own session's status reaches: its roster's visibility, circle, whether that circle is open, and how many people), `localMac(data)` (a MAC keyed by this device's secret, for settings in the extension's store that only the person running `p2p` may make), `confirm(question, yes?)` (false without a terminal, and always false under `--json` unless `yes`), `interactive` (a person at a terminal), `kv` (a small store at `<home>/ext/<ns>.json`), `env`, `cwd`, `io`. That is the contract a well-behaved extension keeps, and the boundary `p2p` itself enforces for what it does on an extension's behalf (sends only its own kinds, re-sanitizes its digests); it is not isolation. On the protocol side the rule stands regardless: an extension adds information, never authorisation (who may message whom is decided only by keys, friendships, circles and rosters).

## Readings chosen here

These are the places where the spec left room. They are listed so other clients can match them.

- **Circle links carry an owner hint.** `p2p://circle/<b64u(head)>~<b64u({doc, join})>` appends the owner's identity document and current join statement to the spec's link. A stranger needs both to reach the owner at all: the head names only the owner's userId, and `circle` envelopes need a cap. A plain spec link still works when the owner is already reachable.
- **A stranger's `want` gets a contact answer.** The owner answers with a `contact` circle invite `{circle, chain}` when it holds no cap for the asker.
- **Confirming before joining.** The client asks the owner of the offered head (§3.3). It joins the longest chain the answers agree on, and judges the confirmation on *that* head: it asks that head's owner and one other member it lists (preferring people you know). The owner's answer is enough only when that head lists nobody but the owner and you. Otherwise, a join that couldn't be confirmed with a second member needs `--yes` or an interactive yes. Answers are taken only from members the client asked, and the inviter.
- **Transfer consent** (`p2p-circle-accept+jws`) travels to the owner inside a `circle` envelope's `ops`. Core ignores it there, and the CLI stores it for `circle transfer`.
- **Co-member caps** (the cap in a join statement) are used only while both sides are in that circle. Leave and removal notices use them once more, to tell the member. In open circles they last at most 14 days. `watch`, and any inbound circle change, re-sign the join with a fresh cap and revoke the old one, when the owner removed someone or the cap is about to lapse (core `openCircleCapActions`).
- **Bundled identity documents are hints only.** The documents carried in an invite, an accept, a circle link or a sync only say which relays to refresh from. Identities enter the store only through core's `refreshIdentity`. Acting on an invite, or adopting a first-time invitee's accept, goes through `reverifyInviteForApproval` / `reverifyFriendshipForApproval`.
- **Joins and own-device sync.** Joining is the user's explicit act. It is carried to the user's other devices by `sync`, together with friendships, caps, petnames, blocks and circles.
- **Short codes (P4)** carry an ordinary invite, sealed under the code; the relay sees only a hash of the code. There is no non-consuming read of a code (taking it is what makes an interception visible). The inviter's client auto-completes its side on the accept of a code's invite (issuing the code was the consent), and a revoked code's invite is refused even after it was taken. A bare code (no relay part) is looked up on your own relays.
- **`invite --link --uses N`** sets the per-relay use count of the invite's contact cap. An invite still binds to the first person who accepts it.
- **Notify-when-idle** is a local, one-shot subscription. It fires on the target session's next busy → idle status (or an `idle` envelope), and expires after an hour with `reason: "expired"`.
- **Session rosters.** A roster follows the session's projects: private until the person shares the project, never wider than every project the session worked in allows (§6, `projects.ts`). The roster rides in every status the session sends. `status`, `send` and the extension sends bind the session to `P2P_WORKDIR` (else the current directory), `P2P_PROJECT_DIRS` and `--project-dir`; sends to anyone outside the projects' audience are refused (`not_shared`), and session `tui` (`p2p tui`, `p2p send` typed with no `--from-session`) is the person's own and only usable from a terminal.
- **Rotation (§2.8).** The sync to a following device is `{rotation: {statement, link, keyholder?}}`, held there for the user (its secret link code kept apart from the listed item); the link code takes the place of the §2.4 compare code, because it travelled only inside an end-to-end encrypted sync to that one device, so the rotating device certifies the request whose MAC verifies. A friend's rotation invite from someone who was never a friend of the old identity is held as an ordinary invite. Rotations seen (from contacts, bundles and documents) are recorded per old identity, bounded, for conflict detection. `p2p circle hold <cid> on` is the §3.3 hold-for-approval policy, local to the owner's devices: it holds admins' proposals and rotated members.

## Terminal UI

`p2p tui` is Peer2Peer in one terminal window, for when no agent is open, or to check on things at a glance. It runs in macOS Terminal, Linux terminals and Windows Terminal, needs nothing beyond the CLI, and uses colour unless `NO_COLOR` is set.

```text
 Peer2Peer  1 People  2 Held (1)  3 Messages  4 Send  5 Health
────────────────────────────────────────────────────────────────────────────────
● ann@k7qm-3xpd-9twa-hf2n  you
  ● [a1b2c3] api busy  shop@fix/login  20s ago
      Fixing the login redirect
      files: src/auth/session.ts, src/auth/redirect.ts
      ↳ a1 Explore "find every caller of redirectTo" (running)
● ben@ab12-cd34-ef56-gh78  friend · circle team
  ○ [d4e5f6] web idle  shop@main  1m ago
      Reviewing the checkout PR
      files: web/checkout.tsx
○ cleo@zz99-yy88-xx77-ww66  circle team
  · [0a0b0c] docs offline  2h ago




 ↑↓ move · m message · d doctor · 1-5 screens · ? help · q quit
```

| Screen | What it shows, and the keys |
|---|---|
| **1 People** | Friends and circle-mates with a live (●) or offline (○) dot, their sessions with label, `[ref]`, state, the one-line status, repo and branch, edited files, and each session's subagents nested under it. `m` (or Enter) messages the person or session; `d` runs the doctor for them. |
| **2 Held** | First contacts, circle invites and join requests (`p2p held`), and messages your Codex sessions hold (`p2p codex held`). `a` accepts or delivers and `x` declines, each after a confirm (a Codex release asks for the code its window shows instead). `t` is *Always deliver from …* for a held message: it shows the sender's fingerprint, and you type its first four characters to confirm (a `y` or a paste doesn't count). The message is released first, and the trust (`p2p trust add`) is saved only once that went through. Messages the Claude Code mod holds live in Claude Code (its `/peers` panel), where the CLI can't see them: the screen says so instead of listing them. |
| **3 Messages** | Recent messages received and sent: delivery receipts as they come back (`shown`, `held`, `declined`, `expired`, `ended`), and messages waiting at the relays for an offline session or in this device's outbox, with when the session was last seen. Enter opens a message; `r` replies. The TUI sends no receipts: its session is private (no status, no roster), so senders don't ask it for any, and a `shown` would only tell them that it exists and when you read it. At most the 100 newest messages are kept in memory. |
| **4 Send** | Pick a session or a person, type, Enter: the same path as `p2p send`, from the TUI's own session (`tui`, or `--session`). Replies come back to it live. |
| **5 Health** | Each relay up or down, with what its `/.well-known/p2p-relay.json` says (open or members-only, software, proof-of-work), and the doctor's checks (identity, document expiry, clock, sharing). `r` runs the doctor again. |

```text
 Peer2Peer  1 People  2 Held (1)  3 Messages  4 Send  5 Health
────────────────────────────────────────────────────────────────────────────────
Relays
  ● wss://relay.example.org/v3  connected  members-only  @peer2peer/relay 0.1.0

Doctor: this device  3 ✓ 0 ✗ 0 ?  (30s ago)
  ✓ identity: ann@k7qm-3xpd-9twa-hf2n, document expires in 21 days
  ✓ clock: within 1 s of the relays
  ✓ relays: 1 of 1 relay reachable


 r run doctor · d on People: one person · 1-5 screens · ? help · q quit
```

- **Live.** The TUI runs the same event stream as `p2p watch`, in-process: deliveries, statuses and held items appear as they arrive. Nothing polls the network.
- **Only on your key press.** Loading changes nothing; accepting, declining, trusting and sending happen only when you press the key. Pasted text (bracketed paste) is typed only into a message or a prompt: it never acts as keys, and never answers a confirmation. Keys within 150 ms after a paste ends count as pasted too, so a paste that carries its own end marker can't press anything; a paste whose end never arrives ends after a second of quiet, and Ctrl-C always quits, even mid-paste. `q` or Ctrl-C quits, and the terminal is restored on quit, on errors and on SIGTERM.
- **Interactive only.** It refuses to start unless stdin and stdout are a terminal, and inside an agent's tool call (Claude Code and Codex). The Claude Code mod's command guard refuses `p2p tui` from the model's shell too, including under `script`, `expect`, `unbuffer`, `socat`, `tmux` and Python's `pty`; like every guard there it is best effort, a backstop and not a sandbox. For scripts, use `ls`, `held`, `watch --jsonl`.
- **Peer text can't drive your terminal.** Every name, label, status, file path, message and kind a peer sends is cleaned before it is drawn: escape sequences (including OSC 8 links and title changes), control characters, bidi overrides and zero-width characters are removed, and long text is cut to fit.

## Doctor

`p2p doctor` answers "they say they're online, so why can't I see them?". Each check prints ✓ (fine), ✗ (a problem, with a one-line fix) or ? (unknown, with what would tell):

```
p2p doctor: can you see ben@ze26-wjlq-5yzp-hga6?

✓ this device: identity, relays and clock look fine
✓ friendship: friends since 2026-10-22; you also share "ix-team"
✓ their identity document: version 1, fresh (expires in 29 days); fetched just now
✓ relays: they list wss://relay.example/v3; you share wss://relay.example/v3, reachable from here
✓ your capability for them: you can reach their mailbox on wss://relay.example/v3
✓ their capability for you: you gave them one for wss://relay.example/v3 (good for 89 days)
✓ last heard from them: 1s ago
✓ blocks and holds: not blocked, suspended or held
✗ their sessions: no status from any of their sessions has reached you.
    fix: they haven't shared any session with "ix-team": ask them to run `/peers circle c_…` in their session (or `/peers add ann@…`)
```

Without a user, it checks this device:
- the identity, and whether its document is fresh, past its soft expiry (peers warn) or its hard expiry (peers refuse everything);
- each relay: reachable, with latency, whether this device signs in and its mailbox answers, how many envelopes are queued for it, and whether your current document is published there;
- the clock against the relays' (things signed more than 5 minutes off are refused);
- the default circle and whether you stand in it (with none, new sessions are private);
- which live sessions are shared, and with whom; when this device last posted a status (the mod does every 60 s) and when a `watch` last moved its cursor. Where nothing local says, it answers `?`;
- the CLI's version against the one the Claude mod bundles (found from `P2P_MOD_ROOT`, which the mod sets, or the plugin folder around a bundled `p2p.mjs`).

With `<user>` (an address, petname, name or userId), it checks whether you can see them: friendship or the circles you both stand in; their identity document, fetched now and fresh; the relays they list and whether you share one you reach; whether you hold a capability for their relays and they hold one from you for yours (as far as this device's records tell); when anything last arrived from them; whether they're blocked, suspended (a contested key move) or held; and whether the sessions they shared include you, and are live. It then lists each of their devices with its protocol minor (and exact client version only when the device publishes one in `dinfo`) and the caps it advertises (from its identity document entry, else its latest status), and the features unavailable between you, in words, never as a failure (docs/compatibility.md); `--json` adds `devices` and `unavailable`.

It's read-only: it publishes nothing, sends nothing, never acks what's queued, and leaves `P2P_HOME` byte-for-byte as it found it. What it refreshes (a friend's document, say) lands in an in-memory overlay that is gone when it exits, so a step that times out and finishes late can't write either. It loads no extension (loading one runs its code and records where it came from). Its bounds, with T = `P2P_DOCTOR_TIMEOUT_MS` (default 5000, never more than `P2P_CONNECT_TIMEOUT_MS`): each relay probe takes at most 2T (the whole connect, then one round trip; relays are probed in parallel, beside one HTTP request of at most T), the friend's document refresh at most 2T, and each local step at most T. It contacts at most 5 of a peer's relays, whatever their (possibly forked) document lists, and keeps no answer body from them. The usual command deadline (`P2P_COMMAND_TIMEOUT_SEC`, 60 s) caps the whole run, so an unreachable relay costs seconds, not a hang. The output never holds keys, capabilities, certificates, invite or link codes, or envelopes. In `--json`, `checks[]` has `{id, status: "ok"|"fail"|"unknown", title, detail, fix?}` and `summary` counts them; the exit code is 0 whatever the checks say. In Claude Code, `/peers doctor [user]` runs it.

## Windows

The CLI runs on Windows 10/11 with Node 22 (PowerShell, cmd or Windows Terminal; `npm link` installs `p2p.cmd` and `p2p.ps1` shims). Things to know:
- **Home:** `%USERPROFILE%\.p2p`, or `P2P_HOME`. Unix file modes (0700/0600) are best effort there; the files sit in your profile directory.
- **Prompts** need a real console. Under Git Bash's mintty, `process.stdin.isTTY` is false, so prompting commands ask for their flags instead (`--yes`, `--expect-compare`). Use Windows Terminal, or `winpty p2p …`.
- **Someone isn't showing up** (or you aren't, for them): run `p2p doctor <them>` on your side and ask them to run `p2p doctor <you>` on theirs. It checks the clock too, a common culprit on Windows machines that don't sync time.
- **Stuck commands** shouldn't happen any more (see "No silent hangs"). If one seems stuck, run it again with `$env:P2P_DEBUG=1` (PowerShell) or `set P2P_DEBUG=1` (cmd) and send the output.
- **State lock:** if a killed command left `<home>\cli\.lock` behind and its process id was reused, commands report "is locked" after 10 s. Delete the file when no `p2p` is running.

Running the tests on Windows (CI-style; there is no Windows runner yet), in PowerShell from the repository root:

```powershell
cd packages\core;  npm ci; npm run build
cd ..\relay;      npm ci; npm run build
cd ..\p2p;        npm ci; npm run typecheck; npm run lint; npm test
```

The suites start relays on 127.0.0.1 with ephemeral ports and use temporary `P2P_HOME`s, so they need no admin rights. `hangs.test.ts` simulates the Windows-flavoured failure modes: a relay that never says hello, an HTTP API that never answers, a stdin that never ends, and a state lock held by a live process.

## Develop

```sh
(cd ../core && npm ci && npm run build)
(cd ../relay && npm ci && npm run build)    # the integration tests start real relays in-process
npm ci && npm run typecheck && npm run lint && npm test && npm run build
node ../../scripts/check-boundaries.mjs
npm run bundle          # rebuilds ../../mods/claude/peer2peer/bin/p2p.mjs (commit it)
npm run bundle:check    # fails unless the committed file is byte-for-byte a fresh build (CI runs it)
../../scripts/check-bundle.sh   # rebuilds core, then the check above, plus defaults.json is the empty list
```

**Reviewers:** CI (started by a maintainer before merging) runs `scripts/check-bundle.sh`; it fails when the committed bundle isn't exactly what the sources build. Run it locally before pushing a change to `packages/p2p`, `packages/core` or `mods/claude/peer2peer/bin` (it also works as a pre-commit hook: `ln -s ../../scripts/check-bundle.sh .git/hooks/pre-commit`). `defaults.json` stays `{"defaultRelays": []}` in the repository; a deploy step writes the team relay into the deployed copy, and only a reviewed PR may change the committed file.

**The bundled CLI.** `mods/claude/peer2peer/bin/p2p.mjs` is the whole CLI in one self-contained, unminified ESM file (esbuild, pinned), run with `node p2p.mjs …`. It is committed, and anyone can verify it: `npm run bundle:check` rebuilds it from the sources and compares the bytes. Beside it, `defaults.json` (`{"defaultRelays": []}`) holds the default relays; the repository's copy is empty, and a deploy step writes the team relay into it.

The integration tests (`src/__tests__/e2e.test.ts`, `flows.test.ts`) drive three users, each in a separate temp `P2P_HOME`, through the full social flow over two real relays. One of the relays is killed partway through.
