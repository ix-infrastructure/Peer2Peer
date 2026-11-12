# Changelog

All five npm packages (`@peer2peer/core`, `relay`, `codex-bridge`, `cli` and `ext-ix`) and the Claude Code mod are released together and always carry the same version. [docs/releasing.md](docs/releasing.md) describes how a release is made.

## Unreleased

### Behaviour changes

- **Ix is optional and recommended; Peer2Peer never installs it for you.**
  - `p2p setup`, run by you at a terminal, explains in a few lines what Ix adds (overlap with peers' sessions, a change's blast radius, local graph memory; all local) when it isn't installed, and asks `Install Ix? [y/N]`. The default is No. A yes prints the install command for your platform, for you to run in your own terminal, then `p2p setup --ix` turns on the Ix extension. Peer2Peer never runs an installer.
  - A no is remembered (`"ixDeclined": true` in config.json) and setup doesn't ask again. `p2p setup --ix` asks again.
  - Setup never offers Ix with `--json`, with `CI` set, without a terminal, or inside an agent's session. (Turning on the Ix extension when Ix is already installed still asks for your `yes` on the terminal, as before, even with `--json`.) `p2p setup --json` reports `ix.installed`, `ix.recommended` and `ix.install` (the command to run) instead. `p2p extensions --json` reports the same under `ix`.
  - The Claude Code mod (beside the first prompt you type) and the Codex bridge (at session start) tell the agent once per session, when Ix isn't installed and you haven't said no, that Ix is optional, that it may suggest Ix to you once, and that it must never install Ix itself.
  - In Claude Code, an agent's shell command that installs Ix (the Ix install scripts, its Homebrew tap or formula, or a global npm install of the Ix CLI package) goes to your permission prompt, even in a mode or under rules that would allow it. Where nobody can be asked, it is refused. A URL counts only in a segment that fetches it (curl, wget, irm, iwr, Invoke-WebRequest, Invoke-RestMethod), so reading or searching for it doesn't ask. Other commands are unaffected.
  - Enabling the Ix extension is still yours alone, as before: the front end's token or your `yes` on the terminal, never from inside an agent's session. `p2p doctor` says Ix is optional and shows the install command.

### Security

- **Identity refreshes: what the newest version revokes applies even when a refresh is cut short.** On slow hardware, a refresh far behind can end incomplete after committing an older version that still lists a device the newest version removed. That device is no longer trusted meanwhile: the newest version is kept as a pending head, and until the stored head reaches it, only the devices and key holders it lists too are trusted. Nothing is denied for good. ([#35](https://github.com/ix-infrastructure/Peer2Peer/issues/35))
- **A genuine history gap is reported as one.** A refresh is cut short by a gap only when a relay held the missing version but it wasn't checked in time. A relay answering with junk no longer turns a real gap (pruned history) into "cut short, try again" on every refresh. An honest relay that runs out of time or allowance still counts as holding the version, so no relay can turn another's slowness into a broken chain. ([#35](https://github.com/ix-infrastructure/Peer2Peer/issues/35))

## 0.1.1

Nothing changes on the wire. 0.1.1 and 0.1.0 clients interoperate in both directions. The cross-version matrix ([docs/compatibility.md](docs/compatibility.md)) checks this against v0.1.0 and 70b86c7, as committed at their tags and as npm installs them.

### Upgrade together

- **Update `@peer2peer/cli` and `@peer2peer/ext-ix` together.** The 0.1.1 CLI won't load an `ix` extension unless it declares the graph-target contract (`graphTargets: 1`), and ext-ix 0.1.0 doesn't. With 0.1.1 CLI and 0.1.0 ext-ix, the `ix` namespace is refused with "update @peer2peer/ext-ix". ext-ix 0.1.1's optional peer range on the CLI is `^0.1.1`. Run `npm i -g @peer2peer/cli@0.1.1 @peer2peer/ext-ix@0.1.1`. The Claude Code mod already ships matching copies of both.
- Graph memory needs both at 0.1.1: the 0.1.1 CLI's `p2p watch` drives it and ext-ix 0.1.1 writes it. An older CLI never asks for it.
- Each package depends on exactly `0.1.1` of the others. `@peer2peer/core` has no code changes since 0.1.0.

### Behaviour changes

- **Your own sessions' messages can be held.** In a session that approves its own tool calls (or whose mode is unknown), a message from one of your own **agent** sessions now waits for Deliver, as a peer's does. A peer could otherwise tell one of your agents what to send to another. A message you typed in your own terminal (`p2p tui`, `p2p send`) is still delivered.
  - Messages from **your other devices** are held in such sessions too. Another device can't yet say whether you typed the message or an agent sent it; [RFC #48](https://github.com/ix-infrastructure/Peer2Peer/issues/48) proposes the wire field for that.
  - To turn the hold off, run `p2p own-agents deliver` yourself, in your own terminal; it is refused inside an agent's session. `p2p own-agents deliver --devices <did…>` or `--devices all-other` lets through only your other devices' sessions (agents included), never this device's agents. `p2p own-agents hold` turns the hold back on. The Claude mod and the Codex bridge read the setting when a message arrives, so a change applies at once.
  - Your own sessions are now turn-capped: at most 30 turns per 10 minutes in a session, and at most 10 since you last typed a prompt there. In Codex, your other devices' sessions keep their cap of 5 per 10 minutes. Past a cap, messages are held until you release them: Deliver in the Claude mod, `p2p codex release <id>` in your own terminal for Codex (`p2p codex held` lists them). A sender that asked for receipts gets `held`. Before, the Claude mod didn't cap your own sessions at all.
- **A session goes private when it changes to a folder that can't be placed.** Front ends now read the folders a command moves to: `cd`, `pushd`, `chdir`, `git -C`/`--git-dir`/`--work-tree`, `make -C`, `tar -C`, `ninja -C`, `env -C` and `sudo -D`. Each target is bound as part of the session's projects. A target that can't be resolved, such as `cd -`, `cd $X`, `cd ~other`, `pushd +1` or a bare `pushd`, makes the session private with the reason `unresolved`, and so does an unknown variable at the start of a path. More than 32 such folders in one command makes it private with the reason `folders`. The CLI now gives each cause its own explanation (`projects`, `folders`, `unresolved`, `front`, `constraints`). For a cause that lasts until the session ends, it says to start a new session instead of suggesting you share the project.
- **`p2p ix import` and `p2p ix note --ix-note` use only the open-source `ix note`, against your local graph.** In 0.1.0 they ran whatever `ix note` answered, which was Ix Pro's: it reads and writes your Ix cloud org.
  - They now run only when the `ix` that answers has the open-source `ix note` and `ix session` (Ix after 0.13.0, without Ix Pro), which `ix --help` shows. With Ix Pro installed, or with an older Ix, they are refused with `graph_target` before anything is read or written, and the message says which (with an older Ix, upgrade).
  - Every graph target is local until shared graph memory lands. Against a shared target, every `ix note` and `ix session` call is refused.
  - Against a local target, ext-ix runs `--help`, `--version`, `impact`, `around`, `overview`, `inventory`, `context`, `subsystems` and `status`, and only its own exact forms of `ix note` and `ix session`: show a note by id or a session by name or id, write a note with its text on stdin, and create a `p2p-<session id>` session record. Any other form is refused with `graph_target`.
  - Before either command, the local endpoint's port must be held by your own process (see graph memory below), or it fails with `ix_listener`. A write whose stderr doesn't confirm it went to the local endpoint fails with `ix_unconfirmed`.
  - `p2p ix import` still needs your consent for exactly the note shown. The note is written with a first line `Shared by <address> over Peer2Peer`.
  - `--ix-note` refuses a graph-memory record of another session unless that session's context may go where this one's does: both sessions in shared projects, everyone the sending session reaches also reached by the recorded one, and the same graph target. A record whose session can't be told is refused too.
  - Plain `p2p ix note` messages to peers (`x:ix.note`) are unaffected.
- **`ix` runs with a pinned endpoint and a minimal environment.** ext-ix takes Ix's endpoint only from p2p's graph target, which is the loopback `ixEndpoint` in `config.json` or the default `http://localhost:8090`, never `IX_ENDPOINT` from the environment. It runs `ix` with an allowlisted environment, so the caller's `IX_ENDPOINT`, `IX_PAT`, `IX_ORG`, `P2P_*`, `NODE_OPTIONS` and proxy settings don't reach it, and background map refresh and update checks are off.
- **A same-device send to yourself is refused with `self_send`.** Before, `--to <you>/<own sid>` was `not_found`.

### New

- **`p2p history`**: messages this device sent and received, kept only on this device. They're encrypted at rest with ChaCha20-Poly1305 under a key of their own (`cli/history.key`, 0600), kept for 30 days up to 8 MiB by default, and sent to no relay or peer. The key is stored next to the data in your home folder, so the encryption protects copies of the history files (backups, sync), not against anyone who can read your account.
  - Options: `--session <sid>` or `--inbox`, `--peer`, `--circle`, `--since 30m|12h|7d|<date>`, `--limit`, `--clear` and `--json`.
  - The full history and the inbox belong to the person: they need the front end's token or your `yes` on the terminal, and are refused inside an agent's session. A session sees only its own history.
  - Settings: `history.enabled`, `history.retentionDays` and `history.maxBytes` in `config.json`. `P2P_HISTORY=0` stops recording.
  - The TUI's Messages screen merges in the history (`h` toggles the inbox only). The Codex bridge has a `p2p_history` tool, and the Claude mod has `/peers history [inbox|here]` and `/peers inbox`.
- **Send to another session on the same device.** `p2p send --to "<you> [ref]"` or `--to <you>/<sid>`, the mod's `SendMessage` and the bridge's `p2p_send` now reach another session of yours on this device when it is named. A bare `--to <you>` still means your other devices. The message goes through your relay sealed to this device, under the same rules as your other devices. Delivery receipts and `--notify-when-idle` work for these sends.
- **Shares that cover subfolders: `p2p project share --subfolders`** (and `/peers project share --subfolders`). A shared non-git folder can cover the folders below it.
  - Coverage is opt-in, so existing shares stay exact.
  - A covered subfolder never crosses a git repository (bare ones included) or a `.p2p-private` marker while its `.git` or marker is there, nor a folder with its own policy.
  - `--subfolders` is refused for `/`, your home folder and the folders above it, the temp folders and the system's top folders, and ignored with a warning on a git repository.
  - At share time it warns about nested repositories and `.p2p-private` folders.
- **`p2p session show <sid>`** (and `/peers session`, typed only): a session's bound projects, who it reaches, every reason it is private, and what to do. It is refused inside an agent's session without the front end's token.
- **Graph memory: your sessions in your local Ix graph** ([#53](https://github.com/ix-infrastructure/Peer2Peer/pull/53), [docs/concepts.md](docs/concepts.md)). With the `ix` extension enabled and an Ix that has the open-source `ix note` (Ix after 0.13.0, without Ix Pro), `p2p watch` records this device's own sessions into your local Ix graph as they run. The Claude mod runs `p2p watch` for each session, so it records them too.
  - **Only sessions in shared projects.** A session whose project ceiling isn't shared (a private or unmapped project, `.p2p-private`, not bound yet) is never recorded, and one that becomes private stops being recorded. Peers' statuses and your other devices' sessions are never recorded.
  - **What it writes**, through the open-source `ix note` and `ix session`: an Ix session record `p2p-<session id>` with the session's label, repository and branch, and a note for its start, each new status line, the repo-relative files it edits, and its end. Every note is tagged `finding` and starts with "Recorded by Peer2Peer (agent-generated, untrusted)". File names with whitespace or control characters, or longer than 200 characters, are left out. Message bodies are never written, and a note a peer shares goes in only when you import it with `p2p ix import`.
  - **Off the hook path, best effort.** `p2p status` runs no Ix. `p2p watch` reads the statuses the session already posted every 5 seconds and queues what changed; at most 64 items wait, and past that new items are dropped. A session's end is written by the next `p2p watch` running on this device. Every dropped item is counted by reason in `p2p doctor`.
  - **Local only.** Each batch must have a local graph target, or it is dropped as `not_local` and never handed to ext-ix, and ext-ix checks the target again. Each write must print on stderr that it went to the local endpoint, or it is skipped as `ix_unconfirmed` and writing stops. With Ix Pro installed (its `ix note` writes to your cloud org) or an older Ix, nothing is written and the doctor says why.
  - **Only to your own backend.** Before writing, ext-ix checks that every listener on the local endpoint's loopback or wildcard port is your own process (Linux: `/proc/net/tcp`; macOS: `netstat` and `lsof`; on other platforms the check can't tell, so nothing is written). A root-owned listener is refused unless you set `"ixTrustRootListener": true` in config.json by hand: Docker's port proxy on Linux runs as root, so set it only if that Docker is yours alone. Otherwise nothing is written (`ix_listener`) and the doctor says what to do. On a machine other people log in to, turn graph memory off.
  - **Turning it off:** `"ixMemory": false` in config.json, or `P2P_IX_MEMORY=0`. The environment can only turn it off.
  - Ix's `-` shorthand (the last note or session shown or created) may name a Peer2Peer record after a background write, instead of your own last note.
- **Ix is on by default, and `p2p doctor` has an Ix section.**
  - `p2p setup` on a new install enables the `ix` extension when both the Ix CLI and `@peer2peer/ext-ix` are found, and otherwise says how to get them. Setup installs nothing. Only you can enable it: with the front end's token or your `yes` on the terminal, never from inside an agent's session.
  - An existing install never changes silently. It gets a one-time notice at a terminal instead.
  - The doctor's Ix section shows the Ix binary and version, whether the extension is enabled, the local backend's health, whether the project here is mapped, and each project's graph target. With Ix installed and the extension on, it also shows whether graph memory is on or off and why, how many items were written and queued, how many were dropped and why, why writing last stopped, and whether `ixTrustRootListener` is set. None of these is a failure. Without Ix, nothing in that section is a failure.
  - `p2p project show|ls` print each project's graph target (`graph: local only (http://localhost:8090)`).

### Fixes

- Project boundaries bind less noise, so sessions go private by mistake less often:
  - `/dev/null` and other device or pseudo files are no longer projects.
  - The scripts of `sed`, `jq`, `awk`, `perl -e`, `python -c`, `sh -c` and similar commands are no longer read as paths, while the absolute and relative paths written inside them now bind.
  - `$HOME`, `$PWD` and `$CLAUDE_JOB_DIR` are expanded when the front end knows their real value.
  - Paths are sent as written, so `git -C /src/secret.repo` binds `/src/secret.repo`, not `/src`.
- Every check stays fail-closed, and each case found in the [#45](https://github.com/ix-infrastructure/Peer2Peer/issues/45) review is closed and tested ([#49](https://github.com/ix-infrastructure/Peer2Peer/pull/49)); remaining gaps are tracked in [#51](https://github.com/ix-infrastructure/Peer2Peer/issues/51).

### Release process

- The cross-version matrix runs on every pull request and in the release workflow, against the previous two release tags from git and from npm ([#36](https://github.com/ix-infrastructure/Peer2Peer/pull/36)).
- The relay install scripts are pinned to the v0.1.0 source tarball ([#39](https://github.com/ix-infrastructure/Peer2Peer/pull/39)). They move to v0.1.1 in a follow-up after this release, once its `SHA256SUMS` exists.

## 0.1.0

The first npm release. These notes were added after it shipped, because the release itself carried only the generated text.

- **Invite codes and `p2p remove`.** A code records which circles its redemption actually put the redeemer in, and `p2p remove` takes the redeemer out of only those, never out of a circle they were already in. Codes redeemed before invite links shipped have no such record. For them, `p2p remove` falls back to undoing every circle the code named.
- **Invite codes on private relays.** A code or link whose relay host is, or resolves to, a loopback, link-local or private address is refused unless the redeemer passes `p2p join --allow-private-relay` (or sets `P2P_ALLOW_PRIVATE_RELAY=1`).
  - The same applies to a code whose inviter's relays are such relays, to pasted long invite links (`p2p accept`) and to circle links (`p2p circle join`) that name one.
  - Held invites and rotations from friends on such relays are approved as before. A relay that is already one of yours (a team's Tailscale or LAN relay) never needs the flag.
  - In Claude Code: `/peers join --allow-private-relay <code>`.
