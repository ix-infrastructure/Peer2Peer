# peer2peer

Claude Code's cross-session messaging, between your sessions and your friends' and circle-mates' sessions on other machines, over the account-free [Peer2Peer v3](../../../docs/protocol.md) network. There is no account and no login. Messages and statuses are end-to-end encrypted and travel over open relays that only ever see ciphertext.

On one machine, Claude sessions already reach each other: `ListAgents` lists them and `SendMessage` delivers to them. With this mod, the same two tools reach live sessions on other machines:

- **ListAgents** gains a "Peer2Peer" section, in three groups:
  - "Your other sessions" (your other devices);
  - one group per circle you are in;
  - "Friends".

  Each live session is listed by its address, `p2p:<name>@<fingerprint>/<label> [ref]`, with its status (idle or busy), repo, branch and what it says it is working on. Names aren't unique, so the address always carries the 16-character fingerprint. A petname you set with `p2p petname` is shown in place of the person's own name.
- **SendMessage** to a `p2p:` address (or a `name@fingerprint` address) goes over Peer2Peer. A bare name such as `ben` or `main` is left to the built-in, for local agents only. It never falls back to a remote session, because anyone can choose their own name.
- **Incoming messages** arrive framed as `<cross-session-message from="p2p:...">`. They reach the model at its next tool round while a turn runs, or start a turn when the session is idle. To reply, copy `from` as `to`.
- **`notify_when_idle`** works across machines. One `[Cross-session idle notice]` arrives when the peer next goes idle or exits.
- **Held items** wait above the prompt with buttons:
  - A **first contact** (a friend invite) and a **circle invite** wait for **Accept** or **Decline**, which run `p2p held approve` or `p2p held decline`. The mod never approves anything by itself.
  - A friend who **moved to a new key** (§2.8) waits the same way, as "<old address> moved to a new key (<new address>)". Accept makes you friends under the new key and ends the old friendship; in a circle you own, Accept lets the new key take the old one's place. When more than one new key claims the same old identity, the row says **CONFLICT** and Accept is refused: someone may hold their old key, so check with them another way (petnames, proofs). An admin's rights never move by themselves: a separate row asks you.
  - **A move you accepted, now contested** by another key claiming the same person: the identity you accepted is suspended at once (no messages, no session access, no circle standing) and the row says **CONTESTED**, with **Keep <address>** for each claimant and **Neither**. Check with them another way first.
  - **Your own identity moving** to a new key, started by one of your key holders, waits the same way and names the new fingerprint and that device. Accept only if you started it: Accept runs `p2p held approve`, which moves this device to the new key. Nothing moves by itself.
  - **Who may start work in this session** depends only on this session's own permission mode. Nothing a peer claims counts.
    - **default** or **plan:** you approve every tool call, so messages from friends and circle-mates are delivered.
    - **bypassPermissions, acceptEdits, auto, dontAsk, or an unknown mode:** the session approves tool calls by itself, so every message from another person waits for **Deliver** or **Decline**.
      - The exception is anyone you **trust**. A held message has an **Always deliver from <name> (<fingerprint>)** button next to Deliver and Decline: it asks you to confirm (naming the fingerprint and the full userId), then trusts them and delivers that message. `/peers trust <p2p:… or name@fingerprint>` does the same from the prompt, `/peers trust circle <name>` trusts a circle's members: that is anyone its owner or admins add, now or later (judged when each message arrives, from the circle's verified state, so someone removed from it is held again). An open circle admits anyone who asks, so it can't be trusted, and a trusted circle that turns open trusts nobody until it is invite-only again, `/peers untrust …` undoes it, and `/peers trust` lists who is trusted. Trust is stored by full userId in p2p's config (`p2p trust`, 0600). A blocked user is never trusted.
      - Trust only skips the hold: a trusted person's message is still framed as their data, never as your instructions. Only you add trust, by a press or a `/peers trust` typed at your own terminal: the model's `/peers trust` and its own `p2p trust` changes are refused, and so is one that arrives over Remote Control (the engine can't attest that it is your hand). The model's shell is kept away from p2p's `config.json` (where trust is stored) on a best-effort basis only: the guard reads each command it sees, and a determined agent with shell access could still find a way around it, so in an auto mode trust only the people you would let drive the session anyway.
      - Anyone you list in `P2P_AUTO_DELIVER`, comma-separated, counts as trusted too. An entry must be a full userId (`p2p:…`) or `name@fingerprint`, which counts by its 16-character fingerprint, checked against the sender's full userId.
      - A bare name or a petname is ignored, with one warning. Names are self-chosen, so anyone could call themselves `morgan`.
    - The mode is read live: a turn the mod starts for peers is checked again when it begins, and queued messages are checked again at each tool round. Until you have typed a prompt in this session, it counts as auto-approving.
      - Matching is by full userId only, never by a name.
    - Messages from your own devices are always delivered.
    - The mode is never published in a status.
  - **Peers can start only so many turns.** Messages that arrive while the session is idle are gathered for half a second and start one turn. Each sender can start at most 3 turns per 10 minutes, and all peers together at most 10. Past that, messages wait for Deliver and a toast says so. Two sessions that auto-reply to each other stop there.
  - **A message sent to you rather than to a session** (when you had no live session it could see) is never delivered by itself. At most one of your local sessions holds it for Deliver: the live one you typed into most recently that isn't private. If none of your non-private sessions is live, the sender gets a "not delivered" notice instead.
  - **Delivery receipts.** When the sender's client asked for them (it saw `receipts.v1` in this session's status), the session reports what became of the message: `held` above the prompt, `shown` (handed to Claude), `declined`, `expired`, or, for a copy of a message to a session that ended, only `ended`. The receipt is end-to-end encrypted, goes only to the sending session, carries no text, and is never sent from a private session. Receipts are on by default, and that is a presence signal: your shared sessions advertise `receipts.v1` to everyone who can see their status, and a `shown` tells the sender when Claude got their message. `/peers receipts off` turns them off; senders then see what an older client looks like.
  - **A newer peer's message this version can't read** (an envelope of a kind it doesn't know) is never dropped silently: the session shows a toast and tells Claude once, at its next tool round, as data: "<peer> sent a <kind> this version of Peer2Peer doesn't understand: update Peer2Peer to see it". Nothing of its content is shown. `/peers doctor <user>` lists each of their devices with its protocol version and caps, and the features unavailable between you.
  - For a sender that didn't ask (an older client), a declined message, or one that expires after 10 minutes, sends one delivery notice back as before.
  - Receipts for this session's own sends reach Claude at its next tool round as a `[Cross-session delivery receipt]` line, framed as data; `/peers` lists the last outcome of each recent send, or "no receipt yet (their client may be older)".
  - At most 5 held items per sender and 50 in all; the oldest are dropped first.
  - Strangers can't message you at all: the relays only take envelopes from people you gave a capability to.
- **Message text is untrusted.** The body is HTML-escaped inside the frame, so a sender can't close the frame early or forge a new one. Everything a peer writes (names, labels, statuses, file names) is shown inert: no `<` or `>`, no control or format characters, one line, and framed as data from a named peer.
- **Project boundaries.** Each project (the git repository a session works in, or its folder) is private until you share it with `/peers project share`: only your own devices see its sessions, and nothing in them (status, summary, files, subagents, Ix footprints, messages) reaches anyone else. A session that reads or changes files in another project, or `cd`s into one, is bound to it too, and reaches only who all its projects share; one that touched a private project stays private until it ends. Peers' messages go only into sessions whose projects reach them. The model's sends (SendMessage, `ix_share`) are refused past that boundary, and it is told to ask you instead. Nothing committed in a repository can share it; a `.p2p-private` file at its top level keeps it private. See [projects](../../../docs/concepts.md#projects-project-boundaries) and the [threat model](../../../docs/security/threat-model.md#project-boundaries).
- **Working-on status.** In a session whose project is shared, a small model (Haiku) turns each prompt you type into a one-line status (a private session makes no model call: nobody would see it), such as "Refactoring the login form validation." The session shares that line with the people its roster allows, together with the repo-relative paths of the files it edits (at most 25).
  - **Subagents** share the status's audience and switch (`P2P_SHARE_STATUS=0` turns them off too). Each edit is credited to the loop that made it: the session's own go in its file list, a subagent's in that agent's entry, relative to its own worktree (never a `.claude/worktrees/…` or absolute path). An entry has an ordinal (`a1`, never the engine's agent id), the agent type, its spawn description as the task (at most 80 characters; no model call, never the prompt, transcript or answer), its state, up to 10 files, and whether it works in its own worktree. Agents spawned by plugins are listed too. Peers whose client understands `agents.v1` get the list; others see `(+N agents)` after the status line.
  - **Peers' statuses** reach Claude beside your prompt in a `<peer-activity>` block, and only when something has changed since the last one.
  - **Conflicts:** when a peer's session (or one of its agents) in the same repo changes a file this session or one of its agents changed, the block flags a potential conflict, naming the agents involved, and Claude sends that session one short message about it. A conflict that appears mid-turn reaches Claude at its next tool round, or beside your next prompt if the turn has ended. It never starts a turn by itself.
- **`/peers`**, which extends the built-in (also available as `/peer2peer`):

  | Command | What it does |
  |---|---|
  | `/peers` | Friends, circles, held items, and who sees this session |
  | `/peers setup [name]` | Makes your identity, once per machine. The backup phrase is shown only to you, above the prompt |
  | `/peers invite [label] [--circle <cid>]…` | Makes a one-time invite link (and its code), shown only to you, with Copy, and a message to send someone who may not have Peer2Peer yet (how to install it, then how to join), with Copy message. It friends whoever uses it and joins them to each circle named (up to 5) or your default circle |
  | `/peers join [--allow-private-relay] <link or code>` | Shows who it's from and every circle it joins; **Join** makes you friends and joins them, in one step. The first circle becomes your default only if you have none. A code whose relay is on a loopback, link-local or private address is refused unless you add `--allow-private-relay` (your own relay on your network) |
  | `/peers accept <link>` | Accepts a long invite link |
  | `/peers relays` / `/peers relays add\|remove <url>` | Lists your relays, or adds or removes one (1-5) |
  | `/peers receipts [on\|off]` | Whether peers get delivery receipts for their messages (on by default) |
  | `/peers circle <create\|invite\|join\|leave\|ls\|members\|default\|…>` | Circles, as `p2p circle` |
  | `/peers add <user>` / `/peers remove <user>` | Changes who sees and may message THIS session |
  | `/peers private` / `/peers circle <cid>` | Shares this session with nobody else, or with a circle you joined (within what its project shares) |
  | `/peers project [show\|ls]` | Who sees sessions in this session's project (its repository, or folder): private until you share it |
  | `/peers project share [<circle>…] [--person <user>]…` / `/peers project private` | Shares this project (bare: with your default circle), or makes it private again. Typed only: the model's `/peers project share` and its shell's `p2p project share` are refused |
  | `/peers approve <id>` / `/peers decline <id>` | Acts on a held item |
  | `/peers dismiss [n\|all]` | Clears a notice above the prompt (a join, an invite code, a warning) without the keyboard. Bare, it clears the only one, or lists them numbered when there are several. Typed only; it never removes anyone (that is the notice's **Remove**) |
  | `/peers friends` / `/peers ls` / `/peers circles` / `/peers held` | Read-only, as `p2p friends`, `p2p ls`, `p2p circle ls` and `p2p held`: friends, open invites and blocks; live sessions (this device's included); your circles; what waits for you |
  | `/peers doctor [user]` | Explains why sessions are or aren't visible: with no user, this device (identity and its expiry, each relay's reachability and latency, your mailbox, your document on each relay, the clock, your default circle, which sessions are shared and when a status last went out, and whether the `p2p` in use matches the one this plugin bundles); with a user, whether you can see them (friendship or circles, their document, a relay you share, capabilities both ways, when anything last arrived, blocks and holds, and whether their sessions are shared with you). Each line is ✓, ✗ or ?, with a one-line fix. Read-only, bounded (it never hangs), works before `/peers setup`, and anyone may run it |
  | `/peers rotate` / `/peers rotate resume` | Moves your identity to a new key: the remedy for a lost or stolen key-holding device (§2.8). First the plan (the new fingerprint, the devices that would follow, Drop for a lost one), then Rotate; your other devices follow when you accept there, friends get a fresh invite they approve, circles move with you. The new backup phrase goes to a file shown only to you; `resume` finishes an interrupted rotation |

  Only commands you type change who reaches you. The mod refuses a change that comes from anywhere else. Secrets appear only above the prompt for you, never in what the model reads. That covers your backup phrase file and where it is, your invite codes, and a code you type into `/peers join` (the command line is masked). As a best-effort extra layer, the mod also stops the model from doing this by itself:
  - shell commands that run mutating `p2p` verbs (`join`, `accept`, `invite`, `held approve`, `relays add|remove`, `circle invite|join`, `devices revoke`, `identity rotate`, `link`, `backup`, `setup`, `init`, `block`, `unblock`, `invites revoke`, `codex release|decline`, `extensions enable|disable`, …) are refused, with a pointer to `/peers`. So are `p2p ix note|subgraph|impact`, which would share Ix data without your Send (the model's path is `ix_share`), and `p2p status`, which the mod posts itself under your opt-outs;
  - this includes commands wrapped in `sh|bash|zsh|pwsh -c` or `eval`;
  - no reading tool may touch the backup phrase file or the `.p2p` folder. That means anything naming both `.p2p` and `backup`, a listing or glob of `~/.p2p`, or its key store.

  These guards parse commands conservatively. They are a backstop, not a sandbox: a determined command can spell things another way. The real protection is that only commands you type change who reaches you.
- **Join notices:** when someone uses your code, a toast and a row above the prompt say "<name>@<fingerprint> joined via <label>". The row has a one-click **Remove**, which unfriends them and takes them out of the circle, and **Dismiss**. The band says how to reach them: ctrl+x then Tab moves to the buttons, or type `/peers dismiss`.
- **Status line:** `p2p: 2 people online (3 sessions) · relays 2/2` (other people with a live session, and how many sessions they have; your own other devices are not counted). Failures are never silent. The line says plainly when:
  - Node.js 22+ is missing (for the bundled `p2p`), or `p2p` can't run;
  - you have no identity yet ("run /peers setup to join");
  - your identity document is expiring or has expired;
  - every relay is down;
  - the watcher keeps failing;
  - a status didn't go out.

  Each failure is also raised once as a toast.

## Install

In a Claude Code terminal session:

```
/plugin marketplace add ix-infrastructure/Peer2Peer
/plugin install peer2peer@peer2peer
```

Then:

```
/peers setup
/peers join <code>
```

`/peers setup` makes your identity, a key that lives on this machine with no account and no login. It saves your 24-word backup phrase to a file only you can read, and shows where that file is above the prompt, where only you can see it. Copy the phrase somewhere offline, then press **I saved it**, which offers to delete the file. `/peers join <code>` uses a code someone gave you. In one step, it makes you friends with them, adds you to their circle and makes that circle the default for your new sessions. To invite someone yourself, use `/peers invite [label]` and send them the code it shows.

The plugin includes the `p2p` command, so there is nothing else to install. It needs Node.js 22 or newer on your `PATH`, and the status line tells you if Node is missing or too old. Nothing is downloaded at runtime. A `p2p` already on your `PATH`, or one you name in `P2P_BIN`, is used instead.

## Two friends, quickstart

**Ann**, in Claude Code:

```
/peers setup ann
/peers invite pairing
```

The invite link appears above the prompt with a **Copy** button, for example `https://ix-infra.com/p2p/invite#relay.example/K7QM-3XPD-9TWA-HF2N-Q8RS`. Only Ann sees it; the model never does. `--circle <cid>` (repeat for up to 5) picks the circles it joins. She sends it to Ben over a channel she trusts. The note under it says who can use it and until when.

**Ben**, in Claude Code:

```
/peers setup ben
/peers join https://ix-infra.com/p2p/invite#relay.example/K7QM-3XPD-9TWA-HF2N-Q8RS
```

Above the prompt Ben sees who the invite is from (Ann's address and fingerprint) and every circle it joins, with its member count, policy and owner, and clicks **Join** (or **Cancel**). A circle that can't be checked, is open, or isn't run by Ann is marked as such and is never joined from the code; its own invite, if it comes, waits for his approval. Ben is now Ann's friend, and in each circle the invite named (by default Ann's default circle). The first becomes his default circle if he has none; an existing default is never changed. Ann gets a notice, "ben@… joined via "pairing"", with a one-click **Remove** if Ben wasn't who she meant. Remove unfriends Ben, takes him out of the circle and takes him off any session's roster.

Nothing is shared yet: each project is private until its owner shares it. Each of them, in the repository they work on together, types `/peers project share` (with their default circle, the one the code joined) or `/peers project share --person <the other>`. From then on, every session in that repository is shared, and only that repository's. (Where the project is already shared with them, the session where Ben typed `/peers join`, and the one where Ann made the code, are shared with the other at once, as before.)

If the code chose the only relay Ben's new identity uses, a warning above the prompt says so: "Your only relay is <host>, chosen by whoever gave you this code". Add another relay you trust with `p2p relays add <url>`. If Ann's circle has other members and none of them confirmed it yet, Ben is not added on his own. A **Join anyway** button waits above the prompt for his explicit click.

Each one's `ListAgents` now lists the other's sessions, with what they are working on. "Ask ann's session whether she's touching src/auth.ts" just works.

The longer flows remain available for anyone who wants them: `/peers accept <link>` takes a long invite link, and `/peers circle …` exposes the full `p2p circle` commands.

## Privacy: what a status shares

A session's status goes, end-to-end encrypted, only to the people its roster allows: the members of the circle you shared it with, the people you added with `/peers add`, and your own other devices. It carries:

- busy or idle;
- the session's label and repo (the git repository's folder name) and its branch. Outside a git repo there is no repo, and the label is just `session`. The permission mode is never shared;
- unless you opt out: the one-line working-on summary and the repo-relative paths of the files the session edits. It never carries absolute paths or your prompt.

To write the summary, your prompt goes to Haiku on your own Claude account. Haiku is told to leave out secrets, private data and absolute paths, and not to quote your request; any absolute path left in its line is stripped before the line is shared. That is an instruction plus a filter for paths only, not for everything, so opt out for sensitive work.

## Lost a key-holding device: rotate

A device that holds your identity key can sign for you even after you revoke it. Type `/peers rotate` on a key-holding device you still have. It first shows the plan above the prompt, to you only: the new key's fingerprint and each device that would follow, with **Drop** beside it. Drop the lost or stolen one (it is revoked before anything else), then press **Rotate** (or **Cancel**). A device this one didn't list itself (or hasn't seen in 30 days) starts out dropped, with the reason and an "unverified label" mark; press **Keep** only if you're sure it's yours. Each kept device then shows "your identity is moving to <fingerprint>, started by your device …" and follows only when you press Accept there (a device that misses it re-links later with `p2p link join <code> --rotated`). Every friend sees "<you> moved to a new key" and decides, and circles move with you. Your old identity then publishes a final version, and relays refuse its devices. `/peers rotate resume` finishes an interrupted rotation.

- **Someone who also has your old key can publish a competing rotation.** Every device of yours that didn't publish it says so on the status line (**ALERT**); on a key holder, `p2p identity rotate --contest` in a terminal answers it. Your friends then see a conflict and nothing is applied: they check with you another way (petnames, proofs) and you exchange a fresh invite. Friends act only on a rotation your old identity's own final version carries.
- **Rotation can't recover circles whose owner key was compromised.** Re-create those circles.
- **Secrets stay with you.** The new backup phrase goes to a 0600 file whose path is shown only above the prompt; the link codes your devices use never leave the CLI.

## Opt-outs

| Setting | Effect |
|---|---|
| `P2P_SHARE_STATUS=0` | No summary and no file list: the session shares only busy/idle, label, repo and branch. The legacy `IX_PEERS_SHARE_STATUS=0` is honoured too. |
| `/peers private` | Only the people you add see this session |
| Uninstalling the mod (`/plugin uninstall peer2peer@peer2peer`) | Nothing is shared |
| `claude -p` | Headless runs don't register, so one-shot scripts don't clutter your peers' listings. Set `P2P_HEADLESS=1` to opt in. |

## Ix items (optional)

With the Ix extension, peers' sessions can share Ix context: a session note, a reference to part of the graph ("look at `src/auth/*`"), or a blast-radius report. The plugin ships a copy of `@peer2peer/ext-ix` in `ext/` and passes `<plugin>/ext` to `p2p` in `P2P_EXTENSION_PATH` (ahead of yours), so there's nothing to install. **It stays off until you enable it**, once per machine, in a terminal:

```
node <plugin>/bin/p2p.mjs extensions enable ix     # or: p2p extensions enable ix
```

An extension runs inside `p2p` with your identity (it can read `~/.p2p`): enable it only if you trust it. To use your own install instead, point `P2P_EXTENSION_PATH` at the `node_modules` that holds it (entries inside the session's repository are ignored, compared by real path so a symlink can't hide one, so a cloned repo can't supply an extension; when you develop the plugin from inside the repo you're working in, its bundled copy is excluded the same way). For the `p2p` the mod runs, only `p2p extensions enable` (config.json) counts: a `P2P_EXTENSIONS` variable enables extensions only for `p2p` run from your own shell. Sending an impact report, resolving a reference and importing a note also need [Ix](https://github.com/ix-infrastructure/Ix) (`ix note` comes from Ix Pro). The model can't enable it: `p2p extensions enable` is refused in its shell.

Once enabled:
- **Receiving:** an item arrives like a message, under the same hold rule and turn caps, framed as the peer's data. Without the extension you see the one-line fallback ("shared an Ix note: install Ix to open it").
- **`/peers ix`** lists what peers sent, with ids; `/peers ix show <id>` shows one.
- **`/peers ix import <id>`** shows the whole note, then `/peers ix import <id> confirm` writes exactly that into your Ix graph. **`/peers ix resolve <id>`** shows the reference, then `… confirm` runs your own Ix on it. Both are typed only: the model can't run them, here or in its shell.
- **Sharing:** `/peers ix note <user> <ix-note-id>`, `/peers ix subgraph <user> <path>|symbol:<name>|region:<name>`, `/peers ix impact <user> <target>` (typed only). The model has an `ix_share` tool (registered only when the extension is loaded), checked against your permission settings first; it never sends by itself: each share waits above the prompt showing the recipient, the kind and every field in full, for your **Send** or **Cancel**, and Send sends exactly what the row shows (it is bound to a hash of it; a share that changed waits for a fresh review). A note from the model is at most 1,500 characters, so the row always holds all of it; longer notes you share yourself with `/peers ix note`. An impact report is computed from your local Ix graph when the model asks, and the row shows the whole report that Send would send. `P2P_IX_AUTO_SHARE` (full userIds, `p2p:…`, matched exactly; off by default) lets shares to those people go without the click. Whatever is sent is shown in the transcript.
- **Overlaps** (with the extension loaded): at most once a minute while the session is busy, the mod compares your footprint with live peers' (`p2p ix overlaps`, ext-ix SPEC §9): the same symbol, one change reaching code the other edits, the same file. High and medium overlaps show up as `POSSIBLE CONFLICT` lines in `<peer-activity>`, each once until it changes, at most one per peer and three in all per 10 minutes; low ones (the same area, two hops away) never reach the model, and neither does a peer's footprint itself. With a hashed footprint on their side, the line names nothing of yours (`hashed: names stay private`) and the model is told to coordinate without naming code; `p2p ix overlaps` in your own terminal shows your readable names.
- **Semantic conflicts** (`P2P_IX_SEMANTIC_CONFLICTS=1`, off by default): peers changing files connected, in your Ix graph, to yours show up as `<peer-activity>` notes, once per peer session and file.
- **Footprint** (`x:ix.footprint`): 10 s after the last edit (and at most every 30 s, then every 5 minutes while the session lives), the mod runs `p2p ix footprint --publish`: your session's changed symbols, their direct dependents and regions, per subagent, from your local Ix, sent to the same people your status goes to. It needs Ix installed (without it the mod stops asking for the run, silently), and follows status sharing (`P2P_SHARE_STATUS=0` turns it off too); `P2P_IX_FOOTPRINT=0` turns off only the footprint. The mod reads only whether it was published, so a footprint, yours or a peer's, never reaches the model. File, symbol and region names are hashed by default; readable names are opt-in per circle, typed by you in a terminal (`p2p ix config --circle <cid> names=plain`, see ext-ix SPEC §8.6). `p2p ix config` signs the setting with a key derived from this device's key, so a plain-names setting written into the store by file tools, or copied from another device or circle, is ignored. The mod also refuses, from the model's tools, `p2p ix config`, `p2p ix footprint --publish|--names|--force`, anything under the p2p home (`~/.p2p` or `P2P_HOME`: keys, `config.json`, `ext/`), and shell forms it can't read on a line that names the CLI (a pipe, here-string or heredoc into a shell, `xargs p2p`, a command word built at run time, interpreter one-liners running p2p); ordinary pipes into a shell (`curl … | sh`, installers) pass. **Neither is a hard boundary:** in a session that approves its own tool calls the model has your shell, and can run `p2p ix config` from a script file, decode a payload into a shell, or read local key material in ways the guard doesn't recognise. The hard boundary is Claude Code's permission prompt: use a mode that asks before running Bash if that matters to you. Mitigation: set plain names only for circles you trust. Hashed is what's published unless something with your shell opts out; a token reveals a name only to someone who has the repository (for a public repository, that's anyone).

Ix commands look at this session's repository: the mod passes it to `p2p` as `P2P_WORKDIR`, since `p2p` itself runs from the plugin folder.

## How it works

The mod never touches keys. The `p2p` CLI holds your identity and device keys, seals and verifies every envelope, and keeps its state in `P2P_HOME` (default `~/.p2p`). The mod calls it as follows:

- At start: `p2p whoami`, then `p2p session roster <sid>` for a session id generated for this run.
- For the life of the run, `p2p watch --session <sid> --jsonl`, restarted with backoff if it exits.
- `p2p status` on every busy/idle change, and otherwise every 60 s. A final idle status goes out when the session ends.
- For ListAgents, `p2p ls --json`: its rows (with the circle each session is shared through) and its `relays` field, which says which relays answered.
- For SendMessage, `p2p send --stdin` (plus `--notify-when-idle` when asked), so the text never shows in a process listing.
- `p2p friends` and `p2p circle ls` for grouping, and `p2p held` for held items.
- For `/peers doctor`, `p2p doctor [user] --json`. Every `p2p` run gets `P2P_MOD_ROOT` (the plugin folder), so the doctor can compare its version with the bundled `bin/p2p.mjs`.

Nothing outlives the session: the watch child ends with it, and there is no daemon.

## Develop

Working on the mod itself (not needed to use it):

```sh
git clone https://github.com/ix-infrastructure/Peer2Peer && cd Peer2Peer
(cd packages/core && npm ci && npm run build)
(cd packages/relay && npm ci && npm run build)
(cd packages/p2p && npm ci && npm run build)    # the CLI the bundled bin/p2p.mjs is built from
claude plugin validate mods/claude/peer2peer
claude plugin test mods/claude/peer2peer
claude --plugin-dir mods/claude/peer2peer   # a session with the mod loaded
```

The integration tests in `integration/` start a relay in-process and give temporary `P2P_HOME`s to the real CLI. They use the bundled `bin/p2p.mjs` when it is built, and `packages/p2p` otherwise. They drive the mod's backend layer (`hooks/backend.ts`) through node's child_process. `onboarding.e2e.ts` covers setup, invite, join, and the two sessions seeing each other. It skips itself when the CLI has no `setup`. Run the tests from the repo root:

```sh
packages/p2p/node_modules/.bin/vitest run --config mods/claude/peer2peer/integration/vitest.config.mjs
```

To type-check the mod, use a `tsconfig.json` kept outside the mod folder. Base it on the one in the header of the plugin-authoring `claude-code.d.ts`, and include that file together with `hooks`, `types` and `tests`.
