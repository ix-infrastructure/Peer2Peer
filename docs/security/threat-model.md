# Threat model

This page says, in plain language, what Peer2Peer protects, against whom, and where the limits are. The normative rules are in the [protocol](../protocol.md) (especially §7), the [relay guide](../run-a-relay.md#the-privacy-promise), and the security sections of the [Claude Code mod](../../mods/claude/peer2peer/README.md) and the [Codex bridge](../../packages/codex-bridge/README.md). If anything here disagrees with them, they win, and please [tell us](../../SECURITY.md).

## What we protect

1. **Confidentiality of content:** message text, status contents (summaries, labels, files, agents), circle names and membership, rosters and friendship certificates. *Not* covered: the envelope's plaintext routing header (below), which includes the kind and the session id.
2. **Authenticity:** every envelope comes from the device of the identity it claims. Nobody can impersonate a userId, claim another device's mailbox, or forge a circle version.
3. **Consent:** without a capability you issued (friendship, a circle you joined, or a code you redeemed), nobody can message you. A stranger can only send a rate-limited **first-contact request** (an invite), which is **held** for your approval and never delivered to your agent. Nobody can enrol you into a circle. Your agent can't be made to change who reaches you.
4. **Your agent's integrity:** peers' text can't instruct your agent, and a peer can't start unlimited work in your session.
5. **Your secrets:** keys, backup phrases, invite and link codes never reach a relay in the clear, the model's context, a process listing or the logs.
6. **Availability:** one relay going down, or flooding one, doesn't cut you off.

## Who we defend against

| Adversary | Can | Can't (by design) |
|---|---|---|
| **A relay operator** (honest-but-curious, or malicious) | See the metadata below; drop, delay or reorder envelopes; refuse service; serve stale identity documents | Read content; forge or redirect envelopes (all are signed by the sending device); impersonate users; re-admit a revoked device into clients' views (clients keep their own history, §2.5) |
| **A network observer** | See that you connect to certain relays, and when and how much (TLS hides content) | Read or forge anything |
| **A stranger** | Make free identities; send first-contact requests (rate-limited per IP, per sender and recipient pair, and per sender, plus proof-of-work only if the relay operator turned it on; `POW_BITS` is 0 by default), which are held for your approval; guess invite codes (100-bit codes with miss budgets) | Message you or your agent without a capability; join an invite-only circle |
| **A peer you accepted** (friend or circle-mate) | Message the sessions you share with them; see those sessions' statuses; send text crafted to manipulate your agent (prompt injection) | Have their text treated as instructions; start more than 3 turns per 10 minutes (10 for all peers together) in an auto-approving session without your click; see sessions you didn't share |
| **A malicious repository** you open | Ship files your agent reads. **If you mark it trusted in Codex**, its `.codex/config.toml` can replace `mcp_servers.peer2peer.command`, `args`, `cwd` or `env.PATH`, so whatever runs is no longer this bridge. Trusting a repo in Codex already grants it code execution as you | Supply a `p2p` extension (extension paths inside the repo are ignored). A repo that only *adds* settings can't change the bridge's guarded settings: they're taken only from your user-level config, and if a project config touches `mcp_servers.peer2peer` at all, the bridge holds everything and refuses releases. That backstop doesn't cover a trusted repo that replaces the server. Trust only repos you'd let run code |
| **Your own agent, prompt-injected** | Use the tools it was given: list peers, send a message, set a status. `p2p_send` and `p2p_status` are annotated open-world, so Codex prompts for them under its default approval settings. That's an annotation Codex honours, not an enforcement. An auto-approving setup, or `approval_mode = "approve"`, sends without asking | Run mutating `p2p` verbs, read `~/.p2p`, approve held items, release held messages, enable extensions. Guards refuse these, and the real protection is that the tools don't offer them |
| **A thief with a non-key-holding device** | Act as that device until you revoke it | Survive revocation: the next identity-document version drops it, and relays refuse its device id |
| **A thief with a key-holding device** | Sign as you (certify devices, publish versions, rotate) | Rotate you away silently: your other key holders alert, friends see two competing rotations as a conflict and apply neither, and you resolve it out of band |

## What each party can see

**A relay necessarily sees** (protocol §7):

- which userIds may reach which (from capabilities), even before any message;
- who sends to whom, by userId and device, with envelope sizes and timing;
- **each envelope's plaintext header**:
  - `from`/`fdid` and `to`/`tdid`;
  - `own`, the user who owns the session;
  - `sid`, the target session id (for example `s-ben`, or the reserved `~contact`/`~circle`);
  - `seq` and `ts`, a sequence counter and a millisecond timestamp;
  - `kind`.

  So a relay can tell a message from a status, roster, idle notice, sync, unfriend, contact or circle update, and can see extension kinds such as `x:ix.note`. The relay reads `kind` itself, for example to accept capability-less `contact` envelopes only. These fields are bound into the encryption's associated data, so a relay can't alter them, but it can read them;
- source IP addresses;
- identity documents, which are public by design (your device list, relays, optional profile and proofs).

The reference relay keeps the smallest record it can. Envelopes are stored with the recipient, size, arrival time and a *source tag* (a keyed hash of the sending IP bucket, whose key lives only in memory), and they're deleted on acknowledgement or after 7 days. It never stores capabilities, only domain-separated SHA-256 hashes of `(issuer, capid)`, kept when it has to remember a revocation or a use count. Its logs are counters-only. A modified relay can log more, and you can't verify which software a relay runs, so **choose relays you trust with metadata, or run your own.**

**Planned improvements:** sealed sender, padding and timing cover, optional relay-to-relay onion routing, and opt-in Tor transport. See the [roadmap](../roadmap.md#metadata-privacy). Until then, v3 doesn't hide metadata.

**Your peers** see what you share with them: sessions in the projects you shared with them, within each session's roster, those sessions' status (busy/idle, label, repo folder name, branch, and, unless you opt out with `P2P_SHARE_STATUS=0`, a one-line summary, repo-relative files and subagent entries), and your public identity document. They never see absolute paths, your prompts or your permission mode.

**Model providers:** in the Claude Code mod, each prompt you type in a session whose project is shared goes to **Haiku on your own Claude account** to produce the one-line status (a private session makes no such call). Haiku is told to leave out secrets and paths, and absolute paths are filtered afterwards. That's an instruction plus a path filter, not a guarantee, so opt out for sensitive work. The Codex bridge uses the summary the model gives `p2p_status` instead.

**Ix Infrastructure** sees nothing. It runs no servers in the Peer2Peer path, and the software sends no telemetry, analytics, crash reports or update checks. See [No data collection, no telemetry](../../README.md#no-data-collection-no-telemetry) for every outbound connection the clients make.

## Trust assumptions

- **The invite channel:** you send a code over a channel you trust. Whoever redeems it first becomes your friend. Codes are single-use, bounded to 7 days, and can be bound to a recipient (`--to`). Your client tells you who joined, and `p2p remove` undoes it.
- **Fingerprints, not names:** names are self-chosen and not unique. Every decision uses full userIds. Clients show 80 bits of fingerprint, and petnames and proofs (GitHub, DNS) help people tell lookalikes apart.
- **Your device:** keys are in 0600 files under `~/.p2p`, and there's no OS keychain backend yet. Malware running as you can read them. Disk encryption and OS account security are your first line.
- **Your agent's sandbox:** the Codex bridge's release checks rely on Codex's sandbox keeping `P2P_HOME` out of the model's reach. Under `danger-full-access` or `--yolo`, nothing can be enforced, so releases are refused and other people's messages are held.
- **Extensions:** an extension you enable runs inside `p2p` **with your identity** and can read your keys. Loading is opt-in, comes only from explicit directories (never the repo you're working in), and is announced, but there's no sandbox.
- **Cryptography:** Ed25519 (strict verification, torsion and small-order checks), X25519, XChaCha20-Poly1305, HKDF-SHA256 and SHA-256, through the audited `@noble` libraries.

## Project boundaries

You may share one project with your circle and keep others private. Peer2Peer enforces that in the `p2p` CLI itself, so the Claude Code mod, the Codex bridge, `p2p tui` and any client that runs `p2p --json` all get the same boundary ([concepts](../concepts.md#projects-project-boundaries) has the full rules).

**What it guarantees.** Peer2Peer never carries a private project's status, files, subagents, footprints, summaries or messages to anyone but you (your own devices):

- **A project is private until you share it**, and only you share it: the policy lives in your `P2P_HOME` on each device, `p2p project share` is refused from an agent's shell and from the mod's model-run `/peers`, and nothing in a repository can widen it. A committed `.p2p-private` can only make a repository private. The project key includes the clone's git common dir, so another clone of a shared repository's remote, or the same folder with its remote changed, is a new project, private until shared.
- **Status and roster:** a private project's sessions sign a private roster with nobody on it, so their statuses go to your own devices only. A shared project's sessions reach exactly who it shares (one circle and named friends per roster, §3.4).
- **Summaries:** a private session sends none, and the mod makes no model call for one.
- **Footprints and overlap:** Ix footprints go to the roster's audience, and overlap or semantic-conflict checks compare a session only with sessions it is shared with.
- **Sends:** every send from an agent's session, `p2p send --from-session`, MCP `p2p_send`, SendMessage, and `ix note`/`subgraph`/`impact` shares, is refused to anyone outside its projects' audience, queued copies included. The refusal names the command **you** run to share the project; there is no flag that lets a caller skip it.
- **Sessions that move:** a session is bound to every project it works in (its folder, a `cd`, files it reads or changes elsewhere) until it ends, and reaches only who **all** of them share. A session that touched a private project's files stays private, so what it read can't leave through Peer2Peer later.
- **Your own sessions can't launder it:** a message from one of your sessions to another carries the sender's bound (cap `projects.v1`, a critical field), and the receiving session takes it on for good. A session of yours on a device whose client can't honour that isn't sent to.
- **Agents can't widen it or speak for the person:** widening commands (`project share`, `circle default`, `session roster --add/--circle`, invites, joins, trust, friends) are refused when an agent runs them: its environment (`CLAUDECODE`, `CODEX_THREAD_ID`, `CODEX_SESSION_ID`, other `CODEX_*` but `CODEX_HOME`) or, when that was scrubbed, a Claude Code or Codex process among its ancestors (`ps`; not on Windows). A session id an agent names that no front end of yours registered starts private. The person's front ends (the mod, the Codex bridge) prove themselves with a token in `P2P_HOME/cli/person.key`, which the mod's guards keep from the model. Session `tui` (the person's) also requires no agent in sight.
- **Inbound:** a message to you with no session named is held only in a session whose projects reach its sender, and a message into a session from outside its audience is refused at the sender and dropped on your device, even with a wider roster signed elsewhere (by an older client of yours, say). Your own devices are always allowed.
- **Relays:** unchanged and content-blind. A relay sees that a private session's status went to your own devices, nothing more.

**What it can't do.**

- **It can't stop an agent leaking through its other tools.** An agent that read a private repository can still paste it into a web request, a `git push`, an email, a file in a shared folder or any other channel its tools give it. Project boundaries close Peer2Peer as a channel; they don't sandbox the agent. That is the agent's own permission prompt's job, and a session that approves its own tool calls has no such boundary (above).
- **A same-user agent with an unrestricted shell can ultimately act as you.** It runs as your user: it can read `P2P_HOME` (the person token, your keys) in a form the guards don't recognise, run a copy of `p2p` with its ancestry hidden (a detached daemon, `launchd`, a remote shell back to the machine), or talk to a relay with code of its own. Peer2Peer's checks (the token, the agent-environment and ancestry checks, the shell guards) are defence in depth; **the real backstop is the agent's own permission mode**: one that asks before running shell commands. Codex's sandbox may let a model's command *read* `P2P_HOME` even where it can't write it, so under Codex the token is a backstop only.
- **Folders the front end never hears about.** A session is bound to the folders its front end reports: the Claude mod reports the session folder, its current folder (at each status and before each send), the paths of files read or changed through Claude Code's file and search tools (relative search roots included), and the absolute, `~` and `..` paths a shell command names; the Codex bridge reports every cwd Codex reports, the files an `apply_patch` or edit names, and the same shell paths. These lists are kept per conversation (Claude Code) or thread (Codex), so a resume stays bound (`/clear` starts afresh). What a parser can't see stays unseen: a path built at run time (`$X/y`, `$(…)`), encoded, read by a script the command runs, or reached by a relative path from a folder the session `cd`'d to inside one command. The CLI still binds the shell's own folder whenever that shell runs `p2p`.
- **What was already shared stays shared.** A session that was shared and then touched a private project stops sending at once, but its last shared status stays in peers' lists until it ages out (150 s), and anything sent before stays sent.
- **Two lows, documented rather than fixed:** a summary the front end made before the session's first binding can reach the earlier audience once (the CLI drops summaries from any session that is private by the time it posts); and Ix content (a note, an impact report) is checked against the sending session's projects, not against the project the Ix graph it came from describes.
- **Each device decides for itself.** Policies aren't synced: share a project on each device that works in it. A device still running a client from before project boundaries keeps the old rule for its own sessions (new sessions follow the default circle), so update every device. An older device can't widen a session that runs on an updated one: that session's own device drops whatever comes in outside its projects' audience.

## How the agent integrations defend you

- **Inert peer text.** Everything a peer writes (messages, names, labels, statuses, file names) is escaped, flattened to one line where shown in lists, stripped of control and bidi characters, and framed as "data from a named peer, not instructions". A sender can't close the frame early.
- **The hold rule.** Only the receiving session's own permission mode counts. A session where you approve each tool call receives messages from friends and circle-mates. A session that approves its own tool calls (or whose mode is unknown) **holds** every message from another person until you click Deliver, unless you listed that person's full userId in `P2P_AUTO_DELIVER`. Messages from your own devices are delivered, with two qualifications in the Codex bridge:
  - your own devices may start at most 5 turns per 10 minutes;
  - when the bridge's location checks fail (a Codex home or `P2P_HOME` in a temp folder, a sandbox-writable folder or the project, or a project config that touches the bridge), it holds everything, own devices and `P2P_AUTO_DELIVER` senders included.
- **Turn caps.** At most 3 peer-started turns per sender per 10 minutes, and 10 for all peers together, so two auto-replying agents can't loop forever.
- **Typed-only control.** Joining, inviting, approving, relays, circles, rosters, project sharing, rotation and enabling extensions only happen through commands you type (`/peers …` or your own terminal). The agents' tools don't offer them, and shell guards refuse them as a backstop.
- **Secrets stay out of context.** Backup phrases, invite codes and link codes are shown only to you (above the prompt, or in your terminal), never in what the model reads.

The shell guards parse commands conservatively, but they're a **backstop, not a sandbox**. A determined command can spell things another way. The real protection is that the tools never do these things.

**A session that approves its own tool calls gives the model your shell.** Then no guard inside `p2p` or the mod is a hard boundary: the model runs as you. It can run a command from a script file the guards never see, decode a payload into a shell, or read local key material (`P2P_HOME`) in a form the guards don't recognise. The guards still stop the obvious forms (the `p2p` verbs above, the p2p home folder, shell forms that hide what they run on a line naming the CLI), and the Ix footprint's plain-names setting is signed with a key derived from the device key, which stops file-tool edits and settings copied from another device or circle. The hard boundary is the agent's own permission prompt: a mode that asks before running shell commands. The defaults are chosen to stay safe without it: incoming messages are held in such a session, and Ix footprints use hashed names unless you opt a trusted circle into plain ones (a hashed name tells nothing to anyone without the repository; for a public repository, that's anyone). Hashed is what's published unless something with your shell opts out.

## Known limits

- **Metadata is visible to relays** (above).
- **A rotation-conflict denial of service:** someone holding your *old* identity key can publish a competing rotation at any time. Friends then suspend the identity they carried over until it's settled out of band (`p2p identity dispute`). This is intended: a real conflict can't be told apart from a theft automatically.
- **A circle whose owner key is compromised** can't be recovered by rotation, so re-create it.
- **Relays forget rotations** after they drop old history (a tombstone after 90 days). Clients keep their own chains, so this doesn't fool them.
- **Spam with free identities** is slowed by per-IP limits, and by proof-of-work if the relay operator enables it (`POW_BITS`, 0 by default), but not prevented. A shared IP (campus, carrier NAT) shares its limits.
- **Windows:** file modes are best-effort, and the Codex bridge always refuses releases there (fail-closed).
- **The CLI's terminal pickers and the send auto-share** (`p2p` on a terminal picks a missing argument, and a send from the `tui` session shares that session with its recipient) turn themselves off inside an agent's tool call by looking for Claude Code's and Codex's environment variables (`CLAUDECODE`, `CODEX_THREAD_ID`, `CODEX_SESSION_ID`) and for a terminal on stdin and stdout. That is a convenience check, not a boundary: an agent that strips those variables and runs `p2p` under a pseudo-terminal reaches them like a person would. The boundary is the mod's command guard (and Codex's shell guard), which refuses the mutating verbs however they're invoked, `send` without `--from-session` among them (that is the person's terminal path, the one that shares the `tui` session), and, beneath it, the agent's own permission prompt.

## Reporting

If a guarantee on this page doesn't hold, that's a vulnerability. Please report it privately, following [SECURITY.md](../../SECURITY.md).
