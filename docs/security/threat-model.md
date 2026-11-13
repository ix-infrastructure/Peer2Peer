# Threat model

This page says, in plain language, what Peer2Peer protects, against whom, and where the limits are. For a one-page summary of where each kind of data goes, see [What is encrypted, what isn't](encryption.md). The normative rules are in the [protocol](../protocol.md) (especially §7), the [relay guide](../run-a-relay.md#the-privacy-promise), and the security sections of the [Claude Code mod](../../mods/claude/peer2peer/README.md) and the [Codex bridge](../../packages/codex-bridge/README.md). If anything here disagrees with them, they win, and please [tell us](../../SECURITY.md).

## What we protect

1. **Confidentiality of content:** message text, status contents (summaries, labels, files, agents), circle names and membership, rosters and friendship certificates. *Not* covered: the envelope's plaintext routing header (below), which includes the kind and the session id, and a circle's chain (name and membership) on a members-only relay that admits that circle (below).
2. **Authenticity:** every envelope comes from the device of the identity it claims. Nobody can impersonate a userId, claim another device's mailbox, or forge a circle version.
3. **Consent:** without a capability you issued (friendship, a circle you joined, or a code you redeemed), nobody can message you. A stranger can only send a rate-limited **first-contact request** (an invite), which is **held** for your approval and never delivered to your agent. Nobody can enrol you into a circle. Your agent's tools never change who reaches you, and its shell is refused when it tries (best effort against an agent with your shell: see [project boundaries](#project-boundaries)).
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
- identity documents, which are public by design (your device list, relays, optional profile and proofs);
- on a **members-only relay** that admits a circle's members (`RELAY_ALLOW_CIRCLE`), that circle's signed chain: its name, owner, admins and members. Members push it in plaintext (`circle-put`; see [Run a relay](../run-a-relay.md)) so the relay can check membership, only to their own relays and only for a circle they are in. Open relays never receive it.

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

**Read this first.** Peer2Peer's project boundaries are a hard rule for what *Peer2Peer* carries. Against an AI agent that runs as your user with an unrestricted shell, though, Peer2Peer's own checks are **best effort**. Such an agent can do anything you can: read `P2P_HOME`, run its own copy of the CLI where no check sees it, or open a network connection. **For a hard barrier, run your agents sandboxed with `P2P_HOME` denied for reads and writes** (below). The checks listed here raise the bar; the sandbox is what holds.

### What Peer2Peer guarantees

Peer2Peer itself never carries a private project's status, files, subagents, footprints, summaries or messages to anyone but you (your own devices):

- **A project is private until you share it.** The policy lives in your `P2P_HOME`, on each device, and nothing in a repository can widen it. A committed `.p2p-private` can only make a repository private. The project key includes the clone's git common dir, so another clone of a shared repository's remote, or the same folder with its remote changed, is a new project, private until shared.
- **Status and roster:** a private project's sessions sign a private roster with nobody on it, so their statuses go to your own devices only. A shared project's sessions reach exactly who it shares (one circle and named friends per roster, §3.4).
- **Summaries:** a private session sends none, and the mod makes no model call for one.
- **Footprints and overlap:** Ix footprints go to the roster's audience, and overlap or semantic-conflict checks compare a session only with sessions it is shared with.
- **Sends:** every send from a session (`p2p send --from-session`, MCP `p2p_send`, SendMessage, `ix note`/`subgraph`/`impact`, queued copies) is refused to anyone outside its projects' audience. The refusal names the command **you** run to share the project; no flag lets a caller skip it.
- **Sessions that move:** a session is bound to every project it works in, until it ends, and reaches only who **all** of them share. That covers its folder, a `cd`, files it reads or changes elsewhere, and paths its shell commands name (more under "what it can't see"). A session that touched a private project stays private. Past a cap (64 projects, folders per command or per session) a session is private; it never keeps "the first N". The project cap is a storage bound: the audience is the intersection of every project's policy, so more projects can only narrow it.
- **A session's own scratch:** paths in the folders Claude Code keeps for this one session (its background tasks' output, the tool results and subagent transcripts it saves, its job folder) bind no project, because what is in them came from the session's own tool calls, whose paths were already bound. The mod names them in `P2P_SESSION_SCRATCH`, and the CLI takes it only from a front end with the person token. The CLI matches them by the session's exact id, on real paths: another session's folders, the shared `memory` folder and other transcripts, lookalike names, and symlinks out of the scratch (bound to their target) all still bind, and a path written with a `..` segment never gets the exemption. Every path is walked as the file system walks it (each existing prefix resolved through its symlinks before a `..` applies), so `link/../x` binds beside the link's target, in the scratch and under a share that covers subfolders alike. A scratch folder that can't be read, or holds more than 4,096 entries, isn't skipped (fails closed), and the exemption is off on Windows. The folders must be the user's own and not symlinks, the per-user temporary folder must have Claude Code's name (`claude-<uid>`), and the job folder must sit in `<config>/jobs` with a name that starts the session's id (so a job's conversation after a `/clear` doesn't get its predecessor's folder). A git repository, a `.p2p-private`, a folder with its own policy, a `.git` that can't be read, or a path naming a `.git` there still binds as everywhere else.
- **Your own sessions don't launder it:** a message from one of your sessions to another carries the sender's bound (cap `projects.v1`, a critical field). The receiving session takes it on for good, and so does a session of yours that holds such a message sent to you with no session named. A session on a device of yours whose client can't honour that isn't sent to. This holds for another session on the same device too: that message is sealed to the device and goes through a relay like any other, so it gets the same receive-side checks. When a bounded session's text reaches your own terminal session (`tui`, which is never bound), a send from there to someone else warns you.
- **Inbound:** a message to you with no session named is held only in a session whose projects reach its sender. A message into a session from outside its audience is refused at the sender, and dropped on your device even with a wider roster signed elsewhere (by an older client of yours, say). Your own devices are always allowed.
- **Relays:** unchanged and content-blind.

- **Message history:** the history a device keeps (`p2p history`) never leaves it, and never reaches a model past the rules live messages follow:
  - A session reads only its own: since its binding began, within the projects it is still bound to, never your inbox or another project's. A session id with a new binding, or a record kept with no binding, shows a session nothing.
  - Your inbox and the whole history are yours only: the token, or your terminal "yes", and refused inside an agent's session. In Claude Code, `/peers history` (typed at your own terminal, not over Remote Control) draws it above the prompt for you; the command's result, which the model reads and the transcript keeps, holds only a count.
  - The Codex bridge's `p2p_history` shows a received body only if that session already showed it to its model, or you released it, in this run. That covers your own sessions too: a message from an agent session of yours or from another device is held like a peer's, so it gets no exemption. A held, declined or expired message, or one from before a restart, is listed by sender only, so history never gets around the hold rule. Each body is capped at 4,000 characters.
  - The model's shell can't run `p2p history` (the guards refuse it, and the CLI refuses an agent's session without the token).

### Graph targets (Ix)

Every `ix` call Peer2Peer makes or lets an extension make has a **graph target**, decided at one chokepoint, `graphTarget` in `packages/p2p/src/projects.ts`, next to the session ceiling: `local` (this machine's Ix backend) or, later, `shared` (the shared graph of exactly one circle a project is shared with). Today no circle has a shared graph, so **every target is local**. `p2p doctor` (under "Where your data goes") and `p2p project show` print it ("local only"). The local Ix backend keeps what it gets in plaintext; a shared graph, when it exists, will hold plaintext its operator can read ([What is encrypted, what isn't](encryption.md)).

- **What it intersects.** The ceiling's rules, over every project the call touches: the session's bound projects (when it names one), its folders (`P2P_WORKDIR`, `P2P_PROJECT_DIRS`), the process's real cwd (always: `P2P_WORKDIR` never replaces it for the boundary), the folder the `ix` child runs in, and every path the call names (its target file or range, `--path`, `--root`, and the command's own `--changed` and `--file`). A private, unmapped or repository-private project anywhere in that set, a session that is private for any reason or not bound yet, a relative path, more than 64 paths, or no single circle with a shared graph, all resolve to `local`. A `shared` result also needs a session a front end of yours registered (its person token); a bare call is local. A folder or path the call names resolves to its own folder, never up to a folder shared with `--subfolders`, so a covered subfolder is local even when the session's ceiling is shared (stricter than the ceiling, never wider).
- **The endpoint comes only from the chokepoint.** ext-ix runs `ix` with an allowlisted environment (`PATH` with its relative and empty entries dropped, `HOME`, temp and locale variables, `IX_HOME` for Ix's local state, and `IX_TOKEN`, which Ix sends to a loopback endpoint only) and sets `IX_ENDPOINT` to the target's endpoint. `IX_ENDPOINT`, `IX_PAT`, `IX_ORG`, the push, OAuth and auto-map knobs, `P2P_*`, `NODE_OPTIONS` and proxies never reach it. The local endpoint is Ix's default (`http://localhost:8090`) or a loopback `ixEndpoint` in your config.json, normalised to origin and path; the environment never picks it. ext-ix checks a host's target again (a `local` target with a cloud URL becomes the default local one). The CLI's own `ix` calls (`p2p doctor`, `p2p setup`) use the same rule, the doctor's health probe follows no redirect, and the environment an extension gets (`ExtContext.env`) has every other `IX_*` variable blanked and `IX_ENDPOINT` pinned as well.
- **An ext-ix from before graph targets isn't loaded.** It would run `ix` with your environment and config, and its `p2p ix import` and `note --ix-note` would run `ix note`, which Ix Pro sends to the cloud. So `p2p` loads the `ix` namespace only from an extension that declares `graphTargets: 1`, and says "update @peer2peer/ext-ix" otherwise. (Pinning `ExtContext.env` alone wouldn't stop an older ext-ix: config.yaml and `ix note` route to the cloud whatever the environment says.)
- **Why: Ix Pro routes to the cloud by itself.** With an org session active, Ix Pro (`@ix/pro`) keeps it in `$IX_HOME/config.yaml` (default `~/.ix`): `tenants`, `orgs` (with the org's JWT), `active` and `cluster`. It also mirrors the cloud cluster into config.yaml's `endpoint`, which plain OSS commands use when `IX_ENDPOINT` is unset. Refresh tokens sit in the macOS Keychain (service `ix-cli`). So a clean environment is not enough:
  1. OSS reads (`impact`, `around`, `status`, ...) would go to the cloud tunnel through config.yaml's `endpoint`. An explicit `IX_ENDPOINT` wins over it, and Pro's fetch wrapper attaches the JWT only to requests at the trusted cloud origin, so these stay local.
  2. `ix map`, and a reader's background map refresh, go through Pro's remote runner whenever `isCloudReady()` holds (an active org with a JWT in config.yaml, or `IX_PAT`), whatever `IX_ENDPOINT` says. ext-ix never runs `ix map`, sets `IX_MAP_BACKGROUND_REFRESH=0` so no reader starts one, and drops `IX_PAT` (Pro's PAT mode is driven by the environment alone).
  3. Ix Pro's `ix note` and `ix session` always read and write Ix-memory in the cloud org. Since Ix #916 (after Ix 0.13.0), an Ix **without** Pro has its own `ix note` and `ix session`, against the local backend: Ix registers them only when Pro didn't load, and they take `IX_ENDPOINT` before config.yaml's `endpoint`. So which one answers depends on whether Pro is installed, not on any config, and ext-ix asks Ix which one it has before every command or batch that uses them: `ix --help` lists the OSS ones under "Memory:" only when Pro didn't load, and Pro's section otherwise. That is a capability check, never a trial write. Only the OSS commands run, and only against a local target. Ix Pro's are refused (`graph_target`, "Ix Pro is installed …"), and so is an Ix with neither ("upgrade Ix"). Against a local target ext-ix runs `--version`, `--help`, `impact`, `around`, `overview`, `inventory`, `context`, `subsystems` and `status`, plus exactly these forms, each argument checked:
     - `ix note --json show <id>` (`p2p ix note --ix-note`);
     - `ix note --tag=<t> [--session=<ref>] [--actor=p2p:<address>] --json`, with the text on stdin, never in argv (`p2p ix import`, graph memory);
     - `ix session --json create p2p-<sid> --purpose=<one line> --actor=p2p[:<address>] --ttl=<hours>` (graph memory).

     Anything else (`ix note ls`, `supersede`, `retract`, `session delete`, a positional text, an extra or repeated flag) is refused, and so is every form against a shared target. Each write must then print `→ local backend <the pinned endpoint>` on stderr, as the OSS commands do. If it doesn't, the call fails with `ix_unconfirmed` and graph memory stops until Ix is asked again. This covers Pro being installed between the check and the write: at most that one write could have gone elsewhere.

  Ix has no per-call "force local" switch (`ix login --local` and `ix instance use local` change the person's global config), and pointing `IX_HOME` at a private folder would lose the workspace registry, so ext-ix keeps the person's `IX_HOME` and closes the routes above instead.
- **Graph memory writes only to the local graph.** `p2p watch` writes this device's own sessions into the person's local graph (concepts, "Graph memory"): their record (start, end, label, repository, branch), their status lines and the files they edited. Each batch is for one session, and its graph target must be local. Anything else is dropped as `not_local`, counted, and never handed to the extension. No shared target exists today; the refusal is explicit so a later shared graph can't receive memory by accident. ext-ix checks the target again, and its guard (above) checks every call.
  - **Only shared projects' sessions.** A session is recorded only while its project ceiling is shared (projects.ts `sessionCeiling`). A session in a private, unmapped or `.p2p-private` project, one bound to several projects that share nobody in common, and one not bound yet are never recorded. A session that becomes private stops being recorded. This fails closed: a private project's context never lands in a graph that a shared session's agent could read and pass on.
  - **Records don't travel between sessions by accident.** `p2p ix note --ix-note <id> --from-session B` refuses a graph-memory record of another session A unless p2p says A's context may go out from B (`mayShareSessionContext`). That requires both ceilings to be shared, B's audience to be within A's, and the same graph target.
    - **How a record is recognised:** by its Ix session (one in ext-ix's store, or one named `p2p-<sid>`) or by its first line.
    - **What is refused:** a record whose session can't be traced back (such as a hashed name), and any record on an older p2p.
    - **The store is MACed** with the device's key (`localMac`), so a planted mapping counts as no record.

    This guards against forwarding a record by mistake. It isn't a boundary against an agent with your shell, which can run `ix note show` itself and paste the text. Only the first rule above (private sessions are never recorded) keeps private context out of the graph.
  - **What it holds.** Only what this device already posted about its own sessions: their statuses, which never carry message text. Peers' statuses, other devices' sessions and message bodies are never written. Message history stays in its own encrypted store. A note a peer shares reaches the graph only when the person imports it (`p2p ix import`, consent as before).
  - **Off the hook path.** `p2p status` runs no Ix. The watch gathers and writes in the background, a batch at a time. The queue holds at most 64 items, and anything dropped (`queue_full`, `not_local`, a failed or unconfirmed write) is counted in `p2p doctor`.
  - **Off when it can't be local.** Without Ix, without the Ix extension, with an Ix that has no local `ix note`, or with Ix Pro installed, nothing is gathered at all. `"ixMemory": false` in config.json, or `P2P_IX_MEMORY=0`, turns it off. The environment can only turn it off, never back on.
  - **Records are framed as untrusted.** Each note starts with "Recorded by Peer2Peer (agent-generated, untrusted)" and is tagged `finding`, so a reader can tell it from the person's own notes. A status line is the session's own, but a model wrote it. File names with whitespace or control characters, or longer than 200 characters, are dropped.
  - **The OSS backend's labels aren't identities.** `--actor=p2p:<address>` is a label on the OSS backend: anything that can write to your local backend can write the same label.
  - **Only to a port you hold.** Before every `ix note` or `ix session` write (graph memory, `p2p ix import`), and once per command for a read (`--ix-note`), ext-ix asks the operating system who listens on the local endpoint's port, on a loopback or wildcard address. Every such listener must be this user's.
    - **Docker on Linux.** `ix docker start` publishes the backend's port through Docker's port proxy, which runs as **root** whoever started the container. On a machine whose Docker daemon others use too, a root-owned listener may be a teammate's backend, and your records and local token would go into their graph. So a root-owned listener is refused unless you set `"ixTrustRootListener": true` in p2p's config.json. You edit it by hand: no command writes it, and no environment variable can turn it on. Set it only if this machine's Docker is yours alone. `p2p doctor` explains the refusal and this opt-in.
    - **macOS.** Docker Desktop's proxy runs as you, so no opt-in is needed.
    - **Linux:** `/proc/net/tcp` and `/proc/net/tcp6`.
    - **macOS:** `netstat -an` for every user's sockets, each matched by one this user's `lsof` shows.

    If that can't be established, including when nothing listens, on another platform, or when the tables are hidden (a sandbox), nothing is sent and graph memory stays off. `p2p doctor` shows the reason. Ix's backend has no identity it can prove, and the opt-in local token is sent to whoever listens, so this check is what keeps a session's context and the token from another user's listener. It narrows the window but doesn't close it: a listener can appear between the check and the write. **On a machine other people log in to, turn graph memory off** (`"ixMemory": false`).
- **What it doesn't cover.**
  - An agent with your shell can run `ix` itself, with your Pro session. Graph targets close ext-ix and Peer2Peer as a path to the cloud; they don't sandbox Ix.
  - A newer Ix or Ix Pro could add another route. The allowlist of commands and forms keeps ext-ix to reads plus the local note and session writes above. If a future Ix lists the OSS "Memory:" section while Pro is loaded, the stderr confirmation is the remaining check.
  - **A shared machine.** "Local" means a loopback port, and on a machine other people log in to, another user can listen on that port first (before `ix docker start`, or after it stops) and receive what `ix` sends: query targets and file paths, and the local token if one is set. Writes check who holds the port first (above). Reads (`impact`, `around`, …) don't. Run Ix on a machine only you use, point `ixEndpoint` at a port you know is yours, and turn graph memory off there (`"ixMemory": false`).

### What Peer2Peer checks, best effort

Only the person widens sharing, and only a session's front end speaks for it. These checks make that hard to get around, but not impossible:

- **The person token.** `P2P_HOME/cli/person.key` (0600). The mod and the Codex bridge make it themselves, exclusively, before any typed command, so a fresh install works. They pass it to their own short `p2p` runs as `P2P_PERSON_TOKEN`, never to the long-lived `p2p watch` (on Linux, a process's environment is readable by others running as you, in `/proc/<pid>/environ`). The CLI checks it once at start and removes it from its own environment, so no child process (git, `ix`, an extension's tool) inherits it. ext-ix runs git with `core.fsmonitor`, hooks and external diffs switched off and an allow-listed environment. The Codex bridge passes it to its short `p2p` runs only, never to `p2p watch` or any other child. On a home with no identity yet, the token doesn't stand in for the person on `p2p link join` or on `p2p setup`'s link and invite paths, which no front end runs: a `person.key` there may have been put there by anything that can write the folder, so the person's terminal `yes` is asked. `link join` then shows the identity's address and fingerprint and keeps nothing until the person confirms it is theirs, because a link code from someone else would make the device theirs.
- **Agent detection:**
  - the variables Claude Code and Codex set in the commands their agents run: `CLAUDECODE`, `CLAUDE_CODE_CHILD_SESSION` (Claude Code's documented ones), `CODEX_TOOL_CALL_ID`, `CODEX_CI`, `CODEX_SANDBOX`, `CODEX_SANDBOX_NETWORK_DISABLED`, `CODEX_THREAD_ID` and `CODEX_SESSION_ID` (from Codex's source). Variables a person sets (`CODEX_HOME`, `CODEX_API_KEY`) don't count;
  - a Claude Code or Codex ancestor, matched by executable name, walking `ps` (not on Windows).
- **Widening commands:** `project share`, `circle default`, `session roster --add/--circle`, invites, joins, accepts, `trust add`, `held approve`, circle invites, joins and policy, unblock, device links, `identity follow` and `extensions enable`.
  - They run only with the token, or, outside any agent's session, after you type `yes` on your **controlling terminal**: read from `/dev/tty` (`CONIN$` on Windows), never from stdin or a flag.
  - A process with no terminal is refused, even with `--yes` or `--no-input`. That covers a daemon, `setsid`, `(sh x.sh &)` and CI.
  - The same "yes" is asked for a send as you (`p2p send` with no `--from-session`), and for the first send from a session id nobody has used.
  - Scripts and CI that should act as you pass the token.
- **Sessions are their front end's:**
  - inside an agent's session, `p2p status`, `send` and extension sends are refused without the token (the agent's path is SendMessage, `ix_share` or `p2p_send`);
  - a session a front end registered refuses everyone else, even a narrowing roster change.
- **Shell guards** in the mod and the Codex bridge refuse:
  - mutating verbs and `project share|private`, and `send` without a `--from-session` the CLI would read as that option (one after `--` is message text, one that is another option's value is that value, and a word up to it that isn't written plain, such as a quote, escape, expansion, brace, glob or redirection, fails closed);
  - interpreter code (`python -c`, `node -e`, …) and pseudo-terminal wrappers (`script`, `expect`, `unbuffer`, `tmux`, …) on a line that names p2p, and (in the mod) an interpreter reading its program from a pipe, here-string, heredoc or file on a command that names p2p;
  - any `--from-session`/`--session` but the session's own (read as the shell reads words, without a cap that padding could exhaust);
  - a command naming p2p that's longer than 16 KiB, or that a guard fails to check.

None of these can stop an agent that runs as you and wants past them. A pseudo-terminal spawned from a script file can answer the terminal "yes". A process can be started outside the agent's tree, by `launchd`, `cron` or an ssh back to the machine. `P2P_HOME` can be read in a form the guards don't recognise (the token, the keys). That agent can also run another `p2p` or speak to a relay itself.

### The hard barrier: sandbox your agents

Deny the agent's commands read and write access to `P2P_HOME` (`~/.p2p` by default), with no way to step outside the sandbox. The token, the keys, the policies and the CLI's state are then out of the agent's reach, and Peer2Peer's checks hold. That state includes three things the hold rule rests on: `config.json` (`trust`, and `ownAgentsDeliver`/`ownDevicesDeliver` from `p2p own-agents`), the person token, and the CLI's `localSends` record (which session on this device sent each same-device message, and whether the person did). An agent that can write any of them can make its own messages look like the person's. The configurations below were checked against the vendors' documentation on 2026-11-04. The Codex one was also run with codex-cli 0.156.1 on macOS (a read and a write under the denied folder failed with "Operation not permitted"; the workspace stayed readable).

**Claude Code** (`settings.json`). Sources: [sandboxing](https://code.claude.com/docs/en/sandboxing) and [permissions](https://code.claude.com/docs/en/permissions).

```json
{
  "sandbox": {
    "enabled": true,
    "allowUnsandboxedCommands": false,
    "filesystem": {
      "denyRead": ["~/.p2p"],
      "denyWrite": ["~/.p2p"]
    }
  },
  "permissions": {
    "deny": ["Read(~/.p2p/**)", "Edit(~/.p2p/**)"]
  }
}
```

- **`allowUnsandboxedCommands: false`.** Without it, a command that fails in the sandbox may be retried with `dangerouslyDisableSandbox`. The docs: "You can disable the unsandboxed retry by setting `"allowUnsandboxedCommands": false` … With the retry disabled, Claude Code ignores the `dangerouslyDisableSandbox` parameter." In `bypassPermissions` mode such a retry "runs without a prompt".
- **`excludedCommands`.** Commands listed in `sandbox.excludedCommands` run outside the sandbox, "which means no filesystem restrictions", and in `bypassPermissions` mode "without a prompt unless an ask rule matches it". Keep that list empty, or limited to tools you'd trust with `P2P_HOME`.
- **`bypassPermissions` mode** (`--dangerously-skip-permissions`) approves everything the sandbox lets out. Don't combine it with this barrier unless both settings above are in place.
- **The file tools.** The sandbox covers Bash and its children, not Claude Code's built-in file tools ("A `denyRead` entry doesn't stop the Read tool"). The `Read`/`Edit` deny rules cover those.
- **Other homes.** Use your own `P2P_HOME` if you moved it. The mod's own `p2p` runs aren't the agent's commands, so they still work.

**Codex** (`config.toml`). Sources: [permissions](https://developers.openai.com/codex/permissions) and agent approvals & security, both now served from learn.chatgpt.com/docs.

- The legacy `sandbox_mode` and `[sandbox_workspace_write]` settings can't deny reads. A named permission profile can. The docs: "`deny`: Denies both reads and writes under the path."
- Permission profiles don't combine with `sandbox_mode`. The docs: "Permission profiles do not compose with the older sandbox settings."
- Use an absolute path:

```toml
default_permissions = "p2p-safe"
# No approval prompts, so no escalation out of the sandbox is offered (the docs: "You can disable
# approval prompts with --ask-for-approval never").
approval_policy = "never"

[permissions.p2p-safe.filesystem]
":minimal" = "read"
"/Users/you/.p2p" = "deny"

[permissions.p2p-safe.filesystem.":workspace_roots"]
"." = "write"
```

Administrators can enforce the same with `[permissions.filesystem] deny_read = ["…/.p2p"]` in Codex's `requirements.toml`.

### What it can't do

- **Stop an agent leaking through its other tools.** An agent that read a private repository can still paste it into a web request, a `git push`, an email or a file in a shared folder. Project boundaries close Peer2Peer as a channel; they don't sandbox the agent. The sandbox and the agent's own permission prompt do that.
- **See paths it can't parse.** A session is bound to the folders its front end reports:
  - the Claude mod reports its folder, its current folder (at each status and before each send), the files its file and search tools touch, and the paths its shell commands name (absolute, `~`, `..` and relative, as written; each folder a command moves to with `cd`, `pushd`, `git -C`, `make -C`, `tar -C`, `env -C` or `sudo -D`, read per simple command, and relative paths against each of them, with one it can't place, such as `cd -` or `cd $X`, making the session private; and absolute paths written inside a quoted program or phrase), plus the `.git` or `.p2p-private` of the repository each path is in (so a shared folder never covers a repository after it is deleted), with `$HOME`, `$PWD` and, in a background session, `$CLAUDE_JOB_DIR` expanded, and only when the command doesn't set them itself (an assignment, `export`, `read`, `eval`, `source`; `$PWD` after a `cd`). `$TMPDIR` isn't expanded: Claude Code's sandbox gives the commands it runs a temp folder of its own. After the session touches the files Claude Code runs before each command (its session-env folder), no variable is;
  - the Codex bridge reports every cwd Codex reports, the files an `apply_patch` or edit names, and the same shell paths, with `$HOME` and `$PWD`.

  A path built at run time any other way (`$X/y`, `$(…)/y`, backticks, `~user`) makes the session private, since it can't be resolved; the refusal says so (not a cap). Further into a path (`/x/$X/y`) the folder before it binds. A bare `$X` or `$(…)` names no path, and a `$(…)` command's own paths bind. Device files (`/dev/null`) aren't projects, and the script of sed, jq, awk and `perl -e` (and the code of `python -c`, `sh -c` and the like) isn't read as a path: only for the command word of a simple command (never in `cat jq x/../k`), only where it has a program's shape, and never when it has a `..` segment or names a file that exists. The absolute paths written inside it are read. A command that could remove a `.git` or `.p2p-private` without naming it (`find … -delete`, `xargs`, dotglob, inline code) names `<folder>/.git` for each folder it names, so a shared folder above never covers that folder; a script that removes one by itself isn't seen, like a script that reads a file by itself. Paths a script opens by itself, or encoded paths, aren't seen. The CLI still binds the shell's own folder whenever that shell runs `p2p`. These lists are kept per conversation (Claude Code) or thread (Codex), so a resume stays bound. A store that can't be read, and a forked conversation (`claude --resume … --fork-session`: a new id, and hooks name no parent), make the session private.
- **Tell who wrote a session's scratch.** Its scratch is skipped because the session's own tool calls wrote it. Another process of yours that writes a private project's content there (another agent session, a script) could pass it on, the same as writing it into any shared folder. A hard link from the scratch into a private project isn't seen either, like a copy; creating one (`ln`) names both paths, so it binds. A symlink made and removed between two bindings is seen only through the paths that named it.
- **Unsend what was shared.** A session that was shared and then touched a private project sends its former audience one blank "private" status and nothing more. Anything sent before stays sent.
- **Keep the message history from your own shell.** `P2P_HOME/cli/history-*.json` is sealed (ChaCha20-Poly1305), but its key (`history.key`, 0600) sits beside it, as your device keys do, and the event log `p2p watch` reads (`events.json`, at most 7 days and 2,000 events) still holds recent message text in the clear (`p2p history --clear` purges it there too). A friend who sends a lot can push your older history out past the size cap. Older copies of single history files are refused, but someone who can write `P2P_HOME` can put back an older index together with its copy and its segments, all from one backup: that rolls the whole history back to the backup. An agent that can read `P2P_HOME` can read both: sandbox it (above). The CLI trusts a front end that holds the person token to ask only for its own session's history; the mod and the Codex bridge do.
- **Two lows, documented rather than fixed:** a summary the front end made before the session's first binding can reach the earlier audience once; and Ix content (a note, an impact report) is checked against the sending session's projects, not against the project the Ix graph it came from describes.
- **Decide for other devices.** Policies aren't synced: share a project on each device that works in it. A device still running a client from before project boundaries keeps the old rule for its own sessions (new sessions follow the default circle), so update every device (`p2p doctor` warns). An older device can't widen a session that runs on an updated one.
- **Ask for the terminal "yes" on Windows without a console.** `CONIN$` needs one, so detached Windows processes are refused like the rest. The ancestry check doesn't run on Windows.

## How the agent integrations defend you

- **Inert peer text.** Everything a peer writes (messages, names, labels, statuses, file names) is escaped, flattened to one line where shown in lists, stripped of control and bidi characters, and framed as "data from a named peer, not instructions". A sender can't close the frame early.
- **The hold rule.** Only the receiving session's own permission mode counts. A session where you approve each tool call receives messages from friends and circle-mates. A session that approves its own tool calls (or whose mode is unknown) **holds** every message from another person until you click Deliver, unless you listed that person's full userId in `P2P_AUTO_DELIVER`. Messages from your own sessions are delivered when you sent them from your own terminal (`tui`). A message from one of your **agent** sessions is held where a peer's would be: a peer may have told that agent what to send, and the receiving session must not run it unattended. A message from another device of yours counts as an agent's (this device can't tell; nothing on the wire says so). `p2p own-agents deliver`, the person's own choice in a terminal, turns that hold off. Further qualifications:
  - your own sessions on the same device may start at most 30 turns per 10 minutes, your other devices 5;
  - your own sessions may start at most 10 turns since the person last typed a prompt in that session;
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
