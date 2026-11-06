# Peer2Peer for Codex (the Codex bridge)

This connects OpenAI Codex CLI sessions to [Peer2Peer v3](../../docs/protocol.md). A Codex session can then see what your friends', circle-mates' and other devices' agent sessions (Claude Code or Codex) are working on, message them end-to-end encrypted, and get flagged when two sessions change the same files. There is no account and no login.

It is the Codex counterpart of the [Claude Code mod](../../mods/claude/peer2peer/README.md) and keeps the same rules. Both run over the same `p2p` CLI and the same relays, so a Claude session and a Codex session see and message each other with no extra setup.

## Install

You need Node.js 22 or newer and Codex CLI with hooks (0.156 or later; `hooks` is a stable feature there).

The bridge ships inside the single-file `p2p` CLI, `mods/claude/peer2peer/bin/p2p.mjs`, so there is nothing to clone or build. Put that file somewhere it can stay, then run:

```sh
mkdir -p ~/.local/share/peer2peer
curl -fsSLo ~/.local/share/peer2peer/p2p.mjs https://raw.githubusercontent.com/ix-infrastructure/Peer2Peer/main/mods/claude/peer2peer/bin/p2p.mjs
curl -fsSLo ~/.local/share/peer2peer/defaults.json https://raw.githubusercontent.com/ix-infrastructure/Peer2Peer/main/mods/claude/peer2peer/bin/defaults.json

node ~/.local/share/peer2peer/p2p.mjs codex install           # prints what it would add
node ~/.local/share/peer2peer/p2p.mjs codex install --write   # adds it
```

While the repository is private, `raw.githubusercontent.com` needs authentication. With the GitHub CLI signed in, fetch the same two files through the API instead:

```sh
mkdir -p ~/.local/share/peer2peer
gh api -H "Accept: application/vnd.github.raw" repos/ix-infrastructure/Peer2Peer/contents/mods/claude/peer2peer/bin/p2p.mjs > ~/.local/share/peer2peer/p2p.mjs
gh api -H "Accept: application/vnd.github.raw" repos/ix-infrastructure/Peer2Peer/contents/mods/claude/peer2peer/bin/defaults.json > ~/.local/share/peer2peer/defaults.json
```

If the Claude Code mod is installed, its bundled `p2p.mjs` works too.

`p2p codex install` prints three things, each pointing at the script you ran:

1. an `[mcp_servers.peer2peer]` table for `~/.codex/config.toml` (`command = "node"`, `args = ["…/p2p.mjs", "codex", "mcp"]`). It includes an `env_vars` line (CODEX_HOME and P2P_SHARE_STATUS only), plus an `[mcp_servers.peer2peer.env]` table holding the guarded settings set in your environment when you run it (`P2P_HOME`, `P2P_AUTO_DELIVER`, …; see "Where settings come from"). Existing entries in that table are kept when you install again;
2. five hooks for `~/.codex/hooks.json`: SessionStart, UserPromptSubmit, PreToolUse (shell commands only), PostToolUse and Stop. Each runs `node …/p2p.mjs codex hook <Event>`;
3. a few lines for `~/.codex/AGENTS.md` on how to treat peers.

`--write` applies all three. It backs up each file first (`<file>.p2p-backup-<time>`), writes atomically, and keeps everything else in those files as it was. It is idempotent: a second run changes nothing, and a moved script replaces its own entries instead of adding more. It also refuses to touch a `config.toml` that already defines `peer2peer` itself, or a `hooks.json` that isn't valid JSON. `--write --remove` takes out exactly what it added. `--codex-home <dir>` (or `CODEX_HOME`) points it at another Codex home. Its hook entries carry `--managed-by=p2p-codex-install`, and only entries with that marker are ever replaced or removed. A symlinked `config.toml` or `hooks.json` (say, from a dotfiles repo) stays a symlink: its target is backed up and written.

Then:

- **Restart Codex and trust the hooks once with `/hooks`.** Codex runs non-managed hooks only after you approve them, and again after any change to them.
- **Make your identity** in a terminal, once per machine: `node …/p2p.mjs setup`. Then join a friend with `node …/p2p.mjs join '<link or code>'`, or make a code for them with `invite`. A code on a relay on a private network (a Tailscale name, a LAN address) needs `--allow-private-relay` on the join (`node …/p2p.mjs join --allow-private-relay '<link>'`), unless that relay is already one of yours. Put the script on your `PATH` as `p2p` if you like.
- **Share your Codex sessions.** A session follows its project (the repository it works in): private until you share the project with `p2p project share [<circle>…] [--person <friend>]…` in it, a command only you run: the bridge's shell guard and the CLI refuse it from the model, best effort (for a hard barrier deny the model's sandbox access to `P2P_HOME`: [threat model](../../docs/security/threat-model.md#the-hard-barrier-sandbox-your-agents)). Every folder the session works in binds it to that project, and `p2p_send` refuses anyone the session's projects don't share. `p2p codex sessions` lists your live Codex sessions with their sids; the bridge registers each one, so only it speaks for them.

## What the model gets

The MCP server offers five tools. None of them changes who reaches you.

| Tool | What it does |
|---|---|
| `p2p_list_peers` | Lists live sessions of friends, circle-mates and your other devices: address, busy or idle, repo, branch, summary and files. All of it is inert, and labelled as data written by those peers. |
| `p2p_send` | Messages a `p2p:<name>@<fingerprint>/<label> [ref]` address or a `name@fingerprint` address. A bare name such as `ann` is refused, because anyone can choose their own name. A listed session is addressed by its owner's full userId. The text goes to `p2p send` on stdin, so it never shows up in a process listing. |
| `p2p_status` | Sets this session's one-line working-on summary (in the model's own words; absolute paths are stripped; at most 200 characters) and its repo-relative files. Paths outside the repository are dropped. |
| `p2p_inbox` | Shows the messages that arrived since the last call, each framed as `<peer-message from="p2p:…">` with its body escaped, under a header that says peers' text is data, not instructions. A held message is listed by sender only, without its text. |
| `p2p_peer_activity` | A digest of what peers' sessions are working on, same repository first, with `POTENTIAL CONFLICT` lines. |

**Codex's own approvals still apply.** The three reading tools are annotated read-only, so Codex runs them without asking. `p2p_send` and `p2p_status` publish text the model wrote, so they are open-world: **Codex asks you before each one.** Under approval policy `never`, Codex refuses them outright ("MCP tool call requires approval, but approval policy is never"). That keeps a session that runs unattended from being talked into sending your data to a peer. Busy/idle and edited files still go out through the hooks, with no tool call. To allow them anyway, add this to `config.toml`:

```toml
[mcp_servers.peer2peer.tools.p2p_send]
approval_mode = "approve"

[mcp_servers.peer2peer.tools.p2p_status]
approval_mode = "approve"
```

Asked for `p2p_join`, `p2p_approve`, `p2p_relays_add`, `p2p_invite`, `p2p_release`, or any other `p2p_*` name it doesn't offer, the server refuses and names the command you would run in your own terminal. Joining, inviting, approving held contacts, relays, circles, sharing a session and releasing held messages are only ever done by you. Secrets stay out of the model's context the same way: the bridge never reads or shows your backup phrase or invite codes.

## How messages reach Codex

Codex has no API for pushing a message into a running session. What it does have is Claude-Code-style hooks, and hooks can add context for the model or continue a turn. The bridge uses those:

| When | How |
|---|---|
| You submit a prompt | The UserPromptSubmit hook adds the waiting messages, any new conflicts, and a note about held messages. |
| During a turn | The PostToolUse hook adds messages that arrived since the last tool call (the same "next tool round" as in Claude Code). |
| When a turn ends | If messages arrived during the turn, the Stop hook continues it (`decision: "block"`) with them. This counts against the turn caps. |
| Any time | The model can read `p2p_inbox`. AGENTS.md and the server's instructions tell it to check at turn boundaries. |
| While idle (opt-in) | With `P2P_CODEX_QUEUE=1`, the bridge starts a turn in an idle thread with `codex queue --thread <id>`. The queued text is the bridge's own pointer ("N new messages from …: call p2p_inbox"), never the peer's text, which would otherwise sit in a process listing and arrive as a user message. This is off by default: `codex queue` is experimental and reaches a running TUI only through Codex's shared app-server daemon. |

Without the hooks, the tools still work and the model can read `p2p_inbox`, but nothing arrives on its own. Status then counts the session as busy for two minutes after each tool call.

The MCP server lives exactly as long as the Codex session. It runs `p2p watch --session <sid> --jsonl` and restarts it with backoff. Nothing runs after the session ends, and there is no daemon.

Hooks reach the server over a local socket (0600, in a 0700 folder under `P2P_HOME`; on Windows a named pipe whose random name is recorded only in that folder). **The socket is untrusted:** anything running as you can talk to it, including the model's own commands (Codex's sandbox allows Unix sockets). So:

- a hook report can only make the mode stricter. It can't loosen it, it never binds the server to a thread, its cwd is ignored, and the files it names must exist in the repo;
- held messages come out of it as metadata only (who, why, when), never their text;
- a release or decline must come from the person (see below).

A hook finds its server by the thread the server is bound to. The server binds only to the thread id in a tool call's `_meta`, which Codex builds. Before that, a hook goes by the Codex process both descend from, and only when exactly one unbound server is there. With more than one, the hook does nothing rather than guess.

## Who may start work in a Codex session (the hold rule)

Only this session's own mode counts; nothing a peer claims does. The bridge reads the mode from Codex itself, from sources a sandboxed command can't forge:

- the latest turn context (approval policy, sandbox, approvals reviewer) in **this thread's own rollout file**, `CODEX_HOME/sessions/**/rollout-*-<thread>.jsonl`. The bridge reads it incrementally, so a turn context far back in a long session still counts (Codex records one only when the settings change);
- the sandbox and auto-review in each tool call's `_meta`.

A hook's `permission_mode` can only make the mode stricter: `bypassPermissions` holds until Codex records a new turn context. Codex may run UserPromptSubmit before it records the turn's context (it does on the compaction path), so a mode-dependent message never goes out at the prompt. It goes out at the first tool round or at the turn's end instead.

- **The session asks before acting** when approvals go to you (`untrusted` or `on-request`, not `never`, not auto-review) **and** the sandbox is `read-only`. Messages from friends and circle-mates are then delivered.
- **Anything else counts as auto-approving.** That covers `workspace-write` (Codex edits files and runs sandboxed commands without asking), `danger-full-access`, `never`, `--yolo`, `--approve-for-me` and `granular`. **An unknown mode holds too**: no tool call has named the thread yet, or there is no turn context. A message held only because the mode was unknown goes out once Codex confirms the session asks. Every message from another person is otherwise **held**. There are two exceptions:
  - senders listed in `P2P_AUTO_DELIVER`, by full userId (`p2p:…`) or `name@fingerprint`. Bare names and petnames are ignored, since names are self-chosen;
  - messages you sent from your own terminal (`p2p tui`, `p2p send`). Your **agent** sessions' messages are held like a peer's unless you ran `p2p own-agents deliver` in your own terminal (the bridge reads the setting before each delivery). Your other devices may start at most 5 turns per 10 minutes, other sessions on this device 30, and all of them 10 since you last typed a prompt (a user message in this thread's rollout file: never a hook report, never the bridge's own `codex queue` pointer); past a cap they are held.
  - **Messages from your other devices are held too.** Another device can't say whether you typed a message (that needs the wire field of [RFC #48](https://github.com/ix-infrastructure/Peer2Peer/issues/48)). `p2p own-agents deliver --devices <device id…|all-other>` lets just those devices through.
- **The mode is never published** in a status.
- **A message sent to you rather than to a session** is never delivered by itself. Your most recently used Codex session holds it.
- **Held messages** wait up to 10 minutes. Their text never reaches the model. Review them in your own terminal:

  ```sh
  p2p codex held              # who, why and when (never the text)
  p2p codex release <id>      # hand it to that session's model at its next prompt, tool call or turn end
  p2p codex decline <id>      # drop it; the sender gets one delivery notice
  ```

  A release (or decline) rests on the sandbox, not on process ancestry, because a daemon can escape the process tree with `setsid` and a double fork. Codex's seatbelt or landlock confinement survives that. Three things are needed:
  - **a nonce file.** Before each request, `p2p codex release` writes a file into `P2P_HOME/codex/confirm/` (folder 0700, file 0600). The file's name is the hash of a secret the command keeps and sends only over the socket, so a sandboxed process that can read the folder still can't present it, or spend it. The bridge accepts only a fresh (under 60 s), matching, regular file owned by you, in real folders (`codex/` and `confirm/` must not be symbolic links), and deletes it;
  - **`P2P_HOME` out of the sandbox's reach.** The bridge checks that `P2P_HOME` (resolved) is outside every writable root of the session's trusted turn context: the workspace, extra writable roots, `TMPDIR` and `/tmp`. If it is inside one, if the session runs under `danger-full-access`, or if the roots aren't known yet (no tool call has named the thread), releases over the socket are refused outright. Release from a separate terminal while the session's sandbox can't write `P2P_HOME`, or leave the auto-approving mode, or list the sender in `P2P_AUTO_DELIVER`. A session started in your home folder has `~/.p2p` inside its workspace: point `P2P_HOME` elsewhere;
  - **a one-time code**, as a second factor, when the session's Codex window is a terminal. The bridge prints it there with the message's sender and first line: "type this into `p2p codex release` in a separate terminal; never paste it into Codex". With no terminal (an IDE extension, the desktop app, `codex exec` with pipes), the nonce file and the writable-roots check are what's required.

  Requests are rate-limited: 5 of yours a minute, with an exponential backoff after wrong codes (2 s, 4 s, 8 s, up to 15 minutes). Requests without a valid nonce file, or from a Codex descendant, are counted apart (30 a minute, with their own backoff), so they can never push your own releases into backoff. A caller the OS shows descends from Codex (`lsof` on macOS, `ss` on Linux) is refused; that check is cheap, but never enough on its own. The writable-roots check runs both ways: a writable root inside `P2P_HOME` or its `codex/confirm` folder refuses too, as does a symlinked `codex/` or `confirm/`.

  **Under `danger-full-access` nothing can be enforced:** the model's commands can write anywhere and run as you. That's why releases are refused in that mode. Messages from other people are held there anyway.

  An expired message also sends its sender one notice. At most 5 held messages per sender and 50 in all are kept; the oldest go first.
- **Turn caps:** messages that arrive while a turn runs are gathered into one continuation. Each sender can start at most 3 turns per 10 minutes, and all peers together at most 10. Past that, messages are held for you.
- **First contacts** (friend invites, circle invites and join requests) are never approved by the bridge. The model is told that they wait for you (`p2p held`, `p2p held approve <id>`).

Defence in depth, not the protection itself: `held`, `release`, `decline` and `install --write` also refuse to run inside a Codex tool call (where `CODEX_THREAD_ID` is set). The PreToolUse hook refuses model shell commands that run mutating `p2p` verbs (`join`, `accept`, `invite`, `held approve`, `relays add|remove`, `circle …`, `session roster`, `codex release`, …), including commands wrapped in `sh -c` or `eval`. It also refuses commands that touch `~/.p2p` (keys, backup phrase, and `~/.p2p/codex/`, the servers' registry and sockets). These guards parse conservatively, like the Claude mod's, and a determined command can spell things another way. What protects you is that the tools never do these things, held text never leaves the bridge, and a release needs the checks above.

## Status: what a Codex session shares

A Codex session's status goes, end-to-end encrypted, only to the people its roster allows. It carries busy or idle, the label (the repository's folder name), the repo and the branch. Unless you opt out, it also carries:

- the one-line summary the model gives `p2p_status`. If the model hasn't given one, the summary is made from the changed files ("Changing src/a.ts in web.");
- the repo-relative files the session changes (at most 25). These come from apply_patch and edit tool calls seen by PostToolUse, and from `p2p_status`. Either way, only files that exist in the repo are shared (or, for `p2p_status`, files an edit already reported).

It never carries absolute paths, your prompt or the mode. Prompts stay inside the hook process and are never sent to the bridge.

Conflicts: when a peer's session in the same repo changes a file this session changed, the model gets a `POTENTIAL CONFLICT` note (at its next prompt or tool call, and in `p2p_peer_activity`). The bridge also sends that session one short message per (session, file).

| Setting | Effect |
|---|---|
| `P2P_SHARE_STATUS=0` | No summary, no files and no conflict messages. Only busy/idle, label, repo and branch are shared. |
| `P2P_AUTO_DELIVER=p2p:…,name@xxxx-xxxx-xxxx-xxxx` | These people's messages are delivered even in an auto-approving session |
| `P2P_CODEX_QUEUE=1` | Push messages into an idle thread with `codex queue` (experimental) |
| `P2P_HOME`, `P2P_BIN` | As for `p2p` |
| `CODEX_HOME` | Where the bridge finds this thread's rollout file (default `~/.codex`) |
| `P2P_CODEX_CONFIRM_RATE`, `P2P_CODEX_CONFIRM_TTY` | Release requests a minute (default 5), and where the one-time code is printed (default the Codex window, `/dev/tty`). Set them only in the server's `env` in `config.toml`; the tests use them |

### Where settings come from

Codex merges config layers in order: user (`CODEX_HOME/config.toml`), profile, then the `.codex/config.toml` files of projects you marked trusted (cwd, its parents, the repo root), then `-c` flags. Codex keeps a project-local denylist (`codex-rs/config/src/loader/mod.rs`, `PROJECT_LOCAL_CONFIG_DENYLIST`: base URLs, model providers, `notify`, profiles, …), but **`mcp_servers` isn't on it**. So a trusted repo's `.codex/config.toml` can add to `mcp_servers.peer2peer.env`, for example `P2P_AUTO_DELIVER = "p2p:<someone>"` or a `P2P_CODEX_CONFIRM_TTY` pointing into the repo. A repo is content, not you, so the bridge takes these settings **only from the user-level config's `[mcp_servers.peer2peer.env]` table**:

`P2P_HOME`, `P2P_AUTO_DELIVER`, `P2P_CODEX_CONFIRM_TTY`, `P2P_CODEX_CONFIRM_RATE`, `P2P_CODEX_QUEUE`, `P2P_CODEX_BIN`, `P2P_CODEX_META_LOG`, `P2P_BIN`, `P2P_RELAY_TRANSPORT`, `P2P_DEFAULT_RELAYS`.

An environment value that differs from the table's is ignored, with a warning in Codex's MCP log and in `p2p codex sessions`. Values from your shell count only once they are in the table (the installer copies them in). `P2P_SHARE_STATUS=0` only tightens, so it is honoured from either place.

**A trusted repo can replace this server outright.** Codex merges `mcp_servers` from trusted project layers key by key, so a repo's `.codex/config.toml` can change `mcp_servers.peer2peer.command`, `args`, `cwd` or `env.PATH`, and then whatever runs isn't this bridge. Everything below is defence in depth against a repo that only adds settings. As a backstop, the bridge reads the `.codex/config.toml` of the cwd and each parent up to the repo root (for its own cwd and for Codex's), and if any of them touches `mcp_servers.peer2peer` at all, it holds everything and refuses every release, with a warning on stderr. It runs the same scan for every working folder it learns later (from the rollout or hooks). Keys are matched decoded (quoted, literal or `\u`-escaped spellings alike), and a file it can't read with confidence counts as touching it. The bridge runs its helpers (`git`, `ps`, `lsof`, `ss`, `getconf`) by absolute path from the system folders with a scrubbed environment (a fixed system `PATH`, no `GIT_*`), `P2P_BIN` and `P2P_CODEX_BIN` only as absolute paths, and nothing through the `PATH` in its own env. The programs it starts (`p2p`, `p2p watch`, `codex queue`) get an environment built from an allowlist: a fixed `PATH` (the node running the bridge, then the system folders), `HOME` (`USERPROFILE` on Windows) from the user database, `P2P_*` (except the extension and defaults-file variables), `LANG`, `LC_*`, `TZ`, `TERM`, and on Windows `SYSTEMROOT`, `APPDATA` and `LOCALAPPDATA`; `codex queue` also gets the bridge's `CODEX_HOME`. `IX_BIN` (the Ix CLI the Ix extension runs) is a guarded setting, taken only from `[mcp_servers.peer2peer.env]` (a project-set `IX_BIN=/bin/sh` would run the repo's scripts), and passed on only as an absolute path to an existing regular file outside temp folders, Codex-granted folders and the project, owned by you or root, writable by no group or others, in folders nobody else can write. Nothing else is passed on, so `NODE_OPTIONS`, `NODE_TLS_REJECT_UNAUTHORIZED`, proxy variables, `NODE_ICU_DATA`, `GCONV_PATH`, `LD_*` and `DYLD_*` set by a project config never reach them.

The bridge takes your home folder from the user database, never from `HOME` (a project config can set `HOME` in the server's env, which would move `~/.codex`, `~/.p2p` and the pin file). If `HOME` is set to anything else, the bridge holds everything and refuses every release. The same happens, whether or not `CODEX_HOME` was given, when the Codex home or `P2P_HOME` in effect lies in a temp folder, in a folder Codex lets the sandbox write (`memories`, `memories_v2` under a Codex home), or in the project, or isn't private to you (not yours, world-writable, or a symlinked `config.toml`). Temp folders are `/tmp`, `/private/tmp`, `/var/tmp`, `/dev/shm` and your own (on macOS from `getconf DARWIN_USER_TEMP_DIR`, which `TMPDIR` can't change). The project is the server's cwd and Codex's own (read from the OS, since a project config can move the server's `cwd`), each with its repo root, plus every cwd a trusted rollout declares. When the cwd is exactly your home folder, `~/.codex` and `~/.p2p` aren't counted as project files (they still have to pass the privacy checks); everything else under `~` is. That exemption holds only while the sandbox can't reach them: whenever a turn context declares writable a folder holding the Codex home or its `config.toml`, or overlapping `P2P_HOME` (a `workspace-write` session started in `~`, say), the bridge holds everything and refuses every release. Read-only and on-request sessions in `~` work as usual. Once a turn context exists but can't be relied on (its writable folders can't be read, or the rollout file isn't trusted), the bridge holds everything and refuses releases too; before the first turn context, only the static checks apply. A home folder that is itself a git repo (dotfiles) doesn't count as a project root, though: only the cwd's own subtree does. When the OS doesn't show Codex's own working folder (Windows, `lsof` missing), the project can't be confirmed, so releases are refused, with a warning. When it does and the server runs somewhere else, which a `cwd` override does, the bridge holds everything unless your user-level `[mcp_servers.peer2peer]` table sets that `cwd`. A symlinked `config.toml` (stow, chezmoi, Nix) is judged by its target: a regular file outside temp folders, Codex-granted folders and the project, owned by you (or by root, as in `/nix/store`), and writable by no group or others, in folders that are each owned by you or root and not group- or world-writable unless sticky.

`CODEX_HOME` locates that user config, so it is checked on its own. A value in any of those places, not owned by you or world-writable is always refused, with symlinks resolved. Otherwise the bridge counts the environment's value only when Codex itself (its parent process) runs with the same `CODEX_HOME`. It checks through `/proc` on Linux and `/bin/ps -E` on macOS (reading only the environment after the command line, and giving up when `CODEX_HOME=` appears twice). Where that can't be seen (Windows, a non-dumpable Codex on Linux, a platform-binary parent on macOS), it counts the value only when `p2p codex install --write` pinned it: the installer records a non-default Codex home in `~/.p2p/codex/codex-homes`, a fixed place outside any project. Otherwise it uses `~/.codex`. Every refusal is logged on stderr. A trusted project can still define its own MCP servers and commands, or replace this one: Codex runs those as you, and no bridge can defend against that. Trust only repos you'd let run code. The installer writes `command` as the absolute path of the node it runs under, so Codex's `PATH` doesn't pick the binary. `p2p codex held|release|decline` and the hooks read `P2P_HOME` from the same user-level table, so they find the bridges.

## What Codex supports (October 2026, codex-cli 0.156.1)

| Capability | Status | Used for |
|---|---|---|
| MCP stdio servers (`[mcp_servers.<name>]`: command, args, env, `env_vars`, cwd, timeouts, enabled/disabled tools) | Stable | The tools |
| Env passed to MCP servers | Allowlist only (HOME, PATH, USER, …) plus `env` / `env_vars` | `env_vars` in the snippet |
| MCP client capabilities | `elicitation`, with no roots and no sampling. Each `tools/call` carries `_meta["x-codex-turn-metadata"]`: session/thread id, turn id, `sandbox_mode`, `auto_review_enabled` (confirmed on the wire by the smoke test) | The thread id and sandbox |
| MCP tool approval | Per server and per tool: `approval_mode` auto/prompt/writes/approve. Under `auto`, read-only tools run freely; otherwise a tool needs approval unless it is annotated non-destructive and not open-world. Under approval `never`, a tool that needs approval is refused | Tool annotations |
| Hooks (`hooks.json` or `[hooks]`): SessionStart, UserPromptSubmit, PreToolUse, PermissionRequest, PostToolUse, Stop, SessionEnd, compaction, subagent and interrupt events | Stable (`features.hooks`). They need trust via `/hooks` | Delivery, status, mode, guard |
| Hook payload | `session_id`, `cwd`, `transcript_path`, `model`, `turn_id`, `permission_mode` (`never` maps to `bypassPermissions`, everything else to `default`; no sandbox), plus per-event fields | Pairing and mode |
| Hook output | `additionalContext` (SessionStart, UserPromptSubmit, PreToolUse, PostToolUse), `decision: "block"` + `reason` (UserPromptSubmit, PostToolUse, Stop; a Stop block continues the turn), PreToolUse `permissionDecision: "deny"` | Delivery and guard |
| `notify` (`agent-turn-complete` as an argv JSON) | Legacy, slated for removal | Not used: Stop replaces it |
| AGENTS.md (`~/.codex/AGENTS.md`, then the repo root down to cwd, `AGENTS.override.md` first) | Stable | Guidance lines |
| Approval policies `untrusted`, `on-request`, `granular`, `never` (`on-failure` is an alias); sandboxes `read-only`, `workspace-write`, `danger-full-access`; `--yolo`, `--approve-for-me` | Stable | The hold rule |
| Injecting into a running session | No direct API. `codex queue --thread` (experimental; through the app-server daemon; starts a turn when the thread is idle) and the app-server's `turn/steer` / `thread/queue/*` | Opt-in `P2P_CODEX_QUEUE` |
| Plugins (`.codex-plugin/plugin.json`, which may bundle MCP servers, hooks and skills) | Stable | Not yet: see Limits |

Sources: [Codex MCP docs](https://learn.chatgpt.com/docs/extend/mcp?surface=cli), [hooks](https://learn.chatgpt.com/docs/hooks), [AGENTS.md](https://developers.openai.com/codex/guides/agents-md), [plugins](https://learn.chatgpt.com/docs/plugins), and the openai/codex source: `codex-rs/rmcp-client/src/utils.rs` (env allowlist), `codex-rs/core/src/mcp_tool_call.rs` (`_meta`, tool approval) and `turn_metadata.rs`, `config/src/mcp_types.rs` (`approval_mode`), `codex-rs/hooks/src/schema.rs` and `core/src/hook_runtime.rs` (hook payloads and `permission_mode`), `codex-rs/hooks/src/legacy_notify.rs`, `ext/queue/src/service.rs` (`codex queue`), `protocol/src/protocol.rs` (approval policies). The hook input and output JSON schemas embedded in the 0.156.1 binary were also checked.

## Limits

- **No push into an idle session by default.** A message that arrives while Codex sits idle waits for your next prompt, unless you opt in to `P2P_CODEX_QUEUE=1`. That path needs Codex's app-server daemon. It queues only the bridge's pointer to `p2p_inbox`.
- **Held messages need a terminal**, outside Codex, with `P2P_HOME` out of the session's sandbox. Codex has no buttons for a bridge to add above the prompt, so release and decline are `p2p codex release|decline`. MCP elicitation could serve as a Deliver button, but whether an auto-approving Codex auto-resolves elicitations is undocumented, so the bridge doesn't rely on it. The one-time code is printed straight into the Codex window and stays visible until the TUI redraws.
- **The summary comes from the model** (`p2p_status`). Nothing else turns a prompt into a status line, and prompts never leave the hook process.
- **The mode and the writable roots depend on Codex's rollout format** (its turn context) and on a tool call having named the thread. Until both are there, messages from other people are held and releases are refused. `codex exec --ephemeral` writes no rollout, so it always holds. The rollout file is distrusted, so the mode counts as unknown, when `CODEX_HOME` is inside a folder the sandbox can write, when two files claim the thread, when its first line isn't the thread's `session_meta`, or when its timestamps run backwards or into the future. Whatever the turn context declares writable, a Codex home or `P2P_HOME` in a temp folder, a Codex-granted folder or the project makes the bridge hold everything (your own devices, `P2P_AUTO_DELIVER` senders and messages already released included) and refuse every release (see "Where settings come from").
- **Pairing a hook with its bridge:** when several unbound sessions run under one Codex process (one app-server), hooks do nothing until a tool call binds each bridge to its thread. They never guess.
- **Guards are a backstop.** As in the Claude mod, the shell-command guard parses conservatively and a determined command can get around it.
- **A sandbox escape defeats the nonce gate.** The release checks rest on Codex's sandbox keeping `P2P_HOME` out of a model command's reach. A process that escapes the sandbox runs as you: it can write the nonce file, read `~/.p2p` (keys included), and talk to any socket. On Linux the sandbox can usually still reach user daemons over their sockets (D-Bus with `systemd-run --user`, tmux, docker), and any of them can start a process outside the sandbox. As far as the Codex source shows, the only control over Unix sockets is the macOS network proxy's `[permissions.<profile>.network.unix_sockets]` allowlist; there's no equivalent on Linux. Keep `network_access` off (the default), never set `dangerously_allow_all_unix_sockets`, and run untrusted work in a container or VM without those sockets. Under `danger-full-access` there is no sandbox at all, and releases are refused.
- **Settings from the user-level config only** (see "Where settings come from"). A profile (`-p name`, `<name>.config.toml`) isn't read for them, and Codex's parent-environment check uses `ps -E`, which macOS hides for platform binaries: started under `/bin/sh`, an environment `CODEX_HOME` counts only when the installer pinned it.
- **No Codex plugin package yet.** A `.codex-plugin` could bundle the MCP server and hooks, but its paths would point into the plugin cache, and plugin hooks need trust too. The installer covers the same ground today.
- **Windows:** releases are always refused there. Windows doesn't show another process's working folder, so the bridge can't confirm the project Codex runs in, and it fails closed: messages it would hold stay held (they expire unread), while everything else is delivered as usual. The socket is a named pipe with a random name. Hook pairing falls back to "the only unbound session". There is no caller check; the nonce file and the writable-roots check still apply. Hook commands are quoted for `cmd`. It is untested there.
- **A real sandboxed attack isn't in the smoke test.** It would mean asking a live Codex model to run a socket client under `workspace-write`. The integration test does the same thing from two processes: a direct descendant of the server's parent (like a model's command), and a daemon that escaped the process tree. Both read only metadata, and their releases are refused, since neither can produce the nonce file a sandboxed process can't write. That the sandbox really can't write `P2P_HOME` is Codex's guarantee (seatbelt on macOS, landlock on Linux); the bridge only checks that `P2P_HOME` is outside the writable roots Codex recorded.

## Develop

```sh
(cd packages/core && npm ci && npm run build)
(cd packages/relay && npm ci && npm run build)
(cd packages/codex-bridge && npm ci && npm run build)
(cd packages/p2p && npm ci && npm run build)
cd packages/codex-bridge
npm run typecheck && npm run lint && npm test && npm run build
node ../../scripts/check-boundaries.mjs
```

The build order matters: core, relay, then this package, then `packages/p2p`, which imports this package's `dist`. `npm test` builds them in that order first (`scripts/pretest.mjs`), running `npm ci` in any of them that has no `node_modules` yet, so it works in a fresh checkout. The integration test (`src/__tests__/integration.test.ts`) starts a relay in-process and gives two temporary `P2P_HOME`s to the real CLI. It drives one Codex session through the MCP server's stdio JSON-RPC and a Codex hook, and the other person through the plain CLI.

A real Codex smoke test runs only on request: `P2P_CODEX_SMOKE=1 npm test` (`src/__tests__/codex-smoke.test.ts`). It needs `codex` on `PATH` and logged in. It starts a relay and two identities, then runs `codex exec --ephemeral -s read-only` with the MCP server given as `-c` overrides, plus `tools.p2p_send.approval_mode = "approve"`. The server is started through `env CODEX_HOME=<throwaway>` and a small node parent, so it reads its guarded settings from a throwaway user-level config. With `CODEX_API_KEY` set it uses a throwaway `CODEX_HOME`; otherwise `--ignore-user-config`, which reads only your login. It never writes any Codex config. It checks that the Codex model lists a CLI peer's status, that its `p2p_send` reaches that peer's `p2p watch`, and that each tool call's `_meta` carries the thread id and `sandbox_mode`. The hooks are not part of the smoke test: running them in `codex exec` would need `--dangerously-bypass-hook-trust`, which would also run your own user hooks. The integration test runs them the way Codex does instead (JSON on stdin, JSON on stdout).

After changing the bridge, rebuild the bundled CLI the Claude mod ships: `cd packages/p2p && npm run bundle`, then `scripts/check-bundle.sh`.
