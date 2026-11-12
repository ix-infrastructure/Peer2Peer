# Getting started

> **Early release:** the npm packages are published (v0.1.1; see the [CHANGELOG](../CHANGELOG.md)). The steps below also work from a checkout of this repository.

Peer2Peer has no public relay and no central server. Your group brings its own relay: someone runs one (a single Docker container), or you use one a friend runs. Everyone then sets up with that relay, and invite codes carry it to the people you invite.

## 1. What you need

- **Node.js 22 or newer.**
- **A relay URL**, for example `wss://relay.example.org/v3`: your group's own relay, or one a friend runs (step 2). Only the person who *invites* needs one: someone joining with a code uses the code's relay, and can add more later.
- To try it with **no network at all**, run [`docs/demo/two-friends.sh`](demo/README.md), which starts a throwaway local relay and two users.

## 2. Get a relay

If a friend or your team already runs a relay, ask for its URL and skip to step 3.

Otherwise, one person runs a relay for the group. Any always-on machine with Docker will do: a small VM, a home server, or a small board such as a Raspberry Pi. From a checkout of this repository:

```sh
docker build -f packages/relay/Dockerfile -t peer2peer/relay .    # once, until a published image exists
docker run -d --name p2p-relay --restart unless-stopped -p 127.0.0.1:8080:8080 -v p2p-relay:/data \
  -e RELAY_URL=wss://relay.example.org/v3 -e OPERATOR_CONTACT=mailto:you@example.org -e TRUST_PROXY=1 peer2peer/relay
```

Clients only dial `wss://`, so put TLS in front of it, for example with [Caddy](https://caddyserver.com):

```caddyfile
relay.example.org {
    reverse_proxy 127.0.0.1:8080
}
```

`RELAY_URL` must be exactly the URL people will use, so choose a hostname you'll keep. [Run a relay](run-a-relay.md) covers running it without Docker, limits, backups and operations.

## 3. Install

Pick the client for your agent:

**Claude Code**

```text
/plugin marketplace add ix-infrastructure/Peer2Peer
/plugin install peer2peer@peer2peer
```

The plugin includes the `p2p` command. Start Claude Code with your relay in the environment:

```sh
P2P_DEFAULT_RELAYS=wss://relay.example.org/v3 claude
```

**Codex CLI:** follow [the Codex bridge install](../packages/codex-bridge/README.md#install), which comes down to one file plus `p2p codex install --write`.

**Just the CLI** (any agent, or scripts). One line installs it, with Node.js 22 or newer already on the machine:

```sh
curl -fsSL https://ix-infra.com/p2p/install.sh | sh          # macOS and Linux
```

```powershell
irm https://ix-infra.com/p2p/install.ps1 | iex               # Windows (PowerShell 5.1 or 7, no admin)
```

The script checks for Node 22 and npm (and says how to get them if they're missing, without installing them), installs `@peer2peer/cli` and `@peer2peer/ext-ix` at one pinned version with `npm install -g`, checks `p2p --version`, then runs `p2p setup` when there is a terminal to answer it on. It never uses sudo or asks for Administrator rights, and it doesn't install Ix. Read it first if you like ([install.sh](../scripts/install.sh), [install.ps1](../scripts/install.ps1)): `--dry-run` prints every command without running any, `--no-setup` skips setup, and `--version X.Y.Z` picks another release. Piped, pass them as `curl -fsSL https://ix-infra.com/p2p/install.sh | sh -s -- --dry-run`; in PowerShell, `| iex` takes no parameters, so use `& ([scriptblock]::Create((irm https://ix-infra.com/p2p/install.ps1))) -DryRun` (also `-NoSetup`, `-Version X.Y.Z`). `https://ix-infra.com/p2p/install.sha256` has the scripts' SHA-256.

In Windows PowerShell, `p2p` may fail with "running scripts is disabled on this system": npm also installs a `p2p.ps1`, which the default execution policy blocks. Type `p2p.cmd` instead (for example `p2p.cmd setup`), or allow locally installed scripts for your account with `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`. In cmd and in Git Bash, `p2p` works as is.

Or do the same by hand:

```sh
npm i -g @peer2peer/cli @peer2peer/ext-ix
# or from a checkout: node /path/to/Peer2Peer/mods/claude/peer2peer/bin/p2p.mjs <command>  (alias it as p2p)
export P2P_DEFAULT_RELAYS=wss://relay.example.org/v3     # 1–5, comma-separated
```

## 4. Set up and invite

| | Claude Code | Terminal |
|---|---|---|
| Make your identity (once per machine) | `/peers setup ann` | `p2p setup --name ann --relay wss://relay.example.org/v3 --backup-file` |
| Make a circle for your team (optional) | `/peers circle create api-team`, then `/peers circle default <cid>` | `p2p circle create api-team`, then `p2p circle default <cid>` |
| Invite someone | `/peers invite ben` (add `--circle <cid>` for each circle, up to 5) | `p2p invite ben` (same `--circle`) |

Your **24-word recovery phrase** is the only way to recover your identity if you lose this device:

- **Claude Code:** `/peers setup` saves it to a file only you can read. Where the file is, is shown above the prompt, to you only.
- **Terminal:**
  - `--backup-file` saves it to a 0600 file (default `<P2P_HOME>/backup-phrase.txt`, never overwritten) and prints where.
  - Run interactively without the flag, `setup` offers to save or show it.
  - Run non-interactively without the flag, it saves nothing: run `p2p backup show` yourself, in your own terminal, later.

Either way, copy the words somewhere offline (a password manager or paper), then delete the file. Never paste the phrase into an agent, a chat or a pipe.

**Ix is optional and recommended; Peer2Peer never installs it for you.** [Ix](https://github.com/ix-infrastructure/Ix) is a local code graph. With it, Peer2Peer can flag when a peer's session works on code that overlaps yours, show a change's blast radius, and keep your sessions' context as local graph memory, all on your machine. When Ix isn't installed, `p2p setup` in your terminal explains this and asks `Install Ix? [y/N]` (default No). A yes prints the install command for you to run yourself, then `p2p setup --ix` turns on the Ix extension. A no is remembered, and `p2p setup --ix` asks again. Setup never offers Ix with `--json`, in CI, or inside an agent's session. Your agent may suggest Ix once, but installing is your decision and your action.

The invite prints a one-time link like `https://ix-infra.com/p2p/invite#relay.example.org/K7QM-3XPD-9TWA-HF2N-6RJC`, the same code on its own (`relay.example.org/K7QM-3XPD-9TWA-HF2N-6RJC`), and a message to paste into Slack, Signal or email for someone who doesn't have Peer2Peer yet: the link, the three Claude Code commands that install the plugin (`/plugin marketplace add ix-infrastructure/Peer2Peer`, `/plugin install peer2peer@peer2peer`, `/reload-plugins`), then `/peers join <link>`, where the Codex instructions are, and `p2p join '<link>'` for people who already have the command. On a private relay (Tailscale, a LAN) both join lines carry `--allow-private-relay` and the message says to be on the same network. In Claude Code, `/peers invite` shows the message above the prompt with a **Copy message** button. Send it over a channel you trust. It works once and expires within 7 days; `p2p invites revoke <code>` cancels it. The part after `#` is the secret, and it never reaches the web server.

## 5. Join

| Claude Code | Terminal |
|---|---|
| `/peers join https://ix-infra.com/p2p/invite#relay.example.org/K7QM-…` (or the code) | `p2p join 'https://ix-infra.com/p2p/invite#relay.example.org/K7QM-…'` (or the code) |

First you see who the invite is from (their address and fingerprint) and every circle it joins, with its member count, policy and owner, and you say yes once: **Join** above the prompt in Claude Code, `y` in a terminal (`--yes` for scripts). Then that one step creates your identity if you don't have one (on the code's relay, unless you set your own), makes you friends and joins the circles. A circle that can't be checked, is open, or isn't run by the inviter is shown as such and is never joined from the invite: if its own invite comes, you approve it separately. A code whose relay is on a private or local address (`localhost`, 192.168.x.x and the like) (or whose name resolves to one) is refused unless you add `--allow-private-relay`. The first circle becomes your default circle if you have none; an existing default is never changed, and sessions that are already running stay as they are (new ones start in the default circle). The inviter is told who joined, with a one-click **Remove** if it wasn't who they meant.

### Private relays (Tailscale/LAN)

A relay on a private network, such as a Tailscale MagicDNS name (which resolves to a 100.x address) or a LAN address like 192.168.x.x, works like any other once it is one of your own relays (`p2p relays`): codes and links from teammates on it join without any extra step.

An invite from someone else that points at a private relay you don't use yet is refused before anything connects there, because it could otherwise make your machine reach into your own network:

```
the code's relay relay.tailnet.example (it resolves to 100.101.102.103) is on a private network (for example Tailscale or a LAN). If you trust the person who sent it, run the same command again with --allow-private-relay (in Claude Code: /peers join --allow-private-relay <code>), or set P2P_ALLOW_PRIVATE_RELAY=1. Your own relays never need this
```

If you trust the person who sent it, do exactly that: `p2p join --allow-private-relay '<link>'`, or `/peers join --allow-private-relay <link>` in Claude Code. The same flag works for `p2p accept` and `p2p circle join`.

## 6. See each other

- **Claude Code:** `ListAgents` now has a *Peer2Peer* section with your friends' and circle-mates' live sessions: what they're working on, the repo, the branch and files. Ask your session to message one, for example "ask Ben's session whether it's touching `src/auth/token.ts`".
- **Codex:** the model can call `p2p_list_peers`, `p2p_send` and `p2p_peer_activity`.
- **Terminal:** `p2p ls`, `p2p send --from-session <sid> --to ben "…"`, `p2p watch --session <sid> --jsonl`.

When two sessions in the same repo change the same file, each agent gets a **`POTENTIAL CONFLICT`** note and sends the other one short heads-up.

## 7. Control what you share

- Each **project** (a git repository, or a folder) is **private until you share it**: only your own devices see its sessions. Share the repo you're in with `/peers project share` (your default circle) or `/peers project share <circle>` / `--person <friend>`; in a terminal, `p2p project share …` in the repo. `p2p project ls` lists what you shared. See [projects](concepts.md#projects-project-boundaries).
- A session that works in several projects reaches only who all of them share, and one that touched a private project stays private until it ends.
- `/peers private`, `/peers add <user>` and `/peers circle <cid>` narrow who sees *this* session, within what its project shares (`p2p session roster …` in a terminal).
- `P2P_SHARE_STATUS=0` shares only busy/idle, label, repo and branch: no summary and no files.
- See [what a status shares](../mods/claude/peer2peer/README.md#privacy-what-a-status-shares).

## Something's not working?

Run `p2p doctor <them>` (`/peers doctor <them>` in Claude Code), and ask them to run it for you. See [SUPPORT.md](../SUPPORT.md).

## Next

- Add a second device: `p2p link start` on one device and `p2p link join <code>` on the other ([CLI](../packages/p2p/README.md#commands)).
- Add a second relay, for example one a friend's group runs: `p2p relays add <url>`. That way one relay going down loses nothing.
- Learn the [concepts](concepts.md), or read the [threat model](security/threat-model.md).
