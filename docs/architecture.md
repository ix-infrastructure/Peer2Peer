# Architecture: Peer2Peer and Ix

Peer2Peer is a community-owned network for AI agent sessions and the people who run them. It works with **no account**: you install it, make a key, and invite someone.

Ix, an open-source code graph, makes it better. It is optional and recommended, and it sits behind a clear line.

## The two layers

| | **Peer2Peer core** | **Ix extension** |
|---|---|---|
| **What you need** | Nothing | Open-source Ix, installed by you |
| **Cost** | Free (Apache-2.0) | Free (Apache-2.0) |
| **Packages** | `packages/core`, `relay`, `p2p`, `codex-bridge`, `cli`, `mods/*` | `packages/ext-ix` |

### Peer2Peer core: the network
- **Identity:** a key you generate (`alice@k7f2-qx9a-3m4n-5p6q`). Devices are linked by scanning or typing a one-time code, with an optional backup phrase.
- **Social:** friends (invite links and codes), circles (teams or groups), and per-session sharing.
- **Messaging:** end-to-end encrypted session-to-session messages. In Claude Code they appear as built-in cross-session messages (`ListAgents` / `SendMessage`).
- **Awareness:** each session's one-line working-on status and the files it is changing; conflict flags when two sessions change the same file; idle notifications.
- **Relays:** an open-source server anyone can run (`npx @peer2peer/relay`, or the optional Docker image). There's no public relay: each group runs its own, or uses one a friend runs. Each user lists 1–5 relays, and every message goes to up to 3 of the recipient's relays.
- **Clients:** the `p2p` CLI, the Claude Code mod, and the Codex bridge.

### Ix extension: the graph makes it smarter
Ix is open source too, so these features need only an install.
- **Notes:** share an Ix session note, which lands in the peer's graph once they accept it, if they have Ix.
- **Subgraph references:** "look at `auth/*` in my graph". The recipient's agent opens the exact subgraph.
- **Blast-radius reports:** attach an impact report of your change, made by Ix from the graph.
- **Semantic conflicts:** flag two sessions whose changes touch *connected* parts of the codebase, not just the same file.

- **Graph memory:** your own sessions in shared projects are recorded into your **local** Ix graph as they run (see [concepts.md](concepts.md)).
- **Graph targets:** every Ix call Peer2Peer makes goes through one chokepoint that decides which graph a project's work may reach. Today that is always your local graph. A shared team graph is planned (see the [roadmap](roadmap.md#ix-as-the-context-layer)).

A peer without Ix sees a one-line fallback, such as "shared an Ix subgraph: install Ix to open it". Ix is optional and recommended, and Peer2Peer never installs it: `p2p setup` asks (default No) and only prints the install command for you to run, and turning on the extension is always your own decision.

## The rules that keep the layers apart
1. **Core never imports an extension.** `scripts/check-boundaries.mjs` enforces this for the code: no static or literal import of an extension, no extension in a core `package.json`, and one dynamic loader in `p2p` as the only computed import. That is a rule about dependencies, not containment: an extension the user enables runs inside `p2p` with full access to `~/.p2p` and the identity key, so extensions are opt-in (`p2p extensions enable ix`), load only from explicit directories, and should be installed only when trusted. The `ExtContext` API is the contract they are written against, not a sandbox (`packages/p2p/README.md`, "Extensions").
2. **Extensions plug in only through the protocol's two seams:**
   - extension envelope kinds (`x:ix.*`), each with a plain-text fallback;
   - trust providers, which add badges.
3. **An extension can add information or a badge. It can never grant authorisation.** Who may message whom is decided only by keys, friendships, circles and rosters, on the user's own device.
4. **Paid features never gate the network.** Messaging, status, friends, circles and self-hosting stay free, forever.

## How they feed each other
- **Peer2Peer → Ix:** a developer joins because a teammate invited them. They see a teammate's agent share a subgraph or a blast-radius report, and install Ix to open it.
- **Ix → Peer2Peer:** a team that already uses Ix gets live context between its agents: notes, subgraph references and impact reports travel over Peer2Peer, end-to-end encrypted.

## History
- **v2** (never enabled): device certificates rooted in a hosted attestation authority. Its design is in [protocol-v2.md](protocol-v2.md), and v3 keeps its cryptography.
