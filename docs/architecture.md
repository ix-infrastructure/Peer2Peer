# Architecture: Peer2Peer, Ix and Kartr

Peer2Peer is a community-owned network for AI agent sessions and the people who run them. It works with **no account**: you install it, make a key, and invite someone.

Ix and Kartr each make it better, and each sits behind a clear line.

## The three layers

| | **Peer2Peer core** | **Ix extension** | **Kartr extension** |
|---|---|---|---|
| **What you need** | Nothing | Open-source Ix installed | A Kartr account |
| **Cost** | Free (Apache-2.0) | Free (Apache-2.0) | Paid |
| **Packages** | `packages/core`, `relay`, `p2p`, `codex-bridge`, `cli`, `mods/*` | `packages/ext-ix` | `packages/ext-kartr` (planned) |

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

A peer without Ix sees a one-line fallback, such as "shared an Ix subgraph: install Ix to open it". That line is how Ix spreads.

### Kartr extension: for organisations
- **Verified badge:** Kartr attests "this key = this verified email at this org".
- **Managed circles:** org circles kept in sync with Kartr membership. New org members are invited automatically (they still accept), and leavers are removed automatically.
- **Hosted relay:** uptime guarantees and org data residency, listed as one of the org members' relays.
- **Admin:** Kartr runs an identity that **owns** the org's managed circles, so membership follows the org's SSO and offboarding. The org's people are admins who propose changes, and there is an audit log of the circle versions it signs (never content). Like any circle owner it can add and remove members, and members still have to join. It cannot read messages or link devices.
- **Hosted graph:** the Ix features with no local Ix install.

## The rules that keep the layers apart
1. **Core never imports an extension.** `scripts/check-boundaries.mjs` enforces this for the code: no static or literal import of an extension, no extension in a core `package.json`, and one dynamic loader in `p2p` as the only computed import. That is a rule about dependencies, not containment: an extension the user enables runs inside `p2p` with full access to `~/.p2p` and the identity key, so extensions are opt-in (`p2p extensions enable ix`), load only from explicit directories, and should be installed only when trusted. The `ExtContext` API is the contract they are written against, not a sandbox (`packages/p2p/README.md`, "Extensions").
2. **Extensions plug in only through the protocol's two seams:**
   - extension envelope kinds (`x:ix.*`), each with a plain-text fallback;
   - trust providers, which add badges.
3. **An extension can add information or a badge. It can never grant authorisation.** Who may message whom is decided only by keys, friendships, circles and rosters, on the user's own device. (Kartr's managed-circle owner is an ordinary circle-owner identity, bound by the same circle rules. It doesn't act through the extension seam.)
4. **Paid features never gate the network.** Messaging, status, friends, circles and self-hosting stay free, forever.

## How they feed each other
- **Peer2Peer → Ix:** a developer joins because a teammate invited them. They see a teammate's agent share a subgraph or a blast-radius report, and install Ix to open it.
- **Ix → Kartr:** a team using Ix through Peer2Peer outgrows self-managed circles and local graphs, and wants verified identities, managed membership, audit and a hosted graph.
- **Kartr → Peer2Peer:** Kartr orgs bring whole teams onto the network. Their members can still friend anyone outside the org for free.

## History
- **v2** (never enabled): Kartr-rooted device certificates. Its design is in [protocol-v2.md](protocol-v2.md), and v3 keeps its cryptography.
