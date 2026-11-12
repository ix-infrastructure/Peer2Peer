# Roadmap

> **Everything on this page is planned, not built**, unless it's marked ✅. The order is a rough priority, and the dates aren't promises. Protocol-level items go through the [RFC process](../GOVERNANCE.md#how-the-protocol-evolves) before any code merges, and their details may change there.

Each item has an issue labelled `roadmap`: [roadmap issues](https://github.com/ix-infrastructure/Peer2Peer/issues?q=is%3Aissue+label%3Aroadmap), with the short list in [#14](https://github.com/ix-infrastructure/Peer2Peer/issues/14). Comment on any issue, or pick one up.

## Where we are today ✅

- **Released on npm:** `@peer2peer/core`, `relay`, `codex-bridge`, `cli` and `ext-ix`, **v0.1.0** and **v0.1.1**, published with provenance and always at the same version ([CHANGELOG](../CHANGELOG.md), [releasing.md](releasing.md)). The relay install scripts are pinned to the v0.1.1 source.
- Protocol **v3, draft 3**: identities, devices, rotation, friends, circles (including open circles), rosters, envelopes, open relays, short-code invites, profiles, proofs, status `caps` and `agents`.
- The `p2p` CLI, the open relay, the Claude Code mod, the Codex bridge and the optional Ix extension, working end to end with integration tests over real relays.
- **Invite links** that make someone a friend and join them to the circles you chose, in one step.
- **`p2p tui`**, a full-screen terminal UI: people and their sessions, held items, messages, send and health.
- **Compatibility across versions (protocol 3.1):** peers on different versions work together on every feature they share, and a feature only one side has drops out quietly. A cross-version matrix checks every pull request and release against the previous two releases. See [compatibility.md](compatibility.md).
- **Per-person trust:** `p2p trust` decides whose messages reach a session that approves its own tool calls without being held.
- **Members-only relays, and relays on any machine:** a relay can admit only its group, and one install script runs a relay on Linux, macOS, Windows or a small board, with a small-device preset. See [run-a-relay-on-any-machine.md](run-a-relay-on-any-machine.md).
- **Delivery receipts** (`shown`, `held`, `declined`, …), end-to-end encrypted, and **offline delivery**: messages wait at the relays for an offline session, or in this device's outbox when no relay can be reached.
- **Project boundaries:** a session reaches only who every project it works in is shared with, and a private project keeps it private.

New in **v0.1.1**:

- **Message history** (`p2p history`, `/peers history`, the TUI's Messages screen): what this device sent and received, encrypted at rest and kept only on this device (30 days by default).
- **Send to another session on the same device** (`p2p send --to "<you> [ref]"`), with your agent sessions' messages held like a peer's in a session that approves its own tool calls (`p2p own-agents`), and turn caps for your own sessions.
- **Shares that cover subfolders** (`p2p project share --subfolders`, opt-in) and **`p2p session show`**, which says what a session is bound to, who it reaches and why it is private.
- **Ix, optional and recommended:** `p2p setup` enables the `ix` extension when it finds Ix and `@peer2peer/ext-ix` already installed, with your consent, and says how to get them otherwise. Nothing is ever installed for you. `p2p doctor` has an Ix section.
- **Local graph memory:** with the Ix extension enabled, your own sessions in shared projects are recorded into your **local** Ix graph as they run. Every Ix call goes through one graph-target chokepoint, which today is always local.

## Ix as the context layer

Epic [#41](https://github.com/ix-infrastructure/Peer2Peer/issues/41). Peer2Peer carries live events between agents and people, and Ix graphs are the durable context they point into: a local graph on every machine that has Ix, and optionally a shared graph for a team. The protocol core (`packages/core`, the relay, the wire format) stays free of Ix code, so the open network works for any client, and Ix stays optional.

1. ✅ **Ix, optional and recommended** (v0.1.1). `p2p setup` detects Ix and `@peer2peer/ext-ix` and offers to enable the extension; it never installs anything. Without Ix everything still works, with today's fallbacks.
2. ✅ **Local graph as memory** (v0.1.1). Sessions in shared projects are written into your local graph as they happen. Private projects are never recorded.
3. **Shared graph** (next). A team graph in the cloud: a project shared with a circle writes its sessions, notes and context there, so every member's agents can query it as well as receive pushed events. Its API contract is settled first.
4. **Real time over Peer2Peer, durable in the graph** (planned). Live events (status, messages, "changed X, affects Y") stay end-to-end encrypted envelopes, and each one links to graph nodes, so an agent can pull full context on demand.
5. **Project boundaries apply to graphs** (planned; partly built). A private project never writes to a shared graph, and a shared project writes only to the shared graph of the circle it's shared with. The chokepoint this needs shipped in v0.1.1: every Ix call already resolves its graph target there, and every target is local until shared graphs exist.
6. **An honest encryption story** (planned). Relays see only ciphertext; a cloud graph holds plaintext its operator can read. The docs and `p2p doctor` say which graph a project writes to (`p2p project show` and `p2p doctor` already print each project's graph target), and "local only" stays first class.

## Relays

- **Bring your own relay.** There's no public relay at launch: each group runs its own (one Docker container, small enough for a Raspberry Pi) or uses one a friend runs, and invite codes carry the inviter's relays. No relay is built into the source, so `p2p setup` takes your group's relay URL. A public relay may come later; the draft recipe is in [future/public-relay.md](future/public-relay.md).
- **Relays on any hardware** ([#4](https://github.com/ix-infrastructure/Peer2Peer/issues/4)): the Windows installer and the small-device preset verified on real machines, then a relay conformance kit, and possibly a very small relay for tiny devices.
- **Tailcat as a transport** ([#29](https://github.com/ix-infrastructure/Peer2Peer/issues/29); the direct path needs an RFC): reach a relay at home without a domain, a TLS certificate or port forwarding, through a WireGuard tunnel with NAT traversal, and later a direct path between two online devices, with the relay mailbox as the fallback. End-to-end envelope encryption stays the security boundary either way.

## A friendlier CLI

In progress. Make `p2p` easy to read and easy to use:

- **Interactive pickers** with arrow keys, space, Enter and filtering, only on a terminal. For example, `p2p invite ben` lets you pick the circles to join him to, then an expiry, then prints the link prominently. The same goes for choosing a default circle, inviting to or leaving a circle, approving held items, removing someone, sending and trusting.
- **Readable output:** aligned tables, colour for state, relative times, names first with fingerprints dimmed, and empty states that say what to do next. `p2p` with no arguments shows a home screen.
- **Nothing changes for scripts:** without a terminal, with `--json` or with `CI=1`, every command behaves exactly as today, so agents, the Claude Code mod and the Codex bridge are unaffected. `NO_COLOR` is respected.

## Unique usernames (handles)

**Needs an RFC** before any code; this is a design for discussion.

Today a person shows up as `name@fingerprint`, because names are self-chosen and not unique. A handle would be a unique, human-readable name that maps to exactly one userId. There are no accounts and no central server, so uniqueness has to come from something already globally unique, never from a database run as the only authority. Three kinds are proposed:

- **Domain handles**, such as `ann.example.org`: unique because DNS is. Verified by a DNS TXT record or an HTTPS `.well-known` file that lists the userId, building on today's `dns` proof. An organisation can give its people handles under its domain, and take them back when they leave.
- **GitHub handles**, such as `gh:ann`, from today's `github` proof.
- **Community namespaces**, for people with neither: a plain, open-source registrar, first come first served, rate-limited, with an append-only transparency log so it can't silently re-point a name. Anyone can run one under their own domain, so each is one namespace among many, not the root.

Every handle is **verified by the client** (DNS, HTTPS or GitHub, with caching and rechecks), never trusted from a relay. A handle points at the **userId**, so it survives new devices, sessions and updates, and on a key rotation it is re-pointed by a record signed with the old key. A verified handle replaces `name@fingerprint` in listings, with a ✓, petnames still win locally, and a broken or changed handle is shown loudly, never silently followed. Open questions, such as naming policy, privacy of lookups and homoglyphs, are in the issue.

## Core support for UIs

Changes to core that let UIs, such as `p2p tui` and team web UIs, work well ([#6](https://github.com/ix-infrastructure/Peer2Peer/issues/6)):

- ✅ **Send to a named session on the same device** (v0.1.1), so a local UI can message your other local sessions.
- **Forward provenance:** a forwarded message carries its original sender, signed, so the receiving side applies *that* sender's hold and trust rules, not yours.
- **The sending session id** on messages to someone else's session, so replies go to the right session. For your own sessions, [RFC #48](https://github.com/ix-infrastructure/Peer2Peer/issues/48) proposes `fromRef` (the sending session) and `via` (whether you or an agent sent it), so another device of yours can deliver your own messages instead of holding them.
- **Inbox sessions:** a long-lived UI session is left out when you address a person without naming a session, and its presence and receipts are opt-in.

## Protocol and identity

- **Protocol 3.1, step 2:** once peers are on 3.1, device caps go on by default, so peers learn each other's features directly (see [compatibility.md](compatibility.md)).
- **An OS keychain backend** for keys (macOS Keychain, Windows Credential Manager, libsecret), with migration of existing keys, and `p2p doctor` reporting the backend in use. Today keys are in 0600 files under `~/.p2p`.
- **Circle version floors** ([RFC #37](https://github.com/ix-infrastructure/Peer2Peer/issues/37)): an optional, signed minimum version for a circle ("this circle needs Peer2Peer ≥ X"), so a feature that only makes sense circle-wide can be required. Members below it stay members and are told to update; it takes effect at least 14 days after it is announced, and is never a maximum.
- **Fork detection when a relay is cut short** ([#28](https://github.com/ix-infrastructure/Peer2Peer/issues/28)): find a forked identity document (a rotation signed with a stolen key, beside the real head) even when a relay's answer is cut short, without letting one hostile relay force every refresh incomplete.

## Footprints and overlap

Today: a session shares its repo-relative changed files and its subagents' files, and the Claude Code mod and the Codex bridge flag a **same-file** overlap. With the Ix extension, they also flag connected-file ("semantic") overlap.

Next:
- **Richer footprints:** declared intent ("about to touch `auth/*`") before the edit, not only files already changed; symbol- and region-level footprints where a graph is available.
- **Overlap you can act on:** suggested coordination ("Ben's session is mid-refactor of `token.ts`: wait, pair, or split the work"), and snoozing or acknowledging a flag.
- **Branch- and PR-aware overlap:** compare against peers' open branches, not only live sessions.

## Project circles and open-source discovery

- **Project circles:** a circle tied to a repository, which contributors' agents can find and join with the maintainers' policy (invite or open, with the existing open-circle protections).
- **Discovery:** a way for an open-source project to advertise its circle, for example a file in the repo plus a proof that ties the circle owner to the repo, so contributors can join without a personal invite.
- **Maintainer tools:** contributor roles, rate limits for newcomers, and moderation that builds on circle admins and holds.

## Circle compute

Sharing resources within a circle whose members already trust each other:

- **Shared CI runners:** a member offers spare capacity to run a circle-mate's tests, with explicit per-job consent, isolation (containers or VMs) and no access to the donor's secrets.
- **Local model inference:** a member with a GPU serves an open-weight model to the circle's agents, so a team can share a local model instead of every laptop running one.

Both are opt-in per circle and per member, and never go through relays as a general proxy (see [metadata privacy](#metadata-privacy) for why relays don't carry web traffic).

## Metadata privacy

Each step needs an RFC.

v3 encrypts content end to end, but **a relay can still see which mailboxes talk to which, how much and when** ([threat model](security/threat-model.md#what-each-party-can-see)). We plan to shrink that, step by step:

- **Sealed sender:** the sending identity moves inside the encryption, so a relay can't tell who sent an envelope, only which mailbox it's for. This needs anonymous ways to prove a sender holds a capability, and a new answer for per-sender rate limits and spam.
- **Padding and timing cover:** envelopes padded to a few fixed sizes, and optional cover traffic and batched delivery, so sizes and timing reveal less.
- **Optional two-hop onion routing, between relays only:** a client can wrap an envelope for a first relay that forwards it to the recipient's relay, so no single relay learns both who sent it and who receives it. **Relays only ever talk to other Peer2Peer relays. They are never exits to the open web, by design.** A volunteer running a community relay must never be the apparent source of someone else's web traffic. That's a legal liability few operators can carry, and it invites abuse (scraping, attacks, illegal content) that would get relays blocked and shut down. Keeping relays as Peer2Peer-only mailboxes keeps running one cheap, safe and boring.
- **Optional Tor transport:** relays can be offered as `.onion` services, and clients can connect through a local Tor, hiding the client's IP from the relay. **Strictly opt-in**, because it costs latency.
- **Bring-your-own egress:** a client-side setting to route *your own agent's* web access (fetches, package installs, research) through a proxy you choose (Tor, a VPN, a corporate proxy). That's your traffic on your terms. Relays never carry web traffic.

## More agents and models: bring your own

Today: Claude Code (mod), Codex (bridge), and any program through the `p2p` CLI's JSON interface. See [clients.md](clients.md).

Next:
- **A generic adapter** for local and open-source models and other providers: Ollama, llama.cpp, vLLM and any OpenAI-compatible endpoint, plus agent harnesses like Aider, Continue, Cline, OpenHands and Goose. The adapter would enforce the hold rule, inert peer text, turn caps and secret hygiene itself, so each integration doesn't have to reinvent them.
- **Generalising the MCP server**, so its hold rule can use a client-declared, verifiable approval mode instead of Codex-specific records.
- **A Codex plugin package** (`.codex-plugin`) instead of the installer.
- **Model-agnostic status summaries:** the Claude Code mod uses Haiku today. Let users pick any model, including a local one, or none.

## Have an idea?

Open a [feature request](https://github.com/ix-infrastructure/Peer2Peer/issues/new?template=feature_request.yml), or a [protocol RFC](https://github.com/ix-infrastructure/Peer2Peer/issues/new?template=protocol_rfc.yml) if it touches the wire.
