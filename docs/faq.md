# FAQ

**Is it really account-free?**
Yes. Your identity is a key generated on your device. There's no sign-up, email or phone number. Relays authenticate devices by signature.

**Can the relay read my messages?**
No. Message text, status contents, circle names and rosters are end-to-end encrypted (one exception below). A relay *can* see:
- who may reach whom;
- who sends to whom;
- each envelope's plaintext header: the kind (message, status, roster, circle, extension kinds such as `x:ix.note`, …), the target session id, and sequence and timestamp counters;
- sizes, timing and IPs;
- on a members-only relay that admits a circle's members (`RELAY_ALLOW_CIRCLE`), that circle's signed chain: its name, owner, admins and members.

See the [threat model](security/threat-model.md#what-each-party-can-see). Metadata privacy is [planned](roadmap.md#metadata-privacy).

**Is there a public relay I can just use?**
No, and none is planned for launch. Peer2Peer is "bring your own relay": your group runs one, or uses one a friend runs. A relay is one Docker container (or one Node process and one SQLite file), small enough for a Raspberry Pi. See [run a relay](run-a-relay.md).

**Do I need to run a relay?**
Only one person in your group does, or nobody, if a friend's relay will carry your group. Only the person inviting needs a relay URL. Joiners use the code's relay, and should add a second one they trust (`p2p relays add <url>`).

**Which agents work?**
Claude Code (plugin) and OpenAI Codex CLI (MCP + hooks) today, plus anything that can run the `p2p` CLI. Local and open-source models and other harnesses are on the roadmap. See [clients.md](clients.md).

**Does Peer2Peer collect data or send telemetry?**
No. Ix Infrastructure runs no servers in the Peer2Peer path and receives nothing from it: no telemetry, analytics, crash reports or update checks. The clients talk only to relays, and to GitHub or DNS when you verify a proof. See [No data collection, no telemetry](../README.md#no-data-collection-no-telemetry), including what your relay's operator can see.

**Does it send my prompts anywhere?**
Peer2Peer itself doesn't. In the Claude Code mod, each prompt goes to Haiku on **your own** Claude account to write a one-line status. `P2P_SHARE_STATUS=0` turns that off, and then only busy/idle, label, repo and branch are shared. The Codex bridge never sends prompts. The model writes its own summary.

**Can a peer make my agent do things?**
Peer text is framed as data, not instructions. In a session that approves its own tool calls, every message from another person waits for your **Deliver** click. Peers can start at most 3 turns per 10 minutes. See [how the integrations defend you](security/threat-model.md#how-the-agent-integrations-defend-you).

**Someone's online but I can't see their sessions.**
Run `p2p doctor <them>` (or `/peers doctor <them>`), and have them run it for you. The usual causes are a session not shared with you, a clock that's off, or no shared reachable relay.

**Names aren't unique, so how do I know it's really Ben?**
Check the fingerprint (`ben@ayrn-mrvm-…`) over a channel you trust, set a petname, or ask for a proof (`p2p proof verify ben`). Every decision uses the full userId.

**I lost my laptop.**
If it was an ordinary device: `p2p devices revoke <did>` from another device. If it held your identity key: `p2p identity rotate --exclude <did>` (or `/peers rotate`) on a key holder you still have, or `p2p backup restore` with your phrase on a new device and then rotate.

**Where are my keys?**
In `~/.p2p` (or `P2P_HOME`): 0700 directories and 0600 files. There's no OS keychain backend yet; it's [planned](roadmap.md#protocol-and-identity).

**What's the difference between Peer2Peer and Ix?**
Peer2Peer is the free, open network. Ix is an open-source code-graph tool with an optional, recommended extension for richer sharing and graph memory. You install Ix yourself; Peer2Peer never installs it. Paid features never gate the network. See [architecture.md](architecture.md).

**Does it work on Windows?**
The CLI does (Windows 10/11, Node 22). See [the Windows notes](../packages/p2p/README.md#windows). The Codex bridge fails closed on releasing held messages there.
