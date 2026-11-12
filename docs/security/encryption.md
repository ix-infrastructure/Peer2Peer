# What is encrypted, what isn't

This page says where each kind of Peer2Peer data goes, and who can read it there. `p2p doctor` prints the same facts for your device, under **Where your data goes**, with each project's graph target. The [threat model](threat-model.md) has the full detail and the known limits; if this page and it disagree, the threat model wins, and please [tell us](../../SECURITY.md).

## In one table

| Data | Where it goes | Who can read it |
|---|---|---|
| Messages, statuses, rosters, delivery receipts, circle updates sent to members, and Ix items you share with peers (notes, footprints) | To the peers who may see them, through relays, as envelopes encrypted end to end to the recipient's devices | The recipients. Relays can't read the content, but see metadata (below) |
| A circle's signed chain (its name, owner, admins and members), on a **members-only relay** that admits that circle (`RELAY_ALLOW_CIRCLE`) | Pushed in plaintext (`circle-put`) by members, only to their own relays, so the relay can check who is a member | That relay's operator. Open relays and relays that don't follow the circle never get it |
| Your identity document (devices, relays, optional profile) | Published to your relays | Anyone: it is public by design |
| Message history (`p2p history`) | This device only: never synced, sent to a relay or shared | Encrypted at rest, but the key sits beside it (below) |
| The event log `p2p watch` reads | This device only | Recent message text is in the clear (below) |
| Graph memory and other Ix data | Your **local** Ix backend, for every project today | Ix stores it in plaintext on this machine |
| Each prompt you type in a session whose project is shared (Claude Code mod) | Haiku on your own Claude account, which turns it into the one-line status summary | Your model provider ([threat model](threat-model.md#what-each-party-can-see)). A private session makes no such call, and `P2P_SHARE_STATUS=0` turns it off |

Ix Infrastructure runs no servers in the Peer2Peer path and receives nothing ([no telemetry](../../README.md#no-data-collection-no-telemetry)).

## On the wire: end to end, but metadata shows

Every envelope is encrypted to the recipient's devices (X25519 and XChaCha20-Poly1305) and signed by the sending device. A relay can't read or alter the content. It **does** see, among other things:

- who may reach whom (from capabilities), and which mailboxes send to which (user and device ids);
- envelope sizes and timing, and source IP addresses;
- each envelope's plaintext header, including its **kind** (message, status, roster, an extension kind such as `x:ix.note`) and the target **session id**;
- your public identity document (devices, relays, optional profile).

**One exception to "content is encrypted": circles on a members-only relay.** A relay run with `RELAY_ALLOW_CIRCLE` admits a circle's current members, so it has to know who they are. Members push the circle's chain to it in plaintext (`circle-put`; see [Run a relay](../run-a-relay.md)): every version is signed, so the relay can't forge one, but it can read each version's name, owner, admins and members. A client pushes a chain only to its own relays (those in its identity document) and only for a circle it is a member of. An open relay, or one that doesn't follow that circle, never receives it.

v3 doesn't hide metadata. Choose relays you trust with it, or run your own. Sealed sender, padding and timing cover are [planned](../roadmap.md#metadata-privacy), not built. The exact list is in the [threat model](threat-model.md#what-each-party-can-see).

Once an envelope arrives, the recipient's device decrypts it. What a peer does with your text after that (keeps it in their history, imports a note into their own Ix graph) is on their machine, under their control.

## On this device

- **Message history** is sealed with ChaCha20-Poly1305 under a key of its own, `P2P_HOME/cli/history.key` (0600). There is no OS keychain backend yet, so that key sits next to the history and your device keys. Encryption keeps message text out of backups, indexers and a grep of the folder. It does **not** stop malware or an agent running as you, which can read both. `history.enabled: false` (or `P2P_HISTORY=0`) records nothing more, and `p2p history --clear` deletes it, the key included.
- **The event log** (`events.json`, at most 7 days and 2,000 events) still holds recent message text in the clear. `p2p history --clear` purges the messages there too.
- **Other state** (peers' statuses, rosters, circles, your device keys) is plain files in `P2P_HOME`, protected by your account's file permissions. Sandbox agents that shouldn't read it ([threat model](threat-model.md#the-hard-barrier-sandbox-your-agents)).

## Ix graphs: local only, in plaintext

Every `ix` call Peer2Peer makes or lets an extension make has a **graph target**, decided at one place (`graphTarget` in `packages/p2p/src/projects.ts`). Today every target is **local only**: your Ix backend on this machine (`http://localhost:8090`, or a loopback `ixEndpoint` in config.json). `p2p project show`, `p2p project ls` and `p2p doctor` print it for each project, with the reason.

- **Graph memory** writes sessions in shared projects into that local graph: their record (label, repository, branch), their status lines and the files they edited. Never message bodies, peers' statuses or other devices' sessions. Sessions in private projects are never recorded. It is on only with Ix, the Ix extension, and an Ix whose `ix note` is local. With Ix Pro installed, whose `ix note` writes to the cloud, nothing is written. Turn it off with `"ixMemory": false` in config.json or `P2P_IX_MEMORY=0`.
- **The local Ix backend stores what it gets in plaintext.** Peer2Peer doesn't encrypt it, and anyone with access to that backend (its data on disk, or its port on a shared machine) can read it. On a machine other people log in to, turn graph memory off ([threat model](threat-model.md#graph-targets-ix)).

"Local only" is the default and stays a first-class choice: nothing in Peer2Peer needs a cloud graph.

## Planned: a shared team graph

A shared team graph in the cloud (part of [epic #41](https://github.com/ix-infrastructure/Peer2Peer/issues/41)) is **planned, not built**. When it exists:

- it will be **opt-in per circle**: a project shared with a circle writes there only if that circle has a shared graph, and a private project never does;
- it will hold **plaintext that its operator can read**. Relays carry only ciphertext; a cloud graph is different, because the graph has to read the context to answer queries about it;
- `p2p doctor` and `p2p project show` will name it as the project's graph target, so you can always see which graph a project writes to.

Until then, no circle has a shared graph, and the code refuses to write graph memory to anything but a local target.
