# Getting help

## First, ask `p2p doctor`

Most "I can't see them" problems are a clock, a relay or a sharing setting, and the doctor checks all of them:

```sh
p2p doctor               # this device: identity, relays, clock, default circle, what you share
p2p doctor ben           # can you see ben? friendship, documents, relays, capabilities, sessions
```

In Claude Code, use `/peers doctor [user]`. Ask the other person to run `p2p doctor <you>` on their side too. Each line is ✓, ✗ or ?, with a one-line fix. The doctor is read-only and never prints keys or codes.

If a command seems stuck, run it again with `P2P_DEBUG=1`. That logs every network step (relay URLs, userIds and frame types; never keys, capabilities, envelopes, codes or phrases), and it's the most useful thing to include in a bug report.

## Then, the docs

- [Getting started](docs/getting-started.md) and the [FAQ](docs/faq.md)
- The [CLI reference](packages/p2p/README.md), including Windows notes
- The [Claude Code mod](mods/claude/peer2peer/README.md) and the [Codex bridge](packages/codex-bridge/README.md)
- [Running a relay](docs/run-a-relay.md)

## Still stuck?

| For | Go to |
|---|---|
| Questions, ideas, show and tell | The [Ix Discord](https://discord.gg/ncEYVHVqZ8) (shared with the Ix project) |
| A reproducible bug | [Open a bug report](https://github.com/ix-infrastructure/Peer2Peer/issues/new?template=bug_report.yml) |
| A feature request | [Open a feature request](https://github.com/ix-infrastructure/Peer2Peer/issues/new?template=feature_request.yml) |
| A protocol change | [Open a protocol RFC](https://github.com/ix-infrastructure/Peer2Peer/issues/new?template=protocol_rfc.yml) |
| Running a relay for your group | [Relay operator issue](https://github.com/ix-infrastructure/Peer2Peer/issues/new?template=relay_operator.yml) |
| **A security problem** | **Privately**, per [SECURITY.md](SECURITY.md). Never in a public issue |
| Kartr (the paid org add-on) | [contact@ix-infra.com](mailto:contact@ix-infra.com) |

**Before posting**, remove anything secret: backup phrases, invite or link codes (`relay/XXXX-…`, `p2p-link:…`), anything from `~/.p2p`, and private repo or file names you don't want public. Addresses (`name@xxxx-xxxx-xxxx-xxxx`) and relay URLs are fine.

Peer2Peer is maintained by a small team plus volunteers, and there's no support SLA for the free project. Well-described issues with `p2p doctor --json` output get answered fastest.
