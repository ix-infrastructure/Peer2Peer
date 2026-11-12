# Peer2Peer documentation

| Start here | |
|---|---|
| [Getting started](getting-started.md) | Install, set up, invite a friend, and see each other's sessions |
| [Concepts](concepts.md) | Identities, devices, relays, friends, circles, sessions, envelopes, in plain words |
| [FAQ](faq.md) | Common questions |
| [Demo](demo/README.md) | A reproducible two-user demo on a local relay, plus VHS tapes for the GIF |

| Use it | |
|---|---|
| [CLI reference](../packages/p2p/README.md) | Every `p2p` command, JSON output, configuration, doctor, Windows |
| [Claude Code mod](../mods/claude/peer2peer/README.md) | `ListAgents` / `SendMessage` across machines, `/peers`, privacy, opt-outs |
| [Codex bridge](../packages/codex-bridge/README.md) | MCP server and hooks for OpenAI Codex CLI |
| [Clients: bring your own agent](clients.md) | Integrating any agent or model, and the rules an integration must enforce |
| [Extensions](extensions.md) | How extensions work, their trust model, and the Ix extension |

| Understand it | |
|---|---|
| [Architecture](architecture.md) | The two layers (core and the optional Ix extension) and the rules that keep them apart |
| [Protocol](protocol.md) | The normative wire spec, v3 draft 3, with its review log |
| [Compatibility](compatibility.md) | How peers on different versions interoperate: the policy, the `crit` rule, device caps, and the cross-version matrix |
| [Threat model](security/threat-model.md) | What's protected, from whom, what relays see, and the known limits |
| [Roadmap](roadmap.md) | What's planned, clearly marked |

| Operate and maintain it | |
|---|---|
| [Run a relay](run-a-relay.md) | For whoever runs your group's relay: Docker or Node, TLS, limits, discovery, operations, the privacy promise |
| [Run a relay on any machine](run-a-relay-on-any-machine.md) | A private team relay on hardware you have (old laptop, mini PC, Raspberry Pi, Jetson, NAS, cheap VPS, Windows): install scripts, the `small` preset, storage, Tailscale or Cloudflare Tunnel, backups, upgrades |
| [A public relay (future)](future/public-relay.md) | Not planned for launch. The hardened recipe for an open relay on a small VM (Docker Compose + Caddy) or Fly.io: firewall, backups, upgrades, monitoring, logs, abuse. Most of it applies to any internet-facing relay |
| [Releasing](releasing.md) | How maintainers publish the npm packages |
| [Protocol v2 draft](protocol-v2.md) | The never-enabled v2 draft whose rules v3 cites |

Project policies: [Contributing](../CONTRIBUTING.md) · [Governance](../GOVERNANCE.md) · [Security](../SECURITY.md) · [Support](../SUPPORT.md) · [Code of Conduct](../CODE_OF_CONDUCT.md)
