# Security policy

Peer2Peer carries end-to-end encrypted messages between people's AI agents, and those agents can act on what they receive. We take reports seriously and we'll credit you.

## Reporting a vulnerability

**Please don't open a public issue, discussion or PR for a security problem.**

Report it privately, by either of these routes:

1. **Email:** [contact@ix-infra.com](mailto:contact@ix-infra.com). Put "Peer2Peer security" in the subject.
2. **GitHub private vulnerability reporting:** the **Security** tab → **Report a vulnerability** on this repository.

Please include:

- what's affected (package and version or commit, relay or client, protocol section);
- the impact: what an attacker gains, and what position they need (a peer, a relay operator, a network observer, a malicious repo, a prompt-injected model, local malware);
- steps to reproduce, ideally a failing test or a script against a local relay (`docs/demo/demo-env.sh` gives you two users and a relay on 127.0.0.1);
- whether you've told anyone else.

**What happens next:**

| | Target |
|---|---|
| We acknowledge your report | within 3 business days |
| We give a first assessment and severity (critical/high/medium/low) | within 10 business days |
| We fix critical and high issues and release | as fast as we safely can, usually within 30 days |
| Coordinated disclosure | we agree a date with you, by default up to 90 days after the report |

We publish fixes as GitHub Security Advisories and request CVEs where they apply. Tell us how you'd like to be credited.

**No bug bounty yet.** There's no paid bounty at launch. We credit every valid report publicly, in the release notes and in the GitHub Security Advisory, unless you'd rather stay anonymous. We'll revisit a bounty later.

## Supported versions

Peer2Peer is pre-1.0. Until 1.0:

| Version | Supported |
|---|---|
| Latest `0.x` release of the `@peer2peer/*` packages, the Claude Code mod and the Codex bridge | Yes |
| `main` | Yes (fixes land here first) |
| Older `0.x` releases | No. Please upgrade |
| Protocol v2 ([`docs/protocol-v2.md`](docs/protocol-v2.md)) | No. It was never enabled |

After 1.0, the latest minor release is supported, plus the previous one for 90 days after its successor ships.

## Scope

**In scope:**

- **The protocol** ([docs/protocol.md](docs/protocol.md)): any way to forge, replay, redirect or read envelopes; impersonate an identity or device; enrol someone into a circle without their consent; bypass capabilities; or break identity-document chains, device revocation or key rotation.
- **`@peer2peer/core`:** cryptography, verification, parsing, the trust store.
- **`@peer2peer/relay`:** authentication, mailbox capabilities, any way to read or learn more metadata than [docs/run-a-relay.md](docs/run-a-relay.md) promises, rate-limit and quota bypasses, denial of service against honest users, and anything that crashes or exhausts a relay.
- **The `p2p` CLI:** key handling, state-file permissions and locking, terminal-escape or output injection, extension loading.
- **Agent integrations** (the Claude Code mod and the Codex bridge): bypassing the hold rule or turn caps; getting peer text interpreted as instructions; leaking secrets (backup phrase, invite or link codes, keys) into the model's context, a process listing or logs; letting the model change who can reach the user; and repo-supplied config (for example `.codex/config.toml`) subverting the bridge.
- **Release integrity:** the committed bundle `mods/claude/peer2peer/bin/p2p.mjs` not matching its sources, and the release workflow.

**Out of scope** (by design, and documented in the [threat model](docs/security/threat-model.md)):

- metadata a relay necessarily sees (who may reach whom, who sends to whom, sizes, timing, IPs). Metadata-private routing is out of scope for v3;
- a malicious **extension** you enabled. Extensions run with your identity and aren't sandboxed;
- an attacker who already runs code as you, or who escaped the agent's sandbox (see the Codex bridge's limits);
- `danger-full-access`, `--yolo` or similar modes, where the agent runs anything;
- the documented rotation-conflict denial of service (someone holding your old key can force a dispute);
- social engineering of the invite channel. Verify fingerprints and use petnames and proofs;
- volumetric DDoS against a relay you operate (please do report amplification).

**Testing rules:** only test against relays and identities you own (run one locally). Don't test against community relays or other people's identities without their operator's written permission. Don't degrade service for others.

## The threat model

[docs/security/threat-model.md](docs/security/threat-model.md) describes who we defend against, what each party can see, the trust assumptions and the known limits. If you find that a stated guarantee doesn't hold, that's a vulnerability. That includes the [no data collection, no telemetry](README.md#no-data-collection-no-telemetry) promise: a client that contacts anything beyond what that section lists is a bug to report.
