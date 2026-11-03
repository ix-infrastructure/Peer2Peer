# Governance

Peer2Peer is an open protocol plus a reference implementation. The protocol has to outlive any one company, so it evolves in the open, and any conforming client or relay must be able to interoperate. This document says who decides what, and how.

> Peer2Peer is young. This model is deliberately light, and we'll revise it, through this same process, as the community grows.

## Roles

| Role | Who | Can |
|---|---|---|
| **Users and contributors** | Anyone | Open issues, discussions and PRs; comment on RFCs; run relays |
| **Committers** | Contributors with a record of quality changes in an area, nominated by a maintainer | Review PRs in their area, and triage issues |
| **Maintainers** | Listed below | Merge PRs, cut releases, accept or reject RFCs |
| **Security reviewers** | Maintainers (or committers) named below for security review | Required second review on security-sensitive changes; handle private vulnerability reports |
| **Lead maintainer** | One maintainer | Breaks ties, and is the final say on releases and RFCs when consensus fails |

### Maintainers

| Name | GitHub | Areas | Security reviewer |
|---|---|---|---|
| Tanner Kocher (**lead maintainer**) | [@TannerTorrey3](https://github.com/TannerTorrey3) | core, protocol, releases | yes |
| Ian Hock | [@KageBinary](https://github.com/KageBinary) | p2p CLI, Claude Code mod, Codex bridge, relay | |

[`.github/CODEOWNERS`](.github/CODEOWNERS) matches this table.

**Becoming a maintainer:** existing maintainers nominate someone who has made sustained, high-quality contributions and reviews, and confirm them by lazy consensus (no objection within 7 days). Maintainers who are inactive for 6 months move to emeritus, and can come back by asking.

## How decisions are made

- **Day-to-day changes** (bug fixes, features within the spec, docs) need one maintainer approval. The PR author can't approve their own PR.
- **Security-sensitive changes** (`packages/core`; relay authentication, capabilities, storage or limits; the hold rules and guards in the agent integrations; release tooling) need a second approval from a security reviewer.
- **Larger or contested changes** are decided by **lazy consensus** among maintainers on the issue or PR. If someone objects, we discuss. If there's still no consensus after a reasonable time, the lead maintainer decides and writes down why.
- **Protocol changes** go through the RFC process below. Code that changes wire behaviour doesn't merge before its RFC is accepted.

Everything is decided in public (issues, PRs, discussions), except security reports and Code of Conduct cases.

## How the protocol evolves

The normative spec is [docs/protocol.md](docs/protocol.md) (currently **v3, draft 3**). Its rule: a conforming client implements that document and nothing from any extension.

### What needs an RFC

You need an RFC for any change a *second, independent implementation* would have to match:

- a new or changed envelope kind, field, signed-object type, size limit or validation rule;
- relay behaviour that clients rely on (§5), including limits clients must respect;
- identity, device, circle, roster or rotation semantics;
- a new extension namespace (§8.1) or trust-provider proof kind (§8.2).

Clarifications, typo fixes and new "readings chosen while implementing" (P3), which record an interpretation without changing behaviour, can go straight to a PR, with one maintainer approval.

### The RFC process

1. **Propose:** open a [Protocol RFC issue](.github/ISSUE_TEMPLATE/protocol_rfc.yml) covering motivation, the proposed text, compatibility, security analysis and alternatives.
2. **Discuss:** at least **14 days** of open comment for normative changes. Security reviewers must comment.
3. **Decide:** maintainers accept, reject or ask for changes by lazy consensus, and the lead maintainer decides if needed. The decision and the reasons are recorded on the issue.
4. **Spec PR:** the accepted text lands in `docs/protocol.md`, marked as an amendment or a new draft, with a review-log entry. Test vectors (`packages/core/src/**/testdata`) are updated in the same PR if the wire format changed.
5. **Implementation:** the reference implementation follows. Behaviour gated on a version or a capability (for example status `caps`) rolls out in two steps, so older peers keep seeing upgraded ones.

### Compatibility rules

The full policy, and what each release must interoperate with, is [docs/compatibility.md](docs/compatibility.md).

- Receivers **ignore unknown fields** (protocol 3.1), except a field an object lists in `crit`, and stay strict on everything security depends on: signatures, ids, sizes, authorisation, replay. A new field that restricts what an object allows must be critical.
- Additive only within a protocol version; every release interoperates with the previous two, checked by the cross-version matrix.
- A breaking change bumps the protocol version (`p2p/v3` → `p2p/v4`). Relays advertise the version they speak in `/.well-known/p2p-relay.json`.
- Extensions never change rules in §2–§5. They can add information or a badge, never authorisation.

### Extension namespaces

New namespaces (`x:<ns>.*`) are registered by PR to §8.3 of the spec, with a SPEC.md for the kinds and a plain-text fallback for each. Registration is first come, first served, for any project that follows §8. The `ix` and `kartr` namespaces are reserved by their current registrations.

## Releases

Maintainers cut releases following [docs/releasing.md](docs/releasing.md): lockstep versions across the `@peer2peer/*` packages, tag-triggered publishing with npm provenance, and a required reviewer on the `npm-publish` environment.

## Relationship with Ix Infrastructure

Ix Infrastructure, Inc. created Peer2Peer, holds the copyright for its own contributions, employs maintainers, and sells optional add-ons ([Kartr](README.md#free-core-optional-add-ons)). Ix Infrastructure commits to this:

- the core network (messaging, status, friends, circles, the clients and self-hosting) stays free and Apache-2.0;
- paid features never gate the network, and extensions can never grant authorisation;
- protocol decisions go through the public RFC process above, the same for everyone.

## Trademark and name

"Peer2Peer" and the Peer2Peer logo are trademarks of Ix Infrastructure, Inc. Forks and community relays are welcome, under any name you like, as long as it doesn't suggest they're the official project or run by us. Saying your fork or relay is "compatible with Peer2Peer" is fine and encouraged.

The Apache-2.0 license doesn't grant rights to project names or marks (section 6).

## Code of Conduct

Everyone who takes part follows the [Code of Conduct](CODE_OF_CONDUCT.md). The maintainers enforce it.

## Changing this document

Changes to this document follow the same lazy-consensus process, with at least 7 days for comment.
