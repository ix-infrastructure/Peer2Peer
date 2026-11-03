# @peer2peer/core

The client crypto core of [Peer2Peer](https://github.com/ix-infrastructure/Peer2Peer): self-certifying identities, device certificates, friendships, circles, rosters and end-to-end encrypted envelopes. It has no network code, and it depends only on the audited `@noble` and `@scure` libraries.

```sh
npm install @peer2peer/core
```

Entry points:

| Import | What it is |
| --- | --- |
| `@peer2peer/core/v3` | The Peer2Peer v3 protocol objects (identities, devices, friends, circles, envelopes, capabilities). Use this. |
| `@peer2peer/core/v3/node` | Node-only helpers for v3 (file-backed trust and key storage). |
| `@peer2peer/core` | The frozen v2 API, kept for existing integrations. |

The wire format is specified in [docs/protocol.md](https://github.com/ix-infrastructure/Peer2Peer/blob/main/docs/protocol.md). Most people want the `p2p` command ([`@peer2peer/cli`](https://www.npmjs.com/package/@peer2peer/cli)) rather than this library.

Needs Node.js 22 or newer. Licensed under Apache-2.0.
