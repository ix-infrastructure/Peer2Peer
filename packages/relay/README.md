# @peer2peer/relay

The open relay for [Peer2Peer](https://github.com/ix-infrastructure/Peer2Peer) v3: a small store-and-forward server for end-to-end encrypted envelopes, public identity documents and short-lived device-link mailboxes. Anyone can run one, and every conforming client works with every conforming relay. It never holds a key, so it can't read what it carries.

You need Node.js 22.13 or newer (it uses the built-in `node:sqlite`; there is no database server and no native dependency).

```sh
RELAY_URL=wss://relay.example.org/v3 \
OPERATOR_CONTACT=mailto:ops@example.org \
DB_PATH=/var/lib/p2p-relay/relay.db \
npx @peer2peer/relay
```

After `npm install -g @peer2peer/relay` the same server runs as `p2p-relay`; `p2p-relay --help` lists the settings. TLS, limits, discovery (`/.well-known/p2p-relay.json`), operations and the privacy promise are covered in [docs/run-a-relay.md](https://github.com/ix-infrastructure/Peer2Peer/blob/main/docs/run-a-relay.md).

**Members-only.** By default the relay is open to any valid device. Set `RELAY_ALLOW` (userIds), `RELAY_ALLOW_FILE` and/or `RELAY_ALLOW_CIRCLE` (a circle whose members the relay admits, verifying the owner-signed chain itself) and only those members can authenticate; strangers are refused at auth (`not-member`, close 4001), removals disconnect at once (`SIGHUP` or an edit of the allow file), `RELAY_DENY` shuts out anyone at once, and a member's `p2p invite` code admits the teammate who redeems it. An open circle never admits anyone (the relay fails closed to the allowlist). See [Members-only relays](https://github.com/ix-infrastructure/Peer2Peer/blob/main/docs/run-a-relay.md#members-only-relays).

The package also exports the `Relay` class and its stores for embedding a relay in tests or another Node process.

Licensed under Apache-2.0.
