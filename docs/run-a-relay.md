# Run a Peer2Peer relay

A Peer2Peer relay is a small store-and-forward server. Anyone can run one, and every conforming client works with every conforming relay. Users list 1–5 relays in their identity document, and senders deliver each message to up to 3 of them, so one relay going down loses nothing.

**There's no public relay: each group brings its own.** One person runs a relay for their team, club, company or group of friends, or the group uses one a friend runs. Everyone else just sets up with its URL, and invite codes carry it, so the people you invite don't run anything. This guide is for the person who runs it. A group's relay can admit only its members ([Members-only relays](#members-only-relays)). The protocol is in [protocol.md](protocol.md) §5.

## What a relay does, and what it can't do

**It does:**
- authenticate devices by signature (no accounts, no passwords);
- hold end-to-end encrypted envelopes for a device until it picks them up and acknowledges them, for up to 7 days;
- check mailbox capabilities and apply rate limits;
- serve users' public identity documents;
- run short-lived (10-minute) link mailboxes for adding a device.

**It can't:**
- read messages, statuses, session names, circle names or rosters. They're end-to-end encrypted, and the relay never has a key;
- forge or redirect messages, because every envelope is signed by the sending device;
- impersonate a user or claim someone else's mailbox.

## The privacy promise

This relay software:
- stores each envelope as exactly this, and nothing more:
  - the signed envelope. Its encrypted body is unreadable to the relay. Its header fields (`from`, `fdid`, `to`, `tdid`, `own`, `sid`, `seq`, `ts`, `kind`) are plaintext, and the relay reads `kind`, see protocol §7;
  - the recipient user id and device id it's for;
  - its size and arrival time;
  - a *source tag*: a keyed hash of the sending IP's bucket (the address, or its /64 for IPv6). It is used only to evict a flooder's envelopes first.

  The key for that hash exists **only in the relay's memory**. It is never written to disk, and a new one is made at every start. So nothing on disk can link an envelope to the sender's network. After a restart, the old tags no longer correspond to any key. They only group the envelopes that came from the same source, so eviction stays fair to each sender without knowing who it was.

  Envelopes are deleted when acknowledged, or after 7 days;
- never stores a capability, only a domain-separated SHA-256 hash of `(issuer, capid)` when it has to remember a revocation or a use count;
- never logs envelope contents, capabilities, certificates or link data. Logs are JSON counters and events. At `LOG_LEVEL=debug`, user ids, device ids and IPs appear only as salted, truncated hashes;
- exposes only aggregate counts on `/metrics`, which by default is served only on `127.0.0.1:9464` and never on the public port. Counters that would tell a delivered or stored message from a dropped one aren't kept at all.

**What any relay necessarily sees** (protocol §7): which user ids may reach which (from capabilities), who sends to whom, envelope sizes and timing, source IPs, and identity documents, which are public by design. Pick relays run by people you trust with that metadata, or run your own.

If you modify the software, your users can't verify it. Publish your policy in `RELAY_POLICY`.

## Run it

A relay is one Node process and one SQLite file. You need Node 22.13 or newer and nothing else: `node:sqlite` is built into Node, so there's no database server and no native dependency. Idle, it uses roughly 50–75 MB of memory.

```sh
RELAY_URL=wss://relay.example.org/v3 \
OPERATOR_CONTACT=mailto:ops@example.org \
DB_PATH=/var/lib/p2p-relay/relay.db \
npx @peer2peer/relay
```

The package installs a `p2p-relay` command, so after `npm install -g @peer2peer/relay` you can run `p2p-relay` instead (`p2p-relay --help` lists the settings). Everything the relay keeps lives in the one file at `DB_PATH`, plus its `-wal` and `-shm` companions. Back it up if you care about undelivered messages surviving a disk loss. Losing it costs at most 7 days of undelivered envelopes and the identity documents, which clients republish.

To keep it running, use whatever supervises your other services, for example a systemd unit:

```ini
[Service]
Environment=RELAY_URL=wss://relay.example.org/v3
Environment=DB_PATH=/var/lib/p2p-relay/relay.db
ExecStart=/usr/bin/p2p-relay
DynamicUser=yes
StateDirectory=p2p-relay
Restart=on-failure
```

**From a checkout** (before the package is published, or to run your own changes):

```sh
(cd packages/core && npm ci && npm run build)
cd packages/relay && npm ci && npm run build
RELAY_URL=wss://relay.example.org/v3 DB_PATH=/var/lib/p2p-relay/relay.db node dist/bin.js
```

### Optional: Docker

If your hosting runs containers, there's an image too. It is the same process, run as an unprivileged user, with the SQLite file in the `/data` volume. Build it from the repository root:

```sh
docker build -f packages/relay/Dockerfile -t peer2peer/relay .
docker run -d --name p2p-relay --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  -v p2p-relay:/data \
  -e RELAY_URL=wss://relay.example.org/v3 \
  -e OPERATOR_CONTACT=mailto:ops@example.org \
  -e RELAY_POLICY="Community relay for the Example group. Counters-only logs; envelopes deleted on ack or after 7 days." \
  peer2peer/relay
```

The image is multi-arch: the same Dockerfile builds for linux/amd64 and linux/arm64, for example `docker buildx build --platform linux/arm64,linux/amd64 -f packages/relay/Dockerfile -t <registry>/peer2peer/relay:<tag> --push .`. To run a private team relay on hardware you already have (an old laptop, a Raspberry Pi, a Jetson board, a NAS, a small cloud server, or Windows), see [run-a-relay-on-any-machine.md](run-a-relay-on-any-machine.md): it has install scripts for Linux, macOS and Windows and uses the `small` preset below.

For a relay on an internet-facing VM, the hardened Docker Compose + Caddy recipe in [future/public-relay.md](future/public-relay.md) adds a read-only container without capabilities, a firewall, backups, upgrades, monitoring and abuse handling. It was written for a public relay, which isn't planned for launch, but most of it applies to any relay.

## Put TLS in front of it

Clients only dial `wss://`. Terminate TLS in a reverse proxy, and keep the relay listening on localhost. With [Caddy](https://caddyserver.com), which gets and renews certificates automatically:

```caddyfile
relay.example.org {
    reverse_proxy 127.0.0.1:8080
}
```

That one block covers the WebSocket endpoint (`/v3`), the identity API (`/v3/identity/...`), `/healthz` and `/.well-known/p2p-relay.json`. Caddy passes WebSocket upgrades through by default.

Then set `TRUST_PROXY` to the number of proxies you run in front of the relay (`1` for Caddy alone), so per-IP limits use the client's address from `X-Forwarded-For` and not the proxy's. The relay takes the n-th entry from the right, because each of your proxies appends one. Set it **only** when the relay is reachable solely through those proxies. Otherwise clients can forge the header.

**Count hops the way your proxies write the header.** A proxy that *appends* to `X-Forwarded-For` adds a hop; one that *replaces* the header resets the count to one.
- **Caddy replaces it by default.** It ignores whatever `X-Forwarded-For` arrives from clients it doesn't trust and sends only the address it saw. So Caddy alone means `TRUST_PROXY=1`.
- **Behind a CDN** (for example Cloudflare in front of Caddy), tell Caddy to trust the CDN (`trusted_proxies` in its `servers` options), so it appends instead of replacing. Then count the CDN too: `TRUST_PROXY=2`.
- **If the number is wrong,** the relay sees the CDN's or Caddy's address for everyone, and every client shares one IP's limits. When the header has fewer entries than `TRUST_PROXY`, the relay falls back to the socket address and logs a warning, at most once a minute.

The relay strips ports and brackets (`[2001:db8::1]:443`) from addresses before applying limits.

Per-IP limits treat an IPv6 client's whole /64 as one address.

`/metrics` is never on the public port unless you set `METRICS_TOKEN`. It's served on a separate listener, `127.0.0.1:9464` by default, for a Prometheus on the same host or reached through your own tunnel.

## `RELAY_URL` must be exact

`RELAY_URL` is the relay's **canonical URL** (protocol §5.1): `wss://`, a lowercase host, no `:443`, and the path without a trailing `/` (default `/v3`). The relay announces it in every `hello`, and devices sign it when they authenticate.
- Clients compare it with the URL they dialled and hang up when the two differ.
- Capabilities and identity documents name relays by this exact string.

If you change it, every capability naming the old URL stops working on this relay. Choose a hostname you'll keep.

## Configuration

Use environment variables, or a JSON file named by `RELAY_CONFIG` that uses the same field names (`relayUrl`, `port`, `dbPath`, `powBits`, `operatorContact`, `policy`, `name`, `trustProxy`, `metricsPort`, `metricsHost`, `metricsToken`, `logLevel`, `allow`, `allowFile`, `allowCircle`, `inviteAdmitSec`, `preset`, `limits: {...}` and `storage: {...}`). The order is: defaults, then the preset, then the file, then environment variables, so environment variables win.

| Variable | Default | Meaning |
|---|---|---|
| `RELAY_URL` | `wss://localhost:<PORT>/v3` | Canonical URL (above). Set this. |
| `PORT` / `HOST` | `8080` / `0.0.0.0` | Listen address. |
| `DB_PATH` | `./relay.db` (`/data/relay.db` in the Docker image) | The SQLite file, or `:memory:`. |
| `POW_BITS` | `0` | Proof-of-work bits required on first-contact messages (0–24). |
| `OPERATOR_CONTACT` | — | How to reach you (`mailto:`, URL). Shown in the relay-info document. |
| `RELAY_NAME`, `RELAY_POLICY` | — | Free text shown in the relay-info document. |
| `TRUST_PROXY` | `0` | How many proxies you run in front of the relay. The client IP is the n-th `X-Forwarded-For` entry from the right. `0` ignores the header. |
| `METRICS_PORT` / `METRICS_HOST` | `9464` / `127.0.0.1` | The separate `/metrics` listener. `off` disables it. |
| `METRICS_TOKEN` | — | Also serve `/metrics` on the public port, to `Authorization: Bearer <token>` only. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. |
| `SWEEP_INTERVAL_SEC` | `300` | How often expired data is deleted. |
| `DEBUG_STATS` | off | `1` serves `GET /debug/stats` on the metrics listener: event-loop delay, memory and internal map sizes, as JSON aggregates. For the resilience suite ([`packages/relay/resilience`](../packages/relay/resilience/README.md)) and local profiling. Leave it off in production. |
| `RELAY_PRESET` | — | `small` sizes the relay for a 2 GB single-board computer and a team of up to about 50 people: a 512 MiB store hard cap, 400 connections (64 per address), smaller mailboxes and a smaller SQLite write-ahead log. It only sets defaults: any `LIMIT_*` or `SQLITE_*` value still wins. The full table is in [run-a-relay-on-any-machine.md](run-a-relay-on-any-machine.md#the-small-preset). Pair it with `NODE_OPTIONS=--max-old-space-size=384`. |
| `LIMIT_*` | see below | Any limit, in upper snake case, for example `LIMIT_MAILBOX_ENVELOPES=5000`. |
| `SQLITE_WAL_LIMIT_BYTES` | 256 MiB | Write-ahead log size past which the checkpoint watchdog intervenes (Operations, below). `storage.walLimitBytes` in the file. |
| `SQLITE_JOURNAL_SIZE_LIMIT_BYTES` | 64 MiB | Size the write-ahead log is truncated back to after a checkpoint. `storage.journalSizeLimitBytes`. |
| `SQLITE_CHECKPOINT_INTERVAL_MS` | 100 | How often the background thread checkpoints. `storage.checkpointIntervalMs`. |
| `RELAY_ALLOW` | — | Members-only: full userIds (`p2p:…`), separated by commas or spaces. See [Members-only relays](#members-only-relays). |
| `RELAY_ALLOW_FILE` | — | Members-only: a file of userIds, one per line (`#` comments; `!<userId>` denies). Re-read on `SIGHUP` and when it changes. |
| `RELAY_DENY` | — | Members-only: userIds never admitted, whatever the list, the circle or an invite says. |
| `RELAY_ALLOW_CIRCLE` | — | Members-only: also admit the current members of this circle (`c_…`). |
| `RELAY_INVITE_ADMIT_SEC` | `604800` (7 days) | Members-only: how long a member's invite code admits its redeemer before the list or the circle must. `0`: codes admit nobody. |

## Members-only relays

By default a relay is **open**: any device with a valid certificate may authenticate. A group running its own relay can make it **members-only** instead. Then only the group's members can use it, and the relay stops serving as a public directory. Leave `RELAY_ALLOW` and `RELAY_ALLOW_CIRCLE` unset for an open relay, as before.

**Who is a member.** A userId is admitted when it is:
- on the **allowlist**: `RELAY_ALLOW`, the `allow` list in the `RELAY_CONFIG` file, and the lines of `RELAY_ALLOW_FILE`, together;
- a current member of the **circle** named by `RELAY_ALLOW_CIRCLE`, by the newest version the relay holds;
- **admitted by an invite code**, for a while (below).

The relay checks the userId that issued the device certificate (`iss`, the hash of the identity key that signed it), so every device of a member is a member. Everyone else is refused **at auth**, before anything is stored for the device and before any mailbox, invite or link operation: the reply is `{"t":"error","code":"not-member"}`, and the connection is closed with code 4001 ("not a member"). The client says `… is members-only and doesn't admit this identity`.

An empty list (`RELAY_ALLOW=""`, or an allow file with no userIds) is members-only with nobody on it: it fails closed. To run open, leave the variables unset.

```sh
# A team relay: the founders on the list, plus everyone in the team's circle.
RELAY_URL=wss://relay.team.example/v3 \
RELAY_ALLOW_FILE=/etc/p2p-relay/members.txt \
RELAY_ALLOW_CIRCLE=c_rczvrfzs6gjzyd57r7lnn2v4x2 \
p2p-relay
```

`p2p whoami` shows a user's userId, and `p2p circle ls` a circle's id.

**Removing someone takes effect at once.** Edit the allow file, or send `SIGHUP` (`docker kill -s HUP p2p-relay`) after changing the `RELAY_CONFIG` file; environment variables are fixed for the life of the process. The relay re-reads the list, refuses new auths by anyone no longer on it, and closes their open connections (error `not-member`, close code 4001). The same happens when the circle's owner removes someone from the circle.
- **Write the allow file atomically:** write a temporary file next to it, then rename it over the old one (`mv members.txt.new members.txt`; most editors save this way). The relay polls the file, and a half-written file could otherwise be read.
- A list that fails to parse keeps the current one: one line that isn't a full userId rejects the whole file, so a partial read never shrinks the list. So does an allow file that is suddenly empty (likely a write in progress; send `SIGHUP` if you meant it).
- A reload never turns a members-only relay back into an open one; that takes a restart.

**Shutting someone out, whatever else admits them.** `RELAY_DENY` (or `deny` in the `RELAY_CONFIG` file, or a `!p2p:…` line in the allow file) lists userIds the relay never admits: not through the list, the circle or an invite. Their open connections close at once, their provisional admission is gone for good (lifting the deny later doesn't bring it back), and their unspent invite grants go too. This is how to remove one provisional member before their period ends; the member who invited them can also do it by revoking that code (below).

**Circle admission.** With `RELAY_ALLOW_CIRCLE`, the relay follows the circle itself:
- It verifies every version as clients do (protocol §3.3, with core's `CircleChain`): version 1 must recompute the circle id from its founder and nonce, and every later version must be signed by the owner of the version before it. Nobody else can add members, and the relay can't be talked into an older version or another circle.
- **Bootstrap.** Put the circle's owner (or another member you trust) on the allowlist. When an allowlisted member's client connects, the relay's auth reply says which circle it follows and which version it holds (`"circle":{"cid","ver"}`, `ver` 0 at first), and the client pushes the chain from version 1. Only an allowlisted userId may seed it.
- After that, any member's client pushes newer versions when it connects, and the owner's client pushes each version it signs right away. A new head re-decides who is admitted, closing the connections of anyone it removed.
- The chain is stored in the database, so a restart keeps it.
- **Open circles fail closed.** An open circle (`p2p circle policy … open`) lets anyone who asks join it, so following one would admit the public. The relay refuses to seed an open circle. If the followed circle's head turns open later, the circle admits nobody here: only the allowlist does (circle members not on it are disconnected), the relay logs an error, and `/.well-known/p2p-relay.json` adds `"attention": true` (no details). It recovers on its own when the owner makes the circle invite-only again. That is why the owner must be on the allowlist too, not only in the circle: otherwise an open head locks the owner out as well, and nobody can push the invite-only version that fixes it.
- Admins only propose; the owner signs. Removing someone from the circle removes them from the relay unless they are also on the allowlist: a userId on both stays admitted until it is off both.

**Bringing in a new teammate: the invite pre-authorises them.** A newcomer has no userId the operator knows yet, and on a members-only relay a stranger can't even publish an identity document. So a member's short code (`p2p invite`, protocol P4) admits its redeemer:
- The inviter's client puts the code's invite with `admit`: the SHA-256 of an admission key derived from the code's secret. The relay keeps it as a grant from that member, single use, until the code expires (at most 7 days). Only full members (on the list, or in the circle) can make grants.
- The newcomer runs `p2p join relay.team.example/K7QM-…`. The client takes the invite (unauthenticated, as on any relay) and authenticates with the admission key (`auth.admit`). The relay hashes it, finds the grant, spends it, and admits the newcomer **provisionally**: for `RELAY_INVITE_ADMIT_SEC` (default 7 days), as long as the inviter stays a member.
- On a circle relay that is the whole story: when the inviter's client adds the newcomer to the circle (what a code with a circle does), it pushes the new version, and the newcomer becomes a circle member. From then on the circle alone decides: removing them cuts them off, whatever was left of the provisional period.
- With an allowlist only, add the newcomer's userId (the inviter sees it in `p2p invites`) to the list before the provisional period ends.
- Revoking the code (`p2p invites revoke`) voids its grant even if someone already took the invite, and removes whoever it already admitted provisionally (the relay records which invite admitted them), closing their connections. A member who is removed takes their unspent grants and provisional joiners with them.
- Anyone who saw the code can use it, as on any relay. The inviter is told who redeemed it, with `p2p remove` at hand; on a circle relay that also takes them off the relay at once.
- `RELAY_INVITE_ADMIT_SEC=0` turns this off: then only the operator admits people.

**What a stranger can still reach.**
- `/healthz` and `/.well-known/p2p-relay.json`, which says `"access":"members"` (it never lists members or the circle), and `"attention": true` while something needs the operator (see the logs).
- `invite-get`, rate-limited as on an open relay: only members can put invites, so there is nothing else to take, and the newcomer needs it.
- `link-put`/`link-get`, which a member's new device uses before it has a certificate: only a member's authenticated device can open a link mailbox.
- The identity API (`/v3/identity/<userId>`, `/tips`, `/chain`) serves only members' documents. Anyone else's userId gets the same 404 as an unknown one, so the relay is no directory of who has used it.

Messages to a non-member are refused (`undeliverable`), so nothing is stored for someone who can't come to get it.

**Limits.** A sponsor holds at most 64 open grants (the oldest goes) and 64 provisional joiners at once, and the relay at most 10,000 provisional members. A userId sends at most 120 `circle-put` frames an hour, each of at most 64 versions.

## Choosing limits

The defaults are the protocol's (§5.4, §5.7). A relay MAY be stricter, and it advertises its limits in `hello` and in `/.well-known/p2p-relay.json`, so clients can choose.

| Limit | Default | Notes |
|---|---|---|
| `LIMIT_MAILBOX_ENVELOPES` / `LIMIT_MAILBOX_BYTES` | 10,000 / 64 MiB | Per device mailbox. The oldest is dropped first. Worst-case disk is about this × active devices. |
| `LIMIT_RETENTION_SEC` | 7 days | Lower it to save disk. Offline users then miss more. |
| `LIMIT_SENDS_PER_MINUTE` | 120 | Per sending user. |
| `LIMIT_CONTACT_PER_SENDER_PER_HOUR` | 60 | First-contact messages without a capability, per sender. |
| `LIMIT_CONTACT_PER_PAIR_PER_HOUR` | 3 | Per (sender, recipient) pair. |
| `LIMIT_CONTACT_PER_IP_PER_HOUR` | 120 | Per source IP. Identities are free, so this is what slows a spammer down. |
| `LIMIT_LINK_OPS_PER_IP_PER_MINUTE` | 60 | Unauthenticated device-link mailbox reads and writes. |
| `LIMIT_MAX_CONNECTIONS` | 10,000 | Concurrent WebSockets in total. |
| `LIMIT_MAX_CONNECTIONS_PER_IPV4` / `LIMIT_MAX_CONNECTIONS_PER_IP` | 512 / 64 | Concurrent WebSockets per IPv4 address, and per IPv6 /64 (see "IPv4 and IPv6 defaults" below). |
| `LIMIT_HTTP_PER_IP_PER_MINUTE` | 600 | Identity lookups and the other GETs. |
| `LIMIT_UNAUTH_TIMEOUT_SEC` | 15 | How long a connection may stay unauthenticated. `hello`/`auth` is one round trip. Advertised as `unauthTimeoutSec` in `hello.limits` and in the relay-info document. A new device polling a link mailbox reconnects to keep polling (protocol §5.7). |
| `LIMIT_MAX_UNAUTH_CONNECTIONS` | 2,000 | Unauthenticated connections at once. When it's full, the oldest unauthenticated socket is dropped to admit the new one, so idle sockets can't lock honest clients out. |
| `LIMIT_MAX_UNAUTH_PER_IP` | 8 | Unauthenticated connections per source IP. |
| `LIMIT_MAX_CONNECTIONS_PER_ISS` | 16 | Connections per user. |
| `LIMIT_FRAMES_PER_CONN_PER_MINUTE` | 600 | Frames of any kind, per connection. |
| `LIMIT_SEND_BYTES_PER_CONN_PER_MINUTE` / `LIMIT_SEND_BYTES_PER_IP_PER_MINUTE` | 8 MiB / 32 MiB | Envelope bytes a connection, and a source IP, may send per minute. |
| `LIMIT_STORE_MAX_BYTES` | 4 GiB | Target for total envelope bytes on disk. Past it, the relay evicts by source: the sending IP that holds the most bytes loses the oldest envelopes of its largest mailbox first. A flood churns the flooder's own envelopes instead of refusing everyone or pushing out other people's mail. The sender of the envelope being stored pays first once its group is over its fair share (the quota divided by the number of sending addresses, and at least 1/16 of the quota); otherwise the largest group goes, whether it was stored before or after a restart. An honest sender is under its share, so it never pushes out its own older mail. A flood, renewed after a restart or spread across many addresses, therefore eats its own data before anyone's parked mail. Size it to your disk. |
| `LIMIT_STORE_HARD_MAX_BYTES` | 5 GiB | Last resort: if eviction can't keep up, sends past this are answered `undeliverable`. |
| `LIMIT_RECIPIENT_MAX_BYTES` | 256 MiB | Stored bytes per recipient user. Past it, the source that sent that user the most bytes loses its oldest envelopes to them first, so one sender can't flush a user's other mail. The fair-share rule above applies here too, so an honest sender can trim its own mail: once a recipient who stays offline has a full mailbox, a sender holding more than its share of it (at least 1/16, about 16 MiB by default) loses its own oldest envelopes to that recipient first. |
| `LIMIT_SOURCE_ACCEPTED_BYTES_PER_HOUR` | 256 MiB | Bytes one source IP (/64 for IPv6) may send per hour, refilling continuously. Past it, that source's sends are `rate-limited`. Contacts to mailboxes that don't exist count too, and acks give nothing back, so the limit reveals nothing about recipients. |
| `LIMIT_SOURCE_MAX_BYTES` | 512 MiB | Stored bytes per source IP: a long-term share of the disk. Past it, that source's *own* oldest envelopes are evicted first. Nothing is refused. |
| `LIMIT_CONNECTS_PER_IP_PER_MINUTE` | 120 | New connections per source IP. |
| `LIMIT_AUTHS_PER_IPV4_PER_MINUTE` / `LIMIT_AUTHS_PER_IP_PER_MINUTE` | 600 / 60 | Authentication attempts per IPv4 address, and per IPv6 /64. |
| `LIMIT_MAX_DEVICES` | 1,000,000 | Device bindings kept. When full, the least recently seen binding is evicted, as long as it has no stored envelopes, no live connection and isn't listed in a held identity document. A new device is refused only when nothing can be evicted. Recovering from a full table: [run-a-relay-on-any-machine.md](run-a-relay-on-any-machine.md#the-small-preset). Known devices, and devices listed in their user's identity document, always get in. |
| `LIMIT_NEW_DEVICES_PER_IPV4_PER_DAY` / `LIMIT_NEW_DEVICES_PER_IP_PER_DAY` | 1,000 / 50 | New device bindings per IPv4 address, and per IPv6 /64. Devices listed in a held identity document are exempt. |
| `LIMIT_REVOKES_PER_CONN_PER_MINUTE` / `LIMIT_REVOKES_PER_ISS_PER_HOUR` | 30 / 600 | Capability revocations. |
| `LIMIT_IDENTITY_PUBLISH_PER_ISS_PER_HOUR` / `..._PER_IP_PER_HOUR` | 30 / 120 | Identity document publishes. |
| `LIMIT_IDENTITY_MAX_TIPS` / `LIMIT_IDENTITY_MAX_VERSIONS` | 4 / 128 | Fork branches and versions kept per user. Past the version cap, the oldest non-tip versions go first. |
| `LIMIT_LINK_OPEN_PER_ISS_PER_HOUR` / `..._PER_IP_PER_HOUR` | 20 / 60 | Device-link mailboxes opened. |
| `LIMIT_LINK_OPEN_PER_IP` / `LIMIT_LINK_TOTAL_BYTES` | 8 / 64 MiB | Open link mailboxes per source IP, and a byte budget across all of them. Each open reserves its mailbox's maximum (80 KiB), so a full budget refuses new opens and never refuses a put into a mailbox that is already open. |
| `LIMIT_INVITE_TTL_MAX_SEC` / `LIMIT_INVITE_BLOB_BYTES` | 7 days / 32 KiB | Short-code invites (protocol P4): the longest a code lives, and the size of its sealed bundle. Invites are stored in the database, so a restart keeps them. |
| `LIMIT_INVITE_PUT_PER_ISS_PER_HOUR` / `..._PER_IP_PER_HOUR` | 20 / 60 | Invite codes created. |
| `LIMIT_INVITE_OPEN_PER_ISS` / `LIMIT_INVITE_TOTAL_BYTES` | 20 / 256 MiB | Open codes per user, and a byte budget across all of them. Past 90% of the budget, only identities this relay has known for `LIMIT_INVITE_YOUNG_IDENTITY_SEC` (1 day) may add codes. When the budget is full, the users holding the most bytes lose their newest codes instead of everyone being refused. |
| `LIMIT_INVITE_BYTES_PER_IP` | 2 MiB | Open code bytes per source network: an IPv4 address, or an IPv6 /48. Stops a handful of addresses from filling the budget. |
| `LIMIT_INVITE_GETS_PER_IP_PER_MINUTE` / `LIMIT_INVITE_MISSES_PER_IP_PER_HOUR` | 10 / 30 | Unauthenticated code lookups per source IP. A lookup that finds nothing also spends the miss budget, and with it spent, every lookup from that address is refused until it refills: that is what keeps guessing 100-bit codes hopeless. Raise the miss budget only with care. |

**Sizing the source limits for shared IPs.** Many people can share one address: carrier NAT, a campus, an office. Size `LIMIT_SOURCE_ACCEPTED_BYTES_PER_HOUR` for the busiest address you expect.
- A rough figure is users × peers × envelope size × sends per hour.
- For example, 100 users each sending a `status` (about 2 KiB) to 10 peers every minute is about 120 MB/h, which fits the 256 MiB default.
- Raise it if you serve a large campus from one address. It only bounds how fast one address can write, and the eviction rules still keep the disk fair.
- **A shared address shares its disk share too.** `LIMIT_SOURCE_MAX_BYTES` and source-first eviction see one address as one source. So when one spammer behind a carrier NAT or campus address pushes that address over its share, the evicted envelopes are that address's oldest, which may be its neighbours' mail rather than the spammer's. Other addresses are unaffected. If you serve a known shared address, raise `LIMIT_SOURCE_MAX_BYTES` so its honest traffic stays well under the share.

**IPv4 and IPv6 defaults.** A shared IPv4 address is normal: carrier-grade NAT, campuses and offices put hundreds of people behind one address. An IPv6 /64, by contrast, is usually one site. So three per-address limits have separate IPv4 values, with room for a few hundred users:

| | IPv4 address | IPv6 /64 |
|---|---|---|
| Concurrent connections | `LIMIT_MAX_CONNECTIONS_PER_IPV4` = 512 | `LIMIT_MAX_CONNECTIONS_PER_IP` = 64 |
| New device bindings per day | `LIMIT_NEW_DEVICES_PER_IPV4_PER_DAY` = 1,000 | `LIMIT_NEW_DEVICES_PER_IP_PER_DAY` = 50 |
| Auth attempts per minute | `LIMIT_AUTHS_PER_IPV4_PER_MINUTE` = 600 | `LIMIT_AUTHS_PER_IP_PER_MINUTE` = 60 |

The trade-off is that a single abuser holding one IPv4 address gets the same room as a busy campus. That room is still bounded:
- the global caps (`LIMIT_MAX_CONNECTIONS`, `LIMIT_MAX_UNAUTH_CONNECTIONS`, `LIMIT_MAX_DEVICES`) apply, and so do the per-user limits (`LIMIT_MAX_CONNECTIONS_PER_ISS`, the send and contact limits);
- what an address can *store* is bounded by the byte quotas and source-first eviction;
- **the pool is protected:** once connections pass 80% of `LIMIT_MAX_CONNECTIONS`, every address, IPv4 included, is held to the strict per-address cap (`LIMIT_MAX_CONNECTIONS_PER_IP`, 64). When the pool is full, room for a newcomer comes only from an address holding *more* than that cap:
  - the address holding the most connections gives one up;
  - within that address, the user with the most connections there loses its least recently active one (close code 4029), and the client reconnects;
  - one newcomer address can cause at most 10 such evictions a minute;
  - if no address is over the cap, the newcomer is refused (HTTP 503).

  So every address keeps up to 64 connections, whatever other addresses do. That is also the floor: while the pool is under pressure, newcomers from other addresses can churn a shared NAT's address (a campus, a carrier NAT) down to 64 connections, by design. Its other users are closed with 4029 and reconnect once the pool has room. If one shared address needs more, raise `LIMIT_MAX_CONNECTIONS` so the pool rarely fills;
- likewise, once the device table passes 80% of `LIMIT_MAX_DEVICES`, IPv4 addresses get the strict new-device allowance.

If you know your users never share addresses (a small private community), lower the IPv4 values. If you serve a very large campus from one address, raise them. Device bindings past the global cap evict the least recently seen idle ones.

**Under spam,** raise `POW_BITS` first. Each extra bit doubles a stranger's cost to send a first contact, and it costs friends nothing, because they hold capabilities. 16–20 bits is a few hundred milliseconds to a few seconds on a laptop.

## Discovery: `/.well-known/p2p-relay.json`

```json
{
  "protocol": "p2p/v3",
  "relay": "wss://relay.example.org/v3",
  "name": "Example community relay",
  "software": { "name": "@peer2peer/relay", "version": "0.1.0" },
  "limits": { "mailboxEnvelopes": 10000, "retentionSec": 604800, "...": "..." },
  "pow": 0,
  "operator": { "contact": "mailto:ops@example.org" },
  "policy": "Counters-only logs; envelopes deleted on ack or after 7 days.",
  "access": "open"
}
```

This is how communities find and compare relays. Keep the contact and the policy honest and current. `access` is `open`, or `members` for a [members-only relay](#members-only-relays). `attention: true` appears only while a members-only relay needs its operator (for now: the followed circle turned open); the logs say why.

## Operations

- **Health:** `GET /healthz` returns `{"ok":true}`, or 503 while shutting down or when the database is unreachable. The optional Docker image has a `HEALTHCHECK`.
- **Metrics:** `GET /metrics` on the metrics listener (above) serves Prometheus text: connections, auth results, sends by wire result, envelopes expired, identity publishes, link operations, and stored totals refreshed at most once a minute.
- **Shutdown:** `SIGTERM` closes every connection with code 1001, then closes the database. Clients reconnect to their other relays and come back. Nothing un-acked is lost.
- **Upgrades:** stop, replace and start. The schema is versioned, and a relay refuses to start on a database schema it doesn't understand.
- **Startup:** the relay first rebuilds its byte counters, in small steps, and only then accepts connections. A large store adds a few seconds to startup.
- **Database checkpoints** run on a background thread with their own connection, so copying the write-ahead log into the database never stalls traffic.
  - A watchdog checks it: if checkpoints make no progress for 30 s (for example because a reader holds an old snapshot; under heavy writes a pass that copies more than the last one counts as progress even when it never fully catches up), or the write-ahead log grows past 256 MiB (`SQLITE_WAL_LIMIT_BYTES`), the relay turns SQLite's built-in checkpoints back on, logs a warning, and restarts the thread. A backup taken with `deploy/relay/backup.mjs` is the exception: while its marker (`<db>-backup`, with the backup's own deadline) is in force, its snapshot holding checkpoints back isn't a stall, so the relay keeps checkpoints on the thread, which catches up once the backup ends (`relay checkpoints held back by a running backup` is logged instead). A marker past its deadline, or written over an hour ago, is ignored.
  - After a checkpoint, the log file is truncated back to 64 MiB (`journal_size_limit`, set by `SQLITE_JOURNAL_SIZE_LIMIT_BYTES`; 16 MiB under the `small` preset).
- **Disk:** every `SWEEP_INTERVAL_SEC`, the relay deletes the items below. Expired envelopes go in batches of 500 that yield between them, so a big expiry never stalls traffic.
  - expired envelopes;
  - capability state older than 91 days;
  - identity versions older than 90 days (except branch tips);
  - every document of a user whose newest version expired more than 90 days ago, leaving a tombstone (below);
  - tombstones older than 91 days, with the device ids they remember;
  - device bindings not seen for 90 days.

  Nothing grows with a user's revocations. Per user, the relay keeps at most `LIMIT_IDENTITY_MAX_VERSIONS` versions (default 128, each listing at most 10 devices). It remembers only device ids that were listed and aren't any more, at most 2,048 per user, each for 91 days from the moment it left: when the allowed list shrinks, when versions that listed it are pruned (the version cap or the 90-day sweep), and when history is discarded (a tombstone, or a replaced root).

## Identity documents: what a relay can and can't vouch for

A relay stores only identity documents that list it.

**Leaving and tombstones.** When a user publishes a version that drops your relay, chaining from the head your relay holds, the relay deletes their documents and stops serving them. It keeps a *tombstone*: the last list of allowed devices and the last version number. The same happens when a user's newest version has been expired for 90 days.
- A tombstone keeps devices revoked before the user left from authenticating: it remembers the device ids its history listed for 91 days, longer than any device certificate lives. Every connection is closed when its device certificate expires, with close code 4003 (clients reconnect with a renewed certificate); 4001 means the device isn't allowed.
- It has no mailboxes: messages to that user are not stored here.
- During a fork, leaving takes a version that merges every branch. Extending one branch isn't enough.
- It also refuses any replayed document older than the last version.
- It is deleted after 91 days, longer than any device certificate can outlive its revocation.

**Stale roots.** When your relay holds nothing for a user, it accepts any validly signed version as the starting point. That includes an *old* version replayed by someone who kept a copy, such as a device that has since been revoked and wants a document that still lists it. Such a starting point is "unanchored" (no version 1 behind it).
- When the owner later publishes a higher version, the relay replaces the unanchored history with it, even if it doesn't chain.
- A history anchored at version 1 is only ever extended, so its owner fills gaps by back-filling the missing versions.
- After a replacement, or when a user returns after a tombstone, the new allowed-device list is capped by the previous one. It can only grow again once the owner publishes a version that chains onto the new one. So a replayed document can never re-admit a revoked device.

**What the relay checks, and what it leaves to clients.** A new version is checked against what the relay holds now:
- it chains onto a held version (or merges two);
- it is signed by the identity key, and its `by` is one of its key holders;
- a merge adds no device.

The relay does **not** remember revocations forever, and it doesn't refuse a version that re-lists a device. Clients refuse those, from their own copy of the history (protocol §2.5). A device that a held version listed, and the current allowed list doesn't, gets no connection at all. A user restoring from a backup brings a brand-new device, so restore still works.

Clients don't trust a single relay's view: they fetch every tip from every relay the user lists (protocol §5.6).
