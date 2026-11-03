# A public relay (not planned for launch)

> **Not planned for launch.** Peer2Peer launches with no public relay: each team or group runs its own, or uses one a friend runs, and invite codes carry the inviter's relays ([run a relay](../run-a-relay.md)). This page is kept for later, and because most of it applies to any relay on an internet-facing VM: the hardening, the firewall, logs, monitoring, backups and upgrades. The placeholder domain is `relay.example.org`.

This is the recipe for an **open, public** Peer2Peer relay: one anyone can use. It runs on a generic small VM (1 vCPU, 1 GB RAM, 40 GB of disk; see the [disk budget](#disk-budget)) with Docker, using the files in [`deploy/relay/`](../../deploy/relay/). A [Fly.io variant](#flyio) follows.

Read [run-a-relay.md](../run-a-relay.md) first. It explains what a relay stores and sees, every setting, and every limit. This page is the hardened, opinionated deployment of the same software.

## What you get

```
 internet ──443/tcp──▶ Caddy (TLS, automatic certs) ──▶ relay:8080 (private network) ──▶ SQLite on volume relay-data
                                                        relay:9464 /metrics ──▶ 127.0.0.1:9464 on the host only
```

| File | What it is |
| --- | --- |
| [`compose.yaml`](../../deploy/relay/compose.yaml) | The relay and Caddy, both hardened. |
| [`Caddyfile`](../../deploy/relay/Caddyfile) | TLS on 443 with automatic certificates (TLS-ALPN challenge, so port 80 stays closed). |
| [`relay.env.example`](../../deploy/relay/relay.env.example) | The relay's settings for an open relay: URL, contact, policy, proof-of-work, limits. |
| [`caddy.env.example`](../../deploy/relay/caddy.env.example) | The domain and the certificate-notice email. |
| [`backup.sh`](../../deploy/relay/backup.sh), [`backup.mjs`](../../deploy/relay/backup.mjs) | A consistent, compacted backup of the SQLite database while the relay runs. [`backup.test.mjs`](../../deploy/relay/backup.test.mjs) checks it finishes under concurrent writes, and [`backup-sh.test.mjs`](../../deploy/relay/backup-sh.test.mjs) checks the script's guards with a fake `docker` (CI runs both). |
| [`fly.toml`](../../deploy/relay/fly.toml) | The Fly.io variant. |

**Hardening** (both containers):

- read-only root filesystem, with a small `tmpfs` for `/tmp`;
- `cap_drop: ALL` (Caddy gets back only `NET_BIND_SERVICE`) and `no-new-privileges`;
- the relay runs as the distroless image's unprivileged user (65532), with no shell in the image;
- hard limits: relay 512 MB memory (no swap), 1 CPU, 128 processes; Caddy 192 MB, half a CPU, 128 processes;
- the relay's data lives in a named volume (`relay-data`), and nothing else is writable;
- only Caddy publishes a port, and only 443. The relay's listener is on the private compose network, and `/metrics` is published on the host's loopback only.

## 1. The machine

Any provider's smallest general-purpose VM works: 1 vCPU, 1 GB RAM, 40 GB disk, a current Debian or Ubuntu. Idle, the relay uses about 50–75 MB; the 512 MB cap leaves room for a few thousand connections.

1. Install **Docker Engine 28 or newer** and the Compose plugin from Docker's own packages. Older engines let hosts on the same network segment reach ports published on `127.0.0.1` (the `/metrics` port here); 28 drops such traffic. Check with `docker version --format '{{.Server.Version}}'`.
2. Create a DNS `A` (and `AAAA`, if the VM has IPv6) record for your domain (here `relay.example.org`) pointing at the VM.
3. **Firewall: only 443 open to the world.** Allow `443/tcp` inbound, plus SSH from your own addresses only (or use your provider's console or a VPN instead of open SSH). Deny everything else inbound. Do it in the provider's firewall *and* on the host, for example with `ufw`:

   ```sh
   sudo ufw default deny incoming
   sudo ufw default allow outgoing
   sudo ufw allow from <your-admin-ip> to any port 22 proto tcp
   sudo ufw allow 443/tcp
   sudo ufw enable
   ```

   Docker writes its own iptables rules for published ports, which bypass `ufw`. That's why `compose.yaml` publishes only `443` and binds metrics to `127.0.0.1`: there is nothing else for Docker to open. Don't add `ports:` entries without a loopback address.

4. Turn on unattended security updates for the OS.

## 2. Configure

On the VM, check out the repository at the release tag you deploy (the relay image is built from source until a published image exists), then:

```sh
cd deploy/relay
cp relay.env.example relay.env
cp caddy.env.example caddy.env
$EDITOR relay.env caddy.env
```

Set at least:

- `RELAY_URL`: `wss://<domain>/v3`. It's the relay's canonical URL and capabilities name it, so choose a hostname you'll keep ([run-a-relay.md, "RELAY_URL must be exact"](../run-a-relay.md#relay_url-must-be-exact)).
- `OPERATOR_CONTACT`: the abuse contact (below).
- `RELAY_DOMAIN` (same host as `RELAY_URL`) and `ACME_EMAIL` in `caddy.env`.

`relay.env` and `caddy.env` are git-ignored; never commit them.

## 3. Start

```sh
docker compose build
docker compose up -d
docker compose ps                     # both "running"; relay "healthy"
curl -fsS https://relay.example.org/healthz
curl -fsS https://relay.example.org/.well-known/p2p-relay.json
```

The first request can take a few seconds while Caddy gets the certificate. Then check from a client:

```sh
P2P_DEFAULT_RELAYS=wss://relay.example.org/v3 p2p doctor
```

## Settings for an open public relay

`relay.env.example` keeps the protocol defaults for almost every limit. They were designed and stress-tested for a relay that strangers can reach: per-IP, per-user, per-pair and per-source limits, source-first eviction, and invite budgets ([run-a-relay.md, "Choosing limits"](../run-a-relay.md#choosing-limits)). On top of that:

| Setting | Value | Why |
| --- | --- | --- |
| `POW_BITS` | `16` | Proof-of-work on first-contact messages, the only messages a stranger can send without a capability. Friends and circle members hold capabilities and pay nothing. 16 bits is well under a second on a laptop. **Under spam, raise it first**, one or two bits at a time, toward 20. |
| `TRUST_PROXY` | `1` (set in `compose.yaml`) | Caddy is the only way in, and it replaces `X-Forwarded-For`, so per-IP limits see the real client. Behind a CDN, see [run-a-relay.md](../run-a-relay.md#put-tls-in-front-of-it). |
| `LIMIT_STORE_MAX_BYTES` / `LIMIT_STORE_HARD_MAX_BYTES` | 4 GiB / 5 GiB (defaults) | Sized for the 40 GB disk: see the [disk budget](#disk-budget). On a smaller disk, lower both. |
| `LIMIT_MAX_CONNECTIONS` / `LIMIT_MAX_UNAUTH_CONNECTIONS` | 5,000 / 1,000 | Lower than the defaults (10,000 / 2,000) to stay inside the 512 MB memory cap. Raise both with the cap on a bigger VM. |
| `LOG_LEVEL` | `info` | See "Logs". |

Leave the IPv4 per-address allowances at their defaults: a public relay serves campuses and carrier NAT, which share one IPv4 address.

## Abuse contact

`OPERATOR_CONTACT` is published in the relay-info document (`/.well-known/p2p-relay.json`) and is how people report abuse. Use an alias that a person reads, for example `mailto:abuse@example.org`. Keep `RELAY_POLICY` short and true: what is logged and how long envelopes live.

What you can do about abuse is limited by design, because the relay never sees content: raise `POW_BITS`, tighten the per-IP limits for a source, or block an address range in the firewall. Every client lists up to 5 relays and delivers through up to 3, so a short outage or a block costs users little.

## Logs

- **The relay** logs JSON counters and events at `info`: no envelope contents, capabilities, certificates or link data, and no user ids, device ids or IPs (at `debug` those appear as salted, truncated hashes). Never run `debug` in production.
- **Caddy** has access logs off (its default); `compose.yaml` keeps it that way. Don't add a `log` directive to the site block: it would record client IPs and paths.
- **Retention:** both containers use Docker's `json-file` driver capped at 5 × 10 MB, so logs rotate away within days. If you ship logs elsewhere, keep at most 14 days.
- Read them with `docker compose logs --since 1h relay`.

## Monitoring

`/metrics` (Prometheus text: connections, auth results, sends by result, expiries, identity publishes, link operations and stored totals) is published on the host's `127.0.0.1:9464` only. It is never on the public port: the relay serves it only on its separate listener, and the Caddyfile refuses `/metrics` and `/debug/*` as well.

- **Scrape it locally:** run a Prometheus or Grafana Agent on the VM that scrapes `127.0.0.1:9464`, and remote-writes to your monitoring service. Or reach it over SSH: `ssh -L 9464:127.0.0.1:9464 <vm>`.
- **Uptime:** an external check on `https://<domain>/healthz` (expects `{"ok":true}`; 503 while shutting down or when the database is unreachable) and on the certificate's expiry.
- **Alert on:** `/healthz` failing for 5 minutes; the store passing 80% of `LIMIT_STORE_MAX_BYTES`; the container restarting (`docker compose ps`, or the `RestartCount` from `docker inspect`); the disk passing 70%; memory near the 512 MB cap.

## Backups

Everything the relay keeps is one SQLite file on the `relay-data` volume. Losing it costs at most 7 days of undelivered envelopes plus the identity documents, which clients republish. So backups protect undelivered mail; they aren't critical for correctness.

[`backup.sh`](../../deploy/relay/backup.sh) copies the database while the relay runs, into `deploy/relay/backups/`, and keeps the newest 2 there:

```sh
./backup.sh
KEEP=1 POST_BACKUP='rclone copy "$1" offsite:p2p-relay-backups/' ./backup.sh
```

- **How:** `backup.mjs` runs inside the relay image (no network, the relay's hardening) and uses SQLite's `VACUUM INTO`. That reads one consistent snapshot in a single statement, so the relay's writes never restart it, and it writes a *compacted* copy, the size of the live data rather than the file's high-water mark. (SQLite's online backup API restarts whenever the database is written, so on a busy relay it never finishes, and its open read lets the WAL grow without bound. `backup.test.mjs` checks that this backup finishes under concurrent writes; the same test fails with the backup API.) The copy is written to a `.tmp` file, checked, fsynced and renamed into place, so a partial file is never left behind, and the copy just made is always kept, even with `KEEP=0`.
- **The WAL grows while it runs.** The backup's snapshot holds the relay's checkpoints back until it ends, so the WAL grows with the relay's write rate: 668 MiB in 50 s was measured on a busy 3 GiB database (about 13 MiB/s). `backup.mjs` writes a marker next to the database (`relay.db-backup`, with its deadline) for as long as it holds the snapshot, and the relay's checkpoint watchdog reads it: a backup isn't a stalled checkpoint worker, so the relay doesn't switch checkpoints back onto its main thread (which used to stall commits for 1-3.6 s after any backup over 30 s, when the first commit copied the grown WAL) and its worker catches up off the main thread when the backup ends. The relay ignores a marker past its deadline or written over an hour ago, so a killed backup can't leave its watchdog off.
- **Guards:** one backup at a time (a lock file); it refuses to run as root; a timeout that also removes the backup container, sized to the disk instead of a fixed 30 minutes (twice the copy time at `BACKUP_DISK_MBPS`, default 40 MiB/s, plus a minute, at least 2 minutes; `BACKUP_TIMEOUT` sets it outright); and a free-space check before it starts, for the copy, the WAL growth over the whole timeout (`BACKUP_WAL_MBPS`, default 16 MiB/s) and headroom (`BACKUP_HEADROOM_MB`, default 1 GiB or a tenth of the database, whichever is more). On a 3 GiB database that is a 214 s timeout and about 7.5 GiB free.
- **Throttled:** the backup container gets half a CPU (`BACKUP_CPUS`) and, if you set `BACKUP_IO_DEVICE` and `BACKUP_IO_BPS` (for example `/dev/sda` and `30mb`), a read and write limit on the disk. A slower backup holds the snapshot longer and grows the WAL more, so throttle I/O only as far as the relay needs, and raise `BACKUP_TIMEOUT` (or lower `BACKUP_DISK_MBPS`) to match.
- **`POST_BACKUP`** gets only a path `backup.mjs` named the way it names its copies, as a regular file in `backups/`, and runs under its own timeout (`POST_BACKUP_TIMEOUT`, default 1 hour). If it fails, the backup is still in `backups/` and the script exits non-zero.
- **Permissions, no sudo:** `backups/` is yours, mode `2770`, and the backup container runs as the relay's user with your primary group added, so the copies are readable by you (`0640`) and nobody else (on Debian and Ubuntu, your primary group is only you). Run it as a user in the `docker` group.

1. **Run it daily at the relay's quietest hour** (its `/metrics` show when), from cron or a systemd timer, logging outside `backups/`:

   ```cron
   17 3 * * *  cd /opt/peer2peer/deploy/relay && ./backup.sh 2>&1 | logger -t p2p-relay-backup
   ```

2. **Ship every backup off the machine** with `POST_BACKUP` (it runs with the new file as `$1`), to object storage or another host, and keep the history *there* (for example 14 daily copies). A backup on the same disk isn't one. Encrypt it at rest: the file holds envelopes (already end-to-end encrypted), public identity documents and device bindings.
3. **Restore drill**, at least once before launch and then quarterly: restore the newest copy on a scratch machine (below) and check `/healthz`.

### Disk budget

Worst case, with the default store caps (4 GiB target, 5 GiB hard cap):

| | Up to |
| --- | --- |
| The database at its high-water mark, plus its WAL (truncated back to 64 MiB, at most 256 MiB) | about 5.3 GiB |
| 2 local backups (`KEEP=2`), each at most the live data | 10 GiB |
| The backup being written (`.tmp`) | 5 GiB |
| WAL growth during a backup (the relay's write rate for as long as it runs; checked before it starts) | about 1-3 GiB at peak traffic |
| An upgrade test copy (see "Upgrades") | 5 GiB |
| OS, Docker images, logs | about 5 GiB |
| **Total** | **about 33 GiB** |

So use a 40 GB disk with the defaults, and alert at 70% (see "Monitoring"). On a 25 GB disk, set `KEEP=1` and lower the caps to `LIMIT_STORE_MAX_BYTES=3221225472` (3 GiB) and `LIMIT_STORE_HARD_MAX_BYTES=3758096384` (3.5 GiB). Real copies are usually far smaller than the cap, because `VACUUM INTO` drops free pages.

To restore: `docker compose down`, copy the backup into the volume as `relay.db` (and remove any `relay.db-wal` and `relay.db-shm` next to it), `docker compose up -d`. For example:

```sh
docker compose down
docker run --rm -v p2p-relay_relay-data:/data -v "$PWD/backups:/backup:ro" alpine:3.20 \
  sh -c 'rm -f /data/relay.db-wal /data/relay.db-shm && cp /backup/relay-<timestamp>.db /data/relay.db && chown 65532:65532 /data/relay.db'
docker compose up -d
```

## Upgrades

Upgrade it the way you would any stateful service: **back up, test on a copy, then swap.** The relay refuses to start on a database schema it doesn't understand, so a failed upgrade doesn't damage data, but test anyway.

1. **Back up:** `./backup.sh`.
2. **Keep the running image as `:prev`**, then **build the new version** without touching the running container:

   ```sh
   docker tag peer2peer/relay:local peer2peer/relay:prev
   git fetch --tags && git checkout v<new>
   docker compose build relay           # retags peer2peer/relay:local; the running container keeps its old image
   ```

3. **Test on a copy** of the backup, with the new image, on loopback only:

   ```sh
   docker volume create p2p-relay-upgrade-test
   docker run --rm -v p2p-relay-upgrade-test:/data -v "$PWD/backups:/backup:ro" alpine:3.20 \
     sh -c 'cp /backup/relay-<timestamp>.db /data/relay.db && chown -R 65532:65532 /data'
   docker run -d --name p2p-relay-upgrade-test --read-only --cap-drop ALL --security-opt no-new-privileges \
     -p 127.0.0.1:18080:8080 -v p2p-relay-upgrade-test:/data \
     -e RELAY_URL=wss://relay.example.org/v3 -e METRICS_PORT=off peer2peer/relay:local
   curl -fsS http://127.0.0.1:18080/healthz        # {"ok":true}: it opened (and, if needed, migrated) the copy
   docker logs p2p-relay-upgrade-test | tail
   docker rm -f p2p-relay-upgrade-test && docker volume rm p2p-relay-upgrade-test
   ```

4. **Swap:** `docker compose up -d relay`. Compose recreates the container with the new image. On `SIGTERM` the old relay closes every connection with code 1001, and clients reconnect to their other relays and come back; nothing un-acked is lost. Check `/healthz` and the logs.
5. **Roll back** if needed, by retagging (no rebuild): `docker tag peer2peer/relay:prev peer2peer/relay:local && docker compose up -d --no-build relay`, then check out the previous tag so the next build matches. If the new version migrated the schema, also restore the backup from step 1.

Upgrade Caddy the same way: change the pinned digest in `compose.yaml`, then `docker compose up -d caddy`.

## Fly.io

[`fly.toml`](../../deploy/relay/fly.toml) runs the same image on one Fly machine (shared CPU, 1 GB) with a 10 GB volume. Fly terminates TLS with automatic certificates and only port 443 is exposed; `/metrics` is on Fly's private network only, for Fly's managed Prometheus. From the repository root:

```sh
fly apps create peer2peer-relay
fly volumes create relay_data --size 10 --region <region> --config deploy/relay/fly.toml
fly deploy . --config deploy/relay/fly.toml --dockerfile packages/relay/Dockerfile --ha=false
fly certs add relay.example.org --config deploy/relay/fly.toml
```

Then point the domain's DNS at the app as `fly certs add` instructs. Differences from the VM recipe:

- Fly runs each machine as a micro-VM, so the container flags (`--read-only`, `--cap-drop`) don't apply; the image still runs as the unprivileged user.
- **Backups:** Fly snapshots the volume daily (`snapshot_retention = 14`). For off-platform copies, put `deploy/relay/backup.mjs` on the machine (`fly ssh sftp shell`, `put deploy/relay/backup.mjs /tmp/backup.mjs`), run it as the relay's user into the machine's ephemeral `/tmp` (`fly ssh console -u nonroot -C '/nodejs/bin/node /tmp/backup.mjs /data/relay.db /tmp/b 1 600'`: the image is distroless, with no shell and no `mkdir`, so `backup.mjs` creates `/tmp/b` itself, and it refuses to run as root, which would leave root-owned files in the volume), copy the file out with `fly ssh sftp get`, and restart or clean `/tmp/b`. Run it at the relay's quietest hour: the same WAL growth applies, and the volume needs room for it. The same `VACUUM INTO` reasoning applies.
- **Metrics:** on the first deploy, confirm Fly's managed Prometheus actually scrapes `:9464/metrics` (Fly's metrics UI or its Prometheus API). `METRICS_HOST=0.0.0.0` is reachable only over Fly's private network because no `[[services]]` entry exposes 9464; never add one, and never bind metrics to `::`.
- **Upgrades:** take a backup, then `fly deploy`. To test first, restore a snapshot into a new volume of a second, unlisted app (`fly volumes create --snapshot-id …`) and deploy the new version there.
- **Logs:** `fly logs`; Fly keeps them briefly. Same rules: `info`, never `debug`.
- Keep exactly one machine (`--ha=false`): the relay is one process with one SQLite file.

## Before you list it as public

- [ ] Domain, operator and abuse contact decided and set.
- [ ] Only 443 reachable from outside: `nmap -Pn <vm>` from another machine shows `443/tcp` open and nothing else (SSH only from admin addresses).
- [ ] `curl https://<domain>/metrics` returns 404.
- [ ] Backups run daily, are copied off the machine, and a restore drill passed.
- [ ] Uptime and disk alerts reach a person.
- [ ] `/.well-known/p2p-relay.json` shows the right `relay`, `operator.contact`, `policy` and `pow`.
