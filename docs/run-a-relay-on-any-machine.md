# Run a team relay on any machine

A private relay for a team of up to about 50 people needs very little: one small process, one SQLite file, and about 50–75 MB of memory when idle. An old laptop, a Raspberry Pi, a Jetson board, a NAS or the cheapest cloud server will do. This guide covers what differs from a server deployment; [run-a-relay.md](run-a-relay.md) is the reference for everything else.

The plan:
- run the relay in **Docker** where you can (Node 22 directly where you can't), with the `small` preset and a memory cap;
- keep its database on **real storage**: an SSD, not an SD card;
- let teammates reach it through a **Tailscale** tailnet, or a **Cloudflare Tunnel** with the relay in members-only mode, so the machine needs no public IP and no open port.

## Pick a machine

| Machine | Works well | Watch out for |
|---|---|---|
| **Old laptop or mini PC** (x86-64) | Plenty of RAM and an SSD already; Docker or Node 22 both fine. A laptop's battery doubles as a UPS. | Old kernels and distributions: Docker needs 20.10.10 or newer, Node 22 needs glibc 2.28 or newer (Ubuntu 20.04, Debian 10 or later). Turn off sleep on lid close. A 32-bit-only CPU (before about 2007) can't run either. |
| **Raspberry Pi 3, 4 or 5** | Low power, silent. A Pi 4 or 5 can boot from a USB SSD (a Pi 5 also from NVMe). [Notes](#raspberry-pi). | **SD-card wear** (use a USB SSD). Use the **64-bit** OS: the image is arm64 and amd64 only, and a 32-bit OS can't run it. A Pi 3 has 1 GB of RAM, which is tight: the script then sizes the container to 512 MiB. |
| **NVIDIA Jetson** (Nano, Xavier, Orin) | Four cores and 2–8 GB of RAM. The relay doesn't use the GPU. [Notes](#jetson-nano). | JetPack 4 (Nano) is Ubuntu 18.04 with **glibc 2.27 and kernel 4.9**: Node 22 can't run natively, so use Docker. Boots from **SD card or eMMC**: put the data on a USB SSD. 2 GB of RAM is shared with the GPU. |
| **Cheap cloud server** (1 vCPU, 1 GB) | Always on, a public IP, real disks. | Costs money, and anything on a public IP gets scanned: keep the relay on localhost behind Caddy or a tunnel ([future/public-relay.md](future/public-relay.md) has a hardened recipe). 1 GB of RAM: the `small` preset fits. |
| **NAS with Docker** (Synology, QNAP, TrueNAS, Unraid) | Already on, already backed up, real disks. | Many vendors ship old Docker builds: check `docker version` is 20.10.10 or newer. Some NAS CPUs are 32-bit ARM, which can't run the image. Point the data volume at a disk pool, not the system partition. |
| **Windows 10/11 PC or Windows Server** | Docker Desktop (WSL2) or Node 22 both work. [Notes](#windows). | Sleep and automatic restarts for updates. Docker Desktop must use **Linux containers**. |

Anything with 1 GB of RAM or more, a 64-bit x86 or ARM CPU, and either Docker 20.10.10+ or Node 22.13+ works.

## Quick install

The install scripts detect what the machine has and set the relay up the way this guide describes: Docker if it's new enough, otherwise Node 22 as a system service, otherwise a list of what's missing. Both listen on localhost only and finish by printing the URL to give your team. Read the [script itself](../scripts/install-relay.sh) before running it; `--dry-run` / `-DryRun` prints the plan without changing anything.

**From a checkout** (works today; the scripts build from the current directory only when it is a git checkout of this repository, or from the folder you name in `P2P_SOURCE_DIR`):

```sh
git clone https://github.com/ix-infrastructure/Peer2Peer && cd Peer2Peer
sh scripts/install-relay.sh --dry-run --url wss://relay.example.org/v3     # look first
sh scripts/install-relay.sh --url wss://relay.example.org/v3
```

```powershell
git clone https://github.com/ix-infrastructure/Peer2Peer; cd Peer2Peer
.\scripts\install-relay.ps1 -DryRun -Url wss://relay.example.org/v3
.\scripts\install-relay.ps1 -Url wss://relay.example.org/v3
```

**From the website** (*available at launch*: until the first release is pinned in the scripts, they ask you to run them from a checkout):

```sh
curl -fsSL https://ix-infra.com/p2p/install-relay.sh | sh -s -- --url wss://relay.example.org/v3
```

```powershell
irm https://ix-infra.com/p2p/install-relay.ps1 | iex
```

`| iex` can't pass parameters, so set the relay URL (and any other option) in the environment first: `$env:P2P_RELAY_URL = 'wss://relay.example.org/v3'` (also `P2P_RELAY_PRESET`, `P2P_RELAY_DATA_DIR`, `P2P_RELAY_DRY_RUN=1`). To pass parameters instead: `& ([scriptblock]::Create((irm https://ix-infra.com/p2p/install-relay.ps1))) -Url wss://relay.example.org/v3`.

**Download, check, then run** (if you'd rather not pipe a download into a shell): fetch the script and the checksum list, compare, read it, then run it.

```sh
curl -fsSLO https://ix-infra.com/p2p/install-relay.sh
curl -fsSLO https://ix-infra.com/p2p/install-relay.sha256
grep ' install-relay.sh$' install-relay.sha256 | sha256sum -c -     # macOS: ... | shasum -a 256 -c -
less install-relay.sh
sh install-relay.sh --url wss://relay.example.org/v3
```

```powershell
irm https://ix-infra.com/p2p/install-relay.ps1 -OutFile install-relay.ps1
irm https://ix-infra.com/p2p/install-relay.sha256 -OutFile install-relay.sha256
(Get-FileHash .\install-relay.ps1 -Algorithm SHA256).Hash.ToLower()
Select-String install-relay.ps1 .\install-relay.sha256     # the two hashes must match
.\install-relay.ps1 -Url wss://relay.example.org/v3
```

`scripts/install-relay.sha256` in the repository is the same list; `npm run install-scripts:checksums` in `packages/relay` regenerates it.

How the scripts are built to be safe:
- the whole body is one function called on the last line, so a download cut short runs nothing;
- they never rely on their own file path;
- outside a checkout, they fetch the relay source for one pinned release and check its SHA-256 before using it;
- sudo (or a UAC prompt on Windows) is used only for the system steps (the service account, the install folder, the service itself, and the firewall rule if you ask for one), and the script says so before it asks. Docker needs none.

| Option | sh | PowerShell | Meaning |
|---|---|---|---|
| Relay URL | `--url` | `-Url` | The exact `wss://<host>/v3` clients will dial (see [How teammates reach it](#how-teammates-reach-it)). |
| Port | `--port` | `-Port` | Local port, default 8080. |
| Preset | `--preset small\|default` | `-Preset` | Default: `small` under 4 GB of RAM. |
| Data folder | `--data-dir` | `-DataDir` | Keep the database there instead of in a Docker volume (for example on a USB SSD). It must be a new or empty folder, or one the relay already owns; the scripts refuse `/`, drive roots, home and profile folders, system folders, links, and paths with characters other than letters, digits and `/ . _ -` (spaces too on Windows). |
| Method | `--method auto\|docker\|node` | `-Method` | Force Docker or Node. |
| Replace | `--replace` | `-Replace` | Upgrade an existing install (the data stays). |
| Other settings | `--env NAME=VALUE` (repeatable) | `-RelayEnv @{ NAME = 'value' }` | Any other relay setting, for example `RELAY_ALLOW_CIRCLE=c_…` for [members-only mode](#members-only-mode). Pass them again with `--replace`. |
| Dry run | `--dry-run` | `-DryRun` | Print the plan; change nothing. |
| Firewall | | `-OpenFirewall` | Windows only: listen on every interface and allow the port on Private networks. Off by default; prefer a tunnel. |

What each path sets up:
- **Docker:** builds the image from the source (there's no published image yet), then runs it with `--restart unless-stopped`, `--memory` sized from RAM (512 MiB under 1.5 GB of RAM, 768 MiB under 4 GB, otherwise 1 GiB), a matching `--max-old-space-size`, a read-only root filesystem, no capabilities, `no-new-privileges`, log rotation, and a named volume `p2p-relay-data` (or `--data-dir`). It warns when the data would land on an SD card or eMMC (`/dev/mmcblk*`).
- **Node on Linux:** builds the relay as you, copies it into `/opt/p2p-relay` (owned by root), and installs a systemd unit that runs it as a dedicated `p2p-relay` system user with `MemoryMax`, `ProtectSystem=strict`, `NoNewPrivileges` and a private `/tmp`; the database is in `/var/lib/p2p-relay` (or `--data-dir`).
- **Node on macOS:** prints a launchd job to install yourself.
- **Node on Windows:** see [Windows](#windows).

The rest of this guide is what the scripts do, step by step, plus what they can't do for you: storage, access, backups and upgrades.

## Storage: keep the database off SD cards

SQLite with a write-ahead log makes many small writes: every stored message, every ack, every checkpoint. SD cards and cheap eMMC have little spare area and simple wear levelling, so this load wears them out in months rather than years, and many cards corrupt data on power loss. When the card holds the operating system, the machine stops booting. Any SSD (a small SATA SSD in a USB 3 enclosure is cheap) handles it for years. On a laptop, mini PC, NAS or cloud server the built-in disk is already fine.

On a single-board computer, format the SSD as ext4 and mount it by UUID, with `nofail` so a missing drive doesn't block boot:

```sh
lsblk -f                                  # find the SSD, for example /dev/sda1
sudo mkfs.ext4 -L p2p-relay /dev/sda1     # erases it
sudo mkdir -p /srv/p2p-relay
echo "UUID=$(sudo blkid -s UUID -o value /dev/sda1) /srv/p2p-relay ext4 defaults,noatime,nofail 0 2" | sudo tee -a /etc/fstab
sudo mount -a && df -h /srv/p2p-relay
sudo install -d -o 65532 -g 65532 -m 0750 /srv/p2p-relay/data          # the container's user
sudo install -d -o "$USER" -g "$(id -g)" -m 2770 /srv/p2p-relay/backups
```

Then install with `--data-dir /srv/p2p-relay/data`. The relay mounts it with `--mount`, which refuses a missing source: if the SSD ever fails to mount, the relay won't start, rather than quietly starting an empty database on the SD card. Optionally, move Docker's own storage there too (`"data-root": "/srv/p2p-relay/docker"` in `/etc/docker/daemon.json`), so image layers and logs don't write to the card either.

Budget about 2 GiB for the database under the `small` preset (512 MiB of envelopes at most, a small write-ahead log, identity documents, indexes), plus room for two backups.

## Run it by hand (Docker)

This is what `install-relay.sh` runs, for when you'd rather do it yourself. Build the image (multi-arch: on any machine, for any target):

```sh
docker buildx build --platform linux/arm64 -f packages/relay/Dockerfile -t peer2peer/relay:local --load .   # or linux/amd64
docker save peer2peer/relay:local | gzip | ssh <user>@<machine> 'gunzip | docker load'                     # if built elsewhere
```

The build stages only compile TypeScript and install pure-JavaScript packages, so a cross-build needs no emulation. To push one tag for both architectures to your own registry: `docker buildx build --platform linux/arm64,linux/amd64 -f packages/relay/Dockerfile -t registry.example.org/peer2peer/relay:<version> --push .`

Put the settings in an env file, for example `/srv/p2p-relay/relay.env` (`chmod 600`; Docker reads values literally, so don't quote them):

```sh
RELAY_URL=wss://relay.example.org/v3
RELAY_NAME=Example team relay
OPERATOR_CONTACT=mailto:ops@example.org
RELAY_POLICY=Private relay for the Example team. Counters-only logs; envelopes deleted on ack or after 7 days.
RELAY_PRESET=small
NODE_OPTIONS=--disable-warning=ExperimentalWarning --max-old-space-size=384
TRUST_PROXY=1
```

```sh
docker run -d --name p2p-relay --restart unless-stopped \
  --env-file /srv/p2p-relay/relay.env \
  -p 127.0.0.1:8080:8080 \
  --mount type=bind,source=/srv/p2p-relay/data,target=/data \
  --memory 768m --memory-swap 768m --pids-limit 128 \
  --read-only --tmpfs /tmp:size=16m --cap-drop ALL --security-opt no-new-privileges \
  --log-opt max-size=10m --log-opt max-file=3 \
  peer2peer/relay:local
docker logs p2p-relay | tail -3       # "relay preset" {"preset":"small"}, then "relay listening"
curl -fsS http://127.0.0.1:8080/healthz && echo
```

- `-p 127.0.0.1:8080:8080` publishes the relay on loopback only: the tunnel or proxy is the only way in, which is what makes `TRUST_PROXY=1` safe.
- `--memory-swap` equal to `--memory` keeps it out of swap. If `docker info` warns that the kernel has no swap limit support, Docker ignores that flag; the memory limit still applies.
- Without Docker, the same settings work as environment variables for `node packages/relay/dist/bin.js` ([Run it](run-a-relay.md#run-it)).

## The `small` preset

`RELAY_PRESET=small` sizes the relay for 1–4 GB of RAM and a team of up to about 50 people. It lowers capacity limits only: frame and envelope sizes, retention (7 days) and the rest of the protocol stay as they are. Any `LIMIT_*` or `SQLITE_*` variable, or the `limits` / `storage` objects in a `RELAY_CONFIG` file, still overrides a single value. Without `RELAY_PRESET`, the server defaults apply unchanged.

| Setting | Default | `small` |
|---|---|---|
| `LIMIT_STORE_MAX_BYTES` / `LIMIT_STORE_HARD_MAX_BYTES` | 4 GiB / 5 GiB | 448 MiB / **512 MiB** (hard cap: sends past it get `undeliverable`) |
| `LIMIT_MAILBOX_ENVELOPES` / `LIMIT_MAILBOX_BYTES` | 10,000 / 64 MiB | 2,000 / 16 MiB |
| `LIMIT_RECIPIENT_MAX_BYTES` | 256 MiB | 32 MiB |
| `LIMIT_SOURCE_MAX_BYTES` / `LIMIT_SOURCE_ACCEPTED_BYTES_PER_HOUR` | 512 MiB / 256 MiB | 256 MiB / 128 MiB |
| `LIMIT_SEND_BYTES_PER_CONN_PER_MINUTE` / `..._PER_IP_PER_MINUTE` | 8 MiB / 32 MiB | 4 MiB / 16 MiB |
| `LIMIT_MAX_CONNECTIONS` | 10,000 | 400 |
| `LIMIT_MAX_CONNECTIONS_PER_IP` / `..._PER_IPV4` | 64 / 512 | 64 / 64 |
| `LIMIT_MAX_UNAUTH_CONNECTIONS` / `LIMIT_MAX_UNAUTH_PER_IP` | 2,000 / 8 | 100 / 8 |
| `LIMIT_NEW_DEVICES_PER_IP_PER_DAY` / `..._PER_IPV4_PER_DAY` | 50 / 1,000 | 100 / 100 |
| `LIMIT_AUTHS_PER_IP_PER_MINUTE` / `..._PER_IPV4_PER_MINUTE` | 60 / 600 | 60 / 60 |
| `LIMIT_MAX_DEVICES` | 1,000,000 | 10,000 |
| `LIMIT_LINK_TOTAL_BYTES` / `LIMIT_INVITE_TOTAL_BYTES` | 64 MiB / 256 MiB | 8 MiB / 16 MiB |
| `SQLITE_WAL_LIMIT_BYTES` (WAL watchdog threshold) | 256 MiB | 64 MiB |
| `SQLITE_JOURNAL_SIZE_LIMIT_BYTES` (WAL truncated back to this after a checkpoint) | 64 MiB | 16 MiB |
| `SQLITE_CHECKPOINT_INTERVAL_MS` (10 ms to 10 s) | 100 | 500 |

Why these:
- **Memory:** `--max-old-space-size=384` caps the JavaScript heap (V8 reads it at startup, so it goes in `NODE_OPTIONS`, not in the relay's config), and the 768 MiB container cap leaves room for SQLite's cache, the checkpoint thread and buffers.
- **Per-address limits are moderate.** 64 connections, 100 new devices a day and 60 sign-ins a minute per address are far more than one person or a small office needs, but low enough that a single outside address can't take all 400 connections or fill the device table, which matters as soon as the relay is reachable through a public tunnel.
- **Checkpoints every 500 ms** batch more page writes into each pass, which is gentler on flash, and still keep the write-ahead log small. The interval is capped at 10 s, so the log can't grow unchecked between passes.

**A whole office behind one NAT address.** If most of the team reaches the relay from one public address (an office network through a Cloudflare Tunnel, say), that address shares one per-address allowance. For 50 people with a few devices each, raise these together:

```sh
LIMIT_MAX_CONNECTIONS_PER_IPV4=400
LIMIT_NEW_DEVICES_PER_IPV4_PER_DAY=500
LIMIT_AUTHS_PER_IPV4_PER_MINUTE=300
LIMIT_MAX_UNAUTH_PER_IP=32
```

Only do this for an address you know; on a tailnet each device has its own address and the preset's values are plenty.

**When the device table fills up** (`LIMIT_MAX_DEVICES`, 10,000 under `small`): each device that ever signed in holds one small binding, kept for 90 days after it was last seen (`LIMIT_DEVICE_RETENTION_SEC`). When the table is full, a new device evicts the least recently seen binding that has no stored envelopes, no live connection, and isn't listed in a held identity document. A new device is refused only when nothing can be evicted: its sign-in fails with the error `full` and close code 4029, and with `LOG_LEVEL=debug` the relay logs `auth failed` with `why: device-cap`. Devices the relay already knows, and devices listed in their user's identity document, always get in. Past 80% of the cap, IPv4 addresses also get the stricter new-device allowance. A team of 50 won't come close; a flood of throwaway devices might. To recover:
1. Count the bindings: `docker exec p2p-relay /nodejs/bin/node -e "const {DatabaseSync}=require('node:sqlite');console.log(new DatabaseSync('/data/relay.db',{readOnly:true}).prepare('SELECT count(*) n FROM devices').get().n)"`.
2. Raise the cap (`LIMIT_MAX_DEVICES=50000`: each binding is a row of about 100 bytes) and restart, so new devices get in again.
3. If the bindings came from a flood, also shorten `LIMIT_DEVICE_RETENTION_SEC` (for example `604800`, 7 days) so idle ones are swept sooner, turn on members-only mode ([below](#members-only-mode)), which refuses strangers before they get a device binding at all, and lower the per-address new-device limits.

## How teammates reach it

Clients dial `wss://` only, and they hang up unless the URL they dialled is exactly the relay's `RELAY_URL` ([why](run-a-relay.md#relay_url-must-be-exact)). So pick **one** way in and set `RELAY_URL` to its address.

### Option A: a Tailscale tailnet (recommended)

Only devices on your tailnet can reach the relay, and nothing is exposed to the internet.

1. [Install Tailscale](https://tailscale.com/kb/1347/installation) on the relay machine and on teammates' devices.
2. In the admin console, enable [MagicDNS and HTTPS certificates](https://tailscale.com/kb/1153/enabling-https).
3. Serve the relay over HTTPS on the tailnet only:

   ```sh
   sudo tailscale serve --bg 8080
   tailscale serve status         # shows the https:// name it serves
   ```

   This is `serve`, which is tailnet-only. Don't use `funnel`: it would put the relay on the public internet.
4. Set `RELAY_URL` to that name with `wss://` and `/v3`, for example `wss://<machine>.<your tailnet's DNS name>/v3`, in lowercase, and rerun the installer with `--replace` (or recreate the container).

Use your tailnet's access controls to decide which devices may reach it.

### Option B: a Cloudflare Tunnel, with members-only mode

For teammates who can't join the tailnet. A tunnel connects out from the machine to Cloudflare, so you need a domain on Cloudflare but no open port and no public IP.

**A tunnel makes the relay reachable from the internet.** Without a gate, anyone who learns the hostname can connect, register devices and store envelopes within the limits above. Run a tunnel only with the relay in [members-only mode](#members-only-mode); until that is available, use Option A.

1. [Install `cloudflared`](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/) (there are amd64 and arm64 packages, and a Windows installer).
2. [Create a tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/get-started/) with a public hostname, for example `relay.example.org`, whose service is `http://localhost:8080`, and run it as a system service. WebSockets pass through by default.
3. Set `RELAY_URL=wss://relay.example.org/v3` and turn on members-only mode, for example `--env RELAY_ALLOW_CIRCLE=c_…` (below), then rerun the installer with `--replace`.

Raise `POW_BITS` if strangers ever send first-contact spam ([Choosing limits](run-a-relay.md#choosing-limits)).

*Optional extra layer:* if every teammate's device is enrolled in your Cloudflare Zero Trust organisation with the WARP client, a [Cloudflare Access application](https://developers.cloudflare.com/cloudflare-one/applications/configure-apps/self-hosted-public-app/) with a device-based policy can also keep strangers away from the hostname. It doesn't replace members-only mode: the relay's clients can't complete a browser login, so an Access policy that needs one locks your team out.

### Members-only mode

With members-only mode, the relay admits only your group and refuses everyone else at sign-in (error `not-member`), before they get a device binding, a mailbox or anything else. That also keeps strangers out of the device table. Set one or more of:

| Setting | Meaning |
|---|---|
| `RELAY_ALLOW` | userIds to admit, separated by commas or spaces. |
| `RELAY_ALLOW_FILE` | A file with one userId per line (`#` comments). The relay rereads it when it changes, and removals take effect at once. |
| `RELAY_ALLOW_CIRCLE` | `c_…`: admit the members of that circle. The relay follows the circle's signed history, so adding or removing someone in the circle updates the relay too. **It must not be an open circle**: anyone can join an open circle, so it would admit anyone (the relay refuses one). Use a closed circle whose owner approves members. |

New teammates join with an invite code from a member, which admits them until the list or circle includes them. Pass them to the installer with `--env RELAY_ALLOW_CIRCLE=c_…` (`-RelayEnv @{ RELAY_ALLOW_CIRCLE = 'c_…' }` in PowerShell), and again whenever you rerun it with `--replace`, which replaces the settings. With Docker, put an allow file in the data folder and point `RELAY_ALLOW_FILE` at `/data/<name>`. [run-a-relay.md](run-a-relay.md) has the details once the mode is merged.

It's worth turning on with Option A too: the tailnet decides who can reach the relay, and members-only mode decides who can use it.

### `TRUST_PROXY`

Both `tailscale serve` and Cloudflare pass the client's address in `X-Forwarded-For`, and the relay is only reachable through them, so the scripts set `TRUST_PROXY=1` and per-address limits see each client. If the relay logs that the header has fewer entries than `TRUST_PROXY`, set `TRUST_PROXY=0`; every client then shares the proxy's address, so raise the per-address limits as for an office NAT above.

## Health checks

- `curl -fsS http://127.0.0.1:8080/healthz` on the machine returns `{"ok":true}`; from a teammate's machine, `curl -fsS https://relay.example.org/healthz` (your `RELAY_URL` host).
- Docker: the image has a `HEALTHCHECK` (every 30 s): `docker inspect -f '{{.State.Health.Status}}' p2p-relay` prints `healthy`. `unless-stopped` restarts a container that exits, not one that is merely unhealthy, so watch this from your monitoring. `docker stats --no-stream p2p-relay` shows memory against the cap.
- systemd: `systemctl status p2p-relay`, `journalctl -u p2p-relay`.
- Metrics: add `-e METRICS_HOST=0.0.0.0 -p 127.0.0.1:9464:9464` to the `docker run` (the Node install serves them on `127.0.0.1:9464` already) and scrape `/metrics` ([Operations](run-a-relay.md#operations)).
- Disk: `df -h /srv/p2p-relay`, and `sudo smartctl -a /dev/sda` if the enclosure passes SMART through.

## Backups

Everything the relay keeps is `relay.db` (plus `-wal` and `-shm`). Losing it costs at most 7 days of undelivered messages plus identity documents, which clients republish, so backups protect undelivered mail; they aren't critical for correctness.

**What a backup reveals.** Message contents are end-to-end encrypted, but the database also holds metadata in the clear: which device mailboxes exist, who has mail waiting from which sending address, envelope sizes and times, device bindings, and public identity documents. Treat every copy like the live relay: **encrypt it before it leaves the machine** and keep it where only operators can read it.

Back up with [`deploy/relay/backup.mjs`](../deploy/relay/backup.mjs), the tool the [public-relay recipe](future/public-relay.md#backups) uses: it runs inside the relay image, takes one consistent, compacted copy with SQLite's `VACUUM INTO` while the relay keeps running, and tells the relay's checkpoint watchdog that a backup is in progress. (`backup.sh` wraps it for the Compose layout; here, call `backup.mjs` directly.)

```sh
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --memory 256m --cpus 1 --user 65532:65532 --group-add "$(id -g)" \
  --mount type=bind,source=/srv/p2p-relay/data,target=/data \
  --mount type=bind,source=/srv/p2p-relay/backups,target=/backup \
  --mount type=bind,source=/opt/peer2peer/deploy/relay/backup.mjs,target=/backup.mjs,readonly \
  --entrypoint /nodejs/bin/node peer2peer/relay:local \
  /backup.mjs /data/relay.db /backup 2 600
```

(With a named volume instead of a folder, use `--mount type=volume,source=p2p-relay-data,target=/data`. For the Node install, run `node backup.mjs /var/lib/p2p-relay/relay.db <backup-dir> 2 600` as the `p2p-relay` user.) It prints the new file's path, keeps the newest 2 copies, and stops itself after 600 s.

Then ship each copy off the machine, encrypted. Two good options:
- **[restic](https://restic.net)** encrypts and deduplicates, and keeps a history on any backend (another machine over SFTP, S3-compatible storage, a USB disk):

  ```sh
  restic -r sftp:<backup-host>:p2p-relay-backups backup /srv/p2p-relay/backups     # once: restic init
  restic -r sftp:<backup-host>:p2p-relay-backups forget --keep-daily 14 --prune
  ```

- **[age](https://age-encryption.org)** encrypts single files to a public key, so the machine can encrypt but not decrypt:

  ```sh
  f=$(ls -t /srv/p2p-relay/backups/relay-*.db | head -1)
  age -r age1<your-public-key> -o "$f.age" "$f" && rsync -a "$f.age" <backup-host>:p2p-relay-backups/ && rm "$f.age"
  ```

Run the backup and the upload daily from cron at a quiet hour, as a user in the `docker` group. A backup on the same disk isn't one.

**Restore:** stop the relay, put the decrypted backup in place as `relay.db`, remove the old WAL files, and start it again:

```sh
docker stop p2p-relay
sudo rm -f /srv/p2p-relay/data/relay.db-wal /srv/p2p-relay/data/relay.db-shm
sudo install -o 65532 -g 65532 -m 0640 relay-<timestamp>.db /srv/p2p-relay/data/relay.db
docker start p2p-relay
```

## Upgrades

Back up, test the new version on a copy, then swap. The relay refuses to start on a database schema it doesn't understand, so a failed upgrade doesn't damage data.

1. **Back up** (above).
2. **Keep the running image** as `:prev`: `docker tag peer2peer/relay:local peer2peer/relay:prev`.
3. **Test the new version on a copy** of the backup, on another loopback port:

   ```sh
   git pull   # or check out the new release tag
   docker buildx build -f packages/relay/Dockerfile -t peer2peer/relay:next --load .
   mkdir -p /srv/p2p-relay/upgrade-test && cp /srv/p2p-relay/backups/relay-<timestamp>.db /srv/p2p-relay/upgrade-test/relay.db
   sudo chown -R 65532:65532 /srv/p2p-relay/upgrade-test
   docker run -d --name p2p-relay-test -p 127.0.0.1:18080:8080 --memory 768m \
     -e RELAY_URL=wss://relay.example.org/v3 -e RELAY_PRESET=small -e METRICS_PORT=off \
     --mount type=bind,source=/srv/p2p-relay/upgrade-test,target=/data peer2peer/relay:next
   curl -fsS http://127.0.0.1:18080/healthz && echo
   docker rm -f p2p-relay-test && sudo rm -rf /srv/p2p-relay/upgrade-test
   ```

4. **Swap:** rerun the installer with the same options plus `--replace` / `-Replace` (or `docker rm -f p2p-relay` and the same `docker run`). On `SIGTERM` the old relay closes connections with code 1001; clients reconnect, and nothing un-acked is lost.
5. **Roll back** if needed: `docker tag peer2peer/relay:prev peer2peer/relay:local`, recreate the container, and, if the new version migrated the schema, restore the backup from step 1. The Node install keeps the previous version in `/opt/p2p-relay.old`.

## Jetson Nano

JetPack 4.x is Ubuntu 18.04 with glibc 2.27 and kernel 4.9. Official Node 22 binaries need glibc 2.28 or newer, so Node won't run natively; the image brings its own (Debian 12, glibc 2.36, Node 22), so the board only needs Docker, which JetPack ships. The relay doesn't use the GPU: no `nvidia-container-toolkit`, `--runtime nvidia` or CUDA setup is needed, and if JetPack made `nvidia` Docker's default runtime, that's harmless.

1. Flash JetPack 4.6.x and finish first boot: NVIDIA's [Getting Started with Jetson Nano 2GB](https://developer.nvidia.com/embedded/learn/get-started-jetson-nano-2gb-devkit) (headless setup over the USB serial console works without a monitor).
2. Boot headless to free several hundred MB: `sudo systemctl set-default multi-user.target && sudo reboot`.
3. Add yourself to the `docker` group (`sudo usermod -aG docker "$USER"`, then log in again) and check `docker version`. Docker older than 20.10.10 has a seccomp profile that predates the `clone3` call newer glibc uses, so the container can't start threads: update it (`sudo apt update && sudo apt install --only-upgrade docker.io`, or [Docker's packages for Ubuntu 18.04](https://docs.docker.com/engine/install/ubuntu/)). Don't work around it with `--security-opt seccomp=unconfined`.
4. Set up a USB SSD ([Storage](#storage-keep-the-database-off-sd-cards)), then run the installer with `--data-dir /srv/p2p-relay/data`. It picks the `small` preset and a 768 MiB cap on the 2 GB board.

Building on the board works (the installer uses `DOCKER_BUILDKIT=1` when there's no buildx), but it's slow; building on another machine and loading the image with `docker save | ssh ... docker load` is quicker.

Jetson Xavier and Orin boards run JetPack 5 or 6 (Ubuntu 20.04 or 22.04), where Node 22 also runs natively; Docker is still the simpler path.

## Raspberry Pi

- Use **64-bit Raspberry Pi OS** (or another arm64 distribution). The image is arm64 and amd64 only.
- Install Docker with [Docker's Debian instructions](https://docs.docker.com/engine/install/debian/) and add yourself to the `docker` group.
- A Pi 4 or 5 can [boot from the USB SSD](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#usb-mass-storage-boot) (a Pi 5 also from NVMe), which takes the SD card out of the picture entirely. Otherwise use `--data-dir` on the SSD as above.
- Raspberry Pi OS reports its root filesystem as `/dev/root`; the installer looks up the real device from the kernel command line to warn about SD cards, and may not be able to tell when root is given as a `PARTUUID`. Check with `lsblk` yourself.
- With 4 GB or more the installer picks the default preset and a 1 GiB cap; the `small` preset (`--preset small`) is still plenty for 50 people.

## Windows

`install-relay.ps1` works on Windows 10/11 and Windows Server with PowerShell 5.1 or newer.

- **With Docker Desktop** using Linux containers (the WSL2 backend): same as Linux, a hardened container in a named volume, no elevation.
- **Without Docker, with Node 22.13+** installed for all users (the installer under `C:\Program Files\nodejs`): it builds the relay as you, then asks once for administrator rights to copy it into `%ProgramData%\p2p-relay` and register a **Scheduled Task** that starts it at boot as a dedicated local account, `p2p-relay`.
  - *Why a Scheduled Task:* a Windows service has to speak the service-control protocol, which `node.exe` doesn't, so running Node as a service needs a third-party wrapper (NSSM, WinSW). A task with an "at startup" trigger needs nothing extra, and restarts the relay if it exits.
  - *Why a dedicated account:* `LocalSystem` would give the relay the whole machine, and `LocalService` is shared by many Windows services, so anything it may write, they may too. The `p2p-relay` account belongs to no group; its random password is generated in the elevated step, handed only to Task Scheduler, and never shown or stored anywhere else. It can read the install folder but not change it, and can write only its data folder.
  - *User rights:* the elevated step grants the account "Log on as a batch job" (what a task needs) and denies "Log on locally" and "Log on through Remote Desktop Services", with `secedit`. On a domain-joined machine, a domain Group Policy that sets these rights replaces the local settings at the next policy refresh: the task may then fail to start (no batch logon) or the account may be able to sign in again. Check with `gpresult /h report.html`, and have the domain policy include the `p2p-relay` account, or run the relay with Docker.
  - *Folders:* the elevated step changes the owner and permissions of the install folder and the data folder, so no folder above either of them, from the drive root down, may be one you can delete, rename or re-permission without elevation (owning it counts). Being able to create new folders in, say, `C:\` is fine: the elevated step creates missing folders itself, one at a time, each already locked to Administrators and SYSTEM when it is created, and stops if one turns up owned by someone else. The elevated step works out who you are from its own (elevated) token and repeats the check, so nothing the unelevated part says is trusted. If the check refuses a custom `-DataDir`, create its parent in an elevated prompt (for example `New-Item D:\p2p-relay -ItemType Directory; icacls D:\p2p-relay /inheritance:r /grant:r *S-1-5-32-544:(OI)(CI)F *S-1-5-18:(OI)(CI)F`), or leave `-DataDir` out. A `%ProgramData%\p2p-relay` (or data folder) that another account created first is deleted and created again if it's empty, and refused if it isn't.
  - *How elevation works:* the elevated step is passed on the elevated PowerShell's command line (`-EncodedCommand`), never written to a file a non-administrator could change in between. It copies the build with `robocopy /XJ`, which follows no links, and checks again for itself that neither folder already holds someone else's files.
  - The relay's output goes to `%ProgramData%\p2p-relay\data\relay.log`.
- It listens on `127.0.0.1` only. `-OpenFirewall` makes it listen on every interface and adds a Windows Firewall rule for the port on Private networks; prefer a tunnel instead (`cloudflared` and Tailscale both run on Windows).
- Keep the machine from sleeping, and schedule Windows Update restarts for a quiet hour.

## Known gaps

- **Not yet run on physical hardware other than a Mac.** The arm64 and amd64 images, the relay's test suite inside them, the Docker install path and the Linux Node install path (with a stand-in for systemd) pass in containers. Running on a Jetson Nano's kernel 4.9 hasn't been verified: Node 22's documented minimum Linux kernel is 4.18, so treat the first boot as a test and report what you find.
- **`install-relay.ps1` needs a test on real Windows before it's relied on.** It passes PSScriptAnalyzer and its dry-run tests in PowerShell 7 on Linux, but the steps that only Windows can run haven't been: the account, `secedit` user rights, the folder ACLs and owner, `robocopy`, the Scheduled Task and the firewall rule.
- **`X-Forwarded-For`** from `tailscale serve` and Cloudflare Tunnel hasn't been checked against the relay's hop count; the [`TRUST_PROXY`](#trust_proxy) note says how to tell and what to do.
