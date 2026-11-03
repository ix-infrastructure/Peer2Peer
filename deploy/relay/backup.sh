#!/usr/bin/env bash
# Copyright 2026 Ix Infrastructure Inc.
#
# Backup of the relay's SQLite database (compose.yaml) while it runs.
# backup.mjs does the work inside the relay image (node:sqlite VACUUM INTO: one
# consistent, compacted snapshot that concurrent writes never restart; see its
# header). backup.test.mjs proves it finishes under write load.
#
#   ./backup.sh                  # backups/relay-<UTC timestamp>.db; keeps the newest KEEP (default 2)
#   KEEP=1 ./backup.sh
#   POST_BACKUP='rclone copy "$1" offsite:p2p-relay-backups/' ./backup.sh
#
# Keep only 1-2 copies on the machine and ship every backup off it with
# POST_BACKUP (it runs with the new file's path as $1); each copy can be as large
# as the live data. docs/future/public-relay.md, "Backups", has the disk budget.
#
# No sudo needed, and it refuses to run as root. backups/ is owned by you, mode
# 2770 (setgid), and the backup container runs as the relay's user (65532) with
# your primary group added, so it can write there and you can read the copies
# (0640). On a host with per-user primary groups (Debian, Ubuntu) that group is
# only you.
#
# While it runs, the backup's snapshot holds the relay's WAL checkpoints back:
# the WAL grows with the relay's write rate (measured: 668 MiB in 50 s on a busy
# 3 GiB database) until it ends. So:
#  - schedule it at the relay's quietest hour (see its metrics);
#  - the free-space check budgets the copy, that WAL growth for the whole
#    timeout, and headroom;
#  - the timeout follows the database size and the disk's speed instead of a
#    fixed 30 minutes;
#  - the container gets a CPU share (and, optionally, an I/O limit), so the
#    relay keeps the machine;
#  - backup.mjs tells the relay it is running (<db>-backup), so the relay's
#    checkpoint watchdog doesn't take it for a stall.
#
# Settings (environment):
#   KEEP                 local copies to keep (2)
#   BACKUP_DISK_MBPS     MiB/s this disk reads and writes the copy (40); sets the default timeout
#   BACKUP_TIMEOUT       seconds before the backup is stopped (default: 2 x the copy time at
#                        BACKUP_DISK_MBPS + 60, at least 120)
#   BACKUP_WAL_MBPS      MiB/s the relay's WAL may grow during a backup (16)
#   BACKUP_HEADROOM_MB   free MiB to leave after the worst case (1024, or a tenth of the database)
#   BACKUP_CPUS          CPUs for the backup container (0.5)
#   BACKUP_IO_DEVICE, BACKUP_IO_BPS
#                        optional: limit the container's reads and writes on that block device
#                        (for example /dev/sda and 30mb); a slower backup holds the WAL longer
#   POST_BACKUP          command run with the new file's path as $1 (optional)
#   POST_BACKUP_TIMEOUT  seconds before POST_BACKUP is stopped (3600)
#
# Run it daily from cron as a user in the docker group, logging outside backups/:
#   17 3 * * *  cd /opt/peer2peer/deploy/relay && ./backup.sh 2>&1 | logger -t p2p-relay-backup
set -euo pipefail
cd "$(dirname "$0")"

if [ "$(id -u)" -eq 0 ]; then
  echo "refusing to run as root: run it as a user in the docker group (see docs/future/public-relay.md)" >&2
  exit 1
fi

posint() { # name value: a positive integer, or exit
  case "$2" in '' | *[!0-9]* | 0) echo "$1 must be a positive integer, not '$2'" >&2; exit 1 ;; esac
}
keep="${KEEP:-2}"
case "$keep" in '' | *[!0-9]*) echo "KEEP must be a number, not '$keep'" >&2; exit 1 ;; esac
disk_mbps="${BACKUP_DISK_MBPS:-40}"; posint BACKUP_DISK_MBPS "$disk_mbps"
wal_mbps="${BACKUP_WAL_MBPS:-16}"; posint BACKUP_WAL_MBPS "$wal_mbps"
post_timeout="${POST_BACKUP_TIMEOUT:-3600}"; posint POST_BACKUP_TIMEOUT "$post_timeout"
# Checked before any arithmetic: bash evaluates $(( )) operands as expressions (a[$(cmd)] runs cmd).
headroom_mb="${BACKUP_HEADROOM_MB:-1024}"; posint BACKUP_HEADROOM_MB "$headroom_mb"
cpus="${BACKUP_CPUS:-0.5}"
case "$cpus" in '' | *[!0-9.]* | *.*.*) echo "BACKUP_CPUS must be a number, not '$cpus'" >&2; exit 1 ;; esac
name=p2p-relay-backup
MiB=$((1024 * 1024))

mkdir -p backups
chmod 2770 backups

# One backup at a time: a run still going (or a container a killed run left) blocks the next.
exec 9>.backup.lock
if ! flock -n 9; then
  echo "another backup is running; not starting a second one" >&2
  exit 1
fi
docker rm -f "$name" >/dev/null 2>&1 || true

# The relay's data volume and image, as compose.yaml names them.
vol=$(docker volume ls -q --filter label=com.docker.compose.project=p2p-relay --filter label=com.docker.compose.volume=relay-data)
[ -n "$vol" ] || { echo "no relay-data volume: is the relay deployed from this directory?" >&2; exit 1; }
image=peer2peer/relay:local
throttle=(--cpus "$cpus")
if [ -n "${BACKUP_IO_DEVICE:-}" ] || [ -n "${BACKUP_IO_BPS:-}" ]; then
  # A whole number of bytes, or of kb/mb/gb (docker's rate syntax): nothing else reaches docker.
  if ! [[ "${BACKUP_IO_BPS:-}" =~ ^[1-9][0-9]{0,11}([kKmMgG][bB]?)?$ ]]; then
    echo "BACKUP_IO_BPS must be a rate such as 30mb, not '${BACKUP_IO_BPS:-}'" >&2
    exit 1
  fi
  [ -b "${BACKUP_IO_DEVICE:-}" ] || { echo "BACKUP_IO_DEVICE must be a block device, not '${BACKUP_IO_DEVICE:-}'" >&2; exit 1; }
  throttle+=(--device-read-bps "$BACKUP_IO_DEVICE:$BACKUP_IO_BPS" --device-write-bps "$BACKUP_IO_DEVICE:$BACKUP_IO_BPS")
fi
# The same hardening as the relay, no network, a CPU share, and your primary group so it can
# write backups/.
node_in_image=(docker run --rm --name "$name" --network none
  --read-only --cap-drop ALL --security-opt no-new-privileges
  --memory 512m --pids-limit 64 "${throttle[@]}"
  --user 65532:65532 --group-add "$(id -g)"
  -v "$vol:/data" -v "$PWD/backup.mjs:/backup.mjs:ro" -v "$PWD/backups:/backup"
  --entrypoint /nodejs/bin/node "$image")

# The copy is at most the size of the database and its WAL.
db_bytes=$(timeout --kill-after=10s 120 "${node_in_image[@]}" -e 'const fs=require("node:fs");let n=0;for(const f of ["relay.db","relay.db-wal"]){try{n+=fs.statSync("/data/"+f).size}catch{}}console.log(n)')
docker rm -f "$name" >/dev/null 2>&1 || true
case "$db_bytes" in '' | *[!0-9]*) echo "could not read the database size ('${db_bytes:0:80}')" >&2; exit 1 ;; esac

# The timeout follows the disk: twice the copy time at BACKUP_DISK_MBPS, plus a minute.
copy_sec=$(( db_bytes / (disk_mbps * MiB) + 1 ))
timeout_sec="${BACKUP_TIMEOUT:-$(( copy_sec * 2 + 60 > 120 ? copy_sec * 2 + 60 : 120 ))}"
posint BACKUP_TIMEOUT "$timeout_sec"

# Room for the copy, the WAL the relay writes meanwhile (for the whole timeout), and headroom.
wal_budget=$(( wal_mbps * MiB * timeout_sec ))
headroom=$(( headroom_mb * MiB ))
[ "$headroom" -ge $(( db_bytes / 10 )) ] || headroom=$(( db_bytes / 10 ))
need=$(( db_bytes + wal_budget + headroom ))
# The relay's volume and backups/ are on the same disk in this recipe; check both.
free_bytes=$(( $(df -Pk backups | awk 'NR==2{print $4}') * 1024 ))
if [ "$free_bytes" -lt "$need" ]; then
  echo "not enough free disk for a backup: need $(( need / MiB )) MiB (copy $(( db_bytes / MiB )), WAL growth $(( wal_budget / MiB )) over ${timeout_sec}s, headroom $(( headroom / MiB ))), have $(( free_bytes / MiB )) MiB" >&2
  exit 1
fi
echo "backup: database $(( db_bytes / MiB )) MiB, timeout ${timeout_sec}s, free $(( free_bytes / MiB )) MiB (need $(( need / MiB )))" >&2

rc=0
out=$(timeout --kill-after=30s "$timeout_sec" "${node_in_image[@]}" /backup.mjs /data/relay.db /backup "$keep" "$timeout_sec") || rc=$?
# timeout stops the docker client, not the container: remove it either way.
docker rm -f "$name" >/dev/null 2>&1 || true
if [ "$rc" -ne 0 ]; then
  echo "backup failed (exit $rc; 124 = timed out after ${timeout_sec}s)" >&2
  exit "$rc"
fi

# Only a file backup.mjs names the way it names its copies, inside backups/, is handed on.
base="${out##*/}"
if ! [[ "$out" =~ ^/backup/relay-[0-9]{8}T[0-9]{6}Z\.db$ ]] || [ -L "backups/$base" ] || ! [ -f "backups/$base" ]; then
  echo "backup: unexpected output path '${out:0:200}'; not running POST_BACKUP" >&2
  exit 1
fi
file="backups/$base"
echo "backup: $file"
if [ -n "${POST_BACKUP:-}" ]; then
  prc=0
  timeout --kill-after=30s "$post_timeout" bash -c "$POST_BACKUP" post-backup "$file" || prc=$?
  if [ "$prc" -ne 0 ]; then
    echo "POST_BACKUP failed (exit $prc; 124 = timed out after ${post_timeout}s); the backup itself is in $file" >&2
    exit "$prc"
  fi
fi
