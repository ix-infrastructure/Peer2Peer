#!/bin/sh
# Copyright 2026 Ix Infrastructure Inc.
# SPDX-License-Identifier: Apache-2.0
#
# install-relay.sh: install a private Peer2Peer relay on this machine.
#
#   sh install-relay.sh --url wss://relay.example.org/v3            # from a checkout or a download
#   curl -fsSL https://ix-infra.com/p2p/install-relay.sh | sh -s -- --url wss://relay.example.org/v3
#
# What it does (docs/run-a-relay-on-any-machine.md has the whole guide):
#   1. Detects the OS, CPU, RAM, kernel, glibc, Docker (and BuildKit) and Node.
#   2. Docker >= 20.10.10: builds the relay image and runs it hardened, with a
#      memory cap, a restart policy, a named volume (or --data-dir), and the
#      `small` preset on machines with less than 4 GB of RAM.
#   3. Otherwise Node >= 22.13 on Linux: installs the relay into /opt/p2p-relay
#      and runs it from a systemd unit as a dedicated unprivileged user. On
#      macOS it prints launchd instructions instead of installing.
#   4. Otherwise: prints what's missing and your options.
#   It listens on 127.0.0.1 only: put a tunnel or a TLS proxy in front.
#
# Flags:
#   --url URL         the relay's public URL, wss://<host>/v3 (RELAY_URL)
#   --port N          local port (default 8080)
#   --preset P        small or default (default: small under 4 GB of RAM)
#   --data-dir DIR    keep the database in DIR instead of a Docker volume
#   --method M        auto, docker or node (default auto)
#   --replace         replace an existing p2p-relay container or install
#   --env NAME=VALUE  pass another relay setting (repeatable), e.g. RELAY_ALLOW_CIRCLE=c_...
#   --dry-run         print the plan and change nothing
#
# Privileges: Docker needs no sudo (your user must be in the docker group).
# The Node path uses sudo only to create the p2p-relay user and its
# directories, copy the files into /opt/p2p-relay and install the systemd
# unit, and says so before it does. It never pipes a download into a shell.
#
# Safe to pipe: everything is inside main(), called on the last line, so a
# truncated download runs nothing. It never relies on its own path. Outside a
# checkout it downloads the relay source for RELAY_VERSION and checks it
# against RELAY_SOURCE_SHA256 before using it.
#
# Detection can be overridden for testing (an empty value means "not found"):
#   P2P_DETECT_OS, P2P_DETECT_ARCH, P2P_DETECT_MEM_MB, P2P_DETECT_KERNEL,
#   P2P_DETECT_GLIBC, P2P_DETECT_DOCKER, P2P_DETECT_BUILDX, P2P_DETECT_NODE,
#   P2P_DETECT_SYSTEMD (yes/no), P2P_DETECT_UID, P2P_DETECT_DATA_DEVICE, P2P_NODE_BIN,
#   P2P_SOURCE_DIR (a checkout to build from).

# Pinned from the release's SHA256SUMS asset (docs/releasing.md, step 5).
# release.yml attaches a deterministic peer2peer-<ver>-src.tar.gz; GitHub's
# generated /archive/ tarballs aren't guaranteed to be byte-stable, so the
# scripts never use those.
RELAY_VERSION="0.1.0"
RELAY_SOURCE_SHA256="f677c00a9422f3adcfa89a174a3bd61e35eeef6ce3975a0f391c2e26dc2f8d65"
RELAY_SOURCE_URL_BASE="https://github.com/ix-infrastructure/Peer2Peer/releases/download"
# TODO(first release): once releases publish a multi-arch image (for example on
# GHCR), pull it by digest here instead of building locally.

IMAGE="peer2peer/relay:local"
NAME="p2p-relay"
SERVICE_USER="p2p-relay"
INSTALL_DIR="/opt/p2p-relay"
MIN_DOCKER="20.10.10"
MIN_NODE="22.13.0"

say() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# version_ge A B: true when dotted version A >= B (suffixes like +dfsg or -ce are ignored).
version_ge() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    sub(/[^0-9.].*$/, "", a); sub(/[^0-9.].*$/, "", b)
    na = split(a, x, "."); nb = split(b, y, ".")
    n = na > nb ? na : nb
    for (i = 1; i <= n; i++) { if (x[i] + 0 > y[i] + 0) exit 0; if (x[i] + 0 < y[i] + 0) exit 1 }
    exit 0
  }'
}

# run CMD...: print it, and run it unless this is a dry run.
run() {
  line="+"
  for a in "$@"; do
    case "$a" in
      *[!A-Za-z0-9_./:=,@+-]* | '') line="$line '$(printf '%s' "$a" | sed "s/'/'\\\\''/g")'" ;;
      *) line="$line $a" ;;
    esac
  done
  printf '%s\n' "$line"
  [ "$DRY_RUN" = 1 ] || "$@"
}

# as_root CMD...: run with sudo (or directly as root), announced once.
as_root() {
  if [ "${P2P_DETECT_UID-$(id -u)}" -eq 0 ]; then run "$@"; return; fi
  if [ "$SUDO_ANNOUNCED" = 0 ]; then
    say "sudo is needed for the next steps only: creating the $SERVICE_USER user and its directories, copying files into $INSTALL_DIR, and installing the systemd unit."
    SUDO_ANNOUNCED=1
  fi
  run sudo "$@"
}

# add_env NAME=VALUE: remember an extra relay setting for --env. Values go into
# a systemd unit and a docker argument, so quotes, backslashes, $, % and
# newlines are refused.
UPPER=ABCDEFGHIJKLMNOPQRSTUVWXYZ
LOWER=abcdefghijklmnopqrstuvwxyz
DIGITS=0123456789
NL='
'
# Characters allowed in a path that reaches a unit file, plist or docker argument.
PATH_CHARS="$UPPER$LOWER$DIGITS/._-"

# only_chars VALUE ALLOWED: VALUE is non-empty, has no newline, and uses only ALLOWED.
# Everything user-supplied that ends up in a systemd unit, a plist or a docker
# argument passes through this (and is quoted there too).
only_chars() {
  case "$1" in '' | *"$NL"*) return 1 ;; esac
  case "$1" in *[!"$2"]*) return 1 ;; esac
  return 0
}

# check_url URL: wss://host[:port][/path], nothing else.
check_url() {
  if ! only_chars "$1" "$UPPER$LOWER$DIGITS.:/_~-" ||
    ! printf '%s\n' "$1" | LC_ALL=C grep -Eq '^wss://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$'; then
    die "--url must look like wss://relay.example.org/v3 (letters, digits and . - _ ~ / only)"
  fi
}

# check_path WHAT PATH: an absolute path of plain characters, without . or .. parts.
check_path() {
  case "$2" in /*) ;; *) die "$1 must be an absolute path, not '$2'" ;; esac
  only_chars "$2" "$PATH_CHARS" || die "$1 may hold only letters, digits and / . _ - (got '$2')"
  case "$2/" in *//* | */./* | */../*) die "$1 must not contain //, /./ or /../ (got '$2')" ;; esac
}

# check_data_dir DIR: refuse /, home directories themselves and system directories.
check_data_dir() {
  [ "$1" != / ] || die "--data-dir must not be /"
  check_path --data-dir "$1"
  d=${1%/}
  case "$d" in
    '' | /bin | /bin/* | /boot | /boot/* | /dev | /dev/* | /etc | /etc/* | /lib | /lib/* | /lib32 | /lib64 | /lib64/* | \
      /libx32 | /media | /mnt | /opt | /opt/p2p-relay | /opt/p2p-relay/* | /proc | /proc/* | /root | /root/* | \
      /run | /run/* | /sbin | /sbin/* | /srv | /sys | /sys/* | /tmp | /usr | /usr/* | /var | /var/lib | /var/tmp | \
      /var/log | /System | /System/* | /Library | /Applications)
      die "--data-dir $1 is a system directory; use a directory of its own, such as /srv/p2p-relay/data" ;;
    /home/*/* | /Users/*/*) ;;
    /home | /home/* | /Users | /Users/*)
      die "--data-dir $1 is a home directory; use a directory of its own, such as /srv/p2p-relay/data" ;;
  esac
  [ "$d" != "${HOME%/}" ] || die "--data-dir must not be your home directory"
}

# take_dir DIR UID: DIR may be used only when it is new, empty, or already
# owned by UID; never a folder that already holds someone else's files.
# Sets DIR_STATE to new, empty or owned.
take_dir() {
  if [ -L "$1" ]; then die "--data-dir $1 is a symbolic link; give the real directory"; fi
  if [ ! -e "$1" ]; then DIR_STATE=new; return 0; fi
  [ -d "$1" ] || die "--data-dir $1 exists and isn't a directory"
  owner=$(stat -c %u "$1" 2>/dev/null || stat -f %u "$1")
  if [ "$owner" = "$2" ]; then DIR_STATE=owned; return 0; fi
  if [ -r "$1" ] && [ -z "$(ls -A "$1" 2>/dev/null)" ]; then DIR_STATE=empty; return 0; fi
  die "--data-dir $1 already holds files and doesn't belong to the relay's user; use a new or empty directory"
}

add_env() {
  # Explicit letter lists, not ranges: [A-Z] matches lower case in some locales.
  case "$1" in
    *[!"$UPPER$LOWER$DIGITS"_.,:/@+=\ -]*) die "--env $1: only letters, digits, spaces and _ . , : / @ + = - are allowed" ;;
  esac
  name=${1%%=*}
  case "$name" in
    "$1" | '' | [!"$UPPER"]* | *[!"$UPPER$DIGITS"_]*) die "--env needs NAME=VALUE with an upper-case NAME, not '$1'" ;;
  esac
  EXTRA_ENV="$EXTRA_ENV$1
"
}

# each_env FORMAT: printf FORMAT once per --env setting.
each_env() {
  old_ifs=$IFS; IFS='
'
  for kv in $EXTRA_ENV; do
    # shellcheck disable=SC2059 # the format is ours
    printf "$1" "$kv"
  done
  IFS=$old_ifs
}

# ---- detection ---------------------------------------------------------------

detect_mem_mb() {
  if [ -r /proc/meminfo ]; then
    awk '/^MemTotal:/ { printf "%d\n", $2 / 1024 }' /proc/meminfo
  elif have sysctl; then
    b=$(sysctl -n hw.memsize 2>/dev/null) && [ -n "$b" ] && echo $((b / 1048576))
  fi
}

detect_glibc() {
  v=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{ print $2 }')
  [ -n "$v" ] || v=$(ldd --version 2>/dev/null | awk 'NR == 1 { print $NF }')
  case "$v" in [0-9]*) echo "$v" ;; esac
}

detect_docker() {
  have docker || return 0
  docker version --format '{{.Server.Version}}' 2>/dev/null || true
}

detect_buildx() {
  if have docker && docker buildx version >/dev/null 2>&1; then echo yes; else echo no; fi
}

detect_node() {
  have node || return 0
  node --version 2>/dev/null | sed 's/^v//'
}

# The block device holding PATH (or its nearest existing parent).
device_of() {
  p=$1
  while [ ! -e "$p" ] && [ "$p" != / ]; do p=$(dirname "$p"); done
  d=$(df -P "$p" 2>/dev/null | awk 'NR == 2 { print $1 }')
  # Raspberry Pi OS and some boards report the root filesystem as /dev/root.
  if [ "$d" = /dev/root ] && [ -r /proc/cmdline ]; then
    r=$(tr ' ' '\n' </proc/cmdline | sed -n 's/^root=//p')
    case "$r" in /dev/*) d=$r ;; esac
  fi
  echo "$d"
}

# ---- sizing ------------------------------------------------------------------

choose_sizing() {
  if [ -z "$PRESET" ]; then
    if [ "$MEM_MB" -lt 4096 ]; then PRESET=small; else PRESET=default; fi
  fi
  case "$PRESET" in
    small)
      if [ "$MEM_MB" -lt 1536 ]; then MEM_LIMIT=512; HEAP=256; else MEM_LIMIT=768; HEAP=384; fi ;;
    default)
      MEM_LIMIT=1024; HEAP=768 ;;
    *) die "--preset must be small or default" ;;
  esac
  NODE_OPTS="--disable-warning=ExperimentalWarning --max-old-space-size=$HEAP"
}

warn_if_flash() {
  case "$1" in
    /dev/mmcblk*)
      warn "the relay's data would live on $1, an SD card or eMMC. SQLite's many small writes wear these out; use a USB SSD (--data-dir on it), see the guide." ;;
  esac
}

# ---- source ------------------------------------------------------------------

sha256_of() {
  if have sha256sum; then sha256sum "$1" | awk '{ print $1 }'
  elif have shasum; then shasum -a 256 "$1" | awk '{ print $1 }'
  else die "need sha256sum or shasum to verify the download"
  fi
}

# is_checkout DIR: DIR is a git checkout of this repository (not just any
# directory that happens to have a packages/relay folder).
is_checkout() {
  [ -e "$1/.git" ] && [ -f "$1/scripts/install-relay.sh" ] && [ -f "$1/packages/relay/Dockerfile" ] &&
    grep -q '"name": "@peer2peer/relay"' "$1/packages/relay/package.json" 2>/dev/null &&
    grep -q '"name": "@peer2peer/core"' "$1/packages/core/package.json" 2>/dev/null
}

# Sets SRC to a relay source tree: P2P_SOURCE_DIR if set, the current
# directory only when it is clearly a checkout, or the pinned, verified
# release download.
find_source() {
  if [ -n "${P2P_SOURCE_DIR:-}" ]; then
    SRC=$P2P_SOURCE_DIR
    say "building from P2P_SOURCE_DIR=$SRC"
  elif is_checkout "$(pwd)"; then
    SRC=$(pwd)
    say "building from the checkout in $SRC"
  else
    if [ -z "$RELAY_VERSION" ] || [ -z "$RELAY_SOURCE_SHA256" ]; then
      die "no Peer2Peer release is pinned in this script yet: run it from the root of a checkout (git clone https://github.com/ix-infrastructure/Peer2Peer && cd Peer2Peer && sh scripts/install-relay.sh ...)"
    fi
    url="$RELAY_SOURCE_URL_BASE/v$RELAY_VERSION/peer2peer-$RELAY_VERSION-src.tar.gz"
    if [ "$DRY_RUN" = 1 ]; then
      say "+ download $url, check sha256 $RELAY_SOURCE_SHA256, unpack"
      SRC="<download>"; return
    fi
    DL_TMP=$(mktemp -d)
    say "downloading $url"
    if have curl; then curl -fsSL -o "$DL_TMP/src.tar.gz" "$url"
    elif have wget; then wget -q -O "$DL_TMP/src.tar.gz" "$url"
    else die "need curl or wget to download the relay source"
    fi
    got=$(sha256_of "$DL_TMP/src.tar.gz")
    [ "$got" = "$RELAY_SOURCE_SHA256" ] || die "checksum mismatch for $url: got $got, expected $RELAY_SOURCE_SHA256. Nothing was installed."
    mkdir "$DL_TMP/src" && tar -xzf "$DL_TMP/src.tar.gz" -C "$DL_TMP/src" --strip-components=1
    SRC="$DL_TMP/src"
  fi
  [ "$SRC" = "<download>" ] || [ -f "$SRC/packages/relay/Dockerfile" ] || die "$SRC is not a Peer2Peer source tree"
}

# ---- health ------------------------------------------------------------------

health_check() {
  [ "$DRY_RUN" = 1 ] && { say "+ wait for http://127.0.0.1:$PORT/healthz"; return 0; }
  i=0
  while [ $i -lt 30 ]; do
    if have curl; then curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && return 0
    elif have wget; then wget -q -O /dev/null "http://127.0.0.1:$PORT/healthz" 2>/dev/null && return 0
    else warn "no curl or wget: check http://127.0.0.1:$PORT/healthz yourself"; return 0
    fi
    i=$((i + 1)); sleep 1
  done
  return 1
}

# ---- Docker path -------------------------------------------------------------

install_docker() {
  say "plan: Docker $DOCKER_V, preset $PRESET, memory cap ${MEM_LIMIT}m, heap ${HEAP} MiB"
  find_source
  if [ "$DRY_RUN" = 0 ] && docker container inspect "$NAME" >/dev/null 2>&1; then
    [ "$REPLACE" = 1 ] || die "a container named $NAME exists; rerun with --replace to rebuild and replace it (its data volume is kept)"
  fi

  if [ -n "$DATA_DIR" ]; then
    warn_if_flash "${P2P_DETECT_DATA_DEVICE-$(device_of "$DATA_DIR")}"
    take_dir "$DATA_DIR" 65532
    if [ "$DIR_STATE" != owned ]; then
      # This path needs no sudo, so it doesn't chown anything itself.
      if [ "$DIR_STATE" = new ]; then fix="sudo install -d -o 65532 -g 65532 -m 0750 $DATA_DIR"; else fix="sudo chown 65532:65532 $DATA_DIR && sudo chmod 0750 $DATA_DIR"; fi
      msg="$DATA_DIR must belong to the container's user (65532). It is $DIR_STATE, so run: $fix"
      if [ "$DRY_RUN" = 1 ]; then say "note: $msg"; else die "$msg"; fi
    fi
    mount="type=bind,source=$DATA_DIR,target=/data"
  else
    if [ -n "${P2P_DETECT_DATA_DEVICE+set}" ]; then dev=$P2P_DETECT_DATA_DEVICE
    else dev=$(device_of "$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)")
    fi
    warn_if_flash "$dev"
    mount="type=volume,source=p2p-relay-data,target=/data"
  fi

  if [ "$BUILDX" = yes ]; then
    run docker buildx build --load -f "$SRC/packages/relay/Dockerfile" -t "$IMAGE" "$SRC"
  else
    printf '+ DOCKER_BUILDKIT=1 docker build -f %s -t %s %s\n' "$SRC/packages/relay/Dockerfile" "$IMAGE" "$SRC"
    [ "$DRY_RUN" = 1 ] || DOCKER_BUILDKIT=1 docker build -f "$SRC/packages/relay/Dockerfile" -t "$IMAGE" "$SRC"
  fi
  if [ "$REPLACE" = 1 ]; then run docker rm -f "$NAME"; fi
  # Extra settings from --env become -e arguments.
  set --
  old_ifs=$IFS; IFS='
'
  for kv in $EXTRA_ENV; do set -- "$@" -e "$kv"; done
  IFS=$old_ifs
  run docker run -d --name "$NAME" --restart unless-stopped \
    -p "127.0.0.1:$PORT:8080" \
    --mount "$mount" \
    -e "RELAY_URL=$URL" -e "RELAY_PRESET=$PRESET" -e "NODE_OPTIONS=$NODE_OPTS" -e TRUST_PROXY=1 \
    --memory "${MEM_LIMIT}m" --memory-swap "${MEM_LIMIT}m" --pids-limit 128 \
    --read-only --tmpfs /tmp:size=16m --cap-drop ALL --security-opt no-new-privileges \
    --log-opt max-size=10m --log-opt max-file=3 \
    "$@" "$IMAGE"
  health_check || die "the relay didn't become healthy; see: docker logs $NAME"
}

# ---- Node path ---------------------------------------------------------------

systemd_unit() {
  cat <<EOF
# Installed by install-relay.sh. docs/run-a-relay-on-any-machine.md
[Unit]
Description=Peer2Peer relay
After=network-online.target
Wants=network-online.target

[Service]
User=$SERVICE_USER
Group=$SERVICE_USER
Environment="RELAY_URL=$URL"
Environment="HOST=127.0.0.1"
Environment="PORT=$PORT"
Environment="DB_PATH=$DB_DIR/relay.db"
Environment="RELAY_PRESET=$PRESET"
Environment="TRUST_PROXY=1"
Environment="NODE_OPTIONS=$NODE_OPTS"
$(each_env 'Environment="%s"\n')
ExecStart="$NODE_BIN" "$INSTALL_DIR/packages/relay/dist/bin.js"
Restart=on-failure
StateDirectory=p2p-relay
StateDirectoryMode=0750
ReadWritePaths="$DB_DIR"
MemoryMax=${MEM_LIMIT}M
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=yes

[Install]
WantedBy=multi-user.target
EOF
}

# Builds core and the relay in a temporary copy, as you, the way the Dockerfile does.
build_tree() {
  stage=$1
  run mkdir -p "$stage/packages"
  run cp -RP "$SRC/packages/core" "$SRC/packages/relay" "$stage/packages/"
  run rm -rf "$stage/packages/core/node_modules" "$stage/packages/relay/node_modules"
  for pkg in core relay; do
    run npm ci --prefix "$stage/packages/$pkg" --ignore-scripts --no-audit --no-fund
    run npm run --prefix "$stage/packages/$pkg" build
  done
  for pkg in core relay; do
    run npm ci --prefix "$stage/packages/$pkg" --omit=dev --ignore-scripts --no-audit --no-fund
  done
}

install_node_macos() {
  NODE_BIN=${P2P_NODE_BIN:-$(command -v node || echo /usr/local/bin/node)}
  check_path "node's path" "$NODE_BIN"
  # The plist below is XML: only plain characters reach it.
  home=$HOME
  only_chars "$home" "$PATH_CHARS" || home="/Users/<you>"
  say "plan: Node $NODE_V on macOS, preset $PRESET. This script doesn't install launchd jobs; to run the relay at boot:"
  cat <<EOF

  1. Build it (from a checkout):
       (cd packages/core && npm ci && npm run build) && (cd packages/relay && npm ci && npm run build)
  2. Save this as ~/Library/LaunchAgents/org.peer2peer.relay.plist, with your paths:
       <?xml version="1.0" encoding="UTF-8"?>
       <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
       <plist version="1.0"><dict>
         <key>Label</key><string>org.peer2peer.relay</string>
         <key>ProgramArguments</key><array>
           <string>$NODE_BIN</string><string>/path/to/Peer2Peer/packages/relay/dist/bin.js</string>
         </array>
         <key>EnvironmentVariables</key><dict>
           <key>RELAY_URL</key><string>$URL</string>
           <key>HOST</key><string>127.0.0.1</string>
           <key>PORT</key><string>$PORT</string>
           <key>DB_PATH</key><string>$home/Library/Application Support/p2p-relay/relay.db</string>
           <key>RELAY_PRESET</key><string>$PRESET</string>
           <key>NODE_OPTIONS</key><string>$NODE_OPTS</string>
$(each_env '%s\n' | sed 's|^\([^=]*\)=\(.*\)$|           <key>\1</key><string>\2</string>|')
         </dict>
         <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
       </dict></plist>
  3. mkdir -p "\$HOME/Library/Application Support/p2p-relay"
     launchctl bootstrap gui/\$(id -u) ~/Library/LaunchAgents/org.peer2peer.relay.plist
  4. curl -fsS http://127.0.0.1:$PORT/healthz
EOF
}

install_node_linux() {
  [ "$SYSTEMD" = yes ] || die "the Node path needs systemd; run the relay yourself: docs/run-a-relay.md"
  have npm || [ "$DRY_RUN" = 1 ] || die "npm is missing (it ships with Node)"
  NODE_BIN=${P2P_NODE_BIN:-$(command -v node)}
  check_path "node's path" "$NODE_BIN"
  case "$NODE_BIN" in /home/* | /root/*)
    die "node is at $NODE_BIN, which the service user can't read. Install Node 22 system-wide (https://nodejs.org/en/download) and rerun." ;;
  esac
  DB_DIR=${DATA_DIR:-/var/lib/p2p-relay}
  # The unit sets ProtectHome=yes, so a data directory under a home can't work.
  case "$DB_DIR" in /home/* | /root/* | /run/user/* | /Users/*)
    die "--data-dir $DB_DIR is under a home directory, which the service can't see (ProtectHome); use a directory such as /srv/p2p-relay/data" ;;
  esac
  if [ -n "$DATA_DIR" ]; then
    relay_uid=$(id -u "$SERVICE_USER" 2>/dev/null || echo none)
    take_dir "$DATA_DIR" "$relay_uid"
  fi
  say "plan: Node $NODE_V with systemd, preset $PRESET, MemoryMax ${MEM_LIMIT}M, heap ${HEAP} MiB, database in $DB_DIR"
  warn_if_flash "${P2P_DETECT_DATA_DEVICE-$(device_of "$DB_DIR")}"
  find_source
  if [ "$DRY_RUN" = 0 ] && [ -e "$INSTALL_DIR" ] && [ "$REPLACE" = 0 ]; then
    die "$INSTALL_DIR exists; rerun with --replace to upgrade it"
  fi

  if [ "$DRY_RUN" = 1 ]; then stage=/tmp/p2p-relay-build; else STAGE=$(mktemp -d); stage=$STAGE; fi
  build_tree "$stage"

  unit=$(systemd_unit)
  if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    nologin=$(command -v nologin || echo /usr/sbin/nologin)
    as_root useradd --system --user-group --home-dir /var/lib/p2p-relay --no-create-home --shell "$nologin" "$SERVICE_USER"
  fi
  # Only a new or empty data directory is taken over; one the relay already owns is left alone.
  if [ -n "$DATA_DIR" ] && [ "$DIR_STATE" != owned ]; then
    as_root install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$DATA_DIR"
  fi
  as_root rm -rf "$INSTALL_DIR.new"
  as_root cp -RP "$stage" "$INSTALL_DIR.new"
  as_root chown -R root:root "$INSTALL_DIR.new"
  # Readable by the service user, writable only by root.
  as_root chmod -R a+rX,go-w "$INSTALL_DIR.new"
  as_root sh -c "rm -rf '$INSTALL_DIR.old'; if [ -e '$INSTALL_DIR' ]; then mv '$INSTALL_DIR' '$INSTALL_DIR.old'; fi; mv '$INSTALL_DIR.new' '$INSTALL_DIR'"
  say "+ write /etc/systemd/system/$NAME.service:"
  printf '%s\n' "$unit" | sed 's/^/    /'
  if [ "$DRY_RUN" = 0 ]; then
    # Written inside the private build directory (mktemp -d, mode 0700), never next to it.
    printf '%s\n' "$unit" >"$stage/$NAME.service"
    as_root install -m 0644 "$stage/$NAME.service" "/etc/systemd/system/$NAME.service"
  fi
  as_root systemctl daemon-reload
  as_root systemctl enable "$NAME"
  as_root systemctl restart "$NAME"
  health_check || die "the relay didn't become healthy; see: journalctl -u $NAME"
}

# Removes the download and build directories, however the script ends.
cleanup() {
  if [ -n "${DL_TMP:-}" ]; then rm -rf "$DL_TMP"; fi
  if [ -n "${STAGE:-}" ]; then rm -rf "$STAGE"; fi
}

# ---- main --------------------------------------------------------------------

usage() {
  cat <<'EOF'
usage: install-relay.sh [options]

  --url URL         the relay's public URL, wss://<host>/v3 (RELAY_URL)
  --port N          local port (default 8080)
  --preset P        small or default (default: small under 4 GB of RAM)
  --data-dir DIR    keep the database in DIR instead of a Docker volume
  --method M        auto, docker or node (default auto)
  --replace         replace an existing p2p-relay container or install
  --env NAME=VALUE  pass another relay setting (repeatable), e.g. RELAY_ALLOW_CIRCLE=c_...
  --dry-run         print the plan and change nothing

Guide: https://github.com/ix-infrastructure/Peer2Peer/blob/main/docs/run-a-relay-on-any-machine.md
EOF
}

main() {
  set -eu
  DRY_RUN=0 URL="" PORT=8080 PRESET="" DATA_DIR="" METHOD=auto REPLACE=0 SUDO_ANNOUNCED=0 EXTRA_ENV=""
  DL_TMP="" STAGE="" DIR_STATE=""
  trap cleanup EXIT
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run) DRY_RUN=1 ;;
      --url) [ $# -ge 2 ] || die "--url needs a value"; URL=$2; shift ;;
      --port) [ $# -ge 2 ] || die "--port needs a value"; PORT=$2; shift ;;
      --preset) [ $# -ge 2 ] || die "--preset needs a value"; PRESET=$2; shift ;;
      --data-dir) [ $# -ge 2 ] || die "--data-dir needs a value"; DATA_DIR=$2; shift ;;
      --method) [ $# -ge 2 ] || die "--method needs a value"; METHOD=$2; shift ;;
      --replace) REPLACE=1 ;;
      --env) [ $# -ge 2 ] || die "--env needs NAME=VALUE"; add_env "$2"; shift ;;
      -h | --help) usage; return 0 ;;
      *) die "unknown option: $1 (try --help)" ;;
    esac
    shift
  done
  case "$PORT" in '' | *[!0-9]*) die "--port must be a number" ;; esac
  if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then die "--port must be 1-65535"; fi
  case "$METHOD" in auto | docker | node) ;; *) die "--method must be auto, docker or node" ;; esac
  if [ -z "$URL" ]; then
    URL="wss://localhost:$PORT/v3"
    warn "no --url: using $URL. Clients only accept the exact public URL (wss://<host>/v3); rerun with --url once you know it."
  fi
  check_url "$URL"
  if [ -n "$DATA_DIR" ]; then check_data_dir "$DATA_DIR"; fi
  [ "$DRY_RUN" = 1 ] && say "dry run: nothing will be changed"

  OS=${P2P_DETECT_OS-$(uname -s)}
  ARCH=${P2P_DETECT_ARCH-$(uname -m)}
  MEM_MB=${P2P_DETECT_MEM_MB-$(detect_mem_mb)}
  KERNEL=${P2P_DETECT_KERNEL-$(uname -r)}
  GLIBC=${P2P_DETECT_GLIBC-$(detect_glibc)}
  DOCKER_V=${P2P_DETECT_DOCKER-$(detect_docker)}
  BUILDX=${P2P_DETECT_BUILDX-$(detect_buildx)}
  NODE_V=${P2P_DETECT_NODE-$(detect_node)}
  SYSTEMD=${P2P_DETECT_SYSTEMD-$(if have systemctl && [ -d /run/systemd/system ]; then echo yes; else echo no; fi)}
  case "$MEM_MB" in '' | *[!0-9]*) warn "couldn't read the RAM size; assuming 2048 MB"; MEM_MB=2048 ;; esac

  say "detected: os=$OS arch=$ARCH ram=${MEM_MB}MB kernel=$KERNEL glibc=${GLIBC:-none} docker=${DOCKER_V:-none} buildx=$BUILDX node=${NODE_V:-none}"
  case "$ARCH" in
    armv6* | armv7* | armhf | i386 | i686)
      warn "$ARCH is a 32-bit CPU or OS. The relay image is built for amd64 and arm64 only; on a Raspberry Pi, install the 64-bit OS." ;;
  esac
  choose_sizing

  docker_ok=0 node_ok=0
  if [ -n "$DOCKER_V" ] && version_ge "$DOCKER_V" "$MIN_DOCKER"; then docker_ok=1; fi
  if [ -n "$NODE_V" ] && version_ge "$NODE_V" "$MIN_NODE"; then node_ok=1; fi

  if [ "$METHOD" = docker ] || { [ "$METHOD" = auto ] && [ $docker_ok = 1 ]; }; then
    [ $docker_ok = 1 ] || die "--method docker needs Docker $MIN_DOCKER or newer (found: ${DOCKER_V:-none})"
    install_docker
  elif [ "$METHOD" = node ] || { [ "$METHOD" = auto ] && [ $node_ok = 1 ]; }; then
    [ $node_ok = 1 ] || die "--method node needs Node $MIN_NODE or newer (found: ${NODE_V:-none})"
    case "$OS" in
      Darwin) install_node_macos; return 0 ;;
      Linux) install_node_linux ;;
      *) die "the Node path supports Linux (systemd) and macOS; on $OS run the relay yourself: docs/run-a-relay.md" ;;
    esac
  else
    say ""
    say "Nothing to install with yet. Missing:"
    if [ -z "$DOCKER_V" ]; then
      if have docker; then say "  - Docker: the docker command is here but the daemon isn't reachable. Start it, or add yourself to the docker group (sudo usermod -aG docker \"\$USER\", then log in again)."
      else say "  - Docker $MIN_DOCKER or newer: not installed."
      fi
    else
      say "  - Docker $MIN_DOCKER or newer: found $DOCKER_V, too old (older seccomp profiles block the image's threads)."
    fi
    say "  - Node $MIN_NODE or newer: found ${NODE_V:-none}."
    if [ -n "$GLIBC" ] && ! version_ge "$GLIBC" 2.28; then
      say "    This system has glibc $GLIBC; official Node 22 builds need 2.28, so Docker is the way here."
    fi
    say ""
    say "Options:"
    say "  - Install or upgrade Docker: https://docs.docker.com/engine/install/ (on Ubuntu/Debian: sudo apt install docker.io)"
    say "  - Or install Node 22 system-wide: https://nodejs.org/en/download"
    say "  - Or run the relay on another machine: docs/run-a-relay-on-any-machine.md"
    exit 2
  fi

  say ""
  if [ "$DRY_RUN" = 1 ]; then say "Dry run done: the relay would listen on http://127.0.0.1:$PORT."
  else say "The relay is running on http://127.0.0.1:$PORT (health: /healthz)."
  fi
  say "Give teammates this relay URL: $URL"
  say "It only listens on this machine: put a tunnel or a TLS proxy in front (Tailscale serve, Cloudflare Tunnel or Caddy), see docs/run-a-relay-on-any-machine.md."
}

main "$@"
