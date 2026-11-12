#!/bin/sh
# Copyright 2026 Ix Infrastructure Inc.
# SPDX-License-Identifier: Apache-2.0
#
# install.sh: install the Peer2Peer client (the `p2p` command) on macOS or Linux.
#
#   curl -fsSL https://ix-infra.com/p2p/install.sh | sh
#   curl -fsSL https://ix-infra.com/p2p/install.sh | sh -s -- --dry-run
#   curl -fsSL https://ix-infra.com/p2p/install.sh | P2P_INSTALL_DRY_RUN=1 sh
#   sh scripts/install.sh [options]                 # from a checkout or a download
#
# What it does:
#   1. Checks for Node.js >= 22 and npm. If either is missing or too old, it
#      prints how to get them for this platform and stops: it never installs
#      Node itself.
#   2. Checks that npm's global folder is writable by you. If it isn't, it
#      explains the options (nvm, or a user-owned npm prefix) and stops: it
#      never runs sudo.
#   3. Runs `npm install -g` for @peer2peer/cli and @peer2peer/ext-ix, pinned
#      to exactly P2P_VERSION, and checks the result with `p2p --version`.
#      npm checks each package against the registry's integrity hash; nothing
#      is downloaded any other way, and no package install scripts run.
#   4. In a terminal, hands over to `p2p setup`, which asks its own questions.
#      Piped (`curl ... | sh`), it reads the answers from /dev/tty when there is
#      one; with no terminal at all it skips setup and says to run `p2p setup`.
#   It doesn't install Ix or anything else.
#
# Flags (or the environment variable in brackets, handy with `| sh`):
#   --version X.Y.Z  install this version instead of P2P_VERSION (P2P_INSTALL_VERSION)
#   --no-setup       don't run `p2p setup` afterwards (P2P_INSTALL_NO_SETUP=1)
#   --dry-run        print what it would run and change nothing (P2P_INSTALL_DRY_RUN=1)
#
# Every command is printed (as "+ ...") before it runs.
#
# Safe to pipe: everything is inside main(), called on the last line as
# `{ main "$@"; }`, so a download truncated anywhere, even inside that line,
# runs nothing (a cut-off line is a syntax error). It never relies on its own path.
#
# Tests (only with P2P_INSTALL_TEST=1) can override detection (an empty value
# means "not found"): P2P_DETECT_OS, P2P_DETECT_NODE, P2P_DETECT_NPM,
# P2P_DETECT_TTY (stdin, dev or none).

# The release these scripts install; bumped after each release (docs/releasing.md, step 5).
P2P_VERSION="0.1.1"
PACKAGES="@peer2peer/cli @peer2peer/ext-ix"
MIN_NODE="22.0.0"
NL='
'

say() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# version_ge A B: true when dotted version A >= B (a leading v and suffixes are ignored).
version_ge() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    sub(/^v/, "", a); sub(/^v/, "", b)
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

# check_version V: an exact npm version (1.2.3 or 1.2.3-rc.1), never a range or a tag.
check_version() {
  case "$1" in *[!0-9A-Za-z.-]* | '') die "--version must be an exact version such as $P2P_VERSION (got '$1')" ;; esac
  printf '%s\n' "$1" | LC_ALL=C grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' ||
    die "--version must be an exact version such as $P2P_VERSION (got '$1')"
}

# How to get Node 22 on this platform. Printed, never run.
node_help() {
  say ""
  say "Peer2Peer needs Node.js $MIN_NODE or newer, with npm. Found: node ${NODE_V:-none}, npm ${NPM_V:-none}."
  say "This script doesn't install Node. Pick one, then run it again:"
  case "$OS" in
    Darwin)
      say "  - The installer from https://nodejs.org/en/download (LTS)"
      say "  - Homebrew: brew install node"
      say "  - nvm (no admin rights, per user): https://github.com/nvm-sh/nvm, then: nvm install 22" ;;
    *)
      say "  - nvm (no admin rights, per user): https://github.com/nvm-sh/nvm, then: nvm install 22"
      say "  - Your distribution's packages, if they have 22 or newer (many have an older one): https://nodejs.org/en/download/package-manager"
      say "  - The prebuilt binaries from https://nodejs.org/en/download (LTS)" ;;
  esac
}

# The first directory in DIR's ancestry that exists.
existing_parent() {
  p=$1
  while [ ! -e "$p" ] && [ "$p" != / ]; do p=$(dirname "$p"); done
  printf '%s\n' "$p"
}

# Sets PREFIX and BIN_DIR, and stops (outside a dry run) when npm's global
# folders aren't writable: sudo is never used.
#
# npm masks anything in its output that looks like a UUID (8-4-4-4-12 hex) or
# an npm token as "***" (@npmcli/redact), so `npm prefix -g` prints a path
# that doesn't exist when one of its folders is named like that. That is
# refused, before anything is installed. (Asking npm another way, through
# `npm exec -c`, would run in the current directory's project context: its
# .npmrc and node_modules/.bin could pick the shell or fake the folder.)
check_prefix() {
  PREFIX=$(npm prefix -g 2>/dev/null) || PREFIX=""
  [ -n "$PREFIX" ] || die "couldn't read npm's global folder (npm prefix -g)"
  case "$PREFIX" in
    *'***'* | *"$NL"* | [!/]*)
      die "npm printed its global folder as '$PREFIX', which isn't a usable path (npm hides folder names that look like IDs as ***). Nothing was installed. Either give npm a folder of your own without such a name and run this again: npm config set prefix \"\$HOME/.npm-global\" (and add \$HOME/.npm-global/bin to your PATH); or install directly: npm install -g $SPECS" ;;
  esac
  BIN_DIR="$PREFIX/bin"
  for d in "$PREFIX/lib/node_modules" "$BIN_DIR"; do
    e=$(existing_parent "$d")
    if [ ! -w "$e" ]; then
      say ""
      say "npm installs global packages into $PREFIX, and $e isn't writable by you."
      say "This script doesn't use sudo. Either:"
      say "  - use nvm, which keeps Node and global packages in your home folder: https://github.com/nvm-sh/nvm"
      say "  - or give npm a folder of your own, then add it to your PATH and run this again:"
      say "      npm config set prefix \"\$HOME/.npm-global\""
      say "      export PATH=\"\$HOME/.npm-global/bin:\$PATH\"     # also in your ~/.profile, ~/.zshrc or ~/.bashrc"
      if [ "$DRY_RUN" = 1 ]; then say "(dry run: continuing to show the plan)"; return 0; fi
      exit 3
    fi
  done
}

# Runs `p2p setup` when there is a terminal to ask questions on.
hand_over() {
  if [ "$NO_SETUP" = 1 ]; then
    say "Next: run \`p2p setup\` to create your identity."
    return 0
  fi
  if [ -n "${P2P_DETECT_TTY+set}" ]; then tty=$P2P_DETECT_TTY
  elif [ -t 0 ]; then tty=stdin
  elif (: </dev/tty) 2>/dev/null; then tty=dev
  else tty=none
  fi
  case "$tty" in
    stdin)
      say ""
      say "Now setting up your identity (p2p setup):"
      if ! run "$P2P_BIN" setup; then warn "p2p setup didn't finish; run \`p2p setup\` to try again."; fi ;;
    dev)
      # Piped into sh: stdin is the script, so the answers come from the terminal.
      say ""
      say "Now setting up your identity (p2p setup, reading answers from /dev/tty):"
      say "+ $P2P_BIN setup </dev/tty"
      if [ "$DRY_RUN" = 0 ] && ! "$P2P_BIN" setup </dev/tty; then warn "p2p setup didn't finish; run \`p2p setup\` to try again."; fi ;;
    *)
      say "No terminal to ask questions on, so setup was skipped. Next: run \`p2p setup\` to create your identity." ;;
  esac
}

usage() {
  cat <<EOF
usage: install.sh [options]

Installs the Peer2Peer client (@peer2peer/cli and @peer2peer/ext-ix $P2P_VERSION)
with npm, then runs \`p2p setup\`.

  --version X.Y.Z  install this version instead of $P2P_VERSION (P2P_INSTALL_VERSION)
  --no-setup       don't run \`p2p setup\` afterwards (P2P_INSTALL_NO_SETUP=1)
  --dry-run        print what it would run and change nothing (P2P_INSTALL_DRY_RUN=1)

Other ways to install: npm i -g @peer2peer/cli, or the Claude Code plugin.
Guide: https://github.com/ix-infrastructure/Peer2Peer/blob/main/docs/getting-started.md
EOF
}

main() {
  set -eu
  if [ "${P2P_INSTALL_TEST:-}" != 1 ]; then unset P2P_DETECT_OS P2P_DETECT_NODE P2P_DETECT_NPM P2P_DETECT_TTY; fi
  VERSION=${P2P_INSTALL_VERSION:-$P2P_VERSION}
  DRY_RUN=0 NO_SETUP=0
  [ "${P2P_INSTALL_DRY_RUN:-}" = 1 ] && DRY_RUN=1
  [ "${P2P_INSTALL_NO_SETUP:-}" = 1 ] && NO_SETUP=1
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run) DRY_RUN=1 ;;
      --no-setup) NO_SETUP=1 ;;
      --version) [ $# -ge 2 ] || die "--version needs a value, such as $P2P_VERSION"; VERSION=$2; shift ;;
      --version=*) VERSION=${1#--version=} ;;
      -h | --help) usage; return 0 ;;
      *) die "unknown option: $1 (try --help)" ;;
    esac
    shift
  done
  check_version "$VERSION"
  SPECS=""
  for p in $PACKAGES; do SPECS="$SPECS $p@$VERSION"; done
  SPECS=${SPECS# }
  [ "$DRY_RUN" = 1 ] && say "dry run: nothing will be changed"

  OS=${P2P_DETECT_OS-$(uname -s)}
  NODE_V=${P2P_DETECT_NODE-$(if have node; then node --version 2>/dev/null | sed 's/^v//'; fi)}
  NPM_V=${P2P_DETECT_NPM-$(if have npm; then npm --version 2>/dev/null; fi)}
  case "$OS" in
    Darwin | Linux) ;;
    *) warn "$OS isn't tested; on Windows use install.ps1 (irm https://ix-infra.com/p2p/install.ps1 | iex)" ;;
  esac
  say "detected: os=$OS node=${NODE_V:-none} npm=${NPM_V:-none}"

  if [ -z "$NODE_V" ] || [ -z "$NPM_V" ] || ! version_ge "$NODE_V" "$MIN_NODE"; then
    node_help
    exit 2
  fi

  check_prefix
  P2P_BIN="$BIN_DIR/p2p"
  say "plan: install $SPECS into $PREFIX with npm, then check $P2P_BIN --version"
  # shellcheck disable=SC2086 # SPECS is a list of plain package@version words
  run npm install -g --ignore-scripts --no-fund --no-audit $SPECS

  if [ "$DRY_RUN" = 1 ]; then
    say "+ $P2P_BIN --version   (expect $VERSION)"
  else
    [ -x "$P2P_BIN" ] || die "npm finished but $P2P_BIN isn't there; run: npm ls -g @peer2peer/cli"
    got=$("$P2P_BIN" --version 2>/dev/null | head -n 1) || got=""
    [ "$got" = "$VERSION" ] || die "$P2P_BIN --version printed '$got', expected $VERSION"
    say "Installed: p2p $got ($P2P_BIN)"
  fi

  found=$(command -v p2p 2>/dev/null || true)
  if [ "$found" != "$P2P_BIN" ]; then
    if [ -z "$found" ]; then
      warn "$BIN_DIR isn't on your PATH: add it (export PATH=\"$BIN_DIR:\$PATH\" in your shell's profile), or open a new terminal."
    else
      warn "\`p2p\` on your PATH is $found, not $P2P_BIN; put $BIN_DIR first on your PATH."
    fi
  fi

  hand_over
  [ "$DRY_RUN" = 0 ] || say "Dry run done: nothing was installed."
}

{ main "$@"; }
