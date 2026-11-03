# Copyright 2026 Ix Infrastructure Inc.
#
# Sourced (not run) by the demo scripts and tapes in this folder.
#
# Starts a throwaway Peer2Peer relay on 127.0.0.1 (in-memory database, nothing
# leaves this machine) and defines two shell functions, `ann` and `ben`, that
# run the real `p2p` CLI against two separate temporary P2P_HOMEs. No network,
# no account, no credentials. Everything is removed when the shell exits.
#
# Prerequisites, from the repository root:
#   (cd packages/core && npm ci && npm run build)
#   (cd packages/relay && npm ci && npm run build)
#   (cd packages/codex-bridge && npm ci && npm run build)   # only for demo_conflicts

DEMO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEMO_BIN="$DEMO_ROOT/mods/claude/peer2peer/bin/p2p.mjs"
DEMO_PORT="${DEMO_PORT:-18787}"
DEMO_DIR="$(mktemp -d "${TMPDIR:-/tmp}/p2p-demo.XXXXXX")"

# The canonical relay URL is a name that resolves nowhere; P2P_RELAY_TRANSPORT
# maps it to the local, TLS-free listener, so nothing is ever dialled outside
# 127.0.0.1.
export P2P_DEFAULT_RELAYS="wss://relay.demo.test/v3"
export P2P_RELAY_TRANSPORT="{\"wss://relay.demo.test/v3\":\"ws://127.0.0.1:${DEMO_PORT}/v3\"}"
export P2P_EXTENSIONS=none

RELAY_URL="wss://relay.demo.test/v3" PORT="$DEMO_PORT" HOST=127.0.0.1 DB_PATH=":memory:" \
  METRICS_PORT=off LOG_LEVEL=warn \
  node "$DEMO_ROOT/packages/relay/dist/bin.js" >"$DEMO_DIR/relay.log" 2>&1 &
DEMO_RELAY_PID=$!

demo_cleanup() {
  kill "$DEMO_RELAY_PID" 2>/dev/null
  [ -n "${DEMO_KEEP:-}" ] || case "$DEMO_DIR" in */p2p-demo.*) rm -rf -- "$DEMO_DIR" ;; esac
}
trap demo_cleanup EXIT

for _ in 1 2 3 4 5 6 7 8 9 10; do
  curl -fsS "http://127.0.0.1:${DEMO_PORT}/healthz" >/dev/null 2>&1 && break
  sleep 0.3
done

ann() { P2P_HOME="$DEMO_DIR/ann" node "$DEMO_BIN" "$@"; }
ben() { P2P_HOME="$DEMO_DIR/ben" node "$DEMO_BIN" "$@"; }

# demo_inbox <who> <session>: what that session's `p2p watch --jsonl` received,
# as plain lines (a real client keeps the watch running; the demo drains it).
demo_inbox() {
  local who="$1" sid="$2" out="$DEMO_DIR/watch-$1-$2.jsonl"
  # In a subshell, so an interactive shell (the tape) prints no "[1] <pid>" job lines.
  (
    "$who" watch --session "$sid" --jsonl >"$out" 2>"$out.err" &
    pid=$!
    sleep 3
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  )
  node -e '
    const lines = require("node:fs").readFileSync(process.argv[1], "utf8").split("\n").filter(Boolean);
    for (const l of lines) {
      const e = JSON.parse(l);
      if (e.kind === "p2p.message") console.log(`✉  from ${e.from.address}: ${e.text}`);
    }' "$out"
}

# demo_conflicts <who> <repo> <file>...: the peer-activity digest that the Codex
# bridge (and, with the same rule, the Claude Code mod) puts in front of the
# model, built from this user's `p2p ls --json` and the files its session changed.
demo_conflicts() {
  local who="$1" repo="$2"; shift 2
  "$who" ls --json | node --input-type=module -e '
    const [lib, repo, ...mine] = process.argv.slice(1);
    const { peerActivity } = await import(lib);
    let raw = ""; for await (const c of process.stdin) raw += c;
    console.log(peerActivity(JSON.parse(raw).peers, repo, mine).text);
  ' "file://$DEMO_ROOT/packages/codex-bridge/dist/index.js" "$repo" "$@"
}

# json <field>: one field of a JSON object on stdin (keeps the tapes free of jq).
json() { node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s)[process.argv[1]]))' "$1"; }
