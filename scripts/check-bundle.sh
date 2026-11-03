#!/usr/bin/env bash
# Copyright 2026 Ix Infrastructure Inc.
#
# Verifies the committed single-file CLI the Claude mod runs:
#   - mods/claude/peer2peer/bin/p2p.mjs is byte-for-byte what the sources build;
#   - mods/claude/peer2peer/bin/defaults.json is the empty list (a deploy step
#     fills in the team relay; only a reviewed PR may change the committed file).
#
# CI (.github/workflows/ci-public.yml) runs it on every pull request. It also
# works as a pre-commit hook:
#   ln -s ../../scripts/check-bundle.sh .git/hooks/pre-commit
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bin="$root/mods/claude/peer2peer/bin"

# The bundle inlines packages/core's build output: build it from the current sources...
[ -d "$root/packages/core/node_modules" ] || (cd "$root/packages/core" && npm ci --no-audit --no-fund >/dev/null)
(cd "$root/packages/core" && npm run --silent build >/dev/null)
# ...and the Codex bridge's (`p2p codex …`), which it inlines the same way.
[ -d "$root/packages/codex-bridge/node_modules" ] || (cd "$root/packages/codex-bridge" && npm ci --no-audit --no-fund >/dev/null)
(cd "$root/packages/codex-bridge" && npm run --silent build >/dev/null)
[ -d "$root/packages/p2p/node_modules" ] || (cd "$root/packages/p2p" && npm ci --no-audit --no-fund >/dev/null)
(cd "$root/packages/p2p" && node scripts/bundle.mjs --check)

# The mod's path and secret scrubbing is core's, copied byte for byte (the mod can't import core).
if ! cmp -s "$root/packages/core/src/v3/redact.ts" "$root/mods/claude/peer2peer/hooks/redact.ts"; then
  echo "mods/claude/peer2peer/hooks/redact.ts must be a copy of packages/core/src/v3/redact.ts: cp packages/core/src/v3/redact.ts mods/claude/peer2peer/hooks/redact.ts" >&2
  exit 1
fi
echo "hooks/redact.ts matches core"

node -e '
const fs = require("node:fs");
const v = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (JSON.stringify(v) !== JSON.stringify({ defaultRelays: [] })) {
  console.error(process.argv[1] + " must be {\"defaultRelays\":[]} in the repository (a deploy step fills it in)");
  process.exit(1);
}
console.log("defaults.json is the empty list");
' "$bin/defaults.json"
