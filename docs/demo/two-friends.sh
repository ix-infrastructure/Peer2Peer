#!/usr/bin/env bash
# Copyright 2026 Ix Infrastructure Inc.
#
# The README demo, end to end and non-interactive: two people, Ann and Ben,
# each with an agent session in the same repo. Setup, a circle, an invite and
# a join, then each sees the other's session, a message, and a conflict flag.
# Runs against a throwaway relay on 127.0.0.1; see demo-env.sh.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/demo-env.sh"

step() { printf '\n\033[1m$ %s\033[0m\n' "$*"; }

step "ann setup --name ann"
ann setup --name ann --no-backup
step "ann circle create api-team && ann circle default <cid>"
cid=$(ann circle create api-team --json | node -p 'JSON.parse(require("fs").readFileSync(0,"utf8")).cid')
ann circle default "$cid"
step "ann invite ben"
code=$(ann invite ben --json | node -p 'JSON.parse(require("fs").readFileSync(0,"utf8")).code')
echo "Join me on Peer2Peer: p2p join $code"

step "ben join <code>      # no setup needed: join creates Ben's identity"
ben join "$code" --name ben

step "ann friends      # Ann's client finishes adding Ben to the circle"
ann friends

step "ben status --session s-ben --state busy --summary … --file src/auth/token.ts"
ben status --session s-ben --state busy --label api --repo api --branch rate-limit \
  --summary "Adding rate limits to login" --file src/auth/token.ts --file src/api/login.ts
step "ann status --session s-ann --state busy --summary … --file src/auth/token.ts"
ann status --session s-ann --state busy --label api --repo api --branch main \
  --summary "Moving refreshToken() into its own module" --file src/auth/token.ts

step "ann ls"
ann ls
step "ben ls"
ben ls

step "ann send --from-session s-ann --to ben …"
ann send --from-session s-ann --to ben "Heads up: I'm moving refreshToken() out of src/auth/token.ts. Can you hold that file for 20 min?"
step "ben's session receives it (p2p watch --jsonl)"
demo_inbox ben s-ben

if [ -f "$DEMO_ROOT/packages/codex-bridge/dist/index.js" ]; then
  step "what Ann's agent sees before its next edit"
  demo_conflicts ann api src/auth/token.ts
fi
