## What and why

<!-- What does this change, and why? Link the issue, and the accepted RFC for a protocol change. -->

Closes #

## Type

- [ ] Bug fix
- [ ] Feature (within the current spec)
- [ ] Protocol change (accepted RFC: #___)
- [ ] Docs / chore

## How I tested it

<!-- The commands you ran and what they returned, for each package you touched. -->

- [ ] `npm run typecheck && npm run lint && npm test && npm run build` in each package I touched
- [ ] `node scripts/check-boundaries.mjs`
- [ ] `scripts/check-bundle.sh`, if `packages/core`, `p2p`, `codex-bridge` or `mods/claude/peer2peer/bin` changed (bundle rebuilt and committed)
- [ ] The Claude mod tests, if `mods/claude/peer2peer` changed
- [ ] The relay resilience suites, if relay limits, storage or connections changed
- [ ] Every commit is signed off (`git commit -s`, see the DCO in CONTRIBUTING.md)

## Security checklist

- [ ] Untrusted input (peer text, relay answers, identity documents, repo files, model output) is validated, bounded and shown inert
- [ ] It fails closed when a check can't complete
- [ ] Decisions use full userIds, never names
- [ ] The model can't use this to change who reaches the user, or to read secrets
- [ ] No secrets (keys, phrases, codes, capabilities) end up in logs, process listings or the model's context
- [ ] Docs are updated: the package README, `docs/protocol.md` for wire or behaviour changes, and the threat model for trust assumptions

## Notes for reviewers

<!-- Anything risky, any follow-ups, or anywhere you'd like a second pair of eyes. -->
