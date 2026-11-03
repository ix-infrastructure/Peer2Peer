# Contributing to Peer2Peer

Thanks for helping. Peer2Peer is a security-sensitive network that strangers' agents run on, so we hold every change to a high bar. We try just as hard to make that bar clear and the path to a merged PR short.

- **Questions and help:** [SUPPORT.md](SUPPORT.md)
- **Security issues:** never in public. See [SECURITY.md](SECURITY.md)
- **Protocol changes:** they start as a [Protocol RFC](.github/ISSUE_TEMPLATE/protocol_rfc.yml). See [GOVERNANCE.md](GOVERNANCE.md#how-the-protocol-evolves)
- **Code of conduct:** [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies everywhere

## Ways to contribute

- Try it with a friend and file what confused you. Onboarding bugs are real bugs.
- Run a relay and tell us how the [operator guide](docs/run-a-relay.md) held up.
- Fix a `good first issue`, improve docs, add tests for an edge case.
- Write a client or adapter for another agent (see [docs/clients.md](docs/clients.md)).
- Review the protocol ([docs/protocol.md](docs/protocol.md)) and the [threat model](docs/security/threat-model.md).

## Dev setup

You need **Node.js 22** (22.13+ for the relay's built-in `node:sqlite`) and git. There's no monorepo tool: each package has its own `package-lock.json`, and packages depend on each other through `file:` paths. **Build order matters:**

```sh
git clone https://github.com/ix-infrastructure/Peer2Peer && cd Peer2Peer

(cd packages/core         && npm ci && npm run build)   # 1. crypto core, everything depends on it
(cd packages/relay        && npm ci && npm run build)   # 2. relay; the CLI's integration tests start real relays
(cd packages/codex-bridge && npm ci && npm run build)   # 3. p2p imports its dist as `p2p codex …`
(cd packages/p2p          && npm ci && npm run build)   # 4. the p2p CLI
(cd packages/ext-ix       && npm ci && npm run build)   # 5. optional Ix extension
```

Try it locally with no network: [`docs/demo/two-friends.sh`](docs/demo/README.md) starts a throwaway relay on 127.0.0.1 and runs two users through setup, invite, join, status, a message and a conflict flag.

The Claude Code mod needs no build of its own. It runs the committed single-file CLI at `mods/claude/peer2peer/bin/p2p.mjs`:

```sh
claude plugin validate mods/claude/peer2peer
claude plugin test mods/claude/peer2peer
claude --plugin-dir mods/claude/peer2peer          # a session with your working copy loaded
```

## Tests and gates

Run these for every package you touched before opening a PR:

```sh
npm run typecheck && npm run lint && npm test && npm run build
```

Plus the repo-wide gates:

| Gate | Command | When |
|---|---|---|
| Layer boundaries | `node scripts/check-boundaries.mjs` | Always. Core must never import an extension |
| Committed bundle | `scripts/check-bundle.sh` | Any change to `packages/core`, `packages/p2p`, `packages/codex-bridge` or `mods/claude/peer2peer/bin`. Rebuild with `(cd packages/p2p && npm run bundle)` and commit `p2p.mjs` |
| ext-ix bundle | `(cd packages/ext-ix && npm run bundle:check)` | Any change to `packages/ext-ix` |
| Redaction copy | (part of `check-bundle.sh`) | `mods/claude/peer2peer/hooks/redact.ts` must be a byte-for-byte copy of `packages/core/src/v3/redact.ts` |
| Claude mod | `claude plugin test mods/claude/peer2peer` and `packages/p2p/node_modules/.bin/vitest run --config mods/claude/peer2peer/integration/vitest.config.mjs` | Any change to the mod |
| Relay resilience | `(cd packages/relay && npm run test:resilience && npm run test:fuzz)` | Changes to relay limits, storage or connection handling |
| Cross-version matrix | `node scripts/compat/matrix.mjs` (after building core and relay) | Any change to what goes on the wire, and every release. See [docs/compatibility.md](docs/compatibility.md): additive only, unknown fields ignored, restricting fields critical, nothing new sent to a peer that hasn't advertised it |
| Cross-implementation vectors | `packages/core/src/__tests__/go-vectors.test.ts` and `packages/core/src/v3/__tests__/vectors.test.ts` (data in their `testdata/`) | Never regenerate them to make a test pass. A vector change is a protocol change |

The integration tests start real relays on `127.0.0.1` with ephemeral ports and temporary `P2P_HOME`s. They need no network, no credentials and no admin rights, and they run on macOS, Linux and Windows (see [packages/p2p/README.md](packages/p2p/README.md#windows)).

**Why the bundle is committed:** the Claude Code plugin installs straight from this repository, with nothing downloaded at runtime. Anyone can verify that `p2p.mjs` is exactly what the sources build: `npm run bundle:check` rebuilds it and compares the bytes. Reviewers run `scripts/check-bundle.sh` on the PR head before approving.

`mods/claude/peer2peer/bin/defaults.json` must stay `{"defaultRelays": []}` in the repository.

## Pull request process

1. **Open an issue first** for anything bigger than a small fix, so nobody builds the wrong thing. Protocol changes need an accepted RFC before code.
2. **Branch** from `main`: `feat/…`, `fix/…`, `docs/…`, `chore/…`.
3. **Keep PRs focused.** One concern per PR. Separate refactors from behaviour changes.
4. **Write the tests with the change.** A bug fix comes with a test that fails without it. A security fix comes with a test for the attack.
5. **Update the docs in the same PR:** the package README, `docs/protocol.md` for any wire or behaviour change a second client would need to match, and the threat model if a trust assumption moved.
6. **Fill in the PR template.** Say what you ran, and call out anything security-relevant.
7. **Review:** at least one maintainer approval. Changes to `packages/core`, the relay's auth or storage, the hold rules, or the protocol need a second reviewer from the security reviewers (see [GOVERNANCE.md](GOVERNANCE.md)).
8. **CI:** see [CI today](#ci-today). For now, run the gates above yourself and paste the results into the PR.
9. **Sign off every commit** (`git commit -s`): see [Developer Certificate of Origin](#developer-certificate-of-origin-dco). The DCO check fails the PR otherwise.
10. **Merge:** a maintainer squash-merges once the review is clean and the gates pass on the exact head commit.

### CI

**CI** (`.github/workflows/ci-public.yml`) runs only when a maintainer starts it (manual dispatch), on a pull request's branch before it merges, on GitHub-hosted runners: Linux and macOS, Node 22 and 24. Run the same checks locally first (see [Develop](README.md#develop)). Each run installs every package with `npm ci --ignore-scripts`, builds them in order (core, relay, codex-bridge, p2p, ext-ix), runs each package's typecheck, lint, tests and build, then `scripts/check-boundaries.mjs`, `scripts/check-bundle.sh` (plus the ext-ix bundle check), and the Claude mod's tests (`claude plugin validate`, `claude plugin test`, with the public Claude CLI and no account) and integration tests. It has a read-only token and no secrets, and only runs on `main` save the cache that other runs read.

The **DCO check** (`.github/workflows/dco.yml`) is the only workflow that runs on every pull request. It never checks out or runs your code: it reads the PR's commit metadata to confirm each commit is signed off.

CI runs untrusted code: your PR's tests. That's why a maintainer starts it by hand after reading the change, and why PR code never runs on self-hosted runners. It isn't a judgement of you.

## Security-review culture

Most of this codebase defends a user against *someone else's* input: a peer's message, a relay's answer, a repo's config file, a model's tool call. Reviews here ask:

- **Who controls this input?** Peer text, peer-supplied names, relay responses, identity documents fetched from relays, files in the user's repo and anything the model writes are all untrusted. Treat them as data, sanitize them before display, and never interpret them as instructions.
- **Does it fail closed?** When a check can't be completed (unknown mode, unreachable relay, unreadable file), the safe answer is to hold, refuse or not publish.
- **Does it decide by full userId?** Never by a self-chosen name or petname.
- **Can the model do this by itself?** Anything that changes who can reach the user (join, accept, approve, relays, circles, rosters, rotate, enabling extensions) is typed by the person, never run by the agent.
- **Do secrets stay out of the model's context and out of logs?** That covers keys, backup phrases, invite and link codes, and capabilities.
- **Is it bounded?** Sizes, counts, time, retries. Every network step has a timeout, and nothing hangs silently.

Findings are rated **critical / high / medium / low**. A PR with an open critical or high doesn't merge. Mediums are fixed or explicitly deferred with an issue. The protocol keeps a **review log** (`docs/protocol.md`, "Review log") so later implementers can see why the rules are what they are.

## Commit conventions

We use [Conventional Commits](https://www.conventionalcommits.org/) with package scopes, matching the history:

```
feat(p2p): p2p doctor [user]
fix(codex-bridge): pin CODEX_HOME
fix(p2p,core,mod): footprint P1 review findings
docs: run-a-relay TLS section
build(npm): make the packages release-ready
```

Common scopes are `core`, `relay`, `p2p`, `codex-bridge`, `ext-ix`, `mod`, `ci` and `docs`. Write the subject in the imperative, and explain the *why* in the body. Reference issues as `#123`.

## Developer Certificate of Origin (DCO)

Peer2Peer uses the [Developer Certificate of Origin](https://developercertificate.org) (DCO) instead of a CLA. You keep the copyright to your work. By signing off, you certify that you wrote the change, or otherwise have the right to submit it under the project's license.

**Sign off every commit** by adding a `Signed-off-by` trailer with your real name and the email address you commit with:

```sh
git commit -s -m "fix(p2p): …"
# adds:  Signed-off-by: Your Name <you@example.com>
```

The `Signed-off-by` name and email must match the commit's author. A DCO check runs on every pull request and fails if any commit is missing a matching sign-off. To fix it:

```sh
git commit --amend -s --no-edit          # the last commit
git rebase --signoff <base>              # every commit on your branch; <base> is your PR's base branch
                                         # (e.g. upstream/main if you work from a fork)
git push --force-with-lease
```

The full text of the DCO, version 1.1 (from [developercertificate.org](https://developercertificate.org)):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), the license of this project.
