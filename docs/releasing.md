# Releasing the npm packages

Peer2Peer's free, open-source packages publish to the public npm registry under the `@peer2peer` scope. The scope belongs to the npm organization `peer2peer`, owned by the Ix Infrastructure company account. Any paid company add-on would publish under a separate scope; nothing here touches it.

| Package | Directory | Depends on (at runtime) |
| --- | --- | --- |
| `@peer2peer/core` | `packages/core` | (third-party only) |
| `@peer2peer/relay` | `packages/relay` | core |
| `@peer2peer/codex-bridge` | `packages/codex-bridge` | (none) |
| `@peer2peer/cli` (the `p2p` command) | `packages/p2p` | core, codex-bridge |
| `@peer2peer/ext-ix` | `packages/ext-ix` | core; optional peer: cli |

All five are licensed Apache-2.0 and versioned in lockstep: they always carry the same version.

**Publish order:** core → relay → codex-bridge → cli → ext-ix. Each package comes after the packages it depends on, so a user never installs a version whose dependencies aren't there yet. `scripts/release-pack.mjs` writes this order to `.release/tarballs/manifest.json`, and the release workflow follows it.

## Release notes

Each release's notes go in [CHANGELOG.md](../CHANGELOG.md), in the PR that bumps the version. Between releases, add anything the next release's notes must say (a behaviour change, a step 2 of a two-step rollout) under an "Unreleased" heading there.

## How a release is built

In the repository the packages depend on each other through `file:` paths. Those can't be published, so **never run `npm publish` inside `packages/*`** (each package's `prepublishOnly` refuses). Instead:

```sh
node scripts/release-pack.mjs
```

It checks that all five packages and their compiled-in version constants agree, builds them in order, copies each package's allowlisted files (`dist`, `README.md`, `SPEC.md` for ext-ix) into `.release/pkg/<dir>` with the repository `LICENSE`, and rewrites the copy's `package.json`: internal dependencies are pinned to exactly `<version>` (the packages release in lockstep, and core is the crypto: a package runs with exactly the core it was tested with), ext-ix's optional peer on `@peer2peer/cli` becomes `^<version>`, README links point at the `v<version>` tag, and `scripts` and `devDependencies` are dropped. Then it packs each copy into `.release/tarballs/*.tgz` and verifies every tarball:

- it contains only `package.json`, `README.md`, `LICENSE`, `SPEC.md` and `dist/**/*.js|.d.ts`: no tests, source maps, fixtures, dotfiles or dot-directories (`.test-homes`, `.npmrc`, `.env`), or databases;
- no file matches a secret pattern (private keys, npm/GitHub/AWS/Google/OpenAI/Anthropic/Slack/Stripe tokens);
- every `main`, `types`, `exports` and `bin` target ships, and each `bin` is executable and starts with `#!/usr/bin/env node`;
- no dependency is still a `file:`, `link:` or `workspace:` spec, and every internal dependency is pinned to the release version.

Finally it installs all five tarballs into a clean temporary project and runs them: `npx p2p --version`, `p2p-relay --help`, an import of every entry point, and a real relay started on `127.0.0.1` with a SQLite database, health-checked, then stopped with SIGTERM. Flags: `--clean-install` (fresh `npm ci --ignore-scripts` everywhere; no dependency needs its install scripts), `--skip-build`, `--no-smoke`, `--no-provenance`, `--out <dir>`.

The repository is never modified by it; `.release/` is git-ignored. `--out` is wiped on every run, so the script refuses a directory that is neither empty nor one it made itself (it leaves a `.p2p-release-pack` marker in its own).

## One-time setup

These need an owner of the npm organization `peer2peer` and an admin of the GitHub repository. **Do them in this order.** The token is the last step, because a token stored before its environment is locked down can be used by any workflow run that names the environment.

1. **Claim the names. Done:** the npm organization `peer2peer` has been created (public packages only). Package names inside the scope don't need reserving: the first publish of each creates it, and no one outside the organization can publish into `@peer2peer`. What's left is to add the release managers as organization members with publish rights.

2. **Make the repository public.** npm only records provenance for packages built from a public repository, and `publishConfig.provenance` is `true` in every package. It is also what makes the protections in the next step available (see the warning below).

3. **Create and lock down the `npm-publish` environment first** (Settings → Environments → New environment → `npm-publish`). This is a hard prerequisite for everything after it:
   - **Required reviewers:** at least one person besides whoever pushes release tags. Turn on *Prevent self-review*.
   - **Deployment branches and tags:** *Selected branches and tags*, with exactly one rule: tag pattern `v*`. No branches. The workflow's publish job runs only for `v*` tags anyway, so nothing else ever needs this environment.
   - **A tag ruleset** (Settings → Rules → Rulesets → New tag ruleset) targeting `v*`: restrict creations, updates and deletions to the release managers, and block force pushes. Without it, anyone with write access can push a `v*` tag and request a publish.

   > **Warning.** On a private repository these protections depend on the plan: environments with deployment branch and tag rules, and rulesets, need GitHub Pro, Team or Enterprise, and required reviewers need GitHub Enterprise. A public repository gets all of them on every plan. Without them, the environment protects nothing. **Do not add `NPM_TOKEN` until the repository is public, or until the plan provides these protections and you have checked they are in force.**

4. **Allow a GitHub-hosted runner.** Both release jobs run on `ubuntu-latest`, because npm refuses provenance from self-hosted runners; the project's self-hosted runners can't be used. Public repositories get GitHub-hosted minutes for free. Check that the organization's Actions policy allows them for this repository.

5. **Authentication, only after steps 2–4. Pick one:**
   - **Granular automation token (needed for the first release).** An organization owner creates it at npmjs.com → Access Tokens → Generate New Token → Granular Access Token. Give it *Read and write* on packages and scopes, limited to the `@peer2peer` scope (organization `peer2peer`), with *Bypass 2FA* enabled (CI can't answer a 2FA prompt), an expiry of 30 days or less, and ideally an allowed IP range. Store it as the secret `NPM_TOKEN` **in the `npm-publish` environment** (never a repository or organization secret). The workflow exposes it only to the single publish step, in a job that has no checkout and runs no repository code.
   - **Trusted publishing (preferred afterwards; no stored secret).** It can only be configured for a package that already exists, so it replaces the token after the first release. On npmjs.com, for each of the five packages, go to Settings → Trusted publishing → GitHub Actions and enter organization `ix-infrastructure`, repository `Peer2Peer`, workflow `release.yml` and environment `npm-publish`. Then set "Publishing access" to *Require two-factor authentication and disallow tokens*, delete the `NPM_TOKEN` secret, and revoke the token on npmjs.com.

## Releasing a version

1. **Bump the version** on a branch, in all five packages at once:

   ```sh
   node scripts/set-version.mjs 0.2.0          # or 0.2.0-rc.1 for a prerelease (published under the "next" tag)
   node scripts/release-pack.mjs               # builds, packs, verifies; must end with the size table
   (cd packages/p2p && npm run bundle)         # the committed single-file CLI inlines the version
   (cd packages/ext-ix && npm run bundle)      # so does the committed ext-ix copy
   scripts/check-bundle.sh
   ```

   `set-version.mjs` updates every `package.json`, the version constants in codex-bridge, p2p and ext-ix, ext-ix's peer range on `@peer2peer/cli`, and every `package-lock.json`. Open a PR, get it reviewed, dispatch `ci` (`ci-public.yml`) on its branch and check it is green on its head, and merge it.

   **Compatibility:** the cross-version matrix ([docs/compatibility.md](compatibility.md)) must be green both ways against the previous two releases, as committed at their tags and as npm installs them. The PR's `compat` check runs it (every pull request does), and so does the dispatch. Locally: `node scripts/compat/matrix.mjs --npm-releases`. A release that turns on something older clients would reject (step 2 of a two-step rollout) is run with that setting too (for example `--new-env P2P_DEVICE_INFO=1`), and its notes say so. To try the new version the way npm will install it, before it is published: `node scripts/release-pack.mjs` and then `node scripts/compat/matrix.mjs --tarballs .release/tarballs` (the tarballs as the old side, this tree's bundle as the new).

2. **Dry run.** Actions → release → Run workflow on `main`. A manual run is always a dry run: its `compat` job runs the cross-version matrix against the previous two releases (from git and npm), and its build job runs the tests, checks the tree is clean, builds and verifies the tarballs, and runs `npm publish --dry-run` for each, in order, with no credentials (a package whose exact version is already on npm is skipped with an "already published, skipped" line, as the publish job skips it); the publish job is skipped. The tarballs are attached to the run as the `peer2peer-tarballs` artifact. Look at them.

3. **Publish** by tagging the merged commit:

   ```sh
   git switch main && git pull --ff-only
   git tag -s v0.2.0 -m "Peer2Peer v0.2.0"
   git push origin v0.2.0
   ```

   The workflow has two jobs. The build job (read-only, no environment, no credentials, dependencies installed with `--ignore-scripts`) checks that the tag matches the package version, runs the tests and gates, checks the tree is still clean, and builds, verifies and uploads the tarballs. The `compat` job (read-only, its own runner, no artifacts) runs the cross-version matrix against the two releases before this tag; the publish job needs both, so a failed matrix fails the release and nothing is published. The publish job runs only for a `v*` tag whose check passed. It waits for an `npm-publish` reviewer, downloads the tarballs (no checkout, no install), checks them against the manifest's hashes, and publishes core, relay, codex-bridge, cli and ext-ix in that order with `--provenance`. A package version that's already on npm is skipped, so if a run fails halfway, re-run it. Only a tag can publish; a manual run can't.

4. **Check:** `npm view @peer2peer/cli@0.2.0`. Each package's npm page shows a provenance badge linking to the workflow run. Then try `npx @peer2peer/cli@0.2.0 --version` in an empty directory, and run the matrix against the published packages: `node scripts/compat/matrix.mjs --npm 0.2.0 --require-npm` (from a checkout of `main`; it fails if the version isn't installable from npm).

5. **The relay install scripts' source.** The same tag run also attaches `peer2peer-<version>-src.tar.gz` and `SHA256SUMS` to the tag's GitHub release (the `github-release` job, `contents: write` only, after the publish job). The tarball is `git archive` of the tag with the commit's time as every file's mtime, compressed with `gzip -n`, so the same commit always gives the same bytes; the build job makes it twice and compares them, and a rerun never replaces an asset that is already there. A manual (dry) run uploads the same files as the `peer2peer-source` artifact.

   The install scripts download that tarball when they aren't run from a checkout. A script can't pin the release it ships in (its own bytes are in the tarball), so pin it in a follow-up PR: set `RELAY_VERSION` and `RELAY_SOURCE_SHA256` (from the release's `SHA256SUMS`) in both `scripts/install-relay.sh` and `scripts/install-relay.ps1`, set `P2P_VERSION` in `scripts/install.sh` and `$P2PVersion` in `scripts/install.ps1` (the client installers, which `npm install -g` exactly that version of `@peer2peer/cli` and `@peer2peer/ext-ix`; pin it only once the publish job has finished), run `npm run install-scripts:checksums` in `packages/relay` (it rewrites both `install-relay.sha256` and `install.sha256`), and merge. The website serves the scripts and both checksum files from that commit.

### Release checklist

- [ ] Version bumped in all five packages (`scripts/set-version.mjs`), bundles rebuilt, `scripts/check-bundle.sh` clean.
- [ ] Release notes written in CHANGELOG.md (the "Unreleased" heading renamed to the version), including any step 2 of a two-step rollout this release turns on.
- [ ] The bump PR's `compat` check green: the cross-version matrix both ways against the previous two releases, from their tags and from npm ([docs/compatibility.md](compatibility.md)). Every check listed there passes, or reports a clean absence for a feature one side doesn't have.
- [ ] A step 2 rollout in this release: the matrix also green with that setting (`--new-env ...`) against both previous releases.
- [ ] `ci` dispatched on the PR's head and green (Linux and macOS, Node 22 and 24).
- [ ] The release workflow's dry run green on `main` (tests, matrix, tarballs, `npm publish --dry-run`); tarballs looked at.
- [ ] Optional, for the installed layout: `node scripts/compat/matrix.mjs --tarballs .release/tarballs` green.
- [ ] Tag signed and pushed; the publish job approved by an `npm-publish` reviewer.
- [ ] After publishing: `npm view`, `npx @peer2peer/cli@<version> --version`, and `node scripts/compat/matrix.mjs --npm <version> --require-npm` green.
- [ ] Relay install scripts pinned to the new source tarball in a follow-up PR (step 5).

A published version can't be reused, even after `npm unpublish`. To withdraw a broken release, `npm deprecate @peer2peer/<pkg>@<version> "<reason>"` and publish a fixed patch version.

## Publishing without the workflow

Use this only if the workflow can't run (for example, the repository is still private or GitHub-hosted runners are unavailable). These packages carry no provenance.

```sh
node scripts/release-pack.mjs --clean-install --no-provenance
cd .release/tarballs
npm login                               # an account with publish rights in the peer2peer org, with 2FA
for t in peer2peer-core-*.tgz peer2peer-relay-*.tgz peer2peer-codex-bridge-*.tgz peer2peer-cli-*.tgz peer2peer-ext-ix-*.tgz; do
  npm publish "./$t" --access public    # npm asks for a 2FA code for each
done
```

Keep that order. Publish from a clean checkout of the tagged commit, never from a working tree with local changes.

## Publishing the repository

This repository's history isn't published. It still holds internal names from before the open-source cleanup. The public repository starts from a fresh, single commit:

1. Start from a clean checkout of the commit you're publishing, with no `node_modules`, build output or local files (`git clean -xdf`, or a fresh clone).
2. Delete `.github/workflows/ci.yml`, the internal self-hosted workflow.
3. Run both secret scans from the tree's root; both must report no leaks: `gitleaks dir --redact .`, plus `gitleaks git --redact .` on the new repository after step 5. `.gitleaks.toml` allows only the known fake fixture values.
4. Run the internal-name grep (the maintainers keep the list of internal hostnames, people and runner names privately), and fix every hit that isn't one of the two intended contact addresses.
5. Copy the tree into a new repository (`git init`), make one commit signed off by a maintainer, and push that.

Never push this repository's history, or any branch from it, to the public repository.
