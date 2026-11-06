# Cross-version compatibility

Peers on different versions should work together on every feature they share, and a feature only one side has should drop out quietly instead of breaking the conversation. This document has two parts: the policy every release follows, and the protocol amendment that makes the policy possible (protocol 3.1, recorded in [protocol.md](protocol.md) as "Forward compatibility").

## Policy

- **Additive only within protocol v3.** A release may add optional fields, kinds, caps and relay features. It may not change what an existing field means, tighten a check on an existing field, or stop accepting something it accepted before.
- **Breaking changes need an RFC and a new protocol version** (`p2p/v3` → `p2p/v4`), through the process in GOVERNANCE.md. Relays advertise the version they speak.
- **Old forms are supported for at least 2 releases or 90 days**, whichever is longer, after their replacement ships. A sender keeps emitting the old form to peers that haven't shown they understand the new one.
- **Every release interoperates with the previous 2 releases** for every feature they share. The cross-version matrix (below) is how we check it, and it's part of the release checklist.
- **New behaviour that older clients would reject rolls out in two steps:** first a release that accepts it, then, once the previous two releases accept it, a release that sends it. Status `caps` (footprint P1) and device info in the identity document (below) both work this way.
- **A field that restricts what an object allows must be listed in `crit`** (below). Never rely on an older client happening to reject a new field.

## The amendment: protocol 3.1

Before 3.1, core refused any object, plaintext or envelope with a field it didn't know (the `noExtraFields` and `only` checks; the `agents` entries), and any envelope kind it didn't know. A peer one version ahead could therefore make every message fail. 3.1 replaces that with two rules:

1. **Must-ignore** for plaintexts and other payloads that grant nothing: an unknown field is ignored. Known fields keep every type, size and value check.
2. **Critical extensions** for signed security objects: an unknown field is ignored, unless the object lists it in an optional `crit` array, in which case the object is refused.

In practice core applies the `crit` rule everywhere (`checkFields` in `packages/core/src/v3/base.ts`). A plaintext may carry `crit` too. Each parser copies the known fields one by one, so an ignored field is never stored, shown, passed to a model or acted on. It is still covered by the object's signature and its `jwsHash`, because both are computed over the bytes as received.

### `crit`

- **Shape:** an optional array of 1-16 distinct field names (`^[A-Za-z][A-Za-z0-9_]{0,31}$`), each one a field the object carries, never `crit` itself. Any other shape makes the object `malformed`.
- **Meaning:** "a receiver that doesn't understand this field must refuse the object". A receiver that doesn't know a listed field refuses with `unsupported-critical`. A listed field the receiver knows is fine.
- **When an issuer must use it:** whenever the new field *restricts* what the object allows (a size cap on a capability, a narrower audience, an extra condition on a membership). Otherwise an older receiver would ignore the restriction and allow more than the issuer meant. A field that only adds information (a label, a hint, a version) stays out of `crit`.
- **Clients before 3.1** refuse any unknown field, `crit` included, so `crit` never makes an object *more* acceptable to them. Today's clients emit no `crit`: no object has a new restricting field yet.
- **Hashing:** two versions of an object that differ only in an ignored field have different `jwsHash`es. They are two versions, as before, and no client normalises them. Chains, forks and replay windows are unaffected.

### Which existing fields are inherently critical

Every field below is part of protocol 3.0, so every 3.x client understands all of them and none needs to be in `crit`. They are listed because ignoring any of them would let an object allow more than it says. If one of them were ever introduced again in a new form, the new form would have to be critical.

| Object | Fields that restrict (critical by nature) | Fields that only inform |
|---|---|---|
| Identity document (§2.5) | `devices`, `keyholders`, `rotation`, `merge`, `prev`, `ver`, `exp`, `iss`, `ik` | `name`, `relays` (routing), `certs`, `proofs`, `profile`, `by`, `dinfo` (3.1) |
| Device certificate (§2.3) | `iss`, `ik`, `did`, `spk`, `kpk`, `iat`, `exp` | `label` |
| Capability (§5.3) | `iss`, `sub`, `cert`, `relays`, `kinds`, `iat`, `exp`, `uses` | `capid` (an id) |
| Circle version (§3.3) | `cid`, `ver`, `prev`, `owner`, `ik`, `admins`, `members`, `policy`, `transfer`, `founder`, `nonce` | `name` |
| Membership (join/leave) statement | `iss`, `cid`, `n`, `op`, `at`, `cap` | `iat` |
| Rotation statement (§2.8) | `from`, `to`, `ik` (both halves) | `iat` |
| Invite, accept, unfriend, roster, proposal, transfer, proof | every field but labels and timestamps | `iat`, labels |
| Envelope (outer, §4.1) | every field (they are the AAD and the routing) | none |

**Still strict, unchanged:** JWS headers (`alg`, `typ`, `kid`); every size cap (the 64 KiB envelope, `MAX_JWS_BYTES`, the 16 KiB identity document); every known field's checks; signatures; authorisation (§4.2), blocks, identity freshness, the replay window and its claims; and the relays' limits.

### Every place that was strict and is now lenient

Security comes first: none of these relaxes authorisation, signatures, replay or size checks. Each one only stops a *newer* peer's additions from breaking an older one.

| Where (core unless noted) | Before | Now | Why it's safe |
|---|---|---|---|
| Signed objects: identity document and its `profile`, device certificate, capability, invite, accept, unfriend, roster, proof, circle version, transfer, membership statement, proposal, rotation halves and the rotation container | unknown field → `malformed` | ignored, unless listed in `crit` | The issuer signed the whole object, so only the issuer could add the field. Parsers copy known fields only. A restricting addition must be critical. |
| Envelope outer payload | unknown field → `malformed` | ignored (dropped from the decoded payload), unless in `crit` | The signature covers it. It isn't in the AAD, so nothing this version reads depends on it. |
| Envelope `kind` | unknown kind → `malformed` (logged, acked, never shown) | a kind shaped `^[a-z][a-z0-9_-]{0,31}$` is verified like any envelope (sender's identity known, cert, signature, blocks, replay claim), opened, never parsed. It is committed to the replay window, logged, and shown once per sender and kind a day (at most 3 a day per sender, since kind names are theirs to make up), as data, if the sender is the user's own device, a friend, or stands in a circle with them | Opening checks it was sealed for this device. Nothing in it is acted on. A stranger (no identity document) is refused before the claim, as before. The notice names only the kind. |
| `msg`, `roster`, `idle`, `status` (outer), `unfriend`, `receipt`, extension plaintexts and their `state` marker | unknown field → `malformed` | ignored, unless in `crit` | They grant nothing by themselves; their authorisation is the envelope's (§4.2). |
| `contact` and `circle` plaintexts (want, bundle, `pow`, `part`) | unknown field → `malformed` | ignored, unless in `crit`. The fields that say what the plaintext is stay exclusive: a contact carries exactly one of `text`, `circle`, `rotation`; a circle plaintext is a want or a bundle, never both | Without exclusivity, ignoring would give one envelope two readings. The signed objects inside get their own checks. |
| Status `agents` entries (received) | unknown field → the whole status `malformed` | the field is dropped (`copyAgents`) | Same as the top-level status fields since the status amendment. A sender's own list is still checked strictly. |
| Relay: envelope, device certificate and capability parsing (`packages/relay/src/crypto.ts`) | unknown fields were already ignored | unchanged, and now an unknown field listed in `crit` is **refused** (`unsupported-critical`, stricter), with core's `crit` shape rules and own-property checks | A relay can't enforce a restriction it doesn't know. |

## Device capabilities: who understands what

### Where it's advertised

- **Per device, in the identity document (`dinfo`).** It's a map from device id to `{caps, client}`, for listed devices only. `caps` uses the status caps' charset (at most 16 per device, each at most 40 characters). `client` is the client's version string.
  - **Why the identity document and not the device certificate:**
    - caps change when the client is upgraded, which has nothing to do with the device's keys;
    - every envelope carries its certificate (`fcert`), so caps there would cost bytes on every message;
    - the document is fetched once and cached, versioned, and already served by relays (§5.6).
  - **How it's kept current:** the document is signed by a key holder. A key-holding device keeps its own entry current, publishing the next version when the entry differs from what it is (at most hourly, `refreshDeviceInfo`). Entries of devices still listed carry over. In this release, a device that isn't a key holder is described by its statuses (below).
- **Per session, in the status `caps`** (§4.3), as before. The CLI adds one new cap: `proto.3.<minor>`, the protocol minor (`proto.3.1`: this amendment). A front end adds its own; the Claude mod adds `receipts.v1`. Status caps were already sent to every peer, so this needs no new field.
- **The exact client version is not in statuses.** A status goes to everyone the roster allows (a whole circle). An exact version string would help single out a device, and tell anyone watching which known bugs it still has. The protocol minor and the feature caps say what a sender needs to know.
  - The exact version rides only in the device's opt-in `dinfo.client`, which the user chose to publish.
  - Doctor shows the exact version when a device publishes one, and otherwise falls back to the protocol minor.
  - The trade-off: "which release is that peer on?" has no answer until step 2 makes `dinfo` the default, and even then only for key-holding devices.

### Two-step rollout for `dinfo`

Pre-release clients from before protocol 3.1 refuse an identity document with a field they don't know. A document with `dinfo` would make its user unreachable to them: the matrix shows this, and their `join` fails with "identity document: unknown field dinfo". So in this release:

- **Step 1 (this release).** Every client accepts and reads `dinfo`. It's **emitted only when opted in** (`P2P_DEVICE_INFO=1`, or `"deviceInfo": true` in config.json), and only to relays whose `/.well-known/p2p-relay.json` lists `identity.lenient`. Opting out removes the entry at the next publish.
- **Step 2 (a later release, once the previous two releases are 3.1).** Emitted by default. Run the matrix with `--new-env P2P_DEVICE_INFO=1` against the refs that release supports before flipping it.

### `peerSupports`

`peerSupports(app, userId, scope, feature)` (`packages/p2p/src/features.ts`) is the one helper every feature-gated send asks. It says yes only on positive evidence:

| Scope | Says yes when |
|---|---|
| `{sid}` | that session is **live now** (a status within 150 s) and its status lists the feature. A stale status never decides. |
| `{did}` | that device's `dinfo` entry lists it; without one, the latest status we hold from any session on that device does |
| `{all}` | every live session of the user that we know of (other than this device's own) lists it, and there is at least one. This is the rule for anything sent to a user as one plaintext (status `agents`, extension state). |

Migrated to it: receipts' `rcpt` (`{sid}`), status `agents` (`{all}`) and extension state (`{all}`).

The outbox-downgrade edge of delivery receipts (a message sealed with `rcpt` and sent days later, after its recipient downgraded) becomes moot once both sides are 3.1: a 3.1 receiver ignores an `rcpt` it doesn't understand instead of rejecting the message. Until then, `rcpt` is still added only for a session that is live now, never on the offline path or the outbox-only path.

### What this client never sends to an older one

The lenient client still interoperates with older clients for everything they support, because it never *sends* them anything new:

- **Status caps:** the new caps are status caps, which every client since the status amendment accepts (the charset is unchanged, and there are at most 16).
- **Identity documents:** no `dinfo` unless opted in (step 2 above).
- **Envelopes:** no new kind or plaintext field to a peer that hasn't advertised it (receipts are gated on a live session's `receipts.v1`).
- **Signed objects:** no `crit` anywhere.

The matrix checks all of this, both ways.

### Invite codes for several circles

A code's bundle names its first circle in `circle`, which every client joins, and up to 4 more in `circles` (heads only). A client from before `circles` ignores the field, as it ignores any field it doesn't know, and joins only the first circle; the inviter still adds it to the others, which reach it as ordinary circle invites for its user to approve. That downgrade is acceptable, so `circles` is not listed in `crit`. Clients that join them all advertise `invite.circles.v1`; when the inviter holds a status from the redeemer without it, its notice says the redeemer's client looks older. The matrix checks both directions: an older redeemer joins the first circle and holds the second.

### Project boundaries

Project boundaries (docs/concepts.md "Projects") change no envelope: a private project's session signs an ordinary `vis:"private"` roster with nobody on it, and the rest is local decisions (what this client sends, and what it accepts into its own sessions). So:

- **Older peers still work.** They see a shared project's sessions as before, and never see a private one's: its status isn't sent to them. A message from an older peer into a session outside its audience is refused at the older client (the roster says so) or, failing that, dropped here.
- **Your own older device can't widen it.** A roster for a session signed by another device of yours is never adopted by the device that runs the session (as before), and that device drops anything coming into the session from outside its projects' audience, whatever roster the message presents.
- **Messages between your own sessions** carry `bound` (critical) from a session with a ceiling: an older client of yours rejects it rather than ignore it, and a session on a device whose status doesn't advertise `projects.v1` isn't sent to at all (`not_shared`, "update Peer2Peer there"). `p2p doctor` warns when one of your other devices runs a client without project boundaries.
- **Devices must update.** An older client keeps the old rule for the sessions *it* runs: new sessions follow the default circle. Policies are per device, so share each project on every updated device that works in it.

`scripts/compat/matrix.mjs` checks that a session in an unshared project reaches nobody, an older peer included, and can't send to it, in both directions.

## Relays

- **What a relay lists.** `/.well-known/p2p-relay.json` now lists:
  - `protocolMinor`;
  - `frames`: the frames it answers;
  - `features`:
    - `identity.lenient`: it stores documents, certs and caps with fields it doesn't know, under the `crit` rule;
    - `envelope.lenient`: it relays unknown kinds and unknown outer fields, under the `crit` rule;
    - `invite-mailbox`;
    - `link-mailbox`;
    - `members`: the software can run members-only. It honours `admit` on `auth` and `invite-put`, and answers `circle-put` (also listed in `frames`). Whether this relay does run members-only is `access` (`"members"` or `"open"`) in the same document, and `attention: true` asks its operator to look at the logs. A client that doesn't know `access`, `attention` or a feature ignores it.
  - Frames are requests, not signed objects: a relay ignores frame fields it doesn't know (an older relay ignores `admit`, which then admits nobody). A client that needs a frame field honoured checks the relay's features first. The operator's allowlist (`allow` and `deny`, `RELAY_ALLOW_*`) is local configuration, not wire format.
- **Older relays.** A relay from before this lists none of these and counts as protocol 3.0 with the baseline frames. A client fetches the file on demand, caches it for a day (`relayInfo`, retried after an hour when a relay doesn't answer), and degrades: it publishes `dinfo` only where every relay lists `identity.lenient`.
- **Older clients.** An older client never asks, and works with a newer relay as before (the matrix runs old clients against this tree's relay).

## Seeing versions

- **`p2p doctor <user>` and `/peers doctor <user>`** list each of the user's devices with:
  - its label;
  - its protocol minor, and its exact client version only when the device publishes one in `dinfo`;
  - the caps it advertises, from its `dinfo` entry or its latest status.
  
  They also list the features unavailable between you, in words, and never count a difference as a failure.
- **`p2p doctor <user> --json`** also returns `devices` and `unavailable`.
- **`p2p ls --json` rows** carry `did` and `proto` (the protocol minor from the session's caps).

## Testing across versions

`scripts/compat/matrix.mjs` runs this tree's committed CLI bundle against earlier releases, over a local relay built from this tree, in both directions: each scenario runs once with the new client as the one that invites, creates the circles and sends first, and once with the old one in that role.

### Baselines

- **Release tags (the default).** The previous two releases: the two highest `v<x.y.z>` tags reachable from `HEAD`, leaving out prereleases (`v0.2.0-rc.1`) and a tag on `HEAD` itself, so a release run on its own tag tests against the two before it. While fewer than two tags exist, 70b86c7 (the initial public release) fills in. Each old CLI is the bundle committed at the tag (`git show <tag>:mods/claude/peer2peer/bin/p2p.mjs`), with the ext-ix copy committed beside it, so nothing is built.
- **npm, as users install it.** `--npm <version>` installs `@peer2peer/cli` at exactly that version, and `@peer2peer/ext-ix` at the same version when it is published, into a fresh temporary project: `npm install --ignore-scripts --save-exact`, then each package's integrity in the lockfile is checked against the registry's `dist.integrity`. The installed CLI runs from its `dist`, with its real dependencies, and finds ext-ix as its sibling, the way `npm i -g @peer2peer/cli @peer2peer/ext-ix` does. A version that isn't published is skipped with a notice (`--require-npm` makes that a failure). `--npm-releases` adds every release tag among the git baselines as its npm version, which is how CI and the release workflow run it.
- **Before publishing.** `--tarballs .release/tarballs` installs the tarballs `scripts/release-pack.mjs` built, the same way, to try the installed layout of a version that isn't on npm yet.
- `--refs` or `P2P_COMPAT_REFS` names other git refs; `--npm` or `P2P_COMPAT_NPM` other npm versions.

### What it checks

Every item runs in both directions, against every baseline:

| Check | What it asserts |
|---|---|
| Invite and join | A short code (or, where the redeemer has invite links, the web link with its confirmation) makes the two friends both ways. |
| Statuses | Each side sees the other's live session in `p2p ls`. |
| Direct friend messages | A message from each side's session reaches the other's. |
| Project boundaries | A session in an unshared project reaches nobody, an older peer included: its status goes to no one, a send from it is refused (`not_shared`), and the other side never sees it or its message. |
| Delivery receipts | Asked for and answered end to end where both sides have them; never asked for where one side doesn't, and the message is still delivered. |
| Extension envelopes | An `x:ix.note` from each side (when its release ships ext-ix): a receiver without the extension enabled shows the plain fallback and interprets nothing; one with it enabled renders it. |
| Circle invite and join | A circle created on one side, invited to by user id, held and approved on the other, which then stands in it. |
| Invite codes for several circles | One code for two circles: a client with them joins both; one before them joins the first and holds the second as a circle invite. |
| Circle messages | A third user, on the second side's release, joins an open circle by its link. It and the circle's owner aren't friends; their circle-shared sessions see each other's statuses and exchange messages both ways. |
| Offline queue | A message to a session seen recently but not live is queued at the relay, asks for no receipt, and is delivered when the session drains. |
| No rejection | No side logged a rejected envelope, an unknown field, `malformed` or `unsupported-critical`. |

A feature only one side has is checked for clean absence, never skipped silently: the line says which side lacked it.

### Running it

```sh
(cd packages/core && npm run build) && (cd packages/relay && npm run build)
node scripts/compat/matrix.mjs                          # the previous two release tags
node scripts/compat/matrix.mjs --npm-releases           # ... and each of them as npm installs it
node scripts/compat/matrix.mjs --npm 0.1.0              # one published version only
node scripts/compat/matrix.mjs --refs v0.2.0,v0.1.0     # named refs
node scripts/compat/matrix.mjs --new-env P2P_DEVICE_INFO=1   # step 2 of a two-step rollout
P2P_COMPAT=1 packages/p2p/node_modules/.bin/vitest run packages/p2p/src/__tests__/compat-matrix.test.ts
```

It takes about 30 seconds per baseline. In CI it runs on every pull request (`ci-public.yml`, the `compat` job, with `--npm-releases`), and on a dispatch unless `compat_matrix` is unticked (`compat_refs` and `compat_npm` pick other baselines). The release workflow's build job runs it against the previous two releases, from git and npm, before it packs anything, and a failure stops the release. The release checklist ([docs/releasing.md](releasing.md)) lists it too.
